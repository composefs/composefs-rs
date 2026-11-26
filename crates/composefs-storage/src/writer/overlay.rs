//! Native overlay scaffolding and interpretation of logical parent chains.

use std::path::Path;

use super::records::{
    self, CONTROL_FILE_MODE, LayerRecord, PRIVATE_DIR_MODE, allow_missing, find_by_id,
};
use super::{ImportError, Result};
use cap_std::fs::Dir;
use rustix::fs::{self, Mode};

// containers/storage/drivers/overlay/overlay.go:maxDepth limits the lower stack
// to 500. An image this deep still fits beneath a container's writable upper.
pub(super) const MAX_IMAGE_LAYERS: usize = 500;
// overlay.go:idLength keeps lower mount-option strings short enough for a page.
pub(super) const SHORT_LINK_LENGTH: usize = 26;
// overlay.go:defaultPerms is the base diff directory's default mode.
const BASE_DIFF_MODE: u32 = 0o555;

/// Resolve parents in overlay order, nearest first, leaving room for the child.
pub(super) fn parent_chain<'a>(layers: &'a [LayerRecord], parent: &str) -> Result<Vec<&'a str>> {
    let mut ids = Vec::new();
    let mut current = parent;
    while !current.is_empty() {
        if ids.len() + 1 >= MAX_IMAGE_LAYERS {
            return Err(ImportError::Malformed(format!(
                "overlay chain depth exceeds {MAX_IMAGE_LAYERS}"
            )));
        }
        records::safe_id(current)?;
        let record = find_by_id(layers, current).ok_or_else(|| {
            ImportError::RecoveryRequired(format!("missing parent record {current}"))
        })?;
        ids.push(record.id.as_str());
        current = record.parent();
    }
    Ok(ids)
}

pub(super) struct LowerChain {
    ids: Vec<String>,
    links: Vec<String>,
}

impl LowerChain {
    /// Read physical link identifiers separately from resolving logical parents.
    /// Missing or incompatible links disqualify reuse candidates.
    pub(super) fn read(overlay: &Dir, ids: &[&str]) -> Result<Option<Self>> {
        let mut links = Vec::with_capacity(ids.len());
        for id in ids {
            let Some(link) = read_optional(overlay, &format!("{id}/link"))? else {
                return Ok(None);
            };
            if !valid_link(&link) {
                return Ok(None);
            }
            links.push(format!("l/{link}"));
        }
        Ok(Some(Self {
            ids: ids.iter().map(|id| (*id).to_owned()).collect(),
            links,
        }))
    }

    pub(super) fn matches(&self, lower: Option<String>, lower_layers: Option<String>) -> bool {
        if !self.ids.is_empty() && lower.is_none() && lower_layers.is_none() {
            return false;
        }
        lower.is_none_or(|value| value == self.links.join(":"))
            && lower_layers.is_none_or(|value| value == self.ids.join(":"))
    }
}

/// Install driver directories and control files after the incomplete record.
pub(super) fn create_layer(
    overlay: &Dir,
    id: &str,
    lowers: &LowerChain,
    created_link: &mut Option<String>,
) -> Result<Dir> {
    let layer = records::create_dir(overlay, id, PRIVATE_DIR_MODE)?;
    let diff = records::create_dir(&layer, "diff", PRIVATE_DIR_MODE)?;
    if let Some(parent) = lowers.ids.first() {
        let stat = fs::statat(
            overlay,
            format!("{parent}/diff"),
            fs::AtFlags::SYMLINK_NOFOLLOW,
        )?;
        fs::fchown(
            &diff,
            Some(fs::Uid::from_raw(stat.st_uid)),
            Some(fs::Gid::from_raw(stat.st_gid)),
        )?;
        fs::fchmod(&diff, Mode::from_bits_truncate(stat.st_mode & 0o7777))?;
    } else {
        fs::fchmod(&diff, Mode::from_bits_truncate(BASE_DIFF_MODE))?;
    }
    let mut random = [0u8; SHORT_LINK_LENGTH];
    openssl::rand::rand_bytes(&mut random).map_err(std::io::Error::other)?;
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let short: String = random
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect();
    // The durable link file must precede the short symlink: Go cleanup
    // discovers that symlink through this file after an interrupted import.
    records::atomic_write(&layer, "link", short.as_bytes(), CONTROL_FILE_MODE)?;
    records::sync_dir(overlay)?;
    let links = records::open_dir(overlay, Path::new("l"))?;
    fs::symlinkat(format!("../{id}/diff"), &links, &short)?;
    *created_link = Some(short);
    records::sync_dir(&links)?;
    for name in ["work", "merged"] {
        records::create_dir(&layer, name, PRIVATE_DIR_MODE)?;
    }
    if lowers.ids.is_empty() {
        records::create_dir(&layer, "empty", PRIVATE_DIR_MODE)?;
    } else {
        for (name, values) in [("lower", &lowers.links), ("lower-layers", &lowers.ids)] {
            records::atomic_write(&layer, name, values.join(":").as_bytes(), CONTROL_FILE_MODE)?;
        }
    }
    Ok(diff)
}

pub(super) fn read_optional(dir: &Dir, path: &str) -> Result<Option<String>> {
    allow_missing(dir.read_to_string(path))
}

pub(super) fn valid_link(link: &str) -> bool {
    link.len() == SHORT_LINK_LENGTH && link.bytes().all(|b| b.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_chains_follow_parent_ids_in_overlay_order() {
        let layers = [("top", "middle"), ("base", ""), ("middle", "base")]
            .into_iter()
            .map(|(id, parent)| LayerRecord {
                id: id.into(),
                parent: Some(parent.into()),
                ..Default::default()
            })
            .collect::<Vec<_>>();
        for (parent, expected) in [
            ("", vec![]),
            ("base", vec!["base"]),
            ("middle", vec!["middle", "base"]),
            ("top", vec!["top", "middle", "base"]),
        ] {
            assert_eq!(parent_chain(&layers, parent).unwrap(), expected);
        }
        assert!(matches!(
            parent_chain(&layers, "missing"),
            Err(ImportError::RecoveryRequired(_))
        ));
        let cycle = vec![LayerRecord {
            id: "cycle".into(),
            parent: Some("cycle".into()),
            ..Default::default()
        }];
        assert!(matches!(
            parent_chain(&cycle, "cycle"),
            Err(ImportError::Malformed(_))
        ));
    }

    #[test]
    fn parent_depth_leaves_room_for_the_child_layer() {
        for count in [MAX_IMAGE_LAYERS - 2, MAX_IMAGE_LAYERS - 1, MAX_IMAGE_LAYERS] {
            let layers: Vec<_> = (0..count)
                .map(|index| LayerRecord {
                    id: format!("layer{index}"),
                    parent: (index > 0).then(|| format!("layer{}", index - 1)),
                    ..Default::default()
                })
                .collect();
            let result = parent_chain(&layers, &format!("layer{}", count - 1));
            if count < MAX_IMAGE_LAYERS {
                let chain = result.unwrap();
                assert_eq!(chain.len(), count);
                assert_eq!(
                    chain.first().copied(),
                    Some(layers.last().unwrap().id.as_str())
                );
                assert_eq!(chain.last().copied(), Some("layer0"));
            } else {
                assert!(matches!(result, Err(ImportError::Malformed(_))));
            }
        }
    }
}

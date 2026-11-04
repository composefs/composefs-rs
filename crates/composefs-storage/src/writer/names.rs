//! Validation and assignment of image names in storage metadata.

use super::records::{ImageRecord, SHA256_HEX_LENGTH, find_by_id, find_by_id_mut};
use super::{ImportError, NamePolicy, Result};
use oci_spec::distribution::Reference;

// containers/image/docker/reference/reference.go:NameTotalLengthMax, excluding
// tags and digests but including the normalized registry and repository path.
const MAX_REPOSITORY_NAME_LENGTH: usize = 255;

fn validate(name: &str) -> Result<()> {
    let reference = name
        .parse::<Reference>()
        .map_err(|e| ImportError::Malformed(format!("invalid image name {name:?}: {e}")))?;
    // Match ParseNormalizedNamed: repository paths must be lowercase, and bare
    // image IDs aren't names. Uppercase registry hosts and tags remain valid.
    if !name.is_ascii()
        || reference
            .repository()
            .bytes()
            .any(|b| b.is_ascii_uppercase())
        || reference.registry().len() + 1 + reference.repository().len()
            > MAX_REPOSITORY_NAME_LENGTH
        || (name.len() == SHA256_HEX_LENGTH
            && name
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        || reference
            .digest()
            .is_some_and(|d| d.bytes().any(|b| b.is_ascii_uppercase()))
    {
        return Err(ImportError::Malformed(format!(
            "invalid image name {name:?}"
        )));
    }
    Ok(())
}

pub(super) fn requested(names: &[String]) -> Result<Vec<String>> {
    let mut unique = Vec::new();
    for name in names {
        validate(name)?;
        // Preserve the caller's repository spelling. Only supply the default
        // tag; a registry port does not count as a tag on the final component.
        let name = if name.contains('@') || name.rsplit('/').next().unwrap().contains(':') {
            name.clone()
        } else {
            format!("{name}:latest")
        };
        if !unique.contains(&name) {
            unique.push(name);
        }
    }
    Ok(unique)
}

/// Resolve conflicts and update names/history without performing any I/O.
pub(super) fn assign(
    images: &mut [ImageRecord],
    id: &str,
    names: &[String],
    policy: NamePolicy,
) -> Result<()> {
    let missing_record = || {
        ImportError::MetadataConflict(format!("missing image record {id} during name assignment"))
    };
    find_by_id(images, id).ok_or_else(missing_record)?;
    if policy == NamePolicy::FailOnConflict {
        for record in images.iter().filter(|record| record.id != id) {
            if let Some(existing) = &record.names
                && let Some(name) = names.iter().find(|name| existing.contains(name))
            {
                return Err(ImportError::NameConflict(name.clone()));
            }
        }
    }
    for record in images.iter_mut().filter(|record| record.id != id) {
        if let Some(list) = &mut record.names {
            list.retain(|name| !names.contains(name));
        }
    }
    let record = find_by_id_mut(images, id).ok_or_else(missing_record)?;
    let assigned = record.names.get_or_insert_default();
    for name in names {
        if !assigned.contains(name) {
            assigned.push(name.clone());
        }
    }
    let history = record.names_history.get_or_insert_default();
    for name in names {
        history.retain(|existing| existing != name);
        history.insert(0, name.clone());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn image_names_use_repository_tag_and_digest_syntax() {
        let digest = "a".repeat(SHA256_HEX_LENGTH);
        for (name, valid) in [
            ("example:Release".into(), true),
            ("EXAMPLE.COM/team/image:Release".into(), true),
            ("localhost:5000/team/image:Release".into(), true),
            ("team/image__name:v1".into(), true),
            (format!("example/image@sha256:{digest}"), true),
            (format!("example/image:Release@sha256:{digest}"), true),
            ("Example:latest".into(), false),
            ("example.com/Team/image:latest".into(), false),
            ("example.com/team/Image:latest".into(), false),
            ("Team/image:latest".into(), false),
            ("example.com/image:tag:extra".into(), false),
            ("example.com/image:tag/path".into(), false),
            ("example.com/image:".into(), false),
            ("example.com/image:@sha256:123".into(), false),
            ("example.com//image:tag".into(), false),
            ("example.com/.image:tag".into(), false),
            ("example.com/image:rélease".into(), false),
            (
                format!("example/image@sha256:{}", "A".repeat(SHA256_HEX_LENGTH)),
                false,
            ),
            (digest, false),
            ("".into(), false),
        ] {
            let result = validate(&name);
            assert_eq!(result.is_ok(), valid, "{name}: {result:?}");
        }
    }

    #[test]
    fn normalized_repository_length_excludes_tags() {
        let prefix = "example.com/";
        for (length, valid) in [
            (MAX_REPOSITORY_NAME_LENGTH, true),
            (MAX_REPOSITORY_NAME_LENGTH + 1, false),
        ] {
            let name = format!("{prefix}{}:Release", "a".repeat(length - prefix.len()));
            assert_eq!(validate(&name).is_ok(), valid, "{name}");
        }
    }

    #[test]
    fn requested_names_default_to_latest_without_resolving_repositories() {
        let digest = format!("sha256:{}", "a".repeat(SHA256_HEX_LENGTH));
        for (name, expected) in [
            ("localhost/image".into(), "localhost/image:latest".into()),
            (
                "localhost:5000/team/image".into(),
                "localhost:5000/team/image:latest".into(),
            ),
            ("image".into(), "image:latest".into()),
            (
                "localhost/image:Release".into(),
                "localhost/image:Release".into(),
            ),
            (
                format!("localhost/image@{digest}"),
                format!("localhost/image@{digest}"),
            ),
            (
                format!("localhost/image:Release@{digest}"),
                format!("localhost/image:Release@{digest}"),
            ),
        ] {
            assert_eq!(requested(&[name]).unwrap(), vec![expected]);
        }
    }

    #[test]
    fn missing_image_record_leaves_name_assignments_unchanged() {
        for policy in [NamePolicy::FailOnConflict, NamePolicy::Reassign] {
            let mut images: Vec<ImageRecord> = serde_json::from_value(json!([
                {"id":"old","names":["example:latest"]}
            ]))
            .unwrap();
            let original = images.clone();
            let result = assign(&mut images, "new", &["example:latest".into()], policy);
            assert!(matches!(
                result,
                Err(ImportError::MetadataConflict(message))
                    if message == "missing image record new during name assignment"
            ));
            assert_eq!(images, original);
        }
    }

    #[test]
    fn name_assignment_preserves_records_and_go_history_order() {
        for policy in [NamePolicy::FailOnConflict, NamePolicy::Reassign] {
            let mut images: Vec<ImageRecord> = serde_json::from_value(json!([
                {"id":"old","names":["example:latest","example:keep"],"custom":42},
                {"id":"new","names":["example:existing"],"names-history":["example:two","example:old"],"mapped-layers":["mapped"]}
            ])).unwrap();
            let original = images.clone();
            let names = requested(&[
                "example".into(),
                "example:two".into(),
                "example:latest".into(),
            ])
            .unwrap();
            assert_eq!(names, ["example:latest", "example:two"]);
            let result = assign(&mut images, "new", &names, policy);
            if policy == NamePolicy::FailOnConflict {
                assert!(
                    matches!(result, Err(ImportError::NameConflict(name)) if name == "example:latest")
                );
                assert_eq!(images, original);
            } else {
                result.unwrap();
                assert_eq!(
                    serde_json::to_value(&images).unwrap(),
                    json!([
                        {"id":"old","names":["example:keep"],"custom":42},
                        {"id":"new","names":["example:existing","example:latest","example:two"],"names-history":["example:two","example:latest","example:old"],"mapped-layers":["mapped"]}
                    ])
                );
            }
        }
    }
}

//! Validation and assignment of image names in storage metadata.

use super::records::{ImageRecord, find_by_id, find_by_id_mut};
use super::{ImportError, NamePolicy, OciDigest, Result};
use oci_spec::distribution::Reference;

// containers/image/docker/reference/reference.go:NameTotalLengthMax, excluding
// tags and digests but including the normalized registry and repository path.
const MAX_REPOSITORY_NAME_LENGTH: usize = 255;

fn validate(name: &str) -> Result<Reference> {
    let reference = name
        .parse::<Reference>()
        .map_err(|e| ImportError::Malformed(format!("invalid image name {name:?}: {e}")))?;
    // Match ParseNormalizedNamed: repository paths must be lowercase.
    // Uppercase registry hosts and tags remain valid.
    if !name.is_ascii()
        || reference
            .repository()
            .bytes()
            .any(|b| b.is_ascii_uppercase())
        || reference.registry().len() + 1 + reference.repository().len()
            > MAX_REPOSITORY_NAME_LENGTH
        || reference
            .digest()
            .is_some_and(|d| d.bytes().any(|b| b.is_ascii_uppercase()))
    {
        return Err(ImportError::Malformed(format!(
            "invalid image name {name:?}"
        )));
    }
    // Parsing expands shorthand repositories and supplies :latest. The caller
    // must choose that policy and pass the resulting complete name explicitly.
    if reference.to_string() != name {
        return Err(ImportError::Malformed(format!(
            "image name {name:?} must be fully qualified with an explicit tag or digest; canonical form is {reference}"
        )));
    }
    Ok(reference)
}

pub(super) fn requested(names: &[String], manifest: &OciDigest) -> Result<Vec<String>> {
    let mut unique = Vec::new();
    for name in names {
        let reference = validate(name)?;
        if let Some(digest) = reference.digest()
            && digest != manifest.as_ref()
        {
            return Err(ImportError::DigestMismatch {
                kind: "image name manifest digest",
                expected: digest.to_owned(),
                actual: manifest.to_string(),
            });
        }
        if !unique.contains(name) {
            unique.push(name.clone());
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
    use crate::writer::records::SHA256_HEX_LENGTH;
    use serde_json::json;

    #[test]
    fn image_names_require_complete_canonical_references() {
        let digest = "a".repeat(SHA256_HEX_LENGTH);
        for (name, valid) in [
            ("localhost/example:Release".into(), true),
            ("EXAMPLE.COM/team/image:Release".into(), true),
            ("localhost:5000/team/image:Release".into(), true),
            ("example.com/team/image__name:v1".into(), true),
            ("docker.io/library/alpine:latest".into(), true),
            (format!("localhost/image@sha256:{digest}"), true),
            (format!("localhost/image:Release@sha256:{digest}"), true),
            ("alpine".into(), false),
            ("alpine:latest".into(), false),
            ("team/image:latest".into(), false),
            ("localhost/image".into(), false),
            ("localhost:5000/team/image".into(), false),
            ("docker.io/alpine:latest".into(), false),
            ("index.docker.io/library/alpine:latest".into(), false),
            (format!("image@sha256:{digest}"), false),
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
                format!("localhost/image@sha256:{}", "A".repeat(SHA256_HEX_LENGTH)),
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
    fn requested_names_preserve_references_and_check_manifest_digests() {
        let manifest: OciDigest = format!("sha256:{}", "a".repeat(SHA256_HEX_LENGTH))
            .parse()
            .unwrap();
        assert!(requested(&[], &manifest).unwrap().is_empty());
        let names = vec![
            "localhost/image:Release".into(),
            "localhost:5000/team/image:latest".into(),
            format!("localhost/image@{manifest}"),
            format!("localhost/image:Release@{manifest}"),
        ];
        let duplicated = [names.clone(), names.clone()].concat();
        assert_eq!(requested(&duplicated, &manifest).unwrap(), names);

        let unrelated = format!("sha256:{}", "b".repeat(SHA256_HEX_LENGTH));
        for name in [
            format!("localhost/image@{unrelated}"),
            format!("localhost/image:Release@{unrelated}"),
        ] {
            assert!(matches!(
                requested(&[name], &manifest),
                Err(ImportError::DigestMismatch { kind, expected, actual })
                    if kind == "image name manifest digest"
                        && expected == unrelated && actual == manifest.as_ref()
            ));
        }
    }

    #[test]
    fn missing_image_record_leaves_name_assignments_unchanged() {
        for policy in [NamePolicy::FailOnConflict, NamePolicy::Reassign] {
            let mut images: Vec<ImageRecord> = serde_json::from_value(json!([
                {"id":"old","names":["localhost/example:latest"]}
            ]))
            .unwrap();
            let original = images.clone();
            let result = assign(
                &mut images,
                "new",
                &["localhost/example:latest".into()],
                policy,
            );
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
                {"id":"old","names":["localhost/example:latest","localhost/example:keep"],"custom":42},
                {"id":"new","names":["localhost/example:existing"],"names-history":["localhost/example:two","localhost/example:old"],"mapped-layers":["mapped"]}
            ])).unwrap();
            let original = images.clone();
            let names = requested(
                &[
                    "localhost/example:latest".into(),
                    "localhost/example:two".into(),
                    "localhost/example:latest".into(),
                ],
                &format!("sha256:{}", "a".repeat(SHA256_HEX_LENGTH))
                    .parse()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(names, ["localhost/example:latest", "localhost/example:two"]);
            let result = assign(&mut images, "new", &names, policy);
            if policy == NamePolicy::FailOnConflict {
                assert!(
                    matches!(result, Err(ImportError::NameConflict(name)) if name == "localhost/example:latest")
                );
                assert_eq!(images, original);
            } else {
                result.unwrap();
                assert_eq!(
                    serde_json::to_value(&images).unwrap(),
                    json!([
                        {"id":"old","names":["localhost/example:keep"],"custom":42},
                        {"id":"new","names":["localhost/example:existing","localhost/example:latest","localhost/example:two"],"names-history":["localhost/example:two","localhost/example:latest","localhost/example:old"],"mapped-layers":["mapped"]}
                    ])
                );
            }
        }
    }
}

//! Typed containers/storage records, retaining fields owned by other writers.
//!
//! Known optional nulls have Go's nil/zero meaning and serialize as absent.
//! Explicit empty values and unknown fields (including nulls) are retained.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use crate::writer::{ImportError, Result};

pub(in crate::writer) trait Record: serde::de::DeserializeOwned {
    fn id(&self) -> &str;
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(in crate::writer) struct LayerRecord {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff_digest: Option<String>,
    // Go uses signed sizes, including -1 for a size not yet known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff_size: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compressed_diff_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compressed_size: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compression: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uidset: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gidset: Option<Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uidmap: Option<Vec<IdMapping>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gidmap: Option<Vec<IdMapping>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<LayerFlags>,
    #[serde(flatten)]
    pub other: Map<String, Value>,
}

impl Record for LayerRecord {
    fn id(&self) -> &str {
        &self.id
    }
}

impl LayerRecord {
    pub fn parent(&self) -> &str {
        self.parent.as_deref().unwrap_or_default()
    }

    pub fn is_incomplete(&self) -> bool {
        self.flags.as_ref().and_then(|flags| flags.incomplete) == Some(true)
    }

    pub fn check_flags(&self) -> Result<()> {
        if let Some(flags) = &self.flags
            && let Some(key) = flags.other.keys().next()
        {
            return Err(ImportError::UnsupportedStore(format!(
                "unsupported layer flag {key}"
            )));
        }
        Ok(())
    }

    pub fn is_reusable(&self) -> bool {
        self.uidmap.as_ref().is_none_or(Vec::is_empty)
            && self.gidmap.as_ref().is_none_or(Vec::is_empty)
            && self.check_flags().is_ok()
    }

    pub fn uncompressed_size(&self) -> Option<u64> {
        // A negative Go size is unknown, rather than reusable byte accounting.
        self.diff_size.and_then(|size| size.try_into().ok())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(in crate::writer) struct LayerFlags {
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub incomplete: Option<bool>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_layer_diffid: Option<String>,
    #[serde(flatten)]
    pub other: Map<String, Value>,
}

// These known flags may be absent, but an explicitly supplied null is invalid.
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(in crate::writer) struct IdMapping {
    pub container_id: i64,
    pub host_id: i64,
    pub size: i64,
    #[serde(flatten)]
    pub other: Map<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(in crate::writer) struct ImageRecord {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub names_history: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mapped_layers: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub big_data_names: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub big_data_sizes: Option<BTreeMap<String, i64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub big_data_digests: Option<BTreeMap<String, String>>,
    #[serde(flatten)]
    pub other: Map<String, Value>,
}

impl Record for ImageRecord {
    fn id(&self) -> &str {
        &self.id
    }
}

impl ImageRecord {
    pub fn layer(&self) -> &str {
        self.layer.as_deref().unwrap_or_default()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(in crate::writer) struct ContainerRecord {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layer: Option<String>,
    #[serde(flatten)]
    pub other: Map<String, Value>,
}

impl Record for ContainerRecord {
    fn id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(in crate::writer) struct MountRecord {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
    #[serde(flatten)]
    pub other: Map<String, Value>,
}

impl Record for MountRecord {
    fn id(&self) -> &str {
        &self.id
    }
}

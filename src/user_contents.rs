use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::PartialEq;
use std::collections::BTreeMap;
use std::default::Default;

use crate::util::is_default;

#[derive(Serialize, Debug, Deserialize, Default, PartialEq, Eq, Clone)]
#[serde(default)]
pub struct UserContents {
    pub archived: BTreeMap<String, usize>,
    pub archived_before: usize,
    pub cert_signers: BTreeMap<String, Vec<String>>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub cert_signers_pattern: String,
    pub permission_rules: BTreeMap<String, PermissionRulesType>,
    pub permissions: BTreeMap<String, PermissionRulesType>,
    pub content_inner_path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub relative_path: String,
    #[serde(flatten)]
    pub optional: Optional,
    #[serde(flatten)]
    #[serde(skip_serializing_if = "is_decentnet_serialization")]
    pub data: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize, Default, PartialEq, Eq, Clone)]
pub struct Optional {
    pub optional: Option<String>,
}

impl Serialize for Optional {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[cfg(feature = "decentnet-toml")]
        let skip_serialization = false;
        #[cfg(not(feature = "decentnet-toml"))]
        let skip_serialization = false;
        let mut s = serializer.serialize_struct(
            "Optional",
            false as usize + if skip_serialization { 0 } else { 1 },
        )?;
        if !skip_serialization {
            s.serialize_field("optional", &self.optional)?;
        }
        s.end()
    }
}

fn is_decentnet_serialization<T: Default + PartialEq>(_: &T) -> bool {
    #[cfg(feature = "decentnet-toml")]
    return true;
    #[cfg(not(feature = "decentnet-toml"))]
    false
}

#[derive(Serialize, Debug, Deserialize, PartialEq, Eq, Clone)]
#[serde(untagged)]
pub enum PermissionRulesType {
    None(bool),
    Rules(PermissionRules),
}

impl Default for PermissionRulesType {
    fn default() -> Self {
        PermissionRulesType::None(false)
    }
}

#[derive(Serialize, Debug, Deserialize, Default, PartialEq, Eq, Clone)]
#[serde(default)]
pub struct PermissionRules {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub files_allowed: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub files_allowed_optional: String,
    #[serde(skip_serializing_if = "is_default")]
    pub max_size: usize,
    #[serde(skip_serializing_if = "is_default")]
    pub max_size_optional: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub signers: Vec<String>,
}

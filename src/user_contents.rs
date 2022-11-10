use serde::{Deserialize, Serialize};
use std::cmp::PartialEq;
use std::collections::BTreeMap;
use std::default::Default;

#[derive(Serialize, Deserialize, Default, PartialEq, Clone)]
#[serde(default)]
pub struct UserContents {
    pub archived: BTreeMap<String, usize>,
    pub archived_before: usize,
    pub cert_signers: BTreeMap<String, Vec<String>>,
    pub cert_signers_pattern: String,
    pub permission_rules: BTreeMap<String, PermissionRulesType>,
    pub permissions: BTreeMap<String, PermissionRulesType>,
    pub content_inner_path: String,
    pub optional: String,
    pub relative_path: String,
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
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

#[derive(Serialize, Deserialize, Default, PartialEq, Clone)]
#[serde(default)]
pub struct PermissionRules {
    pub files_allowed: String,
    pub files_allowed_optional: String,
    pub max_size: usize,
    pub max_size_optional: usize,
    pub signers: Vec<String>,
}

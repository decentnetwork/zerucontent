use serde::{Deserialize, Serialize};
use std::cmp::PartialEq;
use std::collections::BTreeMap;
use std::default::Default;

#[derive(Serialize, Deserialize, Default, PartialEq, Clone)]
pub struct UserContents {
    pub archived: BTreeMap<String, usize>,
    pub archived_before: usize,
    pub cert_signers: BTreeMap<String, Vec<String>>,
    pub cert_signers_pattern: String,
    pub permission_rules: BTreeMap<String, Option<PermissionRules>>,
    pub permissions: BTreeMap<String, Option<PermissionRules>>,
    pub content_inner_path: String,
    pub optional: Option<String>,
    pub relative_path: String,
}

#[derive(Serialize, Deserialize, Default, PartialEq, Clone)]
pub struct PermissionRules {
    files_allowed: Option<String>,
    files_allowed_optional: Option<String>,
    max_size: usize,
    max_size_optional: usize,
    signers: Vec<String>,
}

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
    pub permission_rules: BTreeMap<String, PermissionRules>,
    pub permissions: BTreeMap<String, PermissionRules>,
}

#[derive(Serialize, Deserialize, Default, PartialEq, Clone)]
pub struct PermissionRules {
    files_allowed: String,
    max_size: usize,
}

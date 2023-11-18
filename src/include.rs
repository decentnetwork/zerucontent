use crate::util::is_default;
use serde::{Deserialize, Serialize};
use std::cmp::PartialEq;
use std::default::Default;

#[derive(Serialize, Deserialize, Default, PartialEq, Clone)]
#[serde(default)]
pub struct Include {
    pub signers: Vec<String>,
    #[serde(skip_serializing_if = "is_default")]
    pub signers_required: u64,
    #[serde(skip_serializing_if = "is_default")]
    pub files_allowed: String,
    #[serde(skip_serializing_if = "is_default")]
    pub includes_allowed: bool,
    #[serde(skip_serializing_if = "is_default")]
    pub max_size: u64,
}

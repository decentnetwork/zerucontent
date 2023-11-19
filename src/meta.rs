use serde::{Deserialize, Serialize};

use crate::util::is_default;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Meta {
    #[serde(skip_serializing_if = "is_default")]
    pub inner_path: String,
    // #[serde(skip_serializing_if = "is_default")]
    pub description: Option<String>,
    pub zeronet_version: Option<String>,
}

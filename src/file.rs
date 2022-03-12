use serde::{Deserialize, Serialize};
use std::cmp::PartialEq;
use std::default::Default;

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Clone)]
pub struct File {
    pub sha512: String,
    pub size: usize,
}

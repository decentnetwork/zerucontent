use serde::{Deserialize, Serialize};
use std::cmp::PartialEq;
use std::default::Default;
use std::fmt::Debug;

#[derive(Serialize, Deserialize, Default, PartialEq, Clone)]
pub struct File {
    pub sha512: String,
    pub size: usize,
}

impl Debug for File {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "File Stats: sha512: {}, size: {}",
            self.sha512, self.size
        )
    }
}

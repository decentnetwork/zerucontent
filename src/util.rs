use std::default::Default;

use serde::{Deserialize, Serialize};

pub fn is_default<T: Default + PartialEq>(t: &T) -> bool {
    t == &T::default()
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Number {
    Integer(usize),
    Float(f64),
}

impl Default for Number {
    fn default() -> Self {
        Number::Integer(0)
    }
}

use std::default::Default;

use serde::{Deserialize, Serialize};

pub fn is_default<T: Default + PartialEq>(t: &T) -> bool {
    t == &T::default()
}

#[derive(Serialize, Deserialize, Clone, Debug)]
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

impl From<Number> for usize {
    fn from(n: Number) -> Self {
        match n {
            Number::Integer(i) => i,
            Number::Float(f) => f as usize,
        }
    }
}

impl From<u64> for Number {
    fn from(i: u64) -> Self {
        Number::Integer(i as usize)
    }
}

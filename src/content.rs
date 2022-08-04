use std::{collections::BTreeMap, default::Default, time::SystemTime};

use json_filter_sorted::sort::sort_json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    util::{is_default, Number},
    zeruformatter, File, Include, UserContents,
};

#[derive(Serialize, Deserialize, Default, Clone)]
#[serde(default)]
pub struct Content {
    pub address: String,

    #[serde(skip_serializing_if = "is_default")]
    pub address_index: u32,
    #[serde(skip_serializing_if = "is_default")]
    pub domain: String,
    #[serde(skip_serializing_if = "is_default")]
    pub title: String,
    #[serde(skip_serializing_if = "is_default")]
    pub description: String,
    #[serde(skip_serializing_if = "is_default")]
    pub favicon: String,

    pub files: BTreeMap<String, File>,
    #[serde(skip_serializing_if = "is_default")]
    pub files_optional: BTreeMap<String, File>,

    #[serde(skip_serializing_if = "is_default")]
    pub cloneable: bool,
    #[serde(skip_serializing_if = "is_default")]
    pub cloned_from: String,
    #[serde(skip_serializing_if = "is_default")]
    pub clone_root: String,

    #[serde(rename = "background-color")]
    #[serde(skip_serializing_if = "is_default")]
    pub background_color: String,

    #[serde(rename = "background-color-dark")]
    #[serde(skip_serializing_if = "is_default")]
    pub background_color_dark: String,

    #[serde(skip_serializing_if = "is_default")]
    pub viewport: String,
    #[serde(skip_serializing_if = "is_default")]
    pub translate: Vec<String>,

    #[serde(skip_serializing_if = "is_default")]
    pub user_contents: Option<UserContents>,

    pub ignore: String,
    #[serde(skip_serializing_if = "is_default")]
    pub inner_path: String,
    pub modified: Number, //TODO! This need to be f64 for older content.json format
    #[serde(skip_serializing_if = "is_default")]
    pub postmessage_nonce_security: bool,

    #[serde(skip_serializing_if = "is_default")]
    sign: Vec<f64>, // DEPRECATED
    #[serde(skip_serializing_if = "is_default")]
    pub signers_sign: String,
    #[serde(skip_serializing_if = "is_default")]
    pub signs: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "is_default")]
    pub signs_required: usize,

    #[serde(skip_serializing_if = "is_default")]
    pub includes: BTreeMap<String, Include>,
    #[serde(skip_serializing_if = "is_default")]
    pub merged_type: String,
    #[serde(skip_serializing_if = "is_default")]
    pub optional: String,

    #[serde(skip_serializing_if = "is_default")]
    pub settings: BTreeMap<String, serde_json::Value>,

    #[serde(flatten)]
    other: BTreeMap<String, Value>,
    pub zeronet_version: String,

    #[serde(skip_serializing, skip_deserializing)]
    _raw: Value,
}

pub fn dump<T: Serialize>(value: T) -> Result<String, serde_json::error::Error> {
    zeruformatter::to_string_zero(
        &sort_json(json!(value))
            .unwrap()
            .as_object()
            .map(|x| x.to_owned())
            .unwrap(),
    )
}

impl Content {
    pub fn create(address: String, address_index: u32) -> Content {
        Content {
            title: address.to_owned(),
            address,
            address_index,
            modified: Number::Integer(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as usize,
            ),
            inner_path: "content.json".to_owned(),
            postmessage_nonce_security: true,
            ..Default::default()
        }
    }

    pub fn from_buf(buf: serde_bytes::ByteBuf) -> Result<Content, ()> {
        let _raw: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        let content = match serde_json::from_slice(&buf) {
            Ok(c) => c,
            Err(_) => return Err(()),
        };
        let content = Content { _raw, ..content };
        Ok(content)
    }

    pub fn raw(&self) -> &serde_json::Value {
        &self._raw
    }

    fn cleared(&self) -> Content {
        let mut new_content = self.clone();
        new_content.signs = BTreeMap::new();
        new_content.sign = vec![];
        new_content
    }

    fn dump(&self) -> Result<String, serde_json::error::Error> {
        zeruformatter::to_string_zero(
            &sort_json(json!(self.cleared()))
                .unwrap()
                .as_object()
                .map(|x| x.to_owned())
                .unwrap(),
        )
    }

    fn dump_value(value: Value) -> Result<String, serde_json::error::Error> {
        zeruformatter::to_string_zero(
            &sort_json(value)
                .unwrap()
                .as_object()
                .map(|x| x.to_owned())
                .unwrap(),
        )
    }

    // TODO: verify should probably return more than just a bool
    pub fn verify(&self, key: String) -> bool {
        let mut raw = self._raw.clone();
        let map = raw.as_object_mut().unwrap();
        map.remove("signs");
        map.remove("sign");
        let signature = match self.signs.get(&key) {
            Some(v) => v,
            None => return false,
        };
        let result = zeronet_cryptography::verify(
            Self::dump_value(raw).unwrap().as_bytes(),
            &key,
            &signature,
        );
        result.is_ok()
    }

    pub fn sign(&self, privkey: String) -> String {
        zeronet_cryptography::sign(self.dump().unwrap().as_bytes(), &privkey).unwrap()
    }

    pub fn get_file(&self, inner_path: &str) -> Option<File> {
        if let Some(f) = self.files.get(inner_path) {
            return Some(f.clone());
        } else if let Some(f) = self.files_optional.get(inner_path) {
            return Some(f.clone());
        }
        None
    }
}

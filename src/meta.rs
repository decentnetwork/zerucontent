use serde::Deserialize;

use serde::ser::{Serialize, SerializeStruct};

#[derive(Deserialize, Debug, Clone, Default)]
pub struct Meta {
    pub inner_path: String,
    // #[serde(skip_serializing_if = "is_default")]
    pub description: Option<String>,
    pub zeronet_version: Option<String>,
}

impl Serialize for Meta {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct(
            "Meta",
            false as usize
                + 1
                + self.description.is_some() as usize
                + self.zeronet_version.is_some() as usize,
        )?;
        if let Some(ref description) = self.description {
            s.serialize_field("description", description)?;
        }
        if let Some(ref zeronet_version) = self.zeronet_version {
            s.serialize_field("zeronet_version", zeronet_version)?;
        }
        s.end()
    }
}

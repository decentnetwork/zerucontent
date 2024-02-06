use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Cert {
    #[serde(rename = "cert_auth_type")]
    pub auth_type: String,

    #[serde(rename = "cert_sign")]
    pub sign: String,

    #[serde(rename = "cert_user_id")]
    pub user_id: String,
}

impl Cert {
    pub fn verify(&self, address: &str, key: &str) -> bool {
        let user_id = self.user_id.split('@').next().unwrap();
        let msg = format!("{}#{}/{}", address, self.auth_type, user_id);
        zeronet_cryptography::verify(msg.as_bytes(), key, &self.sign).is_ok()
    }
}

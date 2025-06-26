use std::str::FromStr;

use base64::{Engine, engine::general_purpose};
use color_eyre::eyre::Result;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum MsgData {
    Unlock(UnlockData),
    Stop,
    Encrypt(CryptData),
    Decrypt(CryptData),
}

/// Unlock message body format.
#[derive(Serialize, Deserialize, Debug)]
pub struct UnlockData {
    pub username: String,
    pub password: String,
}

/// Crypto call message body format.
#[derive(Serialize, Deserialize, Debug)]
pub struct CryptData {
    pub data: String,
}

impl CryptData {
    #[allow(dead_code)]
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let data = general_purpose::URL_SAFE.decode(&self.data)?;
        Ok(data)
    }
}

impl MsgData {
    #[allow(dead_code)]
    pub fn pack(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }
}

impl ToString for MsgData {
    #[inline]
    fn to_string(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

impl FromStr for MsgData {
    type Err = serde_json::error::Error;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

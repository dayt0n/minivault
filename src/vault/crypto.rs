use std::num::ParseIntError;

use aes_gcm::{
    Aes256Gcm,
    aead::{Nonce, OsRng},
};
use argon2::{Argon2, RECOMMENDED_SALT_LEN, password_hash::SaltString};
use base64::{Engine, engine::general_purpose};
use color_eyre::eyre::{Result, eyre};

#[inline]
pub fn password_to_key(password: String, salt: Option<Vec<u8>>) -> Result<([u8; 32], Vec<u8>)> {
    let realsalt = if let Some(some_salt) = salt {
        some_salt
    } else {
        let mut salt = [0u8; RECOMMENDED_SALT_LEN];
        let _ = SaltString::generate(OsRng).decode_b64(&mut salt);
        salt.to_vec()
    };
    let mut output = [0u8; 32];
    if Argon2::default()
        .hash_password_into(password.as_bytes(), &realsalt, &mut output)
        .is_ok()
    {
        return Ok((output, realsalt));
    }
    Err(eyre!("unable to hash password"))
}

#[allow(dead_code)]
fn to_hex_string(arr: Vec<u8>) -> String {
    arr.iter().map(|b| format!("{:x?}", b)).collect()
}

#[allow(dead_code)]
fn from_hex_string(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

#[inline]
pub fn to_b64_string(arr: Vec<u8>) -> String {
    let mut result = String::new();
    general_purpose::URL_SAFE.encode_string(arr, &mut result);
    result
}

#[inline]
pub fn from_b64_string(data: &str) -> Result<Vec<u8>> {
    Ok(general_purpose::URL_SAFE.decode(data)?)
}

#[inline]
// Convert encrypted data and nonce to a parsable string.
pub fn to_vault_string(encrypted_data: Vec<u8>, nonce: Nonce<Aes256Gcm>) -> String {
    to_b64_string(encrypted_data).to_owned() + ":" + &to_b64_string(nonce.to_vec())
}

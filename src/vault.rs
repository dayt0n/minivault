use std::{fs, ops::Deref, path::PathBuf};

use aes_gcm::{
    AeadCore, Aes256Gcm, Key, KeyInit,
    aead::{Aead, Nonce, OsRng},
};
use color_eyre::eyre::{Result, eyre};
use crypto::{from_b64_string, password_to_key, to_b64_string, to_vault_string};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use util::{prompt, prompt_or_get};

pub mod crypto;
pub mod util;

#[derive(Serialize, Deserialize, Debug, Clone)]
enum UserKeyType {
    Password,
    PublicKey,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PasswordData {
    encrypted_data: String,
    nonce: String,
    salt: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct PubKeyData {
    encrypted_data: String,
    public_key: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(transparent)]
struct KDWrapper(#[serde(with = "serde_yaml::with::singleton_map")] KeyData);

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
enum KeyData {
    PubKey(PubKeyData),
    Password(PasswordData),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct User {
    #[serde(skip)]
    username: String,
    // SSH public key or hashed password
    key: KDWrapper,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Vault {
    users: FxHashMap<String, User>,
    #[serde(skip, default)]
    key: Option<Box<[u8]>>,
}

impl Vault {
    /// Read in Vault data from YAML file.
    pub fn from(file: &PathBuf) -> Result<Vault> {
        if !file.is_file() {
            return Err(eyre!("Vault data at {:?} does not exist!", file));
        }
        let data = fs::read_to_string(file)?;
        let v: Vault = serde_yaml::from_str(&data)?;
        Ok(v)
    }

    /// Create a new vault with an initial username and password.
    pub fn new_with_password<T: AsRef<str>>(username: T, password: T) -> Result<Vault> {
        Self::new(username, Some(password), None)
    }

    fn new<T: AsRef<str>>(username: T, password: Option<T>, pubkey: Option<T>) -> Result<Vault> {
        // generate master AES key
        let masterkey = Aes256Gcm::generate_key(OsRng).to_vec();
        let admin_keytype;
        if password.is_some() {
            admin_keytype = UserKeyType::Password;
        } else if pubkey.is_some() {
            admin_keytype = UserKeyType::PublicKey;
        } else {
            return Err(eyre!("Specify either a public key or a password!"));
        }
        // create first (admin) user/key
        // encrypt master asymmetric (private) key with user pubkey||password
        let user = match admin_keytype {
            UserKeyType::Password => {
                let passwd = password.unwrap();
                Self::new_user_data(
                    username.as_ref().to_string(),
                    passwd.as_ref().to_string(),
                    masterkey,
                )?
            }
            UserKeyType::PublicKey => todo!("public key encryption has not beeen implemented yet"),
        };
        let mut users = FxHashMap::default();
        users.insert(user.username.clone(), user);
        let v = Vault { key: None, users };
        Ok(v)
    }

    /// Createa a new vault with a username and password, interactively.
    pub fn new_interactive_with_password() -> Result<Vault> {
        let username = prompt("New admin username");
        let mut password;
        loop {
            password = rpassword::prompt_password("New password: ")?;
            let confirm_password = rpassword::prompt_password("Confirm password: ")?;
            if password == confirm_password {
                break;
            }
            eprintln!("Passwords do not match!");
        }

        Self::new_with_password(username, password)
    }

    /// Creates a new user object containing the encrypted masterkey.
    fn new_user_data(username: String, password: String, masterkey: Vec<u8>) -> Result<User> {
        let (user_key, user_salt) = password_to_key(password, None)?;
        let aes_user_key: &Key<Aes256Gcm> = &user_key.into();
        let cipher = Aes256Gcm::new(aes_user_key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        if let Ok(encrypted_master) = cipher.encrypt(&nonce, masterkey.as_slice()) {
            let userkeydata = KDWrapper(KeyData::Password(PasswordData {
                encrypted_data: to_b64_string(encrypted_master),
                nonce: to_b64_string(nonce.to_vec()),
                salt: to_b64_string(user_salt),
            }));
            return Ok(User {
                username,
                key: userkeydata,
            });
        }
        Err(eyre!("Unable to encrypt master key!"))
    }

    /// Verify username and password combination, returning the master key.
    fn verify_user(user: &User, password: Option<String>) -> Result<Vec<u8>> {
        match &user.key.0 {
            KeyData::Password(data) => {
                let salt = from_b64_string(&data.salt)?;
                let encrypted_key = from_b64_string(&data.encrypted_data)?;
                let nonce = from_b64_string(&data.nonce)?;
                let (key_from_password, _salt) =
                    password_to_key(password.clone().unwrap(), Some(salt))?;
                let cipher = Aes256Gcm::new(&key_from_password.into());
                if let Ok(decrypted_master) =
                    cipher.decrypt(nonce.as_slice().into(), encrypted_key.as_slice())
                {
                    return Ok(decrypted_master);
                }
            }
            KeyData::PubKey(_) => {
                todo!("public key encryption has not been implemented yet")
            }
        }
        Err(eyre!("user verification failed!"))
    }

    /// Loads the master key into vault memory.
    fn load_key<T: AsRef<str>>(
        &mut self,
        username: T,
        password: Option<String>,
        _key_password: Option<T>,
    ) -> Result<()> {
        if self.is_unlocked() {
            return Ok(());
        }
        // TODO: have logic to use key_password if SSH key needs it
        if let Some(user) = self.users.get(&username.as_ref().to_string()) {
            if let Ok(key) = Self::verify_user(user, password) {
                self.key = Some(key.into());
                return Ok(());
            } else {
                return Err(eyre!("Incorrect password!"));
            }
        }
        Err(eyre!("unable to load key"))
    }

    /// Unlock the vault with a username and password combination.
    pub fn unlock<T: AsRef<str>>(&mut self, username: T, password: T) -> Result<()> {
        self.load_key(username.as_ref(), Some(password.as_ref().to_string()), None)
    }

    /// Write out Vault data to a YAML file.
    pub fn write(&mut self, filepath: &PathBuf) -> Result<()> {
        let data = serde_yaml::to_string(self)?;
        Ok(fs::write(filepath, data)?)
    }

    /// Returns whether vault is locked or not.
    pub fn is_unlocked(&self) -> bool {
        self.key.is_some()
    }

    /// Lock vault.
    pub fn lock(&mut self) {
        self.key = None;
    }

    /// Add user to vault using an existing username and password.
    pub fn add_user(
        &mut self,
        existing_username: String,
        existing_password: String,
        new_username: String,
        new_password: String,
    ) -> Result<String> {
        if self.users.contains_key(&new_username) {
            return Err(eyre!("User {} already exists!", new_username));
        }
        if let Some(user) = self.users.get(&existing_username) {
            if let Ok(key) = Self::verify_user(user, Some(existing_password)) {
                let new_user = Self::new_user_data(new_username.clone(), new_password, key)?;
                self.users
                    .insert(new_user.username.clone(), new_user.clone());
                return Ok(new_user.username);
            }
            return Err(eyre!("Incorrect password!"));
        }
        Err(eyre!("user {} does not exist!", existing_username))
    }

    /// Add user to vault using an existing username and password, interactively.
    pub fn add_user_interactive(&mut self, current_username: Option<String>) -> Result<String> {
        let username = prompt_or_get(current_username, "Existing user");
        if !self.users.contains_key(&username) {
            return Err(eyre!("user {} does not exist!", username));
        }
        let current_password = rpassword::prompt_password(format!("{}'s password: ", username))?;
        if let Some(user) = self.users.get(&username) {
            if Self::verify_user(user, Some(current_password.clone())).is_ok() {
                // create user
                println!("verified {}!", username);
                let mut new_username;
                loop {
                    new_username = prompt("New username");
                    if !self.users.contains_key(&new_username) {
                        break;
                    }
                    eprintln!(
                        "User {} already exists! Choose a different username.",
                        new_username
                    );
                }
                let mut new_password;
                loop {
                    new_password =
                        rpassword::prompt_password(format!("{}'s new password: ", new_username))?;
                    if new_password == rpassword::prompt_password("Confirm password: ")? {
                        break;
                    }
                    eprintln!("Passwords do not match!");
                }
                return self.add_user(username, current_password, new_username, new_password);
            }
            return Err(eyre!("Incorrect password!"));
        }
        Err(eyre!("unable to add user"))
    }

    /// Change password for existing user in vault.
    pub fn change_password(
        &mut self,
        username: String,
        password: String,
        new_password: String,
    ) -> Result<String> {
        if let Some(user) = self.users.get_mut(&username) {
            if let Ok(key) = Self::verify_user(user, Some(password)) {
                let new_data = Self::new_user_data(username.clone(), new_password, key)?;
                user.key = new_data.key;
                return Ok(username);
            }
            return Err(eyre!("Incorrect password!"));
        }
        Err(eyre!("User '{}' does not exist!", username))
    }

    /// Change password for existing user in vault, interactively.
    pub fn change_password_interactive(&mut self, username: Option<String>) -> Result<String> {
        let username = prompt_or_get(username, "Username");
        if !self.users.contains_key(&username) {
            return Err(eyre!("User '{}' does not exist!", username));
        }
        let password = rpassword::prompt_password("Current password: ")?;
        let user = self.users.get(&username).unwrap();
        if Self::verify_user(user, Some(password.clone())).is_ok() {
            let mut new_password;
            loop {
                new_password = rpassword::prompt_password("New password: ")?;
                if new_password == rpassword::prompt_password("Confirm password: ")? {
                    break;
                }
                eprintln!("Passwords do not match!");
            }
            return self.change_password(username, password, new_password);
        }
        Err(eyre!("Incorrect password!"))
    }

    // Decrypt encrypted data and nonce into bytes.
    #[inline]
    pub fn decrypt_raw(
        &self,
        encrypted_data: Vec<u8>,
        nonce: &Nonce<Aes256Gcm>,
    ) -> Result<Vec<u8>> {
        if let Some(mkey) = &self.key {
            let cipher = Aes256Gcm::new(mkey.deref().into());
            if let Ok(decrypted) = cipher.decrypt(nonce, encrypted_data.as_slice()) {
                return Ok(decrypted);
            }
            return Err(eyre!("unable to decrypt data"));
        }
        Err(eyre!("vault is locked!"))
    }

    /// Decrypt data in a vault string, returning bytes.
    #[inline]
    pub fn decrypt<T: AsRef<str>>(&self, data: T) -> Result<Vec<u8>> {
        let data: Vec<&str> = data.as_ref().splitn(2, ":").collect();
        let (encrypted_data, nonce) = (from_b64_string(data[0])?, from_b64_string(data[1])?);
        self.decrypt_raw(encrypted_data, nonce.as_slice().into())
    }

    /// Decrypt data in a vault string, returning base64 data.
    #[inline]
    pub fn decrypt_to_base64<T: AsRef<str>>(&self, data: T) -> Result<String> {
        match self.decrypt(data) {
            Ok(plaintext) => Ok(to_b64_string(plaintext)),
            Err(e) => Err(e),
        }
    }

    /// Encrypt plaintext base64 data, returning an encrypted vault string.
    #[inline]
    pub fn encrypt_from_base64<T: AsRef<str>>(&self, data: T) -> Result<String> {
        self.encrypt(from_b64_string(data.as_ref())?.as_slice())
    }

    // Encrypt raw bytes to a ciphertext and nonce.
    #[inline]
    pub fn encrypt_raw(&self, data: &[u8]) -> Result<(Vec<u8>, Nonce<Aes256Gcm>)> {
        if let Some(mkey) = &self.key {
            let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
            let cipher = Aes256Gcm::new(mkey.deref().into());
            if let Ok(encrypted) = cipher.encrypt(&nonce, data) {
                return Ok((encrypted, nonce));
            }
            return Err(eyre!("unable to encrypt!"));
        }
        Err(eyre!("vault is locked!"))
    }

    /// Encrypt raw bytes, returning an encrypted vault string.
    #[inline]
    pub fn encrypt(&self, data: &[u8]) -> Result<String> {
        let (encrypted, nonce) = self.encrypt_raw(data)?;
        Ok(to_vault_string(encrypted, nonce))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto() -> Result<()> {
        let username = "admin";
        let password = "password";
        let mut vault = Vault::new_with_password(username, password)?;
        vault.unlock(username, password)?;
        let plaintext = String::from("minivault test").into_bytes();
        let b64ciphertext = vault.encrypt_from_base64(&to_b64_string(plaintext.clone()))?;
        let ciphertext = vault.encrypt(&plaintext.clone())?;
        // ensure pt != ct
        assert_ne!(plaintext, ciphertext.clone().into_bytes());
        // ensure ciphertext is of format 'encrypted_data:nonce'
        let s: Vec<_> = ciphertext.split(":").collect();
        assert!(s.len() == 2);
        // make sure decryption works
        assert_eq!(
            from_b64_string(&vault.decrypt_to_base64(&ciphertext)?)?,
            plaintext
        );
        assert_eq!(
            from_b64_string(&vault.decrypt_to_base64(&b64ciphertext)?)?,
            plaintext
        );
        Ok(())
    }

    #[test]
    fn test_lock_unlock() -> Result<()> {
        let username = String::from("admin");
        let password = String::from("password");
        let mut vault = Vault::new_with_password(username.clone(), password.clone())?;
        // check vault starts locked
        assert!(!vault.is_unlocked());
        let plaintext = String::from("minivault test").into_bytes();
        // check encryption can't happen while locked
        assert!(vault.encrypt(&plaintext.clone()).is_err());
        // check unlock doesn't work with incorrect password
        assert!(
            vault
                .unlock(username.clone(), String::from("incorrect password"))
                .is_err()
        );
        assert!(!vault.is_unlocked());
        // check unlock doesn't work with wrong user
        assert!(
            vault
                .unlock(String::from("nonexistent_username"), password.clone())
                .is_err()
        );
        assert!(!vault.is_unlocked());
        vault.unlock(username, password)?;
        // check if unlock works with correct username/password
        assert!(vault.is_unlocked());
        let ciphertext = vault.encrypt(&plaintext)?;
        vault.lock();
        // check if lock() works
        assert!(!vault.is_unlocked());
        // make sure decryption can't happen while locked
        assert!(vault.decrypt_to_base64(&ciphertext).is_err());
        Ok(())
    }

    #[test]
    fn test_differing_vaults() -> Result<()> {
        let username = String::from("admin");
        let password = String::from("password");
        let mut vault1 = Vault::new_with_password(username.clone(), password.clone())?;
        let mut vault2 = Vault::new_with_password(username.clone(), password.clone())?;
        vault1.unlock(username.clone(), password.clone())?;
        vault2.unlock(username, password)?;
        let plaintext = String::from("minivault test").into_bytes();
        let ciphertext = vault1.encrypt(&plaintext.clone())?;
        // make sure 2 vaults with the same credentials can't decrypt each other's data
        assert!(vault2.decrypt_to_base64(&ciphertext).is_err());
        Ok(())
    }

    #[test]
    fn test_add_user() -> Result<()> {
        let username = String::from("admin");
        let password = String::from("password");
        let mut vault = Vault::new_with_password(username.clone(), password.clone())?;
        // make sure we can't create a new user with the same username
        assert!(
            vault
                .add_user(
                    username.clone(),
                    password.clone(),
                    username.clone(),
                    String::from("overwrite test password")
                )
                .is_err()
        );
        let new_username = String::from("bob");
        let new_password = String::from("alice");
        vault.add_user(
            username.clone(),
            password.clone(),
            new_username.clone(),
            new_password.clone(),
        )?;
        // ensure new user actually exists
        assert!(vault.users.contains_key(&new_username));
        vault.unlock(new_username.clone(), new_password.clone())?;
        // ensure user can unlock vault
        assert!(vault.is_unlocked());
        vault.lock();
        assert!(!vault.is_unlocked());
        vault.unlock(username, password)?;
        // ensure first user can still unlock
        assert!(vault.is_unlocked());
        Ok(())
    }

    #[test]
    fn test_change_password() -> Result<()> {
        let username = String::from("admin");
        let password = String::from("password");
        let mut vault = Vault::new_with_password(username.clone(), password.clone())?;
        // make sure user can unlock before password change
        vault.unlock(username.clone(), password.clone())?;
        assert!(vault.is_unlocked());
        vault.lock();
        let new_password = String::from("new_password");
        vault.change_password(username.clone(), password.clone(), new_password.clone())?;
        // ensure old password no longer unlocks vault
        assert!(vault.unlock(username.clone(), password.clone()).is_err());
        vault.unlock(username.clone(), new_password)?;
        // ensure new password unlocks vault
        assert!(vault.is_unlocked());
        Ok(())
    }
}

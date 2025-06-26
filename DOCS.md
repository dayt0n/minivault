# minivault

While minivault is primarily a CLI tool, it does expose some functionality as a crate.

```rust
use minivault::vault;
use minivault::server;
use minivault::client;
// Or
use minivault::*;
```

## Creating a new in-memory, lockable vault
New vaults require an initial username / password combination:

```rust
use minivault::vault::Vault;
# use color_eyre::eyre::{Result, eyre};

// ...
# fn main() -> Result<()> {
let username = "admin";
let password = "password";
// Create a new vault with an initial username and password.
let mut vault = Vault::new_with_password(username, password)?;
// Unlock the vault with the new username/password.
vault.unlock(username, password)?;
# Ok(())
# }
```

## Encrypting data
Using the `vault` created in the last example, we can encrypt a simple string of data like so:

```rust
use aes_gcm::{Aes256Gcm, aead::Nonce};

# use color_eyre::eyre::{Result, eyre};
# use minivault::vault::Vault;
# fn main() -> Result<()> {
# let username = "admin";
# let password = "password";
# let mut vault = Vault::new_with_password(username, password)?;
# vault.unlock(username, password)?;
// ...
let plaintext: Vec<u8> = String::from("minivault test").into_bytes();
// This creates a "vault string", which is just the base64 encrypted data 
//   and base64 nonce separated by a colon.
let ciphertext: String = vault.encrypt(&plaintext.clone())?;
// You can optionally just pull the encrypted data and nonce into your 
//   application without using a vault string.
let (encrypted_data, nonce): (Vec<u8>, Nonce<Aes256Gcm>) = vault.encrypt_raw(&plaintext)?;
# Ok(())
# }
```

## Decrypting data
To decrypt a vault string or raw data, such as the ones from the above example, you can do the following:

```rust
# use aes_gcm::{Aes256Gcm, aead::Nonce};
# use color_eyre::eyre::{Result, eyre};
# use minivault::vault::Vault;
# fn main() -> Result<()> {
# let username = "admin";
# let password = "password";
# let mut vault = Vault::new_with_password(username, password)?;
# vault.unlock(username, password)?;
# let plaintext: Vec<u8> = String::from("minivault test").into_bytes();
# let ciphertext: String = vault.encrypt(&plaintext.clone())?;
# let (encrypted_data, nonce): (Vec<u8>, Nonce<Aes256Gcm>) = vault.encrypt_raw(&plaintext)?;
// Decrypt a vault string.
let decrypted_data: Vec<u8> = vault.decrypt(ciphertext)?;
// Decrypt raw data with nonce.
let decrypted_raw_data: Vec<u8> = vault.decrypt_raw(encrypted_data, &nonce)?;
# Ok(())
# }
```
use std::path::PathBuf;

use clap::Parser;
use color_eyre::eyre::Result;

use crate::vault::Vault;

#[derive(Parser, Debug, Clone)]
pub struct ChangePasswordArgs {
    #[arg(short, long)]
    vault: PathBuf,
    #[arg(short, long)]
    /// existing user with which to add new user
    username: Option<String>,
}

impl ChangePasswordArgs {
    pub async fn exec(&self) -> Result<()> {
        let mut vault = Vault::from(&self.vault)?;
        let username = vault.change_password_interactive(self.username.clone())?;
        vault.write(&self.vault)?;
        println!("Changed password for '{}'!", username);
        Ok(())
    }
}

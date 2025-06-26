use std::path::PathBuf;

use clap::Parser;
use color_eyre::eyre::Result;

use crate::vault::Vault;

#[derive(Parser, Debug, Clone)]
pub struct AddUserArgs {
    #[arg(short, long)]
    vault: PathBuf,
    #[arg(short, long)]
    /// existing user with which to add new user
    username: Option<String>,
}

impl AddUserArgs {
    pub async fn exec(&self) -> Result<()> {
        let mut vault = Vault::from(&self.vault)?;
        let username = vault.add_user_interactive(self.username.clone())?;
        vault.write(&self.vault)?;
        println!("Added user '{}'!", username);
        Ok(())
    }
}

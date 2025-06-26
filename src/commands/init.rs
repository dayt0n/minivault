use std::path::PathBuf;

use clap::Parser;
use color_eyre::eyre::{Result, eyre};

use crate::vault::Vault;

#[derive(Parser, Debug, Clone)]
pub struct InitArgs {
    #[arg(short, long)]
    vault: PathBuf,
}

impl InitArgs {
    pub async fn exec(&self) -> Result<()> {
        if self.vault.is_file() {
            return Err(eyre!("vault already exists!"));
        }
        let mut vault = Vault::new_interactive_with_password()?;
        vault.write(&self.vault)?;
        println!(
            "Created new vault at {}",
            &self.vault.as_os_str().to_str().unwrap()
        );
        Ok(())
    }
}

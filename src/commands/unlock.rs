use std::path::PathBuf;

use clap::Parser;
use color_eyre::eyre::Result;

use crate::client::MVClient;
use minivault::vault::util::prompt_or_get;

#[derive(Parser, Debug, Clone)]
pub struct UnlockArgs {
    #[arg(short, long)]
    username: Option<String>,
}

impl UnlockArgs {
    pub async fn exec(&self, socket: &PathBuf) -> Result<()> {
        println!("Using {:?}", socket);
        let client = MVClient::new(socket);
        let username = prompt_or_get(self.username.clone(), "Username");
        let password = rpassword::prompt_password("Password: ")?;
        client.unlock(username, password).await?;
        println!("Unlocked minivault!");
        Ok(())
    }
}

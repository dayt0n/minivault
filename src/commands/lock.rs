use std::path::PathBuf;

use clap::Parser;
use color_eyre::eyre::Result;

use crate::client::MVClient;

#[derive(Parser, Debug, Clone)]
pub struct LockArgs {}

impl LockArgs {
    pub async fn exec(&self, socket: &PathBuf) -> Result<()> {
        println!("Using {:?}", socket);
        let client = MVClient::new(socket);
        client.lock().await?;
        println!("Locked minivault");
        Ok(())
    }
}

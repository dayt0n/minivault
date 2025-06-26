use std::{fs, path::PathBuf};

use clap::Parser;
use color_eyre::eyre::{Result, eyre};

use crate::client::MVClient;

#[derive(Parser, Debug, Clone)]
pub struct DecryptArgs {
    #[arg(short, long)]
    data: Option<String>,
    #[arg(short, long)]
    file: Option<PathBuf>,
    #[arg(short, long, default_value_t = false)]
    machine_readable: bool,
}

impl DecryptArgs {
    pub async fn exec(&self, socket: &PathBuf) -> Result<()> {
        if self.data.is_none() && self.file.is_none() {
            return Err(eyre!("Specify either raw base64 data or a file"));
        }
        if !self.machine_readable {
            println!("Using {:?}", socket);
        }
        let mut client = MVClient::new(socket);
        client.machine_readable = self.machine_readable;
        let ct = if let Some(data) = &self.data {
            data.clone()
        } else if let Some(file) = &self.file {
            fs::read_to_string(file)?.trim().to_string()
        } else {
            // will never get here
            return Err(eyre!("Specify either raw base64 data or a file"));
        };
        client.decrypt(ct).await?;
        Ok(())
    }
}

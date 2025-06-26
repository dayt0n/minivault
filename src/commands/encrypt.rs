use std::{
    fs::{self},
    path::PathBuf,
};

use clap::Parser;
use color_eyre::eyre::{Result, eyre};

use crate::client::MVClient;
use minivault::vault::crypto;

#[derive(Parser, Debug, Clone)]
pub struct EncryptArgs {
    #[arg(short, long)]
    data: Option<String>,
    #[arg(short, long)]
    file: Option<PathBuf>,
    #[arg(short, long, default_value_t = false)]
    ascii: bool,
    #[arg(short, long, default_value_t = false)]
    machine_readable: bool,
}

impl EncryptArgs {
    pub async fn exec(&self, socket: &PathBuf) -> Result<()> {
        if self.data.is_none() && self.file.is_none() {
            return Err(eyre!("Specify either a file or raw data"));
        }
        if !self.machine_readable {
            println!("Using {:?}", socket);
        }
        let mut client = MVClient::new(socket);
        client.machine_readable = self.machine_readable;
        let pt = if let Some(data) = &self.data {
            if self.ascii {
                crypto::to_b64_string(data.as_bytes().to_vec())
            } else {
                data.clone()
            }
        } else if let Some(file) = &self.file {
            let fdata = fs::read(file)?;
            crypto::to_b64_string(fdata)
        } else {
            return Err(eyre!("Specify either a file or raw data"));
        };
        client.encrypt(pt).await?;
        Ok(())
    }
}

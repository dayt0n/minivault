use std::path::PathBuf;

use clap::Parser;
use color_eyre::eyre::{eyre, Result};

use crate::server::start_server;

#[cfg(debug_assertions)]
#[derive(Parser, Debug, Clone)]
pub struct RunArgs {
    #[arg(short, long, default_value_t = false)]
    dev_mode: bool,
    #[arg(short, long)]
    vault: PathBuf,
}

#[cfg(not(debug_assertions))]
#[derive(Parser, Debug, Clone)]
pub struct RunArgs {
    #[arg(short, long)]
    vault: PathBuf,
}

impl RunArgs {
    pub async fn exec(&self, socket: &PathBuf) -> Result<()> {
        println!("Using {:?}", socket);
        if socket.metadata().is_ok() {
            #[cfg(debug_assertions)]
            {
                use std::fs;
                if self.dev_mode {
                    println!("Found old socket, deleting...");
                    fs::remove_file(socket)?;
                } else {
                    return Err(eyre!("socket already exists, not starting!"));
                }
            }
            #[cfg(not(debug_assertions))]
            {
                return Err(eyre!("socket already exists, not starting!"));
            }
        }
        // actually run server
        start_server(socket, &self.vault).await?;
        Ok(())
    }
}

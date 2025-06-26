pub mod commands;
use clap::Parser;
use color_eyre::eyre::Result;
use commands::CLI;
mod client;
mod server;
mod vault;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let cli = CLI::parse();
    cli.exec().await
}

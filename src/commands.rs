use std::path::PathBuf;

use add_user::AddUserArgs;
use change_password::ChangePasswordArgs;
use clap::Parser;
use clap::Subcommand;
use color_eyre::eyre::Result;
use decrypt::DecryptArgs;
use encrypt::EncryptArgs;
use init::InitArgs;
use lock::LockArgs;
use run::RunArgs;
use unlock::UnlockArgs;

mod add_user;
mod change_password;
mod decrypt;
mod encrypt;
mod init;
mod lock;
mod run;
mod unlock;

#[derive(Parser, Debug)]
#[command(version,about,long_about=None)]
pub struct CLI {
    #[arg(short, long)]
    verbose: bool,
    #[arg(short, long, default_value = "minivault.sock")]
    socket: PathBuf,
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// run minivault
    Run(RunArgs),
    /// unlock minivault using a password
    Unlock(UnlockArgs),
    /// lock minivault
    Lock(LockArgs),
    /// encrypt data
    Encrypt(EncryptArgs),
    /// decrypt data
    Decrypt(DecryptArgs),
    /// initialize vault
    Init(InitArgs),
    /// add a new authorized user
    AddUser(AddUserArgs),
    /// change password for existing user
    ChangePassword(ChangePasswordArgs),
}

impl CLI {
    pub async fn exec(&self) -> Result<()> {
        // probably need to implement an init process.
        // all the command-line and http server stuff is basically done.
        // just need to implement the actual crypto portion.
        match &self.cmd {
            Commands::Run(args) => args.exec(&self.socket).await,
            Commands::Unlock(args) => args.exec(&self.socket).await,
            Commands::Lock(args) => args.exec(&self.socket).await,
            Commands::Encrypt(args) => args.exec(&self.socket).await,
            Commands::Decrypt(args) => args.exec(&self.socket).await,
            Commands::Init(args) => args.exec().await,
            Commands::AddUser(args) => args.exec().await,
            Commands::ChangePassword(args) => args.exec().await,
        }
    }
}

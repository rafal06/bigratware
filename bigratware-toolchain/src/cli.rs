use std::path::PathBuf;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate public and private RSA keys for use in Bigratware
    GenKeys,

    /// Decrypt a file using the private key
    Decrypt {
        /// Path to a private key file
        #[arg(short, long)]
        key: PathBuf,

        /// Path where the decrypted file will be saved.
        /// Defaults to the original directory and file name with added prefix `decrypted-`
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Path to a file to decrypt
        filename: PathBuf,
    }
}

mod gen_keys;
mod decrypt;

use std::path::PathBuf;
use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::decrypt::decrypt;
use crate::gen_keys::gen_keys;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate public and private RSA keys for use in Bigratware
    GenKeys,
    /// Decrypt a file using the private key
    Decrypt {
        /// Path to a file to decrypt
        filename: PathBuf,
        /// Path to a private key file
        #[arg(short, long)]
        key: PathBuf,
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Command::GenKeys => gen_keys(),
        Command::Decrypt { filename, key } => decrypt(filename, key)
    }
}

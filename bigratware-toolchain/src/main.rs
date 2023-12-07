mod gen_keys;

use clap::{Parser, Subcommand};
use anyhow::Result;
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
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Command::GenKeys => gen_keys(),
    }
}

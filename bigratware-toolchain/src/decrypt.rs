use std::fs;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use anyhow::Result;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Oaep, RsaPrivateKey};
use sha2::Sha512;
use decryptor::decrypt_file_chacha;

const BIGRAT_SIZE: usize = include_bytes!("../../bigrat.png").len();

fn decrypt_key_nonce(mut file: &File, private_key_path: PathBuf) -> Result<([u8; 32], [u8; 19])> {
    file.seek(SeekFrom::Start(BIGRAT_SIZE as u64))?;

    let private_key = fs::read(private_key_path)?;
    let private_key = RsaPrivateKey::from_pkcs8_der(private_key.as_slice())?;

    let mut key_encrypted = [0u8; 256];
    file.read_exact(&mut key_encrypted)?;
    let key = private_key.decrypt(Oaep::new::<Sha512>(), &key_encrypted).unwrap();

    let mut nonce_encrypted = [0u8; 256];
    file.read_exact(&mut nonce_encrypted)?;
    let nonce = private_key.decrypt(Oaep::new::<Sha512>(), &nonce_encrypted).unwrap();

    Ok((
        <[u8; 32]>::try_from(key.as_slice())?,
        <[u8; 19]>::try_from(nonce.as_slice())?,
    ))
}

pub fn decrypt_file(filename: PathBuf, private_key: PathBuf) -> Result<()> {
    let file = File::open(filename)?;
    let (key, nonce) = decrypt_key_nonce(&file, private_key)?;
    // TODO: By default write next to the original file and accept an output path as an optional argument
    let dist_path = PathBuf::from("/home/rafal/boykisser-from-bigrat.png");
    decrypt_file_chacha(&file, dist_path, key, nonce)
}

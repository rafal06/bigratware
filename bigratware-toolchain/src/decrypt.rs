use std::fs;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use anyhow::Result;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use chacha20poly1305::aead::stream::DecryptorBE32;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Oaep, RsaPrivateKey};
use sha2::Sha512;

const BIGRAT_SIZE: usize = include_bytes!("../../bigrat.png").len();
const BUFFER_SIZE: usize = 500 + 16;

pub fn decrypt(filename: PathBuf, private_key: PathBuf) -> Result<()> {
    let mut file = File::open(filename)?;
    file.seek(SeekFrom::Start(BIGRAT_SIZE as u64))?;

    let mut dist_file = File::create("/home/rafal/boykisser-from-bigrat.png")?;

    let private_key = fs::read(private_key)?;
    let private_key = RsaPrivateKey::from_pkcs8_der(private_key.as_slice())?;

    let mut key_encrypted = [0u8; 256];
    file.read_exact(&mut key_encrypted)?;
    let key = private_key.decrypt(Oaep::new::<Sha512>(), &key_encrypted).unwrap();

    let mut nonce_encrypted = [0u8; 256];
    file.read_exact(&mut nonce_encrypted)?;
    let nonce = private_key.decrypt(Oaep::new::<Sha512>(), &nonce_encrypted).unwrap();

    let aead = XChaCha20Poly1305::new(key.as_slice().into());
    let mut stream_decryptor = DecryptorBE32::from_aead(aead, nonce.as_slice().into());

    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        let read_count = file.read(&mut buffer)?;
        if read_count == BUFFER_SIZE {
            let decrypted_data = stream_decryptor.decrypt_next(buffer.as_slice()).unwrap();
            let _ = dist_file.write(&decrypted_data)?;
        } else if read_count == 0 {
            break;
        } else {
            let decrypted_data = stream_decryptor.decrypt_last(&buffer[..read_count]).unwrap();
            let _ = dist_file.write(&decrypted_data)?;
            break;
        }
    }

    Ok(())
}

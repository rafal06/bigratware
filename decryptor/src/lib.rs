pub mod helpers;

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use anyhow::{anyhow, Result};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use chacha20poly1305::aead::stream::DecryptorBE32;

const BIGRAT_SIZE: usize = include_bytes!("../../bigrat.png").len();
const BUFFER_SIZE: usize = 500 + 16;

/// Decrypt a bigratware-encrypted file using the ChaCha20Poly1305
/// algorithm, given a key and nonce derived previously from that file.
/// Writes the decrypted content into the provided destination path.
/// Fails if the key or nonce is incorrect.
pub fn decrypt_file_chacha(
    mut source_file: &File,
    mut dist_file: &File,
    key: [u8; 32],
    nonce: [u8; 19]
) -> Result<()> {
    // Skip a bigrat PNG and encrypted key-nonce pair
    source_file.seek(SeekFrom::Start(BIGRAT_SIZE as u64 + 256 * 2))?;

    let aead = XChaCha20Poly1305::new(key.as_slice().into());
    let mut stream_decryptor = DecryptorBE32::from_aead(aead, nonce.as_slice().into());

    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        let read_count = source_file.read(&mut buffer)?;
        if read_count == BUFFER_SIZE {
            let decrypted_data = match stream_decryptor.decrypt_next(buffer.as_slice()) {
                Ok(data) => data,
                Err(err) => return Err(anyhow!("decryption error: {}", err)),
            };
            let _ = dist_file.write(&decrypted_data)?;
        } else if read_count == 0 {
            break;
        } else {
            let decrypted_data = match stream_decryptor.decrypt_last(&buffer[..read_count]) {
                Ok(data) => data,
                Err(err) => return Err(anyhow!("decryption error: {}", err)),
            };
            let _ = dist_file.write(&decrypted_data)?;
            break;
        }
    }

    Ok(())
}

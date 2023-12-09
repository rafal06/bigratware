mod encrypt_file;

use std::fs::File;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use anyhow::Result;
use crate::encrypt_file::encrypt_file;

const BIGRAT_PNG: &[u8; 1044942] = include_bytes!("../../bigrat.png");
const PUBLIC_KEY: &[u8; 294] = include_bytes!("../../public-key.der");

fn main() -> Result<()> {
    let pub_key = RsaPublicKey::from_public_key_der(PUBLIC_KEY)?;
    let mut rng = rand::thread_rng();

    let mut file_to_encrypt = File::open("/home/rafal/boykisser.png")?;
    encrypt_file(&mut file_to_encrypt, pub_key, &mut rng)?;

    Ok(())
}

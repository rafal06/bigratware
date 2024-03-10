# Encrypted files

Bigratware-encrypted files are a result of Bigratware encryption process (duh)

## Contents

| Content                 | Length (bytes)            |
|-------------------------|---------------------------|
| bigrat.png              | length of bigrat.png      |
| encrypted key           | 256                       |
| encrypted nonce         | 256                       |
| encrypted file contents | until the end of the file |

### Encrypted key
When decrypting, it's used to check if a file is encrypted with Bigratware. If it matches the one in the [status file](status_file.md), then proceed to decrypting the file, otherwise skip the file.

## Location
If Bigratware is compiled in debug mode, it works only in `~/Desktop/bigratware-testground/` directory, so that the environment can be easily controlled and doesn't cause harm to the developer.  
In release mode, the working directory is the user's home directory (`C:\Users\<username>\` on Windows).

The encryption root directory is processed recursively, so that files in every subdirectory are also processed.

## Naming scheme
In normal circumstances, the encrypted file has a name that consists of the original file's name plus `.png` suffix added (without removing the original extension), so that the operating system can display it like a normal PNG file (`bigrat.png`).  
If such file already exists, then a random unsigned 32-bit number (`u32`) is generated and added as a prefix, separated with the rest of the file name with a dash (`-`).

## Encryption algorithm
The files are encrypted using streamed `XChaCha20Poly1305` algorithm with a key and nonce generated on a client's PC one time, and used for every file. Then, the key and nonce are encrypted with a public RSA key (with `SHA512` padding) generated previously by a vendor and built into the Bigratware binary. The RSA-encrypted key and nonce are saved in every Bigratware-encrypted file (see [Contents](#contents)) and a status file (see [Status file](status_file.md#contents)).

# Getting started

> **Attention**  
> All source code and documentation in this repository are provided **FOR EDUCATIONAL PURPOSES ONLY**, I DO NOT encourage nor endorse using them to cause any damage and/or harm. I am not liable for any damages, harm or loss of data resulting from use of the software found in this repository or its documentation.

## Prerequisites
You must have the [Rust language](https://rust-lang.org) installed, preferably via [Rustup](https://rustup.rs), and cloned this repository locally.

If you plan on cross-compiling Bigratware from a non-Windows OS, you must also have `mingw64` installed and Windows target installed via Rustup:
```shell
rustup target add x86_64-pc-windows-gnu
```

## Generating RSA keys
In order to compile Bigratware itself, you have to generate public and private RSA key pair by using the `bigratware-toolchain` package. It can be done with the following command:
```shell
cargo run --release --package bigratware-toolchain gen-keys
```
It should result in creating 2 new files in the directory, `private-key.der` and `public-key.der`. The first one will be needed for decryption of clients' files and the second one will be baked into Bigratware itself.

## Compiling Bigratware
Now that we have all the prerequisites done, we can proceed to compiling Bigratware itself. If you're cross-compiling from Linux, macOS or other non-Windows OS, run the following command:
```shell
cargo build --release --package bigratware --target x86_64-pc-windows-gnu
```
Otherwise, you can skip the `target` flag.

## Conclusion
Congratulations! You have successfully compiled Bigratware. Keep in mind that you'll need the previously mentioned `private-key.der` file in order to decrypt files encrypted by your Bigratware build.

The Bigratware binary can be found in `./target/x86_64-pc-windows-gnu/release/bigratware.exe` if you cross-compiled, or `./target/release/bigratware.exe` if you compiled it directly from Windows.

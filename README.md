# RC4 Stream Cipher 

This Rust crate implements the RC4 stream cipher, optimized for embedded use cases with no standard library dependencies (`#![no_std]`). The implementation ensures memory safety by forbidding unsafe code blocks. Additionally, a command-line utility is provided for file encryption and decryption using RC4. 

**Note:** RC4 is known to be a broken encryption algorithm with several vulnerabilities. It is not recommended for use in security-critical applications.

Based on the book [High Assurance Rust](https://github.com/tnballo/high-assurance-rust)

## Features

- **No Standard Library Dependency**: Suitable for embedded environments.
- **Memory Safe**: Uses Rust's safety guarantees by forbidding unsafe code.
- **Flexible Key Length**: Supports key lengths from 40 to 2048 bits.
- **Simple API**: Functions to initialize the cipher, generate keystream bytes, and apply the keystream to data.
- **Command-Line Utility**: Encrypt and decrypt files using the provided utility.
- **Recursive File Processing**: Encrypt or decrypt all files in a directory and its subdirectories.
- **Large File Support**: Buffering is used to handle files too large to fit into memory.

## Usage


### API

- **`Rc4::new(key: &[u8]) -> Self`**: Initializes a new RC4 instance with the provided key.
- **`Rc4::prga_next(&mut self) -> u8`**: Generates the next byte of the keystream.
- **`Rc4::apply_keystream(&mut self, data: &mut [u8])`**: Encrypts or decrypts the provided data in place.
- **`Rc4::apply_keystream_static(key: &[u8], data: &mut [u8])`**: A static method for one-shot encryption/decryption.

### Testing

Unit tests are included to ensure the implementation's correctness. Run the tests with:

```sh
cargo test
```

## Command-Line Utility

The command-line utility allows you to encrypt and decrypt files using the RC4 cipher.

Build the utility with:

```sh
cd rcli/
cargo install --path . 
```

### Usage

```sh
rcli --file <FILE_NAME> --key <HEX_KEY_BYTES> [--recursive]
```

- **`--file`**: The file or directory to encrypt or decrypt.
- **`--key`**: The encryption/decryption key in hexadecimal byte format.
- **`--recursive`**: (Optional) If set, process all files in the specified directory and its subdirectories.

### Example

Create a file `secret.txt` you want to encrypt and decrypt, and add contents in plaintext to it.

To Encrypt a file:

```sh
rcli --file secret.txt --key 0x4b 0x8e 0x29 0x87 0x80
```

To Decrypt a file:

```sh
rcli --file secret.txt --key 0x4b 0x8e 0x29 0x87 0x80
```

To Recursively Encrypt files in a directory:

```sh
rcli --file my_directory --key 0x4b 0x8e 0x29 0x87 0x80 --recursive
```

To Recursively Decrypt files in a directory:

```sh
rcli --file my_directory --key 0x4b 0x8e 0x29 0x87 0x80 --recursive
```

## License

This project is licensed under the MIT License.

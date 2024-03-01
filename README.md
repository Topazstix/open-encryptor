# Open Encryptor

Simple openssl encryption and decryption tool written in Rust :crab: utilizing the `Cipher::aes_256_cbc()` cipher.

## Usage

Program requires rust to be installed or the binary can be downloaded from the releases page and run on any system that has openssl installed.

### Build

- Clone the repository
- Run `cargo build --release`
- The binary will be located at `target/release/open_encryptor`

### Run

- Encrypt a file: `./open_encryptor -e -f <input_file> -o <output_file>`
- Decrypt a file: `./open_encryptor -d -f <input_file> -o <output_file>`
- Interactive mode: `./open_encryptor -i`

### Example

```bash
$ ./open_encryptor -e -f test.txt -o test.txt.enc
Enter password: Hello World
Encryption successful

$ ./open_encryptor -d -f test.txt.enc -o test.txt
Enter password: Hello World
Decryption successful
```

## License

MIT License

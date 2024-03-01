use clap::Parser;
use core::result::Result;
use openssl::symm::{decrypt, encrypt, Cipher};
use rand::Rng;
use std::error::Error;
use std::fs::File;
use std::io::{self, Read, Write};

///
/// Command line arguments
///
/// - interactive: Run the interactive mode
///
/// - file: The input file to encrypt/decrypt
///
///    - **required_unless_present**: interactive
///
/// - outfile: The output file
///
///    - **required_unless_present**: interactive
///
/// - decrypt: Decrypt the file
///
///   - **required_unless_present**: encrypt or interactive
///
/// - encrypt: Encrypt the file
///
///   - **required_unless_present**: decrypt or interactive
///
#[derive(Parser, Debug)]
#[clap(name = "Open Encryptor")]
struct Args {
    // Input file
    #[clap(
        short = 'f',
        long = "infile",
        value_name = "INPUT FILE",
        required_unless_present = "interactive"
    )]
    file: Option<String>,

    // Interactive mode
    #[clap(short, long, value_name = "INTERACTIVE")]
    interactive: bool,

    // Output file
    #[clap(
        short = 'o',
        long = "outfile",
        value_name = "OUTPUT FILE",
        required_unless_present = "interactive"
    )]
    outfile: Option<String>,

    // Decrypt cli opt
    #[clap(
        short,
        long,
        value_name = "DECRYPT",
        required_unless_present = "encrypt",
        required_unless_present = "interactive"
    )]
    decrypt: bool,

    // Encrypt cli opt
    #[clap(
        short,
        long,
        value_name = "ENCRYPT",
        required_unless_present = "decrypt",
        required_unless_present = "interactive"
    )]
    encrypt: bool,
} // end struct Args

// Generate a random IV, 16 bytes for AES-256
fn generate_iv() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let iv: [u8; 16] = rng.gen(); // 16 byte AES blocks
    iv.to_vec()
} // end generate_iv

///
/// Encrypts a file using AES-256-CBC
///
/// # Arguments
///
/// * `file_path` - The path to the file to encrypt
/// * `out_file_path` - The path to the output file
/// * `key` - The encryption key
/// * `iv` - The initialization vector
///
fn encrypt_file(
    file_path: &str,
    out_file_path: &str,
    key: &[u8],
    iv: &[u8],
) -> Result<(), Box<dyn Error>> {
    let cipher = Cipher::aes_256_cbc();
    let mut file = File::open(file_path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    let encrypted_data = encrypt(cipher, key, Some(iv), &contents)?;

    let mut out_file = File::create(out_file_path)?;
    out_file.write_all(iv)?;
    out_file.write_all(&encrypted_data)?;
    Ok(())
} //end encrypt_file

///
/// Decrypts a file using AES-256-CBC
///
/// # Arguments
///
/// * `file_path` - The path to the file to decrypt
/// * `out_file_path` - The path to the output file
/// * `key` - The encryption key
///
fn decrypt_file(file_path: &str, out_file_path: &str, key: &[u8]) -> Result<(), Box<dyn Error>> {
    let cipher = Cipher::aes_256_cbc();
    let mut file = File::open(file_path)?;
    let mut full_file_data = Vec::new();
    file.read_to_end(&mut full_file_data)?;
    let iv = &full_file_data[0..16];
    let encrypted_data = &full_file_data[16..];

    let decrypted_data = decrypt(cipher, key, Some(iv), encrypted_data)?;
    let mut out_file = File::create(out_file_path)?;
    out_file.write_all(&decrypted_data)?;
    Ok(())
} // end decrypt_file

// Interactive mode for encrypting/decrypting files
// This is a simple CLI interface for encrypting/decrypting files
fn interactive_mode(key: &[u8]) -> Result<(), Box<dyn Error>> {
    loop {
        // Grab user input for encrypting/decrypting a file
        println!("Would you like to encrypt or decrypt a file? (e/d)");
        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;

        if choice.trim() == "e" {
            // Enter the input and output file paths
            println!("Enter the input file path:");
            let mut input_file_path = String::new();
            io::stdin().read_line(&mut input_file_path)?;

            println!("Enter the output file path:");
            let mut output_file_path = String::new();
            io::stdin().read_line(&mut output_file_path)?;

            // Generate a random IV, then encrypt the file
            let iv = generate_iv();
            encrypt_file(input_file_path.trim(), output_file_path.trim(), key, &iv)?;

            println!("File encrypted successfully!");
            break;
        } else if choice.trim() == "d" {
            // Enter the input and output file paths
            println!("Enter the encrypted file path:");
            let mut encrypted_file_path = String::new();
            io::stdin().read_line(&mut encrypted_file_path)?;

            println!("Enter the output file path:");
            let mut output_file_path = String::new();
            io::stdin().read_line(&mut output_file_path)?;

            // Decrypt the file
            decrypt_file(encrypted_file_path.trim(), output_file_path.trim(), key)?;

            println!("File decrypted successfully!");
            break;
        } else {
            // Loop until valid choice is entered
            println!("Invalid choice, please enter 'e' or 'd'");
        }
    }

    Ok(())
} // end interactive_mode

// Get password from user
fn get_password() -> String {
    let mut password = String::new();
    print!("Enter password: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut password).unwrap();
    password.trim().to_string()
}

// Pad the password to 32 bytes
fn pad_password(password: &str) -> Result<[u8; 32], &'static str> {
    let password_bytes = password.as_bytes();
    if password_bytes.len() > 32 {
        Err("Password is too long")
    } else {
        let mut padded_password = [0; 32];
        for (i, &byte) in password_bytes.iter().enumerate() {
            padded_password[i] = byte;
        }
        Ok(padded_password)
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    // Parse command line arguments
    let args = Args::parse();

    // Get password from user
    let password = get_password();
    let key = pad_password(&password)?;

    // Match cli args
    match args {
        Args {
            file,
            interactive,
            outfile,
            decrypt,
            encrypt,
        } => {
            // Run interactive mode if interactive flag is set
            // Otherwise, run the encrypt/decrypt functions
            if interactive {
                interactive_mode(&key)?;
            } else if decrypt {
                println!("Decrypting file: {:#?}", file);

                decrypt_file(file.unwrap().as_str(), outfile.unwrap().as_str(), &key)?;

                println!("File decrypted successfully!");
            } else if encrypt {
                println!("Encrypting file: {:#?}", file);

                let iv = generate_iv();

                encrypt_file(file.unwrap().as_str(), outfile.unwrap().as_str(), &key, &iv)?;

                println!("File encrypted successfully!");
            }
        }
    }

    Ok(())
} // end main

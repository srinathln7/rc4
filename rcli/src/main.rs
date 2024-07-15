use clap::Parser; 
use rc4::Rc4; 
use std::fs::File; 
use std::io::prelude::{Read, Seek, Write}; 
use walkdir::WalkDir; 

/// RC4 file en/decryption
#[derive(Parser, Debug)]
struct Args {
    /// Name of file to en/decrypt
    #[arg(short, long, required = true, value_name = "FILE_NAME")]
    file: String,

    /// En/Decryption key (hexadecimal bytes)
    #[arg(
        short,
        long,
        required = true,
        value_name = "HEX_BYTE",
        num_args = 5..=256, 
    )]
    key: Vec<String>,

    /// Recursively process files in dirs
    #[arg(short, long)]
    recursive: bool, 
}


fn is_printable_ascii(byte: u8) -> bool {
    byte.is_ascii_graphic() // Check if byte is a graphic ASCII character
    || byte == b' '   // OR if it is a space character
    || byte == b'\n'  // OR if it is a newline character
    || byte == b'\r'  // OR if it is a carriage return character 
}



fn process_file(file_path: &str, key_bytes: &[u8]) -> std::io::Result<()> {
    

    let mut contents = Vec::new();

    // Open the file for both reading and writing
    // `?` operator tells the function to short circuit if an operation fails and immediately return the error 
    let mut file = File::options().read(true).write(true).open(file_path)?;

    // Read all file contents into memory
    file.read_to_end(&mut contents)?;

    // Heuristic: Count the number of printable ASCII characters
    let printable_count = contents.iter().filter(|&&byte| is_printable_ascii(byte)).count();
    let printable_ratio = printable_count as f64 / contents.len() as f64;  

    // En/decrypt file contents in-memory
    Rc4::apply_keystream_static(&key_bytes, &mut contents);

    // Overwrite existing file with the result
    file.rewind()?; 
    file.write_all(&contents); 

    // Print success message
    if printable_ratio > 0.7 {
        println!("Encrypted {}", file_path);
    } else {
        println!("Decrypted {}", file_path);
    }

    Ok(())
}


fn main() -> std::io::Result<()> {
    let args = Args::parse();
    //println!("{:?}", args); 

    let key_bytes = args
    .key
    .iter()
    .map(|s| s.trim_start_matches("0x"))
    .map(|s| u8::from_str_radix(s,16).expect("Invalid key hex byte!"))
    .collect::<Vec<u8>>();

    // If the recursive flag is set, process each file in the directory and its subdirectories.
    if args.recursive {
        for entry in WalkDir::new(&args.file)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            process_file(entry.path().to_str().unwrap(), &key_bytes)?;
        }
    } else {
        process_file(&args.file, &key_bytes)?;
    }

    Ok(())
}
//#![allow(unused_imports)]

use std::fs;
use std::io::{
    Cursor,
    Read,
    Write,
};
use std::path::{
    Path, 
    PathBuf,
};
use eyre::{
    eyre, 
    Result,
};
use orion::hazardous::stream::chacha20::{
    Nonce,
    SecretKey,
};
use orion::hazardous::aead::chacha20poly1305;
use orion::hazardous::aead::chacha20poly1305::open;
use orion::hazardous::hash::blake2::blake2b::Blake2b;
use xz2::write::XzEncoder;
use xz2::read::XzDecoder;
use secstr::SecUtf8;
use clap::Parser;
use rpassword;

#[derive(Clone, Debug, Parser)]
#[command(name = "lz", about = "program for compressing|decompressing every file in a path")]
#[command(version = "0.1.0")]
#[command(author = "Scott A. Idler <scott.a.idler@gmail.com>")]
#[command(arg_required_else_help = true)]
#[command(after_help = "after help")]
struct Cli {
    #[clap(short, long)]
    config: Option<PathBuf>,

    #[clap(subcommand)]
    command: Option<Command>,
}

#[derive(Clone, Debug, Parser)]
enum Command {
    #[clap(name = "compress", alias = "c", about = "compress every file in a path")]
    Compress(CommandCli),

    #[clap(name = "decompress", alias = "d", about = "decompress every file in a path")]
    Decompress(CommandCli),
}

#[derive(Clone, Debug, Parser)]
struct CommandCli {
    patterns: Vec<String>,
}

fn compress(path: &Path, password: &SecUtf8) -> Result<()> {
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            compress(&entry?.path(), password)?;
        }
    } else if path.is_file() {
        let output_filename = format!("{}.xz", path.file_name()
            .ok_or_else(|| eyre::eyre!("Failed to get file name"))?
            .to_string_lossy());
        let output_path = path.parent()
            .ok_or_else(|| eyre::eyre!("Failed to get parent directory"))?
            .join(output_filename);

        // Read the file content
        let mut file_content = vec![];
        fs::File::open(path)?.read_to_end(&mut file_content)?;

        // Create a new XzEncoder with compression level 6 (default)
        let mut encoder = XzEncoder::new(vec![], 6);

        // Compress the file content
        encoder.write_all(&file_content)?;
        let compressed_content = encoder.finish()?;

        // Hash the password to generate a 32-byte value
        let mut hasher = Blake2b::new(32)?;
        hasher.update(password.unsecure().as_bytes())?;
        let hashed_password = hasher.finalize()?;

        // Use the hashed password to create a secret key for encryption
        let secret_key = SecretKey::from_slice(hashed_password.as_ref())?;

        // Create a new nonce
        let nonce = Nonce::from([0u8; 12]);

        // Encrypt the compressed content
        let mut dst_out_ct = vec![0u8; compressed_content.len() + 16];
        chacha20poly1305::seal(&secret_key, &nonce, &compressed_content, None, &mut dst_out_ct)?;

        // Write the encrypted content to the output file
        fs::File::create(&output_path)?.write_all(&dst_out_ct)?;

        std::fs::remove_file(path)?;
    }
    Ok(())
}

fn decompress(path: &Path, password: &SecUtf8) -> Result<()> {
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            decompress(&entry?.path(), password)?;
        }
    } else if path.is_file() {
        let output_filename = path.file_stem()
            .ok_or_else(|| eyre::eyre!("Failed to get file stem"))?
            .to_string_lossy()
            .to_string();  // Convert Cow<str> to String
        let output_path = path.parent()
            .ok_or_else(|| eyre::eyre!("Failed to get parent directory"))?
            .join(output_filename);

        // Read the file content
        let mut file_content = vec![];
        fs::File::open(path)?.read_to_end(&mut file_content)?;

        // Hash the password to generate a 32-byte value
        let mut hasher = Blake2b::new(32)?;
        hasher.update(password.unsecure().as_bytes())?;
        let hashed_password = hasher.finalize()?;

        // Use the hashed password to create a secret key for decryption
        let secret_key = SecretKey::from_slice(hashed_password.as_ref())?;

        // Create a new nonce
        let nonce = Nonce::from([0u8; 12]);

       // Decrypt the file content
        let mut decrypted_content = vec![0u8; file_content.len() - 16];
        match open(&secret_key, &nonce, &file_content, None, &mut decrypted_content) {
            Ok(_) => (),
            Err(_) => return Err(eyre::eyre!("Decryption failed. The provided password may be incorrect.")),
        };

        // Create a new XzDecoder
        let mut decoder = XzDecoder::new(Cursor::new(decrypted_content));

        // Decompress the decrypted content
        let mut decompressed_content = vec![];
        decoder.read_to_end(&mut decompressed_content)?;

        // Write the decompressed content to the output file
        fs::File::create(&output_path)?.write_all(&decompressed_content)?;

        std::fs::remove_file(path)?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    println!("{:?}", cli);
    match cli.command {
        Some(Command::Compress(_)) | Some(Command::Decompress(_)) => {
            let prompt = format!("Please re-enter your password: ");

            // Convert the password to SecUtf8
            let password = SecUtf8::from(rpassword::prompt_password(&prompt)?);

            match cli.command {
                Some(Command::Compress(compress_cli)) => {
                    for pattern in compress_cli.patterns {
                        compress(Path::new(&pattern), &password)?;
                    }
                },
                Some(Command::Decompress(decompress_cli)) => {
                    for pattern in decompress_cli.patterns {
                        decompress(Path::new(&pattern), &password)?;
                    }
                },
                None => unreachable!(),  // We already checked this case above
            }
        },
        None => {
            return Err(eyre!("no command"));
        },
    }
    Ok(())
}

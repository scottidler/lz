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
use eyre::Result;
use clap::Parser;
use rpassword;

#[derive(Clone, Debug, Parser)]
#[command(name = "stow", about = "program for compressing|encrypting every file in a path")]
#[command(version = "0.1.0")]
#[command(author = "Scott A. Idler <scott.a.idler@gmail.com>")]
#[command(arg_required_else_help = true)]
#[command(after_help = "first letter alias exists for [p]ack and [l]oad")]
struct Cli {
    #[clap(short, long)]
    config: Option<PathBuf>,

    #[clap(subcommand)]
    command: Option<Command>,
}

#[derive(Clone, Debug, Parser)]
enum Command {
    #[clap(name = "pack", alias = "p", about = "compress|encrypt every file in a path")]
    Pack(CommandCli),

    #[clap(name = "load", alias = "l", about = "decrypt|decompress every file in a path")]
    Load(CommandCli),
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
        let mut file_content = vec![];
        fs::File::open(path)?.read_to_end(&mut file_content)?;
        let mut encoder = XzEncoder::new(vec![], 6);
        encoder.write_all(&file_content)?;
        let compressed_content = encoder.finish()?;
        let mut hasher = Blake2b::new(32)?;
        hasher.update(password.unsecure().as_bytes())?;
        let hashed_password = hasher.finalize()?;
        let secret_key = SecretKey::from_slice(hashed_password.as_ref())?;
        let nonce = Nonce::from([0u8; 12]);
        let mut dst_out_ct = vec![0u8; compressed_content.len() + 16];
        chacha20poly1305::seal(&secret_key, &nonce, &compressed_content, None, &mut dst_out_ct)?;
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
            .to_string();
        let output_path = path.parent()
            .ok_or_else(|| eyre::eyre!("Failed to get parent directory"))?
            .join(output_filename);
        let mut file_content = vec![];
        fs::File::open(path)?.read_to_end(&mut file_content)?;
        let mut hasher = Blake2b::new(32)?;
        hasher.update(password.unsecure().as_bytes())?;
        let hashed_password = hasher.finalize()?;
        let secret_key = SecretKey::from_slice(hashed_password.as_ref())?;
        let nonce = Nonce::from([0u8; 12]);
        let mut decrypted_content = vec![0u8; file_content.len() - 16];
        match open(&secret_key, &nonce, &file_content, None, &mut decrypted_content) {
            Ok(_) => (),
            Err(_) => return Err(eyre::eyre!("Decryption failed. The provided password may be incorrect.")),
        };
        let mut decoder = XzDecoder::new(Cursor::new(decrypted_content));
        let mut decompressed_content = vec![];
        decoder.read_to_end(&mut decompressed_content)?;
        fs::File::create(&output_path)?.write_all(&decompressed_content)?;
        std::fs::remove_file(path)?;
    }
    Ok(())
}

fn get_password() -> Result<SecUtf8> {
    let prompt = "Please enter your password: ";
    let password = SecUtf8::from(rpassword::prompt_password(prompt)?);
    Ok(password)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Pack(compress_cli)) => {
            for pattern in compress_cli.patterns {
                compress(Path::new(&pattern), &get_password()?)?;
            }
        },
        Some(Command::Load(decompress_cli)) => {
            for pattern in decompress_cli.patterns {
                decompress(Path::new(&pattern), &get_password()?)?;
            }
        },
        None => unreachable!(),
    }
    Ok(())
}

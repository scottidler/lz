#![allow(unused_imports)]
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
    Result,
    WrapErr,
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
use tempfile::Builder;
use rayon::prelude::*;
use secstr::SecUtf8;
use std::fs::File;
use clap::Parser;
use rpassword;

const STOW: &str = ".stow";

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

    // optional to rename files with tmp name
    #[clap(short, long, help = "rename files with tmp name")]
    rename: bool,

    patterns: Vec<String>,
}

fn get_pack_path(path: &Path, rename: bool) -> Result<PathBuf> {
    let output_filename = if rename {
        let temp_file = Builder::new().suffix(STOW).tempfile()?;
        temp_file.path().file_name().unwrap().to_string_lossy().into_owned()
    } else {
        format!("{}{}", path.file_name()
            .ok_or_else(|| eyre::eyre!("Failed to get file name"))?
            .to_string_lossy(), STOW)
    };
    let output_path = path.parent()
        .ok_or_else(|| eyre::eyre!("Failed to get parent directory"))?
        .join(output_filename);
    Ok(output_path)
}

fn bundle(path: &Path) -> Result<Vec<u8>> {
    let mut compressed_data = Vec::new();
    let xz_encoder = XzEncoder::new(&mut compressed_data, 6);
    let mut tar_builder = tar::Builder::new(xz_encoder);
    let file_name = path.file_name().ok_or_else(|| eyre::eyre!("Failed to get file name"))?;
    let file_name_str = file_name.to_str().ok_or_else(|| eyre::eyre!("Failed to convert file name to string"))?;
    let mut header = tar::Header::new_gnu();
    header.set_path(file_name_str)?;
    header.set_size(path.metadata()?.len());
    header.set_cksum();
    tar_builder.append(&header, File::open(path)?)?;
    let xz_encoder = tar_builder.into_inner().wrap_err("Failed to finalize tar archive")?;
    xz_encoder.finish().wrap_err("Failed to finalize compression")?;
    Ok(compressed_data)
}

fn encrypt(content: Vec<u8>, password: &SecUtf8) -> Result<Vec<u8>> {
    let mut hasher = Blake2b::new(32)?;
    hasher.update(password.unsecure().as_bytes())?;
    let hashed_password = hasher.finalize()?;
    let secret_key = SecretKey::from_slice(hashed_password.as_ref())?;
    let nonce = Nonce::from([0u8; 12]);
    let mut dst_out_ct = vec![0u8; content.len() + 16];
    chacha20poly1305::seal(&secret_key, &nonce, &content, None, &mut dst_out_ct)?;
    Ok(dst_out_ct)
}

fn pack(path: &Path, password: &SecUtf8, rename: bool) -> Result<()> {
    if path.is_dir() {
        let entries: Vec<_> = fs::read_dir(path)?.collect();
        entries.par_iter().map(|entry| {
            let entry = entry.as_ref().unwrap();
            pack(&entry.path(), password, rename)
        }).collect::<Result<()>>()?;
    } else if path.is_file() {
        let output_path = get_pack_path(path, rename)?;
        let compressed_content = bundle(path)?;
        let encrypted_content = encrypt(compressed_content, password)?;
        fs::File::create(&output_path)?.write_all(&encrypted_content)?;
        std::fs::remove_file(path)?;
    }
    Ok(())
}

fn get_load_path(path: &Path, file_name: &str) -> Result<PathBuf> {
    let output_path = path.parent()
        .ok_or_else(|| eyre::eyre!("Failed to get parent directory"))?
        .join(file_name);
    Ok(output_path)
}

fn decrypt(path: &Path, password: &SecUtf8) -> Result<Vec<u8>> {
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
    Ok(decrypted_content)
}

fn unbundle(content: Vec<u8>) -> Result<(Vec<u8>, String)> {
    let mut xz_decoder = XzDecoder::new(&content[..]);
    let mut tar_archive = tar::Archive::new(&mut xz_decoder);
    let mut uncompressed_data = Vec::new();
    let mut file_name = String::new();
    for entry in tar_archive.entries()? {
        let mut entry = entry?;
        entry.read_to_end(&mut uncompressed_data)?;
        file_name = entry.path()?.to_str().unwrap().to_string();
    }
    Ok((uncompressed_data, file_name))
}

fn load(path: &Path, password: &SecUtf8) -> Result<()> {
    if path.is_dir() {
        let entries: Vec<_> = fs::read_dir(path)?.collect();
        entries.par_iter().map(|entry| {
            let entry = entry.as_ref().unwrap();
            load(&entry.path(), password)
        }).collect::<Result<()>>()?;
    } else if path.is_file() {
        let decrypted_content = decrypt(path, password)?;
        let (decompressed_content, file_name) = unbundle(decrypted_content)?;
        let output_path = get_load_path(path, &file_name)?;
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
        Some(Command::Pack(pack_cli)) => {
            for pattern in pack_cli.patterns {
                pack(Path::new(&pattern), &get_password()?, pack_cli.rename)?;
            }
        },
        Some(Command::Load(load_cli)) => {
            for pattern in load_cli.patterns {
                load(Path::new(&pattern), &get_password()?)?;
            }
        },
        None => unreachable!(),
    }
    Ok(())
}

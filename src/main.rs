//#![allow(unused_imports)]

use clap::Parser;
use eyre::{eyre, Result, WrapErr};
use orion::hazardous::aead::chacha20poly1305;
use orion::hazardous::hash::blake2::blake2b::Blake2b;
use orion::hazardous::stream::chacha20::{Nonce, SecretKey};
use rayon::prelude::*;
use secstr::SecUtf8;
use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};
use tempfile::Builder;
use xz2::read::XzDecoder;
use xz2::write::XzEncoder;
use std::str::FromStr;

const STOW: &str = "stow";

type Buffer = Vec<u8>;

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
    #[clap(short, long, help = "keep original file name")]
    keep_name: bool,

    #[clap(
        short,
        long,
        value_name = "INT",
        default_value = "2",
        help = "number files per archive"
    )]
    bundle_count: usize,

    #[clap(
        short,
        long,
        value_name = "BYTES",
        default_value = "1M",
        value_parse = parse_size,
        help = "maximum archive size"
    )]
    bundle_size: usize,

    patterns: Vec<String>,
}

#[derive(Debug)]
struct SizeParseError;

impl std::fmt::Display for SizeParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Invalid size unit")
    }
}

impl std::error::Error for SizeParseError {}

fn parse_size(size: &str) -> Result<usize, SizeParseError> {
    let (num, unit) = size.split_at(size.len() - 1);
    let num = usize::from_str(num).map_err(|_| SizeParseError)?;
    match unit {
        "K" => Ok(num),
        "M" => Ok(num * 1024),
        "G" => Ok(num * 1024 * 1024),
        _ => Err(SizeParseError),
    }
}

fn get_pack_path(path: &Path, keep_name: bool) -> Result<PathBuf> {
    let output_filename = if keep_name {
        format!(
            "{}.{}",
            path.file_name()
                .ok_or_else(|| eyre!("Failed to get file name"))?
                .to_string_lossy(),
            STOW
        )
    } else {
        Builder::new()
            .suffix(&format!(".{STOW}"))
            .tempfile()
            .wrap_err("Failed to create temporary file")?
            .path()
            .file_name()
            .ok_or_else(|| eyre!("Failed to get file name from temp_file"))?
            .to_string_lossy()
            .into_owned()
    };
    let output_path = path
        .parent()
        .ok_or_else(|| eyre!("Failed to get parent directory"))?
        .join(output_filename);
    Ok(output_path)
}

fn tar_xz(paths: &[&Path]) -> Result<Buffer> {
    let mut compressed_data = vec![];
    let xz_encoder = XzEncoder::new(&mut compressed_data, 6);
    let mut tar_builder = tar::Builder::new(xz_encoder);
    for path in paths {
        let filename = path
            .file_name()
            .ok_or_else(|| eyre!("Failed to get file name"))?
            .to_str()
            .ok_or_else(|| eyre!("Failed to convert file name to string"))?;
        let mut header = tar::Header::new_gnu();
        header.set_path(filename)?;
        header.set_size(path.metadata()?.len());
        header.set_cksum();
        tar_builder.append(&header, File::open(path)?)?;
    }
    let xz_encoder = tar_builder.into_inner().wrap_err("Failed to finalize tar archive")?;
    xz_encoder.finish().wrap_err("Failed to finalize compression")?;
    Ok(compressed_data)
}

fn encrypt(content: &[u8], password: &SecUtf8) -> Result<Buffer> {
    let mut hasher = Blake2b::new(32)?;
    hasher.update(password.unsecure().as_bytes())?;
    let hashed_password = hasher.finalize()?;
    let secret_key = SecretKey::from_slice(hashed_password.as_ref())?;
    let nonce = Nonce::from([0u8; 12]);
    let mut encrypted_content = vec![0u8; content.len() + 16];
    chacha20poly1305::seal(&secret_key, &nonce, content, None, &mut encrypted_content)?;
    Ok(encrypted_content)
}

fn bundle(paths: &[&Path], output_path: &Path, password: &SecUtf8) -> Result<()> {
    let compressed_content = tar_xz(paths)?;
    let encrypted_content = encrypt(&compressed_content, password)?;
    fs::File::create(output_path)?.write_all(&encrypted_content)?;
    for path in paths {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

fn get_chunks_and_dirs(
    entries: &[PathBuf],
    keep_name: bool,
    bundle_count: usize,
    _bundle_size: usize,
) -> (Vec<Vec<&PathBuf>>, Vec<&PathBuf>) {
    let bundle_count = if keep_name { 1 } else { bundle_count };
    let (files, dirs): (Vec<_>, Vec<_>) = entries.iter().partition(|path| path.is_file());
    let chunks = files.chunks(bundle_count).map(|chunk| chunk.to_vec()).collect();
    (chunks, dirs)
}

fn pack(path: &Path, password: &SecUtf8, keep_name: bool, bundle_count: usize) -> Result<()> {
    if path.is_dir() {
        let entries: Vec<_> = fs::read_dir(path)?
            .map(|res| res.map(|e| e.path()))
            .collect::<Result<Vec<_>, std::io::Error>>()
            .wrap_err("Failed to read directory entries")?;
        let (chunks, dirs) = get_chunks_and_dirs(&entries, keep_name, bundle_count, 0);
        chunks
            .par_iter()
            .try_for_each(|chunk| {
                let bundle_paths: Vec<&Path> = chunk.iter().map(AsRef::as_ref).collect();
                let output_path = get_pack_path(chunk[0].as_path(), keep_name)?;
                bundle(&bundle_paths, &output_path, password)
            })
            .wrap_err("Failed to process file bundles")?;
        dirs.par_iter()
            .try_for_each(|dir| pack(dir, password, keep_name, bundle_count))?;
    } else if path.is_file() {
        let output_path = get_pack_path(path, keep_name)?;
        bundle(&[path], &output_path, password)?;
    }
    Ok(())
}

fn get_load_path(path: &Path, filename: &str) -> Result<PathBuf> {
    let output_path = path
        .parent()
        .ok_or_else(|| eyre!("Failed to get parent directory"))?
        .join(filename);
    Ok(output_path)
}

fn decrypt(path: &Path, password: &SecUtf8) -> Result<Buffer> {
    let mut file_content = vec![];
    fs::File::open(path)?.read_to_end(&mut file_content)?;
    let mut hasher = Blake2b::new(32)?;
    hasher.update(password.unsecure().as_bytes())?;
    let hashed_password = hasher.finalize()?;
    let secret_key = SecretKey::from_slice(hashed_password.as_ref())?;
    let nonce = Nonce::from([0u8; 12]);
    let mut decrypted_content = vec![0u8; file_content.len() - 16];
    match chacha20poly1305::open(&secret_key, &nonce, &file_content, None, &mut decrypted_content) {
        Ok(_) => (),
        Err(_) => return Err(eyre!("Decryption failed. The provided password may be incorrect.")),
    };
    Ok(decrypted_content)
}

fn un_tar_xz(content: &[u8]) -> Result<Vec<(Buffer, String)>> {
    let mut xz_decoder = XzDecoder::new(content);
    let mut tar_archive = tar::Archive::new(&mut xz_decoder);
    let mut results = vec![];
    for entry in tar_archive.entries()? {
        let mut entry = entry?;
        let mut uncompressed_data = vec![];
        entry.read_to_end(&mut uncompressed_data)?;
        let filename = entry
            .path()
            .wrap_err("Failed to get file path")?
            .to_str()
            .ok_or_else(|| eyre!("Failed to convert file path to string"))?
            .to_string();
        results.push((uncompressed_data, filename));
    }
    Ok(results)
}

fn load(path: &Path, password: &SecUtf8) -> Result<()> {
    if path.is_dir() {
        let entries: Result<Vec<_>, _> = fs::read_dir(path)?.collect();
        let results: Result<Vec<_>, _> = entries?.par_iter().map(|entry| load(&entry.path(), password)).collect();
        results?;
    } else if path.is_file() && path.extension().and_then(std::ffi::OsStr::to_str) == Some(STOW) {
        let decrypted_content = decrypt(path, password)?;
        for (decompressed_content, filename) in un_tar_xz(&decrypted_content)? {
            let output_path = get_load_path(path, &filename)?;
            fs::File::create(&output_path)?.write_all(&decompressed_content)?;
        }
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
            let bundle_count = if pack_cli.keep_name { 1 } else { pack_cli.bundle_count };
            for pattern in pack_cli.patterns {
                pack(Path::new(&pattern), &get_password()?, pack_cli.keep_name, bundle_count)?;
            }
        }
        Some(Command::Load(load_cli)) => {
            for pattern in load_cli.patterns {
                load(Path::new(&pattern), &get_password()?)?;
            }
        }
        None => unreachable!(),
    }
    Ok(())
}

#![allow(unused_imports)]

use clap::Parser;
use std::path::{Path, PathBuf};
use sevenz_rust::{
    compress_to_path_encrypted, 
    decompress_file_with_password,
};

use eyre::{eyre, Result};
use std::fs;
use aes::Aes256;
use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit, BlockCipher};
use xz2::write::XzEncoder;
use xz2::read::XzDecoder;
use std::io::Cursor;
use secstr::SecUtf8;
use pbkdf2::pbkdf2;
use hmac::Hmac;
use sha2::Sha256;
use std::io::Write;
use std::io::Read;
use rand::Rng;

use generic_array::GenericArray;
use generic_array::typenum::U16;

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
    password: secstr::SecUtf8,

    patterns: Vec<String>,
}

fn compress(path: &Path, password: &SecUtf8) -> Result<()> {
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            compress(&entry?.path(), password)?;  // recursive call for each directory entry
        }
    } else if path.is_file() {
        let output_filename = format!("{}.xz.aes", path.file_name()
            .ok_or_else(|| eyre!("Failed to get file name"))?
            .to_string_lossy());
        let output_path = path.parent()
            .ok_or_else(|| eyre!("Failed to get parent directory"))?
            .join(output_filename);

        let mut file = fs::File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        let mut encoder = XzEncoder::new(Vec::new(), 6);
        encoder.write_all(&buffer)?;

        let compressed_data = encoder.finish()?;

        let salt: [u8; 16] = rand::thread_rng().gen();
        let mut derived_key = [0u8; 32];
        match pbkdf2::<Hmac<Sha256>>(password.unsecure().as_bytes(), &salt, 10000, &mut derived_key) {
            Ok(_) => (),
            Err(e) => return Err(eyre::eyre!("Failed to derive key: {}", e)),
        }

        let cipher = Aes256::new(GenericArray::from_slice(&derived_key));

        let mut encrypted_data = Vec::new();
        for chunk in compressed_data.chunks(16) {
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher.encrypt_block(&mut block);
            encrypted_data.extend_from_slice(&block);
        }

        fs::write(&output_path, &encrypted_data)?;

        fs::remove_file(path)?;
    }
    Ok(())
}

/*
fn compress(path: &Path, password: &SecUtf8) -> Result<()> {
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            compress(&entry?.path(), password)?;  // recursive call for each directory entry
        }
    } else if path.is_file() {
        let output_filename = format!("{}.xz.aes", path.file_name()
            .ok_or_else(|| eyre!("Failed to get file name"))?
            .to_string_lossy());
        let output_path = path.parent()
            .ok_or_else(|| eyre!("Failed to get parent directory"))?
            .join(output_filename);

        let mut file = fs::File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        let mut encoder = XzEncoder::new(Vec::new(), 6);
        encoder.write_all(&buffer)?;

        let compressed_data = encoder.finish()?;

        let salt: [u8; 16] = rand::thread_rng().gen();
        let mut derived_key = [0u8; 32];
        match pbkdf2::<Hmac<Sha256>>(password.unsecure().as_bytes(), &salt, 10000, &mut derived_key) {
            Ok(_) => (),
            Err(e) => return Err(eyre::eyre!("Failed to derive key: {}", e)),
        }

        //let cipher = Aes256::new(GenericArray::from_slice(&derived_key));
        let cipher = Aes256::new(GenericArray::from_slice(&derived_key));


        let mut block = GenericArray::clone_from_slice(&compressed_data[..16]);
        cipher.encrypt_block(&mut block);
        let encrypted_data = block.into_iter().collect::<Vec<_>>();

        fs::write(&output_path, &encrypted_data)?;

        fs::remove_file(path)?;
    }
    Ok(())
}
*/

fn decompress(path: &Path, password: &SecUtf8) -> Result<()> {
    println!("decompressing: {:?}", path);
    if path.is_dir() {
        println!("is dir");
        for entry in fs::read_dir(path)? {
            decompress(&entry?.path(), password)?;
        }
    } else if path.is_file() {
        println!("is file");
        if path.file_name().and_then(|s| s.to_str()).map_or(false, |s| s.ends_with(".xz.aes")) {
            let encrypted_data = fs::read(path)?;

            let salt: [u8; 16] = rand::thread_rng().gen();
            let mut derived_key = [0u8; 32];
            println!("deriving key");
            match pbkdf2::<Hmac<Sha256>>(password.unsecure().as_bytes(), &salt, 10000, &mut derived_key) {
                Ok(_) => (),
                Err(e) => return Err(eyre::eyre!("Failed to derive key: {}", e)),
            }
            println!("derived key: {:?}", derived_key);

            let cipher = Aes256::new(GenericArray::from_slice(&derived_key));

            let mut decrypted_data = Vec::new();
            for chunk in encrypted_data.chunks(16) {
                println!("chunk: {:?}", chunk);
                let mut block = GenericArray::clone_from_slice(chunk);
                cipher.decrypt_block(&mut block);
                decrypted_data.extend_from_slice(&block);
            }

            let mut decoder = XzDecoder::new(Cursor::new(&decrypted_data));
            let mut decompressed_data = Vec::new();
            decoder.read_to_end(&mut decompressed_data)?;

            let output_path = path.with_extension("");
            println!("writing to: {:?}", output_path);
            fs::write(&output_path, decompressed_data)?;

            fs::remove_file(path)?;
        } else {
            println!("path={:?}; not xz.aes", path);
        }
    }
    Ok(())
}

/*
fn decompress(path: &Path, password: &SecUtf8) -> Result<()> {
    println!("decompressing: {:?}", path);
    if path.is_dir() {
        println!("is dir");
        for entry in fs::read_dir(path)? {
            decompress(&entry?.path(), password)?;
        }
    } else if path.is_file() {
        println!("is file");
        //if path.extension().and_then(|s| s.to_str()) == Some("xz.aes") {
            if path.file_name().and_then(|s| s.to_str()).map_or(false, |s| s.ends_with(".xz.aes")) {
            let encrypted_data = fs::read(path)?;

            let salt: [u8; 16] = rand::thread_rng().gen();
            let mut derived_key = [0u8; 32];
            println!("deriving key");
            match pbkdf2::<Hmac<Sha256>>(password.unsecure().as_bytes(), &salt, 10000, &mut derived_key) {
                Ok(_) => (),
                Err(e) => return Err(eyre::eyre!("Failed to derive key: {}", e)),
            }
            println!("derived key: {:?}", derived_key);

            let cipher = Aes256::new(GenericArray::from_slice(&derived_key));

            let mut block = GenericArray::clone_from_slice(&encrypted_data[..16]);
            cipher.decrypt_block(&mut block);
            let decrypted_data = block.into_iter().collect::<Vec<_>>();

            let mut decoder = XzDecoder::new(Cursor::new(&decrypted_data));
            let mut decompressed_data = Vec::new();
            decoder.read_to_end(&mut decompressed_data)?;

            let output_path = path.with_extension("");
            println!("writing to: {:?}", output_path);
            fs::write(&output_path, decompressed_data)?;

            fs::remove_file(path)?;
        } else {
            println!("path={:?}; not xz.aes", path);
        }

    }
    Ok(())
}
*/
/*
fn decompress(path: &Path, password: &SecUtf8) -> Result<()> {
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            decompress(&entry?.path(), password)?;
        }
    } else if path.is_file() {
        if path.extension().and_then(|s| s.to_str()) == Some("xz.aes") {
            let encrypted_data = fs::read(path)?;

            let salt: [u8; 16] = rand::thread_rng().gen();
            let mut derived_key = [0u8; 32];
            match pbkdf2::<Hmac<Sha256>>(password.unsecure().as_bytes(), &salt, 10000, &mut derived_key) {
                Ok(_) => (),
                Err(e) => return Err(eyre::eyre!("Failed to derive key: {}", e)),
            }

            let cipher = Aes256::new(GenericArray::from_slice(&derived_key));

            let mut block = GenericArray::clone_from_slice(&encrypted_data[..16]);
            cipher.decrypt_block(&mut block);
            let decrypted_data = block.into_iter().collect::<Vec<_>>();

            let mut decoder = XzDecoder::new(decrypted_data.as_slice());
            let mut decompressed_data = Vec::new();
            decoder.read_to_end(&mut decompressed_data)?;

            let output_path = path.with_extension("");
            fs::write(&output_path, decompressed_data)?;

            fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn decompress(path: &Path, password: &SecUtf8) -> Result<()> {
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            decompress(&entry?.path(), password)?;
        }
    } else if path.is_file() {
        if path.extension().and_then(|s| s.to_str()) == Some("7z") {
            let temp_dir = tempfile::tempdir()?;
            decompress_file_with_password(path, &temp_dir.path(), password.unsecure().into())?;
            let decompressed_file = temp_dir.path().join(path.file_stem().ok_or_else(|| eyre!("Failed to get file stem"))?);
            let output_path = path.with_extension("");
            fs::rename(&decompressed_file, &output_path)?;
            fs::remove_file(path)?;
            temp_dir.close()?;
        }
    }
    Ok(())
}
*/

fn main() -> Result<()> {
    let cli = Cli::parse();
    println!("{:?}", cli);
    match cli.command {
        Some(Command::Compress(compress_cli)) => {
            for pattern in compress_cli.patterns {
                compress(Path::new(&pattern), &compress_cli.password)?;
            }
        },
        Some(Command::Decompress(decompress_cli)) => {
            for pattern in decompress_cli.patterns {
                decompress(Path::new(&pattern), &decompress_cli.password)?;
            }
        },
        None => {
            return Err(eyre!("no command"));
        },
    }
    Ok(())
}

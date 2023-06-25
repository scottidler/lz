use std::fs;
use clap::Parser;
use eyre::{eyre, Result};
use std::path::{Path, PathBuf};
use secstr::SecUtf8;
use sevenz_rust::{
    compress_to_path_encrypted, 
    decompress_file_with_password,
};

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
        let output_filename = format!("{}.7z", path.file_name()
            .ok_or_else(|| eyre::eyre!("Failed to get file name"))?
            .to_string_lossy());
        let output_path = path.parent()
            .ok_or_else(|| eyre::eyre!("Failed to get parent directory"))?
            .join(output_filename);
        compress_to_path_encrypted(path, &output_path, password.unsecure().into())?;
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

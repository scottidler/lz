//#![allow(unused_imports, dead_code)]

use clap::Parser;
use eyre::{eyre, Result, WrapErr};
use log::info;
use log::LevelFilter;
use log4rs::{
    append::file::FileAppender,
    config::{Appender, Config, Root},
    encode::pattern::PatternEncoder,
};

use rayon::prelude::*;
use secstr::SecUtf8;
use std::fs;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tempfile::Builder;

use std::io;
use std::process::{Command, Stdio};

const SEVENZ: &str = "7z";

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
    action: Option<Action>,
}

#[derive(Clone, Debug, Parser)]
enum Action {
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
        short = 'c',
        long,
        value_name = "INT",
        default_value = "2",
        help = "number files per archive"
    )]
    bundle_count: usize,

    #[clap(
        short = 's',
        long,
        value_name = "BYTES",
        default_value = "1M",
        value_parser = parse_size,
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
    info!("get_pack_path: path={path:?} keep_name={keep_name}");
    let output_filename = if keep_name {
        format!(
            "{}.{}",
            path.file_name()
                .ok_or_else(|| eyre!("Failed to get file name"))?
                .to_string_lossy(),
            SEVENZ
        )
    } else {
        Builder::new()
            .suffix(&format!(".{SEVENZ}"))
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
        .ok_or_else(|| eyre!("Failed to get parent directory for path: {:?}", path))?
        .join(output_filename);

    Ok(output_path)
}

fn bundle_7z(paths: &[&Path], output_path: &Path, password: &SecUtf8) -> Result<()> {
    let cwd = std::env::current_dir()?;
    info!("bundle_7z: paths={paths:?} output_path={output_path:?} cwd={cwd:?}");

    let sevenz = "7zz";
    let mut command = Command::new(sevenz);
    command
        .arg("a")
        .arg("-p")
        .arg("-mhe=on")
        .arg(output_path)
        .args(paths)
        .stdin(Stdio::piped());

    info!("bundle_7z: command: {:?}", command);

    let mut child = command.spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| eyre!("Failed to get stdin for 7z process"))?;
    io::Write::write_all(&mut stdin, password.unsecure().as_bytes())?;
    stdin.flush()?;
    drop(stdin);

    let status = child.wait()?;
    if status.success() {
        for path in paths {
            std::fs::remove_file(path)?;
        }
    } else {
        return Err(eyre!("7zz command failed with status: {}", status));
    }

    Ok(())
}

fn get_chunks_and_dirs(
    entries: &[PathBuf],
    keep_name: bool,
    bundle_count: usize,
    _bundle_size: usize,
) -> (Vec<Vec<&PathBuf>>, Vec<&PathBuf>) {
    info!(
        "get_chunks_and_dirs: entries.len()={} keep_name={} bundle_count={}",
        entries.len(),
        keep_name,
        bundle_count
    );
    let bundle_count = if keep_name { 1 } else { bundle_count };
    let (files, dirs): (Vec<_>, Vec<_>) = entries.iter().partition(|path| path.is_file());
    let chunks = files.chunks(bundle_count).map(|chunk| chunk.to_vec()).collect();
    (chunks, dirs)
}

fn pack(path: &Path, password: &SecUtf8, keep_name: bool, bundle_count: usize) -> Result<()> {
    info!("pack: path={path:?} keep_name={keep_name} bundle_count={bundle_count}");

    if path.is_dir() {
        info!("pack: path is dir");
        let entries: Vec<_> = fs::read_dir(path)?
            .map(|res| res.map(|e| e.path()))
            .collect::<Result<Vec<_>, std::io::Error>>()
            .wrap_err("Failed to read directory entries")?;
        let (chunks, dirs) = get_chunks_and_dirs(&entries, keep_name, bundle_count, 0);
        chunks
            .par_iter()
            .try_for_each(|chunk| {
                let bundle_paths: Vec<&Path> = chunk.iter().map(AsRef::as_ref).collect();
                info!("pack: bundle_paths={bundle_paths:?}");
                let output_path = get_pack_path(chunk[0].as_path(), keep_name)?;
                info!("pack: output_path={output_path:?}");
                bundle_7z(&bundle_paths, &output_path, password)
            })
            .wrap_err("Failed to process file bundles")?;
        dirs.par_iter()
            .try_for_each(|dir| pack(dir, password, keep_name, bundle_count))?;
    } else if path.is_file() {
        info!("pack: path is file");
        let output_path = get_pack_path(path, keep_name)?;
        info!("pack: output_path={output_path:?}");
        bundle_7z(&[path], &output_path, password)?;
    }
    Ok(())
}

fn unbundle_7z(path: &Path, password: &SecUtf8) -> Result<()> {
    info!("unbundle_7z: path={path:?}");
    let sevenz = "7zz";
    let mut command = Command::new(sevenz);
    command.arg("x").arg(path).stdin(Stdio::piped());

    info!("unbundle_7z: command: {:?}", command);

    let mut child = command.spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| eyre!("Failed to get stdin for 7z process"))?;
    io::Write::write_all(&mut stdin, password.unsecure().as_bytes())?;
    stdin.flush()?;
    drop(stdin);

    let status = child.wait()?;
    if status.success() {
        std::fs::remove_file(path)?;
    } else {
        return Err(eyre!("7z command failed with exit status: {:?}", status.code()));
    }

    Ok(())
}

fn load(path: &Path, password: &SecUtf8) -> Result<()> {
    info!("load: path={path:?}");
    if path.is_dir() {
        info!("load: path is dir");
        let entries: Result<Vec<_>, _> = fs::read_dir(path)?.collect();
        let results: Result<Vec<_>, _> = entries?.par_iter().map(|entry| load(&entry.path(), password)).collect();
        results?;
    } else if path.is_file() && path.extension().and_then(std::ffi::OsStr::to_str) == Some(SEVENZ) {
        info!("load: path is file and the extension is stow");
        unbundle_7z(path, password)?;
    }
    Ok(())
}

fn get_password() -> Result<SecUtf8> {
    let prompt = "Please enter your password: ";
    let password = SecUtf8::from(rpassword::prompt_password(prompt)?);
    Ok(password)
}

fn setup_logging() -> Result<()> {
    let log_file_path = std::env::current_exe()?
        .parent()
        .ok_or_else(|| eyre::eyre!("Failed to get parent directory"))?
        .join("stow.log");

    let logfile = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new("{d(%Y-%m-%d %H:%M:%S%.3f)} [{l}] {m}{n}")))
        .build(log_file_path)?;

    let config = Config::builder()
        .appender(Appender::builder().build("logfile", Box::new(logfile)))
        .build(Root::builder().appender("logfile").build(LevelFilter::Info))?;
    log4rs::init_config(config)?;
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    setup_logging()?;

    match cli.action {
        Some(Action::Pack(pack_cli)) => {
            for pattern in pack_cli.patterns {
                pack(
                    Path::new(&pattern),
                    &get_password()?,
                    pack_cli.keep_name,
                    pack_cli.bundle_count,
                )?;
            }
        }
        Some(Action::Load(load_cli)) => {
            for pattern in load_cli.patterns {
                load(Path::new(&pattern), &get_password()?)?;
            }
        }
        None => unreachable!(),
    }
    Ok(())
}

mod checksum;
mod ioutil;
mod metainfo;

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Error, Result};
use bendy::encoding::ToBencode;
use clap::Parser;
use metainfo::{PieceLength, Torrent, MAX_FILE_PATH_DEPTH};
use walkdir::WalkDir;

#[derive(Parser)]
#[clap(name = "mktorrent-rs")]
#[clap(author = "Stephen Weinberg <stephenmweinberg@gmail.com>")]
#[clap(version = "0.1-SNAPSHOT")]
#[clap(about = "Create torrent v2 files", long_about = None)]
struct Cli {
    #[clap(long)]
    announce: String,

    /// The exponent of the piece_length. Must be between 14 and 40.
    #[clap(long, value_name = "EXPONENT")]
    piece_length: u8,

    root: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let root = cli.root;

    let piece_length = {
        if cli.piece_length < 14 || cli.piece_length > 40 {
            return Err(Error::msg("--piece-length must be between 14 and 40"));
        }

        PieceLength {
            layers: cli.piece_length - 14,
        }
    };

    let torrent_name =
        torrent_name_from_path(&root).context("could not convert root filename to UTF-8")?;

    let mut torrent = Torrent::new(cli.announce, torrent_name.clone(), piece_length);

    let metadata =
        fs::metadata(&root).context(format!("failed to stat `{}`", root.to_string_lossy()))?;

    if metadata.is_file() {
        let filename = &torrent_name;
        let dir = root.parent().unwrap_or_else(|| Path::new(""));

        add_file(&mut torrent, dir, piece_length, filename, metadata.len())?;
    } else {
        for (file, l) in get_file_list(&root)? {
            add_file(&mut torrent, &root, piece_length, &file, l)?;
        }
    }

    let encoded = torrent.to_bencode().unwrap();
    io::stdout().write_all(&encoded).unwrap();

    Ok(())
}

fn add_file(
    torrent: &mut Torrent,
    root: &Path,
    piece_length: PieceLength,
    path: &str,
    file_length: u64,
) -> Result<()> {
    let (f, pieces_layer) = {
        let r = ioutil::ClonableFile::new(root.join(path));
        checksum::checksum_file_multithreaded(piece_length, file_length, r)
            .context("failed to checksum file")?
    };

    if !torrent.add_file(path, f, pieces_layer) {
        return Err(Error::msg("conflicting file"));
    }

    Ok(())
}

// Returns the relative path from the root for each file in the root.
fn get_file_list(root: &Path) -> Result<Vec<(String, u64)>> {
    let mut ret = Vec::new();

    for entry in WalkDir::new(root) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }

        if entry.depth() >= MAX_FILE_PATH_DEPTH {
            return Err(Error::msg(format!(
                "hit max file depth ({}) at file: {}",
                MAX_FILE_PATH_DEPTH,
                entry.path().to_string_lossy(),
            )));
        }

        let rel_path = entry.path().strip_prefix(root).unwrap();

        let rel_path_str = rel_path
            .to_str()
            .ok_or_else(|| {
                Error::msg(format!(
                    "cannot convert path to UTF-8: {}",
                    rel_path.to_string_lossy(),
                ))
            })?
            .to_owned();

        let l = entry.metadata()?.len();

        ret.push((rel_path_str, l));
    }

    Ok(ret)
}

// Build the torrent name from the root directory or file.
fn torrent_name_from_path(p: &Path) -> Option<String> {
    Some(p.file_name()?.to_str()?.to_owned())
}

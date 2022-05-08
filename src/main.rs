mod checksum;
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

    /// n where n is 16KiB * 2^n
    #[clap(long)]
    piece_length: u8,

    #[clap(parse(from_os_str))]
    root: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let root = cli.root;

    let piece_length = PieceLength {
        layers: cli.piece_length,
    };

    let torrent_name =
        torrent_name_from_path(&root).context("could not convert root filename to UTF-8")?;

    let mut torrent = Torrent::new(cli.announce, torrent_name.clone(), piece_length);

    let metadata =
        fs::metadata(&root).context(format!("failed to stat `{}`", root.to_string_lossy()))?;

    if metadata.is_file() {
        let filename = &torrent_name;
        let dir = root.parent().unwrap_or(Path::new(""));
        add_file(&mut torrent, dir, piece_length, filename)?;
    } else {
        let files = get_file_list(&root)?;
        for file in files {
            add_file(&mut torrent, &root, piece_length, &file)?;
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
) -> Result<()> {
    let (f, pieces_layer) = {
        let f = fs::File::open(root.join(path)).context("failed to open file")?;
        checksum::checksum_file(piece_length, f).context("failed to read file")?
    };

    if !torrent.add_file(&path, f, pieces_layer) {
        return Err(Error::msg("conflicting file"));
    }

    Ok(())
}

// Returns the relative path from the root for each file in the root.
fn get_file_list(root: &Path) -> Result<Vec<String>> {
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

        ret.push(rel_path_str);
    }

    Ok(ret)
}

// Build the torrent name from the root directory or file.
fn torrent_name_from_path(p: &Path) -> Option<String> {
    Some(p.file_name()?.to_str()?.to_owned())
}

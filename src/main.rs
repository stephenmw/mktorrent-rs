mod checksum;
mod metainfo;

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use bendy::encoding::ToBencode;
use clap::Parser;
use metainfo::{Directory, Info, PieceLength, Torrent};

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

    let (f, pieces_layer) = {
        let f = fs::File::open(&root).context("failed to open file")?;
        checksum::checksum_file(piece_length, f).context("failed to read file")?
    };

    let filename = torrent_name.clone();

    let torrent = Torrent {
        announce: cli.announce,
        info: Info {
            name: torrent_name,
            piece_length: piece_length,
            file_tree: Directory {
                entries: HashMap::from([(filename, f.into())]),
            },
        },
        piece_layers: HashMap::from([(f.pieces_root, pieces_layer)]),
    };

    let encoded = torrent.to_bencode().unwrap();
    io::stdout().write_all(&encoded).unwrap();

    Ok(())
}

// Build the torrent name from the root directory or file.
fn torrent_name_from_path(p: &PathBuf) -> Option<String> {
    Some(p.file_name()?.to_str()?.to_owned())
}

mod checksum;
mod metainfo;

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

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
    file: PathBuf,
}

fn main() {
    let cli = Cli::parse();

    let f = fs::File::open(&cli.file).expect("failed to open file");
    let piece_length = PieceLength {
        layers: cli.piece_length,
    };
    let (f, pieces_layer) = checksum::checksum_file(piece_length, f).expect("failed to read file");

    let filename = cli.file.to_string_lossy().into_owned();

    let torrent = Torrent {
        announce: cli.announce,
        info: Info {
            name: filename.clone(),
            piece_length: piece_length,
            file_tree: Directory {
                entries: HashMap::from([(filename, f.into())]),
            },
        },
        piece_layers: HashMap::from([(f.pieces_root, pieces_layer)]),
    };

    let encoded = torrent.to_bencode().unwrap();
    io::stdout().write_all(&encoded).unwrap();
}

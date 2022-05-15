extern crate ring;

pub mod merkle;
pub mod sha256;
pub mod torrent2;

pub use torrent2::{checksum_file, checksum_file_multithreaded};

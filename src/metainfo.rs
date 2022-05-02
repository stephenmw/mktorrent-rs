extern crate ring;

use std::collections::HashMap;

use bendy::encoding::{AsString, Error, SingleItemEncoder, ToBencode};
use ring::digest::SHA256_OUTPUT_LEN;

const META_VERSION: u8 = 2;
// Arbitrary maximum depth for a path to protect against bad torrent files.
const MAX_FILE_PATH_DEPTH: usize = 20;

pub type Sha256Digest = [u8; SHA256_OUTPUT_LEN];

// A Torrent metainfo file defined in bep_0052.
#[derive(Clone, Debug)]
pub struct Torrent {
    pub announce: String,
    pub info: Info,
    pub piece_layers: HashMap<Sha256Digest, Vec<Sha256Digest>>,
}

impl ToBencode for Torrent {
    const MAX_DEPTH: usize = Info::MAX_DEPTH + 1;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), Error> {
        encoder.emit_dict(|mut e| {
            e.emit_pair(b"announce", &self.announce)?;
            e.emit_pair(b"info", &self.info)?;
            e.emit_pair_with(b"piece layers", |e| {
                e.emit_unsorted_dict(|e| {
                    for (k, v) in self.piece_layers.iter() {
                        // TODO: Reduce copies here.
                        // bendy requires an entire string to be provided as a
                        // single value. This results in an unneeded copy
                        // causing a total of 3 copies to be in memory.
                        if v.is_empty() {
                            continue;
                        }
                        let mut buf = Vec::with_capacity(v.len() * Sha256Digest::default().len());
                        v.iter().for_each(|s| buf.extend_from_slice(s.as_slice()));
                        e.emit_pair(k, AsString(&buf))?;
                    }
                    Ok(())
                })
            })
        })
    }
}

#[derive(Clone, Debug)]
pub struct Info {
    pub name: String,
    pub piece_length: PieceLength,
    pub file_tree: Directory,
}

impl ToBencode for Info {
    const MAX_DEPTH: usize = Directory::MAX_DEPTH + 1;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), Error> {
        encoder.emit_dict(|mut e| {
            e.emit_pair(b"file tree", &self.file_tree)?;
            e.emit_pair(b"meta version", META_VERSION)?;
            e.emit_pair(b"name", &self.name)?;
            e.emit_pair(b"piece length", self.piece_length.bytes())
        })
    }
}

#[derive(Clone, Debug)]
pub enum PathElement {
    Directory(Directory),
    File(File),
}

impl ToBencode for PathElement {
    const MAX_DEPTH: usize = Directory::MAX_DEPTH;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), Error> {
        match self {
            PathElement::Directory(d) => encoder.emit(d),
            PathElement::File(f) => encoder.emit(f),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Directory {
    pub entries: HashMap<String, PathElement>,
}

impl ToBencode for Directory {
    const MAX_DEPTH: usize = MAX_FILE_PATH_DEPTH + File::MAX_DEPTH;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), Error> {
        encoder.emit_unsorted_dict(|e| {
            for (k, v) in self.entries.iter() {
                e.emit_pair(k.as_bytes(), v)?;
            }

            Ok(())
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct File {
    pub length: u64,
    pub pieces_root: Sha256Digest,
}

impl ToBencode for File {
    const MAX_DEPTH: usize = 2;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), Error> {
        // A file is encoded as a dictionary containing a key "" which contains
        // file information.
        encoder.emit_dict(|mut e| {
            e.emit_pair_with(b"", |e| {
                e.emit_dict(|mut e| {
                    e.emit_pair(b"length", self.length)?;
                    if self.length != 0 {
                        e.emit_pair(b"pieces root", AsString(self.pieces_root.as_slice()))?;
                    }
                    Ok(())
                })
            })
        })
    }
}

// The piece length of a v2 torrent. It is measured in number of layers in the
// merkle tree.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct PieceLength {
    pub layers: u8,
}

impl PieceLength {
    // Takes a number of bytes and returns a piece length. Return None if an
    // invalid n is used. n must be a power of two greater than 16KiB (2^14).
    pub fn from_bytes(n: u64) -> Option<Self> {
        let layers = log2(n).filter(|&n| n >= 14).map(|n| n - 14)?;
        Some(PieceLength { layers: layers })
    }

    pub fn bytes(&self) -> u64 {
        1 << (self.layers as u64 + 14)
    }
}

// Returns log2 of the number if an only if it is a perfect power of 2.
fn log2(mut n: u64) -> Option<u8> {
    if n == 0 {
        return None;
    }

    let mut count = 0;
    while n & 1 != 1 {
        n >>= 1;
        count += 1;
    }

    if n >> 1 == 0 {
        Some(count)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Encodes the object to bencode and converts it to a String.
    //
    // # Panics
    //
    // This function will panic if to_bencode() fails or the resulting bencode
    // is not valid UTF-8.
    fn to_bencode_str<T: ToBencode>(b: T) -> String {
        let ret = b.to_bencode().unwrap();
        String::from_utf8(ret).unwrap()
    }

    #[test]
    fn file_encode() {
        let f = File {
            length: 1024,
            pieces_root: ['a' as u8; 32],
        };

        assert_eq!(
            to_bencode_str(f),
            "d0:d6:lengthi1024e11:pieces root32:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaee",
        );
    }

    #[test]
    fn file_encode_zerolen() {
        let f = File {
            length: 0,
            pieces_root: ['a' as u8; 32],
        };

        assert_eq!(to_bencode_str(f), "d0:d6:lengthi0eee",);
    }

    #[test]
    fn torrent_encode_maxdepth() {
        let mut t = Torrent {
            announce: "http://announce.example.com:8080".to_string(),
            info: Info {
                name: "my display name".to_string(),
                piece_length: PieceLength { layers: 0 },
                file_tree: Directory {
                    entries: HashMap::new(),
                },
            },
            piece_layers: HashMap::new(),
        };

        let f = File {
            length: 0,
            pieces_root: ['a' as u8; 32],
        };

        let mut p = PathElement::File(f);
        for _ in 0..MAX_FILE_PATH_DEPTH {
            p = PathElement::Directory(Directory {
                entries: HashMap::from([("a_dir".to_owned(), p)]),
            });
        }

        // test with p at max depth
        t.info.file_tree = match p.clone() {
            PathElement::Directory(d) => d,
            _ => unreachable!(),
        };
        t.to_bencode().unwrap();

        p = PathElement::Directory(Directory {
            entries: HashMap::from([("a_dir".to_owned(), p)]),
        });

        // Test that 1 past max depth is NestingTooDeep. Due to StructureError
        // being private, we need to use a string comparison.
        t.info.file_tree = match p {
            PathElement::Directory(d) => d,
            _ => unreachable!(),
        };
        let err = t.to_bencode().unwrap_err();
        if !format!("{:?}", err).contains("NestingTooDeep") {
            panic!("should be NestingTooDeep, instead: {:?}", err)
        }
    }

    #[test]
    fn directory_encode() {
        let d = Directory {
            entries: HashMap::from([
                (
                    "file1".to_owned(),
                    PathElement::File(File {
                        length: 1024,
                        pieces_root: ['a' as u8; 32],
                    }),
                ),
                (
                    "file2".to_owned(),
                    PathElement::File(File {
                        length: 0,
                        pieces_root: ['b' as u8; 32],
                    }),
                ),
                (
                    "dir1".to_owned(),
                    PathElement::Directory(Directory {
                        entries: HashMap::from([(
                            "file3".to_owned(),
                            PathElement::File(File {
                                length: 0,
                                pieces_root: ['b' as u8; 32],
                            }),
                        )]),
                    }),
                ),
            ]),
        };

        assert_eq!(
            to_bencode_str(d),
            "d4:dir1d5:file3d0:d6:lengthi0eeee5:file1d0:d6:lengthi1024e11:pieces root32:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaee5:file2d0:d6:lengthi0eeee",
        );
    }

    #[test]
    fn torrent_encode() {
        let t = Torrent {
            announce: "http://announce.example.com:8080".to_string(),
            info: Info {
                name: "my display name".to_string(),
                piece_length: PieceLength { layers: 5 },
                file_tree: Directory {
                    entries: HashMap::from([(
                        "file1".to_owned(),
                        PathElement::File(File {
                            length: 1024,
                            pieces_root: ['a' as u8; 32],
                        }),
                    )]),
                },
            },
            piece_layers: HashMap::from([(
                ['a' as u8; 32],
                vec![['b' as u8; 32], ['c' as u8; 32]],
            )]),
        };

        assert_eq!(
            to_bencode_str(t),
            "d8:announce32:http://announce.example.com:80804:infod9:file treed5:file1d0:d6:lengthi1024e11:pieces root32:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaeee12:meta versioni2e4:name15:my display name12:piece lengthi524288ee12:piece layersd32:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa64:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbccccccccccccccccccccccccccccccccee",
        );
    }

    #[test]
    fn piece_length() {
        let tests = [14, 15, 25];

        for t in tests {
            assert_eq!(1 << t, PieceLength::from_bytes(1 << t).unwrap().bytes())
        }

        assert_eq!(PieceLength::from_bytes(0), None);
        assert_eq!(PieceLength::from_bytes(1 << 4), None);
        assert_eq!(PieceLength::from_bytes(1 << 13), None);
        assert_eq!(
            PieceLength::from_bytes(1 << 14),
            Some(PieceLength { layers: 0 })
        );
    }
}

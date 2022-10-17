extern crate ring;

use std::collections::{hash_map::Entry, HashMap};

use crate::checksum::sha256;

use bendy::encoding::{AsString, Error, SingleItemEncoder, ToBencode};

const META_VERSION: u8 = 2;
// Arbitrary maximum depth for a path to protect against bad torrent files.
pub const MAX_FILE_PATH_DEPTH: usize = 20;

// A Torrent metainfo file defined in bep_0052.
#[derive(Clone, Debug)]
pub struct Torrent {
    pub announce: String,
    pub info: Info,
    pub piece_layers: HashMap<sha256::Digest, Vec<sha256::Digest>>,
}

impl Torrent {
    pub fn new(announce: String, name: String, piece_length: PieceLength) -> Self {
        Torrent {
            announce,
            info: Info {
                name,
                piece_length,
                file_tree: Directory::default(),
            },
            piece_layers: HashMap::new(),
        }
    }

    // Adds a file to the torrent. If the file already exists or the path is
    // invalid, no action is taken and false is returned.
    pub fn add_file(&mut self, path: &str, f: File, pieces_layer: Vec<sha256::Digest>) -> bool {
        let mut components = path.split('/');
        let first_component = match components.next() {
            Some(x) => x,
            // the path has no components.
            None => return false,
        };
        let mut cur_dir = self
            .info
            .file_tree
            .entries
            .entry(first_component.to_owned());

        for c in components {
            cur_dir = match cur_dir
                .or_insert_with(|| Directory::default().into())
                .get_entry(c.to_owned())
            {
                Some(x) => x,
                // the path contains a component that is already a file
                None => return false,
            };
        }

        match cur_dir {
            // The file was added before
            Entry::Occupied(_) => return false,
            Entry::Vacant(v) => v.insert(f.into()),
        };

        // TODO: check for piece layer already existing.
        if !pieces_layer.is_empty() {
            self.piece_layers.insert(f.pieces_root, pieces_layer);
        }

        true
    }
}

impl ToBencode for Torrent {
    const MAX_DEPTH: usize = Info::MAX_DEPTH + 1;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), Error> {
        encoder.emit_dict(|mut e| {
            e.emit_pair(b"announce", &self.announce)?;
            e.emit_pair(b"info", &self.info)?;
            e.emit_pair_with(b"piece layers", |e| {
                e.emit_dict(|mut e| {
                    // Sort layers to emit them in order.
                    let mut layers: Vec<_> = self.piece_layers.iter().collect();
                    layers.sort_unstable_by_key(|&(k, _)| k);

                    let max_len = layers.iter().map(|&(_, v)| v.len()).max().unwrap_or(0);
                    let mut buf = Vec::with_capacity(max_len * sha256::Digest::LENGTH);

                    for (k, v) in layers {
                        if v.is_empty() {
                            continue;
                        }

                        buf.truncate(0);
                        v.iter().for_each(|s| buf.extend_from_slice(s.as_ref()));
                        e.emit_pair(k.as_ref(), AsString(&buf))?;
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

impl PathElement {
    // Returns an Entry if the PathElement is a Direcory, otherwise None.
    fn get_entry(&mut self, name: String) -> Option<Entry<'_, String, PathElement>> {
        match self {
            Self::Directory(ref mut d) => Some(d.get_entry(name)),
            _ => None,
        }
    }
}

impl From<Directory> for PathElement {
    fn from(d: Directory) -> Self {
        Self::Directory(d)
    }
}

impl From<File> for PathElement {
    fn from(f: File) -> Self {
        Self::File(f)
    }
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

#[derive(Clone, Debug, Default)]
pub struct Directory {
    pub entries: HashMap<String, PathElement>,
}

impl Directory {
    fn get_entry(&mut self, name: String) -> Entry<'_, String, PathElement> {
        self.entries.entry(name)
    }
}

impl ToBencode for Directory {
    const MAX_DEPTH: usize = MAX_FILE_PATH_DEPTH + File::MAX_DEPTH;

    fn encode(&self, encoder: SingleItemEncoder) -> Result<(), Error> {
        encoder.emit_dict(|mut e| {
            let mut entries: Vec<_> = self.entries.iter().collect();
            entries.sort_unstable_by_key(|&(k, _)| k);

            for (k, v) in entries {
                e.emit_pair(k.as_bytes(), v)?;
            }

            Ok(())
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct File {
    pub length: u64,
    pub pieces_root: sha256::Digest,
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
                        e.emit_pair(b"pieces root", AsString(self.pieces_root.as_ref()))?;
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
    #[allow(dead_code)]
    pub fn from_bytes(n: u64) -> Option<Self> {
        let layers = log2(n).filter(|&n| n >= 14).map(|n| n - 14)?;
        Some(PieceLength { layers })
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
            pieces_root: ['a' as u8; 32].into(),
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
            pieces_root: ['a' as u8; 32].into(),
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
            pieces_root: ['a' as u8; 32].into(),
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
                        pieces_root: ['a' as u8; 32].into(),
                    }),
                ),
                (
                    "file2".to_owned(),
                    PathElement::File(File {
                        length: 0,
                        pieces_root: ['b' as u8; 32].into(),
                    }),
                ),
                (
                    "dir1".to_owned(),
                    PathElement::Directory(Directory {
                        entries: HashMap::from([(
                            "file3".to_owned(),
                            PathElement::File(File {
                                length: 0,
                                pieces_root: ['b' as u8; 32].into(),
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
                            pieces_root: ['a' as u8; 32].into(),
                        }),
                    )]),
                },
            },
            piece_layers: HashMap::from([(
                ['a' as u8; 32].into(),
                vec![['b' as u8; 32].into(), ['c' as u8; 32].into()],
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

    #[test]
    fn torrent_add_file() {
        let mut torrent = Torrent::new("".to_string(), "".to_string(), PieceLength { layers: 0 });
        assert_eq!(true, torrent.add_file("a.txt", File::default(), Vec::new()));
        assert_eq!(torrent.piece_layers.len(), 0); // empty pieces_layer results in it not being added

        // adding the same file results in a conflict
        assert_eq!(
            false,
            torrent.add_file("a.txt", File::default(), Vec::new())
        );

        // adding a different file does not
        assert_eq!(true, torrent.add_file("b.txt", File::default(), Vec::new()));

        // directories work
        assert_eq!(
            true,
            torrent.add_file("c/d.txt", File::default(), Vec::new())
        );

        // cannot use an existing file as a directory
        assert_eq!(
            false,
            torrent.add_file("c/d.txt/e", File::default(), Vec::new())
        );

        // non-empty pieces_layer is added to pieces_layers
        assert_eq!(
            true,
            torrent.add_file(
                "c/f.txt",
                File {
                    pieces_root: ['a' as u8; 32].into(),
                    length: 1
                },
                vec![sha256::Digest::default(), sha256::Digest::default()]
            )
        );
        assert_eq!(
            torrent.piece_layers.get(&['a' as u8; 32].into()).unwrap(),
            &vec![sha256::Digest::default(), sha256::Digest::default()]
        );
    }
}

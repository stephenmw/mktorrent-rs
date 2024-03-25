use std::cmp;
use std::io::{self, Read, Write};

use positioned_io::{Cursor, ReadAt, Slice};
use rayon::prelude::*;

use crate::checksum::{merkle, sha256};
use crate::metainfo::{self, PieceLength};

const BLOCK_SIZE: usize = 16 << 10; // 16MiB

// Produces the metainfo and piece_layer for a file.
pub fn checksum_file(
    piece_length: PieceLength,
    mut r: impl Read,
) -> io::Result<(metainfo::File, Vec<sha256::Digest>)> {
    let l = piece_length.bytes();
    let mut pieces_layer = Vec::new();
    let mut hasher = PieceV2Hasher::new(piece_length);
    let mut read = 0;

    // If the first piece is incomplete, we need to handle it specially.
    let mut piece = (&mut r).take(l);
    let n = io::copy(&mut piece, &mut hasher)?;
    read += n;
    if n == 0 {
        return Ok((metainfo::File::default(), Vec::new()));
    } else if n == l {
        pieces_layer.push(hasher.finish());
    } else {
        let f = metainfo::File {
            pieces_root: hasher.finish_first_piece(),
            length: read,
        };
        return Ok((f, Vec::new()));
    }

    loop {
        let mut piece = (&mut r).take(l);
        let n = io::copy(&mut piece, &mut hasher)?;
        read += n;
        if n == 0 {
            // end of file
            break;
        }

        pieces_layer.push(hasher.finish());

        if n < l {
            // Partial piece read means end of file. Attempting to read may
            // return more but would be unaligned.
            break;
        }
    }

    let f = metainfo::File {
        pieces_root: merkle::root_hash(piece_length.layers, &pieces_layer),
        length: read,
    };

    Ok((f, pieces_layer))
}

// Produces the metainfo and piece_layer for a file.
pub fn checksum_file_multithreaded<T: ReadAt + Sync>(
    piece_length: PieceLength,
    file_length: u64,
    r: &T,
) -> io::Result<(metainfo::File, Vec<sha256::Digest>)> {
    let piece_bytes = piece_length.bytes();
    let num_pieces = {
        file_length / piece_length.bytes()
            + if file_length % piece_length.bytes() > 0 {
                1
            } else {
                0
            }
    };

    // Files with less than 2 pieces have edge cases and would not benefit from
    // multithreading.
    if num_pieces <= 1 {
        return checksum_file(piece_length, piece_reader(r, 0, piece_bytes));
    }

    // Number of pieces to process at a time.
    let batch_size = cmp::max((128 << 20) / piece_length.bytes(), 1);

    let pieces_layer = (0..num_pieces as usize)
        .into_par_iter()
        .with_min_len(batch_size as usize)
        .map_with(r, |r, idx| {
            let mut piece =
                io::BufReader::with_capacity(1 << 20, piece_reader(r, idx as u64, piece_bytes));
            let mut hasher = PieceV2Hasher::new(piece_length);

            let expected_length = {
                if idx as u64 != num_pieces - 1 || file_length % piece_length.bytes() == 0 {
                    piece_length.bytes()
                } else {
                    file_length % piece_length.bytes()
                }
            };

            let n = io::copy(&mut piece, &mut hasher)?;
            if n != expected_length {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF",
                ));
            }

            Ok(hasher.finish())
        })
        .collect::<Result<Vec<_>, _>>()?;

    let f = metainfo::File {
        pieces_root: merkle::root_hash(piece_length.layers, &pieces_layer),
        length: file_length,
    };

    Ok((f, pieces_layer))
}

#[derive(Clone)]
struct PieceV2Hasher {
    piece_length: PieceLength,
    block_hasher: sha256::Hasher,
    block_pos: usize,
    merkle: merkle::Hasher,
}

impl PieceV2Hasher {
    fn new(piece_length: PieceLength) -> Self {
        Self {
            piece_length,
            block_hasher: sha256::Hasher::default(),
            block_pos: 0,
            merkle: merkle::Hasher::default(),
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let n = self.update_block(data);
            data = &data[n..];
        }
    }

    // Returns the hash of the piece. This resets the hasher making it reusable
    // for the next piece. Panics if too much data was provided.
    fn finish(&mut self) -> sha256::Digest {
        self.finish_block();
        let ret = self
            .merkle
            .finish_layer(&sha256::Digest::default(), self.piece_length.layers)
            .unwrap();
        self.reset();
        ret
    }

    fn finish_first_piece(&mut self) -> sha256::Digest {
        self.finish_block();
        self.merkle.finish_tree(&sha256::Digest::default())
    }

    fn reset(&mut self) {
        self.block_hasher = sha256::Hasher::default();
        self.block_pos = 0;
        self.merkle.reset();
    }

    fn update_block(&mut self, data: &[u8]) -> usize {
        let needed = BLOCK_SIZE - self.block_pos;
        let n = cmp::min(needed as usize, data.len());

        self.block_hasher.update(&data[..n]);
        self.block_pos += n;

        if self.block_pos == BLOCK_SIZE {
            self.finish_block();
        }

        n
    }

    fn finish_block(&mut self) {
        if self.block_pos == 0 {
            return;
        }

        self.block_pos = 0;
        let digest = self.block_hasher.finish();
        self.merkle.add_block(&digest);
    }
}

impl Write for PieceV2Hasher {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // no-op
        Ok(())
    }
}

fn piece_reader<I: ReadAt>(io: I, index: u64, piece_length: u64) -> Cursor<Slice<I>> {
    Cursor::new(Slice::new(io, index * piece_length, Some(piece_length)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_file_empty() {
        let piece_length = metainfo::PieceLength::from_bytes(64 << 10).unwrap();
        let (f, pieces_layer) = checksum_file(piece_length, io::empty()).unwrap();

        assert_eq!(
            f,
            metainfo::File {
                length: 0,
                pieces_root: [0; 32].into()
            }
        );
        assert_eq!(pieces_layer, Vec::new());
    }

    #[test]
    fn checksum_file_zeros() {
        const L: u64 = 65 << 10;
        let input_file = [0u8; L as usize].as_slice();
        let piece_length = metainfo::PieceLength::from_bytes(32 << 10).unwrap();
        let (f, pieces_layer) = checksum_file_multithreaded(piece_length, L, &input_file).unwrap();
        assert_eq!(
            f,
            metainfo::File {
                length: 65 << 10,
                pieces_root: [
                    230, 159, 27, 131, 197, 211, 213, 133, 84, 248, 147, 160, 97, 88, 105, 146, 81,
                    144, 15, 69, 203, 145, 187, 180, 46, 23, 211, 74, 172, 184, 160, 31
                ]
                .into()
            }
        );

        assert_eq!(
            pieces_layer,
            vec![
                [
                    195, 109, 13, 214, 168, 134, 225, 252, 231, 88, 182, 181, 197, 49, 183, 3, 161,
                    242, 30, 143, 100, 83, 120, 92, 57, 9, 49, 207, 143, 168, 167, 109
                ]
                .into(),
                [
                    195, 109, 13, 214, 168, 134, 225, 252, 231, 88, 182, 181, 197, 49, 183, 3, 161,
                    242, 30, 143, 100, 83, 120, 92, 57, 9, 49, 207, 143, 168, 167, 109
                ]
                .into(),
                [
                    118, 213, 104, 91, 215, 13, 55, 194, 193, 92, 75, 88, 26, 143, 165, 141, 178,
                    34, 112, 190, 188, 193, 9, 178, 238, 100, 156, 170, 146, 39, 134, 82
                ]
                .into(),
            ]
        );
    }

    #[test]
    fn checksum_file_lessthan_block() {
        let input_file = "test".as_bytes();
        let piece_length = metainfo::PieceLength::from_bytes(32 << 10).unwrap();
        let (f, pieces_layer) =
            checksum_file_multithreaded(piece_length, input_file.len() as u64, &input_file)
                .unwrap();
        assert_eq!(
            f,
            metainfo::File {
                length: 4,
                pieces_root: [
                    159, 134, 208, 129, 136, 76, 125, 101, 154, 47, 234, 160, 197, 90, 208, 21,
                    163, 191, 79, 27, 43, 11, 130, 44, 209, 93, 108, 21, 176, 240, 10, 8
                ]
                .into()
            }
        );

        assert_eq!(pieces_layer, Vec::new());
    }
}

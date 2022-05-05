extern crate ring;

use crate::metainfo::{self, SHA256Digest};
use ring::digest;
use std::cmp;
use std::io::{self, Read, Write};
use std::mem;

const BLOCK_SIZE: usize = 16 << 10; // 16MiB

// Returns the root, length and pieces_layer of a file.
pub fn checksum_file<T: Read>(
    piece_length: metainfo::PieceLength,
    mut r: T,
) -> io::Result<(metainfo::File, Vec<SHA256Digest>)> {
    let mut hasher = FileV2Hasher::new(piece_length);
    io::copy(&mut r, &mut hasher)?;
    Ok(hasher.finish())
}

#[derive(Clone)]
pub struct FileV2Hasher {
    piece_length: metainfo::PieceLength,

    // Number of bytes written in the file.
    length: u64,

    // Hasher for the current block. Must be a sha256 context.
    ctx: digest::Context,
    // Number of bytes written in the current block.
    block_cur: usize,

    piece_merkle: MerkleHasher,
    pieces_layer: Vec<SHA256Digest>,
}

impl FileV2Hasher {
    pub fn new(piece_length: metainfo::PieceLength) -> Self {
        Self {
            piece_length: piece_length,
            ctx: new_sha256_ctx(),
            length: 0,
            block_cur: 0,
            piece_merkle: MerkleHasher::new(),
            pieces_layer: Vec::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        fn update_block(t: &mut FileV2Hasher, data: &[u8]) -> (usize, Option<SHA256Digest>) {
            let needed = BLOCK_SIZE - t.block_cur;
            let n = cmp::min(needed as usize, data.len());
            t.ctx.update(&data[..n]);
            t.block_cur += n;

            if t.block_cur == BLOCK_SIZE {
                (n, Some(t.finish_block()))
            } else {
                (n, None)
            }
        }

        self.length += data.len() as u64;

        let mut data = data;
        while data.len() > 0 {
            let (n, block_digest) = update_block(self, data);
            data = &data[n..];
            if let Some(d) = block_digest {
                self.piece_merkle.add_block(d);
                if let Some(l) = self.piece_merkle.current_layer() {
                    if l == self.piece_length.layers {
                        self.pieces_layer.push(self.piece_merkle.finish());
                    }
                }
            }
        }
    }

    fn finish_block(&mut self) -> SHA256Digest {
        self.block_cur = 0;

        let ctx = mem::replace(&mut self.ctx, new_sha256_ctx());
        let digest = ctx.finish();

        digest.try_into().expect("must be sha256 context")
    }

    // Returns the File and pieces_layer. This resets the hasher.
    pub fn finish(&mut self) -> (metainfo::File, Vec<SHA256Digest>) {
        if self.block_cur > 0 {
            let d = self.finish_block();
            self.piece_merkle.add_block(d);
        }

        if !self.piece_merkle.is_empty() {
            let d = self.piece_merkle.finish();
            self.pieces_layer.push(d);
        }

        // calculate file root
        let mut hasher = MerkleHasher::new();
        self.pieces_layer.iter().for_each(|&d| hasher.add_block(d));
        let root = hasher.finish();

        // A pieces_layer with only one value contains the pieces_root. We can
        // ignore it.
        let pieces_layer = if self.pieces_layer.len() > 1 {
            mem::take(&mut self.pieces_layer)
        } else {
            Vec::new()
        };

        let f = metainfo::File {
            length: self.length,
            pieces_root: if self.length > 0 {
                root
            } else {
                SHA256Digest::default()
            },
        };

        self.reset();

        (f, pieces_layer)
    }

    // Resets the hasher so it can be reused.
    pub fn reset(&mut self) {
        self.ctx = new_sha256_ctx();
        self.length = 0;
        self.block_cur = 0;
        self.piece_merkle.reset();
        self.pieces_layer.truncate(0);
    }
}

impl Write for FileV2Hasher {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // no-op
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct MerkleHasher {
    stack: Vec<MerkleHasherEntry>,
}

impl MerkleHasher {
    fn new() -> Self {
        Self::default()
    }

    // Adds an entry to the bottom layer of the merkle tree.
    fn add_block(&mut self, hash: SHA256Digest) {
        self.stack.push(MerkleHasherEntry::new(hash));
        while self.stack.len() >= 2
            && self.stack[self.stack.len() - 1].layer == self.stack[self.stack.len() - 2].layer
        {
            let b = self.stack.pop().unwrap();
            let a = self.stack.pop().unwrap();

            let d = MerkleHasher::combine_digests(a.digest, b.digest);
            self.stack.push(MerkleHasherEntry {
                layer: a.layer + 1,
                digest: d,
            });
        }
    }

    // Computes SHA256(a + b).
    fn combine_digests(a: SHA256Digest, b: SHA256Digest) -> SHA256Digest {
        let mut ctx = new_sha256_ctx();
        ctx.update(a.as_ref());
        ctx.update(b.as_ref());
        let digest = ctx.finish();

        digest.try_into().expect("must be sha256 context")
    }

    // Returns the current layer if that layer is complete, otherwise None.
    fn current_layer(&self) -> Option<u8> {
        if self.stack.len() == 1 {
            Some(self.stack[0].layer)
        } else {
            None
        }
    }

    fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }

    // Completes the merkle tree using zeroed out digests. Returns the root of
    // the tree. If the MerkleHasher started with no blocks, the output is
    // undefined. The hasher is reset after returning the digest.
    fn finish(&mut self) -> SHA256Digest {
        while self.stack.len() != 1 {
            self.add_block(SHA256Digest::default());
        }

        let ret = self.stack[0].digest;
        self.reset();
        ret
    }

    // Reset the hasher so it can be reused.
    fn reset(&mut self) {
        self.stack.truncate(0);
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct MerkleHasherEntry {
    layer: u8,
    digest: SHA256Digest,
}

impl MerkleHasherEntry {
    fn new(digest: SHA256Digest) -> Self {
        Self { layer: 0, digest }
    }
}

// Returns a new SHA256 context
fn new_sha256_ctx() -> digest::Context {
    digest::Context::new(&digest::SHA256)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_file_empty() {
        let piece_length = metainfo::PieceLength::from_bytes(64 << 10).unwrap();
        let mut h = FileV2Hasher::new(piece_length);
        let (f, pieces_layer) = h.finish();

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
        let buf = [0; 120 << 10];
        let piece_length = metainfo::PieceLength::from_bytes(32 << 10).unwrap();
        let (f, pieces_layer) = checksum_file(piece_length, buf.as_ref()).unwrap();
        assert_eq!(
            f,
            metainfo::File {
                length: 120 << 10,
                pieces_root: [
                    200, 18, 209, 25, 120, 198, 164, 171, 58, 203, 242, 135, 1, 92, 0, 243, 175,
                    245, 140, 86, 145, 70, 124, 111, 150, 150, 245, 81, 151, 231, 182, 73
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
                    195, 109, 13, 214, 168, 134, 225, 252, 231, 88, 182, 181, 197, 49, 183, 3, 161,
                    242, 30, 143, 100, 83, 120, 92, 57, 9, 49, 207, 143, 168, 167, 109
                ]
                .into(),
                [
                    194, 166, 105, 204, 134, 68, 171, 139, 37, 16, 113, 141, 63, 249, 27, 178, 69,
                    219, 16, 61, 251, 2, 103, 128, 162, 223, 72, 98, 78, 76, 129, 248
                ]
                .into()
            ]
        );
    }
}

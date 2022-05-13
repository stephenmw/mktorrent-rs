use crate::checksum::sha256;

// Calculate the root hash of a merkle tree given a layer of the merkle tree.
// Missing hashes are assumed to be zeros at layer zero.
pub fn root_hash<'a>(
    layer: u8,
    digests: impl IntoIterator<Item = &'a sha256::Digest>,
) -> sha256::Digest {
    let mut hasher = Hasher::new();
    for d in digests {
        hasher.add_block(d);
    }

    hasher.finish_tree(&zero_root(layer))
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Hasher {
    stack: Vec<Entry>,
}

impl Hasher {
    pub fn new() -> Self {
        Self::default()
    }

    // Adds an entry to the bottom layer of the merkle tree.
    pub fn add_block(&mut self, hash: &sha256::Digest) {
        self.stack.push(Entry::new(*hash));
        while self.stack.len() >= 2
            && self.stack[self.stack.len() - 1].layer == self.stack[self.stack.len() - 2].layer
        {
            let b = self.stack.pop().unwrap();
            let a = self.stack.pop().unwrap();

            let d = Hasher::combine_digests(&a.digest, &b.digest);
            self.stack.push(Entry {
                layer: a.layer + 1,
                digest: d,
            });
        }
    }

    // Computes SHA256(a + b).
    fn combine_digests(a: &sha256::Digest, b: &sha256::Digest) -> sha256::Digest {
        let mut h = sha256::Hasher::default();
        h.update(a.as_ref());
        h.update(b.as_ref());
        h.into_digest()
    }

    // Returns the current layer if that layer is complete, otherwise None.
    pub fn current_layer(&self) -> Option<u8> {
        if self.stack.len() == 1 {
            Some(self.stack[0].layer)
        } else {
            None
        }
    }

    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }

    // Adds the pad to the merkle tree until there is a single root. This
    // resets the hasher.
    pub fn finish_tree(&mut self, pad: &sha256::Digest) -> sha256::Digest {
        while self.stack.len() != 1 {
            self.add_block(pad);
        }

        let ret = self.stack[0].digest;
        self.reset();
        ret
    }

    // Adds the pad to the merkle tree until the root is at the given layer. If
    // the next root is greater than the given layer, None is returned. In
    // either case the hasher is reset.s
    pub fn finish_layer(&mut self, pad: &sha256::Digest, layer: u8) -> Option<sha256::Digest> {
        if let Some(e) = self.stack.first() {
            // If we have too many blocks, we can't pad to reach tht layer.
            if e.layer > layer || (e.layer == layer && self.stack.len() > 1) {
                self.reset();
                return None;
            }
        }

        while self.current_layer().map(|l| l < layer).unwrap_or(true) {
            self.add_block(pad);
        }

        let ret = self.stack[0].digest;
        self.reset();
        Some(ret)
    }

    // Reset the hasher so it can be reused.
    pub fn reset(&mut self) {
        self.stack.truncate(0);
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Entry {
    layer: u8,
    digest: sha256::Digest,
}

impl Entry {
    fn new(digest: sha256::Digest) -> Self {
        Self { layer: 0, digest }
    }
}

// Calculates the merkle root of a tree with the given layer assuming all input
// blocks are zeroed digests.
pub fn zero_root(layer: u8) -> sha256::Digest {
    let mut d = sha256::Digest::default();
    for _ in 0..layer {
        d = Hasher::combine_digests(&d, &d);
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finish_reset() {
        // test that finish resets the hasher
        let a = ['a' as u8; sha256::Digest::LENGTH].try_into().unwrap();
        let b = ['b' as u8; sha256::Digest::LENGTH].try_into().unwrap();
        let mut h = Hasher::new();
        h.add_block(&a);
        assert_eq!(h.finish_tree(&sha256::Digest::default()), a);
        h.add_block(&b);
        assert_eq!(h.finish_tree(&sha256::Digest::default()), b);
    }

    #[test]
    fn test_no_blocks() {
        // no blocks returns a zeroed Digest
        assert_eq!(root_hash(0, []), sha256::Digest::default());
    }

    #[test]
    fn test_single_block() {
        // acts as an identity function
        let d = ['a' as u8; sha256::Digest::LENGTH].try_into().unwrap();
        assert_eq!(root_hash(0, [&d]), d);
    }

    #[test]
    fn test_two_blocks() {
        // returns the hash of a + b
        let a = ['a' as u8; sha256::Digest::LENGTH].try_into().unwrap();
        let b = ['b' as u8; sha256::Digest::LENGTH].try_into().unwrap();
        assert_eq!(
            root_hash(0, [&a, &b]),
            [
                253, 210, 166, 77, 1, 79, 44, 64, 109, 46, 206, 103, 194, 50, 18, 169, 43, 53, 99,
                20, 244, 222, 180, 43, 36, 195, 149, 41, 110, 227, 4, 210
            ]
            .into()
        );
    }

    #[test]
    fn test_five_blocks() {
        // forms a merkle tree adding 3 zeroed Digests to complete the tree
        let a = ['a' as u8; sha256::Digest::LENGTH].try_into().unwrap();
        let b = ['b' as u8; sha256::Digest::LENGTH].try_into().unwrap();
        let c = ['c' as u8; sha256::Digest::LENGTH].try_into().unwrap();
        let d = ['d' as u8; sha256::Digest::LENGTH].try_into().unwrap();
        let e = ['e' as u8; sha256::Digest::LENGTH].try_into().unwrap();
        assert_eq!(
            root_hash(0, [&a, &b, &c, &d, &e]),
            [
                222, 68, 145, 88, 43, 139, 111, 195, 30, 55, 91, 172, 218, 123, 131, 66, 207, 14,
                90, 238, 92, 245, 212, 7, 254, 132, 100, 221, 80, 132, 186, 238
            ]
            .into()
        );
    }
}

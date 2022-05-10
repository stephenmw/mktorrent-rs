use crate::checksum::sha256;

// Calculate the root hash of a merkle tree given the leaf hashes. Missing leaf
// hashes are replaced with zeros.
pub fn root_hash(digests: impl IntoIterator<Item = sha256::Digest>) -> sha256::Digest {
    let mut hasher = Hasher::new();
    for d in digests {
        hasher.add_block(d);
    }

    hasher.finish()
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
    pub fn add_block(&mut self, hash: sha256::Digest) {
        self.stack.push(Entry::new(hash));
        while self.stack.len() >= 2
            && self.stack[self.stack.len() - 1].layer == self.stack[self.stack.len() - 2].layer
        {
            let b = self.stack.pop().unwrap();
            let a = self.stack.pop().unwrap();

            let d = Hasher::combine_digests(a.digest, b.digest);
            self.stack.push(Entry {
                layer: a.layer + 1,
                digest: d,
            });
        }
    }

    // Computes SHA256(a + b).
    fn combine_digests(a: sha256::Digest, b: sha256::Digest) -> sha256::Digest {
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

    // Completes the merkle tree using zeroed out digests. Returns the root of
    // the tree. If the MerkleHasher is finished with no blocks added, the
    // output is a zeroed digest. The hasher is reset after returning the
    // digest.
    pub fn finish(&mut self) -> sha256::Digest {
        while self.stack.len() != 1 {
            self.add_block(sha256::Digest::default());
        }

        let ret = self.stack[0].digest;
        self.reset();
        ret
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finish_reset() {
        // test that finish resets the hasher
        let a = ['a' as u8; sha256::Digest::LENGTH].try_into().unwrap();
        let b = ['b' as u8; sha256::Digest::LENGTH].try_into().unwrap();
        let mut h = Hasher::new();
        h.add_block(a);
        assert_eq!(h.finish(), a);
        h.add_block(b);
        assert_eq!(h.finish(), b);
    }

    #[test]
    fn test_no_blocks() {
        // no blocks returns a zeroed Digest
        assert_eq!(root_hash([]), sha256::Digest::default());
    }

    #[test]
    fn test_single_block() {
        // acts as an identity function
        let d = ['a' as u8; sha256::Digest::LENGTH].try_into().unwrap();
        assert_eq!(root_hash([d]), d);
    }

    #[test]
    fn test_two_blocks() {
        // returns the hash of a + b
        let a = ['a' as u8; sha256::Digest::LENGTH].try_into().unwrap();
        let b = ['b' as u8; sha256::Digest::LENGTH].try_into().unwrap();
        assert_eq!(
            root_hash([a, b]),
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
            root_hash([a, b, c, d, e]),
            [
                222, 68, 145, 88, 43, 139, 111, 195, 30, 55, 91, 172, 218, 123, 131, 66, 207, 14,
                90, 238, 92, 245, 212, 7, 254, 132, 100, 221, 80, 132, 186, 238
            ]
            .into()
        );
    }
}

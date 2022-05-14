use std::io::Write;

use ring::digest::Digest as RingDigest;
use ring::digest::{self, SHA256_OUTPUT_LEN};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest([u8; SHA256_OUTPUT_LEN]);

impl Digest {
    pub const LENGTH: usize = SHA256_OUTPUT_LEN;
}

impl std::convert::AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl std::convert::From<Digest> for [u8; Digest::LENGTH] {
    fn from(d: Digest) -> Self {
        d.0
    }
}

impl std::convert::From<[u8; Digest::LENGTH]> for Digest {
    fn from(a: [u8; Digest::LENGTH]) -> Self {
        Self(a)
    }
}

impl std::convert::TryFrom<RingDigest> for Digest {
    type Error = &'static str;
    fn try_from(d: RingDigest) -> Result<Self, Self::Error> {
        if d.algorithm() != &digest::SHA256 {
            return Err("Sha256Digest can only be created from a SHA256 Digest");
        }

        let mut ret = [0; Self::LENGTH];
        ret.copy_from_slice(d.as_ref());
        Ok(Self(ret))
    }
}

#[derive(Clone)]
pub struct Hasher {
    ctx: digest::Context,
}

impl Hasher {
    pub fn update(&mut self, data: &[u8]) {
        self.ctx.update(data);
    }

    // Returns the digest and resets the hash.
    pub fn finish(&mut self) -> Digest {
        std::mem::take(self).into_digest()
    }

    // Finishes and destroys the hasher instead of resetting.
    pub fn into_digest(self) -> Digest {
        // try_into is guaranteed because ctx is a digest::SHA256 ctx.
        self.ctx.finish().try_into().unwrap()
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self {
            ctx: digest::Context::new(&digest::SHA256),
        }
    }
}

impl Write for Hasher {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // no-op
        Ok(())
    }
}

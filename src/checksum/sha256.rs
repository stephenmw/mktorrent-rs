use ring::digest::Digest as RingDigest;
use ring::digest::{SHA256, SHA256_OUTPUT_LEN};

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

impl std::convert::From<[u8; Digest::LENGTH]> for Digest {
    fn from(a: [u8; Digest::LENGTH]) -> Self {
        Self(a)
    }
}

impl std::convert::Into<[u8; Digest::LENGTH]> for Digest {
    fn into(self) -> [u8; Digest::LENGTH] {
        self.0
    }
}

impl std::convert::TryFrom<RingDigest> for Digest {
    type Error = &'static str;
    fn try_from(d: RingDigest) -> Result<Self, Self::Error> {
        if d.algorithm() != &SHA256 {
            return Err("Sha256Digest can only be created from a SHA256 Digest");
        }

        let mut ret = [0; Self::LENGTH];
        ret.copy_from_slice(d.as_ref());
        Ok(Self(ret))
    }
}

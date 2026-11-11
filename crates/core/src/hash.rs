use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::encode::{Decode, DecodeError, Encode, Reader};

/// A SHA-256 digest. Displayed and serialized as lowercase hex.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    pub const ZERO: Self = Self([0; 32]);

    /// BIP340-style tagged hash: `sha256(sha256(tag) || sha256(tag) || data)`.
    /// Tags keep hashes from different contexts from ever colliding.
    pub fn tagged(tag: &str, data: &[u8]) -> Self {
        let tag_hash = Sha256::digest(tag.as_bytes());
        let mut h = Sha256::new();
        h.update(tag_hash);
        h.update(tag_hash);
        h.update(data);
        Self(h.finalize().into())
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash256({self})")
    }
}

impl FromStr for Hash256 {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut out = [0; 32];
        hex::decode_to_slice(s, &mut out)?;
        Ok(Self(out))
    }
}

impl Serialize for Hash256 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Hash256 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl Encode for Hash256 {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

impl Decode for Hash256 {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self(r.array()?))
    }
}

/// Merkle root over leaf hashes, RFC 6962 style: leaves and inner nodes use
/// distinct tags and an odd node is promoted rather than duplicated, so two
/// different leaf lists cannot produce the same root.
pub fn merkle_root(leaves: &[Hash256]) -> Hash256 {
    if leaves.is_empty() {
        return Hash256::tagged("namespace/merkle-empty", &[]);
    }
    let mut level: Vec<Hash256> = leaves
        .iter()
        .map(|l| Hash256::tagged("namespace/merkle-leaf", &l.0))
        .collect();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [a, b] => {
                    let mut buf = [0; 64];
                    buf[..32].copy_from_slice(&a.0);
                    buf[32..].copy_from_slice(&b.0);
                    Hash256::tagged("namespace/merkle-node", &buf)
                }
                [a] => *a,
                _ => unreachable!(),
            })
            .collect();
    }
    level[0]
}

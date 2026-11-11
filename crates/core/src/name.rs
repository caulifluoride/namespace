use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::encode::{Decode, DecodeError, Encode, Reader, put_bytes};

pub const MAX_NAME_LEN: usize = 63;

/// A registrable name: 1–63 characters of `a-z`, `0-9` and `-`, not starting
/// or ending with `-`. The rules match a DNS label, so every name can be used
/// as one.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(String);

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NameError {
    #[error("name must be 1-{MAX_NAME_LEN} characters")]
    Length,
    #[error("name may only contain a-z, 0-9 and '-'")]
    Charset,
    #[error("name may not start or end with '-'")]
    Hyphen,
}

impl Name {
    pub fn new(s: &str) -> Result<Self, NameError> {
        if s.is_empty() || s.len() > MAX_NAME_LEN {
            return Err(NameError::Length);
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(NameError::Charset);
        }
        if s.starts_with('-') || s.ends_with('-') {
            return Err(NameError::Hyphen);
        }
        Ok(Self(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name({})", self.0)
    }
}

impl FromStr for Name {
    type Err = NameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for Name {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Name {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::new(&s).map_err(serde::de::Error::custom)
    }
}

impl Encode for Name {
    fn encode(&self, out: &mut Vec<u8>) {
        put_bytes(out, self.0.as_bytes());
    }
}

impl Decode for Name {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let bytes = r.bytes(MAX_NAME_LEN)?;
        let s = std::str::from_utf8(bytes).map_err(|_| DecodeError::Invalid("name"))?;
        Self::new(s).map_err(|_| DecodeError::Invalid("name"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation() {
        assert!(Name::new("alice").is_ok());
        assert!(Name::new("a-1").is_ok());
        assert!(Name::new(&"a".repeat(63)).is_ok());
        assert_eq!(Name::new(""), Err(NameError::Length));
        assert_eq!(Name::new(&"a".repeat(64)), Err(NameError::Length));
        assert_eq!(Name::new("Alice"), Err(NameError::Charset));
        assert_eq!(Name::new("a.b"), Err(NameError::Charset));
        assert_eq!(Name::new("-a"), Err(NameError::Hyphen));
        assert_eq!(Name::new("a-"), Err(NameError::Hyphen));
    }
}

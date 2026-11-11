//! Canonical consensus encoding.
//!
//! Everything that gets hashed or signed goes through this module, so the
//! format is fixed and hand-written rather than delegated to a serde backend:
//! little-endian fixed-width integers, length-prefixed byte strings, and
//! decoders that reject trailing bytes and non-canonical input.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("unexpected end of input")]
    UnexpectedEof,
    #[error("trailing bytes after value")]
    TrailingBytes,
    #[error("length {0} exceeds limit {1}")]
    TooLong(usize, usize),
    #[error("invalid {0}")]
    Invalid(&'static str),
}

pub trait Encode {
    fn encode(&self, out: &mut Vec<u8>);

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }
}

pub trait Decode: Sized {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError>;

    /// Decodes a value that must span the whole input.
    fn from_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let value = Self::decode(&mut r)?;
        r.finish()?;
        Ok(value)
    }
}

pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.buf.len() < n {
            return Err(DecodeError::UnexpectedEof);
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        Ok(self.take(N)?.try_into().expect("length checked"))
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// Reads a `u32`-length-prefixed byte string of at most `max` bytes.
    pub fn bytes(&mut self, max: usize) -> Result<&'a [u8], DecodeError> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(DecodeError::TooLong(len, max));
        }
        self.take(len)
    }

    pub fn finish(self) -> Result<(), DecodeError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}

pub fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(
        out,
        u32::try_from(bytes.len()).expect("byte string fits in u32"),
    );
    out.extend_from_slice(bytes);
}

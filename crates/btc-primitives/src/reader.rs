//! A bounds-checked cursor over a byte slice.
//!
//! Bitcoin's serialisation format is a flat stream of little-endian integers,
//! length-prefixed byte strings, and hashes. Parsing it by hand means tracking
//! an offset and checking every read against the end of the buffer — which is
//! exactly the sort of tedium that produces panics on malformed input.
//!
//! This wraps that up so parsers below read as a list of fields, and a
//! truncated input produces an error rather than a panic.

use crate::hash::Sha256dHash;
use crate::varint;
use core::fmt;

/// A cursor over a byte slice, reading Bitcoin's serialisation primitives.
pub struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    /// Starts reading at the beginning of `bytes`.
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    /// How many bytes are left unread.
    pub const fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    /// Whether everything has been consumed.
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Reads exactly `count` bytes.
    pub fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], ReadError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(ReadError::UnexpectedEnd)?;

        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(ReadError::UnexpectedEnd)?;

        self.position = end;
        Ok(slice)
    }

    /// Reads a fixed-size array.
    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], ReadError> {
        Ok(self
            .read_bytes(N)?
            .try_into()
            .expect("read_bytes returned exactly N bytes"))
    }

    /// Reads a little-endian `u32`.
    pub fn read_u32(&mut self) -> Result<u32, ReadError> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    /// Reads a little-endian `i32`.
    pub fn read_i32(&mut self) -> Result<i32, ReadError> {
        Ok(i32::from_le_bytes(self.read_array()?))
    }

    /// Reads a little-endian `u64`.
    pub fn read_u64(&mut self) -> Result<u64, ReadError> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    /// Reads a 32-byte hash in internal order.
    pub fn read_hash(&mut self) -> Result<Sha256dHash, ReadError> {
        Ok(Sha256dHash::from_internal_bytes(self.read_array()?))
    }

    /// Reads a CompactSize integer.
    pub fn read_varint(&mut self) -> Result<u64, ReadError> {
        let (value, consumed) = varint::decode(&self.bytes[self.position..])?;
        self.position += consumed;
        Ok(value)
    }

    /// Reads a CompactSize length followed by that many bytes.
    ///
    /// This is how scripts, witness items, and most other variable-length
    /// fields are encoded.
    pub fn read_var_bytes(&mut self) -> Result<&'a [u8], ReadError> {
        let length = self.read_varint()?;
        let length = usize::try_from(length).map_err(|_| ReadError::UnexpectedEnd)?;
        self.read_bytes(length)
    }
}

/// Why a read failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadError {
    /// The input ended before the field did.
    UnexpectedEnd,
    /// A CompactSize field was malformed.
    BadVarInt(varint::VarIntError),
}

impl From<varint::VarIntError> for ReadError {
    fn from(error: varint::VarIntError) -> Self {
        Self::BadVarInt(error)
    }
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEnd => write!(f, "input ended before the field did"),
            Self::BadVarInt(error) => write!(f, "malformed varint: {error}"),
        }
    }
}

impl std::error::Error for ReadError {}

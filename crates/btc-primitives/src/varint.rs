//! Bitcoin's variable-length integer encoding ("CompactSize").
//!
//! Counts appear everywhere in Bitcoin's serialisation format — how many inputs
//! a transaction has, how many bytes are in a script, how many transactions are
//! in a block — and almost all of them are small. CompactSize spends one byte
//! on values under 253 and only grows when it has to.
//!
//! | First byte | Total size | Encodes |
//! |---|---|---|
//! | `0x00..=0xFC` | 1 | the value itself |
//! | `0xFD` | 3 | a `u16`, little-endian |
//! | `0xFE` | 5 | a `u32`, little-endian |
//! | `0xFF` | 9 | a `u64`, little-endian |
//!
//! Note this is *not* the same as the "VarInt" used in Bitcoin Core's internal
//! database code, which is a different format entirely. The name collision is
//! unfortunate and has confused a lot of people; this module implements the one
//! used on the wire and in blocks.

/// Appends `value` to `out` in CompactSize form.
pub fn encode(value: u64, out: &mut Vec<u8>) {
    match value {
        // Values below 0xFD encode as themselves. 0xFD, 0xFE and 0xFF are
        // reserved as length prefixes, which is why the boundary is 253 and
        // not 256.
        0..=0xFC => out.push(value as u8),
        0xFD..=0xFFFF => {
            out.push(0xFD);
            out.extend_from_slice(&(value as u16).to_le_bytes());
        }
        0x1_0000..=0xFFFF_FFFF => {
            out.push(0xFE);
            out.extend_from_slice(&(value as u32).to_le_bytes());
        }
        _ => {
            out.push(0xFF);
            out.extend_from_slice(&value.to_le_bytes());
        }
    }
}

/// How many bytes `encode` will write for `value`.
pub fn encoded_len(value: u64) -> usize {
    match value {
        0..=0xFC => 1,
        0xFD..=0xFFFF => 3,
        0x1_0000..=0xFFFF_FFFF => 5,
        _ => 9,
    }
}

/// Reads a CompactSize from the front of `bytes`.
///
/// Returns the value and how many bytes it occupied.
///
/// Rejects **non-canonical** encodings — a value that could have been written
/// in fewer bytes, such as `FD 05 00` for 5. Bitcoin Core rejects these, so
/// accepting them here would mean our idea of a valid block differs from the
/// network's, which is precisely the kind of disagreement that would make a
/// mined block get rejected.
pub fn decode(bytes: &[u8]) -> Result<(u64, usize), VarIntError> {
    let first = *bytes.first().ok_or(VarIntError::UnexpectedEnd)?;

    // Reads a little-endian integer of N bytes starting at offset 1.
    fn read_le<const N: usize>(bytes: &[u8]) -> Result<u64, VarIntError> {
        let slice: [u8; N] = bytes
            .get(1..1 + N)
            .ok_or(VarIntError::UnexpectedEnd)?
            .try_into()
            .expect("slice length checked by get()");
        let mut buf = [0u8; 8];
        buf[..N].copy_from_slice(&slice);
        Ok(u64::from_le_bytes(buf))
    }

    match first {
        0..=0xFC => Ok((first as u64, 1)),
        0xFD => {
            let value = read_le::<2>(bytes)?;
            if value < 0xFD {
                return Err(VarIntError::NonCanonical);
            }
            Ok((value, 3))
        }
        0xFE => {
            let value = read_le::<4>(bytes)?;
            if value <= 0xFFFF {
                return Err(VarIntError::NonCanonical);
            }
            Ok((value, 5))
        }
        0xFF => {
            let value = read_le::<8>(bytes)?;
            if value <= 0xFFFF_FFFF {
                return Err(VarIntError::NonCanonical);
            }
            Ok((value, 9))
        }
    }
}

/// Why a CompactSize could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarIntError {
    /// The input ended before the encoding was complete.
    UnexpectedEnd,
    /// The value was encoded in more bytes than necessary.
    NonCanonical,
}

impl core::fmt::Display for VarIntError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedEnd => write!(f, "input ended mid-varint"),
            Self::NonCanonical => write!(f, "varint encoded in more bytes than necessary"),
        }
    }
}

impl std::error::Error for VarIntError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four size classes and the exact boundaries between them.
    #[test]
    fn boundaries() {
        let cases: &[(u64, &[u8])] = &[
            (0, &[0x00]),
            (252, &[0xFC]),
            (253, &[0xFD, 0xFD, 0x00]),
            (0xFFFF, &[0xFD, 0xFF, 0xFF]),
            (0x1_0000, &[0xFE, 0x00, 0x00, 0x01, 0x00]),
            (0xFFFF_FFFF, &[0xFE, 0xFF, 0xFF, 0xFF, 0xFF]),
            (0x1_0000_0000, &[0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]),
        ];

        for (value, expected) in cases {
            let mut out = Vec::new();
            encode(*value, &mut out);
            assert_eq!(&out, expected, "encoding {value}");
            assert_eq!(encoded_len(*value), expected.len(), "encoded_len of {value}");
            assert_eq!(decode(expected).unwrap(), (*value, expected.len()));
        }
    }

    #[test]
    fn round_trips() {
        for value in [0, 1, 252, 253, 1000, 65535, 65536, u32::MAX as u64, u64::MAX] {
            let mut out = Vec::new();
            encode(value, &mut out);
            assert_eq!(decode(&out).unwrap().0, value);
        }
    }

    #[test]
    fn rejects_non_canonical() {
        // 5 written as a 3-byte encoding.
        assert_eq!(decode(&[0xFD, 0x05, 0x00]), Err(VarIntError::NonCanonical));
        // 300 written as a 5-byte encoding.
        assert_eq!(
            decode(&[0xFE, 0x2C, 0x01, 0x00, 0x00]),
            Err(VarIntError::NonCanonical)
        );
    }

    #[test]
    fn rejects_truncated() {
        assert_eq!(decode(&[]), Err(VarIntError::UnexpectedEnd));
        assert_eq!(decode(&[0xFD, 0x01]), Err(VarIntError::UnexpectedEnd));
        assert_eq!(decode(&[0xFF, 0x00]), Err(VarIntError::UnexpectedEnd));
    }
}

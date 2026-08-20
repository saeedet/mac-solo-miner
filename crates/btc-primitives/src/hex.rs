//! Hex encoding and decoding.
//!
//! Not Bitcoin-specific, but unavoidable: every RPC that returns bytes returns
//! them as hex, and every test vector in this project is written as hex. It
//! lives here so the RPC client, the miner, and the tests all share one
//! implementation rather than three subtly different ones.

use core::fmt;

/// Encodes bytes as lowercase hex.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // `write!` to a String cannot fail, so the result is safely discarded.
        use fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Decodes a hex string. Accepts upper or lower case, rejects anything else.
pub fn decode(s: &str) -> Result<Vec<u8>, HexError> {
    if !s.len().is_multiple_of(2) {
        return Err(HexError::OddLength(s.len()));
    }

    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| HexError::NotHex {
                offset: i,
                found: s[i..i + 2].to_owned(),
            })
        })
        .collect()
}

/// Decodes a hex string known to be exactly `N` bytes.
pub fn decode_array<const N: usize>(s: &str) -> Result<[u8; N], HexError> {
    let bytes = decode(s)?;
    bytes.try_into().map_err(|v: Vec<u8>| HexError::WrongLength {
        expected: N,
        found: v.len(),
    })
}

/// Why a hex string could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexError {
    /// A hex string must have an even number of characters.
    OddLength(usize),
    /// A character outside `[0-9a-fA-F]` was found.
    NotHex {
        /// Character offset of the offending pair.
        offset: usize,
        /// What was there instead.
        found: String,
    },
    /// The string decoded, but to the wrong number of bytes.
    WrongLength {
        /// How many bytes were expected.
        expected: usize,
        /// How many were found.
        found: usize,
    },
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OddLength(n) => write!(f, "hex string has an odd length ({n})"),
            Self::NotHex { offset, found } => {
                write!(f, "non-hex characters {found:?} at offset {offset}")
            }
            Self::WrongLength { expected, found } => {
                write!(f, "expected {expected} bytes, decoded {found}")
            }
        }
    }
}

impl std::error::Error for HexError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let bytes = [0x00, 0x0f, 0xa0, 0xff, 0x42];
        assert_eq!(encode(&bytes), "000fa0ff42");
        assert_eq!(decode("000fa0ff42").unwrap(), bytes);
    }

    #[test]
    fn accepts_uppercase() {
        assert_eq!(decode("DEADBEEF").unwrap(), decode("deadbeef").unwrap());
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(decode("abc"), Err(HexError::OddLength(3)));
        assert!(matches!(decode("zz"), Err(HexError::NotHex { .. })));
        assert!(matches!(
            decode_array::<4>("dead"),
            Err(HexError::WrongLength { expected: 4, found: 2 })
        ));
    }

    #[test]
    fn empty_is_valid() {
        assert_eq!(encode(&[]), "");
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
    }
}

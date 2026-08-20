//! A 256-bit hash that knows which way round it goes.
//!
//! # The single most confusing thing in Bitcoin
//!
//! Bitcoin stores hashes in one byte order and *displays* them in the opposite
//! one. The genesis block is the clearest example:
//!
//! ```text
//! displayed:  000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
//! in memory:  6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000
//! ```
//!
//! Same 32 bytes, written backwards. The leading zeros that make a block hash
//! look impressive are *trailing* zeros in the bytes that are actually hashed
//! and serialised.
//!
//! This is a historical accident — early code printed the hash as though it
//! were a little-endian 256-bit integer — but it is now permanent, and it is
//! responsible for a large share of the bugs in homemade mining software. The
//! usual failure is silent: everything runs, hashes get computed, and no block
//! is ever found because the comparison was done on backwards bytes.
//!
//! # How this type fixes it
//!
//! [`Sha256dHash`] stores **internal** order — the bytes as SHA-256 produced
//! them, which is what gets serialised into headers and fed into merkle trees.
//! The reversal lives entirely in the `Display` and `FromStr` implementations.
//!
//! So the rule becomes: if you are *printing or parsing* a hash you get display
//! order automatically, and if you are *computing* with one you get internal
//! order automatically. Neither requires you to remember anything.

use core::fmt;
use core::str::FromStr;

/// A double-SHA-256 hash, stored in internal (serialisation) byte order.
///
/// Displays and parses in Bitcoin's reversed convention — see the module docs.
///
/// # Ordering
///
/// This type deliberately does **not** implement `Ord`. The internal bytes are
/// stored least-significant-first, so a byte-wise comparison is not the numeric
/// comparison you want. Difficulty checks go through
/// [`Target::is_met_by`](crate::target::Target::is_met_by), which is explicit
/// about interpreting the hash as a 256-bit number.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256dHash([u8; 32]);

impl Sha256dHash {
    /// The all-zero hash, used for the "no previous block" field in a genesis
    /// block and for the null outpoint of a coinbase input.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Computes `sha256d(data)`.
    pub fn hash(data: &[u8]) -> Self {
        Self(sha256d::sha256d(data))
    }

    /// Wraps bytes that are already in internal order.
    pub const fn from_internal_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Wraps bytes that are in display order, reversing them.
    pub fn from_display_bytes(mut bytes: [u8; 32]) -> Self {
        bytes.reverse();
        Self(bytes)
    }

    /// The bytes in internal order — what goes into headers and merkle trees.
    pub const fn as_internal_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consumes the hash, yielding its internal-order bytes.
    pub const fn to_internal_bytes(self) -> [u8; 32] {
        self.0
    }

    /// The bytes in display order.
    pub fn to_display_bytes(self) -> [u8; 32] {
        let mut bytes = self.0;
        bytes.reverse();
        bytes
    }

    /// Compares two hashes as 256-bit numbers.
    ///
    /// Named rather than provided through `Ord` on purpose: the internal bytes
    /// are least-significant-first, so the derived byte-wise ordering would be
    /// wrong, and silently so. Requiring the explicit call means nobody sorts
    /// hashes by accident and gets a plausible-looking wrong answer.
    ///
    /// Walks from the most significant byte and stops at the first difference,
    /// so in the mining loop — where hashes differ almost immediately — this
    /// costs one or two comparisons rather than reversing 32 bytes.
    pub fn numeric_cmp(&self, other: &Self) -> core::cmp::Ordering {
        for i in (0..32).rev() {
            match self.0[i].cmp(&other.0[i]) {
                core::cmp::Ordering::Equal => continue,
                ordering => return ordering,
            }
        }
        core::cmp::Ordering::Equal
    }

    /// Whether this hash is numerically smaller than `other`.
    pub fn is_below(&self, other: &Self) -> bool {
        self.numeric_cmp(other) == core::cmp::Ordering::Less
    }

    /// Counts leading zero **bits** as a human reading the displayed hash would.
    ///
    /// This is the "how close did I get" number a solo miner cares about: a
    /// share with 60 leading zero bits is a near miss worth knowing about, even
    /// though it is not a block.
    pub fn leading_zero_bits(&self) -> u32 {
        // Display order is reversed, so the visually-leading bytes are the
        // last ones in memory.
        let mut count = 0;
        for byte in self.0.iter().rev() {
            count += byte.leading_zeros();
            if *byte != 0 {
                break;
            }
        }
        count
    }
}

/// Prints in Bitcoin's display convention: reversed, lowercase hex.
impl fmt::Display for Sha256dHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.iter().rev() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Debug prints the same as Display — there is no second useful rendering, and
/// a raw byte array in `{:?}` output would be actively misleading.
impl fmt::Debug for Sha256dHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// Parses Bitcoin's display convention: 64 hex characters, reversed.
impl FromStr for Sha256dHash {
    type Err = ParseHashError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 64 {
            return Err(ParseHashError::WrongLength(s.len()));
        }

        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|_| ParseHashError::NotHex)?;
        }

        Ok(Self::from_display_bytes(bytes))
    }
}

/// Why a hash string could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseHashError {
    /// A hash is exactly 64 hex characters; this had a different length.
    WrongLength(usize),
    /// The string contained a character that is not a hex digit.
    NotHex,
}

impl fmt::Display for ParseHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength(n) => write!(f, "expected 64 hex characters, got {n}"),
            Self::NotHex => write!(f, "string contains a non-hex character"),
        }
    }
}

impl std::error::Error for ParseHashError {}

//! Difficulty targets, and the compact "nBits" format that encodes them.
//!
//! Mining succeeds when the block hash, read as a 256-bit number, is **less
//! than or equal to** the target. A smaller target means fewer acceptable
//! hashes, which means more work.
//!
//! # The compact format
//!
//! A header has only 4 bytes for the target, so it stores a floating-point-ish
//! approximation: one exponent byte and three mantissa bytes.
//!
//! ```text
//!     target = mantissa × 256^(exponent − 3)
//! ```
//!
//! For the genesis block, `bits = 0x1d00ffff`:
//!
//! ```text
//!     exponent = 0x1d = 29
//!     mantissa = 0x00ffff = 65535
//!     target   = 65535 × 256^26
//!              = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
//! ```
//!
//! # Byte order, again
//!
//! A [`Target`] is stored big-endian — most significant byte first — because
//! that is the order in which it is a *number*. A [`Sha256dHash`] is stored the
//! other way. Comparing the two therefore requires converting one, and the
//! whole point of [`Target::is_met_by`] is to be the single place where that
//! conversion happens correctly.

use crate::hash::Sha256dHash;
use core::fmt;

/// A 256-bit difficulty target, stored big-endian (most significant byte first).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Target([u8; 32]);

impl Target {
    /// The difficulty-1 target, `0x1d00ffff` — the easiest target mainnet ever had.
    ///
    /// Network difficulty is defined relative to this value, so it is the
    /// numerator in every difficulty calculation.
    pub const DIFFICULTY_ONE: Self = {
        let mut bytes = [0u8; 32];
        bytes[4] = 0xFF;
        bytes[5] = 0xFF;
        Self(bytes)
    };

    /// Decodes a target from a header's compact `bits` field.
    pub fn from_compact(bits: u32) -> Result<Self, TargetError> {
        let exponent = (bits >> 24) as i32;
        let mantissa = bits & 0x007F_FFFF;

        // Bit 0x00800000 is a sign bit inherited from the generic big-number
        // code this format came from. A negative target is meaningless, and
        // Bitcoin Core rejects it, so we do too.
        if bits & 0x0080_0000 != 0 {
            return Err(TargetError::Negative);
        }

        let mut bytes = [0u8; 32];

        // The three mantissa bytes, most significant first, sit at descending
        // powers of 256 starting from `exponent - 1`.
        let mantissa_bytes = [
            (mantissa >> 16) as u8,
            (mantissa >> 8) as u8,
            mantissa as u8,
        ];

        for (i, &byte) in mantissa_bytes.iter().enumerate() {
            let power = exponent - 1 - i as i32;

            if power > 31 {
                // This byte would land above the top of a 256-bit number.
                // Harmless if it is zero, an overflow if it is not.
                if byte != 0 {
                    return Err(TargetError::Overflow);
                }
            } else if power >= 0 {
                bytes[31 - power as usize] = byte;
            }
            // power < 0: the byte is shifted off the bottom and lost. This is
            // what Bitcoin Core does for exponents below 3, so we match it.
        }

        Ok(Self(bytes))
    }

    /// Wraps big-endian bytes that are already a target.
    pub const fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The target's big-endian bytes.
    pub const fn as_be_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Whether `hash` satisfies this target — i.e. whether it is a valid block.
    ///
    /// This is the entire win condition of mining, and it is two lines long.
    ///
    /// The hash is converted to display order first, because that is its
    /// big-endian numeric form. Once both sides are big-endian, a plain
    /// byte-wise comparison *is* the 256-bit numeric comparison, since
    /// lexicographic order on equal-length big-endian byte strings matches
    /// numeric order.
    pub fn is_met_by(&self, hash: &Sha256dHash) -> bool {
        hash.to_display_bytes() <= self.0
    }

    /// The difficulty this target represents, relative to difficulty 1.
    ///
    /// Returned as `f64` because it is only ever used for display: at the time
    /// of writing mainnet difficulty is around 1.27e14, far past the point where
    /// the exact integer matters to a human.
    pub fn difficulty(bits: u32) -> f64 {
        let exponent = (bits >> 24) as i32;
        let mantissa = (bits & 0x007F_FFFF) as f64;

        if mantissa == 0.0 {
            return f64::INFINITY;
        }

        // difficulty = (0xffff × 256^(0x1d−3)) / (mantissa × 256^(exponent−3))
        //            = (0xffff / mantissa) × 256^(0x1d − exponent)
        (0xFFFF as f64 / mantissa) * 256f64.powi(0x1D - exponent)
    }
}

/// Prints as 64 hex characters, big-endian — the same way a hash displays, so
/// a target and a hash can be compared by eye.
impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// Why a compact target could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetError {
    /// The sign bit was set. Targets are unsigned.
    Negative,
    /// The value does not fit in 256 bits.
    Overflow,
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Negative => write!(f, "compact target has the sign bit set"),
            Self::Overflow => write!(f, "compact target overflows 256 bits"),
        }
    }
}

impl std::error::Error for TargetError {}

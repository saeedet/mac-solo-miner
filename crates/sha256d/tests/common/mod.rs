//! Small helpers shared by the integration tests.
//!
//! Deliberately dependency-free: this crate has no dependencies at all, and
//! pulling in a hex crate just for tests would spoil that.

// Each integration-test binary compiles this module separately, so a helper
// used by only one of them reads as dead code in the others.
#![allow(dead_code)]

/// Decodes a hex string into bytes.
pub fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex string must have an even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// Encodes bytes as a lowercase hex string, in the order given.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Encodes a hash the way Bitcoin *displays* it: byte-reversed.
///
/// This is the single most confusing convention in Bitcoin. A block hash on an
/// explorer reads `0000...abcd`, but in the serialised header and in every
/// comparison against the difficulty target it is stored the other way round.
/// The reversal is purely cosmetic — it exists because early code printed the
/// 256-bit value as a little-endian number — but forgetting it makes a correct
/// hasher look broken.
pub fn bitcoin_display(digest: &[u8; 32]) -> String {
    let mut reversed = *digest;
    reversed.reverse();
    to_hex(&reversed)
}

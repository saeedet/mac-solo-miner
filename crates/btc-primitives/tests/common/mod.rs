//! Hex decoding for the test suite.

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

/// Encodes bytes as lowercase hex.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

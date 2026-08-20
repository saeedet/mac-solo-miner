//! Stratum's byte-order conventions, which are the protocol's worst trap.
//!
//! Bitcoin already has two byte orders for a hash — internal and display —
//! and Stratum adds a third. Getting it wrong produces a miner that runs
//! happily, reports a healthy hashrate, and never finds a share. Nothing
//! errors, because every byte order is a valid 32-byte string.
//!
//! # The three orders
//!
//! For the previous block hash, all of these describe the same 256-bit value:
//!
//! ```text
//! display   00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054
//! internal  54a02827d7a8b75601275a160279a3c5768de4c1c4a70200 ... (reversed)
//! stratum   2827a054d7a8b756 ... (internal, with each 4-byte word reversed)
//! ```
//!
//! # Where the third one came from
//!
//! Early mining hardware consumed the header as eight 32-bit big-endian words.
//! The reference pool software byte-swapped each word before sending it so the
//! device could load them directly, and every implementation since has copied
//! that. The original Python implementation expressed it as reordering the
//! eight 8-character groups of the *display* hex string, which is the same
//! transformation seen from the other end.
//!
//! # The one useful property
//!
//! Reversing each 4-byte word is its **own inverse**. Applying [`swap_words`]
//! twice returns the original, so the pool and the miner run the same function
//! rather than a matched encode/decode pair that could drift apart.
//!
//! # Everything else
//!
//! `merkle_branch` entries are sent in plain internal order, with no swapping.
//! `version`, `nbits`, and `ntime` are sent as ordinary big-endian hex of the
//! numeric value — parse them as `u32` and the header's little-endian encoding
//! follows from the normal serialisation.

use btc_primitives::Sha256dHash;

/// Reverses the bytes within each 4-byte word, leaving word order alone.
///
/// Its own inverse, so the same function encodes and decodes.
pub fn swap_words(bytes: [u8; 32]) -> [u8; 32] {
    let mut swapped = bytes;
    for word in swapped.chunks_exact_mut(4) {
        word.reverse();
    }
    swapped
}

/// Encodes a hash for Stratum's `prevhash` field.
pub fn hash_to_stratum(hash: Sha256dHash) -> [u8; 32] {
    swap_words(hash.to_internal_bytes())
}

/// Decodes Stratum's `prevhash` field back into a hash.
pub fn hash_from_stratum(bytes: [u8; 32]) -> Sha256dHash {
    Sha256dHash::from_internal_bytes(swap_words(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::hex;
    use std::str::FromStr;

    /// The transform must be an involution, or the pool and miner will disagree.
    #[test]
    fn swapping_twice_is_the_identity() {
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = i as u8;
        }
        assert_eq!(swap_words(swap_words(bytes)), bytes);
    }

    /// Word order is preserved; only bytes within each word move.
    #[test]
    fn only_bytes_within_a_word_move() {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&[1, 2, 3, 4]);
        bytes[4..8].copy_from_slice(&[5, 6, 7, 8]);

        let swapped = swap_words(bytes);
        assert_eq!(&swapped[..4], &[4, 3, 2, 1]);
        assert_eq!(&swapped[4..8], &[8, 7, 6, 5]);
    }

    /// The equivalence the original Python pool expressed differently.
    ///
    /// Its `reverse_hash` reordered the eight 8-character groups of the
    /// *display* hex string. Swapping each 4-byte word of the *internal* bytes
    /// is the same operation, and this test pins that down — it is the only
    /// reason to trust that our encoding matches what real mining hardware
    /// expects.
    #[test]
    fn matches_the_reference_pool_group_reordering() {
        let display = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        let hash = Sha256dHash::from_str(display).expect("valid");

        // What the reference implementation does: reverse the order of the
        // eight 8-character groups of the display string.
        let groups: Vec<&str> = (0..8).map(|i| &display[i * 8..i * 8 + 8]).collect();
        let reference: String = groups.iter().rev().copied().collect();

        assert_eq!(hex::encode(&hash_to_stratum(hash)), reference);
    }

    #[test]
    fn round_trips_through_the_wire_form() {
        let hash = Sha256dHash::from_str(
            "000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506",
        )
        .expect("valid");

        assert_eq!(hash_from_stratum(hash_to_stratum(hash)), hash);
    }

    /// The three orders really are three different strings, which is exactly
    /// why this module exists.
    #[test]
    fn the_three_orders_differ() {
        let hash = Sha256dHash::from_str(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        )
        .expect("valid");

        let display = hash.to_string();
        let internal = hex::encode(hash.as_internal_bytes());
        let stratum = hex::encode(&hash_to_stratum(hash));

        assert_ne!(display, internal);
        assert_ne!(internal, stratum);
        assert_ne!(display, stratum);
    }
}

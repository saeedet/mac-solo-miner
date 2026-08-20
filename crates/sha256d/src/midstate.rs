//! Midstate caching — the optimisation that mining is built around.
//!
//! # The observation
//!
//! A block header is 80 bytes, and SHA-256 consumes 64 bytes at a time. Padded
//! to 128 bytes it is two blocks, so `sha256d` of a header costs three
//! compressions: two for the first hash, one for the second.
//!
//! ```text
//!  byte:  0       4                       36                      68  72  76  80
//!        +-------+-----------------------+-----------------------+---+---+---+
//!        |version|      prev_block       |      merkle_root      |tim|bit|non|
//!        +-------+-----------------------+-----------------------+---+---+---+
//!        |<--------------- block 0, 64 bytes -------------->|<--- block 1 --->|
//!                                            never changes  |  nonce lives here
//! ```
//!
//! The nonce is at offset 76 — in the *second* block. So during a nonce sweep
//! the first block is byte-for-byte identical every time, and compressing it
//! again for each of four billion nonces is pure waste.
//!
//! Compressing it once and keeping the resulting eight-word state — the
//! **midstate** — cuts three compressions to two. A third of the work, gone,
//! for the price of remembering 32 bytes.
//!
//! # What else this removes
//!
//! The general-purpose [`crate::sha256d`] allocates a padded buffer for every
//! call. Here the padding is known at compile time: a header is always 80 bytes
//! and a digest is always 32, so both tail blocks are built once and only four
//! bytes of one of them ever change. The hot loop allocates nothing.
//!
//! # What this does not do
//!
//! Real ASICs go further and precompute part of the *second* block's message
//! schedule too, since only one of its sixteen words varies. That is worth
//! doing when silicon is the constraint; here the remaining two compressions
//! are already dominated by the hardware SHA instructions.

use crate::constants::H0;

/// A block header is always exactly this many bytes.
pub const HEADER_SIZE: usize = 80;

/// Byte offset of the nonce within a header.
const NONCE_OFFSET: usize = 76;

/// Where the nonce sits inside the second block: 76 - 64.
const NONCE_IN_TAIL: usize = NONCE_OFFSET - 64;

/// A header with its first block already compressed.
///
/// Build one per merkle root — that is, once per extranonce — and sweep nonces
/// against it.
#[derive(Clone)]
pub struct HeaderHasher {
    /// State after compressing header bytes 0..64.
    midstate: [u32; 8],
    /// The second block: header bytes 64..80, then SHA-256 padding.
    tail: [u8; 64],
}

impl HeaderHasher {
    /// Precomputes the midstate for `header`.
    ///
    /// The header's own nonce field is irrelevant — it is overwritten on every
    /// [`Self::hash`] call.
    pub fn new(header: &[u8; HEADER_SIZE]) -> Self {
        let mut midstate = H0;
        let first: &[u8; 64] = header[..64].try_into().expect("64-byte prefix");
        compress(&mut midstate, first);

        // The second block: 16 real bytes, then the padding SHA-256 requires.
        let mut tail = [0u8; 64];
        tail[..16].copy_from_slice(&header[64..80]);
        tail[16] = 0x80; // the mandatory 1 bit
        // Bytes 17..56 stay zero. The last eight are the message length in
        // bits: 80 bytes * 8 = 640, big-endian.
        tail[56..].copy_from_slice(&(HEADER_SIZE as u64 * 8).to_be_bytes());

        Self { midstate, tail }
    }

    /// Hashes the header with `nonce`, returning the digest in internal order.
    pub fn hash(&self, nonce: u32) -> [u8; 32] {
        let mut tail = self.tail;
        tail[NONCE_IN_TAIL..NONCE_IN_TAIL + 4].copy_from_slice(&nonce.to_le_bytes());

        let mut state = self.midstate;
        compress(&mut state, &tail);

        second_hash(&state)
    }
}

/// The second SHA-256, over the 32-byte digest of the first.
///
/// Always exactly one block: 32 bytes of digest, the `0x80` marker, zeros, and
/// a length of 256 bits. Built fresh each call because all 32 input bytes
/// change every time — there is no midstate to be had here.
#[inline(always)]
fn second_hash(first_state: &[u32; 8]) -> [u8; 32] {
    let mut block = [0u8; 64];

    for (i, word) in first_state.iter().enumerate() {
        block[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    block[32] = 0x80;
    block[56..].copy_from_slice(&(32u64 * 8).to_be_bytes());

    let mut state = H0;
    compress(&mut state, &block);

    let mut digest = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        digest[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// Compresses one block, using the hardware instructions where available.
#[inline(always)]
fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    #[cfg(target_arch = "aarch64")]
    if crate::neon::is_available() {
        // SAFETY: `is_available` confirmed the `sha2` feature is present, which
        // is the whole of `neon::compress_block`'s safety contract.
        unsafe {
            crate::neon::compress_block(state, block);
        }
        return;
    }

    crate::reference::compress_block(state, block);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The genesis header, whose hash we have verified since Phase 1.
    const GENESIS: [u8; 80] = [
        0x01, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7,
        0x2c, 0x3e, 0x67, 0x76, 0x8f, 0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a,
        0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a, 0x29, 0xab, 0x5f, 0x49, 0xff, 0xff, 0x00, 0x1d,
        0x1d, 0xac, 0x2b, 0x7c,
    ];

    /// The midstate path must reproduce the genesis hash exactly.
    ///
    /// The nonce baked into `GENESIS` is ignored; it is supplied separately, so
    /// this also proves the nonce lands at the right offset inside the tail
    /// block. An off-by-one there would still hash — just never correctly.
    #[test]
    fn reproduces_the_genesis_hash() {
        let hasher = HeaderHasher::new(&GENESIS);
        let hash = hasher.hash(2_083_236_893);

        let mut display = hash;
        display.reverse();

        assert_eq!(
            display.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }

    /// The optimised path must agree with the general one for every nonce.
    ///
    /// This is the test that makes the optimisation safe to trust: `sha256d` is
    /// verified against real block headers, and this pins the fast path to it.
    #[test]
    fn agrees_with_the_general_implementation() {
        let hasher = HeaderHasher::new(&GENESIS);

        for nonce in [0u32, 1, 42, 0x8000_0000, u32::MAX, 2_083_236_893] {
            let mut header = GENESIS;
            header[NONCE_OFFSET..].copy_from_slice(&nonce.to_le_bytes());

            assert_eq!(
                hasher.hash(nonce),
                crate::sha256d(&header),
                "disagreement at nonce {nonce}"
            );
        }
    }

    /// A midstate built from a header with one nonce must work for all nonces,
    /// which is the entire premise of caching it.
    #[test]
    fn midstate_is_independent_of_the_nonce() {
        let mut other = GENESIS;
        other[NONCE_OFFSET..].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());

        let from_genesis = HeaderHasher::new(&GENESIS);
        let from_other = HeaderHasher::new(&other);

        for nonce in [0u32, 7, 2_083_236_893] {
            assert_eq!(from_genesis.hash(nonce), from_other.hash(nonce));
        }
    }

    /// Changing anything in the first block must change the midstate — if it
    /// did not, the cache would be returning stale work.
    #[test]
    fn first_block_changes_reach_the_hash() {
        let mut altered = GENESIS;
        altered[40] ^= 0x01; // inside the merkle root, block 0

        assert_ne!(
            HeaderHasher::new(&GENESIS).hash(7),
            HeaderHasher::new(&altered).hash(7)
        );
    }
}

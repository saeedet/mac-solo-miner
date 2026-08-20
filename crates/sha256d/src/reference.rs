//! A portable SHA-256, written to mirror FIPS 180-4 line by line.
//!
//! This implementation is not fast and is not trying to be. Its job is to be
//! checkable by eye against the published specification, so that it can serve
//! as the *definition* of correctness that the hardware-accelerated version in
//! [`crate::neon`] is tested against.
//!
//! The structure follows the spec exactly: six small logical functions, a
//! 64-word message schedule, and 64 rounds of a compression function that
//! stirs eight working variables.

use crate::constants::{H0, K};
use crate::padding::pad;

// ---------------------------------------------------------------------------
// The six logical functions, FIPS 180-4 §4.1.2
// ---------------------------------------------------------------------------
//
// `Ch` and `Maj` provide non-linearity; the four `sigma` functions provide
// diffusion, spreading the influence of every input bit across the whole word.
// All rotations are on 32-bit words, so `rotate_right` wraps as the spec wants.

/// `Ch(x, y, z)` — "choose": each bit of `x` selects the matching bit of `y`
/// (where `x` is 1) or of `z` (where `x` is 0).
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

/// `Maj(x, y, z)` — "majority": each output bit is whichever value appears in
/// at least two of the three inputs at that position.
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// `Σ0` — big sigma zero, applied to `a` in the compression function.
fn big_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

/// `Σ1` — big sigma one, applied to `e` in the compression function.
fn big_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

/// `σ0` — small sigma zero, used to extend the message schedule.
///
/// Note this one *shifts* rather than rotates on the last term, so bits fall
/// off the end. That asymmetry is deliberate.
fn small_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

/// `σ1` — small sigma one, used to extend the message schedule.
fn small_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

// ---------------------------------------------------------------------------
// The compression function, FIPS 180-4 §6.2.2
// ---------------------------------------------------------------------------

/// Absorbs one 64-byte block into `state`.
///
/// This is the heart of SHA-256. It is exposed within the crate so that the
/// NEON version can be tested block-for-block against it, and so Phase 5 can
/// reuse it for midstate caching.
pub(crate) fn compress_block(state: &mut [u32; 8], block: &[u8; 64]) {
    // --- Step 1: prepare the 64-word message schedule W ---------------------
    let mut w = [0u32; 64];

    // The first 16 words are just the block itself, read as big-endian u32s.
    // Big-endian is not a choice we get to make: it is what the spec says, and
    // getting it wrong is the single most common way to produce a hasher that
    // looks plausible and computes garbage.
    for t in 0..16 {
        w[t] = u32::from_be_bytes([
            block[t * 4],
            block[t * 4 + 1],
            block[t * 4 + 2],
            block[t * 4 + 3],
        ]);
    }

    // The remaining 48 are derived, each from four earlier words. This is what
    // makes every round depend on the entire block rather than just 4 bytes.
    for t in 16..64 {
        w[t] = small_sigma1(w[t - 2])
            .wrapping_add(w[t - 7])
            .wrapping_add(small_sigma0(w[t - 15]))
            .wrapping_add(w[t - 16]);
    }

    // --- Step 2: initialise the eight working variables ---------------------
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    // --- Step 3: sixty-four rounds ------------------------------------------
    for t in 0..64 {
        let t1 = h
            .wrapping_add(big_sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));

        // Every variable shifts down one position, with `t1` and `t2` injected
        // at the two points that make the round non-invertible.
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    // --- Step 4: feed-forward -----------------------------------------------
    // Adding the previous state back in is what makes the compression function
    // one-way. Without it, the 64 rounds would be a reversible permutation.
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// Computes SHA-256 of `message`, the slow and readable way.
pub fn sha256(message: &[u8]) -> [u8; 32] {
    let padded = pad(message);
    let mut state = H0;

    for block in padded.chunks_exact(64) {
        compress_block(&mut state, block.try_into().expect("chunks_exact(64)"));
    }

    // The digest is the eight state words written out big-endian.
    let mut digest = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        digest[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// Computes `sha256(sha256(message))`, the way Bitcoin does it.
pub fn sha256d(message: &[u8]) -> [u8; 32] {
    sha256(&sha256(message))
}

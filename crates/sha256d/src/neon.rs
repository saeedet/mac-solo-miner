//! SHA-256 using the ARMv8 cryptographic extensions.
//!
//! Every Apple Silicon chip implements four instructions that do in one cycle
//! what [`crate::reference`] spends dozens of operations on:
//!
//! | Instruction | Intrinsic | What it does |
//! |---|---|---|
//! | `SHA256H`   | [`vsha256hq_u32`]   | Four rounds, producing the new `a b c d` |
//! | `SHA256H2`  | [`vsha256h2q_u32`]  | The same four rounds' effect on `e f g h` |
//! | `SHA256SU0` | [`vsha256su0q_u32`] | First half of extending the message schedule |
//! | `SHA256SU1` | [`vsha256su1q_u32`] | Second half of extending the message schedule |
//!
//! The shape of the algorithm is unchanged — the same 64 rounds over the same
//! message schedule — but the eight working variables now live in two 128-bit
//! vector registers (`abcd` and `efgh`) and advance four rounds at a time, so
//! the round loop runs 16 times instead of 64.
//!
//! This file is deliberately still a straightforward loop. Phase 5 is where it
//! gets unrolled and specialised for the 80-byte block header.

use crate::constants::{H0, K};
use crate::padding::pad;
use std::arch::aarch64::*;

/// Whether this CPU has the SHA-256 extensions.
///
/// Always true on Apple Silicon, but checked rather than assumed so the crate
/// stays honest on other `aarch64` targets.
pub fn is_available() -> bool {
    std::arch::is_aarch64_feature_detected!("sha2")
}

/// Absorbs one 64-byte block into `state`.
///
/// # Safety
///
/// The CPU must support the `sha2` target feature; check [`is_available`].
#[target_feature(enable = "sha2")]
pub(crate) unsafe fn compress_block(state: &mut [u32; 8], block: &[u8; 64]) {
    // SAFETY: `state` is 8 u32s so the two 4-lane loads at offsets 0 and 4 are
    // in bounds; `block` is 64 bytes so the four 16-byte loads are in bounds;
    // `K` is 64 u32s so `group * 4` for group < 16 stays in bounds. The sha2
    // intrinsics are enabled by this function's `target_feature` and required
    // of callers by the safety contract above.
    unsafe {
        let abcd_orig = vld1q_u32(state.as_ptr());
        let efgh_orig = vld1q_u32(state.as_ptr().add(4));
        let mut abcd = abcd_orig;
        let mut efgh = efgh_orig;

        // Load the block as four vectors of four words. `vrev32q_u8` reverses
        // the bytes within each 4-byte group, which is how we get the
        // big-endian reads the spec demands on a little-endian machine.
        let mut w = [
            vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr()))),
            vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr().add(16)))),
            vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr().add(32)))),
            vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr().add(48)))),
        ];

        // Sixteen groups of four rounds each.
        for group in 0..16 {
            let i = group % 4;

            // Each round needs W[t] + K[t]; the hardware takes them pre-summed.
            let wk = vaddq_u32(w[i], vld1q_u32(K.as_ptr().add(group * 4)));

            // SHA256H2 needs the value of `abcd` from *before* SHA256H updated
            // it, so it has to be saved. Passing the updated value instead is
            // the classic bug here, and it still produces plausible-looking
            // garbage rather than an obvious failure.
            let abcd_before = abcd;
            abcd = vsha256hq_u32(abcd, efgh, wk);
            efgh = vsha256h2q_u32(efgh, abcd_before, wk);

            // Extend the schedule four words ahead of where we are reading, so
            // the words for group `n + 4` are ready by the time we need them.
            // The last four groups read words that already exist, so the final
            // twelve iterations are the only ones that produce new ones.
            if group < 12 {
                w[i] = vsha256su1q_u32(
                    vsha256su0q_u32(w[i], w[(i + 1) % 4]),
                    w[(i + 2) % 4],
                    w[(i + 3) % 4],
                );
            }
        }

        // The same feed-forward as the reference implementation.
        vst1q_u32(state.as_mut_ptr(), vaddq_u32(abcd, abcd_orig));
        vst1q_u32(state.as_mut_ptr().add(4), vaddq_u32(efgh, efgh_orig));
    }
}

/// Computes SHA-256 of `message` using the hardware instructions.
///
/// # Safety
///
/// The CPU must support the `sha2` target feature; check [`is_available`].
pub unsafe fn sha256(message: &[u8]) -> [u8; 32] {
    let padded = pad(message);
    let mut state = H0;

    for block in padded.chunks_exact(64) {
        // SAFETY: the caller guarantees `sha2` is available, and `chunks_exact`
        // yields slices of exactly 64 bytes.
        unsafe { compress_block(&mut state, block.try_into().expect("chunks_exact(64)")) };
    }

    let mut digest = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        digest[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// Computes `sha256(sha256(message))` using the hardware instructions.
///
/// # Safety
///
/// The CPU must support the `sha2` target feature; check [`is_available`].
pub unsafe fn sha256d(message: &[u8]) -> [u8; 32] {
    // SAFETY: delegated to the caller by this function's own contract.
    unsafe { sha256(&sha256(message)) }
}

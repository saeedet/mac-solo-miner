//! Measures single-core hashrate on 80-byte block headers.
//!
//! This is the number Phase 5 exists to improve, so it is worth recording now,
//! before any optimisation work, to know what the starting point was.
//!
//! What is measured is deliberately the *real* mining operation: `sha256d` over
//! an 80-byte header with the nonce field changing each iteration. That is
//! exactly what the mining loop will do, so the figure translates directly.
//!
//! Run with:
//!
//! ```text
//! cargo run --release --example hashrate -p sha256d
//! ```
//!
//! Release mode matters enormously here — a debug build is roughly 20x slower
//! and the number would be meaningless.

use std::hint::black_box;
use std::time::Instant;

/// The genesis block header, used simply as a realistic 80 bytes to chew on.
const HEADER: [u8; 80] = [
    0x01, 0x00, 0x00, 0x00, // version
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // previous block hash
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, // merkle root
    0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f, 0x61,
    0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32,
    0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a,
    0x29, 0xab, 0x5f, 0x49, // time
    0xff, 0xff, 0x00, 0x1d, // bits
    0x1d, 0xac, 0x2b, 0x7c, // nonce
];

/// Hashes `iterations` headers, changing the nonce each time, and reports the rate.
fn measure(label: &str, iterations: u64, mut hash: impl FnMut(&[u8; 80]) -> [u8; 32]) {
    let mut header = HEADER;

    let start = Instant::now();
    for nonce in 0..iterations {
        // The nonce is the last 4 bytes of the header, little-endian.
        header[76..80].copy_from_slice(&(nonce as u32).to_le_bytes());
        black_box(hash(black_box(&header)));
    }
    let elapsed = start.elapsed();

    let rate = iterations as f64 / elapsed.as_secs_f64();
    println!("{label:<24} {:>10.2} MH/s   ({iterations} hashes in {elapsed:.2?})", rate / 1e6);
}

fn main() {
    println!("single-core sha256d over 80-byte headers\n");

    measure("reference (portable)", 300_000, |h| sha256d::reference::sha256d(h));

    if sha256d::neon::is_available() {
        // SAFETY: `is_available` confirmed the sha2 extensions are present.
        measure("neon (ARMv8 crypto)", 20_000_000, |h| unsafe {
            sha256d::neon::sha256d(h)
        });
    } else {
        println!("neon (ARMv8 crypto)      unavailable on this CPU");
    }

    println!(
        "\nNote: this still allocates a padding buffer per hash and re-hashes\n\
         all 80 bytes every time. Phase 5 removes both."
    );
}

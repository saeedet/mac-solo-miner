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

    // The midstate path is measured differently: the hasher is built once,
    // outside the timed loop, exactly as the mining loop uses it.
    {
        let hasher = sha256d::HeaderHasher::new(&HEADER);
        let iterations = 50_000_000u64;

        let start = Instant::now();
        for nonce in 0..iterations {
            black_box(hasher.hash(black_box(nonce as u32)));
        }
        let elapsed = start.elapsed();

        let rate = iterations as f64 / elapsed.as_secs_f64();
        println!(
            "{:<24} {:>10.2} MH/s   ({iterations} hashes in {elapsed:.2?})",
            "midstate + neon", rate / 1e6
        );
    }

    println!(
        "\nThe first two re-hash all 80 bytes and allocate a padding buffer per\n\
         call. The third caches the first block's compression, which is constant\n\
         across a nonce sweep, and allocates nothing.\n"
    );

    // --- Scaling across cores ------------------------------------------------
    //
    // Each thread gets its own hasher, exactly as the miner gives each thread
    // its own extranonce. Nothing is shared, so this measures the machine
    // rather than any contention we introduced.
    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    println!("scaling across cores ({cores} available)");

    for threads in scaling_steps(cores) {
        let per_thread = 20_000_000u64;

        let start = Instant::now();
        let handles: Vec<_> = (0..threads)
            .map(|index| {
                std::thread::spawn(move || {
                    // A distinct header per thread, as distinct extranonces
                    // would give in the real miner.
                    let mut header = HEADER;
                    header[36] = index as u8;

                    let hasher = sha256d::HeaderHasher::new(&header);
                    for nonce in 0..per_thread {
                        black_box(hasher.hash(black_box(nonce as u32)));
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("mining thread panicked");
        }
        let elapsed = start.elapsed();

        let total = per_thread * threads as u64;
        let rate = total as f64 / elapsed.as_secs_f64();
        println!("{threads:>3} threads {:>10.2} MH/s", rate / 1e6);
    }
}

/// Thread counts worth measuring: powers of two up to the core count.
///
/// On an M3 this gives 1, 2, 4, 8 — and the step from 4 to 8 is the interesting
/// one, because the second four are efficiency cores rather than performance
/// cores and do not add a full core's worth of throughput.
fn scaling_steps(cores: usize) -> Vec<usize> {
    let mut steps = Vec::new();
    let mut threads = 1;
    while threads < cores {
        steps.push(threads);
        threads *= 2;
    }
    steps.push(cores);
    steps
}

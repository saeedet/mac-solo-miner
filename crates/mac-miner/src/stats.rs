//! Hashrate and near-miss accounting, shared across every mining thread.
//!
//! # Why the best hash is worth tracking
//!
//! It is worth nothing in consensus terms. A hash with 60 leading zero bits
//! against a target needing 76 is not a partial block, it is a miss — mining
//! has no partial credit, and the next hash is no more likely for it.
//!
//! It is tracked because it is the *only* feedback solo mining ever gives. Over
//! a session you will see the best climb from around 30 zero bits to the low
//! 40s, and that number is a real, honest measure of how much work the machine
//! did. Without it there is nothing to look at but a hashrate that never
//! produces anything.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

use btc_primitives::Sha256dHash;

/// Counters shared by every mining thread.
pub struct Stats {
    hashes: AtomicU64,
    /// Leading zero bits of the best hash seen. Read on every batch as a cheap
    /// filter, so that the mutex below is only touched on an actual improvement.
    best_zero_bits: AtomicU32,
    best: Mutex<Sha256dHash>,
    started: Instant,
}

impl Stats {
    /// Creates zeroed counters.
    pub fn new() -> Self {
        Self {
            hashes: AtomicU64::new(0),
            best_zero_bits: AtomicU32::new(0),
            best: Mutex::new(Sha256dHash::from_internal_bytes([0xFF; 32])),
            started: Instant::now(),
        }
    }

    /// Records a completed batch.
    ///
    /// Called once per million hashes, not per hash, so the atomics are far off
    /// the hot path and contention between threads is irrelevant.
    pub fn record(&self, hashes: u64, best: Sha256dHash) {
        self.hashes.fetch_add(hashes, Ordering::Relaxed);

        // Compare the cheap summary first; the lock is only taken when this
        // batch actually beat the record, which happens a handful of times a
        // session.
        let zero_bits = best.leading_zero_bits();
        if zero_bits <= self.best_zero_bits.load(Ordering::Relaxed) {
            return;
        }

        let mut current = self.best.lock().expect("stats mutex poisoned");
        if best.is_below(&current) {
            *current = best;
            self.best_zero_bits.store(zero_bits, Ordering::Relaxed);
        }
    }

    /// Total hashes computed since start.
    pub fn total_hashes(&self) -> u64 {
        self.hashes.load(Ordering::Relaxed)
    }

    /// The lowest hash seen, and its leading zero bit count.
    pub fn best(&self) -> (Sha256dHash, u32) {
        let best = *self.best.lock().expect("stats mutex poisoned");
        (best, best.leading_zero_bits())
    }

    /// Average hashrate since start, in hashes per second.
    pub fn average_hashrate(&self) -> f64 {
        self.total_hashes() as f64 / self.started.elapsed().as_secs_f64()
    }
}

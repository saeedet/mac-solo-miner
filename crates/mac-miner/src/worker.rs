//! The hashing loop.
//!
//! Given work, this tries nonces. When the nonce space runs out it increments
//! the extranonce, which changes the coinbase, which changes the merkle root,
//! which yields a completely fresh 2^32 nonces to try.
//!
//! ```text
//! for each extranonce2:
//!     rebuild the merkle root
//!     for each nonce in 0..2^32:
//!         if sha256d(header) <= target: submit
//! ```
//!
//! # Batching
//!
//! Nonces are tried in batches rather than one long run, so that between
//! batches the loop can notice new work has arrived. The batch size is a
//! trade-off: too small and the checks cost real time, too large and the miner
//! keeps grinding a job the chain has already moved past. At a million hashes
//! per batch the check happens several times a second and costs nothing
//! measurable.
//!
//! Phase 5 replaces this single loop with one per core, and replaces the
//! all-80-bytes-every-time hashing with a cached midstate.

use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use btc_primitives::Sha256dHash;
use stratum::{Request, Share, method};

use crate::work::WorkState;

/// Nonces per batch, between checks for new work.
const BATCH: u32 = 1 << 20;

/// How often to print a status line.
const REPORT_INTERVAL: Duration = Duration::from_secs(10);

/// How long to wait for fresh work after finding a block candidate.
///
/// Bounded so that a candidate which loses its race — or a pool that goes quiet
/// — cannot stall the miner indefinitely.
const NEW_WORK_TIMEOUT: Duration = Duration::from_secs(2);

/// Runs until the process ends.
pub fn run(state: Arc<WorkState>, outbound: Sender<String>, worker: String) {
    let mut stats = Stats::new();
    let mut submit_id = 100u64;

    // Never reset, so no extranonce is ever searched twice for the same job —
    // which would mean re-finding and re-submitting a solution we already sent.
    let mut extranonce_counter = 0u64;

    loop {
        let Some((work, generation)) = state.snapshot() else {
            // No job yet. Wait rather than spin.
            std::thread::sleep(Duration::from_millis(100));
            continue;
        };

        extranonce_counter = extranonce_counter.wrapping_add(1);
        let extranonce2 = encode_extranonce2(extranonce_counter, work.extranonce2_size);

        // The merkle root depends on the extranonce, so it is recomputed once
        // here and then reused for the whole 2^32 nonce sweep below.
        let header = work.job.header(&work.extranonce1, &extranonce2, work.job.time, 0);

        let mut start = 0u32;
        while state.is_current(generation) {
            let end = start.saturating_add(BATCH);
            let result = mining::search(&header, &work.target, start..end);
            stats.record(&result);

            if let Some(solution) = result.solution {
                println!(
                    "solution found: {} ({} zero bits)",
                    solution.hash,
                    solution.hash.leading_zero_bits()
                );

                let share = Share {
                    worker: worker.clone(),
                    job_id: work.job.job_id.clone(),
                    extranonce2: extranonce2.clone(),
                    time: work.job.time,
                    nonce: solution.nonce,
                };

                match serde_json::to_string(&Request::call(
                    submit_id,
                    method::SUBMIT,
                    share.to_submit_params(),
                )) {
                    Ok(line) => {
                        if outbound.send(line).is_err() {
                            return; // the connection is gone
                        }
                        submit_id += 1;
                    }
                    Err(error) => eprintln!("cannot serialise share: {error}"),
                }

                // The pool announces the network difficulty, so a solution is a
                // block candidate, not a partial share. However it turns out,
                // the tip is about to move — so there is nothing left worth
                // doing with this job. Wait for fresh work instead of grinding
                // out siblings of a block that has already been submitted.
                wait_for_new_work(&state, generation);
                break;
            }

            stats.report_if_due();

            if end == u32::MAX {
                break; // nonce space exhausted; roll the extranonce
            }
            start = end;
        }
    }
}

/// Blocks until the work changes, or the timeout expires.
fn wait_for_new_work(state: &WorkState, generation: u64) {
    let deadline = Instant::now() + NEW_WORK_TIMEOUT;

    while Instant::now() < deadline {
        if !state.is_current(generation) {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Hashrate and best-share accounting.
struct Stats {
    total_hashes: u64,
    since_report: u64,
    best: Sha256dHash,
    last_report: Instant,
}

impl Stats {
    fn new() -> Self {
        Self {
            total_hashes: 0,
            since_report: 0,
            best: Sha256dHash::from_internal_bytes([0xFF; 32]),
            last_report: Instant::now(),
        }
    }

    fn record(&mut self, result: &mining::SearchResult) {
        self.total_hashes += result.hashes;
        self.since_report += result.hashes;

        if result.best.to_display_bytes() < self.best.to_display_bytes() {
            self.best = result.best;
        }
    }

    fn report_if_due(&mut self) {
        let elapsed = self.last_report.elapsed();
        if elapsed < REPORT_INTERVAL {
            return;
        }

        println!(
            "{:.2} MH/s   total {:.1}M hashes   best {} zero bits",
            self.since_report as f64 / elapsed.as_secs_f64() / 1e6,
            self.total_hashes as f64 / 1e6,
            self.best.leading_zero_bits(),
        );

        self.since_report = 0;
        self.last_report = Instant::now();
    }
}

/// Encodes the extranonce counter into exactly `size` bytes, big-endian.
///
/// Truncates from the top when the counter outgrows the width, which simply
/// means the search wraps — acceptable, because reaching it would take longer
/// than any block interval.
fn encode_extranonce2(counter: u64, size: usize) -> Vec<u8> {
    let bytes = counter.to_be_bytes();
    let mut extranonce2 = vec![0u8; size];

    let copy = size.min(bytes.len());
    extranonce2[size - copy..].copy_from_slice(&bytes[bytes.len() - copy..]);

    extranonce2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extranonce2_fills_the_assigned_width() {
        assert_eq!(encode_extranonce2(1, 4), vec![0, 0, 0, 1]);
        assert_eq!(encode_extranonce2(0x0102, 4), vec![0, 0, 1, 2]);
        assert_eq!(encode_extranonce2(1, 8), vec![0, 0, 0, 0, 0, 0, 0, 1]);
        // A counter wider than the field keeps its low bytes.
        assert_eq!(encode_extranonce2(0x0102_0304_0506, 2), vec![5, 6]);
    }
}

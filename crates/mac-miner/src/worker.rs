//! The hashing loop, run on every core at once.
//!
//! Given work, a thread tries nonces. When the nonce space runs out it claims a
//! new extranonce, which changes the coinbase, which changes the merkle root,
//! which yields a completely fresh 2^32 nonces to try.
//!
//! # How the work is divided
//!
//! Threads do not split the nonce range. Each claims its **own extranonce**
//! from a shared counter, so every thread is searching a different coinbase and
//! therefore a disjoint space. That needs one atomic increment per 2^32 hashes
//! — which is to say, no coordination at all — and it scales to any number of
//! threads without them ever having to agree on anything.
//!
//! Splitting the nonce range instead would have every thread rebuild the same
//! merkle root and would need the range handed out in chunks. This is simpler
//! and strictly better.
//!
//! # Batching
//!
//! Nonces are tried in batches so that between batches a thread can notice new
//! work. Too small and the checks cost real time; too large and the miner keeps
//! grinding a job the chain has moved past. A million hashes is tens of
//! milliseconds, which is well inside the time it takes a new block to matter.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant};

use stratum::{Request, Share, method};

use crate::stats::Stats;
use crate::work::WorkState;

/// Nonces per batch, between checks for new work.
const BATCH: u32 = 1 << 20;

/// How long to wait for fresh work after finding a block candidate.
///
/// Bounded so that a candidate which loses its race — or a pool that goes quiet
/// — cannot stall a thread indefinitely.
const NEW_WORK_TIMEOUT: Duration = Duration::from_secs(2);

/// Everything the mining threads share.
struct Shared {
    state: Arc<WorkState>,
    stats: Arc<Stats>,
    outbound: Sender<String>,
    worker: String,
    /// Handed out one per thread per nonce sweep, so no two threads ever build
    /// the same coinbase.
    extranonce_counter: AtomicU64,
    /// JSON-RPC ids for submissions.
    submit_id: AtomicU64,
}

/// Starts `threads` mining threads and returns immediately.
pub fn spawn(
    state: Arc<WorkState>,
    stats: Arc<Stats>,
    outbound: Sender<String>,
    worker: String,
    threads: usize,
) {
    let shared = Arc::new(Shared {
        state,
        stats,
        outbound,
        worker,
        extranonce_counter: AtomicU64::new(0),
        submit_id: AtomicU64::new(100),
    });

    for _ in 0..threads {
        let shared = Arc::clone(&shared);
        std::thread::spawn(move || mine(&shared));
    }
}

/// One mining thread, running until the connection drops.
fn mine(shared: &Shared) {
    loop {
        let Some((work, generation)) = shared.state.snapshot() else {
            // No job yet. Wait rather than spin.
            std::thread::sleep(Duration::from_millis(100));
            continue;
        };

        // Another thread already solved this job. Wait for the next one rather
        // than looping straight back here and burning a core on nothing.
        if !shared.state.is_current(generation) {
            wait_for_new_work(&shared.state, generation);
            continue;
        }

        // Claim an extranonce nobody else will use.
        let counter = shared.extranonce_counter.fetch_add(1, Ordering::Relaxed);
        let extranonce2 = encode_extranonce2(counter, work.extranonce2_size);

        // The merkle root depends on the extranonce, so it is computed once
        // here and reused for the whole 2^32 nonce sweep below.
        let header = work.job.header(&work.extranonce1, &extranonce2, work.job.time, 0);

        let mut start = 0u32;
        while shared.state.is_current(generation) {
            let end = start.saturating_add(BATCH);
            let result = mining::search(&header, &work.target, start..end);

            shared.stats.record(result.hashes, result.best);

            if let Some(solution) = result.solution {
                // Stop every thread on this job, not just this one.
                shared.state.mark_solved(generation);
                submit(shared, &work.job.job_id, &extranonce2, work.job.time, solution);

                // The pool announces the network difficulty, so a solution is a
                // block candidate rather than a partial share. However it turns
                // out, the tip is about to move — so there is nothing left
                // worth doing with this job. Waiting beats grinding out
                // siblings of a block that has already been submitted.
                wait_for_new_work(&shared.state, generation);
                break;
            }

            if end == u32::MAX {
                break; // nonce space exhausted; claim a new extranonce
            }
            start = end;
        }
    }
}

/// Sends a share to the pool.
fn submit(
    shared: &Shared,
    job_id: &str,
    extranonce2: &[u8],
    time: u32,
    solution: mining::Solution,
) {
    println!(
        "solution found: {} ({} zero bits)",
        solution.hash,
        solution.hash.leading_zero_bits()
    );

    let share = Share {
        worker: shared.worker.clone(),
        job_id: job_id.to_owned(),
        extranonce2: extranonce2.to_vec(),
        time,
        nonce: solution.nonce,
    };

    let id = shared.submit_id.fetch_add(1, Ordering::Relaxed);

    match serde_json::to_string(&Request::call(id, method::SUBMIT, share.to_submit_params())) {
        Ok(line) => {
            let _ = shared.outbound.send(line);
        }
        Err(error) => eprintln!("cannot serialise share: {error}"),
    }
}

/// Blocks until *new work arrives*, or the timeout expires.
///
/// Watches the generation rather than `is_current`, because `is_current` also
/// goes false when this generation is solved — which is exactly the moment this
/// function is called, so using it here would return immediately every time.
fn wait_for_new_work(state: &WorkState, generation: u64) {
    let deadline = Instant::now() + NEW_WORK_TIMEOUT;

    while Instant::now() < deadline {
        if state.generation() != generation {
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
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

    /// Every thread must get a distinct extranonce, or two of them search the
    /// same space and half the machine's work is wasted.
    #[test]
    fn claimed_extranonces_are_distinct() {
        let counter = AtomicU64::new(0);
        let claimed: Vec<_> = (0..64)
            .map(|_| encode_extranonce2(counter.fetch_add(1, Ordering::Relaxed), 4))
            .collect();

        let unique: std::collections::HashSet<_> = claimed.iter().collect();
        assert_eq!(unique.len(), claimed.len());
    }
}

//! The work the miner is currently on, shared between the network thread and
//! the hashing loop.
//!
//! # Why there is a generation counter
//!
//! The hashing loop cannot check for new work on every hash — that would cost
//! more than the hashing. But it must not keep grinding a job that has been
//! superseded either: once a new block arrives, everything built on the old tip
//! is worthless, and every further hash is wasted power.
//!
//! So the loop checks a counter between batches. Bumping it is how the network
//! thread says "stop what you are doing", without any lock being held across
//! the hashing itself.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use btc_primitives::Target;
use stratum::Job;

/// A job together with the connection details needed to work on it.
#[derive(Clone)]
pub struct Work {
    /// The job from `mining.notify`.
    pub job: Job,
    /// This connection's extranonce prefix.
    pub extranonce1: Vec<u8>,
    /// How many extranonce bytes we supply.
    pub extranonce2_size: usize,
    /// The target a header must meet.
    pub target: Target,
}

/// The miner's current work, replaceable at any moment.
pub struct WorkState {
    current: Mutex<Option<Work>>,
    generation: AtomicU64,
    /// The generation a solution has already been found for.
    ///
    /// Because the pool announces the network difficulty, a solution is a block
    /// candidate — and once one thread has produced one, every other thread is
    /// grinding a job whose outcome is already decided. Recording it here stops
    /// the whole machine at once instead of one thread at a time.
    ///
    /// `u64::MAX` means "none", which no real generation will ever reach.
    solved: AtomicU64,
}

impl WorkState {
    /// Creates empty state.
    pub fn new() -> Self {
        Self {
            current: Mutex::new(None),
            generation: AtomicU64::new(0),
            solved: AtomicU64::new(u64::MAX),
        }
    }

    /// Replaces the current work and signals the hashing loop to restart.
    pub fn set(&self, work: Work) {
        *self.current.lock().expect("work mutex poisoned") = Some(work);
        self.generation.fetch_add(1, Ordering::Release);
    }

    /// The current work and the generation it belongs to.
    ///
    /// Returned together so the loop can tell whether what it is holding is
    /// still current without taking the lock again.
    pub fn snapshot(&self) -> Option<(Work, u64)> {
        let work = self.current.lock().expect("work mutex poisoned").clone()?;
        Some((work, self.generation.load(Ordering::Acquire)))
    }

    /// The current generation number.
    ///
    /// Distinct from [`Self::is_current`]: this changes only when *new work*
    /// arrives, whereas `is_current` also goes false once the generation has
    /// been solved. Code waiting for something new to do must watch this one,
    /// or it will see "not current" the instant a solution is found and spin.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Records that a solution was found for `generation`.
    ///
    /// Every thread working that generation will stop at its next batch
    /// boundary and wait for fresh work.
    pub fn mark_solved(&self, generation: u64) {
        self.solved.store(generation, Ordering::Release);
    }

    /// Whether `generation` is still worth working on.
    ///
    /// False once newer work has arrived, and also once this generation has
    /// been solved — there is nothing to gain from a second candidate for a
    /// block that has already been submitted.
    pub fn is_current(&self, generation: u64) -> bool {
        self.generation.load(Ordering::Acquire) == generation
            && self.solved.load(Ordering::Acquire) != generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use btc_primitives::Sha256dHash;

    fn work() -> Work {
        Work {
            job: Job {
                job_id: "1".to_owned(),
                prev_hash: Sha256dHash::ZERO,
                coinbase_prefix: Vec::new(),
                coinbase_suffix: Vec::new(),
                merkle_branch: Vec::new(),
                version: 1,
                bits: 0x207f_ffff,
                time: 0,
                clean_jobs: true,
            },
            extranonce1: vec![0; 4],
            extranonce2_size: 4,
            target: Target::from_compact(0x207f_ffff).expect("valid"),
        }
    }

    #[test]
    fn new_work_becomes_current() {
        let state = WorkState::new();
        assert!(state.snapshot().is_none());

        state.set(work());
        let (_, generation) = state.snapshot().expect("work is set");
        assert!(state.is_current(generation));
    }

    #[test]
    fn newer_work_supersedes_older() {
        let state = WorkState::new();

        state.set(work());
        let (_, first) = state.snapshot().expect("work is set");

        state.set(work());
        let (_, second) = state.snapshot().expect("work is set");

        assert_ne!(first, second);
        assert!(!state.is_current(first));
        assert!(state.is_current(second));
    }

    /// Solving a job must stop every thread on it.
    #[test]
    fn solving_retires_the_generation() {
        let state = WorkState::new();
        state.set(work());
        let (_, generation) = state.snapshot().expect("work is set");

        assert!(state.is_current(generation));
        state.mark_solved(generation);
        assert!(!state.is_current(generation));
    }

    /// The distinction that caused a real bug.
    ///
    /// `mark_solved` makes `is_current` false immediately, so a wait loop
    /// watching `is_current` returns the instant a solution is found and the
    /// caller spins. Only `generation` says whether there is anything *new*.
    ///
    /// The observed symptom was throughput collapsing from 95 blocks in eight
    /// seconds to 3, with the cores busy and doing nothing.
    #[test]
    fn solving_does_not_change_the_generation() {
        let state = WorkState::new();
        state.set(work());
        let (_, generation) = state.snapshot().expect("work is set");

        state.mark_solved(generation);

        assert!(!state.is_current(generation), "no longer worth working on");
        assert_eq!(
            state.generation(),
            generation,
            "but still the newest work — a waiter must not treat this as new"
        );

        state.set(work());
        assert_ne!(state.generation(), generation, "now there is new work");
    }

    /// A fresh generation is workable even though an older one was solved.
    #[test]
    fn solving_one_generation_does_not_retire_the_next() {
        let state = WorkState::new();

        state.set(work());
        let (_, first) = state.snapshot().expect("work is set");
        state.mark_solved(first);

        state.set(work());
        let (_, second) = state.snapshot().expect("work is set");

        assert!(state.is_current(second));
    }
}

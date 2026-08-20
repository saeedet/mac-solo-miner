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
}

impl WorkState {
    /// Creates empty state.
    pub fn new() -> Self {
        Self {
            current: Mutex::new(None),
            generation: AtomicU64::new(0),
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

    /// Whether `generation` is still the latest.
    pub fn is_current(&self, generation: u64) -> bool {
        self.generation.load(Ordering::Acquire) == generation
    }
}

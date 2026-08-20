//! Shared pool state: the current job, and everyone who should hear about it.
//!
//! Two threads touch this. A poller replaces the current job whenever bitcoind
//! offers a new template, and one thread per connected miner reads it. A plain
//! mutex is ample — the job changes at most a few times a minute, and reads are
//! a pointer clone.
//!
//! # Why old jobs are kept
//!
//! A share can arrive for a job that was current when the miner started hashing
//! but has since been replaced. That is not an error and not a miner's fault:
//! it is a message in flight during a template change. Discarding those would
//! throw away real work, so a short history is retained and shares are matched
//! against it.
//!
//! The history is bounded because a share for a job several blocks stale is
//! worthless — it builds on a block the chain has moved past.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};

use crate::job_builder::ActiveJob;

/// How many recent jobs stay valid for share submission.
const JOB_HISTORY: usize = 8;

/// A connected miner's outbound line channel.
struct Subscriber {
    id: u64,
    outbound: Sender<String>,
}

/// Everything shared between the pool's threads.
pub struct PoolState {
    inner: Mutex<Inner>,
    next_connection_id: AtomicU64,
    next_job_id: AtomicU64,
    /// Wakes the template poller ahead of its next tick.
    ///
    /// When we accept a block we already know the tip moved, so waiting for the
    /// poller to discover it is pure latency — and worse, our own `submitblock`
    /// calls contend with `getblocktemplate` inside the node, so the discovery
    /// can lag well past one poll interval. Every moment miners spend on the
    /// old job is wasted work on mainnet.
    refresh: Sender<()>,
}

struct Inner {
    /// Most recent first.
    jobs: VecDeque<Arc<ActiveJob>>,
    subscribers: Vec<Subscriber>,
}

impl PoolState {
    /// Creates empty state, along with the receiver the poller waits on.
    pub fn new() -> (Self, Receiver<()>) {
        let (refresh, wakeups) = channel();

        let state = Self {
            inner: Mutex::new(Inner {
                jobs: VecDeque::new(),
                subscribers: Vec::new(),
            }),
            next_connection_id: AtomicU64::new(1),
            next_job_id: AtomicU64::new(1),
            refresh,
        };

        (state, wakeups)
    }

    /// Asks the poller to fetch a fresh template right now.
    ///
    /// Best-effort: if the poller has gone away there is nothing useful to do
    /// about it here, and the accept loop will notice soon enough.
    pub fn request_refresh(&self) {
        let _ = self.refresh.send(());
    }

    /// Allocates an id for a new connection, used to derive its extranonce1.
    pub fn allocate_connection_id(&self) -> u64 {
        self.next_connection_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Allocates a job id.
    pub fn allocate_job_id(&self) -> String {
        format!("{:x}", self.next_job_id.fetch_add(1, Ordering::Relaxed))
    }

    /// Installs a new job and returns it.
    pub fn set_current_job(&self, job: ActiveJob) -> Arc<ActiveJob> {
        let job = Arc::new(job);

        let mut inner = self.inner.lock().expect("pool state mutex poisoned");
        inner.jobs.push_front(Arc::clone(&job));
        inner.jobs.truncate(JOB_HISTORY);

        job
    }

    /// The job miners should currently be working on.
    pub fn current_job(&self) -> Option<Arc<ActiveJob>> {
        self.inner
            .lock()
            .expect("pool state mutex poisoned")
            .jobs
            .front()
            .map(Arc::clone)
    }

    /// Looks up a job by id, including recently retired ones.
    pub fn job_by_id(&self, job_id: &str) -> Option<Arc<ActiveJob>> {
        self.inner
            .lock()
            .expect("pool state mutex poisoned")
            .jobs
            .iter()
            .find(|job| job.job.job_id == job_id)
            .map(Arc::clone)
    }

    /// Registers a connection to receive pushed work.
    pub fn subscribe(&self, id: u64, outbound: Sender<String>) {
        self.inner
            .lock()
            .expect("pool state mutex poisoned")
            .subscribers
            .push(Subscriber { id, outbound });
    }

    /// Removes a connection.
    pub fn unsubscribe(&self, id: u64) {
        self.inner
            .lock()
            .expect("pool state mutex poisoned")
            .subscribers
            .retain(|subscriber| subscriber.id != id);
    }

    /// Sends a line to every connected miner.
    ///
    /// A send failure means that miner's writer thread is gone, so the
    /// subscriber is dropped rather than retried — the reader thread will
    /// notice the closed socket and clean up the rest.
    pub fn broadcast(&self, line: &str) {
        let mut inner = self.inner.lock().expect("pool state mutex poisoned");
        inner
            .subscribers
            .retain(|subscriber| subscriber.outbound.send(line.to_owned()).is_ok());
    }

    /// How many miners are connected.
    pub fn subscriber_count(&self) -> usize {
        self.inner
            .lock()
            .expect("pool state mutex poisoned")
            .subscribers
            .len()
    }
}

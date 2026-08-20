//! Stratum V1 — the protocol between a mining pool and its miners.
//!
//! Stratum is line-delimited JSON over TCP, and the whole protocol is five
//! methods. A session looks like this:
//!
//! ```text
//! miner -> pool  mining.subscribe                     "what is my extranonce1?"
//! pool  -> miner [[..], extranonce1, extranonce2_size]
//! miner -> pool  mining.authorize  ["worker", "x"]
//! pool  -> miner true
//! pool  -> miner mining.set_difficulty [1.0]           (notification)
//! pool  -> miner mining.notify [job...]                (notification)
//! miner -> pool  mining.submit [worker, job, en2, ntime, nonce]
//! pool  -> miner true
//! ```
//!
//! This crate is shared by both ends deliberately. The pool and the miner
//! encode and decode with the *same* functions, so they cannot drift apart on
//! the details that are easy to get wrong — above all the byte orders in
//! [`byte_order`], which have no error case and simply produce a miner that
//! never finds anything.
//!
//! Nothing here does I/O. These are types and transformations; the sockets live
//! in the pool and miner crates.

pub mod byte_order;
pub mod job;
pub mod message;
pub mod share;

pub use job::{Job, Subscription};
pub use message::{Incoming, Request, Response, StratumError};
pub use share::Share;

/// Method names, so a typo becomes a compile error rather than a silent
/// protocol mismatch.
pub mod method {
    /// Client asks for its extranonce assignment.
    pub const SUBSCRIBE: &str = "mining.subscribe";
    /// Client identifies its worker.
    pub const AUTHORIZE: &str = "mining.authorize";
    /// Client submits a share.
    pub const SUBMIT: &str = "mining.submit";
    /// Server pushes new work.
    pub const NOTIFY: &str = "mining.notify";
    /// Server sets the share difficulty.
    pub const SET_DIFFICULTY: &str = "mining.set_difficulty";
}

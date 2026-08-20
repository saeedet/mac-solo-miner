//! Turning a block template into a mined block.
//!
//! Three things have to happen between "the node told us what to mine" and "we
//! have a valid block":
//!
//! 1. [`coinbase`] — build the transaction that pays us, satisfying BIP 34's
//!    height rule and BIP 141's witness commitment.
//! 2. [`block`] — compute the merkle root and serialise everything.
//! 3. [`search`] — try nonces until the header hash meets the target.
//!
//! This crate deliberately does **no I/O**. It never talks to a node, reads a
//! socket, or looks at a clock. Everything it produces is a pure function of
//! its inputs, which is what lets Phase 4 split it across a pool process and a
//! miner process without rewriting any of it.

pub mod block;
pub mod coinbase;
pub mod script;
pub mod search;
pub mod witness;

pub use block::BlockBuilder;
pub use coinbase::CoinbaseBuilder;
pub use search::{SearchResult, Solution, search};

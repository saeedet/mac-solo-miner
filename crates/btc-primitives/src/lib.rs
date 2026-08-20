//! Bitcoin's data structures: hashes, integers, transactions, merkle trees,
//! difficulty targets, and block headers.
//!
//! Everything here is pure. No I/O, no network, no clock — given the same
//! bytes in, these types always produce the same bytes out. That is what makes
//! them testable against real blocks from the chain, which is exactly how this
//! crate is verified: [`merkle::merkle_root`] rebuilds block 100000's merkle
//! root from its four transaction ids, and [`header::BlockHeader`] reassembles
//! the genesis block byte for byte.
//!
//! # Byte order
//!
//! If you read nothing else here, read [`hash`]. Bitcoin stores hashes in one
//! order and displays them in the reverse, and confusing the two is the most
//! common way for homemade mining software to fail — silently, by never finding
//! a block rather than by crashing. [`hash::Sha256dHash`] makes that a matter
//! of which method you call rather than something to remember.

pub mod hash;
pub mod header;
pub mod merkle;
pub mod reader;
pub mod target;
pub mod transaction;
pub mod varint;

pub use hash::Sha256dHash;
pub use header::BlockHeader;
pub use target::Target;
pub use transaction::{OutPoint, Transaction, TxIn, TxOut};

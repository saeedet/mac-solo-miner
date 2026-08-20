//! Assembling and serialising a complete block.
//!
//! A block on the wire is startlingly simple:
//!
//! ```text
//!   <80-byte header> <CompactSize transaction count> <transaction>...
//! ```
//!
//! The coinbase is always first. The remaining transactions go in exactly the
//! order the node gave them, because that order already satisfies the rule that
//! a transaction spending another's output must come after it.
//!
//! Note transactions are serialised **with** their witnesses here, unlike in
//! the merkle tree, which uses witness-free txids. Both are needed and they are
//! not interchangeable.

use btc_primitives::{BlockHeader, Sha256dHash, Transaction, merkle, varint};

/// A block under construction: a coinbase we built plus transactions the node
/// handed us as raw bytes.
///
/// The other transactions stay as bytes rather than being parsed into
/// [`Transaction`] values. There is nothing to gain from round-tripping them —
/// the node already validated them, and re-serialising introduces a chance of
/// producing something subtly different from what was validated.
#[derive(Debug, Clone)]
pub struct BlockBuilder {
    /// The coinbase transaction.
    pub coinbase: Transaction,
    /// The remaining transactions, serialised, in block order.
    pub transactions: Vec<Vec<u8>>,
    /// Their txids, in the same order, for the merkle tree.
    pub txids: Vec<Sha256dHash>,
}

impl BlockBuilder {
    /// Creates a builder from a coinbase and the node's transaction list.
    pub fn new(
        coinbase: Transaction,
        transactions: Vec<Vec<u8>>,
        txids: Vec<Sha256dHash>,
    ) -> Result<Self, BlockError> {
        if transactions.len() != txids.len() {
            return Err(BlockError::CountMismatch {
                transactions: transactions.len(),
                txids: txids.len(),
            });
        }

        Ok(Self {
            coinbase,
            transactions,
            txids,
        })
    }

    /// The merkle root over the coinbase and every other transaction.
    ///
    /// Uses **txids**, not wtxids — the witness tree is a separate structure
    /// committed to inside the coinbase. See [`crate::witness`].
    pub fn merkle_root(&self) -> Sha256dHash {
        let mut leaves = Vec::with_capacity(self.txids.len() + 1);
        leaves.push(self.coinbase.txid());
        leaves.extend_from_slice(&self.txids);

        merkle::merkle_root(&leaves).expect("the coinbase is always present")
    }

    /// How many transactions the block contains, counting the coinbase.
    pub fn transaction_count(&self) -> usize {
        self.transactions.len() + 1
    }

    /// Serialises the complete block for `submitblock`.
    pub fn serialize(&self, header: &BlockHeader) -> Vec<u8> {
        let mut block = Vec::new();

        block.extend_from_slice(&header.serialize());
        varint::encode(self.transaction_count() as u64, &mut block);

        // The coinbase, with its witness — the reserved value lives there.
        block.extend_from_slice(&self.coinbase.serialize());

        for transaction in &self.transactions {
            block.extend_from_slice(transaction);
        }

        block
    }
}

/// Why a block could not be assembled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockError {
    /// The transaction and txid lists were different lengths, which means the
    /// merkle root would not describe the block's actual contents.
    CountMismatch {
        /// How many raw transactions were given.
        transactions: usize,
        /// How many txids were given.
        txids: usize,
    },
}

impl std::fmt::Display for BlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CountMismatch { transactions, txids } => write!(
                f,
                "{transactions} transactions but {txids} txids — \
                 the merkle root would not match the block"
            ),
        }
    }
}

impl std::error::Error for BlockError {}

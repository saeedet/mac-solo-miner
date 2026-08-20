//! `getblocktemplate` — how a miner asks the node what to mine.
//!
//! The node does all the work a miner would otherwise have to: it picks which
//! transactions to include, orders them so dependencies come first, checks they
//! all fit the size and sigop limits, and works out what the coinbase is
//! allowed to pay. What comes back is everything needed to build a block except
//! the coinbase transaction and the nonce.
//!
//! Defined in BIP 22, extended for SegWit by BIP 145.
//!
//! # What the miner still has to do
//!
//! 1. Build the coinbase transaction — the block's first transaction, which
//!    creates the subsidy and collects the fees.
//! 2. Compute the merkle root over the coinbase and the given transactions.
//! 3. Search for a nonce that makes the header hash meet the target.
//!
//! Everything else here is handed to us.

use btc_primitives::hex::{self, HexError};
use btc_primitives::{Sha256dHash, Target};
use serde::Deserialize;
use std::str::FromStr;

/// A block template from `getblocktemplate`.
///
/// Only the fields this miner uses are declared. Bitcoin Core sends a good deal
/// more, and unknown fields are ignored rather than rejected, so a Core upgrade
/// that adds a field will not break us.
#[derive(Debug, Clone, Deserialize)]
pub struct BlockTemplate {
    /// Block version to put in the header.
    pub version: i32,

    /// The block we are building on top of, in display order.
    #[serde(rename = "previousblockhash")]
    pub previous_block_hash: String,

    /// Transactions to include, already ordered and validated by the node.
    pub transactions: Vec<TemplateTransaction>,

    /// The most the coinbase may pay out: subsidy plus the fees of every
    /// included transaction. Paying more makes the block invalid; paying less
    /// is legal but donates the difference to nobody.
    #[serde(rename = "coinbasevalue")]
    pub coinbase_value: u64,

    /// The compact difficulty target for the header, as hex.
    pub bits: String,

    /// The height this block will have. Required in the coinbase by BIP 34.
    pub height: u32,

    /// Suggested timestamp.
    #[serde(rename = "curtime")]
    pub current_time: u64,

    /// The earliest timestamp consensus will accept, one second past the median
    /// of the last eleven blocks.
    #[serde(rename = "mintime")]
    pub min_time: u64,

    /// The SegWit commitment output's `scriptPubKey`, as hex.
    ///
    /// Present whenever SegWit is active. We compute this ourselves in the
    /// `mining` crate and assert the two agree — deriving it is the point, and
    /// having the node's answer to check against makes that safe.
    #[serde(rename = "default_witness_commitment")]
    pub default_witness_commitment: Option<String>,

    /// Which parts of the template we are allowed to change.
    #[serde(default)]
    pub mutable: Vec<String>,
}

impl BlockTemplate {
    /// The previous block hash, parsed.
    pub fn previous_block(&self) -> Result<Sha256dHash, TemplateError> {
        Sha256dHash::from_str(&self.previous_block_hash)
            .map_err(|_| TemplateError::BadHash(self.previous_block_hash.clone()))
    }

    /// The compact target, parsed from the hex `bits` field.
    ///
    /// Note this is a plain big-endian hex number, *not* a byte-reversed hash,
    /// so it does not go through [`Sha256dHash`].
    pub fn compact_bits(&self) -> Result<u32, TemplateError> {
        let bytes = hex::decode_array::<4>(&self.bits)?;
        Ok(u32::from_be_bytes(bytes))
    }

    /// The difficulty target a solved header must meet.
    pub fn target(&self) -> Result<Target, TemplateError> {
        Target::from_compact(self.compact_bits()?).map_err(TemplateError::BadTarget)
    }

    /// Total weight of the included transactions, excluding the coinbase.
    pub fn transactions_weight(&self) -> u64 {
        self.transactions.iter().map(|tx| tx.weight).sum()
    }
}

/// One transaction the node wants included.
#[derive(Debug, Clone, Deserialize)]
pub struct TemplateTransaction {
    /// The full serialised transaction, as hex, witness included.
    pub data: String,

    /// The transaction id, in display order.
    pub txid: String,

    /// The **witness** transaction id, in display order.
    ///
    /// Confusingly this field is named `hash`, not `wtxid`. For a transaction
    /// with no witness it equals `txid`; otherwise it differs, and it is the
    /// one that goes into the witness commitment.
    pub hash: String,

    /// Fee paid, in satoshis. Already counted in `coinbase_value`.
    #[serde(default)]
    pub fee: i64,

    /// Weight units, for the 4,000,000 block limit.
    #[serde(default)]
    pub weight: u64,
}

impl TemplateTransaction {
    /// The raw transaction bytes.
    pub fn raw(&self) -> Result<Vec<u8>, TemplateError> {
        Ok(hex::decode(&self.data)?)
    }

    /// The transaction id, parsed. Goes into the block's merkle tree.
    pub fn txid(&self) -> Result<Sha256dHash, TemplateError> {
        Sha256dHash::from_str(&self.txid).map_err(|_| TemplateError::BadHash(self.txid.clone()))
    }

    /// The witness transaction id, parsed. Goes into the witness commitment.
    pub fn wtxid(&self) -> Result<Sha256dHash, TemplateError> {
        Sha256dHash::from_str(&self.hash).map_err(|_| TemplateError::BadHash(self.hash.clone()))
    }
}

/// Why a template could not be interpreted.
#[derive(Debug)]
pub enum TemplateError {
    /// A hash field was not 64 hex characters.
    BadHash(String),
    /// A hex field could not be decoded.
    BadHex(HexError),
    /// The `bits` field did not decode to a usable target.
    BadTarget(btc_primitives::target::TargetError),
}

impl From<HexError> for TemplateError {
    fn from(error: HexError) -> Self {
        Self::BadHex(error)
    }
}

impl std::fmt::Display for TemplateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadHash(value) => write!(f, "not a valid hash: {value:?}"),
            Self::BadHex(source) => write!(f, "bad hex in template: {source}"),
            Self::BadTarget(source) => write!(f, "bad target in template: {source}"),
        }
    }
}

impl std::error::Error for TemplateError {}

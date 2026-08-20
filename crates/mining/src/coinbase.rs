//! Building the coinbase — the transaction that pays the miner.
//!
//! Every block's first transaction is special. It has no real input, and its
//! outputs create coins that did not previously exist: the block subsidy plus
//! every fee paid by the other transactions in the block. It is the only place
//! in Bitcoin where value appears from nothing, and it is the entire economic
//! point of mining.
//!
//! It is also where most homemade miners fail, because three separate consensus
//! rules all land on this one transaction:
//!
//! - **BIP 34** — the `scriptSig` must begin with the block height, encoded as
//!   a minimal Script number. Get this wrong and the block is rejected with
//!   `bad-cb-height`.
//! - **BIP 141** — if SegWit is active, an `OP_RETURN` output must carry the
//!   witness commitment, and the input's witness stack must hold exactly one
//!   32-byte item. Rejections here read `bad-witness-merkle-match` or
//!   `bad-witness-nonce-size`.
//! - **The value cap** — outputs may total no more than subsidy plus fees.
//!   Exceeding it gives `bad-cb-amount`.
//!
//! # Why the `scriptSig` has room to spare
//!
//! After the height, the rest of the `scriptSig` is unconstrained. That space
//! is what makes mining scale: the nonce field in the header is only 32 bits,
//! which a fast miner exhausts almost immediately. Changing the `scriptSig`
//! changes the coinbase's txid, which changes the merkle root, which gives a
//! completely fresh 2^32 nonce space to search. That extra data is the
//! **extranonce**, and in Phase 4 the pool will hand out slices of it.

use btc_primitives::{OutPoint, Transaction, TxIn, TxOut};

use crate::script::{encode_block_height, push_data};
use crate::witness;

/// Consensus limits on the coinbase `scriptSig`.
///
/// The lower bound exists so the coinbase cannot be made trivially small; the
/// upper bound caps how much free data a miner can stuff into the chain.
pub const MIN_SCRIPT_SIG: usize = 2;
/// The maximum size of a coinbase `scriptSig`, in bytes.
pub const MAX_SCRIPT_SIG: usize = 100;

/// Assembles a coinbase transaction.
#[derive(Debug, Clone)]
pub struct CoinbaseBuilder {
    height: u32,
    value: u64,
    payout_script: Vec<u8>,
    extranonce: Vec<u8>,
    tag: Vec<u8>,
    witness_commitment: Option<Vec<u8>>,
}

impl CoinbaseBuilder {
    /// Starts a coinbase paying `value` satoshis to `payout_script` at `height`.
    pub fn new(height: u32, value: u64, payout_script: Vec<u8>) -> Self {
        Self {
            height,
            value,
            payout_script,
            extranonce: Vec::new(),
            tag: Vec::new(),
            witness_commitment: None,
        }
    }

    /// Sets the extranonce — the bytes varied to refresh the nonce space.
    pub fn extranonce(mut self, extranonce: impl Into<Vec<u8>>) -> Self {
        self.extranonce = extranonce.into();
        self
    }

    /// Sets an arbitrary tag, the "mined by" text pools traditionally embed.
    pub fn tag(mut self, tag: impl Into<Vec<u8>>) -> Self {
        self.tag = tag.into();
        self
    }

    /// Adds the SegWit commitment output and the required witness item.
    ///
    /// Pass the script from [`witness::commitment_script`]. Omit this only when
    /// SegWit is inactive, which on any live network it is not.
    pub fn witness_commitment(mut self, script: Vec<u8>) -> Self {
        self.witness_commitment = Some(script);
        self
    }

    /// The `scriptSig` this builder will produce.
    ///
    /// Exposed so a caller can check the length before committing to an
    /// extranonce size.
    pub fn script_sig(&self) -> Vec<u8> {
        let mut script = Vec::new();

        // BIP 34: the height, first, encoded exactly as Bitcoin Core expects.
        // Not a plain push — see `encode_block_height`.
        script.extend_from_slice(&encode_block_height(self.height));

        // Everything after is free-form. Both are pushed rather than appended
        // raw so arbitrary bytes can never be read as opcodes.
        if !self.extranonce.is_empty() {
            push_data(&self.extranonce, &mut script);
        }
        if !self.tag.is_empty() {
            push_data(&self.tag, &mut script);
        }

        script
    }

    /// Builds the transaction.
    pub fn build(&self) -> Result<Transaction, CoinbaseError> {
        let script_sig = self.script_sig();

        if script_sig.len() < MIN_SCRIPT_SIG || script_sig.len() > MAX_SCRIPT_SIG {
            return Err(CoinbaseError::ScriptSigLength(script_sig.len()));
        }

        // A coinbase carries a witness only when it also carries a commitment.
        // Adding one without the other makes the block invalid either way.
        let witness = match self.witness_commitment {
            Some(_) => vec![witness::RESERVED_VALUE.to_vec()],
            None => Vec::new(),
        };

        let mut outputs = vec![TxOut {
            value: self.value,
            script_pubkey: self.payout_script.clone(),
        }];

        // The commitment output pays zero — it exists only to be committed to.
        if let Some(script) = &self.witness_commitment {
            outputs.push(TxOut {
                value: 0,
                script_pubkey: script.clone(),
            });
        }

        Ok(Transaction {
            // Version 2 enables BIP 68 relative locktimes. Irrelevant for a
            // coinbase, but it is what every modern miner emits.
            version: 2,
            inputs: vec![TxIn {
                // A coinbase spends nothing, so its outpoint is the null one.
                previous_output: OutPoint::NULL,
                script_sig,
                sequence: 0xFFFF_FFFF,
                witness,
            }],
            outputs,
            lock_time: 0,
        })
    }
}

/// Why a coinbase could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoinbaseError {
    /// The `scriptSig` fell outside the consensus range of 2 to 100 bytes.
    ScriptSigLength(usize),
}

impl std::fmt::Display for CoinbaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ScriptSigLength(length) => write!(
                f,
                "coinbase scriptSig is {length} bytes, outside the consensus range \
                 of {MIN_SCRIPT_SIG}..={MAX_SCRIPT_SIG} (shrink the extranonce or tag)"
            ),
        }
    }
}

impl std::error::Error for CoinbaseError {}

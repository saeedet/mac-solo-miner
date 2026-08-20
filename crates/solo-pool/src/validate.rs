//! Checking a submitted share, and turning a winning one into a block.
//!
//! The pool never takes a miner's word for anything. It rebuilds the exact
//! header the miner claims to have hashed — from the job it issued and the
//! extranonce, timestamp, and nonce the miner supplied — and hashes it itself.
//!
//! In solo mining the miner and the pool operator are the same person, so there
//! is nobody to cheat. Doing it properly anyway is what makes it safe to point
//! an ASIC at this pool later: a Bitaxe's firmware is not something we wrote,
//! and its output should be verified rather than trusted.

use bitcoind_rpc::RpcClient;
use btc_primitives::{BlockHeader, Sha256dHash, hex};
use mining::BlockBuilder;
use stratum::Share;

use crate::job_builder::ActiveJob;

/// What the pool made of a share.
pub enum Verdict {
    /// The hash met the network target and bitcoind accepted the block.
    BlockAccepted {
        /// The block's hash.
        hash: Sha256dHash,
        /// Its height.
        height: u32,
    },
    /// The block was well-formed but did not become the chain tip.
    ///
    /// Bitcoin Core answers `inconclusive` for a valid block that is a sibling
    /// of the current tip, and `duplicate` for one it already has. Neither is a
    /// fault: they mean the work was real but someone — possibly us, moments
    /// earlier — got there first. Distinguishing them from a genuine rejection
    /// matters, because a genuine rejection is always our bug and these are not.
    BlockStale {
        /// Bitcoin Core's reason.
        reason: String,
        /// The block's hash.
        hash: Sha256dHash,
    },
    /// The hash met the network target but bitcoind refused the block.
    ///
    /// Always a bug on our side: the proof of work was real, so the block was
    /// malformed somewhere. The reason string says where.
    BlockRejected {
        /// Bitcoin Core's reason.
        reason: String,
        /// The hash that would have been the block's.
        hash: Sha256dHash,
    },
    /// A valid share that is not a block. Normal, and the overwhelming majority.
    Share {
        /// The hash produced.
        hash: Sha256dHash,
        /// How many leading zero bits it had — the near-miss measure.
        zero_bits: u32,
    },
}

/// Rebuilds and checks a share.
pub fn check(
    client: &RpcClient,
    active: &ActiveJob,
    share: &Share,
    extranonce1: &[u8],
) -> Result<Verdict, ValidationError> {
    // The full extranonce is the pool's half followed by the miner's.
    let mut extranonce = Vec::with_capacity(extranonce1.len() + share.extranonce2.len());
    extranonce.extend_from_slice(extranonce1);
    extranonce.extend_from_slice(&share.extranonce2);

    // Rebuild the coinbase exactly as the miner would have.
    let coinbase = active
        .coinbase(&extranonce)
        .map_err(|error| ValidationError::Rebuild(error.to_string()))?;

    // Cross-check: splicing the extranonce into the halves we sent must give
    // the same bytes as building the coinbase directly. If these disagree, the
    // split was wrong and every share from this job is unusable.
    let spliced = active.job.coinbase(extranonce1, &share.extranonce2);
    if spliced != coinbase.serialize_legacy() {
        return Err(ValidationError::CoinbaseMismatch);
    }

    let header = BlockHeader {
        version: active.job.version,
        prev_block: active.job.prev_hash,
        merkle_root: {
            let mut leaves = Vec::with_capacity(active.txids.len() + 1);
            leaves.push(coinbase.txid());
            leaves.extend_from_slice(&active.txids);
            btc_primitives::merkle::merkle_root(&leaves).expect("the coinbase is present")
        },
        // The miner's own choices, not ours.
        time: share.time,
        bits: active.job.bits,
        nonce: share.nonce,
    };

    let hash = header.hash();

    if !active.network_target.is_met_by(&hash) {
        return Ok(Verdict::Share {
            hash,
            zero_bits: hash.leading_zero_bits(),
        });
    }

    // A real block. Assemble and submit it.
    let block = BlockBuilder::new(coinbase, active.transactions.clone(), active.txids.clone())
        .map_err(|error| ValidationError::Rebuild(error.to_string()))?;

    let raw = block.serialize(&header);

    match client
        .submit_block(&hex::encode(&raw))
        .map_err(|error| ValidationError::Rpc(error.to_string()))?
    {
        None => Ok(Verdict::BlockAccepted {
            hash,
            height: active.height,
        }),
        // These two mean "valid, but not the tip" rather than "malformed".
        Some(reason) if reason == "inconclusive" || reason == "duplicate" => {
            Ok(Verdict::BlockStale { reason, hash })
        }
        Some(reason) => Ok(Verdict::BlockRejected { reason, hash }),
    }
}

/// Why a share could not be checked.
#[derive(Debug)]
pub enum ValidationError {
    /// The coinbase could not be rebuilt from the job.
    Rebuild(String),
    /// Splicing the sent halves disagreed with building the coinbase directly.
    CoinbaseMismatch,
    /// Talking to bitcoind failed.
    Rpc(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rebuild(message) => write!(f, "cannot rebuild the share's block: {message}"),
            Self::CoinbaseMismatch => write!(
                f,
                "the coinbase halves we sent do not splice back into the coinbase we build — \
                 the job's split is wrong"
            ),
            Self::Rpc(message) => write!(f, "bitcoind call failed: {message}"),
        }
    }
}

impl std::error::Error for ValidationError {}

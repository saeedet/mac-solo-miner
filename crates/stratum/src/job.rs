//! A unit of work, and how a miner turns it into a block header.
//!
//! `mining.notify` carries nine positional parameters:
//!
//! ```text
//! [job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs]
//! ```
//!
//! # Why the coinbase arrives in two halves
//!
//! The pool does not send the coinbase transaction. It sends everything
//! *before* the extranonce and everything *after* it, and the miner splices its
//! own bytes into the gap:
//!
//! ```text
//! coinbase = coinb1 ++ extranonce1 ++ extranonce2 ++ coinb2
//! ```
//!
//! `extranonce1` is assigned by the pool at subscribe time and is unique per
//! connection; `extranonce2` is the miner's to vary. Together they guarantee no
//! two miners ever search the same space, without the pool having to coordinate
//! anything.
//!
//! This is also why the pool sends a **merkle branch** rather than a merkle
//! root. The coinbase is the leftmost leaf, so changing it only invalidates the
//! path from that leaf to the root — and that path is exactly the branch. The
//! miner recomputes the root itself, cheaply, for every extranonce it tries.
//!
//! # The half that is not sent
//!
//! `coinb1` and `coinb2` are halves of the coinbase's **witness-free**
//! serialisation, because that is what the txid is computed over and the txid
//! is what the merkle tree needs. The full coinbase, witness included, only
//! matters when a block is finally assembled — which happens at the pool, not
//! the miner. A miner never sees or needs the witness.

use btc_primitives::{BlockHeader, Sha256dHash, hex, merkle};
use serde_json::{Value, json};

use crate::byte_order;

/// What the pool assigns a miner when it subscribes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    /// Per-connection prefix, chosen by the pool. Guarantees two miners never
    /// build the same coinbase even if they pick the same `extranonce2`.
    pub extranonce1: Vec<u8>,
    /// How many bytes of `extranonce2` the miner is expected to supply. The
    /// size is fixed for the session because it determines where the split in
    /// the coinbase falls.
    pub extranonce2_size: usize,
}

/// One job: everything needed to build headers, except the miner's own nonces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    /// Identifies this job when a share is submitted.
    pub job_id: String,
    /// The block being built on.
    pub prev_hash: Sha256dHash,
    /// Coinbase bytes before the extranonce.
    pub coinbase_prefix: Vec<u8>,
    /// Coinbase bytes after the extranonce.
    pub coinbase_suffix: Vec<u8>,
    /// Sibling hashes from the coinbase leaf up to the merkle root.
    pub merkle_branch: Vec<Sha256dHash>,
    /// Header version.
    pub version: i32,
    /// Compact difficulty target for the header.
    pub bits: u32,
    /// Suggested header timestamp.
    pub time: u32,
    /// Whether the miner must discard previous jobs.
    ///
    /// Set when a new block arrives. Anything built on the old tip is worthless
    /// the instant the chain moves, so continuing to hash it wastes power.
    pub clean_jobs: bool,
}

impl Job {
    /// Splices the extranonce into the coinbase, witness-free.
    pub fn coinbase(&self, extranonce1: &[u8], extranonce2: &[u8]) -> Vec<u8> {
        let mut coinbase = Vec::with_capacity(
            self.coinbase_prefix.len()
                + extranonce1.len()
                + extranonce2.len()
                + self.coinbase_suffix.len(),
        );

        coinbase.extend_from_slice(&self.coinbase_prefix);
        coinbase.extend_from_slice(extranonce1);
        coinbase.extend_from_slice(extranonce2);
        coinbase.extend_from_slice(&self.coinbase_suffix);

        coinbase
    }

    /// Rebuilds the merkle root for a given extranonce.
    ///
    /// The whole reason the branch is sent: this is a handful of hashes rather
    /// than a full tree, so the miner can afford to do it every time it rolls
    /// the extranonce.
    pub fn merkle_root(&self, extranonce1: &[u8], extranonce2: &[u8]) -> Sha256dHash {
        let coinbase_txid = Sha256dHash::hash(&self.coinbase(extranonce1, extranonce2));
        merkle::root_from_coinbase_branch(coinbase_txid, &self.merkle_branch)
    }

    /// Builds the header a miner will hash.
    ///
    /// `time` is passed separately because a miner is allowed to roll it within
    /// the range consensus permits, which buys extra search space beyond the
    /// nonce and extranonce.
    pub fn header(
        &self,
        extranonce1: &[u8],
        extranonce2: &[u8],
        time: u32,
        nonce: u32,
    ) -> BlockHeader {
        BlockHeader {
            version: self.version,
            prev_block: self.prev_hash,
            merkle_root: self.merkle_root(extranonce1, extranonce2),
            time,
            bits: self.bits,
            nonce,
        }
    }

    /// Encodes this job as `mining.notify` parameters.
    pub fn to_notify_params(&self) -> Value {
        let branch: Vec<String> = self
            .merkle_branch
            .iter()
            .map(|hash| hex::encode(hash.as_internal_bytes()))
            .collect();

        json!([
            self.job_id,
            hex::encode(&byte_order::hash_to_stratum(self.prev_hash)),
            hex::encode(&self.coinbase_prefix),
            hex::encode(&self.coinbase_suffix),
            branch,
            // Numeric fields go out as plain big-endian hex.
            format!("{:08x}", self.version as u32),
            format!("{:08x}", self.bits),
            format!("{:08x}", self.time),
            self.clean_jobs,
        ])
    }

    /// Decodes `mining.notify` parameters.
    pub fn from_notify_params(params: &Value) -> Result<Self, JobError> {
        let array = params.as_array().ok_or(JobError::NotAnArray)?;
        if array.len() < 9 {
            return Err(JobError::WrongParameterCount(array.len()));
        }

        let string = |index: usize| -> Result<&str, JobError> {
            array[index].as_str().ok_or(JobError::NotAString(index))
        };
        let u32_from_hex = |index: usize| -> Result<u32, JobError> {
            u32::from_str_radix(string(index)?, 16).map_err(|_| JobError::NotHex(index))
        };

        let prev_hash = byte_order::hash_from_stratum(
            hex::decode_array::<32>(string(1)?).map_err(|_| JobError::NotHex(1))?,
        );

        let merkle_branch = array[4]
            .as_array()
            .ok_or(JobError::NotAnArray)?
            .iter()
            .map(|entry| {
                let text = entry.as_str().ok_or(JobError::NotAString(4))?;
                let bytes = hex::decode_array::<32>(text).map_err(|_| JobError::NotHex(4))?;
                // Branch entries are plain internal order — no word swapping.
                Ok(Sha256dHash::from_internal_bytes(bytes))
            })
            .collect::<Result<Vec<_>, JobError>>()?;

        Ok(Self {
            job_id: string(0)?.to_owned(),
            prev_hash,
            coinbase_prefix: hex::decode(string(2)?).map_err(|_| JobError::NotHex(2))?,
            coinbase_suffix: hex::decode(string(3)?).map_err(|_| JobError::NotHex(3))?,
            merkle_branch,
            version: u32_from_hex(5)? as i32,
            bits: u32_from_hex(6)?,
            time: u32_from_hex(7)?,
            clean_jobs: array[8].as_bool().unwrap_or(false),
        })
    }
}

/// Why `mining.notify` parameters could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobError {
    /// The parameters were not a JSON array.
    NotAnArray,
    /// Fewer than the nine required parameters were present.
    WrongParameterCount(usize),
    /// A parameter that must be a string was not.
    NotAString(usize),
    /// A parameter that must be hex was not.
    NotHex(usize),
}

impl std::fmt::Display for JobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAnArray => write!(f, "mining.notify params are not an array"),
            Self::WrongParameterCount(n) => {
                write!(f, "mining.notify needs 9 parameters, got {n}")
            }
            Self::NotAString(i) => write!(f, "mining.notify parameter {i} is not a string"),
            Self::NotHex(i) => write!(f, "mining.notify parameter {i} is not valid hex"),
        }
    }
}

impl std::error::Error for JobError {}

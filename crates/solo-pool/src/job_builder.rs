//! Turning a block template into a Stratum job.
//!
//! The pool has to hand the miner a coinbase split in two, with a gap where the
//! extranonce goes. Finding that gap is the only fiddly part.
//!
//! # How the split is found
//!
//! Rather than computing the offset from the coinbase's structure — which would
//! silently break the moment the scriptSig layout changed — we build the
//! coinbase once with a **sentinel** extranonce, serialise it, and search for
//! those bytes. The split is wherever the sentinel landed.
//!
//! That makes the split self-checking: if the sentinel does not appear exactly
//! once, something is wrong and we refuse to build a job rather than hand a
//! miner work that reconstructs into a different coinbase than we expect.
//!
//! # Why the witness-free serialisation
//!
//! The miner uses its coinbase only to compute a txid, and txids are defined
//! over the serialisation *without* witness data. So the split is taken over
//! the legacy form. The pool keeps everything it needs to rebuild the full
//! coinbase — witness included — when a share turns out to be a block.

use bitcoind_rpc::BlockTemplate;
use btc_primitives::{Sha256dHash, Target, merkle};
use mining::{CoinbaseBuilder, witness};
use stratum::Job;

/// Total extranonce size: 4 bytes assigned by the pool, 4 chosen by the miner.
///
/// Eight bytes gives each connection 2^32 distinct coinbases, and each of those
/// a fresh 2^32 nonce space — far more than any single device will exhaust
/// between block templates.
pub const EXTRANONCE1_SIZE: usize = 4;
/// How many extranonce bytes the miner supplies.
pub const EXTRANONCE2_SIZE: usize = 4;
/// The combined extranonce width spliced into the coinbase.
pub const EXTRANONCE_SIZE: usize = EXTRANONCE1_SIZE + EXTRANONCE2_SIZE;

/// A job, plus everything needed to rebuild a real block from a share.
///
/// The miner receives only [`Self::job`]. The rest stays at the pool, because
/// the miner has no use for it and sending it would mean sending every
/// transaction in the block to every device.
pub struct ActiveJob {
    /// What gets sent to miners.
    pub job: Job,
    /// The height this block would have.
    pub height: u32,
    /// What the coinbase may pay out.
    pub coinbase_value: u64,
    /// Where it pays.
    pub payout_script: Vec<u8>,
    /// The BIP141 commitment output script.
    pub witness_commitment: Vec<u8>,
    /// The other transactions, serialised.
    pub transactions: Vec<Vec<u8>>,
    /// Their txids, in the same order.
    pub txids: Vec<Sha256dHash>,
    /// The target a header must meet to be a real block.
    pub network_target: Target,
}

impl ActiveJob {
    /// Rebuilds the coinbase transaction for a given extranonce.
    ///
    /// Used both when creating the job and when validating a share, so the two
    /// cannot disagree about what the miner was working on.
    pub fn coinbase(&self, extranonce: &[u8]) -> Result<btc_primitives::Transaction, BuildError> {
        CoinbaseBuilder::new(self.height, self.coinbase_value, self.payout_script.clone())
            .extranonce(extranonce.to_vec())
            .tag(b"solo-mac-miner".to_vec())
            .witness_commitment(self.witness_commitment.clone())
            .build()
            .map_err(BuildError::Coinbase)
    }
}

/// Builds a job from a template.
pub fn build(
    job_id: String,
    template: &BlockTemplate,
    payout_script: &[u8],
    clean_jobs: bool,
) -> Result<ActiveJob, BuildError> {
    let wtxids: Vec<Sha256dHash> = template
        .transactions
        .iter()
        .map(|tx| tx.wtxid())
        .collect::<Result<_, _>>()
        .map_err(|error| BuildError::Template(error.to_string()))?;

    let witness_commitment = witness::commitment_script(&wtxids);

    // The node tells us what it expects. Deriving it ourselves and then
    // checking is how we know our derivation is right; disagreeing means one of
    // us is wrong and the block would be rejected either way.
    if let Some(expected) = &template.default_witness_commitment
        && &btc_primitives::hex::encode(&witness_commitment) != expected
    {
        return Err(BuildError::WitnessCommitmentMismatch);
    }

    let txids: Vec<Sha256dHash> = template
        .transactions
        .iter()
        .map(|tx| tx.txid())
        .collect::<Result<_, _>>()
        .map_err(|error| BuildError::Template(error.to_string()))?;

    let transactions: Vec<Vec<u8>> = template
        .transactions
        .iter()
        .map(|tx| tx.raw())
        .collect::<Result<_, _>>()
        .map_err(|error| BuildError::Template(error.to_string()))?;

    let active = ActiveJob {
        job: Job {
            job_id,
            prev_hash: template
                .previous_block()
                .map_err(|error| BuildError::Template(error.to_string()))?,
            // Filled in below, once the split is known.
            coinbase_prefix: Vec::new(),
            coinbase_suffix: Vec::new(),
            merkle_branch: coinbase_branch(&txids),
            version: template.version,
            bits: template
                .compact_bits()
                .map_err(|error| BuildError::Template(error.to_string()))?,
            time: u32::try_from(template.current_time).map_err(|_| BuildError::TimeOverflow)?,
            clean_jobs,
        },
        height: template.height,
        coinbase_value: template.coinbase_value,
        payout_script: payout_script.to_vec(),
        witness_commitment,
        transactions,
        txids,
        network_target: template
            .target()
            .map_err(|error| BuildError::Template(error.to_string()))?,
    };

    let (prefix, suffix) = split_coinbase(&active)?;

    Ok(ActiveJob {
        job: Job {
            coinbase_prefix: prefix,
            coinbase_suffix: suffix,
            ..active.job
        },
        ..active
    })
}

/// The merkle branch from the coinbase leaf to the root.
///
/// [`merkle::coinbase_branch`] wants every leaf including the coinbase, but the
/// coinbase's txid is not fixed — it changes with the extranonce. Only its
/// *position* matters to the branch, so any placeholder works for slot zero.
fn coinbase_branch(txids: &[Sha256dHash]) -> Vec<Sha256dHash> {
    let mut leaves = Vec::with_capacity(txids.len() + 1);
    leaves.push(Sha256dHash::ZERO);
    leaves.extend_from_slice(txids);

    merkle::coinbase_branch(&leaves)
}

/// Splits the coinbase around where the extranonce sits.
fn split_coinbase(active: &ActiveJob) -> Result<(Vec<u8>, Vec<u8>), BuildError> {
    // A value no real coinbase would contain by accident.
    const SENTINEL: [u8; EXTRANONCE_SIZE] = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xF0, 0x0D];

    let coinbase = active.coinbase(&SENTINEL)?;
    let serialised = coinbase.serialize_legacy();

    let matches: Vec<usize> = serialised
        .windows(EXTRANONCE_SIZE)
        .enumerate()
        .filter(|(_, window)| *window == SENTINEL)
        .map(|(offset, _)| offset)
        .collect();

    // Exactly one occurrence, or we cannot know where the miner's bytes go.
    let [offset] = matches[..] else {
        return Err(BuildError::SentinelNotUnique(matches.len()));
    };

    Ok((
        serialised[..offset].to_vec(),
        serialised[offset + EXTRANONCE_SIZE..].to_vec(),
    ))
}

/// Why a job could not be built.
#[derive(Debug)]
pub enum BuildError {
    /// A field in the template could not be interpreted.
    Template(String),
    /// The coinbase could not be constructed.
    Coinbase(mining::coinbase::CoinbaseError),
    /// Our witness commitment disagreed with the node's.
    WitnessCommitmentMismatch,
    /// The template's timestamp did not fit in the header's 32 bits.
    TimeOverflow,
    /// The extranonce sentinel did not appear exactly once in the coinbase.
    SentinelNotUnique(usize),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Template(message) => write!(f, "bad block template: {message}"),
            Self::Coinbase(source) => write!(f, "cannot build coinbase: {source}"),
            Self::WitnessCommitmentMismatch => write!(
                f,
                "our witness commitment disagrees with bitcoind's — \
                 a block built on it would be rejected"
            ),
            Self::TimeOverflow => write!(f, "template timestamp does not fit in a u32"),
            Self::SentinelNotUnique(count) => write!(
                f,
                "extranonce sentinel appeared {count} times in the coinbase, expected once"
            ),
        }
    }
}

impl std::error::Error for BuildError {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A regtest template at height 113, in the shape bitcoind actually sends.
    fn template(transactions: serde_json::Value) -> BlockTemplate {
        serde_json::from_value(json!({
            "version": 536870912,
            "previousblockhash":
                "5bdb6182f63e514dca6711ace4c8a26b6d1f14a676c77fe92bdadd1dea9b6bbb",
            "transactions": transactions,
            "coinbasevalue": 5000000000u64,
            "bits": "207fffff",
            "height": 113,
            "curtime": 1700000000u64,
            "mintime": 1699999000u64,
            "mutable": ["time", "transactions", "prevblock"],
        }))
        .expect("the template shape matches what bitcoind sends")
    }

    const PAYOUT: [u8; 22] = [
        0x00, 0x14, 0x12, 0x7e, 0x95, 0x94, 0x2c, 0x00, 0x8b, 0xa8, 0x26, 0x13, 0xb0, 0x32, 0xba,
        0xa8, 0x5d, 0x2a, 0x53, 0x5d, 0x41, 0x05,
    ];

    /// The whole contract of the split: splicing an extranonce into the two
    /// halves we send must reproduce, byte for byte, the coinbase we build
    /// ourselves from that same extranonce.
    ///
    /// If this ever fails, every miner on the pool is hashing a coinbase the
    /// pool cannot reconstruct, so every share is unusable and no block can
    /// ever be submitted. The pool checks this again at runtime for each share,
    /// but catching it here is a millisecond instead of a wasted session.
    #[test]
    fn spliced_halves_reproduce_the_coinbase() {
        let active = build("1".to_owned(), &template(json!([])), &PAYOUT, true).expect("builds");

        for counter in [0u32, 1, 7, 0xFFFF_FFFF] {
            let extranonce1 = [0x00, 0x00, 0x00, 0x01];
            let extranonce2 = counter.to_be_bytes();

            let mut full = extranonce1.to_vec();
            full.extend_from_slice(&extranonce2);

            let spliced = active.job.coinbase(&extranonce1, &extranonce2);
            let built = active.coinbase(&full).expect("builds").serialize_legacy();

            assert_eq!(spliced, built, "split failed for extranonce2 {counter:#x}");
        }
    }

    /// The gap between the halves must be exactly the extranonce width.
    #[test]
    fn the_gap_is_the_extranonce_width() {
        let active = build("1".to_owned(), &template(json!([])), &PAYOUT, true).expect("builds");

        let spliced = active.job.coinbase(&[0; EXTRANONCE1_SIZE], &[0; EXTRANONCE2_SIZE]);
        let halves = active.job.coinbase_prefix.len() + active.job.coinbase_suffix.len();

        assert_eq!(spliced.len() - halves, EXTRANONCE_SIZE);
    }

    /// An empty block still needs a witness commitment, and its branch is empty
    /// because the coinbase is the only leaf.
    #[test]
    fn empty_block_has_no_merkle_branch() {
        let active = build("1".to_owned(), &template(json!([])), &PAYOUT, true).expect("builds");

        assert!(active.job.merkle_branch.is_empty());
        assert_eq!(active.witness_commitment.len(), 38);
        assert_eq!(active.height, 113);
    }

    /// A mismatch with the node's own commitment must abort job creation, since
    /// any block built on it would be rejected.
    #[test]
    fn disagreeing_with_bitcoind_aborts() {
        let mut value = template(json!([]));
        value.default_witness_commitment = Some("6a24aa21a9ed".to_owned() + &"00".repeat(32));

        assert!(matches!(
            build("1".to_owned(), &value, &PAYOUT, true),
            Err(BuildError::WitnessCommitmentMismatch)
        ));
    }

    /// With transactions present the branch must be deep enough to reach the
    /// root, and the job must carry their ids for block assembly.
    #[test]
    fn transactions_produce_a_branch() {
        let raw = "0100000001".to_owned() + &"00".repeat(50);
        let transactions = json!([
            {
                "data": raw,
                "txid": "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4",
                "hash": "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4",
                "fee": 1000,
                "weight": 400,
            },
            {
                "data": raw,
                "txid": "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4",
                "hash": "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4",
                "fee": 2000,
                "weight": 400,
            },
        ]);

        let active = build("1".to_owned(), &template(transactions), &PAYOUT, true).expect("builds");

        // Three leaves (coinbase + 2) means a two-level tree.
        assert_eq!(active.job.merkle_branch.len(), 2);
        assert_eq!(active.txids.len(), 2);
        assert_eq!(active.transactions.len(), 2);

        // And the split still holds with a non-trivial tree.
        let extranonce1 = [0x00, 0x00, 0x00, 0x01];
        let extranonce2 = [0x00, 0x00, 0x00, 0x09];
        let mut full = extranonce1.to_vec();
        full.extend_from_slice(&extranonce2);

        assert_eq!(
            active.job.coinbase(&extranonce1, &extranonce2),
            active.coinbase(&full).expect("builds").serialize_legacy()
        );
    }
}

//! One attempt at mining a block: template in, submitted block out.
//!
//! Kept separate from `main` so the sequence is readable end to end without
//! argument parsing and setup in the way. Every step here corresponds to
//! something a real miner does; nothing is skipped because it is regtest.

use bitcoind_rpc::{BlockTemplate, RpcClient};
use btc_primitives::hex;
use btc_primitives::{BlockHeader, Sha256dHash};
use mining::{BlockBuilder, CoinbaseBuilder, search, witness};

/// What happened in one round.
pub enum Outcome {
    /// The node accepted our block.
    Accepted {
        /// The block's hash.
        hash: Sha256dHash,
        /// Its height.
        height: u32,
        /// The winning nonce.
        nonce: u32,
        /// How many hashes it took.
        hashes: u64,
    },
    /// The node rejected it, and said why.
    Rejected {
        /// Bitcoin Core's reason string — `bad-cb-height`, `high-hash`, etc.
        reason: String,
    },
    /// The whole 2^32 nonce space was exhausted without a solution.
    ///
    /// Impossible on regtest, routine on mainnet. A real miner responds by
    /// changing the extranonce and searching a fresh space.
    Exhausted {
        /// The lowest hash seen.
        best: Sha256dHash,
        /// How many leading zero bits it had.
        best_zero_bits: u32,
    },
}

/// Builds a block from `template` and mines it.
pub fn mine(
    client: &RpcClient,
    template: &BlockTemplate,
    payout_script: &[u8],
    extranonce: u64,
) -> Result<Outcome, Box<dyn std::error::Error>> {
    // --- 1. The witness commitment ------------------------------------------
    //
    // We derive this ourselves and then check it against the node's own answer.
    // Deriving it is the point; having ground truth to check against is what
    // makes deriving it safe.
    let wtxids: Vec<Sha256dHash> = template
        .transactions
        .iter()
        .map(|tx| tx.wtxid())
        .collect::<Result<_, _>>()?;

    let commitment_script = witness::commitment_script(&wtxids);

    if let Some(expected) = &template.default_witness_commitment {
        let ours = hex::encode(&commitment_script);
        if &ours != expected {
            return Err(format!(
                "our witness commitment disagrees with bitcoind\n  ours: {ours}\n  node: {expected}"
            )
            .into());
        }
    }

    // --- 2. The coinbase ----------------------------------------------------
    let coinbase = CoinbaseBuilder::new(
        template.height,
        template.coinbase_value,
        payout_script.to_vec(),
    )
    .extranonce(extranonce.to_le_bytes().to_vec())
    .tag(b"solo-mac-miner".to_vec())
    .witness_commitment(commitment_script)
    .build()?;

    // --- 3. The block -------------------------------------------------------
    let raw_transactions: Vec<Vec<u8>> = template
        .transactions
        .iter()
        .map(|tx| tx.raw())
        .collect::<Result<_, _>>()?;
    let txids: Vec<Sha256dHash> = template
        .transactions
        .iter()
        .map(|tx| tx.txid())
        .collect::<Result<_, _>>()?;

    let builder = BlockBuilder::new(coinbase, raw_transactions, txids)?;

    let header = BlockHeader {
        version: template.version,
        prev_block: template.previous_block()?,
        merkle_root: builder.merkle_root(),
        time: u32::try_from(template.current_time)?,
        bits: template.compact_bits()?,
        nonce: 0,
    };

    // --- 4. The search ------------------------------------------------------
    let target = template.target()?;
    let result = search(&header, &target, 0..u32::MAX);

    let Some(solution) = result.solution else {
        return Ok(Outcome::Exhausted {
            best: result.best,
            best_zero_bits: result.best.leading_zero_bits(),
        });
    };

    // --- 5. Submit ----------------------------------------------------------
    let solved = BlockHeader {
        nonce: solution.nonce,
        ..header
    };
    let raw_block = builder.serialize(&solved);

    match client.submit_block(&hex::encode(&raw_block))? {
        None => Ok(Outcome::Accepted {
            hash: solution.hash,
            height: template.height,
            nonce: solution.nonce,
            hashes: result.hashes,
        }),
        Some(reason) => Ok(Outcome::Rejected { reason }),
    }
}

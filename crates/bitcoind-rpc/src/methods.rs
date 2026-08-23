//! Typed wrappers for the handful of RPCs a solo miner actually calls.
//!
//! Four methods is the whole surface. A miner needs to know where the tip is,
//! what to mine, and how to submit the result — and on regtest, a throwaway
//! address to pay itself.

use crate::client::{RpcClient, RpcError};
use crate::template::BlockTemplate;

use serde::Deserialize;
use serde_json::json;

/// The subset of `getblockheader` this project uses.
#[derive(Debug, Clone, Deserialize)]
pub struct BlockHeaderInfo {
    /// The block's hash, in display order.
    pub hash: String,
    /// Its height.
    pub height: u32,
    /// Its timestamp. The field testnet's minimum-difficulty rule turns on.
    pub time: u32,
    /// Its compact difficulty target, as hex.
    pub bits: String,
}

/// The result of validating an address.
#[derive(Debug, Clone, Deserialize)]
pub struct AddressInfo {
    /// Whether the address is well-formed **and** belongs to this network.
    #[serde(rename = "isvalid")]
    pub is_valid: bool,
    /// The locking script that pays to it, as hex. Absent when invalid.
    #[serde(rename = "scriptPubKey")]
    pub script_pubkey: Option<String>,
}

/// The subset of `getblockchaininfo` this project uses.
#[derive(Debug, Clone, Deserialize)]
pub struct BlockchainInfo {
    /// Network name: `main`, `testnet4`, or `regtest`.
    pub chain: String,
    /// Height of the most-work fully-validated chain.
    pub blocks: u32,
    /// Height of the highest header we know of. Ahead of `blocks` while
    /// blocks are still being downloaded.
    pub headers: u32,
    /// The tip's hash, in display order.
    #[serde(rename = "bestblockhash")]
    pub best_block_hash: String,
    /// Whether the node is still catching up.
    ///
    /// Mining while this is true is pointless: the tip we would build on is not
    /// the network's tip, so any block found would be rejected. Phase 7's
    /// "lottery mode" gates on exactly this flag.
    #[serde(rename = "initialblockdownload")]
    pub initial_block_download: bool,
    /// Whether the node is pruned.
    pub pruned: bool,
}

impl RpcClient {
    /// Where the chain tip is, and whether the node is caught up.
    pub fn get_blockchain_info(&self) -> Result<BlockchainInfo, RpcError> {
        self.call("getblockchaininfo", json!([]))
    }

    /// Asks the node what to mine.
    ///
    /// The `segwit` rule must be declared or Bitcoin Core refuses to produce a
    /// template at all — it will not hand a SegWit-era template to a client
    /// that has not said it understands SegWit, because such a client would
    /// build an invalid block.
    pub fn get_block_template(&self) -> Result<BlockTemplate, RpcError> {
        self.call(
            "getblocktemplate",
            json!([{ "rules": ["segwit"], "mode": "template" }]),
        )
    }

    /// Submits a solved block.
    ///
    /// Returns `None` when the block was accepted. Anything else is Bitcoin
    /// Core's reason for rejecting it — `high-hash`, `bad-cb-height`,
    /// `bad-witness-nonce-size` and so on. This is the single most important
    /// return value in the project, so it is deliberately not collapsed into a
    /// boolean: the reason string is what tells you which part of block
    /// assembly is wrong.
    pub fn submit_block(&self, raw_block_hex: &str) -> Result<Option<String>, RpcError> {
        self.call("submitblock", json!([raw_block_hex]))
    }

    /// Asks the node's wallet for a new address.
    ///
    /// Used on regtest to get a throwaway payout address. On testnet4 and
    /// mainnet the address comes from the user instead, and from a wallet whose
    /// keys they control.
    pub fn get_new_address(&self) -> Result<String, RpcError> {
        self.call("getnewaddress", json!(["", "bech32"]))
    }

    /// Fetches a block header.
    ///
    /// Needed because `getblocktemplate` reports the parent's *hash* but not
    /// its timestamp, and testnet's minimum-difficulty rule is defined relative
    /// to exactly that timestamp.
    pub fn get_block_header(&self, hash: &str) -> Result<BlockHeaderInfo, RpcError> {
        self.call("getblockheader", json!([hash, true]))
    }

    /// Validates an address and returns its `scriptPubKey`.
    ///
    /// Wallet-independent, so it works for an address the node has never seen —
    /// which is what Phases 6 and 7 need, where the payout address is supplied
    /// by the user rather than generated here.
    ///
    /// This is the safety gate for the payout address. A wrong-network or
    /// typo'd address does not fail loudly at mining time: it produces a
    /// perfectly valid block that pays to nothing recoverable. Checking here
    /// means the miner refuses to start instead.
    pub fn validate_address(&self, address: &str) -> Result<AddressInfo, RpcError> {
        self.call("validateaddress", json!([address]))
    }

    /// Creates a wallet, or loads it if it already exists.
    ///
    /// Regtest convenience: a fresh datadir has no wallet, and `getnewaddress`
    /// fails without one. Idempotent, so it is safe to call on every start.
    pub fn ensure_wallet(&self, name: &str) -> Result<(), RpcError> {
        // A wallet that already exists produces an RPC error rather than a
        // success, and "already there" is exactly the state we want, so both
        // outcomes are fine. Any other failure is a real one.
        let created: Result<serde_json::Value, _> =
            self.call("createwallet", json!([name, false, false, "", false, true]));

        match created {
            Ok(_) => Ok(()),
            Err(RpcError::Rpc { code, .. }) if code == -4 || code == -35 => {
                // -4 - wallet already exists on disk; -35 - already loaded.
                let loaded: Result<serde_json::Value, _> = self.call("loadwallet", json!([name]));
                match loaded {
                    Ok(_) => Ok(()),
                    // -35 again means another process already loaded it. Fine.
                    Err(RpcError::Rpc { code: -35, .. }) => Ok(()),
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        }
    }
}

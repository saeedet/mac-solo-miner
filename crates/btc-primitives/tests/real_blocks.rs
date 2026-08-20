//! Verification against real blocks from the Bitcoin blockchain.
//!
//! These are the tests that matter. Unit tests prove the code does what it was
//! written to do; these prove that what it was written to do is what Bitcoin
//! actually does. Every value below was produced by the real network, and none
//! of it can be made to pass by adjusting our own assumptions.

mod common;
use common::{hex, to_hex};

use btc_primitives::{BlockHeader, Sha256dHash, Transaction, merkle};
use std::str::FromStr;

/// Block 100000's four transaction ids, exactly as a block explorer lists them.
///
/// Fetched from a live node's index rather than transcribed, because these are
/// ground truth: if they are wrong, the test proves nothing.
const BLOCK_100000_TXIDS: [&str; 4] = [
    "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87", // coinbase
    "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4",
    "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4",
    "e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d",
];

/// The Phase 2 gate: rebuild block 100000's merkle root from its transactions.
///
/// In Phase 1 this root was fed into the header as a hex literal to check the
/// hasher. Now we derive it. Passing means the merkle construction, the pairing
/// order, and the byte-order handling are all correct together — and it is the
/// first point at which we can *construct* a header rather than merely hash one
/// somebody else built.
#[test]
fn block_100000_merkle_root_is_derived_from_its_txids() {
    let txids: Vec<Sha256dHash> = BLOCK_100000_TXIDS
        .iter()
        .map(|id| Sha256dHash::from_str(id).expect("valid txid"))
        .collect();

    let root = merkle::merkle_root(&txids).expect("four transactions");

    assert_eq!(
        root.to_string(),
        "f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766"
    );
}

/// The merkle branch must let us rebuild the same root from the coinbase alone.
///
/// This is precisely what a Stratum server sends a miner, so if this works, the
/// Phase 4 protocol split has the primitive it needs.
#[test]
fn block_100000_root_rebuilds_from_the_coinbase_branch() {
    let txids: Vec<Sha256dHash> = BLOCK_100000_TXIDS
        .iter()
        .map(|id| Sha256dHash::from_str(id).expect("valid txid"))
        .collect();

    let branch = merkle::coinbase_branch(&txids);
    assert_eq!(branch.len(), 2, "four leaves means a two-level tree");

    assert_eq!(
        merkle::root_from_coinbase_branch(txids[0], &branch),
        merkle::merkle_root(&txids).expect("four transactions"),
    );
}

/// Block 100000's header, rebuilt field by field and hashed.
#[test]
fn block_100000_header_round_trips() {
    let header = BlockHeader {
        version: 1,
        prev_block: Sha256dHash::from_str(
            "000000000002d01c1fccc21636b607dfd930d31d01c3a62104612a1719011250",
        )
        .expect("valid hash"),
        merkle_root: Sha256dHash::from_str(
            "f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766",
        )
        .expect("valid hash"),
        time: 1_293_623_863,
        bits: 0x1b04_864c,
        nonce: 274_148_111,
    };

    assert_eq!(
        header.hash().to_string(),
        "000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506"
    );

    // The header the real network published, byte for byte.
    assert_eq!(
        to_hex(&header.serialize()),
        concat!(
            "01000000",
            "50120119172a610421a6c3011dd330d9df07b63616c2cc1f1cd0020000000000",
            "6657a9252aacd5c0b2940996ecff952228c3067cc38d4885efb5a4ac4247e9f3",
            "37221b4d",
            "4c86041b",
            "0f2b5710",
        )
    );

    // And it really does satisfy the difficulty it claims.
    assert!(header.is_valid_proof_of_work().expect("valid bits"));

    // Parsing it back must give an identical header.
    assert_eq!(BlockHeader::deserialize(&header.serialize()), header);
}

/// The genesis coinbase transaction, parsed from the raw bytes Satoshi mined.
///
/// This exercises the transaction parser against the oldest data in Bitcoin,
/// and — because the genesis block has exactly one transaction — its txid is
/// also the merkle root, which closes the loop from raw bytes to block hash.
#[test]
fn genesis_coinbase_transaction() {
    let raw = hex(concat!(
        "01000000",                                                         // version
        "01",                                                               // one input
        "0000000000000000000000000000000000000000000000000000000000000000", // null outpoint
        "ffffffff",
        "4d",                                                               // 77-byte scriptSig
        "04ffff001d0104",                                                   // difficulty + push
        "455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f",
        "72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f72",
        "2062616e6b73",
        "ffffffff",                                                         // sequence
        "01",                                                               // one output
        "00f2052a01000000",                                                 // 50 BTC
        "43",                                                               // 67-byte script
        "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61d",
        "eb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11",
        "d5fac",
        "00000000",                                                         // lock time
    ));

    let tx = Transaction::deserialize(&raw).expect("parses");

    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.outputs.len(), 1);
    assert_eq!(tx.outputs[0].value, 50 * 100_000_000, "the original subsidy");
    assert!(!tx.has_witness(), "SegWit was 8 years away");

    // The message Satoshi embedded in the scriptSig — the timestamp proving the
    // chain was not pre-mined, and the closest thing Bitcoin has to an epigraph.
    // It is the last push in the script: 69 bytes, preceded by the 0x45 opcode
    // that pushes exactly that many.
    let script = &tx.inputs[0].script_sig;
    assert_eq!(script[script.len() - 70], 69, "a push-69-bytes opcode");
    assert_eq!(
        String::from_utf8_lossy(&script[script.len() - 69..]),
        "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
    );

    // Re-serialising must reproduce the input exactly.
    assert_eq!(tx.serialize(), raw);

    // With no witness, both ids agree.
    assert_eq!(tx.txid(), tx.wtxid());
    assert_eq!(
        tx.txid().to_string(),
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    );
}

/// The full chain of derivation for the genesis block: transaction bytes ->
/// txid -> merkle root -> header -> block hash.
///
/// Nothing here is a literal except the transaction itself and the final
/// answer. Everything in between is computed.
#[test]
fn genesis_block_derives_end_to_end() {
    let raw = hex(concat!(
        "01000000010000000000000000000000000000000000000000000000000000000000",
        "000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32",
        "303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e6420",
        "6261696c6f757420666f722062616e6b73ffffffff0100f2052a0100000043410467",
        "8afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc",
        "3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000",
    ));

    let coinbase = Transaction::deserialize(&raw).expect("parses");
    let merkle_root = merkle::merkle_root(&[coinbase.txid()]).expect("one transaction");

    let header = BlockHeader {
        version: 1,
        prev_block: Sha256dHash::ZERO,
        merkle_root,
        time: 1_231_006_505,
        bits: 0x1d00_ffff,
        nonce: 2_083_236_893,
    };

    assert_eq!(
        header.hash().to_string(),
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    );
    assert!(header.is_valid_proof_of_work().expect("valid bits"));
}

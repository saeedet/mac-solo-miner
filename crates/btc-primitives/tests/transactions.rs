//! Transaction serialisation, especially the SegWit split between txid and wtxid.

use btc_primitives::{OutPoint, Sha256dHash, Transaction, TxIn, TxOut};

/// Builds a transaction with a witness on its only input.
fn segwit_transaction() -> Transaction {
    Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Sha256dHash::hash(b"some previous transaction"),
                vout: 0,
            },
            // A native SegWit spend has an empty scriptSig; the unlocking data
            // lives entirely in the witness.
            script_sig: Vec::new(),
            sequence: 0xFFFF_FFFF,
            witness: vec![vec![0x30, 0x44, 0x02], vec![0x02, 0x79, 0xBE]],
        }],
        outputs: vec![TxOut {
            value: 99_000,
            script_pubkey: vec![0x00, 0x14, 0xAB, 0xCD],
        }],
        lock_time: 0,
    }
}

/// A witness transaction must round-trip through both serialisation formats.
#[test]
fn segwit_round_trips() {
    let tx = segwit_transaction();
    assert!(tx.has_witness());

    let full = tx.serialize();
    assert_eq!(Transaction::deserialize(&full).expect("parses"), tx);

    // The marker and flag sit immediately after the 4-byte version.
    assert_eq!(&full[4..6], &[0x00, 0x01], "SegWit marker and flag");

    // The legacy form must not contain them, and must be shorter.
    let legacy = tx.serialize_legacy();
    assert!(legacy.len() < full.len());
    assert_ne!(&legacy[4..6], &[0x00, 0x01]);
}

/// The two ids differ for a witness transaction, and the txid ignores the witness.
///
/// This is the property that fixed transaction malleability: changing the
/// witness changes the wtxid but leaves the txid — the thing other transactions
/// reference — untouched.
#[test]
fn witness_changes_wtxid_but_not_txid() {
    let tx = segwit_transaction();
    assert_ne!(tx.txid(), tx.wtxid());

    // The txid is exactly the hash of the witness-free bytes.
    assert_eq!(tx.txid(), Sha256dHash::hash(&tx.serialize_legacy()));

    let mut altered = tx.clone();
    altered.inputs[0].witness[0] = vec![0x30, 0x45, 0x02, 0x21];

    assert_eq!(altered.txid(), tx.txid(), "txid must survive witness changes");
    assert_ne!(altered.wtxid(), tx.wtxid(), "wtxid must not");
}

/// Without a witness, the two serialisations and both ids coincide.
#[test]
fn legacy_transaction_has_one_id() {
    let mut tx = segwit_transaction();
    tx.inputs[0].witness.clear();

    assert!(!tx.has_witness());
    assert_eq!(tx.serialize(), tx.serialize_legacy());
    assert_eq!(tx.txid(), tx.wtxid());
}

/// A coinbase input spends the null outpoint.
#[test]
fn coinbase_outpoint_is_null() {
    assert_eq!(OutPoint::NULL.txid, Sha256dHash::ZERO);
    assert_eq!(OutPoint::NULL.vout, 0xFFFF_FFFF);
}

/// Truncated input must produce an error, never a panic.
#[test]
fn truncated_input_errors_cleanly() {
    let full = segwit_transaction().serialize();
    for length in 0..full.len() {
        assert!(
            Transaction::deserialize(&full[..length]).is_err(),
            "a {length}-byte prefix should not parse"
        );
    }
}

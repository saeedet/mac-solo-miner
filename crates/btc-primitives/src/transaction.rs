//! Transactions, and the two different hashes they have.
//!
//! # Why a transaction has two ids
//!
//! SegWit (BIP 141) moved signatures out of the main transaction body into a
//! separate "witness" section. It had to, and the reason is the whole point:
//! before SegWit, a third party could alter a signature's encoding without
//! invalidating it, changing the transaction's id while leaving its meaning
//! intact. That is transaction malleability, and it broke any protocol that
//! referred to a transaction before it confirmed.
//!
//! The fix was to define the txid over a serialisation that *excludes* the
//! witness. So:
//!
//! - **txid** — hash of the legacy serialisation, with no witness data. This is
//!   what other transactions reference, and what goes into the block's merkle
//!   tree.
//! - **wtxid** — hash of the full serialisation including witnesses. These form
//!   a second merkle tree, whose root is committed to in the coinbase.
//!
//! For a transaction with no witness the two are identical.
//!
//! # Why the miner cares
//!
//! A miner assembling a block needs txids for the merkle root, and wtxids for
//! the witness commitment that Phase 3 has to put in the coinbase. Getting
//! either wrong produces a block that is rejected — so the distinction is worth
//! encoding in the API rather than in a comment.

use crate::hash::Sha256dHash;
use crate::reader::{ReadError, Reader};
use crate::varint;

/// A reference to a specific output of a previous transaction.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OutPoint {
    /// The transaction being spent from.
    pub txid: Sha256dHash,
    /// Which output of it, zero-indexed.
    pub vout: u32,
}

impl OutPoint {
    /// The null outpoint: all-zero txid and `vout` of `0xFFFFFFFF`.
    ///
    /// A coinbase transaction's single input uses this, because it spends
    /// nothing — the coins it creates did not exist before.
    pub const NULL: Self = Self {
        txid: Sha256dHash::ZERO,
        vout: 0xFFFF_FFFF,
    };
}

/// A transaction input.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TxIn {
    /// The output being spent.
    pub previous_output: OutPoint,
    /// The unlocking script. In a coinbase this is unconstrained data, which is
    /// where the block height and the extranonce live.
    pub script_sig: Vec<u8>,
    /// Originally for transaction replacement; now used for relative timelocks
    /// and RBF signalling. Miners normally set `0xFFFFFFFF`.
    pub sequence: u32,
    /// SegWit witness stack. Empty for a legacy input.
    pub witness: Vec<Vec<u8>>,
}

/// A transaction output.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TxOut {
    /// Amount in satoshis.
    pub value: u64,
    /// The locking script that says who may spend it.
    pub script_pubkey: Vec<u8>,
}

/// A Bitcoin transaction.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transaction {
    /// Transaction version.
    pub version: i32,
    /// Inputs. A coinbase has exactly one, spending [`OutPoint::NULL`].
    pub inputs: Vec<TxIn>,
    /// Outputs.
    pub outputs: Vec<TxOut>,
    /// Earliest block height or timestamp at which this may be mined.
    pub lock_time: u32,
}

impl Transaction {
    /// Whether any input carries witness data.
    pub fn has_witness(&self) -> bool {
        self.inputs.iter().any(|input| !input.witness.is_empty())
    }

    /// Serialises without witness data — the pre-SegWit format.
    ///
    /// This is what the txid is computed over, for every transaction, witness
    /// or not.
    pub fn serialize_legacy(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        self.write_inputs(&mut out);
        self.write_outputs(&mut out);
        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out
    }

    /// Serialises in the format used on the wire and in blocks.
    ///
    /// Identical to [`Self::serialize_legacy`] when there is no witness;
    /// otherwise it inserts the SegWit marker and flag and appends the witness
    /// stacks before the lock time.
    pub fn serialize(&self) -> Vec<u8> {
        if !self.has_witness() {
            return self.serialize_legacy();
        }

        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());

        // Marker 0x00 and flag 0x01. The marker is unambiguous because a legacy
        // transaction's next field is its input count, which can never be zero.
        out.push(0x00);
        out.push(0x01);

        self.write_inputs(&mut out);
        self.write_outputs(&mut out);

        // One witness stack per input, in input order.
        for input in &self.inputs {
            varint::encode(input.witness.len() as u64, &mut out);
            for item in &input.witness {
                varint::encode(item.len() as u64, &mut out);
                out.extend_from_slice(item);
            }
        }

        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out
    }

    /// The transaction id: `sha256d` of the witness-free serialisation.
    pub fn txid(&self) -> Sha256dHash {
        Sha256dHash::hash(&self.serialize_legacy())
    }

    /// The witness transaction id: `sha256d` of the full serialisation.
    pub fn wtxid(&self) -> Sha256dHash {
        Sha256dHash::hash(&self.serialize())
    }

    fn write_inputs(&self, out: &mut Vec<u8>) {
        varint::encode(self.inputs.len() as u64, out);
        for input in &self.inputs {
            out.extend_from_slice(input.previous_output.txid.as_internal_bytes());
            out.extend_from_slice(&input.previous_output.vout.to_le_bytes());
            varint::encode(input.script_sig.len() as u64, out);
            out.extend_from_slice(&input.script_sig);
            out.extend_from_slice(&input.sequence.to_le_bytes());
        }
    }

    fn write_outputs(&self, out: &mut Vec<u8>) {
        varint::encode(self.outputs.len() as u64, out);
        for output in &self.outputs {
            out.extend_from_slice(&output.value.to_le_bytes());
            varint::encode(output.script_pubkey.len() as u64, out);
            out.extend_from_slice(&output.script_pubkey);
        }
    }

    /// Parses a transaction, with or without witness data.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ReadError> {
        let mut reader = Reader::new(bytes);
        let version = reader.read_i32()?;

        // A zero input count is the SegWit marker, not a real count.
        let mut input_count = reader.read_varint()?;
        let segwit = input_count == 0;
        if segwit {
            let _flag = reader.read_bytes(1)?;
            input_count = reader.read_varint()?;
        }

        let mut inputs = Vec::new();
        for _ in 0..input_count {
            inputs.push(TxIn {
                previous_output: OutPoint {
                    txid: reader.read_hash()?,
                    vout: reader.read_u32()?,
                },
                script_sig: reader.read_var_bytes()?.to_vec(),
                sequence: reader.read_u32()?,
                witness: Vec::new(),
            });
        }

        let output_count = reader.read_varint()?;
        let mut outputs = Vec::new();
        for _ in 0..output_count {
            outputs.push(TxOut {
                value: reader.read_u64()?,
                script_pubkey: reader.read_var_bytes()?.to_vec(),
            });
        }

        if segwit {
            for input in &mut inputs {
                let items = reader.read_varint()?;
                for _ in 0..items {
                    input.witness.push(reader.read_var_bytes()?.to_vec());
                }
            }
        }

        Ok(Self {
            version,
            inputs,
            outputs,
            lock_time: reader.read_u32()?,
        })
    }
}

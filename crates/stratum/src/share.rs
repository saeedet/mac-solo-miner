//! A submitted share: `mining.submit`.
//!
//! ```text
//! ["worker_name", job_id, extranonce2, ntime, nonce]
//! ```
//!
//! Five fields, and between them they name every degree of freedom a miner has.
//! The pool already knows the job, so it only needs the parts the miner chose:
//! which extranonce it spliced in, what timestamp it settled on, and the nonce
//! that worked. From those it can rebuild the exact header the miner hashed and
//! check the result for itself.
//!
//! That last point is the security model. The pool never trusts a miner's claim
//! that it found something — it reconstructs the work and verifies it. In solo
//! mining that matters less, since the miner and the operator are the same
//! person, but building it correctly now is what lets a Bitaxe be pointed at
//! this pool later without any of it being taken on faith.

use btc_primitives::hex;
use serde_json::{Value, json};

/// A share submitted by a miner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    /// The worker name from `mining.authorize`.
    pub worker: String,
    /// Which job this share is for.
    pub job_id: String,
    /// The miner's half of the extranonce.
    pub extranonce2: Vec<u8>,
    /// The header timestamp the miner used.
    pub time: u32,
    /// The nonce that produced the winning hash.
    pub nonce: u32,
}

impl Share {
    /// Encodes as `mining.submit` parameters.
    pub fn to_submit_params(&self) -> Value {
        json!([
            self.worker,
            self.job_id,
            hex::encode(&self.extranonce2),
            format!("{:08x}", self.time),
            format!("{:08x}", self.nonce),
        ])
    }

    /// Decodes `mining.submit` parameters.
    pub fn from_submit_params(params: &Value) -> Result<Self, ShareError> {
        let array = params.as_array().ok_or(ShareError::NotAnArray)?;
        if array.len() < 5 {
            return Err(ShareError::WrongParameterCount(array.len()));
        }

        let string = |index: usize| -> Result<&str, ShareError> {
            array[index].as_str().ok_or(ShareError::NotAString(index))
        };
        let u32_from_hex = |index: usize| -> Result<u32, ShareError> {
            u32::from_str_radix(string(index)?, 16).map_err(|_| ShareError::NotHex(index))
        };

        Ok(Self {
            worker: string(0)?.to_owned(),
            job_id: string(1)?.to_owned(),
            extranonce2: hex::decode(string(2)?).map_err(|_| ShareError::NotHex(2))?,
            time: u32_from_hex(3)?,
            nonce: u32_from_hex(4)?,
        })
    }
}

/// Why `mining.submit` parameters could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareError {
    /// The parameters were not a JSON array.
    NotAnArray,
    /// Fewer than the five required parameters were present.
    WrongParameterCount(usize),
    /// A parameter that must be a string was not.
    NotAString(usize),
    /// A parameter that must be hex was not.
    NotHex(usize),
}

impl std::fmt::Display for ShareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAnArray => write!(f, "mining.submit params are not an array"),
            Self::WrongParameterCount(n) => write!(f, "mining.submit needs 5 parameters, got {n}"),
            Self::NotAString(i) => write!(f, "mining.submit parameter {i} is not a string"),
            Self::NotHex(i) => write!(f, "mining.submit parameter {i} is not valid hex"),
        }
    }
}

impl std::error::Error for ShareError {}

//! SHA-256 and double-SHA-256 (`sha256d`), the hash function Bitcoin is built on.
//!
//! Bitcoin almost never uses SHA-256 alone. It uses **double** SHA-256:
//! `sha256d(x) = sha256(sha256(x))`. That is what secures block headers, what
//! builds merkle trees, and what mining actually searches over.
//!
//! This crate will hold two implementations of the same function:
//!
//! 1. A **portable reference** version, written to mirror the FIPS 180-4 spec
//!    step by step. It is not fast. Its job is to be readable enough that you
//!    can check it against the spec by eye.
//! 2. An **Apple Silicon** version using the ARMv8 cryptographic extensions
//!    (`sha256h`, `sha256h2`, `sha256su0`, `sha256su1`), which this Mac has.
//!
//! The reference version is the specification the fast version is tested
//! against: a property test asserts the two agree on arbitrary input. That way
//! the slow one teaches, and the fast one is held to what it teaches.
//!
//! Status: scaffolding only. Implemented in Phase 1.

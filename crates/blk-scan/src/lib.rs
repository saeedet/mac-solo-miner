//! Reading, checking, and repairing Bitcoin Core block files.
//!
//! Built for one job: after a `blk00000.dat` was destroyed, work out whether a
//! replacement rebuilt from the network genuinely joins up with the surviving
//! archive — before committing to a reindex measured in tens of hours.
//!
//! Two binaries use it: `blk-scan` reports what chain a set of files contains,
//! and `blk-concat` joins files together while fixing up their obfuscation.

pub mod obfuscation;
pub mod scan;

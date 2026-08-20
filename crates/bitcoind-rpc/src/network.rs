//! The three Bitcoin networks this project targets, and where each keeps things.
//!
//! Every network has its own genesis block, its own difficulty rules, its own
//! address prefixes, and its own default ports. Mixing them up is not a subtle
//! bug — a testnet address on mainnet is unspendable — so the network is a type
//! rather than a string that gets passed around.

use std::path::{Path, PathBuf};

/// Which Bitcoin network a node is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// A private chain with trivial difficulty, existing only on this machine.
    /// Blocks are mined on demand. This is where the miner gets debugged.
    Regtest,
    /// The current public test network. Real peer-to-peer, worthless coins.
    Testnet4,
    /// The real one.
    Mainnet,
}

impl Network {
    /// Bitcoin Core's default JSON-RPC port for this network.
    pub const fn default_rpc_port(self) -> u16 {
        match self {
            Self::Regtest => 18443,
            Self::Testnet4 => 48332,
            Self::Mainnet => 8332,
        }
    }

    /// The subdirectory Bitcoin Core uses inside the datadir.
    ///
    /// Mainnet lives at the top level for historical reasons; every other
    /// network gets its own folder.
    pub const fn datadir_subdirectory(self) -> Option<&'static str> {
        match self {
            Self::Regtest => Some("regtest"),
            Self::Testnet4 => Some("testnet4"),
            Self::Mainnet => None,
        }
    }

    /// Where bitcoind writes the RPC cookie for this network.
    pub fn cookie_path(self, datadir: &Path) -> PathBuf {
        match self.datadir_subdirectory() {
            Some(subdirectory) => datadir.join(subdirectory).join(".cookie"),
            None => datadir.join(".cookie"),
        }
    }

    /// The name Bitcoin Core reports in `getblockchaininfo`'s `chain` field.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Regtest => "regtest",
            Self::Testnet4 => "testnet4",
            Self::Mainnet => "main",
        }
    }

    /// Parses the name used on the command line and by `getblockchaininfo`.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "regtest" => Some(Self::Regtest),
            "testnet4" => Some(Self::Testnet4),
            "main" | "mainnet" => Some(Self::Mainnet),
            _ => None,
        }
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_paths_match_bitcoin_core_layout() {
        let datadir = Path::new("/tmp/data");

        assert_eq!(
            Network::Regtest.cookie_path(datadir),
            Path::new("/tmp/data/regtest/.cookie")
        );
        assert_eq!(
            Network::Testnet4.cookie_path(datadir),
            Path::new("/tmp/data/testnet4/.cookie")
        );
        // Mainnet has no subdirectory.
        assert_eq!(
            Network::Mainnet.cookie_path(datadir),
            Path::new("/tmp/data/.cookie")
        );
    }

    /// `getblockchaininfo` reports mainnet as "main", so parsing must round-trip.
    #[test]
    fn names_round_trip() {
        for network in [Network::Regtest, Network::Testnet4, Network::Mainnet] {
            assert_eq!(Network::parse(network.as_str()), Some(network));
        }
        assert_eq!(Network::parse("testnet3"), None);
    }
}

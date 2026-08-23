//! A small JSON-RPC client for a local Bitcoin Core node.
//!
//! Scoped to what a solo miner needs: fetch a block template, submit a solved
//! block, and ask the node where the chain tip is. It authenticates with the
//! cookie file bitcoind writes on startup, so no password is stored anywhere.
//!
//! The HTTP and base64 layers are written here rather than taken as
//! dependencies — see [`http`] for why that is reasonable for a loopback-only
//! client, and unreasonable for anything else.

pub mod auth;
pub mod client;
pub mod http;
pub mod methods;
pub mod network;
pub mod template;

pub use client::{RpcClient, RpcError};
pub use methods::{AddressInfo, BlockHeaderInfo, BlockchainInfo};
pub use network::Network;
pub use template::{BlockTemplate, TemplateTransaction};

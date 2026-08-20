//! Connects to the local regtest node and prints what it says.
//!
//! The first end-to-end check that cookie auth, the hand-rolled HTTP layer, and
//! the JSON-RPC framing all work against real Bitcoin Core.
//!
//! ```text
//! cargo run --example probe -p bitcoind-rpc
//! ```

use bitcoind_rpc::{Network, RpcClient};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let datadir = std::env::var("SOLO_DATADIR").unwrap_or_else(|_| {
        format!("{}/.bitcoin-solo", std::env::var("HOME").expect("HOME is set"))
    });

    let client = RpcClient::from_datadir(std::path::Path::new(&datadir), Network::Regtest)?;

    let info = client.get_blockchain_info()?;
    println!("chain      : {}", info.chain);
    println!("height     : {}", info.blocks);
    println!("tip        : {}", info.best_block_hash);
    println!("in IBD     : {}", info.initial_block_download);

    let template = client.get_block_template()?;
    println!("\n--- block template ---");
    println!("height     : {}", template.height);
    println!("version    : {}", template.version);
    println!("prev block : {}", template.previous_block()?);
    println!("bits       : {} -> {:#010x}", template.bits, template.compact_bits()?);
    println!("target     : {}", template.target()?);
    println!("coinbase   : {} sats", template.coinbase_value);
    println!("txs        : {}", template.transactions.len());
    println!(
        "witness cmt: {}",
        template
            .default_witness_commitment
            .as_deref()
            .unwrap_or("(none - segwit inactive)")
    );

    Ok(())
}

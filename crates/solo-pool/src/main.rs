//! A solo mining pool: bitcoind on one side, Stratum V1 on the other.
//!
//! ```text
//! solo-pool [--network regtest] [--listen 127.0.0.1:3333] [--address bc1...]
//! ```
//!
//! # What a solo pool is for
//!
//! A normal pool exists to smooth income: hundreds of miners contribute work,
//! and the pool divides the reward. A *solo* pool divides nothing. It exists
//! because Stratum is the protocol mining hardware speaks, and speaking it is
//! what lets any miner — this project's, or an ASIC bought later — point at a
//! node without knowing anything about block assembly.
//!
//! So the split is not ceremony. It is the seam that makes the hardware
//! question independent of the software one.
//!
//! # Threads
//!
//! One poller watches bitcoind for new templates. One thread accepts
//! connections. Each connection gets a reader and a writer. Nothing else.

mod job_builder;
mod session;
mod state;
mod validate;

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bitcoind_rpc::{Network, RpcClient};
use btc_primitives::hex;
use stratum::{Request, method};

use state::PoolState;

/// How often to ask bitcoind whether the work has changed.
///
/// Polling is the simple answer, and at this interval it costs nothing on a
/// local node. The better answer is the ZMQ `hashblock` notification the Phase 0
/// config already enables, which would cut the latency between a new block
/// arriving and miners being told from half a second to nearly zero. Worth
/// doing before mainnet, where every stale second is wasted electricity.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// How often to rebuild the job even when the tip has not moved, to pick up
/// transactions that arrived in the meantime.
const REFRESH_INTERVAL: Duration = Duration::from_secs(30);

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        let mut source = error.source();
        while let Some(cause) = source {
            eprintln!("  caused by: {cause}");
            source = cause.source();
        }
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let options = Options::from_args()?;

    let client = Arc::new(RpcClient::from_datadir(&options.datadir, options.network)?);

    let info = client.get_blockchain_info()?;
    if info.chain != options.network.as_str() {
        return Err(format!(
            "asked for {} but the node at {} is running {}",
            options.network,
            options.datadir.display(),
            info.chain
        )
        .into());
    }

    // Mining on a node that has not caught up builds on the wrong tip, so any
    // block found would be rejected. Refuse rather than waste the session.
    if info.initial_block_download {
        return Err(format!(
            "the node is still syncing ({} of {} blocks) — \
             mining now would build on a stale tip",
            info.blocks, info.headers
        )
        .into());
    }

    let payout_script = resolve_payout_script(&client, &options)?;

    println!("pool    : {} on {}", options.network, options.listen);
    println!("node    : height {}", info.blocks);
    println!("payout  : {}\n", hex::encode(&payout_script));

    let (state, wakeups) = PoolState::new();
    let state = Arc::new(state);

    // The poller owns template watching; the main thread owns accepting.
    {
        let state = Arc::clone(&state);
        let client = Arc::clone(&client);
        std::thread::spawn(move || poll_templates(&state, &client, &payout_script, &wakeups));
    }

    let listener = TcpListener::bind(options.listen)?;
    println!("waiting for miners on {}", options.listen);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // Small writes, sent immediately: a job notification delayed by
                // Nagle is a job the miner is not working on yet.
                let _ = stream.set_nodelay(true);

                let state = Arc::clone(&state);
                let client = Arc::clone(&client);
                std::thread::spawn(move || session::handle(stream, state, client));
            }
            Err(error) => eprintln!("cannot accept connection: {error}"),
        }
    }

    Ok(())
}

/// Watches bitcoind for new work and pushes it to every connected miner.
fn poll_templates(
    state: &PoolState,
    client: &RpcClient,
    payout_script: &[u8],
    wakeups: &std::sync::mpsc::Receiver<()>,
) {
    let mut last_tip = None;
    let mut last_built = std::time::Instant::now();

    loop {
        match client.get_block_template() {
            Ok(template) => {
                let tip = template.previous_block_hash.clone();

                // A changed tip means everything in flight is now worthless, so
                // miners are told to discard it. A periodic refresh on the same
                // tip only adds transactions, so old work stays valid.
                let tip_changed = last_tip.as_ref() != Some(&tip);
                let stale = last_built.elapsed() >= REFRESH_INTERVAL;

                if tip_changed || stale {
                    let job_id = state.allocate_job_id();

                    match job_builder::build(job_id, &template, payout_script, tip_changed) {
                        Ok(active) => {
                            let height = active.height;
                            let transactions = active.transactions.len();
                            let job = state.set_current_job(active);

                            if tip_changed {
                                println!(
                                    "new tip at height {} — job {} ({transactions} txs, {} miners)",
                                    height - 1,
                                    job.job.job_id,
                                    state.subscriber_count(),
                                );
                            }

                            let notify = Request::notification(
                                method::NOTIFY,
                                job.job.to_notify_params(),
                            );
                            if let Ok(line) = serde_json::to_string(&notify) {
                                state.broadcast(&line);
                            }

                            last_tip = Some(tip);
                            last_built = std::time::Instant::now();
                        }
                        Err(error) => eprintln!("cannot build a job: {error}"),
                    }
                }
            }
            Err(error) => eprintln!("cannot fetch a template: {error}"),
        }

        // Sleep, but wake early if a session tells us the tip moved. Draining
        // any further requests that piled up keeps one burst of accepted blocks
        // from causing a burst of redundant template fetches.
        if wakeups.recv_timeout(POLL_INTERVAL).is_ok() {
            while wakeups.try_recv().is_ok() {}
        }
    }
}

/// Works out where block rewards should go.
fn resolve_payout_script(
    client: &RpcClient,
    options: &Options,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // On regtest the coins are meaningless, so a throwaway wallet address is
    // fine and saves the user a step. Anywhere else, the address must be
    // supplied deliberately — this is real money and it should not default.
    let address = match &options.address {
        Some(address) => address.clone(),
        None if options.network == Network::Regtest => {
            client.ensure_wallet("solo-miner-regtest")?;
            client.get_new_address()?
        }
        None => {
            return Err(format!(
                "--address is required on {}. Rewards are paid to it and cannot be recovered \
                 if it is wrong, so there is deliberately no default.",
                options.network
            )
            .into());
        }
    };

    // The safety gate. A wrong-network or mistyped address does not fail
    // loudly at mining time — it produces a perfectly valid block paying to
    // nothing anyone can spend.
    let info = client.validate_address(&address)?;
    if !info.is_valid {
        return Err(format!(
            "{address:?} is not a valid {} address — refusing to mine to it",
            options.network
        )
        .into());
    }

    println!("address : {address}");

    Ok(hex::decode(
        info.script_pubkey
            .as_deref()
            .ok_or("validateaddress returned no scriptPubKey")?,
    )?)
}

/// Command-line options.
struct Options {
    network: Network,
    listen: std::net::SocketAddr,
    address: Option<String>,
    datadir: PathBuf,
}

impl Options {
    fn from_args() -> Result<Self, Box<dyn std::error::Error>> {
        let mut network = Network::Regtest;
        let mut listen = "127.0.0.1:3333".to_owned();
        let mut address = None;

        let mut args = std::env::args().skip(1);
        while let Some(flag) = args.next() {
            let mut value = || {
                args.next()
                    .ok_or_else(|| format!("{flag} needs a value"))
            };

            match flag.as_str() {
                "--network" => {
                    let name = value()?;
                    network = Network::parse(&name)
                        .ok_or_else(|| format!("unknown network {name:?}"))?;
                }
                "--listen" => listen = value()?,
                "--address" => address = Some(value()?),
                "--help" | "-h" => {
                    println!(
                        "solo-pool [--network regtest|testnet4|mainnet] \
                         [--listen ADDR] [--address ADDR]"
                    );
                    std::process::exit(0);
                }
                other => return Err(format!("unknown option {other:?}").into()),
            }
        }

        Ok(Self {
            network,
            listen: listen.parse()?,
            address,
            datadir: std::env::var("SOLO_DATADIR").map_or_else(
                |_| PathBuf::from(std::env::var("HOME").expect("HOME is set")).join(".bitcoin-solo"),
                PathBuf::from,
            ),
        })
    }
}

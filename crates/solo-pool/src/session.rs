//! One connected miner.
//!
//! Each connection gets two threads. A **reader** parses incoming lines and
//! answers them; a **writer** owns the socket's write half and drains a channel.
//!
//! Splitting them that way is what makes pushed work possible. The pool needs
//! to send `mining.notify` at a moment of its choosing, which may be while the
//! reader is blocked waiting for the miner to say something. Routing every
//! outbound line — replies and notifications alike — through one channel and
//! one writer means the socket is never written from two places at once, with
//! no lock around it.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};

use bitcoind_rpc::RpcClient;
use btc_primitives::{Target, hex};
use serde_json::json;
use stratum::{Incoming, Request, Response, Share, StratumError, method};

use crate::job_builder::EXTRANONCE2_SIZE;
use crate::state::PoolState;
use crate::validate::{self, Verdict};

/// Serves one miner until it disconnects.
pub fn handle(stream: TcpStream, state: Arc<PoolState>, client: Arc<RpcClient>) {
    let connection_id = state.allocate_connection_id();
    let peer = stream
        .peer_addr()
        .map_or_else(|_| "<unknown>".to_owned(), |address| address.to_string());

    // Each connection gets a distinct extranonce1, so two miners can never
    // build the same coinbase even if they choose the same extranonce2.
    let extranonce1 = (connection_id as u32).to_be_bytes().to_vec();

    let Ok(write_half) = stream.try_clone() else {
        eprintln!("[{peer}] cannot split the socket, dropping connection");
        return;
    };

    let (outbound, inbox) = channel::<String>();
    std::thread::spawn(move || writer_loop(write_half, inbox));

    println!("[{peer}] connected (extranonce1 {})", hex::encode(&extranonce1));

    let mut session = Session {
        peer: peer.clone(),
        connection_id,
        extranonce1,
        authorized: false,
        outbound: outbound.clone(),
        state: Arc::clone(&state),
        client,
    };

    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }

        if !session.dispatch(&line) {
            break;
        }
    }

    state.unsubscribe(connection_id);
    println!("[{peer}] disconnected");
}

/// Drains the outbound channel onto the socket.
fn writer_loop(mut stream: TcpStream, inbox: Receiver<String>) {
    for line in inbox {
        // Stratum is line-delimited; the newline is the frame boundary.
        if stream.write_all(line.as_bytes()).is_err() || stream.write_all(b"\n").is_err() {
            break;
        }
        if stream.flush().is_err() {
            break;
        }
    }
}

struct Session {
    peer: String,
    connection_id: u64,
    extranonce1: Vec<u8>,
    authorized: bool,
    outbound: Sender<String>,
    state: Arc<PoolState>,
    client: Arc<RpcClient>,
}

impl Session {
    /// Handles one line. Returns false when the connection should close.
    fn dispatch(&mut self, line: &str) -> bool {
        let request = match Incoming::parse(line) {
            Ok(Incoming::Request(request)) => request,
            // A miner sending us a response is a protocol error, but not worth
            // dropping the connection over.
            Ok(Incoming::Response(_)) => return true,
            Err(error) => {
                eprintln!("[{}] {error}", self.peer);
                return true;
            }
        };

        match request.method.as_str() {
            method::SUBSCRIBE => self.on_subscribe(&request),
            method::AUTHORIZE => self.on_authorize(&request),
            method::SUBMIT => self.on_submit(&request),
            other => {
                // Real miners send extensions we do not implement, such as
                // mining.configure for version rolling. Declining politely is
                // correct; they fall back.
                self.reply(Response::error(
                    request.id,
                    StratumError::other(format!("unsupported method {other}")),
                ));
            }
        }

        true
    }

    /// `mining.subscribe` — assign the extranonce and start pushing work.
    fn on_subscribe(&mut self, request: &Request) {
        // The response shape is fixed by convention:
        //   [[[notification, subscription_id], ...], extranonce1, extranonce2_size]
        // The subscription ids exist so a miner can cancel individual
        // notification streams. Nothing does, but the field must be present or
        // real miners fail to parse the reply.
        let subscription_id = format!("{:016x}", self.connection_id);

        self.reply(Response::ok(
            request.id,
            json!([
                [
                    [method::SET_DIFFICULTY, subscription_id.clone()],
                    [method::NOTIFY, subscription_id],
                ],
                hex::encode(&self.extranonce1),
                EXTRANONCE2_SIZE,
            ]),
        ));

        self.state.subscribe(self.connection_id, self.outbound.clone());
    }

    /// `mining.authorize` — solo mining, so any worker name is accepted.
    ///
    /// There is no account system and nothing to authenticate against: the
    /// pool's only user is whoever is running it. The name is kept for logging.
    fn on_authorize(&mut self, request: &Request) {
        let worker = request
            .params
            .get(0)
            .and_then(|value| value.as_str())
            .unwrap_or("<anonymous>");

        println!("[{}] authorized worker {worker}", self.peer);
        self.authorized = true;
        self.reply(Response::ok(request.id, json!(true)));

        self.send_current_work();
    }

    /// `mining.submit` — rebuild the header, verify it, and submit any block.
    fn on_submit(&mut self, request: &Request) {
        if !self.authorized {
            self.reply(Response::error(request.id, StratumError::unauthorized()));
            return;
        }

        let share = match Share::from_submit_params(&request.params) {
            Ok(share) => share,
            Err(error) => {
                self.reply(Response::error(
                    request.id,
                    StratumError::other(error.to_string()),
                ));
                return;
            }
        };

        let Some(active) = self.state.job_by_id(&share.job_id) else {
            // Routine: the job aged out while the share was in flight.
            self.reply(Response::error(request.id, StratumError::job_not_found()));
            return;
        };

        match validate::check(&self.client, &active, &share, &self.extranonce1) {
            Ok(Verdict::BlockAccepted { hash, height }) => {
                println!("\n*** BLOCK FOUND at height {height} ***");
                println!("    {hash}");
                println!("    submitted by {} and accepted by bitcoind\n", self.peer);
                self.reply(Response::ok(request.id, json!(true)));

                // We just moved the tip ourselves. Everything every miner is
                // working on is now worthless, so fetch fresh work immediately
                // rather than waiting for the poller to rediscover what we
                // already know.
                self.state.request_refresh();
            }
            Ok(Verdict::BlockStale { reason, hash }) => {
                // Valid work that lost a race, not a fault. Still worth asking
                // for fresh work, since it means our idea of the tip is behind.
                println!("[{}] block {hash} not adopted ({reason})", self.peer);
                self.reply(Response::ok(request.id, json!(true)));
                self.state.request_refresh();
            }
            Ok(Verdict::BlockRejected { reason, hash }) => {
                // The work was real, so this is our bug, not the miner's.
                eprintln!("[{}] bitcoind REJECTED a solved block: {reason}", self.peer);
                eprintln!("    hash was {hash}");
                self.reply(Response::error(
                    request.id,
                    StratumError::other(format!("node rejected block: {reason}")),
                ));
            }
            Ok(Verdict::Share { hash, zero_bits }) => {
                println!("[{}] share {zero_bits} zero bits  {hash}", self.peer);
                self.reply(Response::ok(request.id, json!(true)));
            }
            Err(error) => {
                eprintln!("[{}] cannot validate share: {error}", self.peer);
                self.reply(Response::error(
                    request.id,
                    StratumError::other(error.to_string()),
                ));
            }
        }
    }

    /// Sends the difficulty and the current job to this miner.
    fn send_current_work(&self) {
        let Some(active) = self.state.current_job() else {
            return;
        };

        // Solo mining announces the network difficulty rather than an easier
        // share difficulty. There is no payout to apportion, so a share below
        // the network target is worth nothing — the only reason to accept
        // easier shares is hashrate monitoring, and the miner measures its own.
        let difficulty = Target::difficulty(active.job.bits);

        self.send(&Request::notification(
            method::SET_DIFFICULTY,
            json!([difficulty]),
        ));
        self.send(&Request::notification(
            method::NOTIFY,
            active.job.to_notify_params(),
        ));
    }

    fn reply(&self, response: Response) {
        match serde_json::to_string(&response) {
            Ok(line) => {
                let _ = self.outbound.send(line);
            }
            Err(error) => eprintln!("[{}] cannot serialise response: {error}", self.peer),
        }
    }

    fn send(&self, request: &Request) {
        match serde_json::to_string(request) {
            Ok(line) => {
                let _ = self.outbound.send(line);
            }
            Err(error) => eprintln!("[{}] cannot serialise notification: {error}", self.peer),
        }
    }
}

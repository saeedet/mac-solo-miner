//! The Stratum socket, split into a line reader and a line writer.
//!
//! Same shape as the pool's session handling and for the same reason: work
//! arrives unprompted. The pool sends `mining.notify` whenever it likes, which
//! may be while we are blocked mid-write or busy hashing, so reading has to be
//! somebody else's job.
//!
//! Both directions become channels. Everything above this module deals in
//! [`Incoming`] values and strings, and never touches the socket.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::mpsc::{Receiver, Sender, channel};

use stratum::Incoming;

/// A live Stratum connection.
pub struct Connection {
    /// Lines to send. Serialised messages go in here.
    pub outbound: Sender<String>,
    /// Messages received, in arrival order.
    pub incoming: Receiver<Incoming>,
}

/// Connects and starts the reader and writer threads.
pub fn connect(address: &str) -> std::io::Result<Connection> {
    let stream = TcpStream::connect(address)?;
    // A share delayed by Nagle is a share that might arrive after the block
    // it solves has been superseded.
    stream.set_nodelay(true)?;

    let read_half = stream.try_clone()?;

    let (outbound, to_send) = channel::<String>();
    let (received, incoming) = channel::<Incoming>();

    std::thread::spawn(move || {
        let reader = BufReader::new(read_half);
        for line in reader.lines() {
            let Ok(line) = line else { break };
            if line.trim().is_empty() {
                continue;
            }

            match Incoming::parse(&line) {
                Ok(message) => {
                    if received.send(message).is_err() {
                        break;
                    }
                }
                // A message we cannot parse is worth reporting but not worth
                // disconnecting over — pools send extensions we ignore.
                Err(error) => eprintln!("cannot parse from pool: {error}"),
            }
        }
    });

    std::thread::spawn(move || {
        let mut stream = stream;
        for line in to_send {
            if stream.write_all(line.as_bytes()).is_err()
                || stream.write_all(b"\n").is_err()
                || stream.flush().is_err()
            {
                break;
            }
        }
    });

    Ok(Connection { outbound, incoming })
}

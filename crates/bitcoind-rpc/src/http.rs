//! A minimal HTTP/1.1 client, scoped to exactly what bitcoind's RPC needs.
//!
//! This is not a general HTTP client and must not be used as one. It speaks to
//! `127.0.0.1` only, it sends one request per connection, and it understands
//! only the response shapes Bitcoin Core produces.
//!
//! That narrowness is the justification for writing it rather than taking a
//! dependency. A real HTTP client has to handle TLS, redirects, chunked
//! transfer encoding, connection pooling, and proxies — none of which apply to
//! a loopback socket talking to a process on the same machine. The whole thing
//! fits in one readable file, and it keeps the dependency list at "JSON only".
//!
//! # Why a new connection per request
//!
//! We send `Connection: close` and reconnect each time. On loopback a TCP
//! connect costs tens of microseconds, which is irrelevant next to how often we
//! actually call the RPC — a few times a second at most. In exchange we avoid
//! keep-alive state, half-closed sockets, and the class of bug where a stale
//! pooled connection surfaces minutes later as an unexplained failure.

use std::fmt;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// An HTTP response from bitcoind.
pub struct Response {
    /// The HTTP status code. Bitcoin Core uses 200 for success, 401 for bad
    /// credentials, and 500 for a JSON-RPC-level error — the last of which
    /// still carries a useful JSON body.
    pub status: u16,
    /// The response body.
    pub body: String,
}

/// A one-shot HTTP client for a local bitcoind.
pub struct HttpClient {
    address: SocketAddr,
    timeout: Duration,
}

impl HttpClient {
    /// Creates a client for `address`, with `timeout` applied to connect,
    /// read, and write independently.
    pub fn new(address: SocketAddr, timeout: Duration) -> Self {
        Self { address, timeout }
    }

    /// POSTs a JSON body to `path` and returns the response.
    ///
    /// `path` is almost always `/`. The exception is a wallet RPC, which
    /// Bitcoin Core dispatches by URI — see
    /// [`RpcClient::call_wallet`](crate::RpcClient::call_wallet).
    pub fn post_json(
        &self,
        path: &str,
        authorization: &str,
        body: &str,
    ) -> Result<Response, HttpError> {
        let stream = TcpStream::connect_timeout(&self.address, self.timeout)
            .map_err(|source| HttpError::Connect { source })?;

        stream.set_read_timeout(Some(self.timeout)).map_err(HttpError::io)?;
        stream.set_write_timeout(Some(self.timeout)).map_err(HttpError::io)?;
        // Disable Nagle: our requests are small and always complete, so waiting
        // to coalesce them only adds latency.
        stream.set_nodelay(true).map_err(HttpError::io)?;

        self.write_request(&stream, path, authorization, body)?;
        read_response(stream)
    }

    fn write_request(
        &self,
        mut stream: &TcpStream,
        path: &str,
        authorization: &str,
        body: &str,
    ) -> Result<(), HttpError> {
        // Written as one buffer and sent in a single write, so the request
        // never arrives split across packets in a way that stalls the server.
        let request = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Authorization: {authorization}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {length}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            host = self.address,
            length = body.len(),
        );

        stream.write_all(request.as_bytes()).map_err(HttpError::io)?;
        stream.flush().map_err(HttpError::io)
    }
}

/// Reads a status line, headers, and body from `stream`.
fn read_response(stream: TcpStream) -> Result<Response, HttpError> {
    let mut reader = BufReader::new(stream);

    // --- Status line: "HTTP/1.1 200 OK" ---
    let mut status_line = String::new();
    reader.read_line(&mut status_line).map_err(HttpError::io)?;

    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| HttpError::BadStatusLine {
            line: status_line.trim().to_owned(),
        })?;

    // --- Headers, until a blank line ---
    let mut content_length = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).map_err(HttpError::io)? == 0 {
            return Err(HttpError::TruncatedHeaders);
        }

        let line = line.trim_end();
        if line.is_empty() {
            break;
        }

        // Header names are case-insensitive per RFC 9110, and Bitcoin Core's
        // capitalisation is not something we should depend on.
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse::<usize>().ok();
        }
    }

    // --- Body ---
    // Prefer Content-Length when present. Bitcoin Core always sends it, but
    // falling back to read-to-EOF is correct anyway given `Connection: close`.
    let mut body = String::new();
    match content_length {
        Some(length) => {
            let mut buffer = vec![0u8; length];
            reader.read_exact(&mut buffer).map_err(HttpError::io)?;
            body = String::from_utf8_lossy(&buffer).into_owned();
        }
        None => {
            reader.read_to_string(&mut body).map_err(HttpError::io)?;
        }
    }

    Ok(Response { status, body })
}

/// Why an HTTP request failed.
#[derive(Debug)]
pub enum HttpError {
    /// The TCP connection could not be established.
    Connect {
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// An I/O error occurred mid-exchange.
    Io(std::io::Error),
    /// The first line of the response was not a recognisable status line.
    BadStatusLine {
        /// What we received instead.
        line: String,
    },
    /// The connection closed before the headers ended.
    TruncatedHeaders,
}

impl HttpError {
    fn io(source: std::io::Error) -> Self {
        Self::Io(source)
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect { source } => {
                write!(f, "cannot connect to bitcoind: {source} (is it running?)")
            }
            Self::Io(source) => write!(f, "i/o error talking to bitcoind: {source}"),
            Self::BadStatusLine { line } => write!(f, "unrecognised HTTP status line: {line:?}"),
            Self::TruncatedHeaders => write!(f, "connection closed before headers ended"),
        }
    }
}

impl std::error::Error for HttpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connect { source } | Self::Io(source) => Some(source),
            _ => None,
        }
    }
}

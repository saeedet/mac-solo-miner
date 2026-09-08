//! The JSON-RPC client itself.
//!
//! Bitcoin Core speaks JSON-RPC 1.0 over HTTP. A request names a method and
//! carries positional parameters:
//!
//! ```json
//! {"jsonrpc": "1.0", "id": "7", "method": "getblocktemplate", "params": [...]}
//! ```
//!
//! and the response carries exactly one of `result` or `error`:
//!
//! ```json
//! {"result": {...}, "error": null, "id": "7"}
//! {"result": null, "error": {"code": -8, "message": "..."}, "id": "7"}
//! ```
//!
//! One wrinkle worth knowing: when the call fails at the RPC level, Bitcoin
//! Core replies with HTTP **500** and a perfectly good JSON body describing
//! what went wrong. Treating a non-200 status as a transport failure would
//! throw away the only useful diagnostic, so the status is checked *after*
//! trying to parse the body.

use crate::auth::{AuthError, Credentials};
use crate::http::{HttpClient, HttpError};
use crate::network::Network;

use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// How long to wait on any single RPC call.
///
/// Generous, because `getblocktemplate` on a busy mainnet node has to assemble
/// a full block, and `submitblock` has to validate one.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// A JSON-RPC client for a local Bitcoin Core node.
pub struct RpcClient {
    http: HttpClient,
    /// Behind a lock because the cookie is re-read when bitcoind rotates it —
    /// see [`RpcClient::call`].
    credentials: RwLock<Credentials>,
    /// Where to re-read the cookie from.
    cookie_path: PathBuf,
    /// JSON-RPC request ids. Only needs to be unique per in-flight request; we
    /// make it monotonic so it is also useful when reading a packet capture.
    next_id: AtomicU64,
}

impl RpcClient {
    /// Connects to the node for `network` using the cookie in `datadir`.
    ///
    /// Reads the cookie immediately, so a misconfigured datadir or a node that
    /// is not running fails here rather than on the first real call.
    pub fn from_datadir(datadir: &Path, network: Network) -> Result<Self, RpcError> {
        let credentials = Credentials::from_cookie_file(&network.cookie_path(datadir))?;
        let address = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            network.default_rpc_port(),
        );

        Ok(Self {
            http: HttpClient::new(address, DEFAULT_TIMEOUT),
            credentials: RwLock::new(credentials),
            cookie_path: network.cookie_path(datadir),
            next_id: AtomicU64::new(1),
        })
    }

    /// Re-reads the cookie file.
    ///
    /// bitcoind generates a fresh cookie on every startup, so credentials read
    /// once at construction go stale the moment the node is restarted. Without
    /// this, a restart turns the pool into a zombie: alive, connected, and
    /// permanently unauthorised.
    fn reload_credentials(&self) -> Result<(), RpcError> {
        let fresh = Credentials::from_cookie_file(&self.cookie_path)?;
        *self
            .credentials
            .write()
            .expect("credentials lock poisoned") = fresh;
        Ok(())
    }

    /// Calls `method` with positional `params`, deserialising the result.
    ///
    /// A 401 triggers one cookie reload and one retry, because the overwhelmingly
    /// likely cause is that bitcoind restarted and rotated the cookie. Only a
    /// second consecutive 401 is reported as an error.
    pub fn call<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T, RpcError> {
        self.call_at("/", method, params)
    }

    /// Calls a **wallet** RPC, addressed to a named wallet.
    ///
    /// # Why the path matters
    ///
    /// Bitcoin Core dispatches wallet RPCs by URI, not by argument. With
    /// exactly one wallet loaded it will guess, and a request to `/` works —
    /// which is how this is easy to get wrong, because it works right up until
    /// the day a second wallet is loaded and then fails with:
    ///
    /// ```text
    /// Multiple wallets are loaded. Please select which wallet to use by
    /// requesting the RPC through the /wallet/<walletname> URI path. (code -19)
    /// ```
    ///
    /// Naming the wallet is also the safer behaviour on its own terms: a miner
    /// that let the node guess could be handed a payout address from a wallet
    /// the user did not mean to mine into.
    pub fn call_wallet<T: DeserializeOwned>(
        &self,
        wallet: &str,
        method: &str,
        params: Value,
    ) -> Result<T, RpcError> {
        // Wallet names are user-chosen and could contain characters that mean
        // something in a URI. Only the small set this project uses is allowed
        // through, rather than half-escaping something that then goes into a
        // request line.
        if !wallet
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        {
            return Err(RpcError::BadWalletName(wallet.to_owned()));
        }

        self.call_at(&format!("/wallet/{wallet}"), method, params)
    }

    /// The shared body of [`Self::call`] and [`Self::call_wallet`].
    fn call_at<T: DeserializeOwned>(
        &self,
        path: &str,
        method: &str,
        params: Value,
    ) -> Result<T, RpcError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);

        let request = json!({
            "jsonrpc": "1.0",
            "id": id.to_string(),
            "method": method,
            "params": params,
        })
        .to_string();

        let mut response = self.post(path, &request)?;

        if response.status == 401 {
            // Reloading can itself fail — the node may be gone entirely, in
            // which case the cookie file is stale or absent. Report that rather
            // than the 401, since it is the more useful diagnosis.
            self.reload_credentials()?;
            response = self.post(path, &request)?;
        }

        // A second 401 means the credentials on disk genuinely do not work.
        if response.status == 401 {
            return Err(RpcError::Unauthorized);
        }

        let parsed: Value =
            serde_json::from_str(&response.body).map_err(|source| RpcError::MalformedResponse {
                method: method.to_owned(),
                status: response.status,
                body: truncate(&response.body),
                source,
            })?;

        // An RPC-level error arrives with HTTP 500 and a populated `error`.
        if let Some(error) = parsed.get("error")
            && !error.is_null()
        {
            return Err(RpcError::Rpc {
                method: method.to_owned(),
                code: error.get("code").and_then(Value::as_i64).unwrap_or(0),
                message: error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("(no message)")
                    .to_owned(),
            });
        }

        let result = parsed
            .get("result")
            .ok_or_else(|| RpcError::MissingResult {
                method: method.to_owned(),
            })?;

        serde_json::from_value(result.clone()).map_err(|source| RpcError::UnexpectedShape {
            method: method.to_owned(),
            source,
        })
    }
}

impl RpcClient {
    /// Sends one request with the credentials currently held.
    fn post(&self, path: &str, request: &str) -> Result<crate::http::Response, RpcError> {
        let header = self
            .credentials
            .read()
            .expect("credentials lock poisoned")
            .authorization_header();

        Ok(self.http.post_json(path, &header, request)?)
    }
}

/// Trims a body for inclusion in an error message.
fn truncate(body: &str) -> String {
    const LIMIT: usize = 200;
    if body.len() <= LIMIT {
        return body.to_owned();
    }
    format!("{}… ({} bytes total)", &body[..LIMIT], body.len())
}

/// Why an RPC call failed.
#[derive(Debug)]
pub enum RpcError {
    /// The cookie could not be read.
    Auth(AuthError),
    /// The HTTP exchange failed.
    Http(HttpError),
    /// bitcoind rejected our credentials twice, with a cookie reload in
    /// between. The cookie on disk genuinely does not work — a different node,
    /// a wrong datadir, or `rpcauth` configured instead of cookie auth.
    Unauthorized,
    /// A wallet name contained characters that cannot go in a URI path.
    BadWalletName(String),
    /// bitcoind returned a JSON-RPC error.
    Rpc {
        /// The method that failed.
        method: String,
        /// Bitcoin Core's error code.
        code: i64,
        /// Bitcoin Core's message.
        message: String,
    },
    /// The response body was not valid JSON.
    MalformedResponse {
        /// The method that was called.
        method: String,
        /// The HTTP status that accompanied it.
        status: u16,
        /// The body, truncated.
        body: String,
        /// The parse failure.
        source: serde_json::Error,
    },
    /// The response was valid JSON but had no `result` field.
    MissingResult {
        /// The method that was called.
        method: String,
    },
    /// The `result` did not match the type we expected.
    UnexpectedShape {
        /// The method that was called.
        method: String,
        /// The deserialisation failure.
        source: serde_json::Error,
    },
}

impl From<AuthError> for RpcError {
    fn from(error: AuthError) -> Self {
        Self::Auth(error)
    }
}

impl From<HttpError> for RpcError {
    fn from(error: HttpError) -> Self {
        Self::Http(error)
    }
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth(source) => write!(f, "{source}"),
            Self::Http(source) => write!(f, "{source}"),
            Self::BadWalletName(name) => write!(
                f,
                "wallet name {name:?} contains characters that cannot appear in \
                 a /wallet/<name> URI path"
            ),
            Self::Unauthorized => write!(
                f,
                "bitcoind rejected our credentials even after re-reading the cookie \
                 — check the datadir is right and that the node uses cookie auth"
            ),
            Self::Rpc { method, code, message } => {
                write!(f, "{method} failed: {message} (code {code})")
            }
            Self::MalformedResponse { method, status, body, .. } => {
                write!(f, "{method} returned HTTP {status} with unparseable body: {body}")
            }
            Self::MissingResult { method } => write!(f, "{method} returned no result field"),
            Self::UnexpectedShape { method, source } => {
                write!(f, "{method} returned an unexpected shape: {source}")
            }
        }
    }
}

impl std::error::Error for RpcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Auth(source) => Some(source),
            Self::Http(source) => Some(source),
            Self::MalformedResponse { source, .. } | Self::UnexpectedShape { source, .. } => {
                Some(source)
            }
            _ => None,
        }
    }
}

//! Stratum's message framing: line-delimited JSON-RPC.
//!
//! Every message is one JSON object on one line, terminated by `\n`. There is
//! no length prefix, no handshake, and no content negotiation — a Stratum
//! session is a plain TCP stream you can read with `telnet`.
//!
//! Three shapes travel over it:
//!
//! ```json
//! {"id": 1, "method": "mining.subscribe", "params": []}
//! {"id": 1, "result": [...], "error": null}
//! {"id": null, "method": "mining.notify", "params": [...]}
//! ```
//!
//! A **request** has an `id` and a `method`. A **response** echoes the `id` and
//! carries exactly one of `result` or `error`. A **notification** is a request
//! with a null `id`, meaning no reply is expected — that is how the pool pushes
//! new work without being asked.
//!
//! # The error format is not JSON-RPC's
//!
//! Stratum errors are a three-element **array**, not an object:
//!
//! ```json
//! [21, "Job not found", null]
//! ```
//!
//! `[code, message, traceback]`. This is a quirk of the original Python
//! implementation that became the de-facto standard, and a client expecting
//! JSON-RPC's `{"code":…, "message":…}` will fail to parse real pool traffic.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A message arriving on the wire, before it is interpreted.
///
/// Both ends need this: a pool reads requests, a miner reads responses *and*
/// notifications interleaved on the same socket, and the only way to tell them
/// apart is whether a `method` field is present.
#[derive(Debug, Clone)]
pub enum Incoming {
    /// A request or notification — anything with a `method`.
    Request(Request),
    /// A reply to something we sent.
    Response(Response),
}

impl Incoming {
    /// Parses one line from the wire.
    pub fn parse(line: &str) -> Result<Self, ParseError> {
        let value: Value = serde_json::from_str(line).map_err(ParseError::Json)?;

        // A `method` field is what distinguishes a request from a response.
        // Checked before deserialising, because the two shapes overlap enough
        // that serde's untagged enums guess wrong.
        if value.get("method").is_some() {
            let request = serde_json::from_value(value).map_err(ParseError::Json)?;
            Ok(Self::Request(request))
        } else {
            let response = serde_json::from_value(value).map_err(ParseError::Json)?;
            Ok(Self::Response(response))
        }
    }
}

/// A request, or — when `id` is `None` — a notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// Correlates a response with its request. `None` means no reply is wanted.
    pub id: Option<u64>,
    /// The method name, such as `mining.notify`.
    pub method: String,
    /// Positional parameters. Stratum never uses named ones.
    #[serde(default)]
    pub params: Value,
}

impl Request {
    /// Builds a request that expects a reply.
    pub fn call(id: u64, method: impl Into<String>, params: Value) -> Self {
        Self {
            id: Some(id),
            method: method.into(),
            params,
        }
    }

    /// Builds a notification, which expects no reply.
    pub fn notification(method: impl Into<String>, params: Value) -> Self {
        Self {
            id: None,
            method: method.into(),
            params,
        }
    }

    /// Whether this is a notification.
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }
}

/// A reply to a request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// The id of the request being answered.
    pub id: Option<u64>,
    /// The result, or `Value::Null` when the call failed.
    #[serde(default)]
    pub result: Value,
    /// The error, when the call failed.
    #[serde(default)]
    pub error: Option<StratumError>,
}

impl Response {
    /// Builds a successful reply.
    pub fn ok(id: Option<u64>, result: Value) -> Self {
        Self {
            id,
            result,
            error: None,
        }
    }

    /// Builds a failure reply.
    pub fn error(id: Option<u64>, error: StratumError) -> Self {
        Self {
            id,
            result: Value::Null,
            error: Some(error),
        }
    }

    /// Whether the call succeeded.
    pub fn is_ok(&self) -> bool {
        self.error.is_none()
    }
}

/// A Stratum error: `[code, message, traceback]`.
///
/// Serialised as an array, not an object — see the module docs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StratumError(pub i64, pub String, pub Option<String>);

impl StratumError {
    /// The share referenced a job the pool no longer has. Routine, not a fault:
    /// it happens whenever a miner submits work for a block that has just been
    /// superseded.
    pub fn job_not_found() -> Self {
        Self(21, "Job not found".to_owned(), None)
    }

    /// The share did not meet the difficulty it was assigned.
    pub fn low_difficulty_share() -> Self {
        Self(23, "Low difficulty share".to_owned(), None)
    }

    /// A share for this job with these exact parameters was already submitted.
    pub fn duplicate_share() -> Self {
        Self(22, "Duplicate share".to_owned(), None)
    }

    /// The client sent `mining.submit` before `mining.authorize`.
    pub fn unauthorized() -> Self {
        Self(24, "Unauthorized worker".to_owned(), None)
    }

    /// Anything else.
    pub fn other(message: impl Into<String>) -> Self {
        Self(20, message.into(), None)
    }

    /// The numeric code.
    pub fn code(&self) -> i64 {
        self.0
    }

    /// The human-readable message.
    pub fn message(&self) -> &str {
        &self.1
    }
}

impl std::fmt::Display for StratumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (code {})", self.1, self.0)
    }
}

impl std::error::Error for StratumError {}

/// Why a line could not be parsed.
#[derive(Debug)]
pub enum ParseError {
    /// The line was not valid JSON, or not a shape we recognise.
    Json(serde_json::Error),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(source) => write!(f, "malformed Stratum message: {source}"),
        }
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(source) => Some(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_a_request() {
        let line = r#"{"id": 1, "method": "mining.subscribe", "params": ["cgminer/4.9.0"]}"#;

        let Incoming::Request(request) = Incoming::parse(line).expect("parses") else {
            panic!("expected a request");
        };
        assert_eq!(request.id, Some(1));
        assert_eq!(request.method, "mining.subscribe");
        assert!(!request.is_notification());
    }

    /// A null id marks a notification, which is how work is pushed.
    #[test]
    fn parses_a_notification() {
        let line = r#"{"id": null, "method": "mining.notify", "params": []}"#;

        let Incoming::Request(request) = Incoming::parse(line).expect("parses") else {
            panic!("expected a request");
        };
        assert!(request.is_notification());
    }

    #[test]
    fn parses_a_response() {
        let line = r#"{"id": 2, "result": true, "error": null}"#;

        let Incoming::Response(response) = Incoming::parse(line).expect("parses") else {
            panic!("expected a response");
        };
        assert!(response.is_ok());
        assert_eq!(response.result, json!(true));
    }

    /// The array-shaped error is the part a JSON-RPC client gets wrong.
    #[test]
    fn parses_the_array_shaped_error() {
        let line = r#"{"id": 4, "result": null, "error": [21, "Job not found", null]}"#;

        let Incoming::Response(response) = Incoming::parse(line).expect("parses") else {
            panic!("expected a response");
        };

        let error = response.error.expect("an error");
        assert_eq!(error.code(), 21);
        assert_eq!(error.message(), "Job not found");
    }

    /// Errors must serialise back to an array, or real miners will not read them.
    #[test]
    fn errors_serialise_as_arrays() {
        let response = Response::error(Some(4), StratumError::low_difficulty_share());
        let encoded = serde_json::to_string(&response).expect("serialises");

        assert!(encoded.contains(r#""error":[23,"Low difficulty share",null]"#), "got {encoded}");
    }

    #[test]
    fn notifications_omit_no_fields_miners_expect() {
        let request = Request::notification("mining.set_difficulty", json!([1.0]));
        let encoded = serde_json::to_string(&request).expect("serialises");

        assert!(encoded.contains(r#""id":null"#), "got {encoded}");
        assert!(encoded.contains(r#""method":"mining.set_difficulty""#));
    }
}

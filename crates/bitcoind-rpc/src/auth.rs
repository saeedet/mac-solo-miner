//! Reading bitcoind's RPC cookie, and the HTTP Basic header built from it.
//!
//! Bitcoin Core supports two ways to authenticate an RPC client: a username and
//! password in the config file, or a **cookie**. We use the cookie, and the
//! reason is worth stating: on startup bitcoind writes a freshly generated
//! random secret to `<datadir>/<network>/.cookie` with mode 0600, and replaces
//! it on every restart.
//!
//! That means no password is ever written into a config file, committed to git,
//! or passed on a command line where it would show up in `ps` output. The
//! filesystem permissions are the whole of the access control, which is exactly
//! right for a service that only ever listens on loopback.
//!
//! The file's contents are `__cookie__:<random>` — already in the
//! `user:password` shape that HTTP Basic authentication wants.

use std::fmt;
use std::path::{Path, PathBuf};

/// A `user:password` pair for HTTP Basic authentication.
pub struct Credentials(String);

impl Credentials {
    /// Reads the cookie file bitcoind wrote at startup.
    pub fn from_cookie_file(path: &Path) -> Result<Self, AuthError> {
        let contents = std::fs::read_to_string(path).map_err(|source| AuthError::Unreadable {
            path: path.to_path_buf(),
            source,
        })?;

        // The file has no trailing newline, but trim anyway rather than send a
        // stray byte in an auth header and get an opaque 401 back.
        let trimmed = contents.trim();

        if !trimmed.contains(':') {
            return Err(AuthError::Malformed {
                path: path.to_path_buf(),
            });
        }

        Ok(Self(trimmed.to_owned()))
    }

    /// The value for an `Authorization:` header.
    pub fn authorization_header(&self) -> String {
        format!("Basic {}", base64_encode(self.0.as_bytes()))
    }
}

/// Deliberately opaque: the cookie is a secret, and secrets that implement a
/// revealing `Debug` end up in log files.
impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credentials(<redacted>)")
    }
}

/// Standard base64 (RFC 4648 §4), encode only.
///
/// Twenty lines, used once per request, so a dependency would be more code than
/// the implementation. Each 3 input bytes become 4 output characters of 6 bits
/// each; a short final chunk is zero-filled and marked with `=`.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);

    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[(triple >> 18) as usize & 0x3F] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 0x3F] as char);
        out.push(match chunk.len() {
            1 => '=',
            _ => ALPHABET[(triple >> 6) as usize & 0x3F] as char,
        });
        out.push(match chunk.len() {
            3 => ALPHABET[triple as usize & 0x3F] as char,
            _ => '=',
        });
    }

    out
}

/// Why authentication could not be set up.
#[derive(Debug)]
pub enum AuthError {
    /// The cookie file could not be read. Usually means bitcoind is not running,
    /// or is running against a different datadir than we expect.
    Unreadable {
        /// Where we looked.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The file existed but did not contain a `user:password` pair.
    Malformed {
        /// Where we looked.
        path: PathBuf,
    },
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { path, source } => write!(
                f,
                "cannot read the RPC cookie at {}: {source} \
                 (is bitcoind running against this datadir?)",
                path.display()
            ),
            Self::Malformed { path } => {
                write!(f, "the cookie at {} is not user:password", path.display())
            }
        }
    }
}

impl std::error::Error for AuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unreadable { source, .. } => Some(source),
            Self::Malformed { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RFC 4648 §10 test vectors, which cover all three padding cases.
    #[test]
    fn base64_matches_rfc4648() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    /// A realistic cookie, in the shape bitcoind writes it.
    #[test]
    fn cookie_becomes_a_basic_header() {
        let credentials = Credentials("__cookie__:secret".to_owned());
        assert_eq!(
            credentials.authorization_header(),
            "Basic X19jb29raWVfXzpzZWNyZXQ="
        );
    }

    /// The secret must not leak through `Debug`.
    #[test]
    fn debug_redacts_the_secret() {
        let credentials = Credentials("__cookie__:hunter2".to_owned());
        let rendered = format!("{credentials:?}");
        assert!(!rendered.contains("hunter2"), "got {rendered}");
    }
}

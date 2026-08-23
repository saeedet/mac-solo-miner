//! Hashes accumulated across every session, ever.
//!
//! # Why this exists
//!
//! Solo mining gives no feedback. There are no partial shares to accumulate, no
//! progress bar, no sense in which you are "closer" than when you started —
//! every hash is an independent trial and the last four billion tell you
//! nothing about the next one.
//!
//! What *is* real is how much work you have done, and that is worth keeping.
//! Mining is memoryless, so stopping and restarting costs nothing: an hour
//! today and an hour next week are worth exactly as much as two hours now. A
//! running total is the honest way to see that, and it is the only number that
//! grows.
//!
//! The other number worth keeping is the best hash ever seen. It is worth
//! nothing in consensus terms — a near miss is a miss — but it is the only
//! thing that resembles feedback, and watching it creep from the low thirties
//! into the forties over a few sessions is the closest solo mining comes to
//! progress.
//!
//! # On the file format
//!
//! Plain JSON, written atomically via a temporary file and a rename, so a crash
//! mid-write leaves the previous totals intact rather than a truncated file.
//! Losing this costs nothing but a number, but it is a number that takes months
//! to rebuild.

use std::path::{Path, PathBuf};

use btc_primitives::Sha256dHash;
use serde::{Deserialize, Serialize};

/// Totals carried across sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lifetime {
    /// Every hash this miner has ever computed.
    pub total_hashes: u64,
    /// The lowest hash ever seen, in display form.
    pub best_hash: String,
    /// Its leading zero bits — the headline "how close" figure.
    pub best_zero_bits: u32,
    /// How many times the miner has been started.
    pub sessions: u64,
    /// Unix time of the first ever run.
    pub first_run: u64,
    /// Unix time of the most recent run.
    pub last_run: u64,

    /// Where this came from. Not serialised.
    #[serde(skip)]
    path: PathBuf,
}

impl Lifetime {
    /// Loads the totals, or starts fresh if there are none.
    ///
    /// A missing or unreadable file is not an error — the numbers are a
    /// curiosity, and refusing to mine because they could not be read would be
    /// the wrong trade.
    pub fn load(path: &Path) -> Self {
        let mut lifetime = std::fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str::<Self>(&text).ok())
            .unwrap_or_else(|| Self {
                total_hashes: 0,
                best_hash: Sha256dHash::from_internal_bytes([0xFF; 32]).to_string(),
                best_zero_bits: 0,
                sessions: 0,
                first_run: now(),
                last_run: now(),
                path: PathBuf::new(),
            });

        lifetime.path = path.to_owned();
        lifetime.sessions += 1;
        lifetime.last_run = now();
        lifetime
    }

    /// Folds one session's figures into the totals.
    ///
    /// `session_hashes` is the count for the whole session so far, not a delta;
    /// the caller tracks what has already been folded in.
    pub fn record(&mut self, new_hashes: u64, best: Sha256dHash, best_zero_bits: u32) {
        self.total_hashes = self.total_hashes.saturating_add(new_hashes);
        self.last_run = now();

        if best_zero_bits > self.best_zero_bits {
            self.best_zero_bits = best_zero_bits;
            self.best_hash = best.to_string();
        }
    }

    /// Writes the totals out, replacing the previous file atomically.
    pub fn save(&self) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let temporary = self.path.with_extension("tmp");
        std::fs::write(&temporary, serde_json::to_string_pretty(self)?)?;

        // Rename is atomic on the same filesystem, so a reader either sees the
        // old file or the new one, never a half-written one.
        std::fs::rename(&temporary, &self.path)
    }

    /// The chance that this much work would have found a block, at `difficulty`.
    ///
    /// Returns the denominator of "about 1 in N". Mining is a Bernoulli trial
    /// per hash with probability `1 / (difficulty * 2^32)`, so the expected
    /// number of blocks found is simply hashes times that — no accumulation, no
    /// memory, which is exactly why the total is the only thing worth keeping.
    pub fn odds_denominator(&self, difficulty: f64) -> f64 {
        let expected = self.total_hashes as f64 / (difficulty * 4_294_967_296.0);
        if expected <= 0.0 { f64::INFINITY } else { 1.0 / expected }
    }
}

/// Seconds since the Unix epoch.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Where the totals live by default.
pub fn default_path() -> PathBuf {
    std::env::var("HOME")
        .map(|home| PathBuf::from(home).join(".solo-mac-miner").join("lifetime.json"))
        .unwrap_or_else(|_| PathBuf::from("lifetime.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("lifetime-test-{name}.json"))
    }

    #[test]
    fn starts_from_nothing_when_absent() {
        let path = temp_path("absent");
        let _ = std::fs::remove_file(&path);

        let lifetime = Lifetime::load(&path);
        assert_eq!(lifetime.total_hashes, 0);
        assert_eq!(lifetime.sessions, 1, "loading counts as starting a session");
    }

    #[test]
    fn totals_survive_a_round_trip() {
        let path = temp_path("roundtrip");
        let _ = std::fs::remove_file(&path);

        let mut first = Lifetime::load(&path);
        first.record(1_000_000, Sha256dHash::hash(b"a"), 33);
        first.save().expect("saves");

        let second = Lifetime::load(&path);
        assert_eq!(second.total_hashes, 1_000_000);
        assert_eq!(second.best_zero_bits, 33);
        assert_eq!(second.sessions, 2, "second load is a second session");

        let _ = std::fs::remove_file(&path);
    }

    /// The best hash must only ever improve, including across restarts.
    #[test]
    fn best_never_regresses() {
        let path = temp_path("best");
        let _ = std::fs::remove_file(&path);

        let mut lifetime = Lifetime::load(&path);
        lifetime.record(10, Sha256dHash::hash(b"good"), 40);
        let good = lifetime.best_hash.clone();

        lifetime.record(10, Sha256dHash::hash(b"worse"), 12);
        assert_eq!(lifetime.best_zero_bits, 40, "a worse hash must not overwrite");
        assert_eq!(lifetime.best_hash, good);

        let _ = std::fs::remove_file(&path);
    }

    /// A corrupt file must not stop the miner; the totals are a curiosity.
    #[test]
    fn corrupt_file_starts_fresh_rather_than_failing() {
        let path = temp_path("corrupt");
        std::fs::write(&path, "{ this is not json").expect("writes");

        let lifetime = Lifetime::load(&path);
        assert_eq!(lifetime.total_hashes, 0);

        let _ = std::fs::remove_file(&path);
    }

    /// The odds are linear in work done — the whole point of tracking a total.
    #[test]
    fn odds_scale_linearly_with_work() {
        let path = temp_path("odds");
        let _ = std::fs::remove_file(&path);

        let mut lifetime = Lifetime::load(&path);
        lifetime.record(1_000_000_000_000, Sha256dHash::hash(b"x"), 30);

        let difficulty = 127.5e12;
        let one_in = lifetime.odds_denominator(difficulty);

        // Doubling the work must halve the denominator, exactly.
        lifetime.record(1_000_000_000_000, Sha256dHash::hash(b"x"), 30);
        let doubled = lifetime.odds_denominator(difficulty);

        assert!((one_in / doubled - 2.0).abs() < 1e-9);

        let _ = std::fs::remove_file(&path);
    }
}

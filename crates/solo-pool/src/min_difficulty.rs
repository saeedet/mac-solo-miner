//! Mining the minimum-difficulty window on testnet.
//!
//! # The rule
//!
//! testnet3 and testnet4 carry a rule mainnet does not (BIP 94, and its
//! predecessor): if a block's timestamp is more than **two block intervals**
//! after its parent's — 20 minutes, given the 10-minute target — then that
//! block may be mined at the minimum difficulty of 1, whatever the chain's
//! real difficulty is.
//!
//! It exists so a test network cannot become unminable when hashpower leaves.
//! Without it, difficulty ratchets up during a burst of mining and then the
//! chain stalls forever when that miner goes away.
//!
//! # How it gets exploited, and why we must too
//!
//! Consensus also allows a block's timestamp to be up to **two hours ahead** of
//! the present. Put the two rules together and a miner can stamp each block
//! 20m01s after its parent's *already-future* timestamp — qualifying for
//! minimum difficulty immediately instead of waiting 20 real minutes. Around
//! six blocks can be mined back to back that way, until the two-hour allowance
//! is exhausted; after that the chain advances one block per 20 real minutes as
//! the clock catches up.
//!
//! Observed on testnet4 at height ~149,549: every block minimum difficulty,
//! every timestamp exactly 1201s after its parent, and seven consecutive blocks
//! arriving in the same second.
//!
//! The consequence is that `getblocktemplate` is no use on its own. It reports
//! the difficulty for the timestamp *it* would pick — roughly now — and with
//! the parent pinned two hours ahead that is the full chain difficulty. To
//! reach minimum difficulty a miner has to choose the timestamp deliberately.
//!
//! # What this module computes
//!
//! Given the parent's timestamp, the one timestamp that qualifies, and the
//! moment it becomes legal to submit. Everything here is pure arithmetic on
//! consensus constants; the awkward part is only that it is not obvious.
//!
//! **None of this applies to mainnet**, which has no minimum-difficulty rule.
//! There, `getblocktemplate` means exactly what it says.

/// Minimum difficulty in compact form — the proof-of-work limit for testnet,
/// which is the same value mainnet's difficulty 1 uses.
pub const MIN_DIFFICULTY_BITS: u32 = 0x1d00_ffff;

/// How far past its parent a block's timestamp must be to qualify: two block
/// intervals of ten minutes each.
const MIN_DIFFICULTY_GAP: i64 = 20 * 60;

/// How far ahead of the present a block's timestamp may be.
///
/// `MAX_FUTURE_BLOCK_TIME` in Bitcoin Core. A block beyond it is rejected as
/// `time-too-new` — and, importantly, rejected *temporarily*: nodes will accept
/// it later, once their clocks catch up.
const MAX_FUTURE_BLOCK_TIME: i64 = 2 * 60 * 60;

/// A plan for mining one minimum-difficulty block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    /// The timestamp our block must carry.
    ///
    /// The *smallest* qualifying value, deliberately: every second added here
    /// is a second longer before the block may be submitted.
    pub ntime: u32,
    /// Unix time at which a block carrying [`Self::ntime`] stops being
    /// "too far in the future" and can be submitted.
    pub legal_at: i64,
}

impl Window {
    /// How long until this window opens. Zero or negative means it is open.
    pub fn seconds_until_open(&self, now: i64) -> i64 {
        self.legal_at - now
    }

    /// Whether a block for this window can be submitted now.
    pub fn is_open(&self, now: i64) -> bool {
        now >= self.legal_at
    }
}

/// Works out the minimum-difficulty window that follows `parent_time`.
pub fn plan(parent_time: u32) -> Window {
    // Strictly greater than parent + gap, so one second past it.
    let ntime = i64::from(parent_time) + MIN_DIFFICULTY_GAP + 1;

    Window {
        ntime: ntime as u32,
        legal_at: ntime - MAX_FUTURE_BLOCK_TIME,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real numbers taken from testnet4 at height 149,550.
    ///
    /// The parent's timestamp was 7,142 seconds ahead of the wall clock, which
    /// is what makes this rule impossible to use without planning: the naive
    /// template came back at difficulty 1,661,387,930.
    #[test]
    fn reproduces_the_observed_testnet4_situation() {
        let now = 1_787_440_940;
        let parent_time = 1_787_448_082;

        let window = plan(parent_time);

        assert_eq!(window.ntime, 1_787_449_283, "one second past parent + 20m");
        assert!(!window.is_open(now), "cannot submit yet");
        assert_eq!(
            window.seconds_until_open(now),
            1_143,
            "about 19 minutes of real time before the clock catches up"
        );
    }

    /// The chosen timestamp must be the smallest that qualifies. A larger one
    /// is equally valid to consensus but opens the window later, which loses
    /// the race to anyone who picked the minimum.
    #[test]
    fn picks_the_earliest_qualifying_timestamp() {
        let window = plan(1_000_000);

        assert_eq!(window.ntime, 1_000_000 + 1201);
        assert!(
            i64::from(window.ntime) > 1_000_000 + MIN_DIFFICULTY_GAP,
            "must be strictly past the gap, or the rule does not apply"
        );
        assert_eq!(
            i64::from(window.ntime) - 1,
            1_000_000 + MIN_DIFFICULTY_GAP,
            "and exactly one second past it, not more"
        );
    }

    /// A parent already in the past means the window is open immediately —
    /// the ordinary case on a chain nobody is time-warping.
    #[test]
    fn open_immediately_when_the_parent_is_old() {
        let now = 2_000_000_000;
        let window = plan((now - 3600) as u32);

        assert!(window.is_open(now));
        assert!(window.seconds_until_open(now) < 0);
    }

    /// The window opens exactly two hours before the timestamp it carries.
    #[test]
    fn opens_two_hours_before_its_own_timestamp() {
        let window = plan(1_500_000_000);
        assert_eq!(i64::from(window.ntime) - window.legal_at, MAX_FUTURE_BLOCK_TIME);
    }

    /// Boundary: at exactly `legal_at` the block is submittable.
    #[test]
    fn boundary_is_inclusive() {
        let window = plan(1_500_000_000);
        assert!(!window.is_open(window.legal_at - 1));
        assert!(window.is_open(window.legal_at));
    }
}

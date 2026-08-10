//! Outbound rate limiting for [`DigLink`], keyed by raw `u8` opcode.
//!
//! Chia's own `RateLimiter` is keyed by `ProtocolMessageTypes`, an enum that cannot represent a
//! DIG opcode — which is the same closed-namespace problem that forced the vendored fork in the
//! first place. So the link carries its own limiter keyed by `u8`.
//!
//! It does **not** carry its own limit *table*: the numbers are lifted from Chia's
//! `V2_RATE_LIMITS` at construction by re-keying each entry to its wire byte. Copying the tables
//! would have created a second set of numbers to drift; deriving them means a Chia opcode is
//! rate-limited exactly as a stock peer would rate-limit it, forever.
//!
//! ## Lockstep pin (do not relax)
//!
//! Deriving buys correctness at the price of one coupling: `V2_RATE_LIMITS` comes from
//! `chia-sdk-client` and is keyed by `chia_protocol::ProtocolMessageTypes`, so the two crates
//! MUST resolve to a single version of that enum. If they ever diverge, `rekey` would key the
//! table by the *other* crate's discriminants and every Chia opcode would silently fall to
//! `default_settings` — a loosening, with no compile error. Bump `chia-protocol` and
//! `chia-sdk-client` together, and never pin them independently.
//!
//! [`DigLink`]: crate::DigLink

use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

use chia_sdk_client::{RateLimit, RateLimits, V2_RATE_LIMITS};
use chia_traits::Streamable;

use crate::DigMessage;

/// Chia's `V2_RATE_LIMITS`, re-keyed from `ProtocolMessageTypes` to the wire byte.
///
/// DIG opcodes are absent by construction and therefore fall to `default_settings`, which is
/// what Chia itself applies to any message it has no specific entry for.
#[derive(Debug, Clone)]
pub struct OpcodeRateLimits {
    default_settings: RateLimit,
    non_tx_frequency: f64,
    non_tx_max_total_size: f64,
    tx: HashMap<u8, RateLimit>,
    other: HashMap<u8, RateLimit>,
}

impl OpcodeRateLimits {
    /// Re-key a Chia limit table onto raw opcodes.
    fn from_chia(limits: &RateLimits) -> Self {
        // `ProtocolMessageTypes` is a streamable single-byte enum, so its encoding IS its wire
        // opcode — the same identity `DigMessage` relies on.
        let rekey = |map: &HashMap<chia_protocol::ProtocolMessageTypes, RateLimit>| {
            map.iter()
                .filter_map(|(msg_type, limit)| Some((*msg_type.to_bytes().ok()?.first()?, *limit)))
                .collect()
        };

        Self {
            default_settings: limits.default_settings,
            non_tx_frequency: limits.non_tx_frequency,
            non_tx_max_total_size: limits.non_tx_max_total_size,
            tx: rekey(&limits.tx),
            other: rekey(&limits.other),
        }
    }
}

impl Default for OpcodeRateLimits {
    fn default() -> Self {
        Self::from_chia(&V2_RATE_LIMITS)
    }
}

/// The verdict on one outbound message.
///
/// Refusal is split in two because the two halves demand opposite caller behaviour: one is
/// worth waiting out, the other is a permanent error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// May be sent now; its cost has been charged to the current window.
    Admitted,
    /// Refused for now, but a later window could admit it — the budget it exhausted resets.
    Deferred,
    /// Refused in every window: the message exceeds a per-message or whole-window bound, so
    /// waiting can never help.
    Unsendable,
}

/// A sliding-window outbound limiter over [`OpcodeRateLimits`].
///
/// Mirrors Chia's algorithm: per-period per-opcode count and cumulative size, plus an aggregate
/// budget for everything that is not a transaction message.
#[derive(Debug, Clone)]
pub struct OpcodeRateLimiter {
    reset_seconds: u64,
    period: u64,
    limit_factor: f64,
    counts: HashMap<u8, f64>,
    cumulative_sizes: HashMap<u8, f64>,
    non_tx_count: f64,
    non_tx_size: f64,
    limits: OpcodeRateLimits,
}

impl OpcodeRateLimiter {
    /// A limiter over `limits`, resetting its window every `reset_seconds`.
    ///
    /// `limit_factor` scales every budget, so a peer can be given a fraction of the nominal
    /// allowance (Chia's clients default to `0.6`).
    #[must_use]
    pub fn new(reset_seconds: u64, limit_factor: f64, limits: OpcodeRateLimits) -> Self {
        Self {
            reset_seconds,
            period: now_seconds() / reset_seconds,
            limit_factor,
            counts: HashMap::new(),
            cumulative_sizes: HashMap::new(),
            non_tx_count: 0.0,
            non_tx_size: 0.0,
            limits,
        }
    }

    /// Whether `message` may be sent now, charging it against the budget when it may.
    ///
    /// A refused message is NOT charged, so a caller that backs off and retries is not
    /// permanently penalised for having asked early.
    ///
    /// Prefer [`Self::admit`] where the caller intends to retry: `true`/`false` cannot say
    /// whether waiting could ever help.
    pub fn allow(&mut self, message: &DigMessage) -> bool {
        self.admit(message) == Admission::Admitted
    }

    /// Whether `message` may be sent now — and, when it may not, whether waiting could help.
    ///
    /// The distinction is what keeps a caller from spinning forever: a *frequency* or
    /// *cumulative* budget clears on the next window roll, but a message larger than the
    /// per-message cap (or than a whole window's budget) is refused identically in every window
    /// that will ever exist. Only [`Admission::Deferred`] is worth retrying.
    pub fn admit(&mut self, message: &DigMessage) -> Admission {
        self.roll_window();

        let size = f64::from(u32::try_from(message.data.len()).unwrap_or(u32::MAX));
        let opcode = message.msg_type;

        let mut limit = self.limits.default_settings;
        let mut counts_against_non_tx = false;
        if let Some(tx_limit) = self.limits.tx.get(&opcode) {
            limit = *tx_limit;
        } else if let Some(other_limit) = self.limits.other.get(&opcode) {
            limit = *other_limit;
            counts_against_non_tx = true;
        }

        let max_total = limit
            .max_total_size
            .unwrap_or(limit.frequency * limit.max_size);

        // Measured against an EMPTY window, so it isolates the budgets a window roll cannot
        // clear. A message failing here is unsendable on this link, permanently.
        let fits_an_empty_window = size <= limit.max_size
            && size <= max_total * self.limit_factor
            && 1.0 <= limit.frequency * self.limit_factor
            && (!counts_against_non_tx
                || (1.0 <= self.limits.non_tx_frequency * self.limit_factor
                    && size <= self.limits.non_tx_max_total_size * self.limit_factor));
        if !fits_an_empty_window {
            return Admission::Unsendable;
        }

        let new_count = self.counts.get(&opcode).unwrap_or(&0.0) + 1.0;
        let new_cumulative = self.cumulative_sizes.get(&opcode).unwrap_or(&0.0) + size;
        let (new_non_tx_count, new_non_tx_size) = if counts_against_non_tx {
            (self.non_tx_count + 1.0, self.non_tx_size + size)
        } else {
            (self.non_tx_count, self.non_tx_size)
        };

        let allowed = new_non_tx_count <= self.limits.non_tx_frequency * self.limit_factor
            && new_non_tx_size <= self.limits.non_tx_max_total_size * self.limit_factor
            && new_count <= limit.frequency * self.limit_factor
            && new_cumulative <= max_total * self.limit_factor;

        if !allowed {
            return Admission::Deferred;
        }

        self.counts.insert(opcode, new_count);
        self.cumulative_sizes.insert(opcode, new_cumulative);
        self.non_tx_count = new_non_tx_count;
        self.non_tx_size = new_non_tx_size;
        Admission::Admitted
    }

    /// Clear the accumulated budget when the wall clock crosses into a new window.
    fn roll_window(&mut self) {
        let period = now_seconds() / self.reset_seconds;
        if self.period == period {
            return;
        }
        self.period = period;
        self.counts.clear();
        self.cumulative_sizes.clear();
        self.non_tx_count = 0.0;
        self.non_tx_size = 0.0;
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::{Admission, OpcodeRateLimiter, OpcodeRateLimits};
    use crate::{Bytes, DigMessage, DIG_MESSAGE};
    use chia_protocol::ProtocolMessageTypes;
    use chia_traits::Streamable;

    fn message(opcode: u8, payload_len: usize) -> DigMessage {
        DigMessage::new(opcode, None, Bytes::new(vec![0u8; payload_len]))
    }

    /// The table is DERIVED, not copied: a Chia opcode with a specific entry upstream must have
    /// that same entry here, under its wire byte. `Handshake` is checked because it has a much
    /// tighter frequency than `default_settings`, so a re-key that silently produced an empty
    /// map would let far more through and fail this test.
    #[test]
    fn chia_opcodes_keep_their_upstream_limits() {
        let limits = OpcodeRateLimits::default();
        let handshake = *ProtocolMessageTypes::Handshake
            .to_bytes()
            .expect("encode")
            .first()
            .expect("one byte");

        let upstream = chia_sdk_client::V2_RATE_LIMITS
            .other
            .get(&ProtocolMessageTypes::Handshake)
            .expect("upstream defines a handshake limit");
        let ours = limits
            .other
            .get(&handshake)
            .expect("re-keyed table kept the handshake limit");

        assert_eq!(ours.frequency, upstream.frequency);
        assert_eq!(ours.max_size, upstream.max_size);
    }

    /// A DIG opcode has no upstream entry, so it is governed by `default_settings` — it is
    /// neither blocked outright nor unlimited. Sending one message must pass.
    #[test]
    fn dig_opcodes_fall_back_to_the_default_budget() {
        let mut limiter = OpcodeRateLimiter::new(60, 1.0, OpcodeRateLimits::default());
        assert!(limiter.allow(&message(DIG_MESSAGE, 16)));
    }

    /// The frequency budget is pinned from BOTH sides: exactly `frequency` messages pass and
    /// the next one is refused. A limiter that never refused would pass a one-sided test.
    #[test]
    fn frequency_budget_admits_up_to_the_bound_and_refuses_past_it() {
        let limits = OpcodeRateLimits::default();
        let allowance = limits.default_settings.frequency as usize;
        let mut limiter = OpcodeRateLimiter::new(60, 1.0, limits);

        for i in 0..allowance {
            assert!(
                limiter.allow(&message(DIG_MESSAGE, 1)),
                "message {i} refused below the bound"
            );
        }
        assert!(
            !limiter.allow(&message(DIG_MESSAGE, 1)),
            "one message over the bound was admitted"
        );
    }

    /// The two refusals are distinguishable, which is the whole point of [`Admission`]: one
    /// clears on the next window, the other never does.
    ///
    /// Both cases are driven on the SAME opcode and the same limiter shape, so the only thing
    /// separating them is which budget was exceeded — an implementation that collapsed them into
    /// a single "refused" verdict could not pass both halves.
    #[test]
    fn a_deferrable_refusal_is_distinguished_from_a_permanent_one() {
        let limits = OpcodeRateLimits::default();
        let allowance = limits.default_settings.frequency as usize;
        let max_size = limits.default_settings.max_size as usize;

        let mut exhausted = OpcodeRateLimiter::new(60, 1.0, limits);
        for _ in 0..allowance {
            assert_eq!(
                exhausted.admit(&message(DIG_MESSAGE, 1)),
                Admission::Admitted
            );
        }
        assert_eq!(
            exhausted.admit(&message(DIG_MESSAGE, 1)),
            Admission::Deferred,
            "an exhausted frequency budget resets on the next window, so waiting can help"
        );

        let mut fresh = OpcodeRateLimiter::new(60, 1.0, OpcodeRateLimits::default());
        assert_eq!(
            fresh.admit(&message(DIG_MESSAGE, max_size + 1)),
            Admission::Unsendable,
            "an oversized message is refused identically in every window"
        );
    }

    /// An oversized single message is refused on size alone — and the at-bound message is
    /// admitted, so the cap is pinned from both sides.
    ///
    /// Each case gets a FRESH limiter on purpose: reusing one would let the accumulated
    /// cumulative-size budget refuse the second message, which would make the test pass for a
    /// reason that has nothing to do with the per-message size cap.
    #[test]
    fn size_cap_is_pinned_from_both_sides() {
        let max_size = OpcodeRateLimits::default().default_settings.max_size as usize;

        let mut at_bound = OpcodeRateLimiter::new(60, 1.0, OpcodeRateLimits::default());
        assert!(at_bound.allow(&message(DIG_MESSAGE, max_size)));

        let mut over_bound = OpcodeRateLimiter::new(60, 1.0, OpcodeRateLimits::default());
        assert!(!over_bound.allow(&message(DIG_MESSAGE, max_size + 1)));
    }
}

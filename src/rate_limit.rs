//! Directional rate limiting for [`DigLink`], keyed by raw `u8` opcode.
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

/// Re-key any Chia limit table onto raw opcodes.
///
/// The numbers remain DERIVED — a caller chooses the *source table*, never the individual limits —
/// so the drift this type exists to prevent stays prevented. A table assembled from
/// `V2_RATE_LIMITS` (retuned, extended, or narrowed for a test) is exactly as trustworthy as the
/// default.
///
/// The module header's lockstep pin applies undiminished, and a caller-supplied table is the one
/// way to violate it from outside this crate: the keys are `chia_protocol::ProtocolMessageTypes`
/// values streamed to their wire byte, so a table keyed by a *different* `chia_protocol` version's
/// enum re-keys to shifted bytes, every Chia opcode misses its entry and falls to
/// `default_settings` — a silent loosening with no compile error. Build the table with the
/// `chia_protocol` this crate resolves; re-export it from here (`crate::RateLimits`) rather than
/// depending on `chia-sdk-client` independently.
impl From<&RateLimits> for OpcodeRateLimits {
    fn from(limits: &RateLimits) -> Self {
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
        Self::from(&*V2_RATE_LIMITS)
    }
}

/// The verdict on one message, in either [`Direction`].
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

/// Which side of the link a limiter guards — and therefore whether a REFUSED message is charged.
///
/// The two directions need opposite accounting, and the difference is the anti-flood ratchet:
///
/// - [`Direction::Inbound`] charges a refusal, because the peer already spent our bandwidth
///   delivering the frame. A peer whose frames are being rejected keeps burning the budget, so the
///   window stays exhausted and the flood cannot run for free.
/// - [`Direction::Outbound`] does not, because we chose not to send: a caller that backs off and
///   retries must not be permanently penalised for having asked early.
///
/// This is an enum rather than upstream's positional `bool` deliberately. A bare `true` in
/// `new(true, ..)` reads as nothing at the call site and can be dropped by a signature change with
/// no reviewer noticing — which is exactly how the inbound rule went missing here once already.
/// `Direction::Inbound` is checkable at a glance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Frames received from a peer; a refusal IS charged.
    Inbound,
    /// Messages we are about to send; a refusal is NOT charged.
    Outbound,
}

/// A sliding-window limiter over [`OpcodeRateLimits`], in one [`Direction`].
///
/// Mirrors Chia's algorithm: per-period per-opcode count and cumulative size, plus an aggregate
/// budget for everything that is not a transaction message.
#[derive(Debug, Clone)]
pub struct OpcodeRateLimiter {
    direction: Direction,
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
    /// A limiter over `limits` guarding `direction`, resetting its window every `reset_seconds`.
    ///
    /// `direction` selects the accounting rule for a REFUSED message — see [`Direction`]; it is
    /// the first parameter so that a call site names it before anything else.
    ///
    /// `limit_factor` scales every budget, so a peer can be given a fraction of the nominal
    /// allowance (Chia's clients default to `0.6`).
    #[must_use]
    pub fn new(
        direction: Direction,
        reset_seconds: u64,
        limit_factor: f64,
        limits: OpcodeRateLimits,
    ) -> Self {
        Self {
            direction,
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

    /// Whether `message` passes the limiter now, charging it against the budget per [`Direction`].
    ///
    /// Prefer [`Self::admit`] where the caller intends to retry: `true`/`false` cannot say
    /// whether waiting could ever help.
    pub fn allow(&mut self, message: &DigMessage) -> bool {
        self.admit(message) == Admission::Admitted
    }

    /// Whether `message` passes now — and, when it does not, whether waiting could help.
    ///
    /// The distinction is what keeps a caller from spinning forever: a *frequency* or
    /// *cumulative* budget clears on the next window roll, but a message larger than the
    /// per-message cap (or than a whole window's budget) is refused identically in every window
    /// that will ever exist. Only [`Admission::Deferred`] is worth retrying.
    ///
    /// Whether a REFUSAL is charged depends on the limiter's [`Direction`], and nothing else: the
    /// verdict itself is computed identically either way.
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

        let new_count = self.counts.get(&opcode).unwrap_or(&0.0) + 1.0;
        let new_cumulative = self.cumulative_sizes.get(&opcode).unwrap_or(&0.0) + size;
        let (new_non_tx_count, new_non_tx_size) = if counts_against_non_tx {
            (self.non_tx_count + 1.0, self.non_tx_size + size)
        } else {
            (self.non_tx_count, self.non_tx_size)
        };

        let fits_this_window = new_non_tx_count <= self.limits.non_tx_frequency * self.limit_factor
            && new_non_tx_size <= self.limits.non_tx_max_total_size * self.limit_factor
            && new_count <= limit.frequency * self.limit_factor
            && new_cumulative <= max_total * self.limit_factor;

        let verdict = match (fits_an_empty_window, fits_this_window) {
            (false, _) => Admission::Unsendable,
            (true, false) => Admission::Deferred,
            (true, true) => Admission::Admitted,
        };

        // The one place the two directions differ. An inbound frame is charged even when refused,
        // because the peer already spent our bandwidth delivering it — that is the ratchet that
        // keeps a rejected flood from being free. An outbound refusal is not charged, because we
        // chose not to send and a backing-off caller must not be penalised for asking early.
        let charge = self.direction == Direction::Inbound || verdict == Admission::Admitted;
        if charge {
            self.counts.insert(opcode, new_count);
            self.cumulative_sizes.insert(opcode, new_cumulative);
            self.non_tx_count = new_non_tx_count;
            self.non_tx_size = new_non_tx_size;
        }

        verdict
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
    use super::{Admission, Direction, OpcodeRateLimiter, OpcodeRateLimits};
    use crate::{Bytes, DigMessage, DIG_MESSAGE};
    use chia_protocol::ProtocolMessageTypes;
    use chia_sdk_client::{RateLimit, RateLimits, V2_RATE_LIMITS};
    use chia_traits::Streamable;

    fn message(opcode: u8, payload_len: usize) -> DigMessage {
        DigMessage::new(opcode, None, Bytes::new(vec![0u8; payload_len]))
    }

    /// The wire byte `Handshake` streams to — the same derivation the re-key itself performs.
    fn handshake_opcode() -> u8 {
        *ProtocolMessageTypes::Handshake
            .to_bytes()
            .expect("encode")
            .first()
            .expect("one byte")
    }

    /// `V2_RATE_LIMITS` with `Handshake` retuned to admit only two messages per window.
    ///
    /// Two is chosen because upstream's own `Handshake` frequency is 5: a limiter built from this
    /// table refuses a third message that a limiter built from the upstream table admits, so the
    /// two are distinguishable by observation rather than by inspecting private fields.
    fn handshake_capped_at_two() -> RateLimits {
        let mut limits = V2_RATE_LIMITS.clone();
        limits.other.insert(
            ProtocolMessageTypes::Handshake,
            RateLimit::new(2.0, 10.0 * 1024.0, None),
        );
        limits
    }

    /// Admit `count` handshakes of a size no cap can refuse, returning the verdict on each.
    ///
    /// The payload is deliberately tiny so the per-message and cumulative SIZE budgets can never
    /// bind: the only budget that can produce a refusal is `frequency`, which is the axis the
    /// custom table moves.
    fn admit_handshakes(limits: OpcodeRateLimits, count: usize) -> Vec<Admission> {
        let mut limiter = OpcodeRateLimiter::new(Direction::Outbound, 60, 1.0, limits);
        (0..count)
            .map(|_| limiter.admit(&message(handshake_opcode(), 16)))
            .collect()
    }

    /// The wire byte `NewPeak` streams to — a SECOND `other` opcode, distinct from `Handshake`.
    ///
    /// A second opcode is what makes the aggregate tests possible: charging can be observed on a
    /// message whose own per-opcode counters were never touched.
    fn new_peak_opcode() -> u8 {
        *ProtocolMessageTypes::NewPeak
            .to_bytes()
            .expect("encode")
            .first()
            .expect("one byte")
    }

    /// The size, in bytes, of a frame that `handshake_capped_at_two` refuses on SIZE alone.
    ///
    /// One byte over the table's own `max_size`, so the refusal is `Unsendable` — the flood shape
    /// that used to cost the peer nothing.
    const OVERSIZED_HANDSHAKE: usize = 10 * 1024 + 1;

    /// Offer `count` oversized handshakes, then one perfectly legal handshake.
    ///
    /// Every oversized frame must be refused on size, and the closing legal frame is the probe:
    /// its verdict is decided entirely by whether those refusals were charged.
    fn flood_then_probe(direction: Direction) -> Admission {
        let mut limiter = OpcodeRateLimiter::new(
            direction,
            60,
            1.0,
            OpcodeRateLimits::from(&handshake_capped_at_two()),
        );

        for i in 0..2 {
            assert_eq!(
                limiter.admit(&message(handshake_opcode(), OVERSIZED_HANDSHAKE)),
                Admission::Unsendable,
                "flood frame {i} was not refused on size -- the fixture is not exercising a refusal"
            );
        }

        limiter.admit(&message(handshake_opcode(), 16))
    }

    /// An INBOUND refusal is charged: a peer flooding frames we reject still burns the window.
    ///
    /// The peer spent our bandwidth delivering each frame, so refusing it must ratchet the budget
    /// down — otherwise a flood of frames that are all rejected on size costs the attacker nothing
    /// and the limiter never closes. Two frames over a `frequency` of 2 exhaust the count, so the
    /// closing LEGAL frame — which an empty window would admit — must now be refused.
    ///
    /// `Deferred`, not `Unsendable`: the probe fits an empty window, so the only thing that can
    /// refuse it is an exhausted budget, and that budget can only be exhausted by the charges.
    #[test]
    fn an_inbound_refusal_is_charged_against_the_window() {
        assert_eq!(
            flood_then_probe(Direction::Inbound),
            Admission::Deferred,
            "a legal inbound frame was admitted after two refused frames -- the refusals were not \
             charged, so a rejected flood is free"
        );
    }

    /// An OUTBOUND refusal is NOT charged — the documented behaviour this fix must preserve.
    ///
    /// The control for the test above, on the IDENTICAL fixture: we chose not to send, so a caller
    /// that backs off and retries must not be penalised for having asked early. That the same
    /// sequence yields opposite verdicts is what proves the direction, and not the fixture, is
    /// doing the work.
    #[test]
    fn an_outbound_refusal_is_not_charged_against_the_window() {
        assert_eq!(
            flood_then_probe(Direction::Outbound),
            Admission::Admitted,
            "a refused outbound message was charged -- a backing-off caller is now penalised"
        );
    }

    /// The inbound charge reaches the shared `non_tx` COUNT aggregate, not only the per-opcode
    /// counters.
    ///
    /// This is the axis the real-world flood runs on: oversized `Handshake` frames exhaust the
    /// aggregate and lock out every other `other` opcode for the window. The probe is therefore a
    /// DIFFERENT opcode (`NewPeak`), whose own counters were never touched — an implementation
    /// that charged only per-opcode would admit it and leave the actual hole open.
    ///
    /// `Handshake`'s own frequency is raised well clear of the flood so it cannot be the budget
    /// that binds, and `non_tx_frequency` is lowered to 2 so the aggregate is reached in two
    /// frames rather than a thousand.
    #[test]
    fn an_inbound_refusal_is_charged_against_the_non_tx_count_aggregate() {
        let probe = |direction| {
            let mut table = V2_RATE_LIMITS.clone();
            table.non_tx_frequency = 2.0;
            table.other.insert(
                ProtocolMessageTypes::Handshake,
                RateLimit::new(100.0, 10.0 * 1024.0, None),
            );
            table.other.insert(
                ProtocolMessageTypes::NewPeak,
                RateLimit::new(100.0, 10.0 * 1024.0, None),
            );

            let mut limiter =
                OpcodeRateLimiter::new(direction, 60, 1.0, OpcodeRateLimits::from(&table));
            for _ in 0..2 {
                assert_eq!(
                    limiter.admit(&message(handshake_opcode(), OVERSIZED_HANDSHAKE)),
                    Admission::Unsendable
                );
            }
            limiter.admit(&message(new_peak_opcode(), 16))
        };

        assert_eq!(
            probe(Direction::Inbound),
            Admission::Deferred,
            "a second `other` opcode was admitted after two refused frames -- the non_tx COUNT \
             aggregate was not charged, so an oversized flood cannot exhaust the shared budget"
        );
        assert_eq!(
            probe(Direction::Outbound),
            Admission::Admitted,
            "the fixture cannot distinguish the directions"
        );
    }

    /// The inbound charge reaches the shared `non_tx` SIZE aggregate too.
    ///
    /// `non_tx_max_total_size` is the budget the worked example actually drains, and it is a
    /// separate field from the count: a fix that charged only the count would pass the test above
    /// and still let a flood of large refused frames run free. The count budget is left wide open
    /// here so that only the size aggregate can produce the refusal.
    #[test]
    fn an_inbound_refusal_is_charged_against_the_non_tx_size_aggregate() {
        let probe = |direction| {
            let mut table = V2_RATE_LIMITS.clone();
            table.non_tx_frequency = 1000.0;
            // Two oversized frames (10 KiB + 1 each) exceed this; one legal probe alone does not.
            table.non_tx_max_total_size = 15.0 * 1024.0;
            table.other.insert(
                ProtocolMessageTypes::Handshake,
                RateLimit::new(100.0, 10.0 * 1024.0, None),
            );
            table.other.insert(
                ProtocolMessageTypes::NewPeak,
                RateLimit::new(100.0, 10.0 * 1024.0, None),
            );

            let mut limiter =
                OpcodeRateLimiter::new(direction, 60, 1.0, OpcodeRateLimits::from(&table));
            for _ in 0..2 {
                assert_eq!(
                    limiter.admit(&message(handshake_opcode(), OVERSIZED_HANDSHAKE)),
                    Admission::Unsendable
                );
            }
            limiter.admit(&message(new_peak_opcode(), 16))
        };

        assert_eq!(
            probe(Direction::Inbound),
            Admission::Deferred,
            "the non_tx SIZE aggregate was not charged for refused frames -- a flood of large \
             rejected frames still costs the peer nothing"
        );
        assert_eq!(
            probe(Direction::Outbound),
            Admission::Admitted,
            "the fixture cannot distinguish the directions"
        );
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

    /// EVERY upstream opcode survives the re-key with its limits intact — not just `Handshake`.
    ///
    /// The single-entry check above cannot see the two failures this module's lockstep pin exists
    /// to prevent, because both leave `Handshake` untouched while corrupting the rest of the table:
    ///
    /// - `rekey` is a `filter_map` whose `ok()?` / `first()?` DROP an entry that fails to encode,
    ///   and a dropped Chia opcode silently falls through to `default_settings` — a loosening, in
    ///   the permissive direction, with no compile error and no panic.
    /// - two `ProtocolMessageTypes` variants that streamed to the SAME byte would collide in the
    ///   `HashMap`, so one limit would silently overwrite the other.
    ///
    /// Cardinality is asserted as well as content precisely because both failures are subtractive:
    /// a per-entry loop over the re-keyed map would still pass while entries were missing from it,
    /// so the count is what makes a drop observable. Checking `tx` and `other` separately keeps a
    /// row that moved between the two tables from cancelling out in a combined total.
    #[test]
    fn every_upstream_opcode_survives_the_rekey_with_its_limits() {
        let ours = OpcodeRateLimits::default();
        let upstream = &*V2_RATE_LIMITS;

        for (label, upstream_map, our_map) in [
            ("tx", &upstream.tx, &ours.tx),
            ("other", &upstream.other, &ours.other),
        ] {
            assert_eq!(
                our_map.len(),
                upstream_map.len(),
                "{label}: re-key changed the entry count, so an opcode was dropped or collided",
            );
            assert!(
                !upstream_map.is_empty(),
                "{label}: upstream table is empty, so this test proves nothing",
            );

            for (msg_type, expected) in upstream_map.iter() {
                let opcode = *msg_type
                    .to_bytes()
                    .expect("ProtocolMessageTypes encodes")
                    .first()
                    .expect("one byte");
                let got = our_map.get(&opcode).unwrap_or_else(|| {
                    panic!("{label}: {msg_type:?} (opcode {opcode}) missing after re-key")
                });
                assert_eq!(got.frequency, expected.frequency, "{label}: {msg_type:?}");
                assert_eq!(got.max_size, expected.max_size, "{label}: {msg_type:?}");
            }
        }
    }

    /// A caller-supplied table governs the limiter — the CUSTOM row is honoured, not upstream's.
    ///
    /// The conversion is observed through behaviour rather than through the derived fields, so it
    /// stays honest about what a consumer can actually do with it: three handshakes are offered to
    /// a limiter whose table caps them at two, and the third must be refused. `Deferred` rather
    /// than merely "not admitted", because a frequency exhaustion is the refusal that a window
    /// roll clears; an `Unsendable` here would mean the size fixture, not the custom row, did the
    /// refusing.
    #[test]
    fn a_caller_supplied_table_governs_the_limiter() {
        let verdicts = admit_handshakes(OpcodeRateLimits::from(&handshake_capped_at_two()), 3);

        assert_eq!(
            verdicts,
            vec![
                Admission::Admitted,
                Admission::Admitted,
                Admission::Deferred
            ],
            "the custom frequency of 2 did not govern"
        );
    }

    /// `Default` is unchanged by the delegation: it still derives from `V2_RATE_LIMITS`.
    ///
    /// The probe is the message the custom table classifies DIFFERENTLY — the third handshake,
    /// refused under a cap of two. Both the `Default`-built and the explicitly
    /// `V2_RATE_LIMITS`-built limiter must admit it, which is a claim a `Default` accidentally
    /// rerouted to some other table could not satisfy.
    #[test]
    fn default_still_derives_from_the_upstream_table() {
        let via_default = admit_handshakes(OpcodeRateLimits::default(), 3);
        let via_upstream = admit_handshakes(OpcodeRateLimits::from(&*V2_RATE_LIMITS), 3);

        assert_eq!(
            via_default, via_upstream,
            "Default no longer agrees with the table it is documented to derive from"
        );
        assert_eq!(
            via_default[2],
            Admission::Admitted,
            "upstream admits a third handshake (frequency 5); this probe cannot distinguish tables \
             if it does not"
        );
    }

    /// A DIG opcode has no upstream entry, so it is governed by `default_settings` — it is
    /// neither blocked outright nor unlimited. Sending one message must pass.
    #[test]
    fn dig_opcodes_fall_back_to_the_default_budget() {
        let mut limiter =
            OpcodeRateLimiter::new(Direction::Outbound, 60, 1.0, OpcodeRateLimits::default());
        assert!(limiter.allow(&message(DIG_MESSAGE, 16)));
    }

    /// The frequency budget is pinned from BOTH sides: exactly `frequency` messages pass and
    /// the next one is refused. A limiter that never refused would pass a one-sided test.
    #[test]
    fn frequency_budget_admits_up_to_the_bound_and_refuses_past_it() {
        let limits = OpcodeRateLimits::default();
        let allowance = limits.default_settings.frequency as usize;
        let mut limiter = OpcodeRateLimiter::new(Direction::Outbound, 60, 1.0, limits);

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

        let mut exhausted = OpcodeRateLimiter::new(Direction::Outbound, 60, 1.0, limits);
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

        let mut fresh =
            OpcodeRateLimiter::new(Direction::Outbound, 60, 1.0, OpcodeRateLimits::default());
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

        let mut at_bound =
            OpcodeRateLimiter::new(Direction::Outbound, 60, 1.0, OpcodeRateLimits::default());
        assert!(at_bound.allow(&message(DIG_MESSAGE, max_size)));

        let mut over_bound =
            OpcodeRateLimiter::new(Direction::Outbound, 60, 1.0, OpcodeRateLimits::default());
        assert!(!over_bound.allow(&message(DIG_MESSAGE, max_size + 1)));
    }

    /// The re-keyed table is pinned to ABSOLUTE values, opcode byte by opcode byte.
    ///
    /// This is the test the module header's lockstep warning demands. `V2_RATE_LIMITS` comes from
    /// `chia-sdk-client` keyed by `chia_protocol::ProtocolMessageTypes`; `rekey` derives each
    /// opcode byte by *streaming that enum*. If the two crates ever resolve different versions of
    /// it, the derived bytes shift, every Chia opcode misses its entry and falls to
    /// `default_settings` — a large LOOSENING, with no compile error and no panic. A silently
    /// permissive rate limiter is a DoS surface.
    ///
    /// A test comparing this table against `V2_RATE_LIMITS` cannot see that: it would ask the
    /// same possibly-shifted enum for the key and agree with itself. So the expectations below
    /// are literals — the opcode byte and both limit numbers, transcribed from the upstream table
    /// and independent of any enum this crate can resolve.
    ///
    /// The chosen opcodes discriminate against the specific failure: `Handshake` (1) sits in
    /// `other` with an entry FAR tighter than `default_settings` on both axes, so a
    /// fall-to-default shows up as a wrong number rather than a missing key; `NewTransaction`
    /// (21) and `TransactionAck` (49) sit in `tx`, so a re-key that dropped one map while
    /// keeping the other still fails here.
    #[test]
    fn the_rekeyed_table_pins_upstream_limits_at_absolute_values() {
        let limits = OpcodeRateLimits::default();

        // (opcode byte, which map, frequency, max_size)
        let handshake = limits
            .other
            .get(&1)
            .expect("opcode 1 (Handshake) kept its entry");
        assert_eq!(handshake.frequency, 5.0, "Handshake frequency");
        assert_eq!(handshake.max_size, 10.0 * 1024.0, "Handshake max_size");

        let tx_ack = limits
            .tx
            .get(&49)
            .expect("opcode 49 (TransactionAck) kept its tx entry");
        assert_eq!(tx_ack.frequency, 5000.0, "TransactionAck frequency");
        assert_eq!(tx_ack.max_size, 2048.0, "TransactionAck max_size");

        let new_tx = limits
            .tx
            .get(&21)
            .expect("opcode 21 (NewTransaction) kept its tx entry");
        assert_eq!(new_tx.frequency, 5000.0, "NewTransaction frequency");
        assert_eq!(new_tx.max_size, 100.0, "NewTransaction max_size");

        // The aggregate budgets are part of the same table and equally silent if lost.
        assert_eq!(limits.non_tx_frequency, 1000.0);
        assert_eq!(limits.non_tx_max_total_size, 100.0 * 1024.0 * 1024.0);
        assert_eq!(limits.default_settings.frequency, 100.0);
        assert_eq!(limits.default_settings.max_size, 1024.0 * 1024.0);
    }

    /// A pinned entry must be TIGHTER than `default_settings`, or the test above could pass on a
    /// table that had silently collapsed to the default everywhere.
    ///
    /// This is the guard against the exact vacuity the module header warns about: it names the
    /// property ("losing an entry is a loosening") rather than restating a number, so it stays
    /// meaningful even if upstream retunes the values.
    #[test]
    fn falling_back_to_the_default_would_be_a_detectable_loosening() {
        let limits = OpcodeRateLimits::default();
        let handshake = limits
            .other
            .get(&1)
            .expect("opcode 1 (Handshake) kept its entry");

        assert!(
            handshake.frequency < limits.default_settings.frequency,
            "Handshake ({}) is not tighter than default ({}) -- the pin above can no longer              distinguish a re-keyed table from a collapsed one",
            handshake.frequency,
            limits.default_settings.frequency
        );
        assert!(
            handshake.max_size < limits.default_settings.max_size,
            "Handshake max_size is not tighter than default"
        );
    }

    /// The table must retain a REALISTIC number of entries. An emptied `other` map would still
    /// satisfy a test that only inspected keys it happens to look up, if those lookups were
    /// themselves derived from the same shifted enum.
    #[test]
    fn the_rekeyed_table_retains_the_bulk_of_the_upstream_entries() {
        let limits = OpcodeRateLimits::default();
        assert!(
            limits.other.len() >= 30,
            "other map holds only {} entries -- the re-key lost most of the table",
            limits.other.len()
        );
        assert!(
            limits.tx.len() >= 5,
            "tx map holds only {} entries -- the re-key lost most of the table",
            limits.tx.len()
        );
        // Every key must be a real wire byte; a shifted enum would produce values outside the
        // chia band, which is a direct signal of the version split.
        for opcode in limits.other.keys().chain(limits.tx.keys()) {
            assert!(
                *opcode < 200,
                "opcode {opcode} is outside the chia band -- the re-key is keying off a                  different ProtocolMessageTypes than the wire uses"
            );
        }
    }
}

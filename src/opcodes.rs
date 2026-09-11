//! The complete DIG opcode namespace — the `200..=225` band, in one place.
//!
//! DIG extends Chia's `ProtocolMessageTypes` (which stops at `RespondCostInfo = 107`) with a
//! band that starts at **200**, leaving a 100-value gap for future upstream additions. The band
//! has two halves:
//!
//! | Range | Half | Where it is defined |
//! |---|---|---|
//! | `200..=219` | **consensus** — the DIG L2 gossip opcodes | [`DigMessageType`], one variant each |
//! | `220..=` | **free** — directed / broadcast application protocols | the constants below |
//!
//! The consensus half is an enum because each opcode has a fixed body type and a gossip
//! strategy; the free half is plain constants because each opcode's body is owned by the
//! application protocol that defines it, not by this crate.
//!
//! These values are **canonical**: a second implementation must match them byte for byte, and
//! no assigned value ever moves (§5.1, additive only).

use crate::DigMessageType;

/// First opcode of the DIG band. Everything below this belongs to Chia.
pub const DIG_BAND_START: u8 = 200;

/// First opcode of the **free** half of the DIG band — application protocols, not L2 consensus.
pub const FREE_BAND_START: u8 = 220;

/// Wire opcode for a directed **dig-message** envelope (WU6, epic #796).
///
/// Carries a `dig-message` directed envelope as OPAQUE bytes in [`DigMessage::data`]. The
/// transport (dig-gossip) never seals, opens, or parses it; end-to-end sealing to the
/// recipient's DID key is `dig-message`'s job.
///
/// [`DigMessage::data`]: crate::DigMessage::data
pub const DIG_MESSAGE: u8 = 220;

/// Wire opcode for a **store-melted** broadcast (epic #1316).
///
/// Announces that a dig-store's on-chain coin has been melted, so peers stop hosting its `.dig`
/// content. A public all-peers flood: signed and mTLS-authenticated, but NOT recipient-sealed —
/// store deletion is addressed to everyone (the §5.4 public-broadcast carve-out).
pub const STORE_MELTED: u8 = 221;

/// Wire opcode for a **holdings-announce** broadcast (#1428, spec #1394).
///
/// Announces a batch of signed holdings add/remove deltas so peers learn which content a
/// provider holds; this feeds dig-dht's holder set. Public flood, same carve-out as
/// [`STORE_MELTED`].
pub const HOLDINGS_ANNOUNCE: u8 = 222;

/// Wire opcode for a **profile-root announce** broadcast (epic #3008).
///
/// Body is exactly 64 bytes: `store_id ‖ root`, two 32-byte hashes with no framing, announcing
/// the sender's current profile-SMT root for that store. A public all-peers flood, same §5.4
/// carve-out as [`STORE_MELTED`].
///
/// **Deliberately unsigned.** The authority for a profile root is the on-chain root, not the
/// announcing peer, so the receiver compares any announced root against chain before trusting
/// it. A forged announce therefore costs an attacker one wasted [`PROFILE_BODY_REQUEST`] that
/// then fails that compare — signing would buy no additional guarantee while adding a signature
/// verification to every message of the highest-volume broadcast in the band.
pub const PROFILE_ROOT_ANNOUNCE: u8 = 223;

/// Wire opcode for a directed **profile-body request** (epic #3008).
///
/// Body is exactly 64 bytes: `store_id ‖ root`, asking one peer for the profile body behind a
/// root learned from a [`PROFILE_ROOT_ANNOUNCE`]. Answered with [`PROFILE_BODY`].
pub const PROFILE_BODY_REQUEST: u8 = 224;

/// Wire opcode for a directed **profile-body** response (epic #3008).
///
/// Body is `store_id ‖ root ‖ len:u32be ‖ body` — the two 32-byte hashes the request named,
/// then a big-endian length prefix and that many bytes of profile body. The receiver rehashes
/// the body and compares against `root`, which is why the announce that started the exchange
/// needs no signature.
pub const PROFILE_BODY: u8 = 225;

/// Wire opcode for a **distributor-announce** broadcast (DIG-Network/dig_ecosystem#3252).
///
/// A public all-peers flood carrying untrusted reward-distributor discovery hints: a
/// `store_id` plus the launcher ids of distributors the sender knows of for that store. Same
/// §5.4 public-broadcast carve-out as [`STORE_MELTED`] and [`HOLDINGS_ANNOUNCE`].
///
/// Body layout (encoded downstream in dig-gossip, not this crate): `store_id(32) ‖
/// launcher_id_count(u16 BE) ‖ launcher_ids(32 each, ≤ 32)`. An empty list is a positive
/// statement that the sender knows of no distributor for that store, distinct from not
/// announcing at all.
///
/// **Deliberately unsigned**, for the same reason [`PROFILE_ROOT_ANNOUNCE`] is: the authority
/// for a distributor is the on-chain coin, not the announcing peer, so a receiver re-derives
/// every property from chain before the launcher id becomes a candidate. Unlike
/// [`HOLDINGS_ANNOUNCE`], the frame carries no addresses, so there is no address-rewriting or
/// DHT-poisoning threat for a signature to close — a forged announce costs a receiver one
/// wasted chain lookup that then fails that compare.
///
/// A received announce is a **hint only**: it must not admit an entry, rank a candidate, or be
/// a claim's authority, and it is a full-replacement snapshot per store with no per-id remove
/// operation, so "evicted" is unencodable and therefore unreconstructable
/// (dig_ecosystem §12.5 clause 7).
pub const DISTRIBUTOR_ANNOUNCE: u8 = 226;

/// Every opcode DIG has assigned, ascending — the 20 consensus opcodes plus the 7 free-band ones.
///
/// This is the list a peer link dispatches on and the list a conformance test checks against
/// Chia's namespace for collisions.
pub const ALL_DIG_OPCODES: [u8; 27] = [
    DigMessageType::NewAttestation as u8,
    DigMessageType::NewCheckpointProposal as u8,
    DigMessageType::NewCheckpointSignature as u8,
    DigMessageType::RequestCheckpointSignatures as u8,
    DigMessageType::RespondCheckpointSignatures as u8,
    DigMessageType::RequestStatus as u8,
    DigMessageType::RespondStatus as u8,
    DigMessageType::NewCheckpointSubmission as u8,
    DigMessageType::ValidatorAnnounce as u8,
    DigMessageType::RequestBlockTransactions as u8,
    DigMessageType::RespondBlockTransactions as u8,
    DigMessageType::ReconciliationSketch as u8,
    DigMessageType::ReconciliationResponse as u8,
    DigMessageType::StemTransaction as u8,
    DigMessageType::PlumtreeLazyAnnounce as u8,
    DigMessageType::PlumtreePrune as u8,
    DigMessageType::PlumtreeGraft as u8,
    DigMessageType::PlumtreeRequestByHash as u8,
    DigMessageType::RegisterPeer as u8,
    DigMessageType::RegisterAck as u8,
    DIG_MESSAGE,
    STORE_MELTED,
    HOLDINGS_ANNOUNCE,
    PROFILE_ROOT_ANNOUNCE,
    PROFILE_BODY_REQUEST,
    PROFILE_BODY,
    DISTRIBUTOR_ANNOUNCE,
];

/// Whether `opcode` belongs to the DIG band rather than Chia's namespace.
///
/// This is a *band* test, not an *assigned* test: an unassigned value such as `250` is still
/// DIG's to allocate, and a link must route it to DIG handling (where it is rejected as unknown)
/// rather than to a Chia decoder that would reject the whole connection.
#[must_use]
pub const fn is_dig_opcode(opcode: u8) -> bool {
    opcode >= DIG_BAND_START
}

#[cfg(test)]
mod tests {
    use super::{
        is_dig_opcode, ALL_DIG_OPCODES, DIG_BAND_START, DIG_MESSAGE, DISTRIBUTOR_ANNOUNCE,
        FREE_BAND_START, HOLDINGS_ANNOUNCE, PROFILE_BODY, PROFILE_BODY_REQUEST,
        PROFILE_ROOT_ANNOUNCE, STORE_MELTED,
    };
    use chia_protocol::ProtocolMessageTypes;
    use chia_traits::Streamable;

    /// No DIG opcode may ever collide with one Chia accepts — probed against the real decoder
    /// over the whole `u8` space rather than against a transcribed copy of Chia's enum, so an
    /// upstream addition that reached into the band would fail this test instead of silently
    /// producing two meanings for one byte.
    #[test]
    fn dig_opcodes_are_disjoint_from_the_chia_namespace() {
        for opcode in ALL_DIG_OPCODES {
            assert!(
                ProtocolMessageTypes::from_bytes(&[opcode]).is_err(),
                "opcode {opcode} is claimed by both DIG and Chia"
            );
        }
    }

    /// The band is contiguous from 200 with no gaps and no duplicates: a gap would mean an
    /// opcode was silently dropped from the list, a duplicate that two protocols share a byte.
    #[test]
    fn the_assigned_band_is_contiguous_from_200() {
        let expected: Vec<u8> = (DIG_BAND_START..=DISTRIBUTOR_ANNOUNCE).collect();
        assert_eq!(ALL_DIG_OPCODES.to_vec(), expected);
    }

    /// The free band starts exactly where the consensus band ends, and every assigned value is
    /// pinned — these are cross-repo canonical constants that must not drift.
    #[test]
    fn free_band_constants_are_pinned() {
        assert_eq!(FREE_BAND_START, 220);
        assert_eq!(DIG_MESSAGE, 220);
        assert_eq!(STORE_MELTED, 221);
        assert_eq!(HOLDINGS_ANNOUNCE, 222);
        assert_eq!(PROFILE_ROOT_ANNOUNCE, 223);
        assert_eq!(PROFILE_BODY_REQUEST, 224);
        assert_eq!(PROFILE_BODY, 225);
        assert_eq!(DISTRIBUTOR_ANNOUNCE, 226);
    }

    /// `DISTRIBUTOR_ANNOUNCE` is a canonical constant (DIG-Network/dig_ecosystem#3252): a
    /// second implementation must match this value byte for byte, so it is pinned as a literal
    /// the same way the other free-band opcodes are.
    #[test]
    fn distributor_announce_is_pinned_to_226() {
        assert_eq!(DISTRIBUTOR_ANNOUNCE, 226);
    }

    /// `ALL_DIG_OPCODES` must enumerate `DISTRIBUTOR_ANNOUNCE` — this is the only mechanism
    /// that gives a 220-band opcode a rate limit in dig-gossip's exhaustiveness test
    /// (`inbound_limits.rs`); an opcode missing from this array silently falls through to the
    /// loose default rate-limit settings (the #1720/#1760-D fail-open bug).
    #[test]
    fn all_dig_opcodes_contains_distributor_announce() {
        assert!(ALL_DIG_OPCODES.contains(&DISTRIBUTOR_ANNOUNCE));
    }

    /// `ALL_DIG_OPCODES` has no duplicates and is strictly ascending — a duplicate would mean
    /// two protocols silently sharing one byte, a non-ascending entry would mean a copy/paste
    /// error when a new opcode was appended.
    #[test]
    fn all_dig_opcodes_is_deduped_and_strictly_ascending() {
        for window in ALL_DIG_OPCODES.windows(2) {
            assert!(
                window[0] < window[1],
                "not strictly ascending at {window:?}"
            );
        }
    }

    /// `ALL_DIG_OPCODES` has grown to 27 entries: 20 consensus opcodes plus 7 free-band ones
    /// now that `DISTRIBUTOR_ANNOUNCE` is assigned.
    #[test]
    fn all_dig_opcodes_has_27_entries() {
        assert_eq!(ALL_DIG_OPCODES.len(), 27);
    }

    /// `is_dig_opcode` is a band test, so it must still recognize the newly assigned value.
    #[test]
    fn is_dig_opcode_recognizes_distributor_announce() {
        assert!(is_dig_opcode(DISTRIBUTOR_ANNOUNCE));
    }

    /// The three profile-SMT opcodes are a single indivisible allocation: each one must be
    /// present in the dispatch list, in order, or the sync protocol is only half-routable. A
    /// list missing just the middle value still passes a naive "highest value is 225" check,
    /// so this asserts the exact contiguous triple as a slice.
    #[test]
    fn the_profile_sync_triple_is_assigned_together() {
        let start = ALL_DIG_OPCODES
            .iter()
            .position(|&op| op == PROFILE_ROOT_ANNOUNCE)
            .expect("PROFILE_ROOT_ANNOUNCE must be present");
        let triple = &ALL_DIG_OPCODES[start..start + 3];
        assert_eq!(
            triple,
            [PROFILE_ROOT_ANNOUNCE, PROFILE_BODY_REQUEST, PROFILE_BODY]
        );
    }

    /// The band predicate is pinned from BOTH sides: 199 is Chia's, 200 is DIG's.
    #[test]
    fn band_predicate_is_pinned_from_both_sides() {
        assert!(!is_dig_opcode(DIG_BAND_START - 1));
        assert!(is_dig_opcode(DIG_BAND_START));
        assert!(is_dig_opcode(u8::MAX));
    }
}

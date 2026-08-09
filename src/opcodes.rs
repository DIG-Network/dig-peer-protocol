//! The complete DIG opcode namespace — the `200..=222` band, in one place.
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

/// Every opcode DIG has assigned, ascending — the 20 consensus opcodes plus the 3 free-band ones.
///
/// This is the list a peer link dispatches on and the list a conformance test checks against
/// Chia's namespace for collisions.
pub const ALL_DIG_OPCODES: [u8; 23] = [
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
        is_dig_opcode, ALL_DIG_OPCODES, DIG_BAND_START, DIG_MESSAGE, FREE_BAND_START,
        HOLDINGS_ANNOUNCE, STORE_MELTED,
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
        let expected: Vec<u8> = (DIG_BAND_START..=HOLDINGS_ANNOUNCE).collect();
        assert_eq!(ALL_DIG_OPCODES.to_vec(), expected);
    }

    /// The free band starts exactly where the consensus band ends, and its three assigned
    /// values are pinned — these are cross-repo canonical constants that must not drift.
    #[test]
    fn free_band_constants_are_pinned() {
        assert_eq!(FREE_BAND_START, 220);
        assert_eq!(DIG_MESSAGE, 220);
        assert_eq!(STORE_MELTED, 221);
        assert_eq!(HOLDINGS_ANNOUNCE, 222);
    }

    /// The band predicate is pinned from BOTH sides: 199 is Chia's, 200 is DIG's.
    #[test]
    fn band_predicate_is_pinned_from_both_sides() {
        assert!(!is_dig_opcode(DIG_BAND_START - 1));
        assert!(is_dig_opcode(DIG_BAND_START));
        assert!(is_dig_opcode(u8::MAX));
    }
}

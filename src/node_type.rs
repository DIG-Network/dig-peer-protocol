//! [`NodeType`] — the service role a peer declares when it registers.
//!
//! ## Why this is not `chia_protocol::NodeType`
//!
//! `NodeType` travels inside [`RegisterPeer`](crate::RegisterPeer), a **DIG** message on the DIG
//! opcode band (218). A field of a DIG message is part of the DIG wire, so DIG owns it; sourcing
//! it from `chia-protocol` made a chia version bump a change to a DIG message body.
//!
//! ## The discriminants are the wire, and they are frozen
//!
//! Each variant's value IS its encoded byte — the encoding below is a single byte, nothing more.
//! The values match what DIG peers are exchanging today and MUST NOT be renumbered:
//! `tests/golden_wire_vectors.rs` pins `FullNode` and `Introducer` as absolute hex inside a real
//! `RegisterPeer` body, so a renumbering fails there rather than silently re-labelling every
//! registered peer on the network.
//!
//! Variants exist for roles DIG itself never registers as (a harvester does not join the DIG
//! gossip network). They are kept so that a peer speaking a fuller node vocabulary round-trips
//! rather than being rejected, and so the numbering can never be reused for something else.

use std::io::Cursor;

use chia_sha2::Sha256;
use chia_traits::{Error, Result, Streamable};

/// The service role a peer declares. One byte on the wire.
#[repr(u8)]
#[derive(Hash, Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub enum NodeType {
    /// A full node. DIG gossip peers register as this.
    FullNode = 1,
    /// A harvester.
    Harvester = 2,
    /// A farmer.
    Farmer = 3,
    /// A timelord.
    Timelord = 4,
    /// An introducer — the peer-discovery role DIG registers against.
    Introducer = 5,
    /// A wallet.
    Wallet = 6,
    /// A data-layer node.
    DataLayer = 7,
}

impl NodeType {
    /// Every variant, in discriminant order.
    ///
    /// Exists so tests and exhaustiveness checks enumerate the real set rather than a transcribed
    /// list that could drift from the enum.
    pub const ALL: [Self; 7] = [
        Self::FullNode,
        Self::Harvester,
        Self::Farmer,
        Self::Timelord,
        Self::Introducer,
        Self::Wallet,
        Self::DataLayer,
    ];

    /// The single byte this role occupies on the wire.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// The role a wire byte names, or `None` when the byte names no role.
    ///
    /// Unknown bytes are refused rather than mapped to a default: a peer declaring a role this
    /// build cannot interpret must surface as an error, never silently become a full node.
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|role| role.to_byte() == byte)
    }
}

impl TryFrom<u8> for NodeType {
    type Error = UnknownNodeType;

    fn try_from(byte: u8) -> std::result::Result<Self, UnknownNodeType> {
        Self::from_byte(byte).ok_or(UnknownNodeType(byte))
    }
}

/// A wire byte that names no [`NodeType`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{0} is not a known node type")]
pub struct UnknownNodeType(pub u8);

impl Streamable for NodeType {
    fn update_digest(&self, digest: &mut Sha256) {
        digest.update([self.to_byte()]);
    }

    fn stream(&self, out: &mut Vec<u8>) -> Result<()> {
        out.push(self.to_byte());
        Ok(())
    }

    fn parse<const TRUSTED: bool>(input: &mut Cursor<&[u8]>) -> Result<Self> {
        let byte = u8::parse::<TRUSTED>(input)?;
        Self::from_byte(byte).ok_or(Error::InvalidEnum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The discriminants ARE the wire format, pinned as absolute values. This is the test that
    /// fails if anyone renumbers the enum, which is a network-wide event and never a refactor.
    #[test]
    fn discriminants_are_frozen_at_their_wire_values() {
        assert_eq!(NodeType::FullNode.to_byte(), 1);
        assert_eq!(NodeType::Harvester.to_byte(), 2);
        assert_eq!(NodeType::Farmer.to_byte(), 3);
        assert_eq!(NodeType::Timelord.to_byte(), 4);
        assert_eq!(NodeType::Introducer.to_byte(), 5);
        assert_eq!(NodeType::Wallet.to_byte(), 6);
        assert_eq!(NodeType::DataLayer.to_byte(), 7);
    }

    /// Streaming emits exactly the discriminant and nothing else — no length prefix, no padding.
    /// Driven over every variant so a single hard-coded byte cannot pass.
    #[test]
    fn streams_as_exactly_one_byte_for_every_variant() {
        for role in NodeType::ALL {
            assert_eq!(role.to_bytes().expect("encode"), vec![role.to_byte()]);
        }
    }

    #[test]
    fn every_variant_round_trips_through_parse() {
        for role in NodeType::ALL {
            let decoded = NodeType::from_bytes(&role.to_bytes().expect("encode")).expect("decode");
            assert_eq!(decoded, role);
        }
    }

    /// Both ends of the valid range plus a mid-range gap-free sweep: every byte that is NOT a
    /// discriminant must be refused. `0` matters specifically — a zero byte is what a truncated
    /// or zero-filled buffer produces, and mapping it to a role would make corruption look like
    /// a valid registration.
    #[test]
    fn a_byte_naming_no_role_is_refused_rather_than_defaulted() {
        for byte in 0..=u8::MAX {
            let is_known = (1..=7).contains(&byte);
            assert_eq!(
                NodeType::from_byte(byte).is_some(),
                is_known,
                "byte {byte} disagreed with the known-role set"
            );
            assert_eq!(NodeType::from_bytes(&[byte]).is_ok(), is_known);
        }
    }

    #[test]
    fn try_from_reports_the_offending_byte() {
        assert_eq!(NodeType::try_from(5), Ok(NodeType::Introducer));
        assert_eq!(NodeType::try_from(0), Err(UnknownNodeType(0)));
        assert_eq!(NodeType::try_from(8), Err(UnknownNodeType(8)));
        assert_eq!(UnknownNodeType(9).to_string(), "9 is not a known node type");
    }

    /// `ALL` must actually contain every variant, or the sweep above silently narrows.
    #[test]
    fn all_covers_the_whole_enum() {
        assert_eq!(NodeType::ALL.len(), 7);
        let mut bytes: Vec<u8> = NodeType::ALL.iter().map(|r| r.to_byte()).collect();
        bytes.sort_unstable();
        bytes.dedup();
        assert_eq!(bytes, vec![1, 2, 3, 4, 5, 6, 7]);
    }
}

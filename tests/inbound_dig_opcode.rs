//! The defect the vendored fork existed to fix: an inbound DIG opcode over a real link.
//!
//! `chia_sdk_client::Peer`'s inbound loop decodes every frame with `chia_protocol::Message::from_bytes`,
//! which errors on any opcode outside `ProtocolMessageTypes` — and that error ends the loop, so
//! one DIG frame drops the whole connection. These tests run opcode **218** (`RegisterPeer`)
//! through [`DigLink`] over a genuine `WebSocketStream` pair and show both halves of the fix:
//! the frame arrives, and the link is still alive afterwards.
//!
//! Each test states the pre-migration behaviour it is contrasted against by asserting directly
//! that `Message::from_bytes` rejects the very bytes the link accepts — so the test is anchored
//! to the real upstream decoder rather than to a claim about it.

use std::net::{Ipv4Addr, SocketAddr};

use chia_protocol::{Bytes, Message, ProtocolMessageTypes};
use chia_traits::Streamable;
use dig_peer_protocol::{DigLink, DigMessage, DigMessageType, LinkOptions};
use tokio::io::DuplexStream;
use tokio_tungstenite::{tungstenite::protocol::Role, WebSocketStream};

/// `RegisterPeer` — the introducer-registration opcode, and the first opcode dig-gossip needed
/// that Chia's namespace cannot express.
const REGISTER_PEER: u8 = DigMessageType::RegisterPeer as u8;

/// A pair of links joined by an in-memory duplex, standing in for two TLS-terminated peers.
///
/// Both ends use `from_server_websocket` because the peer address is known up front here; the
/// framing and inbound routing under test are identical on either constructor (they share
/// `from_parts`).
async fn linked_pair() -> (
    DigLink,
    tokio::sync::mpsc::Receiver<DigMessage>,
    DigLink,
    tokio::sync::mpsc::Receiver<DigMessage>,
) {
    let (left, right) = tokio::io::duplex(64 * 1024);
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 8444));

    let client: WebSocketStream<DuplexStream> =
        WebSocketStream::from_raw_socket(left, Role::Client, None).await;
    let server: WebSocketStream<DuplexStream> =
        WebSocketStream::from_raw_socket(right, Role::Server, None).await;

    let (a, a_rx) = DigLink::from_server_websocket(client, addr, LinkOptions::default());
    let (b, b_rx) = DigLink::from_server_websocket(server, addr, LinkOptions::default());
    (a, a_rx, b, b_rx)
}

/// Await the next inbound message, failing the test rather than hanging if none arrives.
async fn next(rx: &mut tokio::sync::mpsc::Receiver<DigMessage>) -> DigMessage {
    tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("timed out waiting for an inbound message")
        .expect("the link closed instead of delivering a message")
}

/// The pre-migration decoder genuinely rejects opcode 218 — the premise every test below rests
/// on, asserted rather than assumed.
///
/// The control matters: the SAME framing with a Chia opcode must decode cleanly, otherwise a
/// merely-malformed frame would produce this rejection and prove nothing about the opcode.
#[test]
fn the_pre_migration_decoder_rejects_218_but_accepts_the_same_frame_with_a_chia_opcode() {
    let payload = Bytes::new(b"registration".to_vec());

    let dig_frame = DigMessage::new(REGISTER_PEER, Some(7), payload.clone()).to_bytes();
    assert!(
        Message::from_bytes(&dig_frame).is_err(),
        "chia_protocol accepted opcode 218 — the fork's premise no longer holds"
    );

    let chia_opcode = *ProtocolMessageTypes::RequestPeers
        .to_bytes()
        .expect("encode")
        .first()
        .expect("one byte");
    let chia_frame = DigMessage::new(chia_opcode, Some(7), payload).to_bytes();
    assert!(
        Message::from_bytes(&chia_frame).is_ok(),
        "the control frame failed to decode, so the rejection above is about framing, not opcodes"
    );
}

/// Opcode 218 crosses a live link intact, and the link SURVIVES it.
///
/// The follow-up Chia-opcode message is the load-bearing half. Merely receiving the DIG message
/// would also be satisfied by an implementation that decoded it and then tore the connection
/// down; only a second message arriving afterwards distinguishes "decoded" from "still alive",
/// and tearing down is exactly what the upstream loop does.
#[tokio::test]
async fn opcode_218_round_trips_and_leaves_the_link_alive() {
    let (sender_link, _sender_rx, _receiver_link, mut receiver_rx) = linked_pair().await;

    sender_link
        .send_dig(REGISTER_PEER, Bytes::new(b"registration".to_vec()))
        .await
        .expect("send 218");

    let received = next(&mut receiver_rx).await;
    assert_eq!(received.msg_type, REGISTER_PEER);
    assert_eq!(received.data.as_ref(), b"registration");

    let chia_opcode = *ProtocolMessageTypes::RequestPeers
        .to_bytes()
        .expect("encode")
        .first()
        .expect("one byte");
    sender_link
        .send_dig(chia_opcode, Bytes::new(b"after".to_vec()))
        .await
        .expect("send the follow-up");

    let after = next(&mut receiver_rx).await;
    assert_eq!(
        after.data.as_ref(),
        b"after",
        "the link died on the DIG frame — decoding it is not enough"
    );
}

/// An inbound DIG frame carrying a correlation id is delivered to the application, not swallowed
/// by an unrelated outbound waiter that happens to hold the same id.
///
/// Ids are chosen independently by each side, so this collision is routine rather than exotic;
/// upstream's loop answers it by returning an error, which drops the connection.
#[tokio::test]
async fn an_inbound_request_id_is_delivered_rather_than_matched_against_our_own_waiters() {
    let (sender_link, _sender_rx, _receiver_link, mut receiver_rx) = linked_pair().await;

    // Id 0 is the first id `RequestMap` hands out, so it is the id most likely to collide with a
    // waiter on the receiving side.
    sender_link
        .send_message(DigMessage::new(
            REGISTER_PEER,
            Some(0),
            Bytes::new(b"request".to_vec()),
        ))
        .await
        .expect("send an inbound request");

    let received = next(&mut receiver_rx).await;
    assert_eq!(received.msg_type, REGISTER_PEER);
    assert_eq!(
        received.id,
        Some(0),
        "the correlation id must survive, so the reply can echo it"
    );
    assert_eq!(received.data.as_ref(), b"request");
}

/// A DIG-opcode request/response pair correlates end to end: the responder echoes the id it was
/// given and the requester's `request_dig` future resolves with that reply.
///
/// Two DIFFERENT opcodes are used (205 out, 206 back) so a link that returned the request to its
/// own caller — or matched on nothing but the id — would be visible.
#[tokio::test]
async fn a_dig_request_correlates_with_its_response() {
    let (requester, _requester_rx, responder, mut responder_rx) = linked_pair().await;

    let responder_task = tokio::spawn(async move {
        let request = responder_rx.recv().await.expect("a request");
        responder
            .send_message(DigMessage::new(
                DigMessageType::RespondStatus as u8,
                request.id,
                Bytes::new(b"pong".to_vec()),
            ))
            .await
            .expect("send the response");
    });

    // Bounded on purpose: a broken link leaves this future pending forever, and a hanging test
    // is a far worse CI signal than a failing one.
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        requester.request_dig(
            DigMessageType::RequestStatus as u8,
            Bytes::new(b"ping".to_vec()),
        ),
    )
    .await
    .expect("timed out waiting for the response")
    .expect("the request resolves");

    assert_eq!(response.msg_type, DigMessageType::RespondStatus as u8);
    assert_eq!(response.data.as_ref(), b"pong");
    responder_task.await.expect("responder finished");
}

# dig-peer-protocol — Normative Specification

This document is the authoritative contract for the `dig-peer-protocol` crate: the DIG Network
L2 P2P message layer. It specifies the wire framing, the DIG opcode namespace (200–222),
the introducer registration messages, the peer link that carries them, the re-exported
Chia protocol surface, and the invariants an implementation MUST uphold.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as
described in RFC 2119.

The README covers usage; this document covers the contract.

---

## 1. Scope and role

`dig-peer-protocol` is the single import point for DIG P2P messaging. It:

1. Re-exports the Chia protocol ecosystem (`chia-protocol`, `chia-sdk-client`,
   `chia-ssl`, `chia-traits`, `chia_streamable_macro`) so consumers depend on
   `dig-peer-protocol` alone (§6).
2. Defines the DIG opcode band **200–222** as a disjoint extension of Chia's
   `ProtocolMessageTypes` namespace (§3): a consensus half (200–219, `DigMessageType`)
   and a free half (220+, application protocols).
3. Defines `DigMessage`, a framing type that is **byte-identical on the wire** to
   `chia_protocol::Message` but carries the opcode as a raw `u8`, so both Chia and DIG
   opcodes can be encoded and decoded (§2).
4. Defines the introducer wire types: the Chia-standard `RequestPeersIntroducer` /
   `RespondPeersIntroducer` (opcodes 63/64) and the DIG-extension `RegisterPeer` /
   `RegisterAck` (opcodes 218/219, DSC-005) (§4, §5).
5. Defines `DigLink`, the websocket peer link that frames every message as a
   `DigMessage`, so a DIG opcode can be sent and received on a real connection (§7).

## 2. Wire framing — `DigMessage`

### 2.1 Byte layout (normative)

Every message on a DIG P2P connection uses the following framing, identical to
`chia_protocol::Message`'s `Streamable` encoding. All multi-byte integers are
**big-endian**.

```
offset  size        field       meaning
0       1           msg_type    raw u8 opcode (Chia 0–107 or DIG 200–222)
1       1           has_id      0x00 = no id; any non-zero value = id present
2       2 (if id)   id          u16 correlation id, big-endian
+0      4           data_len    u32 payload length, big-endian
+4      data_len    data        opaque payload bytes (encoding defined per opcode)
```

- An encoder MUST emit `has_id` as exactly `0x01` when an id is present and `0x00`
  when absent. A decoder MUST treat any non-zero `has_id` as "id present"
  (`from_bytes` tests `has_id != 0`).
- `data_len` MUST equal the exact byte length of `data`.
- A zero-length payload (`data_len == 0`) is a valid message.

### 2.2 Decoding rules

`DigMessage::from_bytes(&[u8]) -> Option<DigMessage>`:

- MUST accept **any** `msg_type` value — no enum validation at the framing layer.
  Opcode dispatch is the receiver's responsibility (§3.1).
- MUST return `None` (never panic, never read out of bounds) when the buffer is
  truncated at any point: shorter than 2 bytes, ends inside the id, ends inside
  `data_len`, or ends before `data_len` payload bytes.
- MUST return `None` when the decoded `data_len` exceeds `DigMessage::MAX_MESSAGE_SIZE`
  (16 MiB), checked BEFORE any bounds check against `bytes.len()` or slicing/allocating
  the payload — a peer-controlled length prefix cannot force an allocation above this
  ceiling. `MAX_MESSAGE_SIZE` mirrors `chia-protocol`'s own message-size limit and is
  comfortably above any legitimate DIG opcode payload.
- `from_bytes` is a leaf parser over an already-materialized `&[u8]`; `MAX_MESSAGE_SIZE`
  bounds only the allocation `from_bytes` itself performs. Callers (the transport/framing
  layer that assembles the byte slice from the wire) MUST enforce their own per-frame
  size cap BEFORE buffering an incoming frame into a contiguous slice, so an oversized or
  lying length prefix cannot force unbounded buffering ahead of ever reaching
  `from_bytes`.
- All internal offset arithmetic (`offset + 2` for the id, `offset + 4` for `data_len`,
  `offset + data_len` for the payload end) MUST use checked addition and return `None`
  on overflow rather than panicking or wrapping. This keeps decoding safe on every
  target pointer width, including 32-bit targets where a peer-controlled `data_len`
  near `u32::MAX` could otherwise overflow a `usize` bounds check.
- Trailing bytes beyond `data_len` are ignored by `from_bytes` (it reads exactly the
  framed length).

`DigMessage::to_bytes(&self) -> Vec<u8>` MUST produce the §2.1 layout exactly;
`from_bytes(to_bytes(m)) == Some(m)` MUST hold for every `DigMessage`.

`DigMessage::from_bytes_owned(buf: Vec<u8>) -> Option<DigMessage>` applies the
identical acceptance/rejection rules as `from_bytes` (same truncation checks, same
`MAX_MESSAGE_SIZE` cap, same overflow-checked offset arithmetic) but takes the buffer
by value and moves the payload range out of it (via `Vec::drain`) instead of copying it
out of a borrowed slice with `to_vec`. Callers that already own a `Vec<u8>` (e.g. a
transport that read the frame directly into an owned buffer) SHOULD prefer this over
`from_bytes` to avoid an extra payload copy; `from_bytes` remains the correct choice
when only a borrowed `&[u8]` is available.

### 2.3 Fields and construction

```rust
pub struct DigMessage {
    pub msg_type: u8,        // raw wire opcode
    pub id: Option<u16>,     // request/response correlation id
    pub data: Bytes,         // serialized payload body
}
DigMessage::new(msg_type: u8, id: Option<u16>, data: Bytes) -> DigMessage
DigMessage::MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024  // 16 MiB — see §2.2
```

`DigMessage` is `Debug + Clone + PartialEq + Eq`.

### 2.4 No interoperability with `chia_protocol::Message`

`DigMessage` MUST NOT provide conversion to or from `chia_protocol::Message`. The DIG
envelope is native and self-contained; a cheap bridge to `Message` is an on-ramp back to
the closed `ProtocolMessageTypes` enum this crate exists to escape.

Traffic addressed to a chia full node uses `DigLink`'s typed `send`/`request`, which
derive their opcode from `ChiaProtocolMessage` (§7). That is the only supported chia path.

- Classification helpers: `is_dig_extension()` is `msg_type >= 200`;
  `is_chia_standard()` is `msg_type < 200`. The boundary is exactly 200
  (199 is Chia-standard, 200 is DIG-extension).

## 3. DIG opcode namespace — the 200–222 band

### 3.1 The 200+ convention (normative)

Chia's `ProtocolMessageTypes` occupies discriminants 0–107. DIG opcodes start at
**200**, leaving a ≥92-value gap against future Chia additions. Because `msg_type` is an
untyped `u8` on the wire, a receiver MUST dispatch on numeric value:
`< 200` → Chia handler, `>= 200` → DIG handler.

The band has two halves. **200–219** is the L2 **consensus** half, enumerated by
`DigMessageType` (§3.2). **220 and above** is the **free** half, whose opcodes are plain
constants because each body is owned by the application protocol that defines it (§3.5).

New DIG opcodes MUST be assigned only within the DIG band starting at 200, contiguously
after the highest assigned value; an assigned opcode MUST NOT be removed, renumbered, or
repurposed. `ALL_DIG_OPCODES` MUST list every assigned opcode in ascending order, and
`is_dig_opcode(op)` MUST be true for exactly `op >= 200`.

### 3.2 Assigned opcodes (normative registry)

`DigMessageType` is `#[repr(u8)]`; each variant maps 1:1 to its wire value.
`DigMessageType::MAX_ASSIGNED == 219`; `DigMessageType::ALL` lists all 20 variants in
declaration order.

| Opcode | Variant | Delivery strategy | Purpose |
|--------|---------|-------------------|---------|
| 200 | `NewAttestation` | Plumtree eager push | Validator attestation |
| 201 | `NewCheckpointProposal` | Plumtree eager push | Checkpoint proposal from epoch proposer |
| 202 | `NewCheckpointSignature` | Plumtree eager push | BLS signature fragment for checkpoint aggregation |
| 203 | `RequestCheckpointSignatures` | Unicast request | Request checkpoint signatures |
| 204 | `RespondCheckpointSignatures` | Unicast response | Respond with checkpoint signatures |
| 205 | `RequestStatus` | Unicast request | Request peer's chain status |
| 206 | `RespondStatus` | Unicast response | Respond with chain status |
| 207 | `NewCheckpointSubmission` | Plumtree eager push | Aggregated checkpoint after BLS aggregation |
| 208 | `ValidatorAnnounce` | Broadcast flood | Validator directory announcement |
| 209 | `RequestBlockTransactions` | Compact block | Request missing transactions by short ID |
| 210 | `RespondBlockTransactions` | Compact block | Respond with full transactions |
| 211 | `ReconciliationSketch` | ERLAY | Set-reconciliation sketch |
| 212 | `ReconciliationResponse` | ERLAY | Set-reconciliation response |
| 213 | `StemTransaction` | Dandelion++ stem | Privacy-preserving tx origination |
| 214 | `PlumtreeLazyAnnounce` | Plumtree lazy | Hash-only announcement to non-tree peers |
| 215 | `PlumtreePrune` | Plumtree control | Demote sender to lazy |
| 216 | `PlumtreeGraft` | Plumtree control | Promote sender to eager |
| 217 | `PlumtreeRequestByHash` | Plumtree control | Request full payload by hash |
| 218 | `RegisterPeer` | Introducer | Self-registration request (DSC-005) |
| 219 | `RegisterAck` | Introducer | Registration acknowledgement (DSC-005) |

The payload encodings for opcodes 200–217 are defined by their consumers (the gossip
layer); this crate defines the payloads for 218/219 (§4) and the framing for all.

### 3.2a Free band (normative registry)

Opcodes at or above `FREE_BAND_START` (**220**) carry application protocols rather than
L2 consensus. Their bodies are opaque to this crate and to any transport: framing an
opcode says nothing about what its payload means.

| Opcode | Constant | Delivery | Purpose |
|--------|----------|----------|---------|
| 220 | `DIG_MESSAGE` | Directed | `dig-message` envelope, sealed end-to-end to the recipient's DID key by `dig-message` itself |
| 221 | `STORE_MELTED` | Public flood | A store's on-chain coin was melted; peers stop hosting its `.dig` content |
| 222 | `HOLDINGS_ANNOUNCE` | Public flood | Signed holdings add/remove deltas, feeding dig-dht's holder set |

221 and 222 are public all-peers broadcasts addressed to everyone, so they are signed and
mTLS-authenticated but MUST NOT be recipient-sealed (the §5.4 public-broadcast carve-out).
220 is directed and its payload MUST already be sealed by its producer; a transport MUST
NOT seal, open, or parse it.

### 3.3 Conversion and error behavior

- `TryFrom<u8> for DigMessageType`: MUST succeed for exactly 200..=219 and MUST fail
  with `UnknownDigMessageType(value)` for every other `u8` (including all Chia values
  and 220+).
- `UnknownDigMessageType(pub u8)` implements `std::error::Error`; its `Display` is
  `"unknown DigMessageType discriminant: {n}"`.
- `Display` for `DigMessageType` renders `Name(value)`, e.g. `RegisterPeer(218)`.

### 3.4 Serde representation (normative)

`DigMessageType` serializes as the raw `u8` discriminant (e.g. JSON `216`), **not** the
variant name. Deserialization MUST accept unsigned and signed integer inputs, narrow to
`u8`, and reject out-of-`u8`-range values ("out of u8 range") and in-range values that
are not assigned discriminants (the `UnknownDigMessageType` message). Non-integer inputs
are a type error ("DigMessageType wire value (u8 in 200..=219)").

## 4. Introducer registration — `RegisterPeer` / `RegisterAck` (DSC-005)

DIG-extension messages by which a node advertises its P2P reachability to an introducer.
Opcodes 218/219 do not exist in stock `ProtocolMessageTypes`, so these types travel as
`DigMessage`, not `chia_protocol::Message`.

### 4.1 `RegisterPeer` (opcode 218)

Payload fields, encoded with Chia `Streamable` in declaration order:

| # | Field | Type | Streamable encoding | Meaning |
|---|-------|------|---------------------|---------|
| 1 | `ip` | `String` | u32 BE length + UTF-8 bytes | Externally reachable IP or hostname |
| 2 | `port` | `u16` | u16 BE | P2P listening port |
| 3 | `node_type` | `NodeType` (DIG-owned) | u8 discriminant, frozen at `FullNode=1`, `Harvester=2`, `Farmer=3`, `Timelord=4`, `Introducer=5`, `Wallet=6`, `DataLayer=7` | Declared service role; gossip nodes register as `NodeType::FullNode`. A byte naming no role MUST be refused, never defaulted. |

API:

- `RegisterPeer::new(ip, port, node_type)`.
- `to_dig_message(&self, id: Option<u16>) -> Result<DigMessage, chia_traits::Error>` —
  MUST produce a `DigMessage` with `msg_type == 218`, the given `id`, and the
  Streamable-encoded payload.
- `from_dig_message(&DigMessage) -> Option<Result<Self, chia_traits::Error>>` —
  MUST return `None` when `msg_type != 218` (wrong-opcode is not a decode error);
  otherwise `Some(Streamable::from_bytes(data))`, where a corrupt/truncated body
  surfaces as `Some(Err(_))`.

### 4.2 `RegisterAck` (opcode 219)

Payload: a single `bool` (`success`), Streamable-encoded as one byte. A body that is
empty or otherwise not a valid bool encoding MUST decode as `Some(Err(_))`.

`success == false` is a **valid wire outcome** meaning the introducer rejected the
registration by policy; it MUST NOT be treated as a transport or decode error.

API mirrors §4.1: `RegisterAck::new(success)`, `to_dig_message(id)` (opcode 219),
`from_dig_message` (`None` unless `msg_type == 219`).

### 4.3 Registration exchange

1. The node sends `RegisterPeer` (typically with a correlation `id`) declaring
   `ip`, `port`, `node_type`.
2. The introducer replies `RegisterAck { success }`, echoing the correlation semantics
   of the framing layer (§2.1). `success == true` means the peer was accepted into the
   introducer's directory; `false` means a policy rejection.

## 5. Chia-standard introducer types (opcodes 63/64)

`RequestPeersIntroducer` (opcode 63, empty body) and `RespondPeersIntroducer`
(opcode 64, body = `Vec<TimestampedPeerInfo>` in Chia Streamable list encoding) are
declared with `#[streamable(message)]` because their opcodes exist in stock
`ProtocolMessageTypes`. They implement `ChiaProtocolMessage` and therefore work with
`chia_sdk_client::Peer` request APIs directly; they MUST remain byte-compatible with
the upstream Chia introducer protocol.

## 6. Re-exported surface (public API contract)

Consumers MUST be able to obtain the following through `dig_peer_protocol::*` without
importing the underlying crates:

| Source crate | Re-exported |
|--------------|-------------|
| `chia-protocol` | `ChiaProtocolMessage`, `ProtocolMessageTypes`, `TimestampedPeerInfo` — NAMED only. There MUST NOT be a glob re-export: a consumer needing another chia wire type depends on `chia-protocol` directly. |
| `chia-sdk-client` (always) | `load_ssl_cert`, `ClientError`, `Network`, `Peer`, `PeerOptions`, `RateLimit`, `RateLimiter`, `RateLimits`, `V2_RATE_LIMITS` |
| `chia-sdk-client` (TLS-gated, §7) | `Client`, `ClientState`, `Connector`; `create_native_tls_connector` / `create_rustls_connector` per feature |
| `chia-ssl` | `ChiaCertificate` |
| `chia-traits` | `Streamable` |
| `chia_streamable_macro` | `streamable` (proc macro) |
| DIG extensions | `Bytes`, `NodeType`, `UnknownNodeType`, `DigMessage`, `DigMessageType`, `UnknownDigMessageType`, `RegisterPeer`, `RegisterAck`, `RequestPeersIntroducer`, `RespondPeersIntroducer` |
| DIG opcodes | `DIG_BAND_START`, `FREE_BAND_START`, `DIG_MESSAGE`, `STORE_MELTED`, `HOLDINGS_ANNOUNCE`, `ALL_DIG_OPCODES`, `is_dig_opcode` |
| DIG peer link (§7) | `DigLink`, `LinkOptions`, `LinkError`, `OpcodeRateLimiter`, `OpcodeRateLimits` |

Removing or changing the signature/semantics of any re-exported or DIG-extension item is
a breaking change to every consumer; additions are non-breaking.

## 7. Peer link — `DigLink` (normative)

`DigLink` is a websocket link to one peer that frames every message as a `DigMessage`. It
exists because `chia_sdk_client::Peer` cannot carry DIG opcodes: `chia_protocol::Message`
stores `msg_type` as the closed `ProtocolMessageTypes` enum, which has no value for a DIG
opcode, so a DIG opcode is neither constructible nor decodable there.

### 7.1 Framing and decoding

1. Every outbound message MUST be encoded with `DigMessage::to_bytes` and sent as a single
   binary websocket frame.
2. Every inbound binary frame MUST be decoded with `DigMessage::from_bytes_owned`, which
   accepts **any** opcode. A link MUST NOT decode inbound frames through
   `chia_protocol::Message::from_bytes`: that rejects DIG opcodes, and the rejection ends
   the receive loop, dropping a connection over a single well-formed DIG frame.
3. Non-binary frames are handled without affecting message flow: `Close` ends the loop;
   `Ping`/`Pong` are ignored; `Text` is logged and ignored.
4. A binary frame that does not decode as a `DigMessage` MUST be logged and skipped. The
   receive loop MUST continue, and the next frame MUST be decoded and routed normally. An
   implementation MUST NOT treat a malformed frame as fatal.

   Websocket frames are self-delimiting: the transport delivers whole binary payloads and
   the receive loop never reads a length off a byte stream, so an undecodable payload costs
   exactly that payload and cannot desynchronise anything that follows it. Ending the loop
   would therefore buy no integrity, while restoring the same one-frame kill switch rule 2
   and §7.2 exist to remove — any peer, hostile or merely running a version whose framing
   this build does not parse, could drop the link by sending three bytes. It would also fail
   *silently*: the reader stops, but outstanding requests remain registered and resolve only
   when their own deadlines (§7.3) expire, so callers observe an unexplained stall rather
   than a closed connection.

### 7.2 Inbound routing (normative)

A decoded message is routed by correlation id:

- `id == None` → delivered to the application channel.
- `id == Some(n)` **and** a live request waiter holds `n` → delivered to that waiter.
- `id == Some(n)` and **no** waiter holds `n` → delivered to the application channel on a
  best-effort basis (see below).

The third rule is required, not an optimisation. Each side allocates ids from its own
space, so an inbound *request* id routinely collides with an outstanding outbound request
id. An implementation MUST NOT treat an unmatched id as fatal: doing so lets any peer drop
the link at will by sending one unknown id, and misroutes ordinary inbound requests.

**Delivery to the application MUST NOT block the receive loop.** The application channel is
bounded; when it is full, the frame MUST be dropped and logged rather than awaited. Blocking
here is a denial of service: a peer that emits ids nobody is waiting on fills the channel,
the loop parks, and from that moment **no correlated reply is routed at all** — every
outstanding request hangs with no error and no recovery. Correlated routing has no fallback
path, so it MUST NOT be able to queue behind unmatched traffic. Loss of an unmatched inbound
frame under overload is permitted and expected.

### 7.3 Correlated requests

`request_raw` / `request_dig` / `request_infallible` / `request_fallible` MUST allocate an
unused `u16` id, send with that id, and resolve when a message bearing it arrives.
Concurrent requests MUST be bounded by the id space so an id is always available.

Every request MUST carry a deadline (`LinkOptions::request_timeout`). On expiry the request
MUST fail with `LinkError::RequestTimeout` and its id MUST be reclaimed immediately, so a
silent peer can neither hang the caller indefinitely nor exhaust the id space.

Ids MUST be allocated from a monotonically advancing wrapping cursor rather than
lowest-free-first, so a reclaimed id is not reissued until the id space has wrapped. Reclaiming
an id at the deadline otherwise hands it straight to the next request, and a reply that arrives
late — answering the request that already timed out — then matches the new waiter and is
delivered to it as though it were that request's answer. Nothing downstream can detect the
substitution, so this MUST be prevented at allocation.

A reply
whose opcode matches none of the expected ones MUST fail with `LinkError::InvalidResponse`
carrying the raw opcodes — never a `ProtocolMessageTypes`, which cannot name a DIG opcode.

### 7.4 Outbound rate limiting

Outbound messages MUST pass an `OpcodeRateLimiter` before being written. Its limits are
**derived** from Chia's `V2_RATE_LIMITS` by re-keying each entry to its wire byte, so a
Chia opcode is limited exactly as a stock peer limits it; DIG opcodes have no upstream
entry and fall to `default_settings`. A refused message MUST NOT be charged against the
budget.

The source table is selectable: `OpcodeRateLimits` implements `From<&RateLimits>`, and
`Default` is defined as `From<&V2_RATE_LIMITS>`. The limits remain derived under either —
a caller chooses the *table*, never an individual limit, and the type exposes no field-wise
constructor. A supplied table MUST be keyed by the `chia_protocol::ProtocolMessageTypes`
this crate resolves (re-exported from its root); a table keyed by another version's enum
re-keys to shifted wire bytes, silently loosening every Chia opcode to `default_settings`.

A refusal MUST be classified, because the two kinds demand opposite behaviour:

| Verdict | Meaning | Required sender behaviour |
|---|---|---|
| `Admission::Admitted` | within budget, charged | write the frame |
| `Admission::Deferred` | over a budget that a window roll resets | back off and retry, bounded by `LinkOptions::send_timeout`, then fail with `LinkError::SendTimeout` |
| `Admission::Unsendable` | refused even against an empty window (e.g. larger than the per-message `max_size`) | fail immediately with `LinkError::Unsendable` |

A sender MUST NOT retry an `Unsendable` message. No window will ever admit it, so retrying
is an unbounded loop that returns neither success nor error — the caller simply disappears.
A `HoldingsAnnounce` batch above the 1 MiB `default_settings.max_size` is the concrete case:
it must be split by the caller, not waited on.

### 7.5 Construction

| Constructor | Use |
|---|---|
| `from_websocket` | client-side `MaybeTlsStream`; peer address recovered from the stream |
| `from_server_websocket` | server-side transport that cannot inhabit `MaybeTlsStream`; caller supplies the address |
| `connect` / `connect_full_uri` | dial over TLS (requires `native-tls` or `rustls`) |

Both adoption paths MUST produce identical framing, routing and rate-limiting behaviour.
Callers MUST derive a peer id from the client certificate before adopting a server-side
websocket: the certificate is unreachable once the stream is split.

## 8. Features and configuration

| Feature | Default | Effect |
|---------|---------|--------|
| `native-tls` | off | forwards to `chia-sdk-client/native-tls`; enables `Client`, `ClientState`, `Connector`, `create_native_tls_connector`, and `DigLink::connect`/`connect_full_uri` |
| `rustls` | off | forwards to `chia-sdk-client/rustls`; enables `Client`, `ClientState`, `Connector`, `create_rustls_connector`, and `DigLink::connect`/`connect_full_uri` |

With neither feature the crate MUST still build; only the TLS-dependent re-exports are
absent. Consumers select a TLS backend on `dig-peer-protocol` rather than depending on
`chia-sdk-client` directly.

Runtime configuration is limited to `LinkOptions` (§7), which scales the outbound rate-limit budget.

## 9. Security properties

- **Transport security is inherited, not defined here.** Peer connections use Chia's
  mutual-TLS model via the re-exported `chia-sdk-client` connectors and
  `chia-ssl::ChiaCertificate`; this crate adds no cryptography of its own.
- **Decode safety:** `DigMessage::from_bytes`, `DigMessage::from_bytes_owned`, and the
  `from_dig_message` decoders MUST never panic or over-read on malformed input
  (truncated buffers → `None`; corrupt bodies → `Err`; oversized `data_len` → `None`;
  offset arithmetic overflow → `None`, never a panic or wrap). `#![deny(unsafe_code)]`
  is enforced crate-wide (Cargo `[lints.rust]`).
- **No trust in payloads:** the framing layer imposes no semantic validation on `data`;
  consumers MUST validate decoded payloads before acting on them.

## 10. Compatibility invariants

1. **Framing is frozen.** The §2.1 byte layout is byte-identical to
   `chia_protocol::Message` and MUST NOT change.
2. **Opcode registry is append-only.** Assigned values 200–222 (§3.2, §3.2a) are
   permanent; new opcodes extend the band upward, never reuse or renumber.
3. **Payload encodings are append-compatible per Chia Streamable rules** — the
   `RegisterPeer`/`RegisterAck` field lists (§4) are fixed; any evolution must keep old
   encodings decodable.
4. **Serde form is the wire value.** `DigMessageType` JSON/serde representation stays
   the raw integer discriminant.

## 11. Conformance summary

| # | Requirement | Verified by |
|---|-------------|-------------|
| C1 | Frame layout `[u8 type][u8 has_id][u16 id?][u32 len][data]`, big-endian, matches `chia_protocol::Message` | §2.1; round-trip + boundary tests in `src/dig_message.rs` |
| C2 | Decoder accepts any opcode; truncated input → `None`, never panic; `data_len` above `MAX_MESSAGE_SIZE` (16 MiB) → `None` before slicing/allocating; offset arithmetic is overflow-checked on every target width | §2.2; truncation + oversized-length + overflow tests in `src/dig_message.rs` |
| C3 | DIG band is exactly 200–222 with no gaps and no collision with any opcode `chia-protocol` accepts; dispatch boundary at 200 | §3.1–3.2a; disjointness/contiguity/boundary tests in `src/opcodes.rs`, range tests in `src/dig_message_type.rs` |
| C4 | `TryFrom<u8>` rejects every non-assigned value with `UnknownDigMessageType` | §3.3; `unknown_rejected` test |
| C5 | `DigMessageType` serde = raw u8 discriminant | §3.4; serde tests in `src/dig_message_type.rs` |
| C6 | `RegisterPeer` = (`ip: String`, `port: u16`, `node_type: NodeType`) at opcode 218; `RegisterAck` = (`success: bool`) at 219; wrong opcode → `None`, corrupt body → `Err`; `success=false` is valid | §4; round-trip + decode-error tests in `src/introducer_wire.rs` |
| C7 | Opcodes 63/64 remain Chia-`ProtocolMessageTypes`-compatible `#[streamable(message)]` types | §5; streamable round-trip tests |
| C8 | Re-export surface of §6 available from `dig_peer_protocol` alone; TLS items gated by `native-tls`/`rustls` | §6–7; `src/lib.rs` |
| C9 | `unsafe_code` denied; no panics on malformed wire input | §9; `Cargo.toml` lints, decode tests |
| C10 | `DigMessage::to_bytes` is byte-identical to `chia_protocol::Message::to_bytes` for **every** opcode `chia-protocol` accepts, across present/absent ids and payloads spanning the `u32` length prefix | §2.1, §2.4; `tests/wire_compatibility.rs` |
| C11 | An inbound DIG opcode (218) is decoded and delivered, and the link survives it — where `Message::from_bytes` would reject the same frame and end the loop | §7.1; `tests/inbound_dig_opcode.rs` |
| C12 | An inbound message whose id matches no live waiter is delivered to the application, not treated as fatal | §7.2; `tests/inbound_dig_opcode.rs` |
| C13 | Chia opcodes keep their upstream rate limits under the re-keyed table; a caller-supplied table governs the limiter and `Default` still derives from `V2_RATE_LIMITS`; DIG opcodes fall to `default_settings`; budgets are enforced from both sides of the bound | §7.4; tests in `src/rate_limit.rs` |
| C14 | A malformed binary frame is skipped, not fatal: the frame that follows it still decodes and routes to its correlated waiter | §7.1 rule 4; `tests/inbound_dig_opcode.rs` |
| C15 | A late reply to a request that has already timed out is never delivered to a subsequent waiter | §7.3; `tests/link_liveness.rs` |

Peer implementations (any language) MUST reproduce C1–C6 and C10 byte-for-byte to interoperate
with DIG nodes. The gossip layer consuming these opcodes and the introducer/relay
services are specified in their own repositories; the DIG Network protocol documentation
at docs.dig.net covers the network-level behavior built on these messages.

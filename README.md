# dig-peer-protocol

DIG Network L2 protocol types — superset of [`chia-protocol`](https://crates.io/crates/chia-protocol) with extension opcodes **200–222** — plus `DigLink`, the websocket peer link that can actually carry them.

One dependency replaces five: `chia-protocol`, `chia-sdk-client`, `chia-ssl`, `chia-traits`, `chia_streamable_macro` — all re-exported verbatim.

---

## Install

```toml
[dependencies]
dig-peer-protocol = { version = "0.3", features = ["rustls"] }
```

### Features

| Flag         | Forwards to                  | Adds re-exports                                      |
|--------------|------------------------------|------------------------------------------------------|
| `native-tls` | `chia-sdk-client/native-tls` | `Client`, `ClientState`, `Connector`, `create_native_tls_connector` |
| `rustls`     | `chia-sdk-client/rustls`     | `Client`, `ClientState`, `Connector`, `create_rustls_connector`     |

Neither default. Without a TLS feature: DIG types and `Peer` still compile; `Client` does not.

---

## Why this crate exists

`chia_protocol::Message` stores `msg_type` as `ProtocolMessageTypes` — a closed `#[repr(u8)]` enum covering opcodes 0–107. `Message::from_bytes` **rejects any unknown opcode**. DIG extension opcodes (200+) cannot decode through stock `Message`.

`DigMessage` has identical wire layout but stores `msg_type` as raw `u8`. Encodes/decodes any opcode (Chia or DIG) without touching upstream types. Conversions to/from `Message` are lossless for opcodes the Chia enum recognizes. The byte-identity is asserted exhaustively — over every opcode `chia-protocol` accepts — in `tests/wire_compatibility.rs`.

The same closed enum breaks the *transport*, not just the type: `chia_sdk_client::Peer` decodes inbound frames with `Message::from_bytes`, so one DIG frame ends its receive loop and drops the connection. `DigLink` is the replacement — a websocket link written against the wire format that frames `DigMessage`.

```rust,ignore
use dig_peer_protocol::{DigLink, LinkOptions, DIG_MESSAGE};

let (link, mut inbound) = DigLink::connect(addr, connector, LinkOptions::default()).await?;
link.send_dig(DIG_MESSAGE, envelope_bytes.into()).await?;

while let Some(message) = inbound.recv().await {
    // message.msg_type is a raw u8 — Chia opcode or DIG opcode, both arrive.
}
```

DIG previously carried vendored forks of `chia-protocol` and `chia-sdk-client` to get this. `DigLink` replaces them, so `chia-protocol` is an ordinary dependency again with no `[patch.crates-io]`.

---

## Wire format

`DigMessage` binary layout (same as `chia_protocol::Message`):

```text
[u8 msg_type] [u8 has_id (0|1)] [u16 id (big-endian, if has_id==1)] [u32 data_len (BE)] [u8; data_len payload]
```

- `msg_type` < 200 → Chia standard opcode
- `msg_type` ≥ 200 → DIG extension opcode (see `DigMessageType`)

---

## Opcode assignments

DIG band: `200..=219`. Chia band: `0..=107` (+ reserves). Gap `108..=199` reserved for future Chia.

| Opcode | Variant                       | Payload                  | Gossip strategy          |
|--------|-------------------------------|--------------------------|--------------------------|
| 200    | `NewAttestation`              | —                        | Plumtree eager push      |
| 201    | `NewCheckpointProposal`       | —                        | Plumtree eager push      |
| 202    | `NewCheckpointSignature`      | —                        | Plumtree eager push      |
| 203    | `RequestCheckpointSignatures` | —                        | Unicast request          |
| 204    | `RespondCheckpointSignatures` | —                        | Unicast response         |
| 205    | `RequestStatus`               | —                        | Unicast request          |
| 206    | `RespondStatus`               | —                        | Unicast response         |
| 207    | `NewCheckpointSubmission`     | —                        | Plumtree eager push      |
| 208    | `ValidatorAnnounce`           | —                        | Broadcast flood          |
| 209    | `RequestBlockTransactions`    | —                        | Unicast request          |
| 210    | `RespondBlockTransactions`    | —                        | Unicast response         |
| 211    | `ReconciliationSketch`        | —                        | ERLAY reconciliation     |
| 212    | `ReconciliationResponse`      | —                        | ERLAY reconciliation     |
| 213    | `StemTransaction`             | —                        | Dandelion++ stem         |
| 214    | `PlumtreeLazyAnnounce`        | —                        | Plumtree lazy            |
| 215    | `PlumtreePrune`               | —                        | Plumtree control         |
| 216    | `PlumtreeGraft`               | —                        | Plumtree control         |
| 217    | `PlumtreeRequestByHash`       | —                        | Plumtree pull            |
| 218    | `RegisterPeer`                | `RegisterPeer` struct    | Unicast → introducer     |
| 219    | `RegisterAck`                 | `RegisterAck` struct     | Unicast ← introducer     |

Payload types for 200–217 are TBD (defined by consumer crates); the protocol crate only defines discriminants + framing.

---

## Public interface — DIG types

### `DigMessage` — raw-opcode wire message

```rust
pub struct DigMessage {
    pub msg_type: u8,         // 0..=255, any opcode
    pub id: Option<u16>,      // correlation id for req/resp
    pub data: Bytes,          // serialized payload
}

impl DigMessage {
    pub const MAX_MESSAGE_SIZE: usize; // 16 MiB — data_len prefixes above this decode to None

    pub fn new(msg_type: u8, id: Option<u16>, data: Bytes) -> Self;

    // Wire codec (same layout as chia_protocol::Message)
    pub fn to_bytes(&self) -> Vec<u8>;
    pub fn from_bytes(bytes: &[u8]) -> Option<Self>;         // None on short/malformed/oversized buffer
    pub fn from_bytes_owned(buf: Vec<u8>) -> Option<Self>;   // same rules; moves payload instead of copying

    // Interop with stock Chia Message

    // Opcode-range predicates
    pub fn is_dig_extension(&self) -> bool;   // msg_type >= 200
    pub fn is_chia_standard(&self) -> bool;   // msg_type < 200
}
```

**Inputs/outputs**

| Method                    | Input                    | Output                             | Failure mode                       |
|---------------------------|--------------------------|--------------------------------------|------------------------------------|
| `new`                     | `u8`, `Option<u16>`, `Bytes` | `DigMessage`                   | infallible                         |
| `to_bytes`                | `&self`                  | `Vec<u8>`                          | infallible                         |
| `from_bytes`              | `&[u8]`                  | `Option<DigMessage>`               | `None` if truncated or `data_len` > `MAX_MESSAGE_SIZE` |
| `from_bytes_owned`        | `Vec<u8>`                | `Option<DigMessage>`               | same as `from_bytes`; moves payload, no copy |

`from_bytes`/`from_bytes_owned` reject any `data_len` prefix above `MAX_MESSAGE_SIZE`
(16 MiB) before slicing/allocating the payload. This bounds only the allocation these
functions perform — callers MUST still enforce their own per-frame size cap at the
transport layer before buffering an incoming frame.

---

### `DigMessageType` — typed discriminants (200–219)

```rust
#[repr(u8)]
pub enum DigMessageType {
    NewAttestation = 200,
    NewCheckpointProposal = 201,
    NewCheckpointSignature = 202,
    RequestCheckpointSignatures = 203,
    RespondCheckpointSignatures = 204,
    RequestStatus = 205,
    RespondStatus = 206,
    NewCheckpointSubmission = 207,
    ValidatorAnnounce = 208,
    RequestBlockTransactions = 209,
    RespondBlockTransactions = 210,
    ReconciliationSketch = 211,
    ReconciliationResponse = 212,
    StemTransaction = 213,
    PlumtreeLazyAnnounce = 214,
    PlumtreePrune = 215,
    PlumtreeGraft = 216,
    PlumtreeRequestByHash = 217,
    RegisterPeer = 218,
    RegisterAck = 219,
}

impl DigMessageType {
    pub const MAX_ASSIGNED: u8 = 219;
    pub const ALL: [Self; 20];    // declaration order

    // TryFrom<u8> — Err(UnknownDigMessageType) when value ∉ 200..=219
}

// Serde: serializes/deserializes as raw u8 (not variant name)
impl Serialize for DigMessageType { ... }
impl<'de> Deserialize<'de> for DigMessageType { ... }
impl Display for DigMessageType { ... }  // "RegisterPeer(218)"

pub struct UnknownDigMessageType(pub u8);  // Error; Display + std::error::Error
```

**Inputs/outputs**

| Conversion                                | Input  | Output                                      |
|-------------------------------------------|--------|---------------------------------------------|
| `as u8`                                   | variant | `u8` in `200..=219`                        |
| `DigMessageType::try_from(u8)`            | `u8`   | `Result<Self, UnknownDigMessageType>`       |
| `serde_json::to_string(&variant)`         | variant | `"218"` (stringified u8)                   |
| `serde_json::from_str::<DigMessageType>`  | `"218"` | `Ok(RegisterPeer)` / `Err` if not 200–219  |

---

### `RegisterPeer` — introducer registration request (opcode 218)

```rust
#[streamable]
pub struct RegisterPeer {
    pub ip: String,        // externally reachable IP or hostname
    pub port: u16,         // P2P listening port
    pub node_type: NodeType, // e.g. NodeType::FullNode
}

impl RegisterPeer {
    pub fn new(ip: String, port: u16, node_type: NodeType) -> Self;

    // Streamable trait — binary codec for payload body (not full wire message)
    fn to_bytes(&self) -> Result<Vec<u8>, chia_traits::Error>;
    fn from_bytes(bytes: &[u8]) -> Result<Self, chia_traits::Error>;

    // DigMessage wrappers (prepend opcode 218 + framing)
    pub fn to_dig_message(&self, id: Option<u16>) -> Result<DigMessage, chia_traits::Error>;
    pub fn from_dig_message(msg: &DigMessage) -> Option<Result<Self, chia_traits::Error>>;
    // from_dig_message returns None when msg.msg_type != 218
}
```

---

### `RegisterAck` — introducer registration response (opcode 219)

```rust
#[streamable]
pub struct RegisterAck {
    pub success: bool,   // false == policy rejection (valid wire outcome)
}

impl RegisterAck {
    pub fn new(success: bool) -> Self;
    // Streamable: to_bytes / from_bytes
    pub fn to_dig_message(&self, id: Option<u16>) -> Result<DigMessage, chia_traits::Error>;
    pub fn from_dig_message(msg: &DigMessage) -> Option<Result<Self, chia_traits::Error>>;
    // from_dig_message returns None when msg.msg_type != 219
}
```

---

### `RequestPeersIntroducer` / `RespondPeersIntroducer` — Chia-standard (opcodes 63/64)

```rust
#[streamable(message)]
pub struct RequestPeersIntroducer {}

#[streamable(message)]
pub struct RespondPeersIntroducer {
    pub peer_list: Vec<TimestampedPeerInfo>,
}
```

These use `#[streamable(message)]` because opcodes 63/64 exist in stock `ProtocolMessageTypes`. Compatible with `Peer::request_infallible` directly (no `DigMessage` wrapper needed).

---

## Re-exports from Chia crates

### From `chia_protocol::*` (full glob)

~100 wire types. Key items:

| Category          | Types                                                                             |
|-------------------|-----------------------------------------------------------------------------------|
| Framing           | DIG-owned `DigMessage`, `Bytes`, `NodeType`; `ProtocolMessageTypes` + `ChiaProtocolMessage` + `TimestampedPeerInfo` re-exported by name for chia paths |
| Block             | `FullBlock`, `HeaderBlock`, `BlockRecord`, `Foliage`, `FoliageBlockData`          |
| Peer discovery    | `RequestPeers`, `RespondPeers`, `TimestampedPeerInfo`                              |
| Mempool/tx        | `NewTransaction`, `RequestTransaction`, `RespondTransaction`, `MempoolItemsAdded` |
| State/coins       | `Coin`, `CoinState`, `CoinSpend`, `RequestCoinState`, `CoinStateUpdate`           |
| Consensus/PoS     | `ProofOfSpace`, `NewSignagePointOrEndOfSubSlot`, `ChallengeChainSubSlot`          |
| Wallet protocol   | `NewPeakWallet`, `RegisterForCoinUpdates`, `RegisterForPhUpdates`, `SendTransaction` |
| Fees              | `FeeEstimate`, `FeeEstimateGroup`, `FeeRate`, `RequestFeeEstimates`               |

See [`chia-protocol` docs](https://docs.rs/chia-protocol) for the full list.

### From `chia_sdk_client`

```rust
// Always available
pub use chia_sdk_client::{
    ClientError,           // enum — TLS, handshake, io errors
    Network,               // mainnet/testnet selection
    Peer,                  // single-peer connection handle (send/request/receive)
    PeerOptions,           // builder config
    RateLimit,             // per-opcode rate limit entry
    RateLimiter,
    RateLimits,
    V2_RATE_LIMITS,        // static — V2 protocol defaults
    load_ssl_cert,         // load ChiaCertificate from disk
};

// Requires feature = "native-tls" or "rustls"
pub use chia_sdk_client::{Client, ClientState, Connector};

#[cfg(feature = "native-tls")]
pub use chia_sdk_client::create_native_tls_connector;

#[cfg(feature = "rustls")]
pub use chia_sdk_client::create_rustls_connector;
```

### From `chia_ssl`

```rust
pub use chia_ssl::ChiaCertificate;   // { cert_pem: String, key_pem: String }
```

### From `chia_traits`

```rust
pub use chia_traits::Streamable;     // trait — binary codec (to_bytes / from_bytes / hash)
```

### From `chia_streamable_macro`

```rust
pub use chia_streamable_macro::streamable;   // #[streamable] / #[streamable(message)] proc macro
```

---

## Encode / decode example

```rust
use dig_peer_protocol::{DigMessage, DigMessageType, NodeType, RegisterPeer, RegisterAck};

// --- Encode outbound RegisterPeer ---
let rp = RegisterPeer::new("1.2.3.4".into(), 9444, NodeType::FullNode);
let wire: DigMessage = rp.to_dig_message(Some(1)).unwrap();
assert_eq!(wire.msg_type, DigMessageType::RegisterPeer as u8);  // 218
let bytes: Vec<u8> = wire.to_bytes();                            // send over socket

// --- Decode inbound frame ---
let msg: DigMessage = DigMessage::from_bytes(&bytes).expect("valid frame");

match DigMessageType::try_from(msg.msg_type) {
    Ok(DigMessageType::RegisterPeer) => {
        let decoded = RegisterPeer::from_dig_message(&msg).unwrap().unwrap();
        println!("peer {}:{}", decoded.ip, decoded.port);
    }
    Ok(DigMessageType::RegisterAck) => {
        let ack = RegisterAck::from_dig_message(&msg).unwrap().unwrap();
        println!("ack success={}", ack.success);
    }
    Ok(other)   => { /* dispatch other DIG opcode */ }
    Err(_)      => {
        // Not a DIG opcode. `msg` still holds the raw opcode and payload; dispatch on
        // `msg.msg_type` directly. There is deliberately no conversion to
        // `chia_protocol::Message` — see SPEC.md §2.4.
    }
}
```

---

## Error types

| Error                       | Source                            | Cause                                            |
|-----------------------------|-----------------------------------|--------------------------------------------------|
| `UnknownDigMessageType(u8)` | `DigMessageType::try_from`        | Wire value not in 200..=219                      |
| `chia_traits::Error`        | `Streamable::to_bytes/from_bytes` | Malformed payload                                |
| `ClientError`               | `chia_sdk_client`                 | TLS, handshake, IO, protocol violations          |

`DigMessage::from_bytes`/`from_bytes_owned` return `Option<DigMessage>` (no error type)
— `None` means truncated/malformed frame OR a `data_len` prefix above
`DigMessage::MAX_MESSAGE_SIZE` (16 MiB).

---

## Invariants

- `DigMessage::to_bytes` output is binary-identical to `Message::to_bytes` for opcodes present in `ProtocolMessageTypes`.
- `from_bytes(to_bytes(m)) == Some(m)` for all valid `DigMessage`.
- `DigMessageType as u8` ∈ `200..=219` for all variants; `TryFrom<u8>` is the inverse.
- Payload types 200–217 are defined by downstream crates; this crate only defines discriminants + framing.

---

## License

Apache-2.0

//! # aegis-proto
//!
//! The wire protocol spoken between enrolled agents and the server. Messages are
//! length-prefixed JSON frames (`u32` big-endian length, then a JSON
//! [`Message`]). JSON is used deliberately: the [`Event`](aegis_sdk::Event)
//! payload includes a self-describing `Custom` escape hatch, which a
//! non-self-describing binary format could not round-trip.
//!
//! Transport security (mutual TLS) and authentication (enrollment tokens +
//! per-agent Ed25519 keys) are layered *under* this protocol by the transport
//! plugin and the server; this crate defines only the message grammar and
//! framing.
//!
//! Server authentication uses agent-side SHA-256 certificate pinning (see
//! [`pin`]), not a public-CA / X.509 client-cert handshake; agent
//! authentication uses a per-agent Ed25519 signature over a domain-separated,
//! channel-bound nonce carried in a [`Message::Command`]`{`[`ServerCommand::Noop`]`}`
//! challenge. The reusable TLS-config and challenge-digest construction live in
//! the [`tls`] module so that agent (signer) and server (verifier) share one
//! implementation.

use aegis_sdk::Event;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

pub mod pin;
pub mod tls;

/// Bumped on any breaking change to [`Message`].
pub const PROTO_VERSION: u16 = 1;

/// Hard cap on a single frame to bound memory on the receive path.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Upper bound on how much body buffer [`read_message`] pre-allocates up front,
/// regardless of the (attacker-controlled) length prefix. The body is then read
/// incrementally, growing the buffer as bytes actually arrive, so a peer that
/// announces a large frame but sends slowly cannot force a full `MAX_FRAME_BYTES`
/// allocation per stalled connection. Sized to cover the common batch frame
/// without a reallocation.
const READ_CHUNK_BYTES: usize = 64 * 1024;

/// Errors from the framing/transport codec.
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("frame of {0} bytes exceeds maximum {MAX_FRAME_BYTES}")]
    FrameTooLarge(usize),
    #[error("connection closed by peer")]
    Closed,
}

/// Server-issued command delivered to an agent (the response/control channel).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum ServerCommand {
    /// Ask the agent to re-evaluate detection for a subject.
    ///
    /// Today this is a **fire-and-forget stub**: the agent acks `ok:true` and
    /// emits one local `transport.rescore` Custom trigger event, but no plugin in
    /// the workspace subscribes to that kind, so the full re-scoring orchestration
    /// is deferred. The emitted shape is fixed (see
    /// `plugin_transport::actor::dispatch_command`) so a future consumer can key
    /// on it without a wire change.
    Rescore { subject: String },
    /// Push a new configuration subtree to a named plugin.
    ///
    /// **Reserved wire field with no live implementation:** there is no
    /// `Plugin::reconfigure` in `aegis-sdk`, so the agent always acks this
    /// `ok:false` ("unsupported") and changes no state. Defined here so the
    /// protocol is forward-compatible once live reconfiguration lands.
    SetConfig {
        plugin: String,
        config: serde_json::Value,
    },
    /// Request that the endpoint enter a heightened-monitoring posture.
    Isolate { reason: String },
    /// No-op (keepalive / capability probe).
    Noop,
}

/// A single protocol message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "msg", rename_all = "snake_case")]
pub enum Message {
    /// Agent → server: open a session on an already-enrolled connection.
    ClientHello {
        proto_version: u16,
        agent_id: String,
        hostname: String,
        os: String,
        /// Agent's Ed25519 public key (32 bytes).
        agent_pubkey: Vec<u8>,
    },
    /// Server → agent: accept/reject the session.
    ServerHello {
        proto_version: u16,
        accepted: bool,
        reason: Option<String>,
    },
    /// Agent → server: first-contact enrollment using a one-time token.
    EnrollRequest {
        token: String,
        hostname: String,
        os: String,
        agent_pubkey: Vec<u8>,
    },
    /// Server → agent: enrollment result and assigned identity.
    EnrollResponse {
        accepted: bool,
        agent_id: String,
        reason: Option<String>,
    },
    /// Agent → server: a batch of telemetry/derived events.
    EventBatch {
        batch_id: Uuid,
        events: Vec<Event>,
    },
    /// Server → agent: acknowledge a batch.
    BatchAck {
        batch_id: Uuid,
        accepted: u32,
    },
    /// Server → agent: issue a command.
    Command {
        id: Uuid,
        command: ServerCommand,
    },
    /// Agent → server: report the outcome of a command.
    CommandResult {
        id: Uuid,
        ok: bool,
        detail: Option<String>,
    },
    /// Either direction: keepalive.
    Ping,
    Pong,
}

/// Write a length-prefixed JSON frame.
pub async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &Message,
) -> Result<(), ProtoError> {
    let bytes = serde_json::to_vec(message)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtoError::FrameTooLarge(bytes.len()));
    }
    writer
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a single length-prefixed JSON frame.
pub async fn read_message<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Message, ProtoError> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(ProtoError::Closed),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(ProtoError::FrameTooLarge(len));
    }

    // Do NOT trust the length prefix for the allocation: reserve a bounded amount
    // up front and grow only as bytes actually arrive. A peer that announces a
    // 16 MiB frame but sends nothing (or trickles) therefore cannot pin a 16 MiB
    // zeroed buffer per connection — the buffer never exceeds what was received.
    let mut buf: Vec<u8> = Vec::with_capacity(len.min(READ_CHUNK_BYTES));
    while buf.len() < len {
        // Grow the readable region in bounded steps toward `len`.
        let want = (buf.len() + READ_CHUNK_BYTES).min(len);
        if buf.capacity() < want {
            buf.reserve(want - buf.len());
        }
        let prev = buf.len();
        // Read into the uninitialized spare capacity up to `want`.
        buf.resize(want, 0);
        let n = reader.read(&mut buf[prev..want]).await?;
        if n == 0 {
            // EOF before the full body arrived: peer closed mid-frame.
            return Err(ProtoError::Closed);
        }
        buf.truncate(prev + n);
    }
    Ok(serde_json::from_slice(&buf)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_sdk::EventPayload;

    #[tokio::test]
    async fn message_roundtrips_over_duplex() {
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);

        let batch = Message::EventBatch {
            batch_id: Uuid::new_v4(),
            events: vec![Event::new(
                "agent-1",
                "plugin-session",
                EventPayload::Heartbeat { uptime_s: 5 },
            )],
        };
        let sent = batch.clone();
        let writer = tokio::spawn(async move {
            write_message(&mut a, &sent).await.unwrap();
        });

        let got = read_message(&mut b).await.unwrap();
        writer.await.unwrap();

        match (batch, got) {
            (Message::EventBatch { events: e1, .. }, Message::EventBatch { events: e2, .. }) => {
                assert_eq!(e1.len(), e2.len());
                assert_eq!(e2[0].kind, "heartbeat");
            }
            _ => panic!("unexpected message variant"),
        }
    }

    /// M2 regression: a peer that announces a large frame but closes after
    /// sending only a few body bytes must yield `Closed` (EOF mid-frame) rather
    /// than hanging or forcing a `MAX_FRAME_BYTES` pre-allocation. We drive the
    /// reader against a fixed byte stream (len prefix + short body, then EOF).
    #[tokio::test]
    async fn read_message_short_body_then_eof_is_closed() {
        // Announce a 1 MiB body but provide only 3 bytes, then EOF.
        let mut stream: Vec<u8> = Vec::new();
        let announced: u32 = 1024 * 1024;
        stream.extend_from_slice(&announced.to_be_bytes());
        stream.extend_from_slice(b"abc");

        let mut cursor = std::io::Cursor::new(stream);
        let err = read_message(&mut cursor).await.unwrap_err();
        assert!(
            matches!(err, ProtoError::Closed),
            "short body then EOF must be Closed, got {err:?}"
        );
    }

    /// A frame whose announced length exceeds `MAX_FRAME_BYTES` is rejected at the
    /// length check, before any body read or allocation.
    #[tokio::test]
    async fn read_message_oversized_length_is_rejected() {
        let mut stream: Vec<u8> = Vec::new();
        let announced: u32 = (MAX_FRAME_BYTES as u32).saturating_add(1);
        stream.extend_from_slice(&announced.to_be_bytes());
        let mut cursor = std::io::Cursor::new(stream);
        let err = read_message(&mut cursor).await.unwrap_err();
        assert!(matches!(err, ProtoError::FrameTooLarge(_)), "got {err:?}");
    }

    /// A large but legitimately-sent frame still round-trips through the
    /// incremental reader (crosses several `READ_CHUNK_BYTES` boundaries).
    #[tokio::test]
    async fn read_message_large_legit_frame_roundtrips() {
        // Build an EventBatch big enough to span multiple read chunks.
        let events: Vec<Event> = (0..4000)
            .map(|i| {
                Event::new(
                    "agent-1",
                    "plugin-session",
                    EventPayload::Heartbeat { uptime_s: i },
                )
            })
            .collect();
        let batch = Message::EventBatch {
            batch_id: Uuid::new_v4(),
            events,
        };
        let bytes = serde_json::to_vec(&batch).unwrap();
        assert!(
            bytes.len() > READ_CHUNK_BYTES,
            "test frame must exceed one chunk to exercise growth"
        );

        let mut framed: Vec<u8> = Vec::new();
        framed.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        framed.extend_from_slice(&bytes);

        let mut cursor = std::io::Cursor::new(framed);
        let got = read_message(&mut cursor).await.unwrap();
        match got {
            Message::EventBatch { events, .. } => assert_eq!(events.len(), 4000),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn server_command_tagged_json() {
        let c = ServerCommand::Isolate {
            reason: "agent-detected".into(),
        };
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"cmd\":\"isolate\""));
        let back: ServerCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
    }
}

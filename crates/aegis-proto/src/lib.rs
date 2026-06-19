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
    Rescore { subject: String },
    /// Push a new configuration subtree to a named plugin.
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
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
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

//! The Aegis event model.
//!
//! Every observation, derived signal, score, detection, and alert in the system
//! flows through the plugin event bus as an [`Event`]. The event model is the
//! lingua franca between collectors (which produce raw telemetry), processors
//! (which derive higher-level signals such as agent-vs-human verdicts), and
//! sinks (which persist, forward, or alert).
//!
//! # Privacy by design
//!
//! Behavioral telemetry intentionally avoids capturing *content*. For example,
//! [`EventPayload::Keystroke`] carries only inter-arrival *timing* and coarse
//! shape (paste vs. typed), never the characters typed. Commands are summarized
//! by structural statistics and a salted hash, never stored verbatim by default.
//! This is a deliberate design constraint discussed in the accompanying paper.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Stable identifier for an enrolled endpoint (the "agent" host process).
pub type AgentId = String;
/// Identifier for an interactive session (tty/pty/ssh login) on an endpoint.
pub type SessionId = String;

/// Severity ladder for alerts and scored findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// The core question this platform answers about an interactive subject:
/// is the entity driving this session a human operator or an automated agent?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Behavior is consistent with a human operator.
    Human,
    /// Behavior is consistent with an automated agent / program.
    Agent,
    /// Insufficient or conflicting evidence.
    Uncertain,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Verdict::Human => "human",
            Verdict::Agent => "agent",
            Verdict::Uncertain => "uncertain",
        };
        f.write_str(s)
    }
}

/// Typed payloads for well-known event kinds, plus a [`EventPayload::Custom`]
/// escape hatch so third-party plugins can introduce new event types without
/// changing the SDK.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventPayload {
    /// A process was executed on the endpoint.
    ProcessExec {
        pid: u32,
        ppid: u32,
        uid: u32,
        exe: String,
        cmdline: Vec<String>,
        cwd: Option<String>,
    },
    /// An interactive session began.
    SessionStart {
        session_id: SessionId,
        tty: Option<String>,
        user: String,
        /// Remote peer (e.g. ssh client address) if applicable.
        remote: Option<String>,
    },
    /// An interactive session ended.
    SessionEnd { session_id: SessionId },
    /// Timing-only keystroke telemetry. Carries NO content — only the
    /// inter-arrival gap, whether the input arrived as a paste-like burst, and
    /// the burst length. This is the raw substrate for behavioral biometrics.
    Keystroke {
        session_id: SessionId,
        /// Nanoseconds since the previous keystroke in this session.
        inter_arrival_ns: u64,
        /// True if the input was delivered as an atomic burst (paste / program).
        is_paste: bool,
        /// Number of bytes/characters in the burst (1 for normal typing).
        burst_len: u32,
    },
    /// A completed command line was observed (structural summary only).
    CommandObserved {
        session_id: SessionId,
        command_len: u32,
        token_count: u32,
        /// Shannon entropy (bits/char) of the command text.
        shannon_entropy: f64,
        /// Whether the human used corrections (backspace) while composing it.
        had_backspace: bool,
        /// Levenshtein distance from the previous command (0 = identical).
        edit_distance_prev: u32,
        /// Gap since the previous command finished, in nanoseconds (think time).
        inter_command_ns: u64,
        /// Salted hash of the command for correlation without content storage.
        command_hash: String,
    },
    /// A numeric score produced by a scoring plugin for some subject.
    Score {
        subject: String,
        model: String,
        score: f64,
        #[serde(default)]
        features: BTreeMap<String, f64>,
    },
    /// A human-vs-agent (or other) classification verdict for a subject.
    Detection {
        subject: String,
        verdict: Verdict,
        /// Calibrated confidence in [0,1].
        confidence: f64,
        model: String,
        #[serde(default)]
        reasons: Vec<String>,
        #[serde(default)]
        features: BTreeMap<String, f64>,
    },
    /// An actionable alert raised for an operator.
    Alert {
        severity: Severity,
        title: String,
        detail: String,
        subject: Option<String>,
    },
    /// Liveness signal from an endpoint.
    Heartbeat { uptime_s: u64 },
    /// Arbitrary plugin-defined payload.
    Custom(serde_json::Value),
}

impl EventPayload {
    /// The canonical routing kind for this payload (used as the bus topic).
    pub fn default_kind(&self) -> &'static str {
        match self {
            EventPayload::ProcessExec { .. } => "process.exec",
            EventPayload::SessionStart { .. } => "session.start",
            EventPayload::SessionEnd { .. } => "session.end",
            EventPayload::Keystroke { .. } => "input.keystroke",
            EventPayload::CommandObserved { .. } => "command.observed",
            EventPayload::Score { .. } => "score",
            EventPayload::Detection { .. } => "detection",
            EventPayload::Alert { .. } => "alert",
            EventPayload::Heartbeat { .. } => "heartbeat",
            EventPayload::Custom(_) => "custom",
        }
    }
}

/// The unit of information on the event bus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: Uuid,
    /// Producer timestamp, nanoseconds since the Unix epoch.
    pub ts_ns: u64,
    pub agent_id: AgentId,
    /// Name of the plugin (or `"host"`) that produced the event.
    pub source: String,
    /// Routing topic, e.g. `"command.observed"`. Defaults from the payload.
    pub kind: String,
    pub payload: EventPayload,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

impl Event {
    /// Build an event from a payload, deriving the kind and timestamp.
    pub fn new(
        agent_id: impl Into<String>,
        source: impl Into<String>,
        payload: EventPayload,
    ) -> Self {
        let kind = payload.default_kind().to_string();
        Event {
            id: Uuid::new_v4(),
            ts_ns: now_ns(),
            agent_id: agent_id.into(),
            source: source.into(),
            kind,
            payload,
            labels: BTreeMap::new(),
        }
    }

    /// Attach a label and return self (builder style).
    pub fn with_label(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.labels.insert(k.into(), v.into());
        self
    }

    /// Override the routing kind (rarely needed; payload kind is the default).
    pub fn with_kind(mut self, kind: impl Into<String>) -> Self {
        self.kind = kind.into();
        self
    }
}

/// Current wall-clock time in nanoseconds since the Unix epoch.
pub fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_roundtrips_through_json() {
        let ev = Event::new(
            "agent-1",
            "plugin-session",
            EventPayload::Keystroke {
                session_id: "s1".into(),
                inter_arrival_ns: 150_000_000,
                is_paste: false,
                burst_len: 1,
            },
        )
        .with_label("host", "lab");
        let json = serde_json::to_string(&ev).unwrap();
        let back: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, "input.keystroke");
        assert_eq!(back.labels.get("host").map(String::as_str), Some("lab"));
    }

    #[test]
    fn payload_kinds_are_stable() {
        assert_eq!(
            EventPayload::Heartbeat { uptime_s: 1 }.default_kind(),
            "heartbeat"
        );
        assert_eq!(
            EventPayload::Detection {
                subject: "s".into(),
                verdict: Verdict::Agent,
                confidence: 0.9,
                model: "m".into(),
                reasons: vec![],
                features: BTreeMap::new(),
            }
            .default_kind(),
            "detection"
        );
    }
}

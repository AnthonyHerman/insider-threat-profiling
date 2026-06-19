//! Integration test for the full pipe-mode pipeline: file -> analyzer -> events
//! -> bus. Exercises the collector end-to-end with **no real TTY**, so it runs
//! in CI. Asserts the paste/typed distinction, command finalization, edit
//! distance, and — critically — that no event carries raw input content.

use std::sync::{Arc, Mutex};

use aegis_sdk::{Emitter, Event, EventPayload};
use async_trait::async_trait;
use plugin_tty::AnalyzerConfig;

/// A test emitter that captures every event it is handed.
#[derive(Clone, Default)]
struct CapturingEmitter {
    events: Arc<Mutex<Vec<Event>>>,
}

#[async_trait]
impl Emitter for CapturingEmitter {
    async fn emit(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

/// Pull the typed `Keystroke` triplets in order.
fn keystrokes(events: &[Event]) -> Vec<(bool, u32)> {
    events
        .iter()
        .filter_map(|e| match &e.payload {
            EventPayload::Keystroke {
                is_paste,
                burst_len,
                ..
            } => Some((*is_paste, *burst_len)),
            _ => None,
        })
        .collect()
}

fn commands(events: &[Event]) -> Vec<&EventPayload> {
    events
        .iter()
        .map(|e| &e.payload)
        .filter(|p| matches!(p, EventPayload::CommandObserved { .. }))
        .collect()
}

#[tokio::test]
async fn pipe_pipeline_is_content_free_and_correct() {
    // Build an input file. Each line is one read-chunk; run_pipe appends a
    // newline to every chunk, so each line is finalized as its own command.
    // Lines with a leading "<ns>\t" carry an explicit timestamp.
    //
    // We send three "commands":
    //   - "ls"           (single short command; chunk has 2 printable bytes)
    //   - "ls -la"       (a paste-like burst, 6 printable bytes)
    //   - "secret_value" (used to verify content never leaks)
    let secret = "secret_value";
    let input = format!("100\tls\n200\tls -la\n300\t{secret}\n");

    let dir = std::env::temp_dir();
    let path = dir.join(format!("plugin-tty-pipe-{}.txt", std::process::id()));
    tokio::fs::write(&path, input.as_bytes()).await.unwrap();

    let emitter = CapturingEmitter::default();
    let captured = emitter.events.clone();
    let salt = "integration-salt";

    plugin_tty::run_pipe_collector(
        path.clone(),
        Arc::new(emitter),
        "agent-test".to_string(),
        "tester:1".to_string(),
        AnalyzerConfig {
            hash_salt: salt.to_string(),
        },
    )
    .await
    .expect("pipe runtime should complete");

    let _ = tokio::fs::remove_file(&path).await;

    let events = captured.lock().unwrap().clone();

    // One Keystroke per read line, plus one CommandObserved per line.
    let ks = keystrokes(&events);
    assert_eq!(ks.len(), 3, "expected one keystroke per input line");
    // "ls" -> 2 printable bytes + newline = burst_len 3, paste (printable > 1).
    assert_eq!(ks[0], (true, 3));
    // "ls -la" -> 6 printable + newline = 7, paste.
    assert_eq!(ks[1], (true, 7));

    let cmds = commands(&events);
    assert_eq!(cmds.len(), 3, "expected three observed commands");

    // First command "ls": len 2, single token, no correction, distance-from-empty 2.
    match cmds[0] {
        EventPayload::CommandObserved {
            command_len,
            token_count,
            had_backspace,
            edit_distance_prev,
            inter_command_ns,
            ..
        } => {
            assert_eq!(*command_len, 2);
            assert_eq!(*token_count, 1);
            assert!(!*had_backspace);
            assert_eq!(*edit_distance_prev, 2);
            assert_eq!(*inter_command_ns, 0, "first command has no predecessor");
        }
        other => panic!("expected CommandObserved, got {other:?}"),
    }

    // Second command "ls -la": len 6, two tokens, edit distance from "ls" = 4
    // (append " -la"), think time 200 - 100 = 100ns.
    match cmds[1] {
        EventPayload::CommandObserved {
            command_len,
            token_count,
            edit_distance_prev,
            inter_command_ns,
            ..
        } => {
            assert_eq!(*command_len, 6);
            assert_eq!(*token_count, 2);
            assert_eq!(*edit_distance_prev, 4);
            assert_eq!(*inter_command_ns, 100);
        }
        other => panic!("expected CommandObserved, got {other:?}"),
    }

    // A SessionEnd is emitted at EOF.
    assert!(
        events
            .iter()
            .any(|e| matches!(e.payload, EventPayload::SessionEnd { .. })),
        "expected a SessionEnd at EOF"
    );

    // Content-free guarantee: the raw secret must not appear in ANY event JSON.
    for ev in &events {
        let json = serde_json::to_string(ev).unwrap();
        assert!(
            !json.contains(secret),
            "raw input content leaked into event JSON: {json}"
        );
        // The literal command text of the other lines must not leak either.
        assert!(!json.contains("ls -la"), "raw content leaked: {json}");
    }
}

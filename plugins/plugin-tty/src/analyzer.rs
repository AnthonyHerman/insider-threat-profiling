//! The pure, content-free behavioral analyzer.
//!
//! This module is the testable heart of the plugin. It has **no I/O, no async,
//! and no FFI**: it consumes timestamped chunks of raw input bytes and produces
//! [`EventPayload`] values carrying only *timing* and *structural statistics*
//! plus a salted hash — never the bytes themselves.
//!
//! ## Content-free invariant
//!
//! The analyzer reconstructs the current line in a transient buffer purely to
//! compute structural statistics (length, token count, entropy) and the edit
//! distance from the previous line. That buffer, and the single-line history
//! kept for edit distance, are held **only in process memory**, are never
//! emitted, and are discarded on [`Analyzer::on_session_end`]. The only things
//! that leave this module are counts, timing gaps, an edit distance, and the
//! salted command hash produced by [`plugin_session::command_stats`]. The unit
//! tests assert (by serializing every produced payload to JSON) that raw input
//! text never escapes.

use aegis_sdk::EventPayload;

use crate::levenshtein::levenshtein;

/// ASCII backspace.
const BS: u8 = 0x08;
/// ASCII delete (what most terminals send for the Backspace key).
const DEL: u8 = 0x7f;
/// Carriage return.
const CR: u8 = 0x0d;
/// Line feed.
const LF: u8 = 0x0a;

/// Static configuration for the analyzer.
#[derive(Debug, Clone)]
pub struct AnalyzerConfig {
    /// Per-deployment salt forwarded to [`plugin_session::command_stats`] so the
    /// correlation hash is unlinkable across deployments.
    pub hash_salt: String,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        AnalyzerConfig {
            // Matches plugin-session's default so hashes correlate by default.
            hash_salt: "aegis-default-salt".to_string(),
        }
    }
}

/// Maximum number of printable bytes the transient line buffer may accumulate
/// before it is silently truncated. This prevents unbounded heap growth from a
/// pathological pipe input or a user who pastes megabytes without pressing
/// Enter. The value is generous enough that no real command line ever hits it,
/// but it stops a runaway allocation.
const MAX_LINE_BUF: usize = 16_384;

/// Stateful, content-free analyzer for a single interactive session.
///
/// Drive it by feeding successive read-chunks to [`Analyzer::on_read`]; it
/// returns the events each chunk produces. Call [`Analyzer::on_session_end`]
/// when the session terminates to obtain the `SessionEnd` payload and drop all
/// transient line state.
pub struct Analyzer {
    session_id: String,
    cfg: AnalyzerConfig,

    /// Timestamp of the previous read, for keystroke inter-arrival timing.
    last_read_ns: Option<u64>,
    /// Timestamp the previous command finished, for inter-command think time.
    last_command_finish_ns: Option<u64>,

    /// Transient reconstruction of the line currently being typed. Used only to
    /// compute statistics, then cleared. **Never emitted.**
    line_buf: Vec<u8>,
    /// Whether a correction (backspace/delete) occurred while composing the
    /// current line. Reset when the line completes.
    had_backspace: bool,
    /// The previous completed line, kept solely to compute `edit_distance_prev`.
    /// Held only in memory, never emitted, dropped on session end.
    prev_line: String,
    /// Set when the most-recently processed terminator was CR. A \n that
    /// immediately follows is treated as the second half of a CRLF pair and
    /// suppressed, preventing a spurious empty `CommandObserved`.
    last_was_cr: bool,
}

impl Analyzer {
    /// Create an analyzer for the given session.
    pub fn new(session_id: impl Into<String>, cfg: AnalyzerConfig) -> Self {
        Analyzer {
            session_id: session_id.into(),
            cfg,
            last_read_ns: None,
            last_command_finish_ns: None,
            line_buf: Vec::new(),
            had_backspace: false,
            prev_line: String::new(),
            last_was_cr: false,
        }
    }

    /// The session id this analyzer reports under.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Consume one timestamped read-chunk of input bytes and return the events
    /// it produces: exactly one [`EventPayload::Keystroke`] followed by zero or
    /// more [`EventPayload::CommandObserved`] (one per line terminator seen in
    /// the chunk — normally zero or one).
    ///
    /// `now_ns` is taken as a parameter so callers (and tests) control the clock.
    pub fn on_read(&mut self, bytes: &[u8], now_ns: u64) -> Vec<EventPayload> {
        let mut out = Vec::new();

        // 1. Keystroke timing: gap since the previous read (0 for the first).
        let inter_arrival_ns = self
            .last_read_ns
            .map(|p| now_ns.saturating_sub(p))
            .unwrap_or(0);
        self.last_read_ns = Some(now_ns);

        // 2. Paste heuristic. A read that delivers more than one printable byte
        //    at once is treated as an atomic burst (paste / program-driven);
        //    a single byte is normal typing. `burst_len` is the chunk size.
        let printable = bytes
            .iter()
            .filter(|b| b.is_ascii_graphic() || **b == b' ')
            .count();
        let is_paste = printable > 1;
        let burst_len = bytes.len().max(1) as u32;
        out.push(EventPayload::Keystroke {
            session_id: self.session_id.clone(),
            inter_arrival_ns,
            is_paste,
            burst_len,
        });

        // 3. Update the transient line buffer byte-by-byte, finalizing a command
        //    on each line terminator.
        for &b in bytes {
            match b {
                DEL | BS => {
                    self.last_was_cr = false;
                    self.had_backspace = true;
                    self.line_buf.pop();
                }
                CR => {
                    self.last_was_cr = true;
                    out.push(self.finish_line(now_ns));
                }
                LF => {
                    if self.last_was_cr {
                        // This \n is the second half of a \r\n pair. Suppress
                        // it so we don't emit a spurious empty CommandObserved.
                        self.last_was_cr = false;
                    } else {
                        out.push(self.finish_line(now_ns));
                    }
                }
                _ if b.is_ascii_graphic() || b == b' ' => {
                    self.last_was_cr = false;
                    // Silently drop printable bytes beyond the cap so the buffer
                    // stays bounded even for pathological pipe inputs or huge pastes.
                    if self.line_buf.len() < MAX_LINE_BUF {
                        self.line_buf.push(b);
                    }
                }
                // Other control bytes are counted toward the keystroke chunk
                // length above but are not part of the reconstructed line.
                _ => {
                    self.last_was_cr = false;
                }
            }
        }

        out
    }

    /// Finalize the current line into a content-free [`EventPayload::CommandObserved`]
    /// and reset per-line transient state.
    fn finish_line(&mut self, now_ns: u64) -> EventPayload {
        // Reconstruct the line transiently for statistics only.
        let line = String::from_utf8_lossy(&self.line_buf).into_owned();

        // Reuse plugin-session's helper for length/tokens/entropy/hash so the
        // two collectors agree and we never duplicate the hashing logic.
        let stats = plugin_session::command_stats(&line, &self.cfg.hash_salt);

        let edit_distance_prev = levenshtein(&self.prev_line, &line) as u32;

        let inter_command_ns = self
            .last_command_finish_ns
            .map(|p| now_ns.saturating_sub(p))
            .unwrap_or(0);
        self.last_command_finish_ns = Some(now_ns);

        let had_backspace = self.had_backspace;

        // Retain only the line text for the next edit-distance computation;
        // discard the working buffer and reset per-line flags.
        self.prev_line = line;
        self.line_buf.clear();
        self.had_backspace = false;
        // last_was_cr is managed by the caller (on_read byte loop), not here.

        EventPayload::CommandObserved {
            session_id: self.session_id.clone(),
            command_len: stats.command_len,
            token_count: stats.token_count,
            shannon_entropy: stats.shannon_entropy,
            had_backspace,
            edit_distance_prev,
            inter_command_ns,
            command_hash: stats.command_hash,
        }
    }

    /// End the session: drop all transient line state and return the
    /// [`EventPayload::SessionEnd`] payload to emit.
    pub fn on_session_end(&mut self) -> EventPayload {
        self.line_buf.clear();
        self.prev_line.clear();
        self.had_backspace = false;
        self.last_was_cr = false;
        EventPayload::SessionEnd {
            session_id: self.session_id.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_session::command_stats;

    const SALT: &str = "unit-test-salt";

    fn analyzer() -> Analyzer {
        Analyzer::new(
            "user:1234",
            AnalyzerConfig {
                hash_salt: SALT.to_string(),
            },
        )
    }

    /// Extract the single Keystroke that every `on_read` produces first.
    fn keystroke(evs: &[EventPayload]) -> (u64, bool, u32) {
        match &evs[0] {
            EventPayload::Keystroke {
                inter_arrival_ns,
                is_paste,
                burst_len,
                ..
            } => (*inter_arrival_ns, *is_paste, *burst_len),
            other => panic!("expected Keystroke first, got {other:?}"),
        }
    }

    fn commands(evs: &[EventPayload]) -> Vec<&EventPayload> {
        evs.iter()
            .filter(|e| matches!(e, EventPayload::CommandObserved { .. }))
            .collect()
    }

    #[test]
    fn single_printable_byte_is_typed_not_paste() {
        let mut a = analyzer();
        let evs = a.on_read(b"l", 1000);
        let (_, is_paste, burst_len) = keystroke(&evs);
        assert!(!is_paste);
        assert_eq!(burst_len, 1);
        assert_eq!(evs.len(), 1, "no command without a line terminator");
    }

    #[test]
    fn multibyte_read_is_a_paste_burst() {
        let mut a = analyzer();
        let evs = a.on_read(b"ls -la", 1000);
        let (_, is_paste, burst_len) = keystroke(&evs);
        assert!(is_paste);
        assert_eq!(burst_len, 6);
    }

    #[test]
    fn lone_control_byte_is_not_a_paste() {
        let mut a = analyzer();
        // A single carriage return: 1 byte, not printable -> not a paste.
        let evs = a.on_read(b"\r", 1000);
        let (_, is_paste, burst_len) = keystroke(&evs);
        assert!(!is_paste);
        assert_eq!(burst_len, 1);
    }

    #[test]
    fn inter_arrival_is_gap_between_reads_first_is_zero() {
        let mut a = analyzer();
        let (gap0, _, _) = keystroke(&a.on_read(b"a", 1_000));
        assert_eq!(gap0, 0, "first read has no predecessor");
        let (gap1, _, _) = keystroke(&a.on_read(b"b", 1_500));
        assert_eq!(gap1, 500);
        let (gap2, _, _) = keystroke(&a.on_read(b"c", 3_000));
        assert_eq!(gap2, 1_500);
    }

    #[test]
    fn typing_a_command_finalizes_on_carriage_return() {
        let mut a = analyzer();
        a.on_read(b"l", 1);
        a.on_read(b"s", 2);
        let evs = a.on_read(b"\r", 3);
        let cmds = commands(&evs);
        assert_eq!(cmds.len(), 1);
        let want = command_stats("ls", SALT);
        match cmds[0] {
            EventPayload::CommandObserved {
                command_len,
                token_count,
                shannon_entropy,
                command_hash,
                had_backspace,
                ..
            } => {
                assert_eq!(*command_len, 2);
                assert_eq!(*token_count, 1);
                assert_eq!(*command_len, want.command_len);
                assert_eq!(*command_hash, want.command_hash);
                assert!((*shannon_entropy - want.shannon_entropy).abs() < 1e-12);
                assert!(!*had_backspace);
            }
            other => panic!("expected CommandObserved, got {other:?}"),
        }
    }

    #[test]
    fn line_feed_also_finalizes() {
        let mut a = analyzer();
        let evs = a.on_read(b"pwd\n", 10);
        let cmds = commands(&evs);
        assert_eq!(cmds.len(), 1);
        if let EventPayload::CommandObserved { command_len, .. } = cmds[0] {
            assert_eq!(*command_len, 3);
        }
    }

    #[test]
    fn backspace_sets_flag_and_edits_the_buffer() {
        let mut a = analyzer();
        // Type "lx", delete the 'x', type 's', then enter -> "ls".
        a.on_read(b"l", 1);
        a.on_read(b"x", 2);
        a.on_read(&[DEL], 3);
        a.on_read(b"s", 4);
        let evs = a.on_read(b"\r", 5);
        let cmds = commands(&evs);
        assert_eq!(cmds.len(), 1);
        let want = command_stats("ls", SALT);
        match cmds[0] {
            EventPayload::CommandObserved {
                command_len,
                command_hash,
                had_backspace,
                ..
            } => {
                assert!(*had_backspace, "correction must be recorded");
                assert_eq!(*command_len, 2, "deleted char must be gone");
                // Hash must equal that of the *edited* line "ls", proving the
                // 'x' was removed from the reconstruction.
                assert_eq!(*command_hash, want.command_hash);
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn backspace_flag_resets_between_commands() {
        let mut a = analyzer();
        a.on_read(b"a", 1);
        a.on_read(&[BS], 2);
        a.on_read(b"b", 3);
        let first = a.on_read(b"\r", 4);
        assert!(matches!(
            commands(&first)[0],
            EventPayload::CommandObserved {
                had_backspace: true,
                ..
            }
        ));
        // Next command has no correction.
        a.on_read(b"c", 5);
        let second = a.on_read(b"\r", 6);
        assert!(matches!(
            commands(&second)[0],
            EventPayload::CommandObserved {
                had_backspace: false,
                ..
            }
        ));
    }

    #[test]
    fn edit_distance_to_previous_command() {
        let mut a = analyzer();
        // First command "ls" -> distance from empty prev = len("ls") = 2.
        let first = a.on_read(b"ls\r", 1);
        if let EventPayload::CommandObserved {
            edit_distance_prev, ..
        } = commands(&first)[0]
        {
            assert_eq!(*edit_distance_prev, 2);
        }
        // Second command "ls -l" -> distance from "ls" = 3.
        let second = a.on_read(b"ls -l\r", 2);
        if let EventPayload::CommandObserved {
            edit_distance_prev, ..
        } = commands(&second)[0]
        {
            assert_eq!(*edit_distance_prev, 3);
        }
    }

    #[test]
    fn identical_consecutive_commands_have_zero_distance() {
        let mut a = analyzer();
        a.on_read(b"whoami\r", 1);
        let again = a.on_read(b"whoami\r", 2);
        if let EventPayload::CommandObserved {
            edit_distance_prev, ..
        } = commands(&again)[0]
        {
            assert_eq!(*edit_distance_prev, 0);
        }
    }

    #[test]
    fn inter_command_timing_is_finish_to_finish_first_is_zero() {
        let mut a = analyzer();
        let first = a.on_read(b"a\r", 100);
        if let EventPayload::CommandObserved {
            inter_command_ns, ..
        } = commands(&first)[0]
        {
            assert_eq!(*inter_command_ns, 0, "first command has no predecessor");
        }
        let second = a.on_read(b"b\r", 450);
        if let EventPayload::CommandObserved {
            inter_command_ns, ..
        } = commands(&second)[0]
        {
            assert_eq!(*inter_command_ns, 350);
        }
    }

    #[test]
    fn chunk_with_terminator_yields_keystroke_then_command() {
        let mut a = analyzer();
        let evs = a.on_read(b"id\r", 1);
        assert!(matches!(evs[0], EventPayload::Keystroke { .. }));
        assert!(matches!(evs[1], EventPayload::CommandObserved { .. }));
        assert_eq!(evs.len(), 2);
    }

    #[test]
    fn session_end_drops_state_and_returns_payload() {
        let mut a = analyzer();
        a.on_read(b"secret", 1);
        let end = a.on_session_end();
        match end {
            EventPayload::SessionEnd { session_id } => assert_eq!(session_id, "user:1234"),
            other => panic!("got {other:?}"),
        }
        // After end, edit distance restarts from empty prev_line.
        let evs = a.on_read(b"x\r", 2);
        if let EventPayload::CommandObserved {
            edit_distance_prev, ..
        } = commands(&evs)[0]
        {
            assert_eq!(*edit_distance_prev, 1);
        }
    }

    /// The central privacy guarantee: no produced payload, serialized to JSON,
    /// ever contains the raw input text.
    #[test]
    fn produced_events_are_content_free() {
        let mut a = analyzer();
        let secret = "rm -rf /very/secret/path";
        let mut all = Vec::new();
        for &b in secret.as_bytes() {
            all.extend(a.on_read(&[b], 1));
        }
        all.extend(a.on_read(b"\r", 2));
        all.push(a.on_session_end());

        for ev in &all {
            let json = serde_json::to_string(ev).unwrap();
            assert!(
                !json.contains("secret"),
                "raw content leaked into event JSON: {json}"
            );
            assert!(!json.contains("rm -rf"), "raw content leaked: {json}");
        }
        // Sanity: a command was actually observed (so the test isn't vacuous).
        assert!(all
            .iter()
            .any(|e| matches!(e, EventPayload::CommandObserved { .. })));
    }

    /// CRLF (\r\n) in a single chunk must produce exactly one CommandObserved,
    /// not two. The \n that follows a \r must be suppressed (CRLF-pair collapse).
    #[test]
    fn crlf_in_single_chunk_yields_one_command() {
        let mut a = analyzer();
        // "ls\r\n" in one read: CR finalizes "ls"; the LF immediately following
        // must be swallowed, not produce a second (empty) CommandObserved.
        let evs = a.on_read(b"ls\r\n", 1);
        let cmds = commands(&evs);
        assert_eq!(
            cmds.len(),
            1,
            "CRLF must yield exactly one command, got {}",
            cmds.len()
        );
        if let EventPayload::CommandObserved { command_len, .. } = cmds[0] {
            assert_eq!(*command_len, 2, "should be 'ls' (2 chars)");
        }
    }

    /// A \r followed by a \n in *separate* reads must still produce two commands
    /// (the \r finalizes the first; the \n in the next read is not the second
    /// half of a CRLF pair because a new read chunk intervened).
    #[test]
    fn cr_then_lf_in_separate_reads_yields_two_commands() {
        let mut a = analyzer();
        // First command: "ls" followed by bare CR.
        let evs1 = a.on_read(b"ls\r", 1);
        assert_eq!(commands(&evs1).len(), 1, "CR should finalize first command");
        // Second command: "pwd" with a bare LF. The inter-read interval means
        // the LF is NOT the tail of a CRLF pair; it finalizes its own command.
        let evs2 = a.on_read(b"pwd\n", 2);
        assert_eq!(
            commands(&evs2).len(),
            1,
            "LF should finalize second command"
        );
    }

    /// The line buffer must be truncated at MAX_LINE_BUF and must not panic.
    #[test]
    fn line_buf_is_bounded_at_max_line_buf() {
        let mut a = analyzer();
        // Feed MAX_LINE_BUF + 1000 printable bytes without a terminator.
        let big = vec![b'a'; MAX_LINE_BUF + 1000];
        let evs = a.on_read(&big, 1);
        // No terminator: one Keystroke, zero commands.
        assert_eq!(evs.len(), 1);
        assert!(matches!(evs[0], EventPayload::Keystroke { .. }));
        // Now finalize with a CR. The resulting command must have length == MAX_LINE_BUF.
        let fin = a.on_read(b"\r", 2);
        let cmds = commands(&fin);
        assert_eq!(cmds.len(), 1);
        if let EventPayload::CommandObserved { command_len, .. } = cmds[0] {
            assert_eq!(
                *command_len, MAX_LINE_BUF as u32,
                "command_len must be capped at MAX_LINE_BUF"
            );
        }
    }
}

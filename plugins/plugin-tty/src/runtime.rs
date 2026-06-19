//! I/O drivers that feed the pure [`Analyzer`] and emit onto the event bus.
//!
//! Two runtimes share the same content-free analyzer:
//!
//! * [`run_pipe`] — reads timestamped input chunks from a fifo/file. This makes
//!   the whole pipeline (analyzer -> events -> bus) exercisable in CI with **no
//!   real terminal**.
//! * [`run_shell`] — runs the user's `$SHELL` inside a real PTY (via `forkpty`),
//!   puts the controlling terminal in raw mode, and pumps bytes both ways. Only
//!   *input* bytes are analyzed for timing/structure; shell *output* is passed
//!   through untouched and never inspected (content-free).
//!
//! The PTY path is impure (FFI + a real terminal) and is therefore not unit
//! tested; correctness lives in [`crate::analyzer`] and the `run_pipe`
//! integration test.

use std::path::PathBuf;
use std::sync::Arc;

use aegis_sdk::{now_ns, Emitter, Event, EventPayload};

use crate::analyzer::{Analyzer, AnalyzerConfig};

/// Source name stamped on every event this plugin emits.
const SOURCE: &str = "plugin-tty";

/// Build an [`Event`] from a payload and publish it on the bus.
pub async fn pump_event(emitter: &Arc<dyn Emitter>, agent_id: &str, payload: EventPayload) {
    emitter.emit(Event::new(agent_id, SOURCE, payload)).await;
}

// ---------------------------------------------------------------------------
// (a) Pipe mode — CI-testable, no TTY required.
// ---------------------------------------------------------------------------

/// Read timestamped input chunks from `path` (a fifo or regular file) and drive
/// the analyzer, emitting every resulting event.
///
/// Each input line is one of:
///
/// * `"<ns>\t<chunk>"` — an explicit timestamp (nanoseconds) and the raw chunk
///   bytes (the remainder of the line, verbatim). A trailing newline is
///   appended to the chunk so it terminates the reconstructed command exactly
///   as a real terminal Enter would.
/// * `"<chunk>"` — no tab: the timestamp is taken from [`now_ns`] and the chunk
///   is the line bytes plus a trailing newline.
///
/// The function returns when the input reaches EOF, after emitting a final
/// [`EventPayload::SessionEnd`].
pub async fn run_pipe(
    path: PathBuf,
    emitter: Arc<dyn Emitter>,
    agent_id: String,
    session_id: String,
    cfg: AnalyzerConfig,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncBufReadExt, BufReader};

    let file = tokio::fs::File::open(&path).await?;
    let mut lines = BufReader::new(file).lines();

    // Register the session up front. Pipe mode has no PTY login event, and
    // downstream processors (agent-detect) deliberately DROP telemetry for any
    // session they never saw start — so without our own SessionStart the
    // keystrokes/commands are discarded unless some other plugin happens to emit
    // a SessionStart with an identical session_id. Emitting it here makes the
    // collector self-sufficient. Content-free: only the session id + user.
    pump_event(
        &emitter,
        &agent_id,
        EventPayload::SessionStart {
            session_id: session_id.clone(),
            tty: None,
            user: std::env::var("USER").unwrap_or_else(|_| "unknown".into()),
            remote: None,
        },
    )
    .await;

    let mut analyzer = Analyzer::new(session_id, cfg);

    while let Some(line) = lines.next_line().await? {
        let (ts, chunk) = parse_pipe_line(&line);
        for payload in analyzer.on_read(&chunk, ts) {
            pump_event(&emitter, &agent_id, payload).await;
        }
    }

    pump_event(&emitter, &agent_id, analyzer.on_session_end()).await;
    Ok(())
}

/// Parse one pipe-mode line into a `(timestamp_ns, chunk_bytes)` pair. A
/// trailing newline is always appended so the chunk finalizes a command.
fn parse_pipe_line(line: &str) -> (u64, Vec<u8>) {
    if let Some((ts_str, rest)) = line.split_once('\t') {
        if let Ok(ts) = ts_str.trim().parse::<u64>() {
            let mut chunk = rest.as_bytes().to_vec();
            chunk.push(b'\n');
            return (ts, chunk);
        }
    }
    let mut chunk = line.as_bytes().to_vec();
    chunk.push(b'\n');
    (now_ns(), chunk)
}

// ---------------------------------------------------------------------------
// (b) Shell / PTY mode — real interactive terminal.
// ---------------------------------------------------------------------------

/// An owned raw file descriptor that is `close(2)`d on drop.
struct OwnedFd(libc::c_int);

impl Drop for OwnedFd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            // SAFETY: we own this fd and close it exactly once on drop.
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

/// Restores the saved terminal attributes on `fd` when dropped. This is what
/// guarantees the user's terminal is not left in raw mode on any exit path
/// (normal return, error, or panic).
struct TermiosGuard {
    fd: libc::c_int,
    orig: libc::termios,
}

impl Drop for TermiosGuard {
    fn drop(&mut self) {
        // SAFETY: `orig` was captured from this same fd; restoring is safe.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.orig);
        }
    }
}

/// Run an instrumented interactive shell.
///
/// Spawns the user's `$SHELL` (falling back to `/bin/sh`) inside a freshly
/// allocated PTY, mirrors the parent terminal size, switches the controlling
/// terminal to raw mode, and pumps bytes in both directions. Input bytes are
/// fed to the analyzer (timing/structure only) before being forwarded to the
/// shell; shell output is forwarded to the user's terminal and never inspected.
///
/// This call is **blocking** and runs its own internal pump loop; callers should
/// run it on a dedicated thread or via `spawn_blocking`. It returns when the
/// shell exits.
pub fn run_shell(
    emitter: Arc<dyn Emitter>,
    agent_id: String,
    session_id: String,
    cfg: AnalyzerConfig,
) -> anyhow::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let shell = std::env::var_os("SHELL")
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| std::ffi::OsString::from("/bin/sh"));

    // Build a NUL-terminated argv: [shell, NULL].
    let shell_c = std::ffi::CString::new(shell.as_bytes())
        .map_err(|_| anyhow::anyhow!("shell path contains an interior NUL byte"))?;
    let argv: [*const libc::c_char; 2] = [shell_c.as_ptr(), std::ptr::null()];

    // Snapshot the parent terminal size so the child PTY matches it.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: TIOCGWINSZ writes a winsize through the pointer; ignore failure
    // (e.g. when stdin is not a tty) and fall back to the zeroed struct.
    unsafe {
        libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws);
    }

    let mut master_fd: libc::c_int = -1;
    // SAFETY: forkpty allocates a pty pair, forks, and in the child sets up the
    // slave as the controlling terminal (login_tty). All pointers are valid.
    let pid = unsafe { libc::forkpty(&mut master_fd, std::ptr::null_mut(), std::ptr::null(), &ws) };

    if pid < 0 {
        return Err(anyhow::anyhow!(
            "forkpty failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    if pid == 0 {
        // ---- Child: become the shell. ----
        // forkpty already called login_tty (setsid + dup of the slave onto
        // 0/1/2), so we just exec the shell on its controlling pty.
        // SAFETY: argv is NUL-terminated and points to a live CString.
        unsafe {
            libc::execvp(shell_c.as_ptr(), argv.as_ptr());
            // execvp only returns on failure.
            libc::_exit(127);
        }
    }

    // ---- Parent: own the master fd and drive the pumps. ----
    let master = OwnedFd(master_fd);

    // Switch the controlling terminal to raw mode, saving the original attrs so
    // the RAII guard can restore them on every exit path.
    let _termios_guard = enter_raw_mode(libc::STDIN_FILENO);

    // Best-effort SessionStart (mirrors plugin-session's field shape).
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
    let tty = std::env::var("SSH_TTY")
        .or_else(|_| std::env::var("TTY"))
        .ok();
    block_on_emit(
        &emitter,
        &agent_id,
        EventPayload::SessionStart {
            session_id: session_id.clone(),
            tty,
            user,
            remote: None,
        },
    );

    let mut analyzer = Analyzer::new(session_id, cfg);

    pump_loop(master.0, &mut analyzer, &emitter, &agent_id);

    // Reap the child and emit SessionEnd. The termios guard restores the
    // terminal when it drops at end of scope.
    // SAFETY: standard waitpid on our child pid.
    unsafe {
        let mut status: libc::c_int = 0;
        libc::waitpid(pid, &mut status, 0);
    }
    block_on_emit(&emitter, &agent_id, analyzer.on_session_end());

    Ok(())
}

/// Put `fd` into raw mode, returning a guard that restores the prior attributes
/// on drop. Returns `None` (no guard, no change) if `fd` is not a terminal.
fn enter_raw_mode(fd: libc::c_int) -> Option<TermiosGuard> {
    let mut orig: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: tcgetattr fills `orig`; a non-zero return means fd isn't a tty.
    if unsafe { libc::tcgetattr(fd, &mut orig) } != 0 {
        return None;
    }
    let mut raw = orig;
    // SAFETY: cfmakeraw mutates the termios struct in place.
    unsafe {
        libc::cfmakeraw(&mut raw);
        libc::tcsetattr(fd, libc::TCSANOW, &raw);
    }
    Some(TermiosGuard { fd, orig })
}

/// Bidirectional pump between the user's terminal and the shell's PTY master.
///
/// Uses `poll(2)` to wait on both `STDIN_FILENO` (user input) and `master`
/// (shell output). User input is analyzed (timing/structure) and forwarded to
/// the shell; shell output is forwarded to the terminal only. Returns when the
/// master reports EOF/HUP or stdin closes.
fn pump_loop(
    master: libc::c_int,
    analyzer: &mut Analyzer,
    emitter: &Arc<dyn Emitter>,
    agent_id: &str,
) {
    let mut fds = [
        libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: master,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let mut buf = [0u8; 4096];

    loop {
        // SAFETY: fds points to a valid array of 2 pollfds; -1 blocks forever.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue; // EINTR: retry.
            }
            break;
        }

        // User input -> analyze -> forward to shell.
        if fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            // SAFETY: reading into our buffer; n in [0, len].
            let n = unsafe {
                libc::read(
                    libc::STDIN_FILENO,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n <= 0 {
                break;
            }
            let ts = now_ns();
            let chunk = &buf[..n as usize];
            for payload in analyzer.on_read(chunk, ts) {
                block_on_emit(emitter, agent_id, payload);
            }
            write_all(master, chunk);
        }

        // Shell output -> forward to terminal (never inspected).
        if fds[1].revents & libc::POLLIN != 0 {
            // SAFETY: reading from the master into our buffer.
            let n = unsafe { libc::read(master, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n <= 0 {
                break; // EOF or error on the master: the shell has exited.
            }
            write_all(libc::STDOUT_FILENO, &buf[..n as usize]);
        }

        // Master hung up: shell exited.
        if fds[1].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            break;
        }
    }
}

/// Write the whole buffer to `fd`, retrying short writes and ignoring EINTR.
fn write_all(fd: libc::c_int, mut data: &[u8]) {
    while !data.is_empty() {
        // SAFETY: writing `data.len()` bytes from a valid slice to an owned fd.
        let n = unsafe { libc::write(fd, data.as_ptr() as *const libc::c_void, data.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if n == 0 {
            break;
        }
        data = &data[n as usize..];
    }
}

/// Emit an event from a blocking (non-async) context by driving the async
/// emitter to completion on the current thread.
fn block_on_emit(emitter: &Arc<dyn Emitter>, agent_id: &str, payload: EventPayload) {
    let event = Event::new(agent_id, SOURCE, payload);
    futures::executor::block_on(emitter.emit(event));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_explicit_timestamp_line() {
        let (ts, chunk) = parse_pipe_line("1500\tls -la");
        assert_eq!(ts, 1500);
        assert_eq!(chunk, b"ls -la\n");
    }

    #[test]
    fn parse_plain_line_appends_newline() {
        let (_, chunk) = parse_pipe_line("whoami");
        assert_eq!(chunk, b"whoami\n");
    }

    #[test]
    fn parse_non_numeric_prefix_is_treated_as_plain() {
        // No valid numeric timestamp before the tab -> whole line is the chunk.
        let (_, chunk) = parse_pipe_line("notanumber\tdata");
        assert_eq!(chunk, b"notanumber\tdata\n");
    }
}

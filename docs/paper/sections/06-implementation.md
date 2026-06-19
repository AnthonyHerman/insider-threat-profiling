## Implementation & Assurance

### Workspace Structure

Aegis is implemented as a Rust workspace of fifteen crates — eight
infrastructure/binary crates and seven plugins — organized into three layers. The
foundation layer consists of `aegis-sdk`, which defines the stable public contracts
— the `Event` model and the `Plugin` trait with its inventory-based registration
macro — and `aegis-core`, the kernel that discovers plugins, manages their
lifecycle, and routes events over a single internal bus. `aegis-proto` sits
alongside these two, specifying the length-framed, versioned wire protocol used
between agent and server. Two more crates support development and testing —
`aegis-integration-tests` (the in-process end-to-end pipeline tests) and
`example-plugin` (a reference dynamic `cdylib` plugin). Neither `aegis-sdk` nor
`aegis-core` implements any behavioral feature; they are deliberately thin so that
all domain logic lives in plugins.

The binary layer contains three executables: `aegis-agent` (the endpoint client),
`aegisd` (the server), and `aegisctl` (the management CLI). The agent embeds every
plugin it uses at link time via the `inventory` static discovery mechanism, so
there is no runtime asset directory and no external plugin resolver to compromise.
The server follows the same discipline for its own plugins.

The plugin layer provides all operational capability as seven crates:
`plugin-process` (process-execution telemetry), `plugin-session` (session lifecycle
and the content-free command-statistics helpers), `plugin-tty` (PTY/pipe
keystroke- and command-timing capture, content-free), `plugin-agent-detect` (the
flagship agent-vs-human classifier, described in Sections 3–5), `plugin-scoring`
(per-subject risk aggregation and alerting), `plugin-tamper` (endpoint
self-protection), and `plugin-transport` (the mTLS forwarder sink). The kernel
dispatches events to subscribers by kind string;
plugins declare subscriptions in their `Plugin` implementation and never hold a
reference to any other plugin, making the dependency graph explicit and the
system incrementally extensible without modifying core [karantzas2021edr].

### Self-Contained Server Binary

A practical deployment concern for any security monitoring product is the
complexity of the server itself: external databases, runtime configuration
directories, and shared libraries each represent an additional attack surface and
operational dependency. `aegisd` is designed as a single, statically-linked
binary that carries its complete runtime inside itself. Persistence uses an
embedded `redb` key-value store compiled directly into the server; the operator
dashboard is bundled as a Rust byte literal at build time; and there are no
dynamically loaded libraries beyond what the musl C library provides — and the
musl build eliminates even that.

The static build targets `x86_64-unknown-linux-musl`. Because the TLS stack
(`rustls` and `ring`) requires C compilation for assembly routines, the CI job
installs `musl-tools` to provide `musl-gcc`; the development documentation
(`docs/BUILD.md`) describes the same prerequisite for local builds. The result is
a binary that `ldd` reports as "statically linked," deployable by a single `scp`
without installing a runtime, linking against system libraries, or running a
package manager on the target host. The backup strategy is correspondingly simple:
copy the `redb` database file.

The decision to compile with `--locked` throughout (both CI jobs enforce this)
means the exact dependency tree recorded in `Cargo.lock` is what is built, and
any uncommitted change to a transitive dependency causes a build failure rather
than a silent drift. This is a lightweight but meaningful supply-chain hygiene
measure for a security product [aucsmith1996tamper].

### Continuous Integration

The CI pipeline (`.github/workflows/ci.yml`) runs two jobs on every push to
`main` and on every pull request.

The first job, `fmt + clippy + test`, enforces uniform formatting with
`cargo fmt --all -- --check`, then runs `cargo clippy --workspace --all-targets
-- -D warnings`, treating every Clippy diagnostic as a build error. Clippy
catches a class of defects — integer overflow in debug arithmetic, unguarded
`unwrap` on fallible paths, needless clones — that would otherwise survive to
review. The job then builds the full workspace and runs `cargo test --workspace
--locked`. The Rust toolchain version is pinned in `rust-toolchain.toml`
(Rust 1.92); the `rustup show` step at the start of the job makes the resolved
version visible in the CI log.

The second job, `self-contained server (static musl)`, installs `musl-tools`,
adds the `x86_64-unknown-linux-musl` target, and builds `aegisd` with
`--release --locked`. It then explicitly verifies the binary's link character:

```
ldd "$BIN" 2>&1 | grep -qiE "not a dynamic executable|statically linked"
```

If that check fails, the job exits with a non-zero status, which blocks the pull
request. The static binary is uploaded as a CI artifact (`aegisd-static-x86_64-musl`)
on every passing run, giving reviewers a reproducible build to inspect without
local toolchain setup.

A shared `Swatinem/rust-cache@v2` action (with a separate cache key for the musl
job) reduces cold-build time and makes the dependency state explicit rather than
re-downloaded per run.

### Adversarially-Verified Security Audit

Because Aegis is itself a security product — one that runs privileged, holds
endpoint credentials, and sees sensitive behavioral telemetry about users — the
bar for its own hygiene is higher than for a typical research artifact. Before the
paper was finalized, the full workspace was subjected to a structured security
audit using a two-phase methodology.

Phase 1 partitioned the workspace into five domains: transport and cryptography,
server ingest and enrollment, detection integrity, tamper resistance, and the core
plugin loader. Each domain was read for memory-safety defects, resource-exhaustion
paths, authentication and authorization gaps, confidentiality failures, and
logic errors, with particular attention to the trust boundaries that matter for
an insider-threat deployment: agent-to-server network, local-user-to-agent on the
monitored host, and plugin-to-host inside the process.

Phase 2 subjected every candidate finding to adversarial verification: each was
re-checked against the exact source with a hostile reading — *Is the code path
reachable? Is the claimed primitive real? Is the severity justified or inflated?*
Findings that did not survive this pass were discarded. Severities that the code
did not support were adjusted: two findings proposed at medium were downgraded to
low (a privilege-gate real-uid check and an installer symlink-follow, both
requiring non-default invocation), and one low finding was upgraded to medium
(stale index entries in the `events_by_agent` secondary index silently corrupt the
operator-facing pagination API). No finding in the final report is a false
positive.

The audit confirmed 28 findings: 7 high, 10 medium, and 11 low. The most
structurally significant concern is the dynamic plugin loader (findings H5–H7):
`.so` plugins are currently `dlopen`ed with no integrity, signature, or ownership
verification, and a disabled plugin's constructor still executes before the
enable check runs — an arbitrary native-code-execution surface inside the very
component meant to detect an insider. Additional high-severity findings document
that short-session `NaN` feature values silently drop Detection events from the
audit log (H4), that the spill-to-disk buffer never enforces its configured size
cap on the main enrolled path (H1), and that the spill database is created
world-readable while the agent's own key material is locked to 0600 (H2). The
full findings table, per-finding rationale, and a prioritized remediation backlog
are in `docs/security-audit.md`.

The audit's methodology — parallel domain coverage followed by an adversarial
per-finding verification pass — is explicitly designed to prevent the inflated
severity counts that result when candidate findings are accepted without hostile
re-examination. For a research prototype whose threat model spans both the
endpoint and the server, this two-pass approach provides stronger assurance than
a single-pass reading, even if it does not substitute for a formal third-party
audit in a production deployment [cappelli2012cert].

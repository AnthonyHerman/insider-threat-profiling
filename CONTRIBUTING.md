# Contributing to Aegis

Thanks for your interest in Aegis — a plugin-native, client/server behavioral
threat-modeling platform. This document covers how to build and test the
workspace, what CI enforces, the repository layout, commit/PR norms, and the
project ethos that every change is expected to respect.

If you are writing a plugin, read [`docs/PLUGINS.md`](docs/PLUGINS.md). For
deployment and the static-binary story, read [`docs/BUILD.md`](docs/BUILD.md).
For what "tamper-resistant" actually guarantees, read
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Project ethos

These are not style preferences; they are design invariants. A change that
violates one of them will be sent back regardless of how well it is written.

- **The kernel has no features.** `aegis-core` knows how to load plugins, route
  [`Event`](crates/aegis-sdk/src/event.rs)s between them, and manage their
  lifecycle — nothing else. Telemetry collection, agent-vs-human detection, risk
  scoring, persistence, transport, and even endpoint self-protection are all
  plugins. **Adding a capability must never require editing the core.** If you
  find yourself wanting to teach `aegis-core` about a specific event kind or a
  specific feature, that logic almost certainly belongs in a plugin instead.
- **Everything is a plugin.** New functionality arrives as a crate implementing
  the [`Plugin`](crates/aegis-sdk/src/plugin.rs) trait, discovered either
  statically (via `register_plugin!`/`inventory`) or dynamically (via the C-ABI
  `cdylib`). The kernel treats a built-in collector and a third-party shared
  object identically once loaded.
- **Content-free telemetry.** Behavioral telemetry intentionally never captures
  *content*. [`EventPayload::Keystroke`](crates/aegis-sdk/src/event.rs) carries
  only inter-arrival timing, a paste/typed flag, and burst length — never the
  characters typed. [`EventPayload::CommandObserved`](crates/aegis-sdk/src/event.rs)
  carries structural statistics (length, token count, Shannon entropy, edit
  distance, think-time) and a *salted hash* for correlation — never the command
  text. Do not add a payload, label, or log line that records what a user typed,
  ran, or saw. This constraint is load-bearing for the project's privacy claims.
- **Ethical tamper resistance.** The agent defends its own integrity, but there
  is a deliberate, documented root escape hatch (`aegis-agent uninstall` as
  root). Tamper resistance raises the cost of covert subversion and makes
  tampering *observable*; it is explicitly **not** a mechanism for trapping a
  legitimate machine owner or hiding the agent's presence. Keep changes on the
  right side of that line — see `docs/THREAT_MODEL.md`.

## Prerequisites

- Rust, pinned by [`rust-toolchain.toml`](rust-toolchain.toml) to **1.92.0**
  with the `rustfmt` and `clippy` components. `rustup` will install the pinned
  toolchain automatically when you build in the repo.
- For the static server build: the musl target
  (`rustup target add x86_64-unknown-linux-musl`, also declared in the toolchain
  file) and a C toolchain that targets musl for `ring` (CI installs
  `musl-tools`, which provides `musl-gcc`).

## Build, test, lint, format

The workspace is the unit of work; run everything with `--workspace`.

```bash
# Build everything (all crates + plugins).
cargo build --workspace

# Run the full test suite (unit + integration).
cargo test --workspace

# Lint with warnings treated as errors — this is what CI runs.
cargo clippy --workspace --all-targets -- -D warnings

# Check formatting (CI uses --check; drop it to format in place).
cargo fmt --all -- --check
cargo fmt --all
```

Before opening a PR, run all four locally. The clippy and fmt invocations above
are exactly the ones CI runs, so matching them locally avoids round-trips.

A few useful targeted commands while developing:

```bash
# List the plugins the kernel discovers (proves the plugin-native core).
cargo run --bin aegisctl -- plugins

# Build only one plugin/crate.
cargo build -p plugin-scoring

# Build the example dynamic plugin as a cdylib (libexample_plugin.so).
cargo build -p example-plugin
```

## Continuous integration

CI is defined in [`.github/workflows/ci.yml`](.github/workflows/ci.yml) and runs
on every push to `main`, every pull request, and on manual dispatch. There are
two jobs; **both must be green** to merge.

1. **`fmt + clippy + test`** (the `test` job), in order:
   - `cargo fmt --all -- --check` — formatting must already be applied.
   - `cargo clippy --workspace --all-targets -- -D warnings` — **zero warnings**;
     any clippy lint fails the build.
   - `cargo build --workspace --locked` — must build with the committed
     `Cargo.lock` (no implicit dependency updates).
   - `cargo test --workspace --locked` — the whole test suite must pass.
2. **`self-contained server (static musl)`** (the `static-server` job): builds
   the server as a fully static binary and *verifies* it is self-contained.
   - `cargo build --release --bin aegisd --target x86_64-unknown-linux-musl --locked`
   - The job then runs `ldd` on the resulting `aegisd` and **fails** unless the
     binary reports "statically linked" / "not a dynamic executable", then
     uploads it as an artifact. `aegisd` is meant to ship as one static binary
     with an embedded `redb` store and embedded dashboard assets and no runtime
     asset directory — keep it that way. Pulling in a dependency that forces a
     dynamic libc (or otherwise breaks the musl static build) will fail this job.

Because both jobs pass `--locked`, commit an updated `Cargo.lock` whenever you
add or bump a dependency.

## Workspace layout

The workspace is declared in the root [`Cargo.toml`](Cargo.toml) with shared
`[workspace.package]` metadata and pinned `[workspace.dependencies]`. Prefer
`foo.workspace = true` over re-pinning a version in a member crate.

```
crates/
  aegis-sdk                 The plugin contract: Event/EventPayload, the Plugin
                            trait, PluginContext, register_plugin!, and the
                            dynamic C-ABI types. Depend on this to write a plugin.
  aegis-core                The kernel: plugin discovery (static + dynamic),
                            the event bus + dispatcher, ScopedEmitter, the
                            Host/HostBuilder/RunningHost lifecycle, and config.
  aegis-proto               Wire protocol shared by agent and server.
  aegis-agent               The endpoint agent binary; links the built-in
                            collector/control plugins and discovers them.
  aegis-server              The self-contained server (aegisd): the static
                            single-binary build target.
  aegis-cli                 Operator CLI (aegisctl).
  aegis-integration-tests   Cross-crate integration tests (e.g. proving the
                            dynamic example-plugin's code actually runs).
  example-plugin            Worked third-party plugin shipped as a cdylib; the
                            reference for the dynamic-loading path.
plugins/
  plugin-process            Collector: process-execution telemetry from /proc.
  plugin-session            Collector: interactive session start/end.
  plugin-tty                Collector: timing-only keystroke/tty telemetry.
  plugin-agent-detect       Processor: agent-vs-human detection.
  plugin-scoring            Processor: per-subject risk aggregation + alerts.
  plugin-tamper             Control: endpoint self-protection.
  plugin-transport          Sink: forwards events to the server.
```

Built-in plugins reach a binary by being listed as a path dependency of that
binary's crate (see `crates/aegis-agent/Cargo.toml`) and discovered at startup
via `inventory`. The `example-plugin` is deliberately the exception: its
`[lib] crate-type = ["cdylib"]` means it is **never** linked into a host binary
and is loaded only at runtime.

## Where a change belongs

- New telemetry source → a new `Collector` plugin under `plugins/`.
- New derived signal / detector / score → a new `Processor` plugin.
- New persistence/forwarding/alerting target → a new `Sink` plugin.
- New endpoint self-protection / lifecycle behavior → a `Control` plugin.
- A genuinely cross-cutting routing/lifecycle primitive that *all* plugins need
  → `aegis-core`, but expect scrutiny: the bar for touching the kernel is high
  (see the ethos above).
- A change to the plugin contract itself (event payloads, the `Plugin` trait,
  the dynamic ABI) → `aegis-sdk`, and bump `PLUGIN_API_VERSION` on any breaking
  change so mismatched dynamic plugins are rejected at load time.

## Commit and PR norms

- **Branch from `main`** and open a pull request; do not push directly to
  `main`.
- **Keep PRs focused.** One coherent change per PR. A new plugin plus an
  unrelated core refactor should be two PRs.
- **Tests travel with code.** New behavior needs tests in the same PR. The
  existing crates favor small, deterministic unit tests for pure logic (see the
  `RiskState` tests in `plugins/plugin-scoring/src/lib.rs`) and integration
  tests in `aegis-integration-tests` for end-to-end behavior (e.g. proving a
  dynamically loaded plugin's events traverse the real dispatcher).
- **Green CI is required.** Run fmt + clippy (`-D warnings`) + test locally
  before pushing; both CI jobs must pass before merge.
- **Conventional, imperative commit subjects.** Write `add tty paste-burst
  detector`, not `added` / `adds`. Keep the subject short; put the *why* in the
  body. Reference issues where relevant.
- **Document privacy- and tamper-relevant changes.** If a change touches what
  telemetry is captured or how the agent protects itself, say so explicitly in
  the PR description and update `docs/THREAT_MODEL.md` if the guarantees move.
- **Co-authorship trailer.** This repository tags AI-assisted commits. End
  commit messages with:

  ```
  Co-Authored-By: Claude <noreply@anthropic.com>
  ```

## License

By contributing you agree your contributions are licensed under the project's
Apache-2.0 license (see [`LICENSE`](LICENSE)).

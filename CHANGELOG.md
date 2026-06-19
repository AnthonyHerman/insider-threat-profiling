# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-06-19

First release of **Aegis**, a plugin-native, client/server platform for
behavioral insider-threat modeling. Its flagship capability is distinguishing an
**automated agent** from a **human operator** at a Linux endpoint, from timing
and structure alone — never keystroke content. End-to-end validated on real
hardware (see [`docs/linode-integration.md`](docs/linode-integration.md)).

### Platform / kernel
- **Plugin-native core (`aegis-core`).** The kernel implements no features: it
  discovers plugins, wires them onto a single bounded event bus, routes events by
  subscription, and manages lifecycle. Plugins are discovered **statically** (via
  `inventory`, just by being linked) and **dynamically** (a versioned C-ABI
  entrypoint loaded from a shared object, with the enable/disable policy evaluated
  on the declared name *before* `dlopen`).
- **Stable contracts (`aegis-sdk`).** The `Event` model and the `Plugin`
  trait/registration that every capability is built against.
- **Back-pressure.** Bounded per-plugin queues (`queue_depth`, default 4096) with
  drop counters, so event loss is observable/alertable rather than unbounded growth.
- **TOML host configuration (`HostConfig`).** `agent_id`, `data_dir`,
  `enabled_plugins`/`disabled_plugins`, `dynamic_plugins`, per-plugin `[plugins."plugin-x"]`
  subtrees, and `queue_depth`.

### Endpoint agent (`aegis-agent`)
- **Content-free behavioral collectors.** `plugin-session` (session lifecycle +
  per-command structural statistics: length, token count, Shannon entropy, salted
  correlation hash) and `plugin-tty` (interactive shell instrumented via a PTY;
  keystroke timing + command structure). No raw keystrokes or command text are
  ever stored or emitted.
- **Process collector (`plugin-process`).** Samples `/proc`, emitting
  `ProcessExec` for newly-seen processes (PID + start-time keyed, so PID reuse is
  handled), capturing lineage and uid as part of the behavioral picture.
- **Forwarder (`plugin-transport`).** Batches telemetry and ships it to the server
  over **pinned mutual TLS**, with an in-memory ring plus on-disk spill so events
  survive a server outage; full-jitter exponential reconnect backoff, keepalives,
  and configurable in-flight/FIFO delivery.
- **Enrollment.** `aegis-agent enroll` generates a per-agent Ed25519 identity,
  connects over a pinned TLS channel, exchanges enroll messages, and persists the
  server-assigned `agent_id` + cert pin. Secure intake paths (`--enroll-blob`,
  `--token-file`, stdin) keep the one-time token off `argv`.
- **Instrumented shell.** `aegis-agent shell` runs `$SHELL` inside a PTY and emits
  content-free telemetry (timing/structure only).
- **Tamper-resistant install (`plugin-tamper`).** `aegis-agent install` (root)
  copies the binary root-owned, generates a mutually-dependent **systemd
  service + guardian** watchdog pair, writes a SHA-256 baseline manifest, and sets
  the **immutable attribute** on the protected files — defending *visibility*
  against an unprivileged user using only supported OS mechanisms (no rootkit, no
  kernel exploits). Symlink-safe writes (`O_NOFOLLOW` + `fchown` the fd) and
  `NoNewPrivileges=yes` close escalation paths. A runtime tamper loop alerts on
  altered/removed protected files and reports a posture self-check.
- **Authenticated root-only uninstall.** `aegis-agent uninstall` is the
  deliberate administrator escape hatch: gated on uid 0 (authority), not on the
  install token (intent); clears immutability first, then disables/removes
  everything, idempotently.

### Server (`aegisd`)
- **Single self-contained, statically-linked binary.** No external database and
  no runtime asset directory: an embedded `redb` store and the operator dashboard
  assets are compiled in, and the binary targets static linking (musl). CI builds
  it and verifies it is statically linked.
- **Central processors.** `plugin-agent-detect` (the flagship agent-vs-human
  detector: per-session feature accumulation feeding a transparent additive model,
  with an EWMA sequential test and dead-band-camping escalation) and
  `plugin-scoring` (decaying per-subject risk aggregation that raises an `Alert`
  on threshold crossing).
- **Ingest + storage + API.** A TLS ingest listener for enrolled agents, the
  embedded store sink, a live command router, an HTTP/JSON operator API with an
  SSE live feed, and the embedded dashboard.

### Management CLI (`aegisctl`)
- List discovered plugins; show platform/server identity (cert fingerprint,
  protocol version, agent count); manage one-time enrollment tokens
  (create/list/revoke); list enrolled agents and recent alerts.

### Detection model
- Transparent, **explainable** additive model (`transparent-additive/v1`) over
  content-free features, emitting a verdict (Human / Uncertain / Agent) with a
  confidence and human-readable reasons. Calibrated against a synthetic human
  distribution; field deployments are expected to re-derive thresholds.

### Tooling, docs & CI
- Documentation set: architecture, threat model & ethics, detection / server /
  transport design notes, a security audit, performance micro-benchmarks, a live
  hardware-integration report, build & contributing guides, a plugin-authoring
  guide, plus a research paper and a blog post.
- Example configs (`configs/agent.example.toml`, `configs/server.example.toml`),
  a scratch-based `Dockerfile` for the self-contained server, and demo scripts.
- CI on every push/PR: `rustfmt`, `clippy -D warnings`, workspace build + tests
  (`--locked`), and a dedicated job that builds the static musl `aegisd`,
  asserts it is statically linked, and uploads it as an artifact.

[0.1.0]: https://github.com/AnthonyHerman/insider-threat-profiling/releases/tag/v0.1.0

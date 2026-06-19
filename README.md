# Aegis — Plugin-Native Behavioral Threat Modeling

> A client/server platform for **behavioral insider-threat modeling**, whose
> flagship capability is distinguishing an **automated agent** from a **human
> operator** at a Linux endpoint — built entirely as a plugin system.

*Authors: Anthony Herman and Claude.*

---

## What this is

Aegis watches *how* an endpoint is being driven, not just *what* runs on it. The
central research question it answers is **agent-vs-human**: is the entity at the
keyboard a person, or an automated program/AI agent? It answers this from
*timing and structure* — keystroke cadence, think-time between commands, paste
behaviour, correction patterns, command structure — never from keystroke
content. Those signals feed a transparent, explainable risk model.

It is a **client/server** system:

- **`aegis-agent`** — the endpoint client. Collects privacy-preserving
  behavioral telemetry and (optionally) installs itself as a **tamper-resistant**
  service that an unprivileged, monitored user cannot silently disable.
- **`aegisd`** — the server. A **single, self-contained, statically-linked
  binary** (no external database, no runtime asset directory) that ingests
  telemetry, runs central detection/scoring, and serves an operator dashboard.
- **`aegisctl`** — the management CLI.

## The core idea: a feature-free kernel, with the bus as the seam

The kernel (`aegis-core`) implements **no features**. It only discovers plugins,
wires them onto a single event bus, routes events by subscription, and manages
lifecycle. The processing surface is plugin-delivered: telemetry collection,
agent-vs-human detection, risk scoring, transport, and the agent's self-protection
are all [`Plugin`](crates/aegis-sdk/src/plugin.rs)s, and on the server *persistence*
arrives as the store-sink plugin. The one deliberate exception is the server's
**I/O drivers** — the TLS ingest listener and the operator HTTP API/dashboard are
thin non-plugin modules wired *around* the bus (they hold a `RunningHost::emitter()`
and the store handle) rather than registering as plugins. The invariant is "the
kernel is feature-free and the bus is the seam," not "literally every line is a
plugin." Plugins are discovered two ways:

- **statically**, via `inventory` (a built-in plugin is auto-discovered just by
  being linked in), and
- **dynamically**, via a versioned C-ABI entrypoint loaded from a shared object
  at runtime.

```
              ┌──────────────────────────────────────────────┐
              │                  aegis-core                    │
              │   discovery · event bus · routing · lifecycle  │
              └───────────────▲───────────────┬───────────────┘
   emits events               │ Event         │ Event (by subscription)
   ┌──────────────────────────┴───┐   ┌───────▼───────────────────────┐
   │ Collectors                   │   │ Processors                     │
   │  plugin-process              │   │  plugin-agent-detect (flagship)│
   │  plugin-session (timing)     │   │  plugin-scoring                │
   │  plugin-tty (pty/pipe)       │   └───────┬───────────────────────┘
   ┌──────────────────────────────┐   ┌───────▼───────────────────────┐
   │ Control                      │   │ Sinks                          │
   │  plugin-tamper (self-protect)│   │  plugin-transport · store-sink │
   └──────────────────────────────┘   └────────────────────────────────┘
```

The server's *persistence* is the store-sink plugin shown above; its network
ingress (TLS listener) and operator HTTP/dashboard are **non-plugin** I/O drivers
wired around the same bus, not plugins.

## Workspace layout

| Crate | Role |
|-------|------|
| `crates/aegis-sdk` | Stable contracts: the `Event` model and the `Plugin` trait/registration. |
| `crates/aegis-core` | The kernel: plugin host, event bus, static + dynamic loaders. |
| `crates/aegis-proto` | Wire protocol: framed, versioned agent↔server messages. |
| `crates/aegis-agent` | Endpoint client binary (`aegis-agent`). |
| `crates/aegis-server` | Self-contained server binary (`aegisd`). |
| `crates/aegis-cli` | Management CLI (`aegisctl`). |
| `crates/aegis-integration-tests` | In-process end-to-end pipeline tests (no public surface). |
| `crates/example-plugin` | Reference dynamic (`cdylib`) plugin. |
| `plugins/plugin-process` | Collector: process-execution telemetry. |
| `plugins/plugin-session` | Collector: session lifecycle + content-free command-statistics helpers. |
| `plugins/plugin-tty` | Collector: PTY/pipe keystroke + command timing (content-free). |
| `plugins/plugin-agent-detect` | Processor: **agent-vs-human** distinction. |
| `plugins/plugin-scoring` | Processor: per-subject risk aggregation + alerting. |
| `plugins/plugin-tamper` | Control: endpoint self-protection. |
| `plugins/plugin-transport` | Sink: mTLS forwarder (agent → server). |

## Build & run

```bash
# Build everything
cargo build --workspace

# List the plugins discovered by the kernel
cargo run --bin aegisctl -- plugins

# Run the agent locally and watch the events it produces
cargo run --bin aegis-agent -- run --print-events

# Build the self-contained, statically-linked server
cargo build --release --bin aegisd --target x86_64-unknown-linux-musl
ldd target/x86_64-unknown-linux-musl/release/aegisd   # => "statically linked"

# ...or build the scratch container image carrying only that one binary
docker build -t aegisd:0.1.0 .
```

Start from the commented example configs when deploying:
[`configs/agent.example.toml`](configs/agent.example.toml) and
[`configs/server.example.toml`](configs/server.example.toml). For the
tamper-resistant agent install (generated systemd units) and the authenticated
root uninstall, see [`packaging/README.md`](packaging/README.md).

## Tamper resistance & ethics

The protected asset is **visibility**. In an insider-threat deployment, the
monitored (and typically unprivileged) user must not be able to silently turn
monitoring off on their own workstation — the same property every commercial
EDR/DLP agent provides. Aegis achieves this with **supported OS mechanisms
only** (root-owned files, the immutable attribute, and a systemd watchdog pair).
It is **not** a rootkit, employs no kernel exploits or hiding, and always retains
an **authenticated, root/administrator uninstall** path. The full reasoning,
including limitations and abuse-resistance, lives in
[`THREAT_MODEL.md`](docs/THREAT_MODEL.md) and the accompanying paper's ethics
section.

## Documentation

**Start here**
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — the plugin kernel, event bus, discovery, and lifecycle.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — what is defended, the attacker model, ethics, and the limits of tamper resistance.
- [`docs/PLUGINS.md`](docs/PLUGINS.md) — the plugin catalog and how to author your own.

**Design notes**
- [`docs/detection-design.md`](docs/detection-design.md) — the agent-vs-human model: features, the transparent additive scorer, and calibration.
- [`docs/server-design.md`](docs/server-design.md) — the self-contained server: ingest, embedded store, operator API, and dashboard.
- [`docs/transport-design.md`](docs/transport-design.md) — the agent↔server wire protocol, pinned mutual TLS, enrollment, and the durable forwarder.

**Operations**
- [`docs/BUILD.md`](docs/BUILD.md) — building everything, plus the static musl server.
- [`configs/agent.example.toml`](configs/agent.example.toml) · [`configs/server.example.toml`](configs/server.example.toml) — fully-commented example host configs.
- [`Dockerfile`](Dockerfile) — scratch image carrying only the single `aegisd` binary.
- [`packaging/README.md`](packaging/README.md) — the agent's self-installing systemd units and the authenticated root uninstall.

**Assurance**
- [`docs/security-audit.md`](docs/security-audit.md) — the full-workspace security audit and remediation status.
- [`docs/perf.md`](docs/perf.md) — hot-path micro-benchmarks.
- [`docs/linode-integration.md`](docs/linode-integration.md) — end-to-end validation on real hardware.

**Project**
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — contribution workflow and conventions.
- [`CHANGELOG.md`](CHANGELOG.md) — release notes.
- [`docs/paper/paper.md`](docs/paper/paper.md) — the research paper.
- [`docs/blog/blog.md`](docs/blog/blog.md) — the blog post.

## Status

**Implemented and live-validated.** All components are built end-to-end: the
plugin kernel, the content-free collectors, the flagship agent-vs-human detector
and risk scoring, the durable mutual-TLS transport with enrollment, the
tamper-resistant agent installer, and the single self-contained `aegisd` server
(embedded `redb` store + embedded dashboard). The full client/server pipeline —
enrollment, mTLS forwarding, server-side detection — has been exercised on a real
Linux host distinct from the build machine (see
[`docs/linode-integration.md`](docs/linode-integration.md)).

CI on every push/PR runs `rustfmt`, `clippy -D warnings`, and the workspace
build + tests (`--locked`), and a dedicated job builds the static musl `aegisd`
and asserts it is statically linked. A full security audit
([`docs/security-audit.md`](docs/security-audit.md)) has been completed with
findings remediated against source. This is research-grade software; see the
threat model and design docs for scope, assumptions, and known limitations.

## License

Apache-2.0. See [`LICENSE`](LICENSE).

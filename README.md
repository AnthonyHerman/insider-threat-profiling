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

## The core idea: everything is a plugin

The kernel (`aegis-core`) implements **no features**. It only discovers plugins,
wires them onto a single event bus, routes events by subscription, and manages
lifecycle. Every capability — telemetry collection, agent-vs-human detection,
risk scoring, persistence, transport, and even the agent's self-protection — is a
[`Plugin`](crates/aegis-sdk/src/plugin.rs). Plugins are discovered two ways:

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
   └──────────────────────────────┘   └───────┬───────────────────────┘
   ┌──────────────────────────────┐   ┌───────▼───────────────────────┐
   │ Control                      │   │ Sinks                          │
   │  plugin-tamper (self-protect)│   │  storage · transport · alert   │
   └──────────────────────────────┘   └────────────────────────────────┘
```

## Workspace layout

| Crate | Role |
|-------|------|
| `crates/aegis-sdk` | Stable contracts: the `Event` model and the `Plugin` trait/registration. |
| `crates/aegis-core` | The kernel: plugin host, event bus, static + dynamic loaders. |
| `crates/aegis-proto` | Wire protocol: framed, versioned agent↔server messages. |
| `crates/aegis-agent` | Endpoint client binary (`aegis-agent`). |
| `crates/aegis-server` | Self-contained server binary (`aegisd`). |
| `crates/aegis-cli` | Management CLI (`aegisctl`). |
| `plugins/plugin-process` | Collector: process-execution telemetry. |
| `plugins/plugin-session` | Collector: session + keystroke/command timing (content-free). |
| `plugins/plugin-agent-detect` | Processor: **agent-vs-human** distinction. |
| `plugins/plugin-scoring` | Processor: per-subject risk aggregation + alerting. |
| `plugins/plugin-tamper` | Control: endpoint self-protection. |

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
```

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

- Architecture: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Threat model & ethics: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
- Research paper: [`docs/paper/`](docs/paper/)
- Blog post: [`docs/blog/`](docs/blog/)

## Status

Active research prototype. CI builds, lints, tests every crate, and verifies the
server links statically. See the design docs for the roadmap.

## License

Apache-2.0. See [`LICENSE`](LICENSE).

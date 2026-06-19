# Aegis Architecture

> This document is expanded by the architecture design workflow. The summary
> below reflects the foundation; detailed component diagrams and rationale follow.

Aegis is a plugin-native client/server platform. The kernel (`aegis-core`)
provides discovery, an event bus, subscription routing, and lifecycle; all
features are plugins implementing the `aegis-sdk` `Plugin` trait.

- **Event model** — one envelope (`Event`) for telemetry, derived signals,
  scores, detections, and alerts (`crates/aegis-sdk/src/event.rs`).
- **Plugin host** — static (`inventory`) and dynamic (C-ABI shared object)
  discovery; per-plugin queues with back-pressure (`crates/aegis-core`).
- **Wire protocol** — length-prefixed JSON frames, enrollment + per-agent keys
  (`crates/aegis-proto`).

See `THREAT_MODEL.md` for the security and ethics analysis.

# Live Integration Test on Real Hardware

This documents an end-to-end validation of the full Aegis client/server system on
a real Linux host (a Linode VM, Ubuntu 24.04, x86-64, 1 vCPU, glibc 2.39),
distinct from the build/dev machine. It exercises the **complete pipeline** the
in-process unit/integration tests cannot: real process boundaries, real TLS over
a socket, enrollment, and the server's central detection over forwarded telemetry.

Driver: [`scripts/integration_demo.sh`](../scripts/integration_demo.sh) (release
binaries copied over; no Rust toolchain on the host).

## What was validated

1. **Self-contained server on real hardware.** A single `aegisd` binary started,
   created its embedded `redb` store and self-signed TLS cert, and bound both the
   TLS ingest listener and the HTTP/dashboard — no external database, no asset
   directory, no runtime dependencies:
   ```
   server up: {"fingerprint":"2d86957f…449e492e","proto_version":1}
   ```
2. **Enrollment + mutual TLS + per-agent identity.** `aegisctl` minted a one-time
   token; the agent generated an Ed25519 key, connected over pinned TLS, enrolled,
   and persisted its identity:
   ```
   enrolled: agent_id=f406f988-5906-4a87-be92-3908442755b1
   transport: online agent_id=f406f988-… host=127.0.0.1 port=8443
   ```
3. **Telemetry forwarding + ingest.** The agent (collectors + the `plugin-transport`
   forwarder) batched events over mTLS; the server validated and ingested them
   (a sample run accepted 153/154 events, rejecting one as a malformed-frame guard).
4. **Central agent-vs-human detection — the flagship — on forwarded telemetry.**
   Synthetic *agent-like* telemetry (metronomic, paste-like, no corrections; via
   `plugin-tty` pipe mode) was forwarded to the server, whose central
   `plugin-agent-detect` produced a verdict, visible through the operator API:
   ```json
   {"agent_id":"aegisd","subject":"moji:65404","verdict":"agent",
    "confidence":0.855,"model":"transparent-additive/v1",
    "reasons":["uncorrelated-flat-throughput","gap-non-autocorrelation",
               "whole-line-injection","constant-think-time"]}
   ```
5. **Scoring + alerting.** Risk aggregation produced scores and `critical` alerts,
   served from the operator API.

## Two real bugs this caught (that in-process tests missed)

The prior unit/integration tests run the pipeline over the in-process event bus,
so they never exercised the real *enroll → authenticated session → forward* path.
The live test exposed two genuine defects, both fixed:

1. **Forwarder session authentication used the wrong identity.** The forwarder
   sent the local host-config `agent_id` in its `ClientHello` instead of the
   server-assigned enrollment UUID, so every telemetry session was rejected
   "unknown agent" — the agent enrolled but silently never reported. Fixed by
   authenticating as `identity.agent_id`.
2. **Pipe-mode telemetry was dropped by the unknown-session guard.** The H3
   hardening drops keystroke/command events for any session without a prior
   `SessionStart`. `plugin-tty`'s pipe mode emitted `SessionEnd` but not
   `SessionStart`, relying on `plugin-session`'s login event — whose `session_id`
   coincided on the dev box but differed under the remote ssh environment, so the
   session telemetry was discarded and no detection fired. Fixed by having pipe
   mode emit its own `SessionStart`.

Both fixes are covered going forward by `scripts/integration_demo.sh`, which
reproduces the full network path and polls for the verdict.

## Reproduce

```bash
cargo build --release --bin aegisd --bin aegis-agent --bin aegisctl
scp target/release/aegis{d,-agent,ctl} scripts/integration_demo.sh user@host:/tmp/aegis/
ssh user@host 'cd /tmp/aegis && bash integration_demo.sh /tmp/aegis /tmp/aegis/work'
```

The host needs only `curl` and `bash`; the binaries are self-contained.

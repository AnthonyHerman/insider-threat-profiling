# Aegis Technical Diagrams

This is the shared diagram set for the Aegis blog post and academic paper. Each diagram is maintained here as the single source of truth and referenced by both documents. All diagrams were validated against the implementation in `crates/` and the design documents in `docs/`.

---

## Aegis plugin-native architecture: feature-free aegis-core kernel, BusEmitter/ScopedEmitter, and plugin families

```mermaid
flowchart TB
  subgraph AGENT_HOST["aegis-agent endpoint"]
    direction TB

    subgraph ACOL["Collectors - Subscriptions::None, produce only"]
      direction LR
      PP["plugin-process<br/>proc sampler -> process.exec"]
      PS["plugin-session<br/>session.start only"]
      PTTY["plugin-tty<br/>pty/pipe -> input.keystroke, command.observed, session.end"]
    end

    subgraph ACTRL["Control"]
      PT["plugin-tamper<br/>posture + tamper-watch -> alert"]
    end

    ASE["ScopedEmitter per plugin<br/>wraps BusEmitter, stamps source + agent_id<br/>each plugin gets its own instance in PluginContext"]

    subgraph AKERNEL["aegis-core kernel - NO features"]
      direction TB
      AING["Ingress<br/>bounded mpsc, depth = queue_depth"]
      ADISP["Dispatcher task<br/>fan-out by Subscriptions.matches kind"]
      AQ["Per-plugin bounded queues<br/>one handler task each"]
      AING --> ADISP --> AQ
    end

    subgraph ASINK["Sinks"]
      PX["plugin-transport<br/>Subscriptions::All"]
    end

    PP -- "emit()" --> ASE
    PS -- "emit()" --> ASE
    PTTY -- "emit()" --> ASE
    PT -- "emit()" --> ASE
    ASE -- "BusEmitter emit; critical kinds await-back-pressure, others try_send" --> AING
    AQ -- "all kinds" --> PX
  end

  subgraph SERVER_HOST["aegisd server"]
    direction TB

    SING["TLS ingest task (ingest.rs)<br/>aegis-proto over TLS<br/>RunningHost.emitter emit per accepted event"]

    subgraph SKERNEL["aegis-core kernel - NO features"]
      direction TB
      SIN["Ingress<br/>bounded mpsc"]
      SDISP["Dispatcher task<br/>fan-out by Subscriptions.matches kind"]
      SQ["Per-plugin bounded queues"]
      SIN --> SDISP --> SQ
    end

    subgraph SPROC["Processors"]
      direction TB
      PAD["plugin-agent-detect<br/>input.keystroke, command.observed, session.* -> detection"]
      PSC["plugin-scoring<br/>detection, process.exec, alert -> score, alert"]
    end

    subgraph SSINK["Sinks"]
      SS["store-sink<br/>score, detection, alert, heartbeat -> redb"]
    end

    SSE["ScopedEmitter per plugin<br/>wraps BusEmitter<br/>each plugin gets its own instance in PluginContext"]

    SING --> SIN
    SQ -- "input.keystroke, command.observed, session.*" --> PAD
    SQ -- "detection, process.exec, alert" --> PSC
    SQ -- "score, detection, alert, heartbeat" --> SS
    PAD -- "emit() detection" --> SSE
    PSC -- "emit() score, alert" --> SSE
    SSE --> SIN
  end

  PX == "EventBatch over aegis-proto, TLS" ==> SING

  classDef kernel fill:#eef,stroke:#669,stroke-width:1px;
  class AKERNEL,SKERNEL kernel;
```

Both the agent and server run the same feature-free aegis-core kernel (ingress mpsc to dispatcher to per-plugin queues); every plugin emits through a ScopedEmitter wrapping the BusEmitter, while collectors/control/processors/sinks supply all behavior and the agent's plugin-transport forwards batches to the server's ingest over aegis-proto.

---

## Aegis agent-to-server transport lifecycle

```mermaid
sequenceDiagram
    autonumber
    actor OP as Operator
    participant CLI as aegisctl
    participant A as "aegis-agent (plugin-transport)"
    participant S as "aegisd (ingest)"
    participant R as "store (redb)"
    participant B as "host bus + detect/scoring"

    Note over OP,S: Bootstrap - mint one-time enrollment token
    OP->>CLI: enroll-token create --label laptop-07
    CLI->>S: POST /api/v1/tokens {label}
    S->>R: store token hex, created_at_ns, used=false
    CLI-->>OP: token hex + server cert fingerprint (pin)
    OP-->>A: deliver blob out-of-band (AEGIS-ENROLL base64(token||pin32), stdin / 0600 file)

    Note over A,S: TLS 1.3 handshake; agent pins SHA-256 of server cert DER

    rect rgb(235, 245, 255)
    Note over A,S: First run only - enrollment (one-time token)
    A->>S: "EnrollRequest { token, hostname, os, agent_pubkey }"
    S->>R: "redeem token hex; reject missing/expired/used"
    S->>R: assign agent_id; store AgentRow + pubkey
    S-->>A: "EnrollResponse { accepted, agent_id, reason }"
    A->>A: persist identity.json + Ed25519 key (0600)
    A->>S: close, then reconnect for a clean session
    end

    rect rgb(235, 255, 235)
    Note over A,S: Every session - Ed25519 possession proof
    A->>S: "ClientHello { proto_version, agent_id, hostname, os, agent_pubkey }"
    S->>R: "check proto_version; look up agent; verify pubkey == enrolled"
    S-->>A: "Command { id: nonce_uuid, command: Noop } (auth challenge)"
    A->>A: "nonce32 = SHA-256(challenge_id); sig = sign(AUTH_LABEL||pin||agent_id||nonce32||tls_exporter)"
    A->>S: "CommandResult { id, ok: true, detail: base64(sig) }"
    S->>S: "verify(enrolled_pubkey, auth_challenge_digest(pin, agent_id, nonce32, exporter))"
    S-->>A: "ServerHello { proto_version, accepted: true }"
    end

    rect rgb(255, 250, 235)
    Note over A,S: Online - telemetry, at-least-once, FIFO at max_in_flight=1
    loop drain ring / spill
        A->>S: "EventBatch { batch_id, events }"
        S->>S: "dedup by Event.id (in-memory DedupWindow); clamp ts_ns skew; allowlist kinds"
        S->>S: overwrite agent_id with authenticated identity
        S->>R: write_event to audit log
        S->>B: "emit(ev) -> Detection -> Score -> maybe Alert"
        S-->>A: "BatchAck { batch_id, accepted }"
        A->>A: drop batch from pending map; ack_through spill rows
    end
    end

    rect rgb(248, 240, 255)
    Note over B,A: Server -> agent commands (same duplex)
    B->>S: "policy/operator POSTs to /api/v1/agents/:id/command -> Router enqueues ServerCommand"
    S-->>A: "Command { id, Rescore | SetConfig | Isolate | Noop }"
    A->>A: dispatch on spawned task, rate-limit, session-bound
    A->>S: "CommandResult { id, ok, detail }"
    end

    rect rgb(245, 245, 245)
    Note over A,S: Keepalive + watchdog
    A->>S: Ping
    S-->>A: Pong
    Note over A,S: "silence > keepalive_timeout -> drop -> backoff/reconnect"
    end
```

Sequence of the Aegis agent-to-server lifecycle, from aegisctl minting a one-time enrollment token through TLS-pinned enrollment, the per-session Ed25519 nonce challenge, at-least-once EventBatch/BatchAck telemetry feeding server-side detection and scoring, and the duplex ServerCommand channel with keepalive.

---

## Agent-vs-Human Detection Pipeline

```mermaid
flowchart TD
    TTY["TTY read-chunks<br/>analyzer.on_read bytes, ts"]

    subgraph PRODUCE["Telemetry producers, content-free"]
        direction LR
        KS["Keystroke<br/>inter_arrival_ns, is_paste, burst_len"]
        CMD["CommandObserved<br/>inter_command_ns, had_backspace, shannon_entropy"]
    end

    TTY -->|per read| KS
    TTY -->|on newline / command boundary| CMD

    subgraph ACC["SessionAccumulator.features, gated"]
        direction TB
        GATE["Gate: MIN_KEYSTROKES 12, MIN_COMMANDS 3<br/>Tier-3 needs MIN_COMMANDS_ROBUST 16, else NaN"]
        subgraph T1["Tier-1 marginals, cheap to fake"]
            T1F["keystroke_cv, paste_ratio,<br/>mean_inter_command_ms, backspace_ratio,<br/>entropy_mean, cadence_regularity"]
        end
        subgraph T23["Tier-2/3 robust, joint structure"]
            T23F["gap_autocorr, think_tail_ratio,<br/>throughput_decay, whole_line_paste_ratio,<br/>keystroke_burst_cv; reaction_floor_hits"]
        end
        GATE --> T1F
        GATE --> T23F
    end

    KS --> GATE
    CMD --> GATE

    subgraph MODEL["Transparent additive model, model.rs"]
        direction TB
        WAVG["Weighted average<br/>NaN terms dropped and renormalized"]
        RULES["Asymmetric hard rules, can only raise:<br/>physiological-floor+paste,<br/>reaction-time-floor,<br/>uncorrelated-flat-throughput"]
        WAVG --> RULES
    end

    T1F --> WAVG
    T23F --> WAVG

    RULES --> PAGENT{{"p_agent"}}

    PAGENT -->|"p_agent >= 0.62"| AGENT["Verdict: Agent<br/>risk += 60 x confidence"]
    PAGENT -->|"0.35 < p_agent < 0.62"| UNCERTAIN["Verdict: Uncertain"]
    PAGENT -->|"p_agent <= 0.35"| HUMAN["Verdict: Human"]

    subgraph SEQ["EWMA sequential test, per session, lib.rs"]
        direction TB
        LLR["llr = logit p_agent<br/>EWMA alpha = 0.3"]
        ESC{"ewma_logit >= 0.25<br/>AND Uncertain<br/>AND not yet escalated?"}
        LLR --> ESC
    end

    PAGENT -.->|feed each re-assessment| LLR
    UNCERTAIN -.->|sustained dead-band camper, A5| ESC
    ESC -->|yes| ESCALATE["Escalate to Agent<br/>reason: sequential-escalation"]
    ESC -->|no| WATCH["Keep watching"]
    ESCALATE --> AGENT

    classDef agent fill:#f8c9c9,stroke:#b23,stroke-width:1px;
    classDef human fill:#cdeccd,stroke:#2a7,stroke-width:1px;
    classDef uncertain fill:#fdecc8,stroke:#c90,stroke-width:1px;
    class AGENT,ESCALATE agent;
    class HUMAN human;
    class UNCERTAIN uncertain;
```

End-to-end agent-vs-human detection: TTY read-chunks become content-free Keystroke/CommandObserved events, the gated SessionAccumulator derives Tier-1 marginals and Tier-2/3 robust features, a transparent additive model plus asymmetric hard rules yields p_agent and a Human/Uncertain/Agent verdict, while a per-session EWMA sequential test escalates sustained dead-band campers from Uncertain to Agent.

---

## Detection-vs-Evasion Stackelberg Game and AUC-vs-Evasion-Budget Degradation

```mermaid
flowchart TB
    subgraph Defender["Defender Aegis commits first - open-source white-box"]
        direction TB
        FS["Feature set F: six Tier-1 scalars (old model) plus Tier-2/3 joint-structure terms (live model)"]
        TH["Thresholds: agent >= 0.62, human <= 0.35, else Uncertain"]
        GATE["Evidence gate: MIN_KEYSTROKES=12, MIN_COMMANDS=3"]
        FS --> TH --> GATE
    end

    subgraph Agent["Adaptive agent ADV-A best-responds - spends evasion budget e"]
        direction TB
        BUDGET["Evasion budget e in 0..1 = fraction of playbook implemented"]
        subgraph Cheap["Cheap-to-fake marginals - moment-match, no fidelity (old Tier-1 weights)"]
            direction TB
            C1["backspace_ratio w=0.15 cheapest: flip a bool, dp -0.137"]
            C2["keystroke_cv w=0.25: jitter via sleep, dp -0.208"]
            C3["mean_inter_command_ms w=0.25: constant delay, dp -0.245"]
            C4["paste_ratio w=0.20: per-char write loop, dp -0.140"]
            C5["entropy_mean w=0.05, cadence_regularity w=0.10: near free"]
        end
        subgraph Costly["Costly-to-fake joint structure - must causally generate"]
            direction TB
            R1["Kernel-boundary eBPF tty timestamps - cannot forge as non-root"]
            R2["HID/evdev interrupt correlation - a pty emits no /dev/input"]
            R3["error_recovery_coupling and gap autocorrelation - breaks in the joint"]
            R4["sub-human flight-time floor and sustained-throughput-no-decay"]
        end
        BUDGET --> Cheap
        BUDGET --> Costly
    end

    subgraph Outcome["Best-response outcome"]
        direction TB
        WIN["Full mimic p_agent ~ 0.055 = Human, or dead-band camp ~ 0.568 = Uncertain"]
        NOTE["Uncertain = attacker win: plugin-scoring adds risk only on Agent"]
        WIN --> NOTE
    end

    subgraph Degrade["Conceptual degradation: p_agent on a TRUE agent vs budget e"]
        direction TB
        E0["e=0.0 | Regime A p=0.85 | Regime B p=0.88"]
        E2["e=0.2 | A=0.55 | B=0.85"]
        E4["e=0.4 | A=0.30 crosses below 0.35 = evaded | B=0.80"]
        E6["e=0.6 | A=0.20 | B=0.66"]
        E8["e=0.8 | A=0.15 | B=0.45"]
        E10["e=1.0 | A=0.12 floor | B=0.30"]
        E0 --> E2 --> E4 --> E6 --> E8 --> E10
        REGA["Regime A: six Tier-1 marginals - concave collapse, AUC falls by e~0.4, no effort wall"]
        REGB["Regime B: Tier-3-weighted ensemble - convex-then-floored, AUC holds, marginal evasions interfere"]
    end

    GATE -->|"publishes full commitment, follower sees everything"| BUDGET
    Cheap -->|"defeats Regime A: ~half the weight beaten by sleep calls"| WIN
    Costly -.->|"raises cost to forge kernel timestamps + synth HID - capabilities ADV-A lacks"| REGB
    Cheap -->|"low effort spent, high AUC loss"| REGA
    WIN -->|"feed verdict back; defender re-weights next round"| FS
    REGA -. "robustness = area under TPR-vs-effort curve, not TPR at one point" .-> REGB
```

A Stackelberg detection-vs-evasion game where the open-source defender commits a feature set and thresholds first and the adaptive agent best-responds by spending an evasion budget on cheap-to-fake marginals versus costly-to-fake joint-structure features, with the conceptual AUC/p_agent degradation showing Regime A (six Tier-1 marginals) collapsing below threshold by budget ~0.4 while the Tier-3-weighted Regime B stays robust.

---

## Aegis tamper-resistance: conjunctive root-gated layers protecting visibility against an unprivileged user, with a deliberate authenticated root uninstall

```mermaid
flowchart TB
    subgraph Threat["Adversary model and ethics"]
        direction TB
        UnprivUser["Unprivileged monitored user (UNTRUSTED)<br/>own UID: shell, signals, ptrace, cron/user-timers,<br/>namespaces, LD_PRELOAD, config edits"]
        Ethics{{"Ethics: resists the USER, never the ADMIN<br/>no rootkit, no process hiding, no kernel/LSM tamper<br/>always visible in ps / systemctl / on disk"}}
    end

    Asset(["Protected asset A1: endpoint visibility<br/>agent alive, running as root, emitting telemetry"])
    UnprivUser -->|"attempts to silently go dark"| Asset

    subgraph Resist["Resistance layers - conjunctive, each gated on a privileged primitive the user lacks"]
        direction TB
        L1["Layer 1 - Root-owned files + immutable bit<br/>fchown root:root, O_NOFOLLOW writes<br/>FS_IMMUTABLE_FL 0x10 via FS_IOC_SETFLAGS<br/>set immutable LAST at install"]
        L2["Layer 2 - systemd service + guardian<br/>service: Restart=always, RestartSec=1, Requires=guardian<br/>guardian: BindsTo=aegis-agent.service, Restart=always<br/>guard loop: is-active then systemctl start<br/>NoNewPrivileges, OOMScoreAdjust=-900, KillMode=process"]
        G1{"Privileged primitive #1:<br/>CAP_LINUX_IMMUTABLE<br/>delete / truncate / overwrite needs it"}
        G2{"Privileged primitive #2:<br/>cross-UID signal + ptrace denied<br/>User=root, kill/strace from user UID fails"}
        L1 -.->|"clear-cost = become root"| G1
        L2 -.->|"clear-cost = become root"| G2
    end

    subgraph Detect["Detection layers - make any privilege-escalation tamper loud, not silent"]
        direction TB
        D1["SHA-256 baseline manifest watch<br/>manifest.json root-owned + immutable<br/>each tick (default 15s): content drift,<br/>immutable-bit-cleared, existence fallback, heartbeat"]
        D2["SIGTERM / SIGINT tripwire<br/>emit Critical alert BEFORE exit, flush, then exit<br/>cross-UID signal denied, so fires on legit/root stop"]
        D3["Startup posture self-check<br/>is_root, systemd_present, pid_ns_matches_init,<br/>files-immutable; reports Critical, does NOT exit"]
        D1 --> Alert
        D2 --> Alert
        D3 --> Alert
        Alert[/"Critical Alert + Heartbeat to server<br/>going dark becomes a loud event, not a silent gap"/]
    end

    Asset --> L1
    Asset --> L2
    G1 --> Verdict
    G2 --> Verdict
    L1 --> D1
    L2 --> D2

    Verdict{{"Unprivileged user lacks root: every removal rung<br/>either fails to persist past the guardian revive<br/>or trips a Critical alert -> best response is NOT to tamper"}}
    Verdict --> Asset

    subgraph Admin["Deliberate root escape hatch A8 - the one intentional backdoor"]
        direction TB
        Root["Root / administrator (TRUSTED)<br/>holds CAP_LINUX_IMMUTABLE + systemd control + ownership"]
        Uninstall["Authenticated uninstall - hard precondition uid 0 ONLY<br/>token marks intent, root is authority (missing token still removes)<br/>1. clear immutable bit FIRST<br/>2. systemctl disable --now both units<br/>3. remove files; token deliberately NOT immutable"]
        Root --> Uninstall
    end

    Uninstall -->|"passes cleanly through every layer by design"| Asset
    Ethics -.->|"bounds the whole posture"| Resist
    Ethics -.->|"guarantees removability"| Admin
```

Aegis protects endpoint visibility with conjunctive, root-gated layers (root-owned + FS_IMMUTABLE_FL files and a Restart=always/BindsTo systemd service+guardian) backed by detection (SHA-256 manifest watch, SIGTERM/SIGINT tripwire, posture self-check) so an unprivileged user can neither persist a removal past the guardian nor go dark silently, while a single authenticated uid-0-only uninstall remains a deliberate, ethics-mandated escape hatch that resists the user but never the administrator.

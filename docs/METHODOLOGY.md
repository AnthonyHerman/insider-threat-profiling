# How Aegis Was Built — A Multi-Agent, Workflow-Driven Methodology

This document records *how* Aegis was produced, not what it does. Aegis was built
by a human author (Anthony Herman) directing a fleet of AI coding agents (Claude)
through a sequence of **orchestrated, multi-agent workflows** — design war-rooms,
implementation workflows, an adversarial security audit, multi-discipline
verification, live hardware integration, and authoring — each leaving an auditable
trace in the repository (commits, design docs, the audit report, the integration
report). Every claim below is grounded in artifacts you can open in this repo; the
"Where to verify" pointers say exactly where.

The aim is honesty about process: the methodology is interesting precisely because
it is *checkable*. Where a technique paid off concretely (real bugs caught, findings
remediated), the payoff is cited to the artifact that proves it.

---

## 1. The shape of the process

Each phase was run as one or more **parallel agent workflows**. The commit history
preserves how many ran per phase — the subject lines carry an explicit
`(N workflows)` tag:

| Phase | Commit | Parallelism |
|-------|--------|-------------|
| Foundation (kernel, SDK, protocol, agent/server/CLI skeletons, CI) | `5a48031` | 1 |
| **Design** (architecture, threat model, detection/server/transport design notes) + eval harness | `44fb262` | **5 workflows** |
| Implement `plugin-tty` collector + harden the detector | `3b1a2bd` | 2 workflows |
| Implement agent→server transport (mTLS + enrollment + forwarder) | `b1397c5` | 1 workflow |
| Self-contained server data path + tamper-resistant installer | `30cba7c` | 2 workflows |
| Operator dashboard + HTTP API + `aegisctl` admin + **security audit** | `3c0de7f` | — |
| **Remediate 28 audit findings** + core hardening + paper bibliography/diagrams | `b58f3ed` | — |
| Reproducible evaluation results + generator | `b28ec89` | — |
| End-to-end pipeline integration tests + demo script + full paper | `7a46896` | — |
| Blog post | `ced073f` | — |
| Runtime dynamic plugin loading (cdylib via C-ABI) | `0fb1b4d` | — |
| Wire-protocol property/robustness tests + doc refresh | `8e5d2b0` | — |
| **Live-integration bug fixes** (forwarder identity; pipe-mode session) | `8e79fe2`, `c9697c7` | — |
| Criterion benches + perf doc + CONTRIBUTING + plugin guide | `a15e010` | — |
| Learned-baseline **model cross-check** + deployment packaging | `1b2ac14` | 2 workflows |
| **Completeness critique**: 26 verified gaps fixed across code, docs, CI | `ad76a22` | — |

> **A note on the word "workflows."** In these subject lines "workflows" means the
> *parallel agent build/design workflows* run during that phase — not GitHub
> Actions workflow files. CI itself is a single file, `.github/workflows/ci.yml`,
> containing **two jobs** (`fmt + clippy + test` and the static-musl server build).
> The design phase, for instance, ran five parallel workflows yet touched no CI.

**Where to verify:** `git log --oneline` (subjects above are verbatim); the design
artifacts produced by `44fb262` are `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`,
`docs/detection-design.md`, `docs/server-design.md`, `docs/transport-design.md`.

---

## 2. The arc, phase by phase

### 2.1 Design war-rooms and round-tabling

The design phase ran five parallel workflows that war-roomed the architecture and
the adversarial surface *before* most code existed, producing the five long-form
design documents in one commit (`44fb262`, +4,269 lines of docs). The output was
then consolidated through a **cross-discipline round-table review** whose verdict
is recorded directly in the repository: the Architecture Decision Record in
`docs/ARCHITECTURE.md` is introduced as *"Distilled from the cross-discipline
round-table review,"* and its 26 ADR rows separate *standing* decisions already in
the code from *recommended* roadmap decisions, each carrying a live **Status**
column. The round-table was re-run as a code-review pass later in the project
(`b598cfc`, "Round-table code-review fixes (14)").

**Where to verify:** `docs/ARCHITECTURE.md` (ADR preamble + the 26-row table);
commits `44fb262`, `b598cfc`.

### 2.2 Implementation workflows

With the design fixed, capability was built in focused implementation workflows,
each landing a coherent slice: the PTY/pipe collector and detector hardening
(`3b1a2bd`), the mTLS transport with enrollment and a durable forwarder
(`b1397c5`), the self-contained server data path and the tamper-resistant installer
(`30cba7c`), and the operator dashboard / HTTP API / CLI admin surface (`3c0de7f`).
The ADR **Status** column was the running ledger: most of the design-phase roadmap
is now marked **Done** against the code (e.g. ADRs 8–12, 14, 16, 17, 19).

**Where to verify:** the ADR Status column in `docs/ARCHITECTURE.md`; the
corresponding crates under `plugins/` and `crates/aegis-server/`.

### 2.3 Adversarially-verified security audit + remediation

A full-workspace security audit was run as a **two-phase adversarial process**,
documented in `docs/security-audit.md`: *Phase 1* a parallel domain audit, *Phase 2*
an **adversarial per-finding verification** in which every candidate finding was
re-checked against the exact source with a hostile reading ("Is the path actually
reachable? Is the primitive real? Is the severity inflated?"). Findings that did not
survive were dropped; severities the code did not support were adjusted (two
downgrades, one upgrade, all noted inline).

The audit confirmed **28 findings (7 high, 10 medium, 11 low), no false positives**.
Remediation was then driven against source and the report's status re-verified
against code: **26 of 28 are now Fixed**, with the two that remain explicitly
tracked — **H5**, the dynamic-loader *cryptographic* integrity gate (a pre-`dlopen`
path/ownership-safety gate did land; the signature/hash gate is the remaining gap,
ADR #15), and a documentation item now satisfied.

**Where to verify:** `docs/security-audit.md` (Method line; the §1 remediation
banner "26 of 28 are now Fixed"; the closing line "26 Fixed, 1 Open (H5 …)");
remediation commit `b58f3ed` ("Remediate 28 audit findings + core hardening").

### 2.4 Red-team / fuzz / perf / code-review verification

Verification used a deliberate **variety of independent lenses**, so that the agent
that generated a thing was rarely the one that signed off on it:

- **Red-teaming.** The transport and detection designs were stress-tested against an
  adversary and the findings written down. `docs/transport-design.md` §6.2 carries a
  *"Red-team findings and mitigations"* table (RT-1…RT-n) *"derived adversarially
  against this exact design,"* each row paired with a concrete mitigation;
  `docs/detection-design.md` red-teams the deployed feature set (the Stackelberg
  framing). The threat model in `docs/THREAT_MODEL.md` and paper section
  `docs/paper/sections/04-threat-game.md` carry the matching **game-theoretic**
  analysis (a Stackelberg leader-follower evasion game with an explicit evasion
  budget).
- **Fuzz / property testing.** The wire protocol got property-based and robustness
  tests (`8e5d2b0`); the regressions corpus is committed at
  `crates/aegis-proto/tests/framing.proptest-regressions`.
- **Performance.** Hot paths were micro-benchmarked with Criterion and written up in
  `docs/perf.md` (`a15e010`); benches live under `crates/aegis-core/benches/`,
  `crates/aegis-proto/benches/`, and `plugins/plugin-agent-detect/benches/`.
- **Model cross-check (model variety).** Rather than trust the hand-calibrated
  detector on its own claims, a **learned logistic-regression baseline**
  (`plugins/plugin-agent-detect/src/baseline.rs`) was built and run head-to-head
  through the *same* leak-free feature pipeline; the skeptical write-up is
  `docs/model-comparison.md` (the two are statistically indistinguishable at low/
  moderate evasion, both collapse to chance under a perfect mimic). The synthetic
  evaluation itself is made reproducible and **CI-gated for drift** — `ci.yml`
  regenerates `docs/paper/results.md` from the seeded `eval_report` example and
  fails on any diff.
- **Round-table code review.** A consolidated review pass applied 14 fixes
  (`b598cfc`).

**Where to verify:** `docs/transport-design.md` §6.2; `docs/detection-design.md`;
`docs/THREAT_MODEL.md` §5 and `docs/paper/sections/04-threat-game.md`; `docs/perf.md`;
`docs/model-comparison.md` + `baseline.rs`; the proptest regressions file; the
`ci.yml` reproducibility step.

### 2.5 Live hardware integration

The full client/server pipeline was exercised on a **real Linux host distinct from
the build machine** (a Linode VM, Ubuntu 24.04, x86-64), driven by
`scripts/integration_demo.sh` with release binaries copied over (no toolchain on the
host). It validated the self-contained server start, enrollment + mutual TLS +
per-agent Ed25519 identity, telemetry forwarding + ingest, server-side
agent-vs-human detection over forwarded telemetry (verdict `agent`, confidence
`0.855`, model `transparent-additive/v1`), and scoring/alerting — all through the
operator API. This is documented in `docs/linode-integration.md`.

**Concrete payoff — two real bugs the in-process tests missed.** Because the unit
and integration tests run the pipeline over the *in-process* event bus, they never
exercised the real *enroll → authenticated session → forward* path. The live test
exposed two genuine defects, both fixed and now guarded by the demo script:

1. **Forwarder authenticated with the wrong identity** — it sent the local
   host-config `agent_id` in its `ClientHello` instead of the server-assigned
   enrollment UUID, so every telemetry session was rejected "unknown agent" (the
   agent enrolled but silently never reported). Fixed in `8e79fe2` by
   authenticating as `identity.agent_id`.
2. **Pipe-mode telemetry was dropped by the unknown-session guard** — `plugin-tty`'s
   pipe mode emitted `SessionEnd` but not `SessionStart`, relying on
   `plugin-session`'s login event whose `session_id` coincided on the dev box but
   differed under the remote ssh environment, so the session telemetry was
   discarded and no detection fired. Fixed in `c9697c7` by having pipe mode emit its
   own `SessionStart`.

**Where to verify:** `docs/linode-integration.md` (§"Two real bugs this caught");
commits `8e79fe2`, `c9697c7`; `scripts/integration_demo.sh`.

### 2.6 Paper and blog authoring

The research artifacts were authored against the *implemented and live-validated*
system: a sectioned research paper (`docs/paper/paper.md` + `docs/paper/sections/`,
with a bibliography and diagrams) and a blog post (`docs/blog/blog.md`). The
evaluation numbers quoted in the paper come from the reproducible harness whose
output is the CI-checked `docs/paper/results.md`, so the paper cannot silently
diverge from the model code that produces its tables. Both artifacts credit
"Anthony Herman and Claude."

**Where to verify:** `docs/paper/paper.md`, `docs/paper/sections/*`,
`docs/paper/results.md`, `docs/blog/blog.md`; the `ci.yml` results-drift gate.

### 2.7 Completeness critique

A final **completeness critique** pass swept the whole repository for verified gaps
between what was claimed and what was implemented, and closed them across code,
docs, and CI in one commit (`ad76a22`, "Completeness pass: 26 verified gaps fixed
across code, docs, CI") — the current `HEAD` of `main`.

**Where to verify:** commit `ad76a22`.

---

## 3. Keeping parallel workflows conflict-free

Running multiple agent workflows at once only works if they cannot collide. Two
disciplines kept them clean, and both are still visible in the result:

- **Disjoint files / scoped ownership.** Each workflow owned a distinct slice of the
  tree, which the plugin-native architecture makes natural: every capability is its
  own crate (`plugins/plugin-*`, `crates/aegis-*`) depending only on the stable
  `aegis-sdk` contracts, and **no plugin holds a reference to any other plugin** —
  they communicate solely through `Event`s on the kernel's bus. So a workflow
  building `plugin-transport` and one building `plugin-tty` edit disjoint
  directories and cannot conflict. The SDK←core←binary layering (a project
  invariant in `CONTRIBUTING.md`) means adding a capability "must never require
  editing the core," which keeps the shared kernel out of the contention path. This
  same discipline governs even single-session work: where this release-polish task
  ran alongside a sibling editing Rust, the two were given **strictly disjoint
  files** (this task: `README.md`, `CHANGELOG.md`, this document; the sibling: the
  `.rs`/`Cargo` sources).
- **Scoped verification.** Verification was deliberately *narrow and source-anchored*
  rather than global hand-waving: the audit verified each finding against an exact
  file:line ("re-checked against the exact source — not the summary"), the CI
  reproducibility gate checks one specific generated file for drift, and the live
  integration test scoped itself to the one path the in-process tests could not
  cover (real sockets / real process boundaries). Narrow, checkable scopes let
  independent passes run without stepping on each other.

**Where to verify:** the workspace layout in `README.md` and `Cargo.toml`;
the "kernel has no features / everything is a plugin / SDK←core←binary layering"
ethos in `CONTRIBUTING.md`; the per-finding `Location:` lines in
`docs/security-audit.md`; the scoped reproducibility step in `.github/workflows/ci.yml`.

---

## 4. Concrete payoffs (grounded)

- **Live integration caught two real bugs in-process tests missed** — wrong
  forwarder identity and dropped pipe-mode telemetry — each a silent failure that
  unit tests over the in-process bus could not surface
  (`docs/linode-integration.md`; `8e79fe2`, `c9697c7`).
- **The adversarial audit found 28 findings; 26 are remediated** against source,
  with the remaining two (notably H5, the dynamic-loader cryptographic integrity
  gate) explicitly tracked rather than quietly dropped (`docs/security-audit.md`;
  `b58f3ed`).
- **The skeptical model cross-check kept the simpler model honest** — a learned
  baseline gave no field-meaningful edge, so the explainable transparent model was
  retained on purpose, not by default (`docs/model-comparison.md`; `baseline.rs`).
- **Reproducibility is enforced, not asserted** — CI regenerates the paper's results
  table from a seeded harness and fails on drift, so the prose and the model code
  cannot diverge (`.github/workflows/ci.yml`).

---

## 5. Honest limitations of this account

- "Workflows" counts come from commit subject tags; the per-phase parallelism is
  recorded only where a subject carries an `(N workflows)` tag, so phases without a
  tag are left blank above rather than guessed.
- This methodology describes *process*, and the open hardening items it references
  (e.g. H5 / ADR #15, the eBPF ground-truth collector, server-side final
  classification) remain open in the product — see `docs/ARCHITECTURE.md` (ADR),
  `docs/security-audit.md`, and `docs/THREAT_MODEL.md` for their current status. A
  rigorous build process is not a claim that the system is finished.

---

*See also: [`README.md`](../README.md) (overview and documentation index),
[`docs/security-audit.md`](security-audit.md), and
[`docs/linode-integration.md`](linode-integration.md).*

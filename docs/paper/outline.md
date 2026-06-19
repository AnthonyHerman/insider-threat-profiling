# Research Paper — Working Outline

**Title (working):** *Aegis: A Plugin-Native Platform for Behavioral Insider-Threat
Modeling, with Content-Free Agent-vs-Human Operator Distinction*

**Authors:** Anthony Herman; Claude

> This is the structural outline. Section prose is produced by the paper
> authoring/verification workflows and assembled into `paper.md`. Every empirical
> number must come from the reproducible harness in `plugin-agent-detect`
> (`synth.rs` + `eval.rs`) or a cited source — no invented results.

## Abstract
- Problem: insiders and, increasingly, *automated agents* operating endpoints.
- Contribution: (1) a plugin-native architecture where the kernel has no
  features; (2) a content-free agent-vs-human detector with a transparent model
  and a game-theoretic evasion analysis; (3) an ethical tamper-resistance design
  that resists the unprivileged user while preserving root uninstall; (4) a
  self-contained single-binary server.

## 1. Introduction
- Motivation; the rise of agentic operators; why behavior, not content.
- Thesis & contributions; paper map.

## 2. Background & Related Work
- Keystroke dynamics & behavioral biometrics.
- Insider-threat detection / UEBA.
- Bot/human and human/automation discrimination.
- Security games (Stackelberg) & moving-target/evasion.
- EDR/DLP tamper-resistance (prior art and its ethics).
*(Bibliography assembled + verified by the references workflow.)*

## 3. Threat Model & Ethics
- Assets, adversaries (ADV-U/A/N/P), trust boundaries (from `THREAT_MODEL.md`).
- Ethics: tamper resistance targets the unprivileged user only; authenticated
  root uninstall; content-free telemetry; abuse-resistance.

## 4. System Architecture
- Plugin-native kernel; the Event model; static + dynamic plugin discovery.
- Event bus, subscriptions, back-pressure.
- Client/server split; self-contained server.
- Figures: component diagram; data-flow; plugin lifecycle (reuse `ARCHITECTURE.md`).

## 5. Agent-vs-Human Detection
- Behavioral substrate (content-free) and feature catalog.
- The transparent additive model; calibration; sequential testing.
- Evasion-robustness taxonomy (cheap vs costly-to-fake features).

## 6. Game-Theoretic Analysis
- Detection-vs-evasion as a Stackelberg game; tamper-vs-removal war of attrition.
- Equilibria and design implications.

## 7. Evaluation
- Methodology: synthetic generator from documented distributions; honesty about
  synthetic ≠ field-validated.
- Results: ROC-AUC; precision/recall/F1; **degradation vs evasion budget** curve.
- Tamper-resistance: layered-cost argument; Linode integration evidence.
- Self-contained server: static binary size / zero runtime deps.

## 8. Implementation
- Rust workspace; ~N crates; the static musl build; CI.

## 9. Limitations & Future Work
- Synthetic evaluation; eBPF/HID ground-truth; field study; cross-platform.

## 10. Conclusion

## Figures / Tables (to generate)
1. System architecture (Mermaid → exported).
2. Agent→server data flow.
3. Detection pipeline.
4. ROC curve(s).
5. AUC vs evasion-budget degradation curve.
6. Tamper-resistance layers diagram.
7. Feature catalog table; results table.

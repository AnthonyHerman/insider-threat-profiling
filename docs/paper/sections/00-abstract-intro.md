## Abstract & Introduction

### Abstract

Insiders with privileged access to organizational endpoints represent one of the
most persistent and difficult-to-detect threat classes in computer security
[cappelli2012cert; homoliak2019survey]. The problem is now compounded by a new
category of operator: automated agents — LLM-driven or scripted programs — that
drive real terminal sessions in ways behaviorally indistinguishable, at first
glance, from humans. We present Aegis, a plugin-native research platform for
behavioral insider-threat modeling on Linux endpoints. Aegis makes four
contributions. First, a plugin-native architecture in which the kernel implements
no features: telemetry collection, detection, scoring, transport, and tamper
resistance are all independently deployable plugins sharing a single typed event
bus. Second, a content-free agent-vs-human detector that classifies sessions from
timing and structural statistics alone — never keystroke content — using a
transparent additive model with six interpretable features. Third, a
game-theoretic analysis of detection-vs-evasion as a Stackelberg signaling game
and of tamper-resistance as a war of attrition, yielding concrete design rules for
both. Fourth, ethical tamper resistance implemented exclusively via supported OS
mechanisms, paired with a single self-contained statically-linked server binary.
Evaluation on synthetic sessions demonstrates ROC-AUC 1.000 against naive
automated agents, degrading monotonically to AUC 0.500 against a perfect
behavioral mimic, with the evasion-effort curve consistent with the game-theoretic
predictions.

---

### 1. Introduction

#### 1.1 The insider-threat problem and its agentic extension

The canonical insider threat is a human with legitimate access who misuses it
[schonlau2001masquerade; cappelli2012cert]. Detection has historically centered
on anomaly detection over access logs, process telemetry, and network flows
[homoliak2019survey; tuor2017deepueba; yuan2021deepreview]. Keystroke dynamics
and behavioral biometrics offer a complementary signal: the way a person types is
a stable, hard-to-transfer behavioral trait [monrose2000keystroke;
killourhy2009; gunetti2005free], and departures from an established baseline can
flag account takeover, masquerade, or coercion.

The threat model has recently expanded in a direction the behavioral biometrics
literature has not fully addressed. Automated agents — LLM-driven assistants,
scripted remote-execution pipelines, or CI/CD bots — increasingly drive real
terminal sessions on production endpoints. Unlike the masquerade attacker who
steals a human's credentials, these agents operate openly, often with the human
operator's knowledge. The security question is different: not "is this still the
same person?" but "is there a person here at all?" Answering it matters because
an automated agent executing under a human's account and privilege level can
exfiltrate data, persist malware, or reconfigure systems at machine speed while
appearing, to process and network monitors, entirely legitimate.

The challenge is separable from keystroke biometrics: we do not need to recognize
the specific human; we need only to distinguish human from machine. This simpler
binary problem has precedent in CAPTCHA [vonahn2003captcha], bot detection in web
and blog contexts [chu2013blogbots; kadel2024botracle], and mouse-dynamics
discrimination [ahmed2007mouse]. What is missing is a principled platform
treatment grounded in the endpoint security context, with explicit game-theoretic
analysis of adaptive evasion.

#### 1.2 The gap

Existing insider-threat systems focus on *what* is accessed or executed — UEBA
[tuor2017deepueba], anomaly detection over shell commands [schonlau2001masquerade],
or data-loss monitoring — and do not attempt to determine whether the session is
human-driven at all. Keystroke-dynamics research focuses on per-user biometric
recognition [killourhy2009; acien2022typenet; shadman2025keystroke] rather than
the human/automation binary, and assumes cooperative data collection from willing
subjects rather than an adversarial endpoint.

Critically, no prior platform addresses the full engineering stack: content-free
telemetry design that makes key-content capture impossible by construction; a
plugin architecture that allows arbitrary capability extension without modifying a
kernel; tamper resistance designed to resist an unprivileged monitored user while
preserving an authenticated administrator uninstall path; and a transportable
single-binary server. The closest prior work on evasion comes from adversarial
machine-learning attacks on classifiers [biggio2013; biggio2018] and from
Stackelberg security games [tambe2011; paruchuri2008; hu2025], but neither body
of work has been applied to the specific adversary model of an automated terminal
agent white-boxing its own detector.

#### 1.3 Contributions

This paper makes four contributions:

**Plugin-native architecture.** Aegis is built on the principle that the kernel
(`aegis-core`) implements no features. Every capability — process and session
telemetry collection, agent-vs-human detection, risk scoring, network transport,
and tamper resistance — is a `Plugin` that registers onto a single shared event
bus and depends only on a stable SDK contract (`aegis-sdk`). Two registration
paths coexist: static link-time registration via an `inventory` distributed slice
(zero boilerplate for built-in plugins) and dynamic loading from a versioned C-ABI
shared object at runtime (for out-of-tree extensions). This architecture makes
capabilities independently replaceable and testable, enforces a strict
dependency-layering that prevents plugin code from reaching into kernel internals,
and allows the system to be extended with new detectors, sinks, or collectors
without modifying any existing crate.

**Content-free agent-vs-human detection.** The event model structurally prohibits
key-content capture: `EventPayload::Keystroke` carries only inter-arrival timing,
a paste/burst flag, and burst length; `EventPayload::CommandObserved` carries
length, token count, Shannon entropy, a backspace flag, edit distance from the
previous command, inter-command timing, and a salted hash for correlation —
never verbatim text. From these content-free features `plugin-agent-detect`
constructs six behavioral signals (keystroke timing coefficient of variation,
paste ratio, mean inter-command think time, backspace ratio, command entropy mean,
and cadence regularity) and combines them in a transparent additive model whose
every verdict is attributable to named features and reported reasons. The model is
designed to be swappable: the `Model::assess` interface is stable and a learned
model can replace the hand-calibrated logistic terms without changing the pipeline.

**Game-theoretic evasion analysis.** We analyze detection as a Stackelberg
signaling game in which the defender commits to the model first and the automated
agent best-responds by choosing an evasion-effort vector over the six feature
dimensions. Because the codebase is open-source, the follower observes every
logistic center, slope, and weight exactly. We independently compute payoffs from
`model.rs` and show that the cheapest evasion strategy — the dead-band camp at
`p_agent` between the `Uncertain` thresholds — achieves zero risk accumulation at
near-zero effort, and that the timing features, despite carrying the highest model
weight, are defeatable by `sleep()` calls alone. The equilibrium analysis
identifies that parameter tuning cannot escape the problem; only changes to the
strategy space (kernel-anchored eBPF/HID signals, server-side classification,
actionable `Uncertain`) shift the equilibrium. We apply the same game-theoretic
lens to tamper resistance, modeling it as a war of attrition in which the
defender installs conjunctive privilege-gated layers and showing that the
equilibrium is a step function of layer completeness: the unprivileged user's
removal probability collapses from approximately 1 to approximately 0 only when
root ownership, filesystem immutability, a real guardian watchdog, and hash-based
tamper detection all hold simultaneously.

**Ethical tamper resistance and self-contained server.** The endpoint client
(`aegis-agent`) is designed to resist silent disablement by an unprivileged
monitored user using only supported OS mechanisms: root-owned files, the Linux
immutable attribute (`FS_IMMUTABLE_FL`), and a systemd watchdog pair with mutual
`BindsTo` binding. No kernel exploits, no process hiding, and no LSM tampering
are used; the agent is always visible to root in `ps`, `systemctl`, and on disk
[aucsmith1996tamper; karantzas2021edr]. An authenticated root uninstall path is
preserved by design as a non-negotiable ethical constraint [ball2021monitoring;
roundy2020creepware]. The server (`aegisd`) ships as a single statically-linked
binary with no external database and no runtime asset directory, verified in CI by
an `ldd` static-link assertion, enabled by a pure-Rust dependency stack
(`rustls`/`ring` for TLS, `redb` for embedded storage, `rust-embed` for dashboard
assets).

#### 1.4 Paper map

Section 2 surveys keystroke dynamics, UEBA, bot/human discrimination, security
games, and EDR tamper-resistance prior art. Section 3 presents the threat model
and ethics analysis, covering the four adversary classes (ADV-U, ADV-A, ADV-N,
ADV-P) and the eight protected assets. Section 4 describes the system architecture
in depth: the event model, the plugin trait and registration paths, the event bus
and back-pressure design, and the client/server split. Section 5 describes the
agent-vs-human detection pipeline — feature extraction, the transparent additive
model, the evidence gate, and the scoring and alerting chain. Section 6 presents
the game-theoretic analysis of both the detection game and the tamper-resistance
game. Section 7 evaluates the system on synthetic sessions, reporting detection
performance versus evasion budget and the tamper-resistance layered-cost argument.
Section 8 covers implementation. Section 9 discusses limitations, including the
synthetic evaluation, the unimplemented network transport and hardening lifecycle,
and the path to field validation. Section 10 concludes.

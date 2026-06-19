# Blog Post — Working Outline

**Title (working):** *Can You Tell a Human From an AI at the Keyboard? Building
Aegis, a Plugin-Native Insider-Threat Platform in Rust*

**Authors:** Anthony Herman & Claude

> Structural outline. The narrative + technical diagrams are produced by the blog
> authoring/diagram workflows and assembled into `blog.md`. Diagrams are Mermaid
> (render on GitHub) so the post is self-contained.

## Hook
- A short scenario: an "operator" logs in at 3am and runs a flawless 12-command
  cleanup in 4 seconds, never a typo. Human or agent?

## Why behavior, not content
- Privacy-preserving (timing/structure only); why content is the wrong signal.

## The big idea: everything is a plugin
- The kernel has no features; a diagram of the event bus + plugins.
- Diagram 1: plugin-native architecture.

## Telling humans from agents
- The tells: cadence, think-time, pastes, corrections, rhythm.
- Diagram 2: the detection pipeline (telemetry → features → model → verdict).
- The transparent model: why explainability matters here.

## It's a game
- Adaptive agents fight back; the evasion budget; what's cheap vs costly to fake.
- Diagram 3: detection-vs-evasion, and the AUC-vs-evasion degradation curve.

## Making the agent hard to kill (ethically)
- The insider-threat reality; resisting the user, not the admin.
- Diagram 4: the tamper-resistance layers + the root escape hatch.

## One binary to run it all
- The self-contained static server; backup = copy one file.

## Numbers
- The reproducible synthetic results (AUC, degradation), clearly labelled.

## What's next / try it
- Limitations honestly; link to the repo and the paper.

## Diagram inventory (Mermaid)
1. Plugin-native architecture / event bus.
2. Detection pipeline.
3. Detection-vs-evasion game + degradation curve.
4. Tamper-resistance layers.
5. Agent→server enrollment & telemetry sequence.

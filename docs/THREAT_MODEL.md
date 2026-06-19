# Aegis Threat Model & Ethics

> This document is expanded by the threat-modeling / red-team workflows.

## Protected asset
Monitoring **visibility** on enrolled endpoints, and the **integrity** of the
detection pipeline and server.

## Adversaries
1. **Monitored unprivileged user** attempting to disable/evade endpoint
   monitoring (the primary insider-threat case).
2. **Automated agent** attempting to mimic human behaviour to evade the
   agent-vs-human detector (detection-vs-evasion game).
3. **Network adversary** between agent and server.
4. **Malicious plugin** loaded into the host.

## Ethics & guardrails
- Tamper resistance targets the **unprivileged user**, never the administrator:
  an authenticated **root uninstall** always exists.
- Telemetry is **content-free** (timing/structure only) by design.
- No kernel exploits, no process hiding, no rootkit techniques — supported OS
  mechanisms only.

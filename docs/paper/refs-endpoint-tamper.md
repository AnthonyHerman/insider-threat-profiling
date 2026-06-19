# References — Endpoint protection & tamper resistance

Curated, **web-verified** references for the paper's treatment of endpoint
self-protection, agent integrity, Linux enforcement mechanisms (LSM / immutable
attribute), and the ethics/abuse dimension of monitoring. Each maps to the
`THREAT_MODEL.md` tamper-resistance design (root-owned files, `chattr +i`, the
guardian pair) and to the ethics/abuse-resistance sections of the paper.

BibTeX lives in [`refs-endpoint-tamper.bib`](refs-endpoint-tamper.bib). All seven
entries were confirmed to exist via web search/lookup on 2026-06-19 (publisher,
USENIX, MDPI/DOI, or JRC repository pages). None are fabricated.

| Key | Citation | Verified | Relevance |
|-----|----------|----------|-----------|
| `aucsmith1996tamper` | Aucsmith, *Tamper Resistant Software: An Implementation*, IH '96, LNCS 1174, pp. 317–333. DOI 10.1007/3-540-61996-8_49 | yes | Seminal anti-tampering / agent-integrity work: threat model + design principles for software that resists modification — the conceptual ancestor of EDR self-protection and Aegis's integrity checks. |
| `wright2002lsm` | Wright, Cowan, Smalley, Morris, Kroah-Hartman, *Linux Security Modules: General Security Support for the Linux Kernel*, USENIX Security 2002, pp. 17–31. | yes | The LSM framework that underlies modern Linux mandatory access control; grounds the OS-mechanism claim that hardening can be enforced in-kernel rather than via rootkit techniques. |
| `loscocco2001selinux` | Loscocco & Smalley, *Integrating Flexible Support for Security Policies into the Linux Operating System*, USENIX ATC (FREENIX) 2001, pp. 29–42. | yes | SELinux/Flask: canonical MAC-on-Linux reference for confining even privileged code — supports "supported OS mechanisms only, not a rootkit" and the option to constrain a compromised plugin. |
| `karantzas2021edr` | Karantzas & Patsakis, *An Empirical Assessment of EDR Systems against APT Attack Vectors*, J. Cybersecurity & Privacy 1(3):387–421, 2021. DOI 10.3390/jcp1030021 | yes | Empirically shows adversaries tampering with/"blinding" EDR telemetry providers — directly motivates Aegis's A1 "visibility" asset and self-protection (TB1/TB2) against telemetry suppression. |
| `cappelli2012cert` | Cappelli, Moore, Trzeciak, *The CERT Guide to Insider Threats*, Addison-Wesley (SEI), 2012. ISBN 978-0-321-81257-5 | yes | Foundational insider-threat corpus and mitigation practices; frames why an unprivileged monitored insider (ADV-U) must not be able to silently disable monitoring. |
| `ball2021monitoring` | Ball, *Electronic Monitoring and Surveillance in the Workplace*, EC JRC report JRC125716, 2021. DOI 10.2760/451453 | yes | Rigorous review (398 sources) of workplace-monitoring impacts on trust/autonomy/privacy — anchors the ethics section and the content-free, consent-scoped design constraints. |
| `roundy2020creepware` | Roundy, Mendelberg, Dell, McCoy, Nissani, Ristenpart, Tamersoy, *The Many Kinds of Creepware Used for Interpersonal Attacks*, IEEE S&P 2020, pp. 626–643. DOI 10.1109/SP40000.2020.00069 | yes | Maps the dual-use/abuse surface of monitoring software (stalkerware/creepware) — directly supports the abuse-resistance guardrails (no covert/rootkit capability, always-removable by owner). |

## Verification notes

- **Aucsmith 1996** — confirmed on SpringerLink (chapter DOI 10.1007/3-540-61996-8_49,
  Information Hiding First Int'l Workshop, LNCS 1174, ed. Ross Anderson).
- **Wright et al. 2002** — confirmed via USENIX proceedings + DBLP; author order and
  pages 17–31 cross-checked against the USENIX full-paper PDF and Kroah-Hartman's
  mirror.
- **Loscocco & Smalley 2001** — confirmed via USENIX 2001 FREENIX track listing and
  Semantic Scholar; NSA SELinux portal hosts the paper.
- **Karantzas & Patsakis 2021** — confirmed via MDPI/DOI and arXiv:2108.10422
  (the assessment explicitly discusses tampering with EDR telemetry providers).
- **Cappelli et al. 2012** — confirmed via publisher/Google Books/Amazon and SEI;
  distinct from the CERT *Common Sense Guide* report series (also by CERT/SEI).
- **Ball 2021** — confirmed via EC JRC Publications Office (JRC125716, ISBN
  978-92-76-41480-3, doi:10.2760/451453) and the St Andrews research repository.
- **Roundy et al. 2020** — confirmed via IEEE S&P 2020 program and the authors'
  camera-ready PDF; CreepRank "guilt by association" study of creepware.

## Optional follow-ups (not yet added; verify before citing)

- An eBPF-based provenance/telemetry-integrity paper to buttress the
  "kernel-anchored, un-forgeable signals" argument (§5.1 of the threat model).
- A BYOVD / "bring your own vulnerable driver" or "EDR-kill" study to deepen the
  EDR self-protection-bypass discussion alongside `karantzas2021edr`.

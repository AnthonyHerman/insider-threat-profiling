## Background & Related Work

Aegis draws on five intersecting research areas: behavioral biometrics and
keystroke dynamics, insider-threat detection and user and entity behavior
analytics (UEBA), human-versus-automation discrimination, security games and
adversarial evasion, and endpoint tamper resistance together with the ethics of
workplace monitoring. We situate Aegis's contributions against each area and
are explicit about what is genuinely novel versus what is a deliberate
reapplication of established ideas to a new operational target.

### Keystroke Dynamics and Behavioral Biometrics

The foundational insight is that *how* an operator types reveals something
about *who*—or what—is typing, independent of content. Monrose and Rubin
[monrose2000keystroke] established inter-keystroke timing as a viable biometric
for authentication, and Gunetti and Picardi [gunetti2005free] demonstrated that
free, unconstrained text—not just fixed password strings—provides sufficient
discriminative signal to distinguish individuals. Killourhy and Maxion
[killourhy2009] contributed the canonical CMU benchmark dataset and a rigorous
comparative evaluation of anomaly detectors that remains the standard reference
for methodology. Sim and Janakiraman [sim2007digraphs] issued an important
caveat: context-free digraph timing loses discriminative power relative to
word-specific or phrase-anchored timing, a limitation Aegis takes seriously
because it deliberately discards all content. Modern deep approaches, notably
TypeNet [acien2022typenet], extend free-text keystroke biometrics to Internet
scale using siamese neural networks, and the comprehensive survey of Shadman et
al. [shadman2025keystroke] maps the current landscape of metrics, datasets, and
algorithms. More recently, Modi et al. [modi2026botdetection] explicitly
compare keystroke dynamics and mouse trajectories for the task of bot detection,
the closest published framing to Aegis's agent-vs-human problem.

Aegis reuses this substrate but inverts its conventional goal. Rather than
identifying *which human* is at the keyboard, it asks whether the operator is a
human at all, using only content-free timing and structural features derived
from observed input sequences.

### Insider Threat Detection and UEBA

The conceptual ancestor of Aegis's monitoring model is masquerade detection:
Schonlau et al. [schonlau2001masquerade] framed an unauthorized operator as a
statistical deviation from a legitimate user's behavioral profile captured in
Unix command sequences. The CMU CERT insider-threat dataset [glasser2013cert]
became the de-facto multi-modal benchmark, and the taxonomy of Homoliak et al.
[homoliak2019survey]—distinguishing malicious insiders, masqueraders, and
negligent users—organizes the human actor space that Aegis extends with a
fourth class: the automated agent operating a session that was legitimately
opened by a human. Buczak and Guven [buczak2016survey] survey the ML and
anomaly-detection foundations that underpin behavioral UEBA. Deep learning
approaches, including the unsupervised recurrent architecture of Tuor et al.
[tuor2017deepueba] and the broader review by Yuan and Wu [yuan2021deepreview],
demonstrate that content-free behavioral features—timing, access sequences,
command co-occurrence—are sufficient to surface anomalous activity without
inspecting data payloads.

Aegis's contribution within this line of work is narrow but deliberate: it
treats the agent-vs-human signal as a first-class insider-threat indicator
rather than a secondary heuristic, and favors a transparent, additive scoring
model over the opaque deep architectures that dominate recent UEBA literature.
The trade-off is a bounded statistical ceiling in exchange for explainability
and auditability—properties the CERT guide [cappelli2012cert] implicitly
requires of any monitoring capability that must satisfy an organizational
accountability chain.

### Human-versus-Automation Discrimination

The formal root of the human-or-computer problem is the CAPTCHA [vonahn2003captcha]:
a challenge that a human can resolve but a program cannot, operationalized as
a security primitive. Where CAPTCHA demands active participation, Aegis is
passive and continuous, sitting in the lineage of behavioral discriminators
deployed without explicit user interaction. Ahmed and Traoré [ahmed2007mouse]
demonstrated that passively observed mouse-movement dynamics alone characterize
an operator; Chu et al. [chu2013blogbots] separated bot-authored from
human-authored blog content via passively captured behavioral biometrics; and
BOTracle [kadel2024botracle] performs behavior-only bot detection at web scale
without injecting challenges. Guerar et al. [guerar2021captcha] review twenty
years of the human-or-computer dilemma, including transparent schemes and their
evasion histories—a survey that contextualizes how each generation of
discriminators has been followed by adapted adversaries.

Aegis is squarely in this tradition. Its differentiating factors are the
deployment context (a monitored Linux endpoint rather than a web form or browser
session) and the specific threat model (general AI and scripted agents driving a
shell, not click-fraud bots or blog spammers). The absence of any active
challenge is both a design constraint—enterprise operators cannot be interrupted
with CAPTCHAs during legitimate work—and an adversarial exposure, since a
passive sensor can in principle be profiled and evaded without triggering any
observable response.

### Security Games and Adversarial Evasion

A behavioral detector operating in a contested environment invites evasion, so
Aegis models the detection-vs-evasion interaction as a Stackelberg game in which
the defender commits to a detection policy first and the adversary best-responds
[tambe2011]. Adversary type uncertainty—the detector cannot know a priori
whether the actor is human, script, or AI agent—is handled in the Bayesian-
Stackelberg tradition [paruchuri2008], which yields equilibrium mixed strategies
under incomplete information about attacker type.

The evasion analysis rests on adversarial machine learning. Szegedy et al.
[szegedy2014] revealed that imperceptibly small perturbations suffice to flip
classifier decisions, and Biggio et al. [biggio2013] formalized test-time
evasion as a constrained optimization problem—the lens through which an agent
mimicking human timing can be understood. Biggio and Roli [biggio2018] survey
the resulting decade-long arms race, documenting how each hardening technique
has been followed by an adapted evasion strategy. Hu et al. [hu2025] derive a
game-theoretic Neyman-Pearson detector with equilibrium ROC curves, providing a
principled bound on what any detector can achieve when the adversary knows the
detection scheme. Le and Zincir-Heywood [le2020] show empirically that insiders
can blend malicious actions into normal behavioral profiles, demonstrating
practical evasion of anomaly-based detectors in a realistic enterprise setting.

Aegis applies these frameworks rather than extending their theory. The value of
the analysis is a feature taxonomy that separates cheap-to-fake signals (e.g.,
mean inter-key interval, which an agent can match with a single parameter) from
costly-to-fake signals (e.g., the long-tail distribution of human hesitations
under cognitive load), allowing qualitative reasoning about detector durability
over time rather than a claim of unbreakable detection.

### Endpoint Tamper Resistance and the Ethics of Monitoring

A monitoring sensor that an insider can silently disable provides no assurance.
Aucsmith [aucsmith1996tamper] introduced anti-tampering software design as a
formal concern; Karantzas and Patsakis [karantzas2021edr] empirically demonstrate
that adversaries can blind EDR telemetry through process injection and driver
manipulation, motivating self-protection as a first-order design requirement.
Aegis enforces tamper resistance exclusively through supported OS mechanisms—
Linux Security Modules [wright2002lsm] and SELinux/Flask mandatory access
controls [loscocco2001selinux]—rather than rootkit techniques. An authenticated
root uninstall path is always preserved, ensuring the machine owner retains
control.

The ethical dimension is equally load-bearing. Ball's review of workplace
electronic monitoring [ball2021monitoring] and the creepware study of Roundy et
al. [roundy2020creepware] document how monitoring tooling deployed for security
purposes has been systematically repurposed for intimate-partner surveillance
and employee harassment. These findings ground Aegis's design constraints:
content-free telemetry only (no keylog content, no screen capture), explicit
organizational consent scope, and no covert capability. Aegis does not claim a
new tamper-resistance primitive; its contribution is positioning these
constraints as non-negotiable design requirements that target the unprivileged
monitored user while explicitly foreclosing the abuse surface that makes general
monitoring software dangerous.

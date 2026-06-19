## Agent-vs-Human Detection

Aegis's flagship capability answers a ternary question about an interactive
session: is the entity at the keyboard a **human operator**, an **automated
agent**, or is the evidence **uncertain**? We treat this as a first-class
insider-threat signal rather than a CAPTCHA-style gate [vonahn2003captcha]:
detection is passive, continuous, and—critically—operates on a content-free
behavioral substrate. The full pipeline is shown in Figure 3 (the
Agent-vs-Human Detection Pipeline diagram), from raw TTY read-chunks through
the verdict and the per-session sequential test.

### Content-free behavioral substrate

The detector never sees *what* an operator types, only *how* and *when*.
Terminal read-chunks are reduced at the collector into two content-free event
families: `Keystroke` events carrying inter-arrival timing, a paste flag, and a
burst length; and `CommandObserved` events carrying inter-command timing, a
backspace flag, and the Shannon entropy of the (discarded) command text. No
characters, file paths, or argument values cross the wire. This is a hard
invariant of the system, not a configuration choice, and it shapes the entire
feature design: every signal below is a count, a timing statistic, a ratio, or
a salted hash. The substrate inherits the long line of evidence that operators
are separable from *how* they type independent of *what* they type
[monrose2000keystroke, gunetti2005free, killourhy2009], while inverting the
usual biometric goal—we ask not *which human* is typing but *whether* a human
is typing at all, in the behavior-only tradition of Chu et al. [chu2013blogbots]
and BOTracle [kadel2024botracle]. We adopt Sim and Janakiraman's caution
[sim2007digraphs]—that context-free timing discards discriminative power
available to content-aware schemes—as a deliberate, privacy-motivated cost.

### Feature catalog: marginals versus joint structure

Features are organized by *evasion cost*: not how well a feature separates a
human from a naive agent today, but what an adaptive adversary must construct to
fake it, and whether faking it forces a detectable distortion elsewhere. Two
tiers result.

**Tier-1 marginals** are first-moment statistics that fall to a single
moment-match. The six features in the original shipping model are all Tier-1:
keystroke-timing coefficient of variation, paste ratio, mean inter-command
latency, backspace ratio, mean command entropy, and cadence regularity. Each
can be satisfied by code that targets one scalar—jitter the keystroke timer,
inject a constant pre-command delay, flip a backspace flag on a fraction of
commands—without any model of human behavior. A marginal that checks only a
mean or a variance is, by construction, cheap to forge.

**Tier-2/3 evasion-robust features** measure distribution *shape* or, more
durably, *joint structure*—a relationship between two streams or across time.
The live model weights gap autocorrelation, the think-time tail ratio
(p90/p50), throughput decay over the session, the whole-line injection ratio,
within-burst keystroke-timing variability, and a reaction-time-floor counter.
The defining property of the joint-structure tier is that the cheap evasion of a
Tier-1 feature *actively produces* the Tier-2/3 tell. An agent that injects
i.i.d. random delays to fix its mean inter-command latency and its keystroke CV
thereby drives the gap autocorrelation toward zero—whereas human gap series sit
in a structured, positively autocorrelated band with phase trends (ramp-up,
fast middle, fatigue). An agent that toggles a backspace flag independently of
its timing breaks the coupling between corrections and the localized
keystroke-timing dip a real correction produces. An agent that types character
by character to avoid pasting must then reproduce burst micro-structure it has
no organic reason to generate. These features are, in effect, traps laid on the
standard evasion playbook—most informative precisely against an adversary who
has already defeated the marginals. This taxonomy of cheap- versus
costly-to-fake signals is the analytical contribution carried into the
game-theoretic treatment [tambe2011, biggio2013]; it reasons about a detector's
*durability* under adaptation rather than claiming unbreakability.

### Transparent additive model, hard rules, and calibration

Because every verdict must be explainable to a human analyst, the model is a
deliberately **transparent additive** one rather than an opaque network. Each
feature maps through a documented logistic transfer (with a stated centre and
slope) into an agent-evidence value in `[0,1]`, and the values are combined as a
weighted average; terms that cannot yet be estimated are dropped and the
remaining weights renormalized. The path from the original six-feature model is
to shift decision weight off the Tier-1 marginals and onto the joint-structure
tier while keeping this additive structure intact. The resulting `p_agent` is
thresholded into the ternary verdict: `p_agent ≥ 0.62` yields **Agent**,
`p_agent ≤ 0.35` yields **Human**, and the intervening dead band yields
**Uncertain**. Assessment is gated until enough evidence exists (a minimum
keystroke and command count) and re-runs as events accrue.

Layered on top of the weighted average are **asymmetric hard rules** that can
only ever raise `p_agent`, never lower it. The clearest is the
reaction-time-floor rule: a typed (non-pasted) command issued within roughly
150 ms of the previous one is biomechanically implausible for a human, so a
sub-floor gap can decisively incriminate, while its *absence* contributes
nothing toward a Human verdict. Treating such physiological signals as one-sided
evidence—rather than folding them into a symmetric average—reflects the loss
asymmetry of the deployment: a false "Agent" verdict on a real operator inflates
a risk score toward a human-reviewed alert, and repeated false alerts erode
analyst trust in the signal. The design therefore targets a Neyman-Pearson
objective—maximize the true-positive rate subject to a hard cap on the
false-positive rate—rather than raw accuracy, in the spirit of game-theoretic
Neyman-Pearson detection under strategic evasion [hu2025]. Calibration completes
the picture: the score is mapped to a genuine `P(agent | x)`, so the confidence
consumed by downstream risk scoring is a real probability and the operating
point can be set from the empirical high quantile of a human-only distribution
rather than guessed.

The synthetic evaluation (Section 7) bears out the intended behavior and is
honest about its ceiling. Naive automated agents are separated from humans at
**ROC-AUC 1.000** with **accuracy 1.000** and a zero false-positive rate, and
detection degrades **monotonically** as the evasion budget rises. A *perfect*
behavioral mimic collapses detection toward chance (**AUC 0.500** at evasion
budget `e = 1.0`), exactly as theory predicts—an adversary that perfectly
reproduces human timing is, behaviorally, a human. The value of the detector is
therefore the *cost* it imposes to reach that point: through the mid-budget
range the evasion-robust features keep AUC elevated where cheap marginal
mimicry alone would already have collapsed it. These figures are synthetic,
sampled from documented behavioral distributions rather than collected from
instrumented humans and agents in the field, and are not a claim of field
accuracy.

### EWMA sequential test against dead-band camping

A memoryless per-snapshot verdict has an exploitable flaw: because `Uncertain`
adds no risk downstream, an adaptive agent can deliberately steer `p_agent` into
the dead band between 0.35 and 0.62 and *camp* there, harvesting a stream of
"win" verdicts indefinitely. The joint-structure features also need more
evidence to estimate than a single early snapshot affords. Aegis closes both
gaps with a per-session **sequential test**. Each re-assessment contributes its
log-odds—`logit(p_agent)`—to an exponentially weighted moving average (EWMA)
with smoothing factor `α = 0.3`, so recent evidence is emphasized while
transient dips do not reset the accumulated signal. When the EWMA of the logit
sustains above an escalation threshold (`ewma_logit ≥ 0.25`) while the
instantaneous verdict remains `Uncertain` and the session has not already been
escalated, the detector promotes the verdict to **Agent** with a distinct
`sequential-escalation` reason. This defeats the dead-band camper directly: a
sustained lean toward agent-like behavior accumulates relentlessly even when no
single snapshot crosses the hard threshold, and time favors the defender,
because an agent cannot fake every robust feature for the length of a long
session without leaving a residual. Evasion is thereby reframed from "fool one
snapshot" into "sustain a perfect lie indefinitely"—a burden that forces the
agent toward human throughput and error rates, eroding the very advantage that
made automation worthwhile.

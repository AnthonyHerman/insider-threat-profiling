# Related Work

Aegis draws on five lines of prior work: behavioral biometrics, insider-threat
detection and UEBA, human-versus-automation discrimination, security games and
adversarial evasion, and endpoint tamper resistance together with the ethics of
workplace monitoring. We situate Aegis's four contributions—a plugin-native
architecture, a content-free agent-vs-human detector, a game-theoretic evasion
analysis, and an ethically constrained tamper-resistance design—against this
literature, and are explicit about what is genuinely novel versus what is a
reapplication of established ideas to a new target class.

**Behavioral biometrics.** That an operator can be identified from *how* they
type, independent of *what* they type, is well established. Monrose and Rubin
[monrose2000keystroke] established inter-keystroke timing as a biometric, and
Gunetti and Picardi [gunetti2005free] showed that free, unconstrained text—not
just fixed passwords—suffices to distinguish users. Killourhy and Maxion
[killourhy2009] contributed the canonical CMU benchmark and a rigorous detector
comparison that still anchors evaluation methodology, while Sim and Janakiraman
[sim2007digraphs] cautioned that context-free digraph timing loses discriminative
power relative to word-specific timing—a caveat we take seriously, since Aegis
deliberately discards content. Modern deep methods such as TypeNet
[acien2022typenet] push free-text keystroke biometrics to Internet scale, and the
survey of Shadman et al. [shadman2025keystroke] maps the metric, dataset, and
algorithm landscape. Aegis reuses this substrate but inverts its usual goal:
rather than identifying *which human* is typing, it asks whether the operator is
a human at all, using only content-free timing and structure.

**Insider-threat detection and UEBA.** The conceptual ancestor of our problem is
masquerade detection: Schonlau et al. [schonlau2001masquerade] framed an
unauthorized operator as a deviation from a legitimate user's behavioral profile.
The CMU CERT dataset [glasser2013cert] became the de-facto multi-modal testbed,
and the taxonomy of Homoliak et al. [homoliak2019survey]—malicious insider,
masquerader, negligent user—organizes the actor space we extend with an automated
agent. Methodologically, Buczak and Guven [buczak2016survey] survey the ML
foundations of anomaly-based detection, and deep UEBA work such as Tuor et al.
[tuor2017deepueba] and the review by Yuan and Wu [yuan2021deepreview] establish
that content-free behavioral features (timing, access sequences) can score
anomalous activity. Aegis's contribution here is narrow but deliberate: it treats
the *agent-vs-human* question as a first-class insider-threat signal, and favors
a transparent additive model over the opaque architectures that dominate recent
UEBA, trading some statistical ceiling for explainability.

**Human-versus-automation discrimination.** The formal root is the CAPTCHA
problem [vonahn2003captcha]: a test humans pass but programs cannot. Where CAPTCHA
demands active participation, Aegis is passive and continuous, in the tradition of
behavioral discriminators. Ahmed and Traoré [ahmed2007mouse] showed interaction
dynamics alone characterize an operator; Chu et al. [chu2013blogbots] separated
bots from humans via passively observed biometrics; and recent systems such as
BOTracle [kadel2024botracle] do behavior-only bot detection at web scale. The
survey of Guerar et al. [guerar2021captcha] reviews twenty years of the
human-or-computer dilemma, including transparent schemes and their attacks. Aegis
is squarely in this lineage; its difference is the deployment context (a monitored
Linux endpoint, not a web form) and the specific target (general automated/AI
agents driving a shell, not click-fraud or blog spam).

**Security games and adversarial evasion.** A behavioral detector invites
evasion, so we model detection-vs-evasion as a Stackelberg game in which the
defender commits first [tambe2011], with adversary type uncertainty handled in the
Bayesian-Stackelberg tradition [paruchuri2008]—a natural fit when the detector
cannot know a priori whether the observed actor is human or agent. The evasion
side rests on adversarial ML: Szegedy et al. [szegedy2014] revealed that small
perturbations flip classifier decisions, Biggio et al. [biggio2013] formalized
test-time evasion as optimization, and Biggio and Roli [biggio2018] chronicle the
resulting arms race. Hu et al. [hu2025] give a game-theoretic Neyman-Pearson
detector with equilibrium ROC curves, and Le and Zincir-Heywood [le2020] show
empirically that insiders can blend malicious actions into normal patterns to
evade anomaly detectors. Our analysis applies these frameworks rather than
extending their theory; its value is a feature taxonomy separating cheap-to-fake
from costly-to-fake signals, used to reason about durability rather than to claim
an unbreakable detector.

**Tamper resistance and the ethics of monitoring.** Aucsmith [aucsmith1996tamper]
introduced anti-tampering software design, the conceptual ancestor of EDR
self-protection; Karantzas and Patsakis [karantzas2021edr] empirically show
adversaries "blinding" EDR telemetry, motivating self-protection against signal
suppression. Crucially, Aegis enforces hardening through supported OS
mechanisms—Linux Security Modules [wright2002lsm] and SELinux/Flask
[loscocco2001selinux]—rather than rootkit techniques, and retains an
authenticated root uninstall. The CERT guide [cappelli2012cert] frames why an
unprivileged monitored insider must not silently disable monitoring, while Ball's
review [ball2021monitoring] and the creepware study of Roundy et al.
[roundy2020creepware] ground our ethical constraints: content-free, consent-scoped
telemetry, no covert capability, and always removable by the machine owner. Aegis
does not claim a new tamper-resistance primitive; its contribution is positioning
these constraints as design requirements that target the unprivileged user while
explicitly foreclosing the abuse surface of monitoring tools.

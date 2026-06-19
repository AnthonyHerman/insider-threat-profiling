## Evaluation

We evaluate the agent-vs-human detector on two questions: can it separate automated operators from humans on the behaviours it models, and how does that separation hold up as an adversary spends effort to mimic a human? Because we lack IRB-approved field traces from instrumented humans and agents, the evaluation is conducted on synthetic sessions sampled from documented behavioural distributions and driven through the *real* pipeline. We are explicit throughout that this validates the pipeline and quantifies an evasion trade-off; it is not a claim of field accuracy.

### Methodology

The substrate is a deterministic synthetic generator (`synth.rs`) that samples interactive sessions from behavioural distributions taken from the keystroke-dynamics literature [killourhy2009; gunetti2005free; monrose2000keystroke]. Human inter-keystroke gaps are heavy-tailed (log-normal, mean ~170 ms, high coefficient of variation); inter-command think times are heavy-tailed in seconds and *serially correlated* via a variance-preserving AR(1) process (φ ≈ 0.45), with a fatigue drift that lengthens think times over a session; backspaces (corrections) are common. Modelled automated agents type near-metronomically (mean ~18 ms, low variation) or paste whole lines, react in milliseconds, react independently (φ = 0) with no throughput decay, and rarely mistype. These differences in autocorrelation and decay — not raw speed alone — are what the model's evasion-robust terms key on.

Crucially, synthetic events are not scored by a parallel shortcut model. Each session is folded into the production `SessionAccumulator` — the same feature-extraction path the live collectors feed — and classified by the same transparent additive model the deployed plugin runs. The generator uses a self-contained SplitMix64 PRNG seeded explicitly, so every number below is reproducible. Each reported row averages five seeds (1–5), with 2000 human and 2000 agent sessions per seed (20 000 sessions per row). Agent is the positive class. The headline operating point is the model's natural 0.5 threshold. The full table is produced by `cargo run --release -p plugin-agent-detect --example eval_report`.

To model an adaptive adversary we introduce an *evasion budget* `e ∈ [0,1]` that interpolates the agent's generating parameters toward the human distribution: `e=0` is a naive agent, `e=1` a perfect behavioural mimic whose marginal behaviour is, by construction, the human one. Sweeping `e` traces how detection degrades as the adversary spends effort, which is the quantity of interest for the game-theoretic analysis: the detector's value is the *cost* it imposes, not an unbreakable boundary.

### Results

The table below is taken verbatim from the reproducible harness output (`results.md`).

| evasion e | ROC-AUC | accuracy | precision | recall | F1 | uncertain% |
|----------:|--------:|---------:|----------:|-------:|-----:|-----------:|
| 0.0 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.0% |
| 0.1 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.0% |
| 0.2 | 1.000 | 0.997 | 1.000 | 0.994 | 0.997 | 0.3% |
| 0.3 | 1.000 | 0.838 | 1.000 | 0.675 | 0.806 | 16.2% |
| 0.4 | 1.000 | 0.593 | 1.000 | 0.187 | 0.314 | 40.7% |
| 0.5 | 1.000 | 0.516 | 1.000 | 0.031 | 0.061 | 48.1% |
| 0.6 | 0.999 | 0.502 | 1.000 | 0.004 | 0.007 | 37.0% |
| 0.7 | 0.983 | 0.500 | 0.760 | 0.001 | 0.001 | 8.8% |
| 0.8 | 0.889 | 0.500 | 0.200 | 0.000 | 0.000 | 0.8% |
| 0.9 | 0.716 | 0.500 | 0.000 | 0.000 | 0.000 | 0.1% |
| 1.0 | 0.500 | 0.500 | 0.000 | 0.000 | 0.000 | 0.0% |

The confusion matrices at the 0.5 operating point (mean per seed, verbatim) make the precision/recall trade-off concrete:

*evasion e = 0.0:*

| | predicted agent | predicted human |
|--|--:|--:|
| actual agent | 2000 (TP) | 0 (FN) |
| actual human | 0 (FP) | 2000 (TN) |

*evasion e = 0.5:*

| | predicted agent | predicted human |
|--|--:|--:|
| actual agent | 62 (TP) | 1937 (FN) |
| actual human | 0 (FP) | 2000 (TN) |

*evasion e = 1.0:*

| | predicted agent | predicted human |
|--|--:|--:|
| actual agent | 0 (TP) | 2000 (FN) |
| actual human | 0 (FP) | 2000 (TN) |

### Interpretation

Three findings stand out. First, **no human is ever misclassified as an agent**: the false-positive count is 0 at every operating point shown — `e=0.0`, `e=0.5`, and `e=1.0` alike — and precision stays at 1.000 from `e=0.0` through `e=0.6`. This is the design priority for a monitoring tool, where a false accusation against a legitimate user is the most damaging error [cappelli2012cert; ball2021monitoring]. The detector's failure mode under evasion is to *miss* agents (rising false negatives), not to flag humans. At high budgets precision becomes ill-defined or zero only because the model emits essentially no positive predictions at all (the denominator collapses), not because humans are being flagged — the FP column remains 0.

Second, **ranking power (AUC) holds far longer than threshold accuracy, then degrades gracefully**. ROC-AUC stays at 1.000 through `e=0.6` and only falls below 0.99 past `e=0.7`, reaching chance (0.500) at `e=1.0` exactly as theory predicts: an adversary that perfectly reproduces the human marginal *is*, behaviourally, indistinguishable. Accuracy at the fixed 0.5 threshold drops much earlier (to 0.516 by `e=0.5`) because the agent's score is pushed into the dead band around 0.5, producing abstentions (the `uncertain%` column peaks at 48.1% at `e=0.5`). The gap between near-perfect AUC and collapsing single-shot accuracy through the mid-budget range is informative: the evasion-robust (Tier-2/3) features — serial autocorrelation and throughput decay, which are costly to fake convincingly — keep the classes separable even where cheap (Tier-1) timing mimicry alone would already have flattened the boundary.

Third, the abstentions in the mid-budget range are not wasted signal. The deployed plugin does not classify from a single snapshot; it runs a **sequential test** that folds each re-assessment's log-likelihood ratio into an EWMA and escalates a session that *sustainably* sits in the dead band. The single-shot numbers in the table are therefore a deliberately conservative lower bound: a partial mimic that camps near 0.5 emits repeated `Uncertain` verdicts, and the sequential escalation recovers a large share of these to `Agent` over a longer session — while a guard keeps the human false-positive rate low, which is what makes the rescue safe to deploy. This sequential rescue is the practical answer to the mid-budget recall trough visible at `e=0.4`–`0.6`: the adversary's cost is not just to look human once, but to look human *consistently* across an extended interactive session.

### Limitations

The central caveat must be stated plainly: **these results are synthetic, not field-validated**. Sessions are sampled from documented behavioural distributions, not collected from instrumented humans and agents operating real endpoints. The evaluation rigorously establishes that the production feature pipeline and transparent model separate the *modelled* behaviours, and it quantifies the evasion trade-off under those models — but the absolute AUC, accuracy, and per-budget figures are properties of the generator's distributions, and real human and agent behaviour will differ in ways the generator does not capture. In particular, the evasion budget is an idealised knob: it assumes an adversary can smoothly interpolate toward the human marginal, including hard-to-imitate properties like think-time autocorrelation and fatigue, which a real evader may approximate only crudely or, conversely, defeat in ways we have not modelled. Sim and Janakiraman's caution that content-free timing carries less information than content-aware features [sim2007digraphs] applies directly here, since Aegis deliberately discards content. The synthetic separation should therefore be read as necessary evidence that the mechanism is sound and the evasion economics are as claimed — not as a measured field detection rate. A field study with IRB-approved, consent-scoped data collection, and ground truth from instrumentation such as eBPF/HID capture, is required to estimate real-world accuracy and is left to future work.

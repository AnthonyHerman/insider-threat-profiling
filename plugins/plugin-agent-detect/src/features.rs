//! Behavioral feature extraction for agent-vs-human distinction.
//!
//! Features are derived purely from *timing and structure*, never content. The
//! intuition behind each is documented inline; the accompanying paper derives
//! them more formally. We accumulate raw observations per session and compute a
//! [`FeatureVector`] once enough evidence exists.
//!
//! The feature set is split into tiers by how expensive each signal is to forge:
//!
//! * **Tier 1** — first-moment / per-command marginals (keystroke CV, paste
//!   ratio, mean think time, backspace ratio, entropy, cadence). Cheap to fake:
//!   an evader injecting i.i.d. delays and jitter matches all of these.
//! * **Tier 2** — distributional shape (think-time tail ratio, within-burst
//!   keystroke CV). Harder: requires matching a *distribution*, not a mean.
//! * **Tier 3** — joint / temporal structure (gap autocorrelation, throughput
//!   decay, whole-line paste delivery) and physiological hard-rule inputs
//!   (sub-150 ms non-paste reaction floor). These require reproducing the
//!   *correlations* and *fatigue dynamics* of a real operator and are what an
//!   i.i.d.-delay evader fails to reproduce.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Minimum keystrokes and commands required before we will emit a *provisional*
/// verdict. Kept low so short sessions still resolve (leaning Tier-1 and, by
/// design, more often landing `Uncertain` — the FPR-protecting choice).
pub const MIN_KEYSTROKES: usize = 12;
pub const MIN_COMMANDS: usize = 3;

/// Minimum commands before the volume-hungry Tier-3 temporal features
/// (autocorrelation, think-tail, throughput decay) carry signal. Below this they
/// are emitted as `NaN` sentinels so the model treats them as "no evidence" and
/// renormalizes over the surviving terms. Physiological hard-rule inputs
/// (reaction floor, whole-line paste) remain valid at the low gate.
pub const MIN_COMMANDS_ROBUST: usize = 16;

/// Physiological reaction-time floor in milliseconds. A non-paste command gap
/// shorter than this is faster than a human can read output and react; it is a
/// strong agent signature regardless of how other moments are faked.
const REACTION_FLOOR_MS: f64 = 150.0;

/// Per-session accumulator of raw behavioral observations.
#[derive(Debug, Default, Clone)]
pub struct SessionAccumulator {
    /// Inter-keystroke gaps in milliseconds, in arrival order.
    inter_arrivals_ms: Vec<f64>,
    /// Inter-command "think time" gaps in milliseconds, in arrival order.
    inter_commands_ms: Vec<f64>,
    /// Per-command Shannon entropy (bits/char).
    entropies: Vec<f64>,
    keystrokes: u64,
    pastes: u64,
    commands: u64,
    backspace_commands: u64,
    /// Whether the keystroke input seen since the last `record_command` arrived
    /// as a paste burst. Consumed (and reset) by `record_command` so we can
    /// attribute "this command was delivered whole-line" and "the input
    /// preceding this command's gap was a paste" without storing content.
    pending_command_is_paste: bool,
    /// Count of commands delivered as a single whole-line paste burst.
    whole_line_pastes: u64,
    /// Count of non-paste command gaps below the physiological reaction floor.
    /// (A "perfection tax" input for the model's hard rules.)
    sub_floor_nonpaste_gaps: u64,
}

impl SessionAccumulator {
    pub fn record_keystroke(&mut self, inter_arrival_ns: u64, is_paste: bool, burst_len: u32) {
        self.keystrokes += burst_len.max(1) as u64;
        if is_paste {
            self.pastes += 1;
        }
        // Remember whether the most recent input toward the pending command was a
        // paste. The last keystroke before `record_command` wins; for a
        // whole-line paste that is the single paste burst itself.
        self.pending_command_is_paste = is_paste;
        // Ignore the very first keystroke's gap (no predecessor) and absurd gaps.
        let ms = inter_arrival_ns as f64 / 1.0e6;
        if ms > 0.0 && ms < 60_000.0 {
            self.inter_arrivals_ms.push(ms);
        }
    }

    pub fn record_command(&mut self, inter_command_ns: u64, had_backspace: bool, entropy: f64) {
        self.commands += 1;
        if had_backspace {
            self.backspace_commands += 1;
        }
        self.entropies.push(entropy);

        let was_paste = self.pending_command_is_paste;
        if was_paste {
            self.whole_line_pastes += 1;
        }
        // Reset for the next command's keystrokes.
        self.pending_command_is_paste = false;

        let ms = inter_command_ns as f64 / 1.0e6;
        // A sub-floor reaction is only incriminating if the command was *typed*
        // (a paste legitimately arrives instantly). Count it before the upper
        // filter so a fast slip is never silently dropped.
        if ms > 0.0 && ms < REACTION_FLOOR_MS && !was_paste {
            self.sub_floor_nonpaste_gaps += 1;
        }
        // Retain the gap itself (keep the existing lower/upper filtering: drop
        // only non-positive and >=1h gaps — sub-150 ms gaps must be retained so
        // the tail/autocorr/decay statistics see the genuine distribution).
        if ms > 0.0 && ms < 3_600_000.0 {
            self.inter_commands_ms.push(ms);
        }
    }

    pub fn enough_evidence(&self) -> bool {
        self.keystrokes as usize >= MIN_KEYSTROKES && self.commands as usize >= MIN_COMMANDS
    }

    /// Compute the feature vector, or `None` if there is insufficient evidence.
    ///
    /// Tier-3 temporal features require `MIN_COMMANDS_ROBUST` command gaps; below
    /// that they are emitted as `NaN` so the model renormalizes over the terms it
    /// can trust. The hard-rule inputs (`reaction_floor_hits`,
    /// `whole_line_paste_ratio`) and Tier-1/2 marginals are always populated once
    /// the low gate is met.
    pub fn features(&self) -> Option<FeatureVector> {
        if !self.enough_evidence() {
            return None;
        }
        let (ka_mean, ka_std) = mean_std(&self.inter_arrivals_ms);
        let keystroke_cv = if ka_mean > 0.0 { ka_std / ka_mean } else { 0.0 };

        let (ic_mean, ic_std) = mean_std(&self.inter_commands_ms);
        let inter_command_cv = if ic_mean > 0.0 { ic_std / ic_mean } else { 0.0 };
        let cadence_regularity = 1.0 - inter_command_cv.min(1.0);

        let paste_ratio = ratio(self.pastes, self.commands.max(1));
        let backspace_ratio = ratio(self.backspace_commands, self.commands.max(1));
        let entropy_mean = if self.entropies.is_empty() {
            0.0
        } else {
            self.entropies.iter().sum::<f64>() / self.entropies.len() as f64
        };

        // --- Tier 2/3: shape and joint structure -------------------------------

        // Within-burst keystroke variability: only gaps that plausibly belong to
        // one typing burst (gap < 300 ms). A char-by-char metronome has near-zero
        // CV here even if a few large idle gaps inflate the global CV.
        let burst_gaps: Vec<f64> = self
            .inter_arrivals_ms
            .iter()
            .copied()
            .filter(|&g| g < 300.0)
            .collect();
        let keystroke_burst_cv = {
            let (m, s) = mean_std(&burst_gaps);
            if burst_gaps.len() >= 4 && m > 0.0 {
                s / m
            } else {
                f64::NAN
            }
        };

        // Whole-line paste delivery: fraction of commands delivered atomically.
        let whole_line_paste_ratio = ratio(self.whole_line_pastes, self.commands.max(1));

        // Reaction-floor hits: fraction of (all) command gaps that were sub-floor
        // non-paste. Valid at the low gate; feeds the physiological hard rules.
        let reaction_floor_hits = ratio(self.sub_floor_nonpaste_gaps, self.commands.max(1));

        // Tier-3 temporal features: require robust volume, else NaN sentinels.
        let robust = self.commands as usize >= MIN_COMMANDS_ROBUST;
        let gap_autocorr = if robust {
            lag1_autocorr(&self.inter_commands_ms)
        } else {
            f64::NAN
        };
        let think_tail_ratio = if robust {
            let p50 = percentile(&self.inter_commands_ms, 0.50);
            let p90 = percentile(&self.inter_commands_ms, 0.90);
            if p50 > 0.0 {
                p90 / p50
            } else {
                f64::NAN
            }
        } else {
            f64::NAN
        };
        let throughput_decay = if robust {
            decay_slope(&self.inter_commands_ms)
        } else {
            f64::NAN
        };

        Some(FeatureVector {
            keystroke_cv,
            paste_ratio,
            mean_inter_command_ms: ic_mean,
            backspace_ratio,
            entropy_mean,
            cadence_regularity,
            gap_autocorr,
            think_tail_ratio,
            throughput_decay,
            reaction_floor_hits,
            whole_line_paste_ratio,
            keystroke_burst_cv,
        })
    }
}

fn ratio(num: u64, den: u64) -> f64 {
    if den == 0 {
        0.0
    } else {
        num as f64 / den as f64
    }
}

/// Population mean and standard deviation.
pub fn mean_std(xs: &[f64]) -> (f64, f64) {
    if xs.is_empty() {
        return (0.0, 0.0);
    }
    let n = xs.len() as f64;
    let mean = xs.iter().sum::<f64>() / n;
    let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    (mean, var.sqrt())
}

/// Lag-1 Pearson autocorrelation of a series (mean-centered).
///
/// Independent delays (the cheapest evasion: inject i.i.d. padding) produce
/// ≈0; genuine human think-time is serially correlated (≈0.1–0.6) because
/// difficulty, fatigue and context persist across adjacent commands. Returns
/// `0.0` for series too short or with no variance.
fn lag1_autocorr(xs: &[f64]) -> f64 {
    if xs.len() < 4 {
        return 0.0;
    }
    let n = xs.len() as f64;
    let mean = xs.iter().sum::<f64>() / n;
    let mut denom = 0.0;
    for &x in xs {
        denom += (x - mean) * (x - mean);
    }
    if denom <= 0.0 {
        return 0.0;
    }
    let mut numer = 0.0;
    for w in xs.windows(2) {
        numer += (w[0] - mean) * (w[1] - mean);
    }
    numer / denom
}

/// The `q`-quantile (0..=1) of `xs` via sorted linear interpolation.
/// Returns `0.0` for an empty slice.
fn percentile(xs: &[f64], q: f64) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    if v.len() == 1 {
        return v[0];
    }
    let q = q.clamp(0.0, 1.0);
    let pos = q * (v.len() - 1) as f64;
    let lo = pos.floor() as usize;
    let hi = pos.ceil() as usize;
    if lo == hi {
        v[lo]
    } else {
        let frac = pos - lo as f64;
        v[lo] * (1.0 - frac) + v[hi] * frac
    }
}

/// Normalized throughput-decay slope in roughly `[-1, 1]`.
///
/// We regress the *command index* (y) on *cumulative elapsed time* (x) — the
/// inverse of throughput. A human slows down over a session (fatigue, deeper
/// reading): commands accrue more slowly per unit time, so the slope of
/// index-vs-elapsed *decreases* relative to a constant-rate baseline, yielding a
/// negative normalized value. An agent holds (or raises) a constant rate →
/// ≈0 or positive. We compare the local rate in the first vs second half and
/// squash with `tanh`. Returns `0.0` if insufficient.
fn decay_slope(gaps: &[f64]) -> f64 {
    if gaps.len() < 6 {
        return 0.0;
    }
    // Cumulative elapsed time at each command boundary.
    let mut elapsed = Vec::with_capacity(gaps.len());
    let mut acc = 0.0;
    for &g in gaps {
        acc += g;
        elapsed.push(acc);
    }
    let total = *elapsed.last().unwrap();
    if total <= 0.0 {
        return 0.0;
    }
    // Throughput = commands per ms. Compare first-half vs second-half rate.
    let mid = gaps.len() / 2;
    let first_cmds = mid as f64;
    let first_time = elapsed[mid - 1];
    let second_cmds = (gaps.len() - mid) as f64;
    let second_time = total - elapsed[mid - 1];
    if first_time <= 0.0 || second_time <= 0.0 {
        return 0.0;
    }
    let rate_first = first_cmds / first_time;
    let rate_second = second_cmds / second_time;
    if rate_first <= 0.0 {
        return 0.0;
    }
    // Relative change in throughput: negative ⇒ slowing down (human fatigue).
    let rel = (rate_second - rate_first) / rate_first;
    // Squash to keep the model's transfer well-conditioned.
    (rel * 1.5).tanh()
}

/// The standardized behavioral feature vector consumed by the model.
///
/// The first six fields are the original Tier-1 marginals. The remaining fields
/// (added later) carry the evasion-robust Tier-2/3 evidence and the
/// physiological hard-rule inputs. They are `#[serde(default)]` so vectors
/// serialized before they existed still deserialize (missing ⇒ `0.0`).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct FeatureVector {
    /// Coefficient of variation of inter-keystroke timing. Humans are bursty and
    /// irregular (high CV); automation is metronomic (low CV). *(Tier 1)*
    pub keystroke_cv: f64,
    /// Fraction of commands delivered as atomic pastes/bursts (agents paste).
    /// *(Tier 1)*
    pub paste_ratio: f64,
    /// Mean think time between commands in ms (humans read output; agents react).
    /// *(Tier 1)*
    pub mean_inter_command_ms: f64,
    /// Fraction of commands composed with corrections/backspaces (humans err).
    /// *(Tier 1)*
    pub backspace_ratio: f64,
    /// Mean Shannon entropy of commands (agents emit clean, dense one-liners).
    /// *(Tier 1)*
    pub entropy_mean: f64,
    /// Regularity of command cadence in [0,1] (agents are clockwork-regular).
    /// *(Tier 1)*
    pub cadence_regularity: f64,

    /// Lag-1 autocorrelation of inter-command think times. i.i.d. injected
    /// delays ⇒ ≈0 (agent); genuine operators ⇒ 0.1–0.6. `NaN` below the robust
    /// command gate. *(Tier 3 — traps the cheapest evasion)*
    #[serde(default)]
    pub gap_autocorr: f64,
    /// p90/p50 of inter-command think times. Constant/uniform padding ⇒ ≈1
    /// (agent); humans have heavy tails ⇒ >4. `NaN` below the robust gate.
    /// *(Tier 2)*
    #[serde(default)]
    pub think_tail_ratio: f64,
    /// Normalized throughput decay in [-1,1]. Negative ⇒ slowing (human
    /// fatigue); flat/positive ⇒ agent. `NaN` below the robust gate. *(Tier 3)*
    #[serde(default)]
    pub throughput_decay: f64,
    /// Fraction of non-paste command gaps below the ~150 ms physiological
    /// reaction floor. A hard-rule input: even a single slip incriminates a long
    /// session. *(Tier 3 hard-rule input)*
    #[serde(default)]
    pub reaction_floor_hits: f64,
    /// Fraction of commands delivered as a single whole-line paste burst.
    /// Refines `paste_ratio` toward the agent-shaped atomic delivery. *(Tier 3)*
    #[serde(default)]
    pub whole_line_paste_ratio: f64,
    /// CV of within-burst keystroke gaps (gaps < 300 ms). Sharpens metronomic
    /// detection of char-by-char fakes. `NaN` with too few burst gaps. *(Tier 2)*
    #[serde(default)]
    pub keystroke_burst_cv: f64,
}

impl FeatureVector {
    /// Flatten to a labelled map for inclusion in a [`Detection`] event. Emits
    /// every feature (old and new) so the dashboard/analyst sees the full,
    /// evasion-robust evidence behind a verdict.
    pub fn to_map(&self) -> BTreeMap<String, f64> {
        let mut m = BTreeMap::new();
        m.insert("keystroke_cv".into(), self.keystroke_cv);
        m.insert("paste_ratio".into(), self.paste_ratio);
        m.insert("mean_inter_command_ms".into(), self.mean_inter_command_ms);
        m.insert("backspace_ratio".into(), self.backspace_ratio);
        m.insert("entropy_mean".into(), self.entropy_mean);
        m.insert("cadence_regularity".into(), self.cadence_regularity);
        m.insert("gap_autocorr".into(), self.gap_autocorr);
        m.insert("think_tail_ratio".into(), self.think_tail_ratio);
        m.insert("throughput_decay".into(), self.throughput_decay);
        m.insert("reaction_floor_hits".into(), self.reaction_floor_hits);
        m.insert("whole_line_paste_ratio".into(), self.whole_line_paste_ratio);
        m.insert("keystroke_burst_cv".into(), self.keystroke_burst_cv);
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulator_gates_on_evidence() {
        let mut acc = SessionAccumulator::default();
        assert!(acc.features().is_none());
        for _ in 0..20 {
            acc.record_keystroke(150_000_000, false, 1);
        }
        // keystrokes ok but no commands yet
        assert!(acc.features().is_none());
        for _ in 0..3 {
            acc.record_command(2_000_000_000, true, 3.5);
        }
        assert!(acc.features().is_some());
    }

    #[test]
    fn human_like_inputs_yield_high_cv() {
        let mut acc = SessionAccumulator::default();
        // Irregular human-ish gaps.
        for ms in [
            80.0, 220.0, 130.0, 400.0, 90.0, 310.0, 175.0, 60.0, 500.0, 140.0, 95.0, 260.0, 330.0,
            110.0,
        ] {
            acc.record_keystroke((ms * 1.0e6) as u64, false, 1);
        }
        for _ in 0..4 {
            acc.record_command(3_500_000_000, true, 3.4);
        }
        let f = acc.features().unwrap();
        assert!(f.keystroke_cv > 0.4, "cv was {}", f.keystroke_cv);
        assert!(f.backspace_ratio > 0.9);
    }

    #[test]
    fn tier3_features_are_nan_below_robust_gate() {
        // 3 commands (>= MIN_COMMANDS) but < MIN_COMMANDS_ROBUST.
        let mut acc = SessionAccumulator::default();
        for _ in 0..20 {
            acc.record_keystroke(150_000_000, false, 1);
        }
        for _ in 0..3 {
            acc.record_command(2_000_000_000, false, 3.5);
        }
        let f = acc.features().unwrap();
        assert!(f.gap_autocorr.is_nan(), "autocorr should be NaN");
        assert!(f.think_tail_ratio.is_nan(), "tail should be NaN");
        assert!(f.throughput_decay.is_nan(), "decay should be NaN");
        // Hard-rule inputs remain valid at the low gate.
        assert!(f.reaction_floor_hits.is_finite());
        assert!(f.whole_line_paste_ratio.is_finite());
    }

    #[test]
    fn tier3_features_present_above_robust_gate() {
        let mut acc = SessionAccumulator::default();
        for _ in 0..40 {
            acc.record_keystroke(150_000_000, false, 1);
        }
        // 20 commands with varied think times so the stats are well-defined.
        for i in 0..20 {
            let ms = 2_000 + (i % 5) * 700; // varied -> finite tail ratio
            acc.record_command((ms as u64) * 1_000_000, false, 3.5);
        }
        let f = acc.features().unwrap();
        assert!(f.gap_autocorr.is_finite());
        assert!(f.think_tail_ratio.is_finite() && f.think_tail_ratio >= 1.0);
        assert!(f.throughput_decay.is_finite());
    }

    #[test]
    fn reaction_floor_counts_only_nonpaste_fast_gaps() {
        let mut acc = SessionAccumulator::default();
        // 20 keystrokes for the gate.
        for _ in 0..20 {
            acc.record_keystroke(150_000_000, false, 1);
        }
        // Typed, fast (50 ms) -> counts as a floor hit.
        acc.record_command(50_000_000, false, 3.5);
        // A paste burst then a fast command -> must NOT count (paste is instant).
        acc.record_keystroke(5_000_000, true, 30);
        acc.record_command(40_000_000, false, 3.5);
        // Typed, slow -> not a floor hit.
        acc.record_command(3_000_000_000, false, 3.5);
        let f = acc.features().unwrap();
        // 1 floor hit out of 3 commands.
        assert!(
            (f.reaction_floor_hits - 1.0 / 3.0).abs() < 1e-9,
            "hits {}",
            f.reaction_floor_hits
        );
        // 1 whole-line paste out of 3 commands.
        assert!(
            (f.whole_line_paste_ratio - 1.0 / 3.0).abs() < 1e-9,
            "wl {}",
            f.whole_line_paste_ratio
        );
    }

    #[test]
    fn lag1_autocorr_detects_iid_vs_correlated() {
        // i.i.d.-ish alternating noise around a mean -> low/negative autocorr.
        let iid = [10.0, 11.0, 9.0, 12.0, 8.0, 11.0, 9.5, 10.5, 9.0, 11.0];
        assert!(lag1_autocorr(&iid) < 0.3, "iid {}", lag1_autocorr(&iid));
        // Smooth trend -> high positive autocorr.
        let trend: Vec<f64> = (0..12).map(|i| i as f64).collect();
        assert!(
            lag1_autocorr(&trend) > 0.6,
            "trend {}",
            lag1_autocorr(&trend)
        );
        // Too short -> 0.
        assert_eq!(lag1_autocorr(&[1.0, 2.0]), 0.0);
    }

    #[test]
    fn percentile_interpolates() {
        let xs = [1.0, 2.0, 3.0, 4.0, 5.0];
        assert!((percentile(&xs, 0.5) - 3.0).abs() < 1e-9);
        assert!((percentile(&xs, 0.0) - 1.0).abs() < 1e-9);
        assert!((percentile(&xs, 1.0) - 5.0).abs() < 1e-9);
        assert_eq!(percentile(&[], 0.5), 0.0);
    }

    #[test]
    fn decay_slope_negative_when_slowing() {
        // First half fast (rate high), second half slow (rate low) -> decay < 0.
        let mut gaps = vec![100.0; 6]; // fast
        gaps.extend(vec![2000.0; 6]); // slow
        assert!(decay_slope(&gaps) < -0.1, "slope {}", decay_slope(&gaps));
        // Constant rate -> ~0.
        let flat = vec![500.0; 12];
        assert!(
            decay_slope(&flat).abs() < 1e-6,
            "flat {}",
            decay_slope(&flat)
        );
    }
}

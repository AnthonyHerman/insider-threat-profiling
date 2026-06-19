//! Behavioral feature extraction for agent-vs-human distinction.
//!
//! Features are derived purely from *timing and structure*, never content. The
//! intuition behind each is documented inline; the accompanying paper derives
//! them more formally. We accumulate raw observations per session and compute a
//! [`FeatureVector`] once enough evidence exists.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Minimum keystrokes and commands required before we will emit a verdict.
pub const MIN_KEYSTROKES: usize = 12;
pub const MIN_COMMANDS: usize = 3;

/// Per-session accumulator of raw behavioral observations.
#[derive(Debug, Default, Clone)]
pub struct SessionAccumulator {
    /// Inter-keystroke gaps in milliseconds.
    inter_arrivals_ms: Vec<f64>,
    /// Inter-command "think time" gaps in milliseconds.
    inter_commands_ms: Vec<f64>,
    /// Per-command Shannon entropy (bits/char).
    entropies: Vec<f64>,
    keystrokes: u64,
    pastes: u64,
    commands: u64,
    backspace_commands: u64,
}

impl SessionAccumulator {
    pub fn record_keystroke(&mut self, inter_arrival_ns: u64, is_paste: bool, burst_len: u32) {
        self.keystrokes += burst_len.max(1) as u64;
        if is_paste {
            self.pastes += 1;
        }
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
        let ms = inter_command_ns as f64 / 1.0e6;
        if ms > 0.0 && ms < 3_600_000.0 {
            self.inter_commands_ms.push(ms);
        }
    }

    pub fn enough_evidence(&self) -> bool {
        self.keystrokes as usize >= MIN_KEYSTROKES && self.commands as usize >= MIN_COMMANDS
    }

    /// Compute the feature vector, or `None` if there is insufficient evidence.
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

        Some(FeatureVector {
            keystroke_cv,
            paste_ratio,
            mean_inter_command_ms: ic_mean,
            backspace_ratio,
            entropy_mean,
            cadence_regularity,
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

/// The standardized behavioral feature vector consumed by the model.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct FeatureVector {
    /// Coefficient of variation of inter-keystroke timing. Humans are bursty and
    /// irregular (high CV); automation is metronomic (low CV).
    pub keystroke_cv: f64,
    /// Fraction of commands delivered as atomic pastes/bursts (agents paste).
    pub paste_ratio: f64,
    /// Mean think time between commands in ms (humans read output; agents react).
    pub mean_inter_command_ms: f64,
    /// Fraction of commands composed with corrections/backspaces (humans err).
    pub backspace_ratio: f64,
    /// Mean Shannon entropy of commands (agents emit clean, dense one-liners).
    pub entropy_mean: f64,
    /// Regularity of command cadence in [0,1] (agents are clockwork-regular).
    pub cadence_regularity: f64,
}

impl FeatureVector {
    /// Flatten to a labelled map for inclusion in a [`Detection`] event.
    pub fn to_map(&self) -> BTreeMap<String, f64> {
        let mut m = BTreeMap::new();
        m.insert("keystroke_cv".into(), self.keystroke_cv);
        m.insert("paste_ratio".into(), self.paste_ratio);
        m.insert("mean_inter_command_ms".into(), self.mean_inter_command_ms);
        m.insert("backspace_ratio".into(), self.backspace_ratio);
        m.insert("entropy_mean".into(), self.entropy_mean);
        m.insert("cadence_regularity".into(), self.cadence_regularity);
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
}

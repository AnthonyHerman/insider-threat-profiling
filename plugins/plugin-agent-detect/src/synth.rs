//! Synthetic behavioral-trace generator for reproducible evaluation.
//!
//! To evaluate the agent-vs-human detector without access to labelled field
//! data, we sample interactive sessions from *documented behavioral
//! distributions* and feed them through the **real** feature pipeline
//! ([`SessionAccumulator`]) and model. This is honest about its limits: synthetic
//! data validates that the pipeline separates the modelled behaviours, not that
//! the model is field-accurate. The distributions are drawn from the
//! keystroke-dynamics literature:
//!
//! * **Human** inter-keystroke gaps are heavy-tailed/log-normal (high
//!   coefficient of variation); think-time between commands is heavy-tailed
//!   (seconds); corrections (backspaces) are common.
//! * **Automated agents** emit near-constant keystroke timing or whole-line
//!   pastes, react in milliseconds, and rarely "mistype".
//!
//! The generator is fully deterministic given a seed (no external RNG), so every
//! number in the paper is reproducible.

use crate::features::SessionAccumulator;

/// A small, fast, deterministic PRNG (SplitMix64). Deterministic output keeps
/// the evaluation reproducible across machines and CI.
#[derive(Debug, Clone)]
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng {
            state: seed ^ 0x9E37_79B9_7F4A_7C15,
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in [0, 1).
    pub fn uniform(&mut self) -> f64 {
        // 53-bit mantissa precision.
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Standard normal via Box–Muller.
    pub fn normal(&mut self, mean: f64, std: f64) -> f64 {
        let u1 = (self.uniform()).max(1e-12);
        let u2 = self.uniform();
        let z = (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos();
        mean + std * z
    }

    /// Log-normal with the given underlying-normal parameters.
    pub fn lognormal(&mut self, mu: f64, sigma: f64) -> f64 {
        self.normal(mu, sigma).exp()
    }

    /// Bernoulli trial.
    pub fn bernoulli(&mut self, p: f64) -> bool {
        self.uniform() < p
    }

    /// A positive integer count from a clamped normal.
    pub fn count(&mut self, mean: f64, std: f64, min: u32) -> u32 {
        let v = self.normal(mean, std).round();
        (v.max(min as f64)) as u32
    }
}

/// Which behaviour to synthesize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Human,
    Agent,
}

/// Tunable parameters for a synthetic profile. Defaults encode the literature
/// values; the evasion harness perturbs the [`Profile::Agent`] parameters to
/// model an adaptive evader.
#[derive(Debug, Clone)]
pub struct ProfileParams {
    /// Underlying-normal (mu, sigma) for inter-keystroke gap (ms), log-normal.
    pub keystroke_lognormal: (f64, f64),
    /// (mu, sigma) for inter-command think time (ms), log-normal.
    pub think_lognormal: (f64, f64),
    /// Probability a command was composed with at least one backspace.
    pub backspace_p: f64,
    /// Probability a command is delivered as a paste/burst.
    pub paste_p: f64,
    /// (mean, std) of per-command Shannon entropy (bits/char).
    pub entropy: (f64, f64),
    /// (mean, std) of commands per session.
    pub commands: (f64, f64),
    /// (mean, std) of keystrokes per typed command.
    pub keystrokes_per_cmd: (f64, f64),
}

impl ProfileParams {
    pub fn human() -> Self {
        ProfileParams {
            keystroke_lognormal: (5.0, 0.55), // mean ~170ms, CV ~0.6
            think_lognormal: (8.0, 0.85),     // mean ~4s, heavy tail
            backspace_p: 0.30,
            paste_p: 0.02,
            entropy: (3.6, 0.3),
            commands: (8.0, 2.0),
            keystrokes_per_cmd: (24.0, 6.0),
        }
    }

    pub fn agent() -> Self {
        ProfileParams {
            keystroke_lognormal: (2.9, 0.12), // mean ~18ms, CV ~0.12 (metronomic)
            think_lognormal: (3.9, 0.25),     // mean ~50ms, instant reaction
            backspace_p: 0.03,
            paste_p: 0.5,
            entropy: (4.7, 0.2),
            commands: (10.0, 3.0),
            keystrokes_per_cmd: (28.0, 8.0),
        }
    }

    pub fn for_profile(profile: Profile) -> Self {
        match profile {
            Profile::Human => Self::human(),
            Profile::Agent => Self::agent(),
        }
    }
}

/// Generate one synthetic session and return the populated accumulator. The
/// accumulator is the *real* one the plugin uses, so this exercises the genuine
/// feature-extraction path.
pub fn synth_session(params: &ProfileParams, rng: &mut Rng) -> SessionAccumulator {
    let mut acc = SessionAccumulator::default();
    let n_commands = rng.count(params.commands.0, params.commands.1, 3);

    for _ in 0..n_commands {
        let is_paste = rng.bernoulli(params.paste_p);
        let cmd_len = rng.count(params.keystrokes_per_cmd.0, params.keystrokes_per_cmd.1, 12);

        if is_paste {
            // A paste delivers the whole line atomically: one fast burst.
            let gap_ms = rng.lognormal(params.keystroke_lognormal.0.min(3.0), 0.2);
            acc.record_keystroke((gap_ms * 1.0e6) as u64, true, cmd_len);
        } else {
            // Typed character by character with profile-specific cadence.
            for _ in 0..cmd_len {
                let gap_ms = rng
                    .lognormal(params.keystroke_lognormal.0, params.keystroke_lognormal.1)
                    .clamp(1.0, 5_000.0);
                acc.record_keystroke((gap_ms * 1.0e6) as u64, false, 1);
            }
        }

        let think_ms = rng
            .lognormal(params.think_lognormal.0, params.think_lognormal.1)
            .clamp(1.0, 600_000.0);
        let had_backspace = rng.bernoulli(params.backspace_p);
        let entropy = rng
            .normal(params.entropy.0, params.entropy.1)
            .clamp(0.0, 8.0);
        acc.record_command((think_ms * 1.0e6) as u64, had_backspace, entropy);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rng_is_deterministic() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn normal_has_expected_moments() {
        let mut rng = Rng::new(7);
        let n = 20_000;
        let xs: Vec<f64> = (0..n).map(|_| rng.normal(10.0, 2.0)).collect();
        let mean = xs.iter().sum::<f64>() / n as f64;
        let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
        assert!((mean - 10.0).abs() < 0.1, "mean {mean}");
        assert!((var.sqrt() - 2.0).abs() < 0.1, "std {}", var.sqrt());
    }

    #[test]
    fn profiles_separate_in_feature_space() {
        let mut rng = Rng::new(1);
        let h = synth_session(&ProfileParams::human(), &mut rng)
            .features()
            .unwrap();
        let a = synth_session(&ProfileParams::agent(), &mut rng)
            .features()
            .unwrap();
        // The defining separations should hold for typical draws.
        assert!(
            h.keystroke_cv > a.keystroke_cv,
            "h_cv {} a_cv {}",
            h.keystroke_cv,
            a.keystroke_cv
        );
        assert!(h.mean_inter_command_ms > a.mean_inter_command_ms);
    }
}

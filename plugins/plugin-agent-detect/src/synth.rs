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
    /// AR(1) coefficient `φ ∈ [0,1)` on the *underlying-normal* think-time
    /// process. Real operators' think times are **serially correlated** —
    /// difficulty, context and concentration persist across adjacent commands —
    /// so humans use `φ ≈ 0.45`. Automated agents react independently each time
    /// (`φ = 0`). The AR(1) is variance-preserving, so the think-time marginal
    /// (mean, tail) is unchanged; only the *autocorrelation* differs. This is
    /// what the model's `gap-non-autocorrelation` term and the
    /// `uncorrelated-flat-throughput` hard rule key on.
    pub think_autocorr: f64,
    /// Fractional drift of the think-time location across a session (fatigue).
    /// Humans slow down over a long session (`+0.5` ⇒ think times ~50% longer by
    /// the end), giving a *negative* throughput decay. Agents hold a constant
    /// rate (`0.0`). Keyed on by the model's `no-throughput-decay` term.
    pub think_fatigue: f64,
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
            think_autocorr: 0.45, // think times persist across commands
            think_fatigue: 0.5,   // operator slows down over the session
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
            think_autocorr: 0.0, // independent reactions
            think_fatigue: 0.0,  // constant throughput
        }
    }

    pub fn for_profile(profile: Profile) -> Self {
        match profile {
            Profile::Human => Self::human(),
            Profile::Agent => Self::agent(),
        }
    }
}

/// One synthesized behavioral event, in arrival order. Mirrors the timing-only
/// telemetry the collectors emit ([`Keystroke`](SynthEvent::Keystroke) /
/// [`Command`](SynthEvent::Command)), so callers can either fold a whole session
/// into an accumulator at once ([`synth_session`]) or replay it
/// snapshot-by-snapshot (the sequential-test harness).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SynthEvent {
    Keystroke {
        inter_arrival_ns: u64,
        is_paste: bool,
        burst_len: u32,
    },
    Command {
        inter_command_ns: u64,
        had_backspace: bool,
        entropy: f64,
    },
}

impl SynthEvent {
    /// Apply this event to an accumulator (the genuine feature-extraction path).
    pub fn apply(&self, acc: &mut SessionAccumulator) {
        match *self {
            SynthEvent::Keystroke {
                inter_arrival_ns,
                is_paste,
                burst_len,
            } => acc.record_keystroke(inter_arrival_ns, is_paste, burst_len),
            SynthEvent::Command {
                inter_command_ns,
                had_backspace,
                entropy,
            } => acc.record_command(inter_command_ns, had_backspace, entropy),
        }
    }
}

/// Generate one synthetic session as an ordered [`SynthEvent`] stream.
///
/// `min_commands` forces at least that many commands (use `0` for the natural
/// draw); the sequential-test harness forces a longer session so the robust
/// Tier-3 features engage and there are multiple re-assessment snapshots. Human
/// think times follow a variance-preserving AR(1) process with a fatigue drift
/// (see [`ProfileParams::think_autocorr`]/[`ProfileParams::think_fatigue`]);
/// agents react independently with constant throughput.
pub fn synth_events(params: &ProfileParams, rng: &mut Rng, min_commands: u32) -> Vec<SynthEvent> {
    let n_commands = rng.count(
        params.commands.0.max(min_commands as f64),
        params.commands.1,
        min_commands.max(3),
    );

    // AR(1) state on the *underlying-normal* think time. We carry the previous
    // deviation from the (drifting) mean so successive think times are serially
    // correlated for humans (φ>0) and independent for agents (φ=0). The
    // innovation is scaled by √(1−φ²) so the marginal variance — and hence the
    // think-time tail — is preserved regardless of φ.
    let (think_mu, think_sigma) = params.think_lognormal;
    let phi = params.think_autocorr.clamp(0.0, 0.99);
    let innov_scale = (1.0 - phi * phi).sqrt();
    let mut prev_dev = 0.0f64; // previous (z - mu_t) deviation
    let mut have_prev = false;

    let mut events = Vec::new();
    for cmd_i in 0..n_commands {
        let is_paste = rng.bernoulli(params.paste_p);
        let cmd_len = rng.count(params.keystrokes_per_cmd.0, params.keystrokes_per_cmd.1, 12);

        if is_paste {
            // A paste delivers the whole line atomically: one fast burst.
            let gap_ms = rng.lognormal(params.keystroke_lognormal.0.min(3.0), 0.2);
            events.push(SynthEvent::Keystroke {
                inter_arrival_ns: (gap_ms * 1.0e6) as u64,
                is_paste: true,
                burst_len: cmd_len,
            });
        } else {
            // Typed character by character with profile-specific cadence.
            for _ in 0..cmd_len {
                let gap_ms = rng
                    .lognormal(params.keystroke_lognormal.0, params.keystroke_lognormal.1)
                    .clamp(1.0, 5_000.0);
                events.push(SynthEvent::Keystroke {
                    inter_arrival_ns: (gap_ms * 1.0e6) as u64,
                    is_paste: false,
                    burst_len: 1,
                });
            }
        }

        // Fatigue drift of the location, in [0, think_fatigue] across the session.
        let frac = if n_commands > 1 {
            cmd_i as f64 / (n_commands - 1) as f64
        } else {
            0.0
        };
        let mu_t = think_mu + (params.think_fatigue * frac);

        // AR(1) step on the deviation; eps ~ N(0, sigma).
        let eps = rng.normal(0.0, think_sigma);
        let dev = if have_prev {
            phi * prev_dev + innov_scale * eps
        } else {
            eps
        };
        prev_dev = dev;
        have_prev = true;

        let think_ms = (mu_t + dev).exp().clamp(1.0, 600_000.0);
        events.push(SynthEvent::Command {
            inter_command_ns: (think_ms * 1.0e6) as u64,
            had_backspace: rng.bernoulli(params.backspace_p),
            entropy: rng
                .normal(params.entropy.0, params.entropy.1)
                .clamp(0.0, 8.0),
        });
    }
    events
}

/// Generate one synthetic session and return the populated accumulator. The
/// accumulator is the *real* one the plugin uses, so this exercises the genuine
/// feature-extraction path. Equivalent to folding [`synth_events`] (natural
/// length) into a fresh accumulator.
pub fn synth_session(params: &ProfileParams, rng: &mut Rng) -> SessionAccumulator {
    let mut acc = SessionAccumulator::default();
    for evt in synth_events(params, rng, 0) {
        evt.apply(&mut acc);
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

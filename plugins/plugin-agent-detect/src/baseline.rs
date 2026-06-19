//! A learned **logistic-regression baseline** for cross-checking the transparent
//! detector ([`crate::model::Model`]).
//!
//! ## Why this exists (and the honesty caveat)
//!
//! The production detector is a *transparent additive* model with hand-calibrated
//! coefficients and physiological hard rules. A fair question is: *does a model
//! free to fit the data do materially better?* This module trains an ordinary
//! logistic regression on the **same** feature pipeline and scores it head-to-head
//! against the transparent model with the **same** ROC-AUC estimator
//! ([`crate::eval::roc_auc`]) on the **same** held-out sessions.
//!
//! **The caveat must be read with every number this produces.** The learned model
//! trains on data from the *same generator* it is tested against
//! ([`crate::synth`]). Even with a disjoint train/test split, it can learn the
//! generator's idiosyncrasies — the exact log-normal parameters, the AR(1)/fatigue
//! structure — rather than field-general behaviour. So its role is a **cross-check
//! on relative ranking and competitiveness**, not a claim of field accuracy. The
//! transparent model encodes physiological priors (the ~150 ms reaction floor,
//! whole-line-injection, uncorrelated-flat-throughput) that an LR cannot invent
//! from generator samples; the comparison shows whether those hand-crafted priors
//! keep pace with a model that is free to overfit the synthetic distribution. See
//! `docs/model-comparison.md` for the full discussion.
//!
//! ## Design
//!
//! * Features come **only** from the real pipeline: `synth_session(...).features()`.
//!   We never hand-roll feature values.
//! * `FeatureVector` legitimately carries `NaN` for the four Tier-3 fields below
//!   the robust gate (see [`crate::features::MIN_COMMANDS_ROBUST`]). The transparent
//!   model drops-and-renormalizes; an LR with fixed weights cannot. We use the
//!   honest, leak-free fix from real ML pipelines: **mean-imputation with a
//!   missingness indicator**, both fit on the *training set only*.
//! * Standardization (`(x − mean)/std`, population std via [`crate::features::mean_std`]
//!   to match the crate's convention) is likewise fit on train and applied to test.
//! * Training is deterministic: weights init to `0.0`, full-batch gradient descent,
//!   fixed data order, no RNG inside the optimizer. The only seeded randomness is
//!   the synthetic **data** generation, which is where reproducibility matters.

use crate::features::{mean_std, FeatureVector};
use crate::model::sigmoid;
use crate::synth::{synth_session, ProfileParams, Rng};

/// The 12 raw feature columns, in a fixed canonical order. `feature_row` and the
/// imputation/standardization machinery all key on this order.
pub const FEATURE_NAMES: [&str; 12] = [
    "keystroke_cv",
    "paste_ratio",
    "mean_inter_command_ms",
    "backspace_ratio",
    "entropy_mean",
    "cadence_regularity",
    "gap_autocorr",
    "think_tail_ratio",
    "throughput_decay",
    "reaction_floor_hits",
    "whole_line_paste_ratio",
    "keystroke_burst_cv",
];

/// Number of raw features.
pub const N_FEATURES: usize = 12;

/// Indices (into the raw [`feature_row`]) of the Tier-3 features that can legitimately
/// be `NaN` below the robust gate. For each we append a binary "was-missing"
/// indicator column so the LR can learn that "Tier-3 absent" (a short session) is
/// itself weak evidence rather than silently reading the imputed mean as a real
/// measurement. Order: `gap_autocorr`, `think_tail_ratio`, `throughput_decay`,
/// `keystroke_burst_cv`.
const IMPUTABLE_INDICES: [usize; 4] = [6, 7, 8, 11];

/// Whether to append the missingness-indicator columns. Gated behind a const so
/// the design is easy to ablate (set to `false` ⇒ plain mean-imputation, `D = 12`).
const USE_MISSINGNESS_INDICATORS: bool = true;

/// The design dimensionality: 12 raw features plus the 4 missingness indicators
/// (when enabled).
const DESIGN_DIM: usize = if USE_MISSINGNESS_INDICATORS {
    N_FEATURES + IMPUTABLE_INDICES.len()
} else {
    N_FEATURES
};

/// Map a [`FeatureVector`] to its raw `[f64; 12]` row in [`FEATURE_NAMES`] order.
/// Values may be non-finite (the Tier-3 `NaN` sentinels); imputation happens later.
pub fn feature_row(f: &FeatureVector) -> [f64; N_FEATURES] {
    [
        f.keystroke_cv,
        f.paste_ratio,
        f.mean_inter_command_ms,
        f.backspace_ratio,
        f.entropy_mean,
        f.cadence_regularity,
        f.gap_autocorr,
        f.think_tail_ratio,
        f.throughput_decay,
        f.reaction_floor_hits,
        f.whole_line_paste_ratio,
        f.keystroke_burst_cv,
    ]
}

/// Per-column standardizer (`z = (x − mean)/std`), fit on the training design
/// matrix. Constant columns (`std <= 1e-12`, e.g. an indicator column when a fold
/// has no short sessions) map to `0.0` so they neither help nor blow up.
#[derive(Debug, Clone)]
pub struct Standardizer {
    mean: Vec<f64>,
    std: Vec<f64>,
}

impl Standardizer {
    /// Fit per-column population mean/std over `rows` (each of length `DESIGN_DIM`).
    fn fit(rows: &[Vec<f64>]) -> Self {
        let d = rows.first().map(|r| r.len()).unwrap_or(DESIGN_DIM);
        let mut mean = vec![0.0; d];
        let mut std = vec![0.0; d];
        for j in 0..d {
            let col: Vec<f64> = rows.iter().map(|r| r[j]).collect();
            let (m, s) = mean_std(&col);
            mean[j] = m;
            std[j] = s;
        }
        Standardizer { mean, std }
    }

    /// Standardize one design row in place-style, returning a new vector.
    fn transform(&self, row: &[f64]) -> Vec<f64> {
        row.iter()
            .zip(self.mean.iter().zip(self.std.iter()))
            .map(|(&x, (&m, &s))| if s <= 1e-12 { 0.0 } else { (x - m) / s })
            .collect()
    }
}

/// Hyperparameters for [`LogisticRegression::train`]. Deterministic: there is no
/// seed because training itself uses no RNG (zero-init weights, fixed data order).
#[derive(Debug, Clone)]
pub struct TrainConfig {
    pub epochs: usize,
    pub lr: f64,
    /// L2 penalty strength (applied to weights, not the bias).
    pub l2: f64,
}

impl Default for TrainConfig {
    fn default() -> Self {
        // Tuned so the LR converges to AUC > 0.9 at evasion 0 on the synthetic set
        // (inputs are standardized, so a large-ish lr is fine and converges fast).
        TrainConfig {
            epochs: 600,
            lr: 0.5,
            l2: 1e-3,
        }
    }
}

/// A logistic-regression classifier over the behavioral [`FeatureVector`].
///
/// Carries everything needed to reproduce the train-time transform at predict time:
/// the raw-feature imputation means, the standardizer, and the fitted weights/bias.
/// [`predict_proba`](Self::predict_proba) returns `p_agent ∈ [0,1]`, drop-in
/// comparable to [`crate::model::Model::assess`]`(..).p_agent`.
#[derive(Debug, Clone)]
pub struct LogisticRegression {
    weights: Vec<f64>, // length DESIGN_DIM
    bias: f64,
    scaler: Standardizer,
    /// Per-raw-column imputation means (length `N_FEATURES`), fit on train.
    impute_means: Vec<f64>,
}

impl LogisticRegression {
    /// Build the standardized design row from a raw [`FeatureVector`] using the
    /// stored imputation means and standardizer: impute non-finite cells with the
    /// training-set column mean, append the missingness indicators, then standardize.
    fn design_row(&self, f: &FeatureVector) -> Vec<f64> {
        let raw = feature_row(f);
        let design = impute_and_indicate(&raw, &self.impute_means);
        self.scaler.transform(&design)
    }

    /// Probability the subject is an automated agent, in `[0, 1]`.
    pub fn predict_proba(&self, f: &FeatureVector) -> f64 {
        let z = self.design_row(f);
        let dot: f64 = z
            .iter()
            .zip(self.weights.iter())
            .map(|(a, b)| a * b)
            .sum::<f64>()
            + self.bias;
        sigmoid(dot)
    }

    /// Train via deterministic full-batch gradient descent on binary
    /// cross-entropy with an L2 penalty on the weights (bias unregularized).
    ///
    /// The pipeline mirrors [`predict_proba`](Self::predict_proba): raw rows →
    /// impute (train means) → append indicators → standardize (train stats). The
    /// resulting model is fully determined by the data and `cfg` (zero-init,
    /// fixed order, no RNG).
    pub fn train(train: &[(FeatureVector, bool)], cfg: &TrainConfig) -> Self {
        // 1. Raw rows + labels.
        let raw_rows: Vec<[f64; N_FEATURES]> = train.iter().map(|(f, _)| feature_row(f)).collect();
        let labels: Vec<f64> = train
            .iter()
            .map(|(_, y)| if *y { 1.0 } else { 0.0 })
            .collect();

        // 2. Imputation means from finite cells only (fit on train).
        let impute_means = column_imputation_means(&raw_rows);

        // 3. Design rows (impute + indicators), then fit + apply standardizer.
        let design_rows: Vec<Vec<f64>> = raw_rows
            .iter()
            .map(|r| impute_and_indicate(r, &impute_means))
            .collect();
        let scaler = Standardizer::fit(&design_rows);
        let x: Vec<Vec<f64>> = design_rows.iter().map(|r| scaler.transform(r)).collect();

        // 4. Gradient descent.
        let n = x.len();
        let d = DESIGN_DIM;
        let mut weights = vec![0.0f64; d];
        let mut bias = 0.0f64;

        if n > 0 {
            let inv_n = 1.0 / n as f64;
            for _ in 0..cfg.epochs {
                // Forward pass + residuals σ(Xw+b) − y.
                let mut grad_w = vec![0.0f64; d];
                let mut grad_b = 0.0f64;
                for (row, &y) in x.iter().zip(labels.iter()) {
                    let dot: f64 = row
                        .iter()
                        .zip(weights.iter())
                        .map(|(a, b)| a * b)
                        .sum::<f64>()
                        + bias;
                    let resid = sigmoid(dot) - y;
                    grad_b += resid;
                    for (g, &xj) in grad_w.iter_mut().zip(row.iter()) {
                        *g += resid * xj;
                    }
                }
                // Mean gradient + L2 on weights (bias is not regularized).
                for (g, w) in grad_w.iter_mut().zip(weights.iter()) {
                    *g = *g * inv_n + cfg.l2 * *w;
                }
                grad_b *= inv_n;
                // Update.
                for (w, g) in weights.iter_mut().zip(grad_w.iter()) {
                    *w -= cfg.lr * g;
                }
                bias -= cfg.lr * grad_b;
            }
        }

        LogisticRegression {
            weights,
            bias,
            scaler,
            impute_means,
        }
    }
}

/// Per-column imputation means over finite cells only (length `N_FEATURES`). A
/// column that is entirely non-finite (degenerate) imputes to `0.0`.
fn column_imputation_means(raw_rows: &[[f64; N_FEATURES]]) -> Vec<f64> {
    let mut means = vec![0.0f64; N_FEATURES];
    for (j, m) in means.iter_mut().enumerate() {
        let mut sum = 0.0;
        let mut count = 0usize;
        for row in raw_rows {
            if row[j].is_finite() {
                sum += row[j];
                count += 1;
            }
        }
        *m = if count > 0 { sum / count as f64 } else { 0.0 };
    }
    means
}

/// Impute non-finite cells with `impute_means`, then (when enabled) append a binary
/// missingness indicator per imputable Tier-3 column. Returns a design row of length
/// `DESIGN_DIM`.
fn impute_and_indicate(raw: &[f64; N_FEATURES], impute_means: &[f64]) -> Vec<f64> {
    let mut out = Vec::with_capacity(DESIGN_DIM);
    for (j, &x) in raw.iter().enumerate() {
        out.push(if x.is_finite() { x } else { impute_means[j] });
    }
    if USE_MISSINGNESS_INDICATORS {
        for &idx in &IMPUTABLE_INDICES {
            out.push(if raw[idx].is_finite() { 0.0 } else { 1.0 });
        }
    }
    out
}

/// Generate a labelled dataset by sampling `n_per_class` sessions from each of the
/// positive (agent) and negative (human) profiles through the **real** feature
/// pipeline, dropping under-evidenced sessions exactly as [`crate::eval`] does.
///
/// `params_pos` is the agent (label `true`); `params_neg` is the human (`false`).
/// Reuse with **different seeds / disjoint draws** for train vs test.
pub fn make_dataset(
    params_pos: &ProfileParams,
    params_neg: &ProfileParams,
    n_per_class: usize,
    rng: &mut Rng,
) -> Vec<(FeatureVector, bool)> {
    let mut out = Vec::with_capacity(n_per_class * 2);
    for _ in 0..n_per_class {
        for (params, is_agent) in [(params_neg, false), (params_pos, true)] {
            let acc = synth_session(params, rng);
            if let Some(f) = acc.features() {
                out.push((f, is_agent));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eval::roc_auc;

    /// A naive agent vs human dataset, generated deterministically.
    fn naive_dataset(n: usize, seed: u64) -> Vec<(FeatureVector, bool)> {
        let mut rng = Rng::new(seed);
        make_dataset(
            &ProfileParams::agent(),
            &ProfileParams::human(),
            n,
            &mut rng,
        )
    }

    #[test]
    fn separates_naive_agents_from_humans() {
        // Train on one seed, test on a disjoint seed (no leakage).
        let train = naive_dataset(300, 1);
        let test = naive_dataset(150, 2);
        let lr = LogisticRegression::train(&train, &TrainConfig::default());
        let scored: Vec<(f64, bool)> = test
            .iter()
            .map(|(f, y)| (lr.predict_proba(f), *y))
            .collect();
        let auc = roc_auc(&scored);
        assert!(auc > 0.9, "learned baseline AUC on naive agents was {auc}");
    }

    #[test]
    fn standardized_train_columns_have_zero_mean_unit_std() {
        let train = naive_dataset(300, 7);
        let raw_rows: Vec<[f64; N_FEATURES]> = train.iter().map(|(f, _)| feature_row(f)).collect();
        let impute_means = column_imputation_means(&raw_rows);
        let design_rows: Vec<Vec<f64>> = raw_rows
            .iter()
            .map(|r| impute_and_indicate(r, &impute_means))
            .collect();
        let scaler = Standardizer::fit(&design_rows);
        let z: Vec<Vec<f64>> = design_rows.iter().map(|r| scaler.transform(r)).collect();
        // For each non-constant column, mean ~ 0 and std ~ 1.
        for j in 0..DESIGN_DIM {
            let col: Vec<f64> = z.iter().map(|r| r[j]).collect();
            let (m, s) = mean_std(&col);
            assert!(m.abs() < 1e-9, "col {j} mean {m}");
            // Constant columns standardize to 0 (std 0); others to unit std.
            assert!(s < 1e-9 || (s - 1.0).abs() < 1e-9, "col {j} std {s}");
        }
    }

    #[test]
    fn predict_proba_is_finite_on_short_nan_bearing_vector() {
        // A short session emits NaN for the four Tier-3 fields. The impute +
        // indicator path must yield a finite probability (a fixed-weight dot
        // product against a NaN would otherwise poison the whole score).
        let train = naive_dataset(200, 11);
        let lr = LogisticRegression::train(&train, &TrainConfig::default());
        let short = FeatureVector {
            keystroke_cv: 0.5,
            paste_ratio: 0.1,
            mean_inter_command_ms: 1200.0,
            backspace_ratio: 0.1,
            entropy_mean: 4.0,
            cadence_regularity: 0.4,
            gap_autocorr: f64::NAN,
            think_tail_ratio: f64::NAN,
            throughput_decay: f64::NAN,
            reaction_floor_hits: 0.0,
            whole_line_paste_ratio: 0.0,
            keystroke_burst_cv: f64::NAN,
        };
        let p = lr.predict_proba(&short);
        assert!(p.is_finite() && (0.0..=1.0).contains(&p), "p = {p}");
    }

    #[test]
    fn training_is_deterministic() {
        // Same data + config ⇒ identical weights, bias, and downstream AUC.
        let train = naive_dataset(200, 5);
        let a = LogisticRegression::train(&train, &TrainConfig::default());
        let b = LogisticRegression::train(&train, &TrainConfig::default());
        assert_eq!(a.weights, b.weights);
        assert_eq!(a.bias, b.bias);

        let test = naive_dataset(100, 6);
        let score = |m: &LogisticRegression| -> f64 {
            roc_auc(
                &test
                    .iter()
                    .map(|(f, y)| (m.predict_proba(f), *y))
                    .collect::<Vec<_>>(),
            )
        };
        assert_eq!(score(&a), score(&b));
    }
}

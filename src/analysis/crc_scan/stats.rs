//! Analytic and empirical false-alarm calibration for `crcscan`.

use std::collections::BTreeSet;

use crate::nulls::null::SplitMix64;

use super::hash::{HASH_VARIANTS, OutputByteOrder};

const U32_SPACE: f64 = 4_294_967_296.0;

/// Analytic Poisson false-alarm summary.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AnalyticSignificance {
    /// Expected spurious-hit count under uniform random `u32` digests.
    pub lambda: f64,
    /// Observed unique word/config/target hit count.
    pub observed_hits: usize,
    /// Poisson tail probability `P(X >= observed_hits)`.
    pub p_at_least_observed: f64,
}

/// Empirical matched-null distribution driven by in-crate `SplitMix64`.
#[derive(Clone, Debug, PartialEq)]
pub struct EmpiricalNull {
    /// Deterministic PRNG seed used for this run.
    pub seed: u64,
    /// Number of Monte-Carlo trials.
    pub trials: usize,
    /// Mean hit count per trial.
    pub mean: f64,
    /// Minimum sampled hit count.
    pub min: usize,
    /// Median sampled hit count.
    pub median: f64,
    /// Maximum sampled hit count.
    pub max: usize,
    /// Empirical tail probability `P(X >= observed_hits)`.
    pub p_at_least_observed: f64,
}

/// Error returned when null calibration cannot run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NullCalibrationError {
    /// A Monte-Carlo null needs at least one trial.
    ZeroTrials,
}

impl std::fmt::Display for NullCalibrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroTrials => f.write_str("at least one empirical-null trial is required"),
        }
    }
}

impl std::error::Error for NullCalibrationError {}

/// Returns the number of digest-variant and output-byte-order configurations.
#[must_use]
pub const fn config_count() -> usize {
    HASH_VARIANTS.len() * OutputByteOrder::ALL.len()
}

/// Computes the analytic expected spurious-hit count.
#[must_use]
pub fn expected_lambda(target_count: usize, dict_size: usize) -> f64 {
    target_count as f64 * config_count() as f64 * dict_size as f64 / U32_SPACE
}

/// Computes the Poisson probability `P(X >= k)` for mean `lambda`.
#[must_use]
pub fn poisson_tail_at_least(k: usize, lambda: f64) -> f64 {
    if k == 0 {
        return 1.0;
    }
    if lambda == 0.0 {
        return 0.0;
    }
    let mut term = (-lambda).exp();
    let mut cdf_below = term;
    for i in 1..k {
        term *= lambda / i as f64;
        cdf_below += term;
    }
    (1.0 - cdf_below).clamp(0.0, 1.0)
}

/// Builds the analytic significance summary for one observed scan.
#[must_use]
pub fn analytic_significance(
    target_count: usize,
    dict_size: usize,
    observed_hits: usize,
) -> AnalyticSignificance {
    let lambda = expected_lambda(target_count, dict_size);
    AnalyticSignificance {
        lambda,
        observed_hits,
        p_at_least_observed: poisson_tail_at_least(observed_hits, lambda),
    }
}

/// Runs the matched empirical null with uniform random `u32` digests.
///
/// Each trial draws one random raw digest per dictionary word and hash variant,
/// applies the same two output byte orders as the real scan, and counts hits
/// against the same unique target set.
///
/// # Errors
/// Returns [`NullCalibrationError::ZeroTrials`] when `trials == 0`.
pub fn run_empirical_null(
    targets: &BTreeSet<u32>,
    dict_size: usize,
    observed_hits: usize,
    trials: usize,
    seed: u64,
) -> Result<EmpiricalNull, NullCalibrationError> {
    if trials == 0 {
        return Err(NullCalibrationError::ZeroTrials);
    }
    let mut samples = Vec::with_capacity(trials);
    let mut rng = SplitMix64::new(seed);
    for _trial in 0..trials {
        samples.push(sample_trial(targets, dict_size, &mut rng));
    }
    Ok(summarize_samples(samples, observed_hits, trials, seed))
}

impl EmpiricalNull {
    /// Returns whether this empirical mean is close to analytic `lambda`.
    ///
    /// The tolerance is a six-sigma Monte-Carlo band with a small absolute floor
    /// for tiny lambdas where a short null usually samples all zeros.
    #[must_use]
    pub fn agrees_with_lambda(&self, lambda: f64) -> bool {
        let sigma = if lambda > 0.0 {
            (lambda / self.trials as f64).sqrt()
        } else {
            0.0
        };
        (self.mean - lambda).abs() <= f64::max(0.01, 6.0 * sigma)
    }
}

fn sample_trial(targets: &BTreeSet<u32>, dict_size: usize, rng: &mut SplitMix64) -> usize {
    let mut hits = 0usize;
    for _word in 0..dict_size {
        for _variant in HASH_VARIANTS {
            let draw = next_u32(rng);
            for order in OutputByteOrder::ALL {
                if targets.contains(&order.apply(draw)) {
                    hits += 1;
                }
            }
        }
    }
    hits
}

fn next_u32(rng: &mut SplitMix64) -> u32 {
    let [b0, b1, b2, b3, _, _, _, _] = rng.next_u64().to_le_bytes();
    u32::from_le_bytes([b0, b1, b2, b3])
}

fn summarize_samples(
    mut samples: Vec<usize>,
    observed_hits: usize,
    trials: usize,
    seed: u64,
) -> EmpiricalNull {
    let tail_count = samples
        .iter()
        .filter(|&&sample| sample >= observed_hits)
        .count();
    let sum: usize = samples.iter().sum();
    samples.sort_unstable();
    let min = samples.first().copied().unwrap_or_default();
    let max = samples.last().copied().unwrap_or_default();
    EmpiricalNull {
        seed,
        trials,
        mean: sum as f64 / trials as f64,
        min,
        median: median_sorted(&samples),
        max,
        p_at_least_observed: tail_count as f64 / trials as f64,
    }
}

fn median_sorted(samples: &[usize]) -> f64 {
    let mid = samples.len() / 2;
    if samples.len().is_multiple_of(2) {
        let left = samples
            .get(mid.saturating_sub(1))
            .copied()
            .unwrap_or_default();
        let right = samples.get(mid).copied().unwrap_or_default();
        (left + right) as f64 / 2.0
    } else {
        samples.get(mid).copied().unwrap_or_default() as f64
    }
}

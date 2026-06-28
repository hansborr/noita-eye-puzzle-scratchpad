//! Shared scaffolding for the near-identical keystream and ragbaby crackers.
//!
//! Both cracker drivers ([`crate::attack::keystream`] and [`crate::attack::ragbaby`])
//! run the same shape of pipeline — anneal a key, score it, then gate it against a
//! random-key diagnostic null and a Fisher-Yates **matched** null — and historically
//! kept byte-identical copies of the supporting arithmetic. This module holds the
//! invariant pieces (the population mean/std, the null-vs-best significance test,
//! the matched-null trial loop, and the invariant candidate-record blocks) so the two
//! sides share one implementation while each keeps its own config/candidate types,
//! bare `search`, per-trial seed math, survival rule, and bespoke record lines.
//!
//! The matched-null loop owns only the loop structure plus aggregation (via
//! [`crate::nulls::heldout::matched_null_stats`]); every RNG-touching seed derivation
//! and the inner search stay side-local, threaded in as closures.

use std::fmt;

use crate::nulls::heldout::{MatchedNullStats, matched_null_stats};
use crate::nulls::null::{SplitMix64, fisher_yates};

/// Population mean and standard deviation (`(0.0, 0.0)` for an empty slice).
///
/// The exact summation order is load-bearing: both crackers freeze the resulting
/// f64 bits in anti-drift tests, so this stays a verbatim shared copy.
#[must_use]
pub(crate) fn mean_std(samples: &[f64]) -> (f64, f64) {
    if samples.is_empty() {
        return (0.0, 0.0);
    }
    let count = samples.len() as f64;
    let mean = samples.iter().sum::<f64>() / count;
    let variance = samples
        .iter()
        .map(|value| {
            let delta = value - mean;
            delta * delta
        })
        .sum::<f64>()
        / count;
    (mean, variance.sqrt())
}

/// A candidate's best score compared against one null distribution `(mean, std)`.
///
/// Captures the shared null-vs-best arithmetic both crackers use for their
/// random-key diagnostic and matched-null gates. The field formulas are frozen
/// bit-for-bit (the crackers store [`Self::z`] and gate on [`Self::clears`]).
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct NullComparison {
    /// The null distribution mean.
    pub(crate) mean: f64,
    /// The null distribution standard deviation.
    pub(crate) std: f64,
    /// `best - mean`, the absolute nat margin above the null mean.
    pub(crate) margin: f64,
    /// `margin / std` (or `0.0` when `std == 0.0`), the z-score.
    pub(crate) z: f64,
}

impl NullComparison {
    /// Compares `best` against a null `(mean, std)`, deriving the margin and z-score.
    #[must_use]
    pub(crate) fn new(best: f64, mean: f64, std: f64) -> Self {
        let margin = best - mean;
        let z = if std > 0.0 { margin / std } else { 0.0 };
        Self {
            mean,
            std,
            margin,
            z,
        }
    }

    /// Whether the comparison clears the gate: `enabled` and z-score `>= z_threshold`
    /// and margin `>= min_margin`.
    ///
    /// `enabled` is the per-gate guard (e.g. `matched_null_trials > 0`); pass `true`
    /// for a gate with no trial guard. The z/margin checks reproduce each cracker's
    /// original boolean exactly.
    #[must_use]
    pub(crate) fn clears(&self, enabled: bool, z_threshold: f64, min_margin: f64) -> bool {
        enabled && self.z >= z_threshold && self.margin >= min_margin
    }
}

/// Runs the shared matched-null trial loop and aggregates the result.
///
/// For each of `trials` trials this seeds a fresh [`SplitMix64`] from
/// `shuffle_seed(trial)`, Fisher-Yates shuffles a fresh copy of `stream` once, then
/// calls `run_trial(&shuffled, trial)` to obtain that trial's `(full_score,
/// heldout_score)` pair; the pairs are aggregated by
/// [`matched_null_stats`]. `trials == 0` yields [`MatchedNullStats::ZERO`].
///
/// The loop owns only the shuffle + aggregation. All RNG-touching seed math and the
/// inner bare search live in the side-local closures: `shuffle_seed` derives the
/// per-trial shuffle seed, and `run_trial` derives the per-trial search seed, runs
/// the side's bare search, and scores the result. The loop's shuffle RNG never
/// crosses into `run_trial` (each search seeds its own generator), preserving the
/// per-side call order. Generic closures (no boxing) keep this clear of
/// `clippy::type_complexity`.
pub(crate) fn matched_null_loop<T, ShuffleSeed, RunTrial>(
    stream: &[T],
    trials: usize,
    shuffle_seed: ShuffleSeed,
    mut run_trial: RunTrial,
) -> MatchedNullStats
where
    T: Clone,
    ShuffleSeed: Fn(usize) -> u64,
    RunTrial: FnMut(&[T], usize) -> (f64, f64),
{
    let mut samples: Vec<(f64, f64)> = Vec::with_capacity(trials);
    for trial in 0..trials {
        let mut rng = SplitMix64::new(shuffle_seed(trial));
        let mut shuffled = stream.to_vec();
        if fisher_yates(&mut shuffled, &mut rng).is_err() {
            // Unreachable for an in-bounds slice on a 64-bit target; skip the trial
            // rather than panic (a dropped trial only shrinks the sample).
            continue;
        }
        samples.push(run_trial(&shuffled, trial));
    }
    matched_null_stats(&samples)
}

/// Slugifies a label into a filename-safe lowercase token.
///
/// Shared verbatim by both record writers (their record filenames are stable, so
/// this output is byte-frozen).
#[must_use]
pub(crate) fn slugify(label: &str) -> String {
    label
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

/// Writes the invariant `## Decrypt (hypothesis, not a decode)` block: the heading,
/// a blank line, and the rendered `plaintext` line.
///
/// # Errors
/// Returns [`fmt::Error`] if writing to `out` fails (it cannot for a `String`).
pub(crate) fn write_decrypt_block(out: &mut String, plaintext: &str) -> fmt::Result {
    use std::fmt::Write as _;
    writeln!(out, "## Decrypt (hypothesis, not a decode)")?;
    writeln!(out)?;
    writeln!(out, "{plaintext}")?;
    Ok(())
}

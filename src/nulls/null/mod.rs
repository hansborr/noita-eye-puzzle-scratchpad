//! Null-distribution machinery for the reading-order audit.
//!
//! The null used here resamples rendered grid contents only: each cell in the
//! verified row-width structure is drawn uniformly from orientation digits
//! `0..=4`, and every synthetic corpus is searched over the same
//! [`crate::analysis::orders::standard36_orders`] digit-permutation family used by the
//! Stage A reading-order audit.
//!
//! This corrects for grid-content randomness plus selection among the 36 fixed
//! digit permutations. It does **not** correct for broader post-hoc researcher
//! degrees of freedom such as the choice of honeycomb traversal family, trigram
//! grouping rule, or which statistic to headline. For that broader calibrated
//! adaptive correction, see [`crate::nulls::dof_null`].
//!
//! The shared statistical helpers live in the `stats` submodule and the generic
//! matched-null harness in `harness`; both re-export their public items here so
//! the historical `crate::nulls::null::*` paths are unchanged.

use std::fmt;

use crate::analysis::orders::{GlyphGrid, GridError, corpus_grids, standard36_orders};
use crate::core::glyph::Orientation;
use crate::report::{self, Report};

mod harness;
mod stats;
#[cfg(test)]
mod tests;

pub use harness::{
    F64Band, NullColumnError, NullResult, NullSampler, NullTestError, UsizeBand,
    WithinMessageShuffle, f64_band, run_null_test, run_null_test_columns,
    run_null_test_columns_streams, run_null_test_streams, usize_band,
};
use stats::{
    Quantile, evaluate_trial, random_grids_like, run_length_histogram, sorted_quantile,
    total_trigrams,
};
pub use stats::{
    analytic_headline_bounds, median_f64, median_usize, random_orientation_grids_like,
    scaled_quantile_index, wilson_95,
};

/// Deterministic in-crate `SplitMix64` pseudo-random number generator.
///
/// ```
/// use noita_eye_puzzle::nulls::null::SplitMix64;
///
/// // The stream depends only on the seed, so two generators built from the
/// // same seed agree step-for-step — the property the locked null models rely on.
/// let mut a = SplitMix64::new(0x6e6f_6974_61);
/// let mut b = SplitMix64::new(0x6e6f_6974_61);
/// assert_eq!(a.next_u64(), b.next_u64());
/// assert_eq!(a.next_u64(), b.next_u64());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Creates a generator from an explicit seed.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Returns the next pseudo-random `u64`.
    #[must_use]
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn orientation(&mut self) -> Orientation {
        // Modulo reduction carries a negligible bias here (2^64 mod 5 == 1, so
        // digit 0 is favored by ~5e-20). It is kept intentionally: switching to
        // rejection sampling would change the deterministic PRNG stream and
        // break the regression-locked null statistics.
        match self.next_u64() % 5 {
            0 => Orientation::Zero,
            1 => Orientation::One,
            2 => Orientation::Two,
            3 => Orientation::Three,
            _ => Orientation::Four,
        }
    }
}

/// Hashes a single seed to one pseudo-random `u64` via a fresh [`SplitMix64`].
///
/// This is the stateless one-shot form used by control-construction code that
/// needs a deterministic, well-mixed value per seed (for example per-symbol
/// source weights) without threading a mutable generator. It is equivalent to
/// `SplitMix64::new(seed).next_u64()`.
#[must_use]
pub fn stateless_splitmix(seed: u64) -> u64 {
    SplitMix64::new(seed).next_u64()
}

/// Returns the add-one Monte-Carlo p-value estimator `(count + 1) / (trials + 1)`.
///
/// The increments saturate before conversion to keep the helper infallible even
/// at impossible `usize::MAX` inputs. For ordinary Monte-Carlo counts this is
/// exactly the conventional add-one estimator.
#[must_use]
pub fn add_one_p_value(count: usize, trials: usize) -> f64 {
    let numerator = count.saturating_add(1);
    let denominator = trials.saturating_add(1);
    numerator as f64 / denominator as f64
}

/// Derives a deterministic sub-seed from `seed` and `tag`.
///
/// This is the shared one-shot mixer for callers that identify Monte-Carlo
/// streams by a stable tag. It is equivalent to `stateless_splitmix(seed ^ tag)`.
#[must_use]
pub fn mix_seed(seed: u64, tag: u64) -> u64 {
    stateless_splitmix(seed ^ tag)
}

/// Error returned by the shared index-draw helpers when a bound cannot be used.
///
/// Carries the offending `bound` so each caller can surface it through its own
/// error type (every Monte-Carlo module maps this into its
/// `RandomBoundTooLarge { bound }` variant).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RandomBoundError {
    /// The bound that was zero or too large to represent as a `u64`.
    pub bound: usize,
}

/// Draws a uniformly-distributed index in `0..bound` from `rng` using rejection
/// sampling (no modulo bias).
///
/// # Errors
/// Returns [`RandomBoundError`] if `bound` is `0` or cannot be represented as a
/// `u64`.
pub fn random_index_below(bound: usize, rng: &mut SplitMix64) -> Result<usize, RandomBoundError> {
    let bound_u64 = u64::try_from(bound).map_err(|_error| RandomBoundError { bound })?;
    if bound_u64 == 0 {
        return Err(RandomBoundError { bound });
    }
    let rejection_threshold = u64::MAX - (u64::MAX % bound_u64);
    loop {
        let draw = rng.next_u64();
        if draw < rejection_threshold {
            let index_u64 = draw % bound_u64;
            return usize::try_from(index_u64).map_err(|_error| RandomBoundError { bound });
        }
    }
}

/// Shuffles `values` in place with a Fisher-Yates shuffle driven by `rng`.
///
/// # Errors
/// Returns [`RandomBoundError`] if an index draw fails; this is unreachable for
/// in-bounds slices on 64-bit targets.
pub fn fisher_yates<T>(values: &mut [T], rng: &mut SplitMix64) -> Result<(), RandomBoundError> {
    let mut unswapped = values.len();
    while unswapped > 1 {
        let last = unswapped - 1;
        let partner = random_index_below(unswapped, rng)?;
        values.swap(last, partner);
        unswapped = last;
    }
    Ok(())
}

/// Returns a uniformly random permutation of `0..n` driven by `rng`.
///
/// # Errors
/// Returns [`RandomBoundError`] if an index draw fails (see
/// [`random_index_below`]).
pub fn shuffled_permutation(
    n: usize,
    rng: &mut SplitMix64,
) -> Result<Vec<usize>, RandomBoundError> {
    let mut values = (0..n).collect::<Vec<_>>();
    fisher_yates(&mut values, rng)?;
    Ok(values)
}

/// Configuration for a reading-order null run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NullConfig {
    /// Explicit deterministic PRNG seed.
    pub seed: u64,
    /// Number of synthetic corpora to sample.
    pub trials: usize,
}

/// Error returned when a [`NullConfig`] cannot drive a Monte-Carlo null run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NullConfigError {
    /// `trials` was zero; a Monte-Carlo null needs at least one trial.
    ZeroTrials,
}

impl fmt::Display for NullConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroTrials => write!(f, "at least one Monte-Carlo trial is required"),
        }
    }
}

impl std::error::Error for NullConfigError {}

impl NullConfig {
    /// Validates that the configuration can drive a Monte-Carlo null run.
    ///
    /// Both the standard-36 null ([`run_standard36_null`]) and the base-7
    /// pipeline null ([`crate::nulls::pipeline_null::run_pipeline_null`]) consume this
    /// config. With zero trials every reported rate would be a degenerate
    /// `0/0` (and the Wilson intervals collapse to `0..0`), so those run
    /// functions reject that input internally (surfacing
    /// [`NullRunError::Config`]) rather than emit meaningless summaries. This
    /// method is exposed so callers can validate ahead of time as well.
    ///
    /// # Errors
    /// Returns [`NullConfigError::ZeroTrials`] if `trials == 0`.
    pub const fn validate(&self) -> Result<(), NullConfigError> {
        if self.trials == 0 {
            return Err(NullConfigError::ZeroTrials);
        }
        Ok(())
    }
}

/// Error returned by a Monte-Carlo null run.
///
/// Bundles the configuration rejection ([`NullConfigError`]) and the corpus
/// reconstruction failure ([`GridError`]) so [`run_standard36_null`] and
/// [`crate::nulls::pipeline_null::run_pipeline_null`] enforce the zero-trials invariant
/// in the library — matching every sibling null module — instead of relying on
/// each caller to pre-validate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NullRunError {
    /// The configuration was rejected before any trial ran.
    Config(NullConfigError),
    /// The verified corpus grids could not be reconstructed or read.
    Grid(GridError),
}

impl fmt::Display for NullRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(config_error) => write!(f, "{config_error}"),
            Self::Grid(grid_error) => write!(f, "grid/order error: {grid_error:?}"),
        }
    }
}

impl std::error::Error for NullRunError {}

impl From<NullConfigError> for NullRunError {
    fn from(error: NullConfigError) -> Self {
        Self::Config(error)
    }
}

impl From<GridError> for NullRunError {
    fn from(error: GridError) -> Self {
        Self::Grid(error)
    }
}

/// A two-sided Wilson score interval for a binomial event rate.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WilsonInterval {
    /// Observed event count.
    pub count: usize,
    /// Number of Bernoulli trials.
    pub trials: usize,
    /// Observed count divided by trials.
    pub estimate: f64,
    /// Lower 95% Wilson bound.
    pub lower: f64,
    /// Upper 95% Wilson bound.
    pub upper: f64,
}

/// Analytic fixed-order probability bounds for the headline event.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AnalyticBounds {
    /// Probability for one fixed order under independent uniform trigrams.
    pub per_order: f64,
    /// Bonferroni family-wise upper bound over the fixed order family.
    pub bonferroni: f64,
    /// Sidak family-wise probability over the fixed order family.
    pub sidak: f64,
    /// Number of fixed orders in the family.
    pub family_size: usize,
}

/// Summary of one synthetic corpus after taking the best result over all
/// standard-36 orders.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TrialOutcome {
    /// Whether any order produced the exact headline `0..=82` value set.
    pub headline_0_to_82: bool,
    /// Minimum distinct-value count achieved by any order.
    pub min_distinct: usize,
    /// Minimum maximum value achieved by any order.
    pub min_ceiling: u8,
    /// Whether any order had zero adjacent equal trigrams.
    pub adjacent_equal_zero: bool,
    /// Largest distance-4 spike ratio, `d4 / mean(d1..d6)`, over the family.
    pub max_distance4_ratio: f64,
}

/// Aggregate Monte-Carlo null results.
#[derive(Clone, Debug, PartialEq)]
pub struct NullReport {
    /// Configuration used for the run.
    pub config: NullConfig,
    /// Number of standard orders searched per synthetic corpus.
    pub family_size: usize,
    /// Count of corpora where some order produced exactly `0..=82`.
    pub headline_count: usize,
    /// Count of corpora where some order produced zero adjacent equal trigrams.
    pub adjacent_zero_count: usize,
    /// Histogram of per-corpus minimum distinct counts.
    pub min_distinct_histogram: Vec<(usize, usize)>,
    /// Histogram of per-corpus minimum ceiling values.
    pub min_ceiling_histogram: Vec<(u8, usize)>,
    /// Smallest observed best-over-family distance-4 ratio.
    pub distance4_ratio_min: f64,
    /// Median observed best-over-family distance-4 ratio.
    pub distance4_ratio_median: f64,
    /// Largest observed best-over-family distance-4 ratio.
    pub distance4_ratio_max: f64,
    /// Analytic fixed-order probability bounds for the headline event.
    pub analytic_bounds: AnalyticBounds,
}

impl Report for NullReport {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(&mut out, "standard36 random-grid null");
        report::appendln!(&mut out, "seed: {}", self.config.seed);
        report::appendln!(&mut out, "trials: {}", self.config.trials);
        report::appendln!(&mut out, "orders searched per trial: {}", self.family_size);
        report::appendln!(
            &mut out,
            "resampled: verified row-width structure with uniform orientation cells 0..=4"
        );
        report::appendln!(
            &mut out,
            "held fixed: honeycomb traversal, trigram grouping, and the statistic family"
        );
        report::appendln!(&mut out);

        append_interval(
            &mut out,
            "headline exact 0..=82",
            wilson_95(self.headline_count, self.config.trials),
        );
        append_interval(
            &mut out,
            "some order adjacent_equal == 0",
            wilson_95(self.adjacent_zero_count, self.config.trials),
        );
        report::appendln!(
            &mut out,
            "min distinct achieved over standard36: {}",
            report::format_histogram(&self.min_distinct_histogram)
        );
        report::appendln!(
            &mut out,
            "min ceiling achieved over standard36: {}",
            report::format_histogram(&self.min_ceiling_histogram)
        );
        report::appendln!(
            &mut out,
            "best distance-4 ratio d4/mean(d1..d6): min {:.3}, median {:.3}, max {:.3}",
            self.distance4_ratio_min,
            self.distance4_ratio_median,
            self.distance4_ratio_max
        );
        report::appendln!(&mut out);
        report::appendln!(
            &mut out,
            "analytic fixed-order headline bounds under independent uniform trigrams:"
        );
        report::appendln!(
            &mut out,
            "  per-order (83/125)^1036: {:.6e}",
            self.analytic_bounds.per_order
        );
        report::appendln!(
            &mut out,
            "  Bonferroni over {} orders: {:.6e}",
            self.analytic_bounds.family_size,
            self.analytic_bounds.bonferroni
        );
        report::appendln!(
            &mut out,
            "  Sidak over {} orders: {:.6e}",
            self.analytic_bounds.family_size,
            self.analytic_bounds.sidak
        );
        report::appendln!(&mut out);
        report::appendln!(
            &mut out,
            "Interpretation: this corrects grid-content randomness and fixed standard36 digit-permutation selection only. It does not correct for broader researcher degrees of freedom such as choosing the traversal family, grouping rule, or headline statistic after looking at the data."
        );
        report::appendln!(
            &mut out,
            "Seed-stability note: multi-seed regressions over seeds 12345, 67890, 13579, 24680, and 424242 keep the exact contiguous-0..=82 headline count at zero; changing seed only moves sampled null summaries."
        );
        out
    }
}

fn append_interval(out: &mut String, label: &str, interval: WilsonInterval) {
    report::appendln!(
        out,
        "{label}: {}/{} = {:.6} (95% Wilson {:.6}..{:.6})",
        interval.count,
        interval.trials,
        interval.estimate,
        interval.lower,
        interval.upper
    );
}

/// Runs the standard-36 reading-order null over synthetic uniform grids.
///
/// Each synthetic corpus preserves the verified row-width structure while
/// drawing every cell uniformly from orientation digits `0..=4`.
///
/// # Errors
/// Returns [`NullRunError::Config`] if `config.trials == 0`, or
/// [`NullRunError::Grid`] if the verified corpus grids cannot be reconstructed
/// or an order is incompatible with a generated grid.
pub fn run_standard36_null(config: NullConfig) -> Result<NullReport, NullRunError> {
    run_standard36_null_with(config, random_grids_like)
}

/// Runs the standard-36 reading-order null with a caller-supplied corpus
/// generator.
///
/// `generate` receives the verified corpus grids (as width templates) plus the
/// shared deterministic PRNG and must return one synthetic corpus per call. This
/// lets alternative nulls — for example the base-7 pipeline null in
/// [`crate::nulls::pipeline_null`] — reuse the identical reading-order statistics and
/// report shape while varying only how synthetic cells are produced.
///
/// # Errors
/// Returns [`NullRunError::Config`] if `config.trials == 0`, or
/// [`NullRunError::Grid`] if the verified corpus grids cannot be reconstructed
/// or an order is incompatible with a generated grid.
pub fn run_standard36_null_with(
    config: NullConfig,
    mut generate: impl FnMut(&[GlyphGrid], &mut SplitMix64) -> Vec<GlyphGrid>,
) -> Result<NullReport, NullRunError> {
    config.validate()?;
    let templates = corpus_grids()?;
    let orders = standard36_orders();
    let mut rng = SplitMix64::new(config.seed);
    let mut headline_count = 0;
    let mut adjacent_zero_count = 0;
    let mut min_distinct_values = Vec::new();
    let mut min_ceiling_values = Vec::new();
    let mut distance4_ratios = Vec::new();

    for _trial in 0..config.trials {
        let grids = generate(&templates, &mut rng);
        let outcome = evaluate_trial(&grids, &orders)?;
        if outcome.headline_0_to_82 {
            headline_count += 1;
        }
        if outcome.adjacent_equal_zero {
            adjacent_zero_count += 1;
        }
        min_distinct_values.push(outcome.min_distinct);
        min_ceiling_values.push(outcome.min_ceiling);
        distance4_ratios.push(outcome.max_distance4_ratio);
    }

    Ok(NullReport {
        config,
        family_size: orders.len(),
        headline_count,
        adjacent_zero_count,
        min_distinct_histogram: run_length_histogram(&min_distinct_values),
        min_ceiling_histogram: run_length_histogram(&min_ceiling_values),
        distance4_ratio_min: sorted_quantile(&distance4_ratios, Quantile::Min),
        distance4_ratio_median: sorted_quantile(&distance4_ratios, Quantile::Median),
        distance4_ratio_max: sorted_quantile(&distance4_ratios, Quantile::Max),
        analytic_bounds: analytic_headline_bounds(orders.len(), total_trigrams(&templates)),
    })
}

//! Null-distribution machinery for the reading-order audit.
//!
//! The null used here resamples rendered grid contents only: each cell in the
//! verified row-width structure is drawn uniformly from orientation digits
//! `0..=4`, and every synthetic corpus is searched over the same
//! [`crate::orders::standard36_orders`] digit-permutation family used by the
//! Stage A reading-order audit.
//!
//! This corrects for grid-content randomness plus selection among the 36 fixed
//! digit permutations. It does **not** correct for broader post-hoc researcher
//! degrees of freedom such as the choice of honeycomb traversal family, trigram
//! grouping rule, or which statistic to headline. For that broader calibrated
//! adaptive correction, see [`crate::dof_null`].

use crate::glyph::Orientation;
use crate::orders::{
    GlyphGrid, GridError, corpus_grids, read_corpus_message_values, standard36_orders,
};
use crate::trigram::TrigramValue;

const TRIGRAM_ALPHABET_SIZE: f64 = 125.0;
const HEADLINE_ALPHABET_SIZE: f64 = 83.0;
const WILSON_Z_95: f64 = 1.959_963_984_540_054;

/// Deterministic in-crate `SplitMix64` pseudo-random number generator.
///
/// ```
/// use noita_eye_puzzle::null::SplitMix64;
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

impl NullConfig {
    /// Validates that the configuration can drive a Monte-Carlo null run.
    ///
    /// Both the standard-36 null ([`run_standard36_null`]) and the base-7
    /// pipeline null ([`crate::pipeline_null::run_pipeline_null`]) consume this
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
/// [`crate::pipeline_null::run_pipeline_null`] enforce the zero-trials invariant
/// in the library — matching every sibling null module — instead of relying on
/// each caller to pre-validate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NullRunError {
    /// The configuration was rejected before any trial ran.
    Config(NullConfigError),
    /// The verified corpus grids could not be reconstructed or read.
    Grid(GridError),
}

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
/// [`crate::pipeline_null`] — reuse the identical reading-order statistics and
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

/// Returns 95% Wilson score interval for a count.
#[must_use]
pub fn wilson_95(count: usize, trials: usize) -> WilsonInterval {
    if trials == 0 {
        return WilsonInterval {
            count,
            trials,
            estimate: 0.0,
            lower: 0.0,
            upper: 0.0,
        };
    }
    let n = trials as f64;
    let p = count as f64 / n;
    let z2 = WILSON_Z_95 * WILSON_Z_95;
    let denominator = 1.0 + z2 / n;
    let center = p + z2 / (2.0 * n);
    let spread = WILSON_Z_95 * ((p * (1.0 - p) + z2 / (4.0 * n)) / n).sqrt();
    WilsonInterval {
        count,
        trials,
        estimate: p,
        lower: ((center - spread) / denominator).max(0.0),
        upper: ((center + spread) / denominator).min(1.0),
    }
}

/// Computes fixed-order Bonferroni and Sidak headline-event bounds.
#[must_use]
pub fn analytic_headline_bounds(family_size: usize, trigrams: usize) -> AnalyticBounds {
    let per_order = (HEADLINE_ALPHABET_SIZE / TRIGRAM_ALPHABET_SIZE).powf(trigrams as f64);
    let family = family_size as f64;
    let sidak = -f64::exp_m1(family * f64::ln_1p(-per_order));
    AnalyticBounds {
        per_order,
        bonferroni: (family * per_order).min(1.0),
        sidak,
        family_size,
    }
}

fn random_grids_like(templates: &[GlyphGrid], rng: &mut SplitMix64) -> Vec<GlyphGrid> {
    random_orientation_grids_like(templates, rng)
}

/// Generates uniform random orientation grids with the same row widths.
///
/// Each output grid keeps the source message key and row structure while drawing
/// every rendered cell independently from orientation digits `0..=4`.
#[must_use]
pub fn random_orientation_grids_like(
    templates: &[GlyphGrid],
    rng: &mut SplitMix64,
) -> Vec<GlyphGrid> {
    let mut grids = Vec::new();
    for template in templates {
        let mut rows = Vec::new();
        for width in template.row_widths() {
            let mut row = Vec::new();
            for _cell in 0..width {
                row.push(rng.orientation());
            }
            rows.push(row);
        }
        grids.push(GlyphGrid::from_orientation_rows(
            template.message_key(),
            rows,
        ));
    }
    grids
}

fn evaluate_trial(
    grids: &[GlyphGrid],
    orders: &[crate::orders::ReadingOrder],
) -> Result<TrialOutcome, GridError> {
    let mut headline_0_to_82 = false;
    let mut min_distinct = usize::MAX;
    let mut min_ceiling = u8::MAX;
    let mut adjacent_equal_zero = false;
    let mut max_distance4_ratio = 0.0;
    for order in orders {
        let message_values = read_corpus_message_values(grids, *order)?;
        let stats = FastStats::from_message_values(&message_values);
        headline_0_to_82 |= stats.is_contiguous_0_to_82();
        min_distinct = min_distinct.min(stats.distinct);
        if let Some(max) = stats.max {
            min_ceiling = min_ceiling.min(max);
        }
        adjacent_equal_zero |= stats.adjacent_equal == 0;
        max_distance4_ratio = f64::max(max_distance4_ratio, distance4_ratio(&stats));
    }
    Ok(TrialOutcome {
        headline_0_to_82,
        min_distinct,
        min_ceiling,
        adjacent_equal_zero,
        max_distance4_ratio,
    })
}

struct FastStats {
    distinct: usize,
    min: Option<u8>,
    max: Option<u8>,
    adjacent_equal: usize,
    recurrence_distance_1_to_6: [usize; 6],
}

impl FastStats {
    fn from_message_values(message_values: &[Vec<TrigramValue>]) -> Self {
        let mut seen = [false; 125];
        let mut distinct = 0;
        let mut min = None;
        let mut max = None;
        let mut recurrence_distance_1_to_6 = [0; 6];
        for values in message_values {
            for value in values {
                let raw = value.get();
                if let Some(slot) = seen.get_mut(usize::from(raw))
                    && !*slot
                {
                    *slot = true;
                    distinct += 1;
                    min = Some(min.map_or(raw, |current: u8| current.min(raw)));
                    max = Some(max.map_or(raw, |current: u8| current.max(raw)));
                }
            }
            add_message_recurrence(values, &mut recurrence_distance_1_to_6);
        }
        Self {
            distinct,
            min,
            max,
            adjacent_equal: recurrence_distance_1_to_6
                .first()
                .copied()
                .unwrap_or_default(),
            recurrence_distance_1_to_6,
        }
    }

    fn is_contiguous_0_to_82(&self) -> bool {
        self.distinct == 83 && self.min == Some(0) && self.max == Some(82)
    }
}

fn add_message_recurrence(values: &[TrigramValue], recurrence: &mut [usize; 6]) {
    let mut previous_positions = [None; 125];
    for (position, value) in values.iter().copied().enumerate() {
        let raw = usize::from(value.get());
        if let Some(slot) = previous_positions.get_mut(raw) {
            if let Some(previous) = *slot {
                let distance = position - previous;
                if (1..=6).contains(&distance)
                    && let Some(count) = recurrence.get_mut(distance - 1)
                {
                    *count += 1;
                }
            }
            *slot = Some(position);
        }
    }
}

fn distance4_ratio(stats: &FastStats) -> f64 {
    let total: usize = stats.recurrence_distance_1_to_6.iter().sum();
    if total == 0 {
        return 0.0;
    }
    let mean = total as f64 / 6.0;
    let [_, _, _, d4, _, _] = stats.recurrence_distance_1_to_6;
    d4 as f64 / mean
}

fn total_trigrams(grids: &[GlyphGrid]) -> usize {
    grids.iter().map(GlyphGrid::eye_count).sum::<usize>() / 3
}

fn run_length_histogram<K: Ord + Copy>(values: &[K]) -> Vec<(K, usize)> {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let mut histogram = Vec::new();
    for value in sorted {
        if let Some((last_value, count)) = histogram.last_mut()
            && *last_value == value
        {
            *count += 1;
            continue;
        }
        histogram.push((value, 1));
    }
    histogram
}

#[derive(Clone, Copy)]
enum Quantile {
    Min,
    Median,
    Max,
}

fn sorted_quantile(values: &[f64], quantile: Quantile) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    match quantile {
        Quantile::Min => sorted.first().copied().unwrap_or(0.0),
        Quantile::Median => median_f64(&sorted),
        Quantile::Max => sorted.last().copied().unwrap_or(0.0),
    }
}

/// Median of a pre-sorted slice of `f64` values (returns `0.0` when empty).
///
/// The caller is responsible for sorting; for an even length the mean of the
/// two central elements is returned via [`f64::midpoint`].
#[must_use]
pub fn median_f64(sorted: &[f64]) -> f64 {
    let len = sorted.len();
    if len == 0 {
        return 0.0;
    }
    let middle = len / 2;
    if len.is_multiple_of(2) {
        match (
            sorted.get(middle.saturating_sub(1)).copied(),
            sorted.get(middle).copied(),
        ) {
            (Some(left), Some(right)) => f64::midpoint(left, right),
            _ => 0.0,
        }
    } else {
        sorted.get(middle).copied().unwrap_or(0.0)
    }
}

/// Median of a pre-sorted slice of `usize` values, returned as `f64`.
///
/// The caller is responsible for sorting; for an even length the mean of the
/// two central elements is returned via [`f64::midpoint`].
#[must_use]
pub fn median_usize(sorted: &[usize]) -> f64 {
    let len = sorted.len();
    if len == 0 {
        return 0.0;
    }
    let middle = len / 2;
    if len.is_multiple_of(2) {
        match (
            sorted.get(middle.saturating_sub(1)).copied(),
            sorted.get(middle).copied(),
        ) {
            (Some(left), Some(right)) => f64::midpoint(left as f64, right as f64),
            _ => 0.0,
        }
    } else {
        sorted
            .get(middle)
            .copied()
            .map_or(0.0, |value| value as f64)
    }
}

/// Quantile index into a pre-sorted slice of `len` elements.
///
/// Returns `floor((len - 1) * numerator / denominator)`, clamped to `0` when
/// `len` or `denominator` is zero. The caller is responsible for sorting.
#[must_use]
pub fn scaled_quantile_index(len: usize, numerator: usize, denominator: usize) -> usize {
    if len == 0 || denominator == 0 {
        return 0;
    }
    len.saturating_sub(1).saturating_mul(numerator) / denominator
}

#[cfg(test)]
mod tests {
    use super::{
        NullConfig, NullConfigError, NullRunError, SplitMix64, add_one_p_value,
        analytic_headline_bounds, evaluate_trial, mix_seed, run_standard36_null,
        stateless_splitmix, wilson_95,
    };
    use crate::orders::{corpus_grids, standard36_orders};

    const STABILITY_SEEDS: [u64; 5] = [12_345, 67_890, 13_579, 24_680, 424_242];
    const FLOAT_RELATIVE_EPSILON: f64 = 1.0e-12;

    fn assert_relative_close(actual: f64, expected: f64, label: &str) {
        let tolerance = expected.abs() * FLOAT_RELATIVE_EPSILON;
        let difference = (actual - expected).abs();
        assert!(
            difference <= tolerance,
            "{label} changed: actual={actual:.17e} expected={expected:.17e} diff={difference:.17e} tolerance={tolerance:.17e}"
        );
    }

    #[test]
    fn splitmix64_seed_is_reproducible() {
        let mut first = SplitMix64::new(12_345);
        let mut second = SplitMix64::new(12_345);
        let first_values: Vec<u64> = (0..8).map(|_| first.next_u64()).collect();
        let second_values: Vec<u64> = (0..8).map(|_| second.next_u64()).collect();
        assert_eq!(first_values, second_values);
    }

    #[test]
    fn add_one_p_value_uses_plus_one_estimator() {
        assert_eq!(
            add_one_p_value(0, 2_000).to_bits(),
            (1.0_f64 / 2_001.0_f64).to_bits()
        );
        assert_eq!(
            add_one_p_value(6, 1_000).to_bits(),
            (7.0_f64 / 1_001.0_f64).to_bits()
        );
    }

    #[test]
    fn mix_seed_is_deterministic_splitmix_of_seed_xor_tag() {
        let seed = 0x1234_5678_9abc_def0;
        let tag = 0x0fed_cba9_8765_4321;
        let mixed = mix_seed(seed, tag);
        assert_eq!(mixed, mix_seed(seed, tag));
        assert_eq!(mixed, stateless_splitmix(seed ^ tag));
    }

    #[test]
    fn null_run_rejects_zero_trials() {
        let config = NullConfig { seed: 1, trials: 0 };
        assert_eq!(
            run_standard36_null(config),
            Err(NullRunError::Config(NullConfigError::ZeroTrials))
        );
    }

    #[test]
    fn null_run_is_reproducible_for_fixed_seed() {
        let config = NullConfig {
            seed: 0x5eed,
            trials: 3,
        };
        let first = run_standard36_null(config).unwrap();
        let second = run_standard36_null(config).unwrap();
        assert_eq!(first.headline_count, second.headline_count);
        assert_eq!(first.adjacent_zero_count, second.adjacent_zero_count);
        assert_eq!(first.min_distinct_histogram, second.min_distinct_histogram);
        assert_eq!(first.min_ceiling_histogram, second.min_ceiling_histogram);
        assert_eq!(
            first.distance4_ratio_min.to_bits(),
            second.distance4_ratio_min.to_bits()
        );
        assert_eq!(
            first.distance4_ratio_median.to_bits(),
            second.distance4_ratio_median.to_bits()
        );
        assert_eq!(
            first.distance4_ratio_max.to_bits(),
            second.distance4_ratio_max.to_bits()
        );
    }

    #[test]
    fn analytic_bound_matches_stage_a_headline_scale() {
        let bounds = analytic_headline_bounds(36, 1036);

        assert_eq!(bounds.family_size, 36);
        assert_relative_close(
            bounds.per_order,
            5.836_200_792_956_83e-185,
            "per-order analytic headline probability",
        );
        assert_relative_close(
            bounds.bonferroni,
            2.101_032_285_464_46e-183,
            "Bonferroni analytic headline bound",
        );
        assert_relative_close(
            bounds.sidak,
            2.101_032_285_464_46e-183,
            "Sidak analytic headline bound",
        );
    }

    #[test]
    fn standard36_fast_sweep_does_not_manufacture_contiguous_headline() {
        for seed in STABILITY_SEEDS {
            let report = run_standard36_null(NullConfig { seed, trials: 128 }).unwrap();

            assert_eq!(
                report.headline_count, 0,
                "seed {seed} reproduced the contiguous 0..=82 headline"
            );
        }
    }

    #[test]
    #[ignore = "canonical 1000-trial Monte Carlo regression; run with cargo test -- --ignored"]
    fn standard36_seed_12345_null_matches_headline_regression() {
        let report = run_standard36_null(NullConfig {
            seed: 12_345,
            trials: 1_000,
        })
        .unwrap();

        assert_eq!(report.family_size, 36);
        assert_eq!(report.headline_count, 0);
        assert_eq!(report.adjacent_zero_count, 2);
        assert_eq!(
            report.min_distinct_histogram,
            vec![(122, 1), (123, 2), (124, 136), (125, 861)]
        );
        assert_eq!(report.min_ceiling_histogram, vec![(124, 1_000)]);
        assert_relative_close(
            report.distance4_ratio_min,
            0.171_428_571_428_571,
            "minimum distance-4 ratio",
        );
        assert_relative_close(
            report.distance4_ratio_median,
            1.102_040_816_326_53,
            "median distance-4 ratio",
        );
        assert_relative_close(
            report.distance4_ratio_max,
            2.210_526_315_789_47,
            "maximum distance-4 ratio",
        );

        let adjacent_interval = wilson_95(report.adjacent_zero_count, report.config.trials);
        assert_eq!(adjacent_interval.count, 2);
        assert_eq!(adjacent_interval.trials, 1_000);
        assert_relative_close(
            adjacent_interval.estimate,
            0.002,
            "adjacent-zero Wilson point estimate",
        );

        let grids = corpus_grids().unwrap();
        let real_outcome = evaluate_trial(&grids, &standard36_orders()).unwrap();
        assert_relative_close(
            real_outcome.max_distance4_ratio,
            2.785_714_285_714_29,
            "real-corpus maximum distance-4 ratio",
        );
        assert!(real_outcome.max_distance4_ratio > report.distance4_ratio_max);
    }

    #[test]
    #[ignore = "multi-seed 1000-trial stability sweep; run with cargo test -- --ignored"]
    fn standard36_ignored_sweep_does_not_manufacture_contiguous_headline() {
        for seed in STABILITY_SEEDS {
            let report = run_standard36_null(NullConfig {
                seed,
                trials: 1_000,
            })
            .unwrap();

            assert_eq!(
                report.headline_count, 0,
                "seed {seed} reproduced the contiguous 0..=82 headline"
            );
        }
    }
}

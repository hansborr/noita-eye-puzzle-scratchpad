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

// ===========================================================================
// Matched-null harness
//
// The within-message shuffle nulls in the structural battery
// (`isomorph_null`, `zero_adjacency_null`, `perseus`, `tree_residual`,
// `orientation_homogeneity`, `conditional_structure`, `modular_diff`,
// `periodicity`) all share the same scaffolding: clone a real observation,
// resample it, recompute a statistic, count tails, and summarize the sample
// set into a band. The types and functions below centralize that scaffolding
// while leaving every numeric convention (p-value combiner, band fields, tail
// direction) with the caller — the harness performs only the mechanical loop.
// ===========================================================================

/// A resampling scheme: produces one synthetic draw from `rng`, of the same
/// shape as the real observation it is calibrating.
///
/// The associated [`NullSampler::Draw`] type lets each scheme preserve its own
/// draw shape (per-message value vectors, segment-shaped messages, repartition
/// tables, …) rather than flattening to a single `Vec` and discarding the
/// boundary structure the null exists to preserve.
pub trait NullSampler {
    /// The unit of data a statistic consumes (for example
    /// `Vec<Vec<TrigramValue>>` for a within-message shuffle).
    type Draw;

    /// Produces one synthetic draw.
    ///
    /// # Errors
    /// Returns [`RandomBoundError`] if a bounded index draw fails; this is
    /// unreachable for in-bounds slices on 64-bit targets.
    fn sample(&self, rng: &mut SplitMix64) -> Result<Self::Draw, RandomBoundError>;
}

/// Within-message Fisher-Yates shuffle: clones each message's value multiset
/// and shuffles it in place, preserving per-message length and multiset.
///
/// This is the shared form of the per-module `shuffled_messages` helper that the
/// structural battery used to copy verbatim. Messages are iterated in order and
/// each is shuffled with one [`fisher_yates`] pass, so the PRNG draw order is
/// identical to the hand-written loops it replaces.
pub struct WithinMessageShuffle<'a, T: Clone> {
    /// The real per-message value vectors to resample.
    pub messages: &'a [Vec<T>],
}

impl<T: Clone> NullSampler for WithinMessageShuffle<'_, T> {
    type Draw = Vec<Vec<T>>;

    fn sample(&self, rng: &mut SplitMix64) -> Result<Self::Draw, RandomBoundError> {
        let mut shuffled = self.messages.to_vec();
        for values in &mut shuffled {
            fisher_yates(values, rng)?;
        }
        Ok(shuffled)
    }
}

/// Outcome of comparing a real statistic to a Monte-Carlo shuffle null.
///
/// Carries the raw samples (in draw order) and both tail counts only; it
/// deliberately does **not** compute a p-value or band, because those
/// conventions differ per caller. Finish with [`add_one_p_value`] and the shared
/// band constructors ([`usize_band`] / [`f64_band`]).
#[derive(Clone, Debug, PartialEq)]
pub struct NullResult<T> {
    /// The real observed statistic the samples are compared against.
    pub observed: T,
    /// Sampled statistics in draw order; callers that pin sample order rely on
    /// this ordering being stable.
    pub samples: Vec<T>,
    /// Number of samples less than or equal to `observed`.
    pub lower_tail_count: usize,
    /// Number of samples greater than or equal to `observed`.
    pub upper_tail_count: usize,
    /// Total number of trials sampled.
    pub trials: usize,
}

/// Error returned by [`run_null_test`] / [`run_null_test_streams`].
///
/// Folds the harness's own [`RandomBoundError`] and the statistic's error `E`
/// into one type so each caller can map it into its own error variant exactly as
/// it maps [`RandomBoundError`] today. An infallible statistic uses
/// `E = core::convert::Infallible`, leaving the [`NullTestError::Statistic`] arm
/// uninhabited.
///
/// This is the generic per-trial error type; it is distinct from the non-generic
/// [`NullRunError`] used by the grid-content standard-36 null.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NullTestError<E> {
    /// A bounded PRNG draw failed inside the sampler.
    Random(RandomBoundError),
    /// The statistic returned an error for a synthetic draw.
    Statistic(E),
}

impl<E> From<RandomBoundError> for NullTestError<E> {
    fn from(error: RandomBoundError) -> Self {
        Self::Random(error)
    }
}

/// Error returned by [`run_null_test_columns`] /
/// [`run_null_test_columns_streams`].
///
/// Like [`NullTestError`] but adds a [`NullColumnError::WidthMismatch`] arm for
/// the case where the row statistic returns a row whose width differs from the
/// observed row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NullColumnError<E> {
    /// A row statistic returned a row of unexpected width.
    WidthMismatch {
        /// Expected column count (the observed row width).
        expected: usize,
        /// Observed column count returned by the statistic.
        observed: usize,
    },
    /// A bounded PRNG draw failed inside the sampler.
    Random(RandomBoundError),
    /// The statistic returned an error for a synthetic draw.
    Statistic(E),
}

impl<E> From<RandomBoundError> for NullColumnError<E> {
    fn from(error: RandomBoundError) -> Self {
        Self::Random(error)
    }
}

/// Runs `trials` shuffle draws, scoring each with `statistic`, counting both
/// tails against `observed`.
///
/// Deterministic in `seed`: a fresh [`SplitMix64`] is seeded and threaded
/// through every sampler call, so the PRNG stream — and therefore every reported
/// number — depends only on `seed`, the sampler, and the statistic. The
/// `statistic` is fallible (`Result<T, E>`); the loop propagates the first `Err`
/// as [`NullTestError::Statistic`], and a sampler draw failure surfaces as
/// [`NullTestError::Random`].
///
/// # Errors
/// Returns [`NullTestError::Random`] if a sampler draw fails, or
/// [`NullTestError::Statistic`] if the statistic returns an error.
pub fn run_null_test<S, T, E>(
    statistic: impl Fn(&S::Draw) -> Result<T, E>,
    observed: T,
    sampler: &S,
    trials: usize,
    seed: u64,
) -> Result<NullResult<T>, NullTestError<E>>
where
    S: NullSampler,
    T: PartialOrd + Copy,
{
    let mut outcomes = Vec::with_capacity(trials);
    let mut lower_tail_count = 0usize;
    let mut upper_tail_count = 0usize;
    let mut rng = SplitMix64::new(seed);
    for _trial in 0..trials {
        let draw = sampler.sample(&mut rng)?;
        let value = statistic(&draw).map_err(NullTestError::Statistic)?;
        if value <= observed {
            lower_tail_count += 1;
        }
        if value >= observed {
            upper_tail_count += 1;
        }
        outcomes.push(value);
    }
    Ok(NullResult {
        observed,
        samples: outcomes,
        lower_tail_count,
        upper_tail_count,
        trials,
    })
}

/// Runs [`run_null_test`] once per derived seed stream and concatenates the
/// samples, reproducing the `seed_count × trials_per_stream` loops that several
/// modules write by hand.
///
/// `derive_seed(stream_index)` stays caller-supplied because the derivation
/// differs per module (a chained base RNG, a wrapping stride, an xor-mix). It is
/// [`FnMut`] so a *stateful* derivation — for example one that advances a single
/// captured base [`SplitMix64`] per stream — can mutate its captured state. The
/// returned [`NullResult::trials`] is the total over all streams, and the tail
/// counts are summed (counting is additive over disjoint sample partitions).
///
/// # Errors
/// Returns [`NullTestError::Random`] if a sampler draw fails, or
/// [`NullTestError::Statistic`] if the statistic returns an error.
pub fn run_null_test_streams<S, T, E>(
    statistic: impl Fn(&S::Draw) -> Result<T, E>,
    observed: T,
    sampler: &S,
    streams: usize,
    trials_per_stream: usize,
    mut derive_seed: impl FnMut(usize) -> u64,
) -> Result<NullResult<T>, NullTestError<E>>
where
    S: NullSampler,
    T: PartialOrd + Copy,
{
    let mut outcomes = Vec::with_capacity(streams.saturating_mul(trials_per_stream));
    let mut lower_tail_count = 0usize;
    let mut upper_tail_count = 0usize;
    for stream_index in 0..streams {
        let seed = derive_seed(stream_index);
        let stream = run_null_test(&statistic, observed, sampler, trials_per_stream, seed)?;
        lower_tail_count += stream.lower_tail_count;
        upper_tail_count += stream.upper_tail_count;
        outcomes.extend(stream.samples);
    }
    let trials = outcomes.len();
    Ok(NullResult {
        observed,
        samples: outcomes,
        lower_tail_count,
        upper_tail_count,
        trials,
    })
}

/// Like [`run_null_test`] but the statistic emits a fixed-width row of scalars,
/// returning one [`NullResult`] per column.
///
/// Every trial draws once from `sampler`, scores the draw into a row, and
/// distributes the row across the per-column accumulators (so all columns share
/// the same draws, exactly as the hand-written multi-statistic loops do). The
/// width is fixed by `observed.len()`; a row of any other width is a
/// [`NullColumnError::WidthMismatch`].
///
/// # Errors
/// Returns [`NullColumnError::Random`] if a sampler draw fails,
/// [`NullColumnError::Statistic`] if the statistic returns an error, or
/// [`NullColumnError::WidthMismatch`] if a row's width differs from `observed`.
pub fn run_null_test_columns<S, T, E>(
    row_statistic: impl Fn(&S::Draw) -> Result<Vec<T>, E>,
    observed: Vec<T>,
    sampler: &S,
    trials: usize,
    seed: u64,
) -> Result<Vec<NullResult<T>>, NullColumnError<E>>
where
    S: NullSampler,
    T: PartialOrd + Copy,
{
    let width = observed.len();
    let mut columns = observed
        .into_iter()
        .map(|observed| NullResult {
            observed,
            samples: Vec::with_capacity(trials),
            lower_tail_count: 0,
            upper_tail_count: 0,
            trials,
        })
        .collect::<Vec<_>>();
    let mut rng = SplitMix64::new(seed);
    for _trial in 0..trials {
        let draw = sampler.sample(&mut rng)?;
        let row = row_statistic(&draw).map_err(NullColumnError::Statistic)?;
        if row.len() != width {
            return Err(NullColumnError::WidthMismatch {
                expected: width,
                observed: row.len(),
            });
        }
        for (column, value) in columns.iter_mut().zip(row) {
            if value <= column.observed {
                column.lower_tail_count += 1;
            }
            if value >= column.observed {
                column.upper_tail_count += 1;
            }
            column.samples.push(value);
        }
    }
    Ok(columns)
}

/// Runs [`run_null_test_columns`] once per derived seed stream and concatenates
/// each column's samples, the columnar analogue of [`run_null_test_streams`].
///
/// `derive_seed` is [`FnMut`] for the same stateful-derivation reason as
/// [`run_null_test_streams`]. Per-column tail counts and trial totals are summed
/// across streams.
///
/// # Errors
/// Returns [`NullColumnError::Random`] if a sampler draw fails,
/// [`NullColumnError::Statistic`] if the statistic returns an error, or
/// [`NullColumnError::WidthMismatch`] if a row's width differs from `observed`.
pub fn run_null_test_columns_streams<S, T, E>(
    row_statistic: impl Fn(&S::Draw) -> Result<Vec<T>, E>,
    observed: &[T],
    sampler: &S,
    streams: usize,
    trials_per_stream: usize,
    mut derive_seed: impl FnMut(usize) -> u64,
) -> Result<Vec<NullResult<T>>, NullColumnError<E>>
where
    S: NullSampler,
    T: PartialOrd + Copy,
{
    let mut merged = observed
        .iter()
        .copied()
        .map(|observed| NullResult {
            observed,
            samples: Vec::new(),
            lower_tail_count: 0,
            upper_tail_count: 0,
            trials: 0,
        })
        .collect::<Vec<_>>();
    for stream_index in 0..streams {
        let seed = derive_seed(stream_index);
        let columns = run_null_test_columns(
            &row_statistic,
            observed.to_vec(),
            sampler,
            trials_per_stream,
            seed,
        )?;
        for (accumulator, column) in merged.iter_mut().zip(columns) {
            accumulator.lower_tail_count += column.lower_tail_count;
            accumulator.upper_tail_count += column.upper_tail_count;
            accumulator.trials += column.trials;
            accumulator.samples.extend(column.samples);
        }
    }
    Ok(merged)
}

/// Monte-Carlo band over a `usize` sample set.
///
/// Holds `{trials, mean, min, q025, median, q975, max}`, computed with the same
/// conventions every per-module `null_band` used: arithmetic `mean`, raw
/// `min`/`max` from the sorted ends, `scaled_quantile_index(_, 25|975, 1000)`
/// for the percentile edges, and [`median_usize`] for the median. Modules bridge
/// their named band struct from this via a `From` conversion.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct UsizeBand {
    /// Number of samples summarized.
    pub trials: usize,
    /// Arithmetic mean of the samples.
    pub mean: f64,
    /// Smallest sampled value.
    pub min: usize,
    /// Lower pointwise 95% percentile edge.
    pub q025: usize,
    /// Sample median.
    pub median: f64,
    /// Upper pointwise 95% percentile edge.
    pub q975: usize,
    /// Largest sampled value.
    pub max: usize,
}

/// Summarizes a `usize` sample set into a [`UsizeBand`].
#[must_use]
pub fn usize_band(samples: &[usize]) -> UsizeBand {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    UsizeBand {
        trials: samples.len(),
        mean: usize_sample_mean(samples),
        min: sorted.first().copied().unwrap_or_default(),
        q025: sorted
            .get(scaled_quantile_index(sorted.len(), 25, 1_000))
            .copied()
            .unwrap_or_default(),
        median: median_usize(&sorted),
        q975: sorted
            .get(scaled_quantile_index(sorted.len(), 975, 1_000))
            .copied()
            .unwrap_or_default(),
        max: sorted.last().copied().unwrap_or_default(),
    }
}

fn usize_sample_mean(samples: &[usize]) -> f64 {
    if samples.is_empty() {
        0.0
    } else {
        samples.iter().sum::<usize>() as f64 / samples.len() as f64
    }
}

/// Monte-Carlo band over an `f64` sample set.
///
/// Holds `{trials, mean, min, q025, median, q975, max}`, computed with the same
/// conventions every per-module `scalar_null_band`/`scalar_band` used: arithmetic
/// `mean` over the samples in slice order, a [`f64::total_cmp`] sort, raw
/// `min`/`max` from the sorted ends, `scaled_quantile_index(_, 25|975, 1000)` for
/// the percentile edges, and [`median_f64`] for the median.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct F64Band {
    /// Number of samples summarized.
    pub trials: usize,
    /// Arithmetic mean of the samples.
    pub mean: f64,
    /// Smallest sampled value.
    pub min: f64,
    /// Lower pointwise 95% percentile edge.
    pub q025: f64,
    /// Sample median.
    pub median: f64,
    /// Upper pointwise 95% percentile edge.
    pub q975: f64,
    /// Largest sampled value.
    pub max: f64,
}

/// Summarizes an `f64` sample set into a [`F64Band`].
#[must_use]
pub fn f64_band(samples: &[f64]) -> F64Band {
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    F64Band {
        trials: samples.len(),
        mean: f64_sample_mean(samples),
        min: sorted.first().copied().unwrap_or(0.0),
        q025: sorted
            .get(scaled_quantile_index(sorted.len(), 25, 1_000))
            .copied()
            .unwrap_or(0.0),
        median: median_f64(&sorted),
        q975: sorted
            .get(scaled_quantile_index(sorted.len(), 975, 1_000))
            .copied()
            .unwrap_or(0.0),
        max: sorted.last().copied().unwrap_or(0.0),
    }
}

fn f64_sample_mean(samples: &[f64]) -> f64 {
    if samples.is_empty() {
        0.0
    } else {
        samples.iter().sum::<f64>() / samples.len() as f64
    }
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

#[cfg(test)]
mod harness_tests {
    use super::{
        F64Band, NullColumnError, NullSampler, SplitMix64, UsizeBand, WithinMessageShuffle,
        f64_band, median_f64, median_usize, run_null_test, run_null_test_columns,
        run_null_test_columns_streams, run_null_test_streams, scaled_quantile_index, usize_band,
    };
    use core::convert::Infallible;

    fn first_value(draw: &[Vec<usize>]) -> usize {
        draw.first()
            .and_then(|message| message.first())
            .copied()
            .unwrap_or_default()
    }

    fn last_value(draw: &[Vec<usize>]) -> usize {
        draw.first()
            .and_then(|message| message.last())
            .copied()
            .unwrap_or_default()
    }

    fn total_value(draw: &[Vec<usize>]) -> usize {
        draw.iter().flatten().copied().sum()
    }

    #[test]
    fn within_message_shuffle_preserves_each_message_multiset() {
        let messages = vec![vec![0usize, 0, 1, 1, 2, 2], vec![3, 4, 5]];
        let sampler = WithinMessageShuffle {
            messages: &messages,
        };
        let mut rng = SplitMix64::new(0x5151);

        let draw = sampler.sample(&mut rng).unwrap();

        assert_eq!(draw.len(), messages.len());
        for (original, shuffled) in messages.iter().zip(&draw) {
            assert_eq!(shuffled.len(), original.len());
            let mut original_sorted = original.clone();
            let mut shuffled_sorted = shuffled.clone();
            original_sorted.sort_unstable();
            shuffled_sorted.sort_unstable();
            assert_eq!(shuffled_sorted, original_sorted);
        }
    }

    #[test]
    fn run_null_test_with_invariant_statistic_is_hand_checkable() {
        let messages = vec![vec![0usize, 1, 2], vec![3, 4]];
        let sampler = WithinMessageShuffle {
            messages: &messages,
        };

        // Sum is invariant under a within-message shuffle, so every sample is
        // exactly the observed total and the observed value sits in both tails.
        let result = run_null_test(
            |draw| Ok::<usize, Infallible>(total_value(draw)),
            10,
            &sampler,
            5,
            0xABCD,
        )
        .unwrap();

        assert_eq!(result.observed, 10);
        assert_eq!(result.samples, vec![10usize; 5]);
        assert_eq!(result.lower_tail_count, 5);
        assert_eq!(result.upper_tail_count, 5);
        assert_eq!(result.trials, 5);
    }

    #[test]
    fn run_null_test_is_deterministic_in_seed() {
        let messages = vec![vec![0usize, 1, 2, 3, 4]];
        let sampler = WithinMessageShuffle {
            messages: &messages,
        };

        let first = run_null_test(
            |draw| Ok::<usize, Infallible>(first_value(draw)),
            0,
            &sampler,
            16,
            0x1234,
        )
        .unwrap();
        let second = run_null_test(
            |draw| Ok::<usize, Infallible>(first_value(draw)),
            0,
            &sampler,
            16,
            0x1234,
        )
        .unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn run_null_test_streams_concatenates_in_stream_order() {
        let messages = vec![vec![0usize, 1, 2, 3, 4, 5]];
        let sampler = WithinMessageShuffle {
            messages: &messages,
        };
        let seeds = [111u64, 222, 333];

        let streamed = run_null_test_streams(
            |draw| Ok::<usize, Infallible>(first_value(draw)),
            2,
            &sampler,
            3,
            4,
            |index| seeds.get(index).copied().unwrap_or_default(),
        )
        .unwrap();

        let mut expected_samples = Vec::new();
        let mut lower = 0usize;
        let mut upper = 0usize;
        for &seed in &seeds {
            let stream = run_null_test(
                |draw| Ok::<usize, Infallible>(first_value(draw)),
                2,
                &sampler,
                4,
                seed,
            )
            .unwrap();
            expected_samples.extend(stream.samples);
            lower += stream.lower_tail_count;
            upper += stream.upper_tail_count;
        }

        assert_eq!(streamed.samples, expected_samples);
        assert_eq!(streamed.trials, 12);
        assert_eq!(streamed.lower_tail_count, lower);
        assert_eq!(streamed.upper_tail_count, upper);
    }

    #[test]
    fn run_null_test_columns_reports_width_mismatch() {
        let messages = vec![vec![0usize, 1, 2]];
        let sampler = WithinMessageShuffle {
            messages: &messages,
        };

        let result: Result<_, NullColumnError<Infallible>> = run_null_test_columns(
            |_draw| Ok(vec![1usize, 2]),
            vec![0usize, 0, 0],
            &sampler,
            4,
            7,
        );

        assert_eq!(
            result,
            Err(NullColumnError::WidthMismatch {
                expected: 3,
                observed: 2,
            })
        );
    }

    #[test]
    fn run_null_test_columns_streams_matches_per_stream_columns() {
        let messages = vec![vec![0usize, 1, 2, 3]];
        let sampler = WithinMessageShuffle {
            messages: &messages,
        };
        let seeds = [7u64, 9, 11];
        let observed = [1usize, 2];

        let columns = run_null_test_columns_streams(
            |draw| Ok::<Vec<usize>, Infallible>(vec![first_value(draw), last_value(draw)]),
            &observed,
            &sampler,
            3,
            5,
            |index| seeds.get(index).copied().unwrap_or_default(),
        )
        .unwrap();

        let mut expected: Vec<Vec<usize>> = vec![Vec::new(), Vec::new()];
        for &seed in &seeds {
            let per_stream = run_null_test_columns(
                |draw| Ok::<Vec<usize>, Infallible>(vec![first_value(draw), last_value(draw)]),
                observed.to_vec(),
                &sampler,
                5,
                seed,
            )
            .unwrap();
            for (slot, column) in expected.iter_mut().zip(&per_stream) {
                slot.extend(column.samples.iter().copied());
            }
        }

        assert_eq!(columns.len(), 2);
        for (column, expected_samples) in columns.iter().zip(&expected) {
            assert_eq!(&column.samples, expected_samples);
            assert_eq!(column.trials, 15);
        }
    }

    #[test]
    fn usize_band_matches_explicit_quantile_math() {
        let samples: Vec<usize> = vec![5, 3, 8, 1, 9, 2, 7, 4, 6, 0];
        let band: UsizeBand = usize_band(&samples);

        let mut sorted = samples.clone();
        sorted.sort_unstable();
        assert_eq!(band.trials, samples.len());
        assert_eq!(band.min, sorted.first().copied().unwrap());
        assert_eq!(band.max, sorted.last().copied().unwrap());
        assert_eq!(
            band.q025,
            sorted
                .get(scaled_quantile_index(sorted.len(), 25, 1_000))
                .copied()
                .unwrap()
        );
        assert_eq!(
            band.q975,
            sorted
                .get(scaled_quantile_index(sorted.len(), 975, 1_000))
                .copied()
                .unwrap()
        );
        assert_eq!(band.median.to_bits(), median_usize(&sorted).to_bits());
        let expected_mean = samples.iter().sum::<usize>() as f64 / samples.len() as f64;
        assert_eq!(band.mean.to_bits(), expected_mean.to_bits());
    }

    #[test]
    fn f64_band_matches_explicit_quantile_math() {
        let samples: Vec<f64> = vec![5.0, 3.0, 8.5, 1.0, 9.0, 2.0, 7.0, 4.0, 6.0, 0.5];
        let band: F64Band = f64_band(&samples);

        let mut sorted = samples.clone();
        sorted.sort_by(f64::total_cmp);
        assert_eq!(band.trials, samples.len());
        assert_eq!(
            band.min.to_bits(),
            sorted.first().copied().unwrap().to_bits()
        );
        assert_eq!(
            band.max.to_bits(),
            sorted.last().copied().unwrap().to_bits()
        );
        assert_eq!(
            band.q025.to_bits(),
            sorted
                .get(scaled_quantile_index(sorted.len(), 25, 1_000))
                .copied()
                .unwrap()
                .to_bits()
        );
        assert_eq!(
            band.q975.to_bits(),
            sorted
                .get(scaled_quantile_index(sorted.len(), 975, 1_000))
                .copied()
                .unwrap()
                .to_bits()
        );
        assert_eq!(band.median.to_bits(), median_f64(&sorted).to_bits());
        let expected_mean = samples.iter().sum::<f64>() / samples.len() as f64;
        assert_eq!(band.mean.to_bits(), expected_mean.to_bits());
    }
}

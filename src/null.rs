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

/// Deterministic std-only `SplitMix64` pseudo-random number generator.
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
        match self.next_u64() % 5 {
            0 => Orientation::Zero,
            1 => Orientation::One,
            2 => Orientation::Two,
            3 => Orientation::Three,
            _ => Orientation::Four,
        }
    }
}

/// Configuration for a reading-order null run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NullConfig {
    /// Explicit deterministic PRNG seed.
    pub seed: u64,
    /// Number of synthetic corpora to sample.
    pub trials: usize,
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
/// Returns [`GridError`] if the verified corpus grids cannot be reconstructed
/// or if an order is incompatible with a generated grid.
pub fn run_standard36_null(config: NullConfig) -> Result<NullReport, GridError> {
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
/// Returns [`GridError`] if the verified corpus grids cannot be reconstructed
/// or if an order is incompatible with a generated grid.
pub fn run_standard36_null_with(
    config: NullConfig,
    mut generate: impl FnMut(&[GlyphGrid], &mut SplitMix64) -> Vec<GlyphGrid>,
) -> Result<NullReport, GridError> {
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
        min_distinct_histogram: usize_histogram(&min_distinct_values),
        min_ceiling_histogram: u8_histogram(&min_ceiling_values),
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

fn usize_histogram(values: &[usize]) -> Vec<(usize, usize)> {
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

fn u8_histogram(values: &[u8]) -> Vec<(u8, usize)> {
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
        Quantile::Median => median(&sorted),
        Quantile::Max => sorted.last().copied().unwrap_or(0.0),
    }
}

fn median(sorted: &[f64]) -> f64 {
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

#[cfg(test)]
mod tests {
    use super::{
        NullConfig, SplitMix64, analytic_headline_bounds, evaluate_trial, run_standard36_null,
        wilson_95,
    };
    use crate::orders::{corpus_grids, standard36_orders};

    #[test]
    fn splitmix64_seed_is_reproducible() {
        let mut first = SplitMix64::new(12_345);
        let mut second = SplitMix64::new(12_345);
        let first_values: Vec<u64> = (0..8).map(|_| first.next_u64()).collect();
        let second_values: Vec<u64> = (0..8).map(|_| second.next_u64()).collect();
        assert_eq!(first_values, second_values);
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
        assert_eq!(bounds.per_order.to_bits(), 0x19af_be03_5701_f8c3);
        assert_eq!(bounds.bonferroni.to_bits(), 0x1a01_dae1_e0f1_1bee);
        assert_eq!(bounds.sidak.to_bits(), 0x1a01_dae1_e0f1_1bee);
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
        assert_eq!(report.distance4_ratio_min.to_bits(), 0x3fc5_f15f_15f1_5f16);
        assert_eq!(
            report.distance4_ratio_median.to_bits(),
            0x3ff1_a1f5_8d0f_ac69
        );
        assert_eq!(report.distance4_ratio_max.to_bits(), 0x4001_af28_6bca_1af3);

        let adjacent_interval = wilson_95(report.adjacent_zero_count, report.config.trials);
        assert_eq!(adjacent_interval.count, 2);
        assert_eq!(adjacent_interval.trials, 1_000);
        assert_eq!(adjacent_interval.estimate.to_bits(), 0x3f60_624d_d2f1_a9fc);

        let grids = corpus_grids().unwrap();
        let real_outcome = evaluate_trial(&grids, &standard36_orders()).unwrap();
        assert_eq!(
            real_outcome.max_distance4_ratio.to_bits(),
            0x4006_4924_9249_2492
        );
        assert!(real_outcome.max_distance4_ratio > report.distance4_ratio_max);
    }
}

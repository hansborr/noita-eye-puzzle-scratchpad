//! Shared statistical helpers for the reading-order null.
//!
//! Wilson and analytic fixed-order bounds, the per-trial `FastStats` summary and
//! its recurrence/distance helpers, the synthetic-grid generators, and the
//! quantile/median primitives the matched-null bands reuse. The public helpers
//! are re-exported from the parent module so `crate::nulls::null::X` paths are
//! unchanged.

use crate::analysis::orders::{GlyphGrid, GridError, read_corpus_message_values};
use crate::core::trigram::TrigramValue;

use super::{AnalyticBounds, SplitMix64, TrialOutcome, WilsonInterval};

const TRIGRAM_ALPHABET_SIZE: f64 = 125.0;
const HEADLINE_ALPHABET_SIZE: f64 = 83.0;
const WILSON_Z_95: f64 = 1.959_963_984_540_054;

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

pub(super) fn random_grids_like(templates: &[GlyphGrid], rng: &mut SplitMix64) -> Vec<GlyphGrid> {
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

pub(super) fn evaluate_trial(
    grids: &[GlyphGrid],
    orders: &[crate::analysis::orders::ReadingOrder],
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

pub(super) fn total_trigrams(grids: &[GlyphGrid]) -> usize {
    grids.iter().map(GlyphGrid::eye_count).sum::<usize>() / 3
}

pub(super) fn run_length_histogram<K: Ord + Copy>(values: &[K]) -> Vec<(K, usize)> {
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
pub(super) enum Quantile {
    Min,
    Median,
    Max,
}

pub(super) fn sorted_quantile(values: &[f64], quantile: Quantile) -> f64 {
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

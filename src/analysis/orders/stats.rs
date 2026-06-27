//! Structural and reading-layer flatness statistics over trigram value streams.
//!
//! `OrderStats` and `ReadingLayerFlatnessStats` plus the recurrence and
//! fixed-lag counters, and the per-order audit drivers that pair an order with
//! its computed statistics.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    GlyphGrid, GridError, READING_LAYER_ALPHABET_SIZE, ReadingOrder, audit_orders,
    read_corpus_message_values, standard36_orders,
};
use crate::analysis::analysis;
use crate::core::glyph::Glyph;
use crate::core::trigram::TrigramValue;

/// Structural statistics for one trigram value stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderStats {
    /// Number of trigrams in the stream.
    pub total: usize,
    /// Number of distinct trigram values.
    pub distinct: usize,
    /// Minimum value present, if the stream is non-empty.
    pub min: Option<u8>,
    /// Maximum value present, if the stream is non-empty.
    pub max: Option<u8>,
    /// Whether the distinct value set is exactly contiguous between min/max.
    pub contiguous: bool,
    /// Number of distinct trigram values greater than `82`.
    pub values_above_82: usize,
    /// Count of adjacent equal trigrams.
    pub adjacent_equal: usize,
    /// Distance since previous occurrence histogram for distances `1..=6`.
    pub recurrence_distance_1_to_6: [usize; 6],
}

impl OrderStats {
    /// Computes statistics for a trigram value stream.
    #[must_use]
    pub fn from_values(values: &[TrigramValue]) -> Self {
        let distinct_values: BTreeSet<u8> = values.iter().map(|value| value.get()).collect();
        let min = distinct_values.first().copied();
        let max = distinct_values.last().copied();
        let contiguous = min
            .zip(max)
            .is_some_and(|(low, high)| usize::from(high - low + 1) == distinct_values.len());
        let adjacent_equal = count_recurrence(values, 1);
        let recurrence = [
            adjacent_equal,
            count_recurrence(values, 2),
            count_recurrence(values, 3),
            count_recurrence(values, 4),
            count_recurrence(values, 5),
            count_recurrence(values, 6),
        ];
        Self {
            total: values.len(),
            distinct: distinct_values.len(),
            min,
            max,
            contiguous,
            values_above_82: distinct_values.iter().filter(|&&value| value > 82).count(),
            adjacent_equal,
            recurrence_distance_1_to_6: recurrence,
        }
    }

    /// Computes statistics for a corpus stream while preserving message
    /// boundaries for recurrence counts.
    #[must_use]
    pub fn from_message_values(message_values: &[Vec<TrigramValue>]) -> Self {
        let values: Vec<TrigramValue> = message_values.iter().flatten().copied().collect();
        let mut stats = Self::from_values(&values);
        let adjacent_equal = count_message_recurrence(message_values, 1);
        let recurrence = [
            adjacent_equal,
            count_message_recurrence(message_values, 2),
            count_message_recurrence(message_values, 3),
            count_message_recurrence(message_values, 4),
            count_message_recurrence(message_values, 5),
            count_message_recurrence(message_values, 6),
        ];
        stats.adjacent_equal = adjacent_equal;
        stats.recurrence_distance_1_to_6 = recurrence;
        stats
    }

    /// Returns true for the headline contiguous `0..=82` result.
    #[must_use]
    pub fn is_contiguous_0_to_82(&self) -> bool {
        self.distinct == 83
            && self.contiguous
            && self.min == Some(0)
            && self.max == Some(82)
            && self.values_above_82 == 0
    }
}

/// Frequency, entropy, `IoC`, and chi-square flatness stats for one order.
#[derive(Clone, Debug, PartialEq)]
pub struct ReadingLayerFlatnessStats {
    /// Number of trigrams across all messages.
    pub total: usize,
    /// Count of trigrams whose value is in the `0..=82` reading-layer alphabet.
    pub in_alphabet_total: usize,
    /// Count of trigrams outside the `0..=82` reading-layer alphabet.
    pub outside_alphabet_occurrences: usize,
    /// Frequency table for the `0..=82` reading-layer alphabet.
    pub frequencies: Vec<(u8, usize)>,
    /// Uniform expected frequency, `total / 83`.
    pub mean_frequency: f64,
    /// Smallest observed frequency among the `0..=82` buckets.
    pub min_frequency: usize,
    /// Largest observed frequency among the `0..=82` buckets.
    pub max_frequency: usize,
    /// Number of `0..=82` buckets with zero observations.
    pub zero_frequency_symbols: usize,
    /// Per-message weighted Shannon entropy, in bits per trigram.
    pub entropy_bits_per_symbol: f64,
    /// Maximum entropy for a valid 83-symbol uniform stream.
    pub max_entropy_bits_per_symbol: f64,
    /// Per-message weighted `IoC` probability.
    pub ioc_probability: f64,
    /// `IoC` normalized to the 83-symbol uniform baseline (`1.0` means uniform).
    pub normalized_ioc: f64,
    /// Concatenated-corpus `IoC` probability, reported as a community-reference cross-check.
    pub concatenated_ioc_probability: f64,
    /// Concatenated `IoC` normalized to the 83-symbol uniform baseline.
    pub concatenated_normalized_ioc: f64,
    /// Pearson chi-square statistic against uniform support on `0..=82`.
    ///
    /// This is infinite when the order emits any value outside `0..=82`, because
    /// an 83-symbol expected distribution assigns those values probability zero.
    pub chi_square_vs_uniform: f64,
    /// Upper-tail p-value `P(X_df >= chi_square_vs_uniform)` for the finite statistic.
    ///
    /// This is `None` when the order emits a value outside `0..=82`, because
    /// that observation is outside the support of the 83-symbol reference model.
    pub chi_square_vs_uniform_upper_tail_p_value: Option<f64>,
}

impl ReadingLayerFlatnessStats {
    /// Degrees of freedom for the fully specified 83-bucket uniform chi-square reference.
    pub const CHI_SQUARE_VS_UNIFORM_DEGREES_OF_FREEDOM: usize = READING_LAYER_ALPHABET_SIZE - 1;

    /// Computes reading-layer flatness stats from per-message trigram values.
    #[must_use]
    pub fn from_message_values(message_values: &[Vec<TrigramValue>]) -> Self {
        let message_glyphs = glyph_messages_from_values(message_values);
        let glyphs: Vec<Glyph> = message_glyphs.iter().flatten().copied().collect();
        let counts = analysis::frequencies(&glyphs);
        let mut frequencies = Vec::with_capacity(READING_LAYER_ALPHABET_SIZE);
        for value in 0..READING_LAYER_ALPHABET_SIZE {
            let glyph = Glyph(value as u16);
            frequencies.push((value as u8, counts.get(&glyph).copied().unwrap_or(0)));
        }

        let total = glyphs.len();
        let in_alphabet_total = frequencies.iter().map(|(_value, count)| *count).sum();
        let outside_alphabet_occurrences = total.saturating_sub(in_alphabet_total);
        let min_frequency = frequencies
            .iter()
            .map(|(_value, count)| *count)
            .min()
            .unwrap_or(0);
        let max_frequency = frequencies
            .iter()
            .map(|(_value, count)| *count)
            .max()
            .unwrap_or(0);
        let zero_frequency_symbols = frequencies
            .iter()
            .filter(|(_value, count)| *count == 0)
            .count();
        let frequency_counts: Vec<usize> =
            frequencies.iter().map(|(_value, count)| *count).collect();
        let ioc_probability = analysis::message_weighted_index_of_coincidence(&message_glyphs);
        let concatenated_ioc_probability = analysis::index_of_coincidence(&glyphs);
        let chi_square_vs_uniform = if outside_alphabet_occurrences == 0 {
            analysis::chi_square_goodness_of_fit_uniform(&frequency_counts)
        } else {
            f64::INFINITY
        };
        let chi_square_vs_uniform_upper_tail_p_value = if outside_alphabet_occurrences == 0 {
            analysis::chi_square_upper_tail_p_value(
                chi_square_vs_uniform,
                Self::CHI_SQUARE_VS_UNIFORM_DEGREES_OF_FREEDOM,
            )
        } else {
            None
        };

        Self {
            total,
            in_alphabet_total,
            outside_alphabet_occurrences,
            frequencies,
            mean_frequency: total as f64 / READING_LAYER_ALPHABET_SIZE as f64,
            min_frequency,
            max_frequency,
            zero_frequency_symbols,
            entropy_bits_per_symbol: analysis::message_weighted_entropy(&message_glyphs),
            max_entropy_bits_per_symbol: (READING_LAYER_ALPHABET_SIZE as f64).log2(),
            ioc_probability,
            normalized_ioc: ioc_probability * READING_LAYER_ALPHABET_SIZE as f64,
            concatenated_ioc_probability,
            concatenated_normalized_ioc: concatenated_ioc_probability
                * READING_LAYER_ALPHABET_SIZE as f64,
            chi_square_vs_uniform,
            chi_square_vs_uniform_upper_tail_p_value,
        }
    }
}

/// Converts per-message reading-layer trigram values into generic glyphs.
///
/// This keeps message boundaries intact for statistics that must not create
/// artificial evidence across joins.
#[must_use]
pub fn glyph_messages_from_values(message_values: &[Vec<TrigramValue>]) -> Vec<Vec<Glyph>> {
    message_values
        .iter()
        .map(|values| {
            values
                .iter()
                .map(|value| Glyph(u16::from(value.get())))
                .collect()
        })
        .collect()
}

/// Counts values whose previous occurrence was exactly `distance` positions ago.
///
/// This is the recurrence convention used by the reading-order audit. It is
/// not the same as all-pair lag autocorrelation: only the immediately previous
/// occurrence of each value is considered.
#[must_use]
pub fn count_recurrence(values: &[TrigramValue], distance: usize) -> usize {
    if distance == 0 {
        return 0;
    }
    let mut previous_positions = BTreeMap::new();
    let mut count = 0;
    for (position, value) in values.iter().copied().enumerate() {
        if previous_positions
            .insert(value, position)
            .is_some_and(|previous| position - previous == distance)
        {
            count += 1;
        }
    }
    count
}

/// Sums [`count_recurrence`] over messages without crossing message joins.
#[must_use]
pub fn count_message_recurrence(message_values: &[Vec<TrigramValue>], distance: usize) -> usize {
    message_values
        .iter()
        .map(|values| count_recurrence(values, distance))
        .sum()
}

/// Counts exact equality pairs at a fixed lag in one message.
///
/// For lag `L`, this checks every valid pair `symbol[i] == symbol[i + L]`.
/// Returns zero for lag zero or for lags greater than or equal to the message
/// length.
#[must_use]
pub fn count_lag_matches(values: &[TrigramValue], lag: usize) -> usize {
    if lag == 0 || lag >= values.len() {
        return 0;
    }
    values
        .iter()
        .zip(values.iter().skip(lag))
        .filter(|(left, right)| left == right)
        .count()
}

/// Counts comparable pairs at a fixed lag in one message.
///
/// This is the denominator for [`count_lag_matches`].
#[must_use]
pub fn count_lag_comparisons(values: &[TrigramValue], lag: usize) -> usize {
    if lag == 0 {
        return 0;
    }
    values.len().saturating_sub(lag)
}

/// Sums exact equality pairs at a fixed lag over messages.
///
/// Message boundaries are preserved: no pair is formed from the end of one
/// message to the beginning of another.
#[must_use]
pub fn count_message_lag_matches(message_values: &[Vec<TrigramValue>], lag: usize) -> usize {
    message_values
        .iter()
        .map(|values| count_lag_matches(values, lag))
        .sum()
}

/// Sums comparable fixed-lag pairs over messages without crossing joins.
#[must_use]
pub fn count_message_lag_comparisons(message_values: &[Vec<TrigramValue>], lag: usize) -> usize {
    message_values
        .iter()
        .map(|values| count_lag_comparisons(values, lag))
        .sum()
}

/// Statistics for a named order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamedOrderStats {
    /// The reading order.
    pub order: ReadingOrder,
    /// The computed statistics.
    pub stats: OrderStats,
}

/// Flatness statistics for a named order.
#[derive(Clone, Debug, PartialEq)]
pub struct NamedReadingLayerFlatnessStats {
    /// The reading order.
    pub order: ReadingOrder,
    /// The computed flatness statistics.
    pub flatness: ReadingLayerFlatnessStats,
}

/// Computes stats for every order in [`audit_orders`].
///
/// # Errors
/// Returns [`GridError`] if any order is incompatible with the grids.
pub fn audit_order_stats(grids: &[GlyphGrid]) -> Result<Vec<NamedOrderStats>, GridError> {
    let mut stats = Vec::new();
    for order in audit_orders() {
        let values = read_corpus_message_values(grids, order)?;
        stats.push(NamedOrderStats {
            order,
            stats: OrderStats::from_message_values(&values),
        });
    }
    Ok(stats)
}

/// Computes flatness stats for one order.
///
/// # Errors
/// Returns [`GridError`] if the order is incompatible with the grids.
pub fn reading_layer_flatness_stats(
    grids: &[GlyphGrid],
    order: ReadingOrder,
) -> Result<ReadingLayerFlatnessStats, GridError> {
    let message_values = read_corpus_message_values(grids, order)?;
    Ok(ReadingLayerFlatnessStats::from_message_values(
        &message_values,
    ))
}

/// Computes flatness stats for every order in [`audit_orders`].
///
/// # Errors
/// Returns [`GridError`] if any order is incompatible with the grids.
pub fn audit_order_flatness_stats(
    grids: &[GlyphGrid],
) -> Result<Vec<NamedReadingLayerFlatnessStats>, GridError> {
    let mut stats = Vec::new();
    for order in audit_orders() {
        stats.push(NamedReadingLayerFlatnessStats {
            order,
            flatness: reading_layer_flatness_stats(grids, order)?,
        });
    }
    Ok(stats)
}

/// Computes flatness stats for the exact Toboter-style standard-36 family.
///
/// # Errors
/// Returns [`GridError`] if any standard order is incompatible with the grids.
pub fn standard36_flatness_stats(
    grids: &[GlyphGrid],
) -> Result<Vec<NamedReadingLayerFlatnessStats>, GridError> {
    let mut stats = Vec::new();
    for order in standard36_orders() {
        stats.push(NamedReadingLayerFlatnessStats {
            order,
            flatness: reading_layer_flatness_stats(grids, order)?,
        });
    }
    Ok(stats)
}

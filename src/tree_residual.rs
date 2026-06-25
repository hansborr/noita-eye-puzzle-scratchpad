//! Tree-residual cross-tail n-gram null.
//!
//! This experiment asks whether cross-message n-gram sharing remains after the
//! aligned tree trunk is removed. The trunk mask is not reconstructed here:
//! it reuses the `perseus` module's Experiment 7C shared-region definition:
//! same-offset common runs of length at least two that belong to the earliest
//! leading-family alignment or an East/West counterpart pair.
//!
//! The residual statistic is position-independent across messages. For each
//! `k` in [`K_VALUES`], it counts distinct k-gram kinds that occur in residual
//! tails of at least two different messages. K-grams are built within one
//! message residual segment at a time; no k-gram crosses a message join or a
//! masked shared span. The null shuffles each message's residual symbols while
//! preserving that message's residual length, residual segment shape, and exact
//! residual multiset.

use std::collections::{BTreeMap, BTreeSet};
use std::mem::size_of;

use crate::null::{SplitMix64, add_one_p_value, fisher_yates};
use crate::orders::{self, GridError, ReadingOrder, read_corpus_message_values};
use crate::perseus::{self, SharedPartition};
use crate::trigram::TrigramValue;

/// Default deterministic base seed for the tree-residual shuffle null.
pub const DEFAULT_SEED: u64 = 0x7472_6565_7461_696c;
/// Default number of within-tail shuffle trials per seed.
pub const DEFAULT_TRIALS: usize = 1_000;
/// Default number of deterministic seed batches.
pub const DEFAULT_SEED_COUNT: usize = 5;
/// K-gram sizes scanned by this experiment.
pub const K_VALUES: [usize; 2] = [3, 4];
/// Conventional pointwise upper-tail significance cutoff.
pub const SIGNIFICANCE_ALPHA: f64 = 0.05;

const TREE_RESIDUAL_ROW_COUNT: usize = 2 * K_VALUES.len();
const MAX_VEC_ALLOCATION_BYTES: usize = usize::MAX / 2;

/// Configuration for the tree-residual cross-tail n-gram null.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeResidualConfig {
    /// Deterministic base PRNG seed.
    pub seed: u64,
    /// Number of within-tail shuffle trials to sample per seed.
    pub trials: usize,
    /// Number of deterministic seed batches.
    pub seed_count: usize,
}

impl Default for TreeResidualConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_SEED,
            trials: DEFAULT_TRIALS,
            seed_count: DEFAULT_SEED_COUNT,
        }
    }
}

/// Error returned by the tree-residual cross-tail n-gram null.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TreeResidualError {
    /// The verified corpus could not be reconstructed or read.
    Grid(GridError),
    /// The shared-region mask could not be reconstructed.
    Perseus(perseus::PerseusError),
    /// At least one Monte-Carlo trial is required.
    ZeroTrials,
    /// At least one deterministic seed batch is required.
    ZeroSeedCount,
    /// K-gram length must be at least one.
    InvalidK {
        /// Requested k-gram length.
        k: usize,
    },
    /// The caller supplied a different number of keys and message streams.
    KeyCountMismatch {
        /// Number of message keys.
        keys: usize,
        /// Number of message streams.
        messages: usize,
    },
    /// The reconstructed mask count did not match the message count.
    MessageMaskMismatch {
        /// Number of message streams.
        messages: usize,
        /// Number of partition masks.
        masks: usize,
    },
    /// One message's mask length differed from its stream length.
    TailMaskLengthMismatch {
        /// Message key whose mask could not be applied.
        message_key: &'static str,
        /// Reading-layer stream length.
        values: usize,
        /// Mask length.
        mask: usize,
    },
    /// A shuffle bound did not fit in the PRNG draw helper.
    RandomBoundTooLarge {
        /// Requested exclusive upper bound.
        bound: usize,
    },
    /// The configured sample count was too large for allocation or p-values.
    SampleCountTooLarge,
}

impl From<GridError> for TreeResidualError {
    fn from(value: GridError) -> Self {
        Self::Grid(value)
    }
}

impl From<perseus::PerseusError> for TreeResidualError {
    fn from(value: perseus::PerseusError) -> Self {
        Self::Perseus(value)
    }
}

impl From<crate::null::RandomBoundError> for TreeResidualError {
    fn from(error: crate::null::RandomBoundError) -> Self {
        Self::RandomBoundTooLarge { bound: error.bound }
    }
}

/// Stream scope used for one cross-message statistic row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TreeResidualScope {
    /// Residual tails after applying the Experiment 7C shared-region mask.
    ResidualTails,
    /// Full unmasked messages, used as a sanity cross-check.
    FullMessages,
}

impl TreeResidualScope {
    /// Human-readable scope label for reports.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ResidualTails => "residual-tails",
            Self::FullMessages => "full-messages",
        }
    }
}

/// Per-message residual-tail summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageTailSummary {
    /// Message key.
    pub message_key: &'static str,
    /// Number of unmasked residual symbols in this message.
    pub residual_symbols: usize,
    /// Number of contiguous unmasked residual segments.
    pub residual_segments: usize,
    /// Longest contiguous residual segment.
    pub longest_segment: usize,
}

/// Cross-message distinct k-gram overlap statistic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrossTailStatistic {
    /// Number of distinct k-gram kinds seen in at least one message.
    pub total_distinct_ngrams: usize,
    /// Number of distinct k-gram kinds seen in at least two different messages.
    pub shared_distinct_ngrams: usize,
    /// Largest number of messages containing any one k-gram kind.
    pub max_messages_per_ngram: usize,
}

/// Monte-Carlo distribution band for the shared-k-gram count.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CrossTailNullBand {
    /// Number of shuffled samples.
    pub samples: usize,
    /// Mean shared-k-gram count.
    pub mean: f64,
    /// Smallest sampled shared-k-gram count.
    pub min: usize,
    /// Lower pointwise 95% percentile edge.
    pub q025: usize,
    /// Sample median.
    pub median: f64,
    /// Upper pointwise 95% percentile edge.
    pub q975: usize,
    /// Largest sampled shared-k-gram count.
    pub max: usize,
}

/// Real-vs-null row for one scope and k-gram length.
#[derive(Clone, Debug, PartialEq)]
pub struct TreeResidualRow {
    /// Stream scope for this row.
    pub scope: TreeResidualScope,
    /// K-gram length.
    pub k: usize,
    /// Observed cross-message statistic.
    pub observed: CrossTailStatistic,
    /// Shuffle-null distribution.
    pub null: CrossTailNullBand,
    /// Number of shuffles with count less than or equal to the observed count.
    pub lower_tail_count: usize,
    /// Number of shuffles with count greater than or equal to the observed
    /// count.
    pub upper_tail_count: usize,
    /// Add-one lower-tail empirical p-value.
    pub lower_tail_p: f64,
    /// Add-one upper-tail empirical p-value; this is the reused-motif signal
    /// direction.
    pub upper_tail_p: f64,
    /// Add-one two-sided empirical p-value, capped at one.
    pub two_sided_p: f64,
    /// Whether this row has a pointwise significant upper-tail excess.
    pub significant_excess: bool,
}

/// Complete tree-residual cross-tail n-gram null report.
#[derive(Clone, Debug, PartialEq)]
pub struct TreeResidualReport {
    /// Configuration used for the run.
    pub config: TreeResidualConfig,
    /// Reading order used for the real and shuffled streams.
    pub order: ReadingOrder,
    /// Per-message stream lengths in corpus order.
    pub message_lengths: Vec<(&'static str, usize)>,
    /// Total reading-layer symbols across full messages.
    pub total_length: usize,
    /// Reconstructed shared/non-shared partition reused from Experiment 7C.
    pub partition: SharedPartition,
    /// Per-message residual-tail summaries.
    pub tail_lengths: Vec<MessageTailSummary>,
    /// Total residual-tail symbols across messages.
    pub tail_total_length: usize,
    /// Deterministic seed batches actually sampled.
    pub seeds: Vec<u64>,
    /// Real-vs-null rows for residual tails and full-message sanity checks.
    pub rows: Vec<TreeResidualRow>,
}

/// Runs the tree-residual cross-tail n-gram null on the verified eye corpus.
///
/// # Errors
/// Returns [`TreeResidualError`] when the corpus cannot be reconstructed, the
/// accepted reading order is incompatible with a grid, the Experiment 7C
/// shared mask cannot be reconstructed, or the configuration is invalid.
pub fn run_tree_residual(
    config: TreeResidualConfig,
) -> Result<TreeResidualReport, TreeResidualError> {
    validate_config(config)?;
    let grids = orders::corpus_grids()?;
    let keys = grids
        .iter()
        .map(crate::orders::GlyphGrid::message_key)
        .collect::<Vec<_>>();
    let order = orders::accepted_honeycomb_order();
    let message_values = read_corpus_message_values(&grids, order)?;
    report_from_message_values(config, order, &keys, &message_values)
}

fn report_from_message_values(
    config: TreeResidualConfig,
    order: ReadingOrder,
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
) -> Result<TreeResidualReport, TreeResidualError> {
    validate_config(config)?;
    let partition = perseus::build_shared_partition(keys, message_values)?;
    let residual_messages = residual_segment_messages(keys, message_values, &partition)?;
    let full_messages = full_segment_messages(keys, message_values)?;
    report_from_segment_messages(
        config,
        order,
        keys,
        message_values,
        partition,
        &residual_messages,
        &full_messages,
    )
}

fn report_from_segment_messages(
    config: TreeResidualConfig,
    order: ReadingOrder,
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    partition: SharedPartition,
    residual_messages: &[MessageSegments],
    full_messages: &[MessageSegments],
) -> Result<TreeResidualReport, TreeResidualError> {
    validate_config(config)?;
    let sample_count = total_sample_count(config)?;
    let seeds = seed_batches(config.seed, config.seed_count)?;
    let mut rows = initial_row_accumulators(residual_messages, full_messages, sample_count)?;

    for seed in &seeds {
        let mut rng = SplitMix64::new(*seed);
        for _trial in 0..config.trials {
            let shuffled_residual = shuffled_segment_messages(residual_messages, &mut rng)?;
            let shuffled_full = shuffled_segment_messages(full_messages, &mut rng)?;
            accumulate_trial_rows(&mut rows, &shuffled_residual, &shuffled_full)?;
        }
    }

    let rows = rows
        .into_iter()
        .map(RowAccumulator::into_report_row)
        .collect::<Vec<_>>();
    let lengths = message_values.iter().map(Vec::len).collect::<Vec<_>>();
    let total_length = lengths.iter().sum();
    let tail_lengths = tail_summaries(residual_messages);
    let tail_total_length = tail_lengths
        .iter()
        .map(|summary| summary.residual_symbols)
        .sum();

    Ok(TreeResidualReport {
        config,
        order,
        message_lengths: keys.iter().copied().zip(lengths).collect(),
        total_length,
        partition,
        tail_lengths,
        tail_total_length,
        seeds,
        rows,
    })
}

fn validate_config(config: TreeResidualConfig) -> Result<(), TreeResidualError> {
    if config.trials == 0 {
        return Err(TreeResidualError::ZeroTrials);
    }
    if config.seed_count == 0 {
        return Err(TreeResidualError::ZeroSeedCount);
    }
    let sample_count = total_sample_count(config)?;
    validate_vec_capacity::<usize>(sample_count)?;
    validate_vec_capacity::<u64>(config.seed_count)?;
    Ok(())
}

fn total_sample_count(config: TreeResidualConfig) -> Result<usize, TreeResidualError> {
    config
        .trials
        .checked_mul(config.seed_count)
        .ok_or(TreeResidualError::SampleCountTooLarge)
}

fn reserve_exact<T>(values: &mut Vec<T>, capacity: usize) -> Result<(), TreeResidualError> {
    validate_vec_capacity::<T>(capacity)?;
    match values.try_reserve_exact(capacity) {
        Ok(()) => Ok(()),
        Err(_error) => Err(TreeResidualError::SampleCountTooLarge),
    }
}

fn validate_vec_capacity<T>(capacity: usize) -> Result<(), TreeResidualError> {
    if capacity > max_vec_capacity_for::<T>() {
        return Err(TreeResidualError::SampleCountTooLarge);
    }
    Ok(())
}

fn max_vec_capacity_for<T>() -> usize {
    let element_size = size_of::<T>();
    if element_size == 0 {
        return usize::MAX;
    }
    MAX_VEC_ALLOCATION_BYTES / element_size
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MessageSegments {
    message_key: &'static str,
    segments: Vec<Vec<TrigramValue>>,
}

impl MessageSegments {
    fn total_len(&self) -> usize {
        self.segments.iter().map(Vec::len).sum()
    }

    fn longest_segment(&self) -> usize {
        self.segments.iter().map(Vec::len).max().unwrap_or_default()
    }
}

#[derive(Clone, Debug, PartialEq)]
struct RowAccumulator {
    scope: TreeResidualScope,
    k: usize,
    observed: CrossTailStatistic,
    samples: Vec<usize>,
    lower_tail_count: usize,
    upper_tail_count: usize,
}

impl RowAccumulator {
    fn observe_sample(&mut self, sample: usize) {
        if sample <= self.observed.shared_distinct_ngrams {
            self.lower_tail_count += 1;
        }
        if sample >= self.observed.shared_distinct_ngrams {
            self.upper_tail_count += 1;
        }
        self.samples.push(sample);
    }

    fn into_report_row(self) -> TreeResidualRow {
        let lower_tail_p = add_one_p_value(self.lower_tail_count, self.samples.len());
        let upper_tail_p = add_one_p_value(self.upper_tail_count, self.samples.len());
        let two_sided_p = (2.0 * lower_tail_p.min(upper_tail_p)).min(1.0);
        let null = null_band(&self.samples);
        let significant_excess =
            self.observed.shared_distinct_ngrams > null.q975 && upper_tail_p <= SIGNIFICANCE_ALPHA;
        TreeResidualRow {
            scope: self.scope,
            k: self.k,
            observed: self.observed,
            null,
            lower_tail_count: self.lower_tail_count,
            upper_tail_count: self.upper_tail_count,
            lower_tail_p,
            upper_tail_p,
            two_sided_p,
            significant_excess,
        }
    }
}

fn initial_row_accumulators(
    residual_messages: &[MessageSegments],
    full_messages: &[MessageSegments],
    sample_count: usize,
) -> Result<Vec<RowAccumulator>, TreeResidualError> {
    let mut rows = Vec::with_capacity(TREE_RESIDUAL_ROW_COUNT);
    for (scope, messages) in [
        (TreeResidualScope::ResidualTails, residual_messages),
        (TreeResidualScope::FullMessages, full_messages),
    ] {
        for k in K_VALUES {
            let mut samples = Vec::new();
            reserve_exact(&mut samples, sample_count)?;
            rows.push(RowAccumulator {
                scope,
                k,
                observed: cross_message_statistic(messages, k)?,
                samples,
                lower_tail_count: 0,
                upper_tail_count: 0,
            });
        }
    }
    Ok(rows)
}

fn accumulate_trial_rows(
    rows: &mut [RowAccumulator],
    residual_messages: &[MessageSegments],
    full_messages: &[MessageSegments],
) -> Result<(), TreeResidualError> {
    for row in rows {
        let messages = match row.scope {
            TreeResidualScope::ResidualTails => residual_messages,
            TreeResidualScope::FullMessages => full_messages,
        };
        let sample = cross_message_statistic(messages, row.k)?.shared_distinct_ngrams;
        row.observe_sample(sample);
    }
    Ok(())
}

fn residual_segment_messages(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    partition: &SharedPartition,
) -> Result<Vec<MessageSegments>, TreeResidualError> {
    if keys.len() != message_values.len() {
        return Err(TreeResidualError::KeyCountMismatch {
            keys: keys.len(),
            messages: message_values.len(),
        });
    }
    if message_values.len() != partition.masks().len() {
        return Err(TreeResidualError::MessageMaskMismatch {
            messages: message_values.len(),
            masks: partition.masks().len(),
        });
    }

    let mut messages = Vec::new();
    for ((message_key, values), mask) in keys
        .iter()
        .copied()
        .zip(message_values)
        .zip(partition.masks())
    {
        if values.len() != mask.len() {
            return Err(TreeResidualError::TailMaskLengthMismatch {
                message_key,
                values: values.len(),
                mask: mask.len(),
            });
        }
        messages.push(MessageSegments {
            message_key,
            segments: unmasked_segments(values, mask),
        });
    }
    Ok(messages)
}

fn unmasked_segments(values: &[TrigramValue], mask: &[bool]) -> Vec<Vec<TrigramValue>> {
    let mut segments = Vec::new();
    let mut active = Vec::new();
    for (value, is_shared) in values.iter().copied().zip(mask.iter().copied()) {
        if is_shared {
            if !active.is_empty() {
                segments.push(std::mem::take(&mut active));
            }
        } else {
            active.push(value);
        }
    }
    if !active.is_empty() {
        segments.push(active);
    }
    segments
}

fn full_segment_messages(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
) -> Result<Vec<MessageSegments>, TreeResidualError> {
    if keys.len() != message_values.len() {
        return Err(TreeResidualError::KeyCountMismatch {
            keys: keys.len(),
            messages: message_values.len(),
        });
    }
    Ok(keys
        .iter()
        .copied()
        .zip(message_values)
        .map(|(message_key, values)| MessageSegments {
            message_key,
            segments: vec![values.clone()],
        })
        .collect())
}

fn tail_summaries(messages: &[MessageSegments]) -> Vec<MessageTailSummary> {
    messages
        .iter()
        .map(|message| MessageTailSummary {
            message_key: message.message_key,
            residual_symbols: message.total_len(),
            residual_segments: message.segments.len(),
            longest_segment: message.longest_segment(),
        })
        .collect()
}

fn cross_message_statistic(
    messages: &[MessageSegments],
    k: usize,
) -> Result<CrossTailStatistic, TreeResidualError> {
    if k == 0 {
        return Err(TreeResidualError::InvalidK { k });
    }

    let mut message_counts = BTreeMap::<Vec<TrigramValue>, usize>::new();
    for message in messages {
        for ngram in distinct_message_ngrams(message, k) {
            *message_counts.entry(ngram).or_default() += 1;
        }
    }
    let total_distinct_ngrams = message_counts.len();
    let shared_distinct_ngrams = message_counts.values().filter(|count| **count >= 2).count();
    let max_messages_per_ngram = message_counts.values().copied().max().unwrap_or_default();

    Ok(CrossTailStatistic {
        total_distinct_ngrams,
        shared_distinct_ngrams,
        max_messages_per_ngram,
    })
}

fn distinct_message_ngrams(message: &MessageSegments, k: usize) -> BTreeSet<Vec<TrigramValue>> {
    let mut ngrams = BTreeSet::new();
    for segment in &message.segments {
        for window in segment.windows(k) {
            let _inserted = ngrams.insert(window.to_vec());
        }
    }
    ngrams
}

fn shuffled_segment_messages(
    messages: &[MessageSegments],
    rng: &mut SplitMix64,
) -> Result<Vec<MessageSegments>, TreeResidualError> {
    let mut shuffled = Vec::new();
    for message in messages {
        let lengths = message.segments.iter().map(Vec::len).collect::<Vec<_>>();
        let mut values = message
            .segments
            .iter()
            .flat_map(|segment| segment.iter().copied())
            .collect::<Vec<_>>();
        fisher_yates(&mut values, rng)?;
        shuffled.push(MessageSegments {
            message_key: message.message_key,
            segments: repartition_segments(values, &lengths),
        });
    }
    Ok(shuffled)
}

fn repartition_segments(values: Vec<TrigramValue>, lengths: &[usize]) -> Vec<Vec<TrigramValue>> {
    let mut iter = values.into_iter();
    let mut segments = Vec::new();
    for len in lengths {
        let mut segment = Vec::with_capacity(*len);
        for _position in 0..*len {
            if let Some(value) = iter.next() {
                segment.push(value);
            }
        }
        segments.push(segment);
    }
    segments
}

fn seed_batches(seed: u64, seed_count: usize) -> Result<Vec<u64>, TreeResidualError> {
    let mut seeds = Vec::new();
    reserve_exact(&mut seeds, seed_count)?;
    if seed_count == 0 {
        return Ok(seeds);
    }
    seeds.push(seed);
    let mut rng = SplitMix64::new(seed);
    while seeds.len() < seed_count {
        seeds.push(rng.next_u64());
    }
    Ok(seeds)
}

fn null_band(samples: &[usize]) -> CrossTailNullBand {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    CrossTailNullBand {
        samples: samples.len(),
        mean: mean_usize(samples),
        min: sorted.first().copied().unwrap_or_default(),
        q025: quantile_from_sorted(&sorted, 25, 1_000),
        median: median_usize(&sorted),
        q975: quantile_from_sorted(&sorted, 975, 1_000),
        max: sorted.last().copied().unwrap_or_default(),
    }
}

fn mean_usize(samples: &[usize]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    samples.iter().sum::<usize>() as f64 / samples.len() as f64
}

fn median_usize(sorted: &[usize]) -> f64 {
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

fn quantile_from_sorted(sorted: &[usize], numerator: usize, denominator: usize) -> usize {
    sorted
        .get(scaled_quantile_index(sorted.len(), numerator, denominator))
        .copied()
        .unwrap_or_default()
}

fn scaled_quantile_index(len: usize, numerator: usize, denominator: usize) -> usize {
    if len == 0 || denominator == 0 {
        return 0;
    }
    len.saturating_sub(1).saturating_mul(numerator) / denominator
}

#[cfg(test)]
mod tests {
    use super::{
        CrossTailStatistic, MessageSegments, TreeResidualConfig, TreeResidualError,
        TreeResidualScope, cross_message_statistic, max_vec_capacity_for,
        report_from_message_values, residual_segment_messages, run_tree_residual, seed_batches,
    };
    use crate::null::SplitMix64;
    use crate::orders;
    use crate::perseus;
    use crate::trigram::TrigramValue;

    const FLOAT_RELATIVE_EPSILON: f64 = 1.0e-12;

    fn assert_relative_close(actual: f64, expected: f64, label: &str) {
        let tolerance = expected.abs().max(1.0) * FLOAT_RELATIVE_EPSILON;
        let difference = (actual - expected).abs();
        assert!(
            difference <= tolerance,
            "{label} changed: actual={actual:.17e} expected={expected:.17e} diff={difference:.17e} tolerance={tolerance:.17e}"
        );
    }

    #[test]
    fn kgram_intersection_counts_distinct_cross_message_overlap() {
        let messages = vec![
            message("a", &[&[1, 2, 3, 1, 2, 4]]),
            message("b", &[&[0, 1, 2, 3, 8]]),
            message("c", &[&[9, 1, 2, 4, 9]]),
        ];

        let statistic = cross_message_statistic(&messages, 3).unwrap();

        assert_eq!(
            statistic,
            CrossTailStatistic {
                total_distinct_ngrams: 8,
                shared_distinct_ngrams: 2,
                max_messages_per_ngram: 2,
            }
        );
    }

    #[test]
    fn kgrams_do_not_cross_residual_segments() {
        let messages = vec![
            message("a", &[&[1, 2], &[3, 4]]),
            message("b", &[&[1, 2, 3]]),
        ];

        let statistic = cross_message_statistic(&messages, 3).unwrap();

        assert_eq!(statistic.shared_distinct_ngrams, 0);
        assert_eq!(statistic.total_distinct_ngrams, 1);
    }

    #[test]
    fn residual_mask_reuses_perseus_shared_partition() {
        let keys = ["east1", "west1"];
        let messages = vec![
            values(&[80, 1, 2, 3, 10, 11, 12]),
            values(&[81, 1, 2, 3, 20, 21, 22]),
        ];
        let partition = perseus::build_shared_partition(&keys, &messages).unwrap();

        let residual = residual_segment_messages(&keys, &messages, &partition).unwrap();

        let segment_lengths = residual
            .iter()
            .map(|message| message.segments.iter().map(Vec::len).collect::<Vec<_>>())
            .collect::<Vec<_>>();
        assert_eq!(segment_lengths, vec![vec![1, 3], vec![1, 3]]);
        let mut residual_iter = residual.iter();
        let first = residual_iter.next().unwrap();
        let second = residual_iter.next().unwrap();
        assert_eq!(first.segments, vec![values(&[80]), values(&[10, 11, 12])]);
        assert_eq!(second.segments, vec![values(&[81]), values(&[20, 21, 22])]);
    }

    #[test]
    fn oversized_sample_count_returns_error_without_capacity_panic() {
        let too_many_samples = max_vec_capacity_for::<usize>() + 1;

        let result = report_from_message_values(
            TreeResidualConfig {
                seed: 0,
                trials: too_many_samples,
                seed_count: 1,
            },
            orders::accepted_honeycomb_order(),
            &[],
            &[],
        );

        assert_eq!(result.err(), Some(TreeResidualError::SampleCountTooLarge));
    }

    #[test]
    fn oversized_seed_count_returns_error_without_capacity_panic() {
        let too_many_seeds = max_vec_capacity_for::<u64>() + 1;

        let result = seed_batches(0, too_many_seeds);

        assert_eq!(result.err(), Some(TreeResidualError::SampleCountTooLarge));
    }

    #[test]
    fn planted_common_motif_positive_control_is_significant() {
        let keys = ["east1", "west1", "east2"];
        let messages = planted_motif_fixture();
        let report = report_from_message_values(
            TreeResidualConfig {
                seed: 0x5151,
                trials: 512,
                seed_count: 2,
            },
            orders::accepted_honeycomb_order(),
            &keys,
            &messages,
        )
        .unwrap();

        for row in report
            .rows
            .iter()
            .filter(|row| row.scope == TreeResidualScope::ResidualTails)
        {
            assert!(
                row.significant_excess,
                "planted motif should exceed its null for k={}: row={row:?}",
                row.k
            );
            assert!(
                row.observed.shared_distinct_ngrams >= 7usize.saturating_sub(row.k),
                "motif contribution disappeared for k={}: row={row:?}",
                row.k
            );
        }
    }

    #[test]
    fn independent_tail_negative_control_matches_shuffle_null() {
        let keys = ["north", "south", "east1", "west1", "east2"];
        let messages = independent_tail_fixture(0x1234, keys.len(), 72, 97);
        let report = report_from_message_values(
            TreeResidualConfig {
                seed: 0x6161,
                trials: 512,
                seed_count: 2,
            },
            orders::accepted_honeycomb_order(),
            &keys,
            &messages,
        )
        .unwrap();

        for row in report
            .rows
            .iter()
            .filter(|row| row.scope == TreeResidualScope::ResidualTails)
        {
            assert!(
                !row.significant_excess,
                "independent tails produced an unexpected excess for k={}: row={row:?}",
                row.k
            );
            assert!(
                row.two_sided_p > 0.01,
                "independent tails landed in an extreme two-sided tail for k={}: row={row:?}",
                row.k
            );
        }
    }

    #[test]
    fn eye_headline_counts_are_pinned() {
        let report = run_tree_residual(TreeResidualConfig {
            seed: 12_345,
            trials: 16,
            seed_count: 1,
        })
        .unwrap();

        assert_eq!(report.tail_total_length, 851);
        assert_row_observed(&report.rows, TreeResidualScope::ResidualTails, 3, 3, 2);
        assert_row_observed(&report.rows, TreeResidualScope::ResidualTails, 4, 0, 1);
        assert_row_observed(&report.rows, TreeResidualScope::FullMessages, 3, 56, 6);
        assert_row_observed(&report.rows, TreeResidualScope::FullMessages, 4, 49, 6);
    }

    #[test]
    #[ignore = "canonical 1000-trial x 5-seed tree-residual regression; run with cargo test -- --ignored"]
    fn eye_tree_residual_null_matches_headline_regression() {
        let report = run_tree_residual(TreeResidualConfig {
            seed: 12_345,
            trials: 1_000,
            seed_count: 5,
        })
        .unwrap();

        assert_eq!(report.tail_total_length, 851);
        assert_row_observed(&report.rows, TreeResidualScope::ResidualTails, 3, 3, 2);
        assert_row_observed(&report.rows, TreeResidualScope::ResidualTails, 4, 0, 1);
        assert_row_observed(&report.rows, TreeResidualScope::FullMessages, 3, 56, 6);
        assert_row_observed(&report.rows, TreeResidualScope::FullMessages, 4, 49, 6);
        let residual_k3 = find_row(&report.rows, TreeResidualScope::ResidualTails, 3);
        assert_eq!(residual_k3.null.samples, 5_000);
        assert_eq!(residual_k3.upper_tail_count, 92);
        assert_relative_close(
            residual_k3.upper_tail_p,
            0.018_596_280_743_851_23,
            "residual k=3 upper p",
        );
        assert!(residual_k3.significant_excess);

        let residual_k4 = find_row(&report.rows, TreeResidualScope::ResidualTails, 4);
        assert!(!residual_k4.significant_excess);

        let full_k3 = find_row(&report.rows, TreeResidualScope::FullMessages, 3);
        let full_k4 = find_row(&report.rows, TreeResidualScope::FullMessages, 4);
        assert_eq!(full_k3.upper_tail_count, 0);
        assert_eq!(full_k4.upper_tail_count, 0);
        assert!(full_k3.significant_excess);
        assert!(full_k4.significant_excess);
    }

    fn assert_row_observed(
        rows: &[super::TreeResidualRow],
        scope: TreeResidualScope,
        k: usize,
        expected_shared: usize,
        expected_max_messages: usize,
    ) {
        let row = find_row(rows, scope, k);
        assert_eq!(
            row.observed.shared_distinct_ngrams, expected_shared,
            "{scope:?} k={k} shared count changed"
        );
        assert_eq!(
            row.observed.max_messages_per_ngram, expected_max_messages,
            "{scope:?} k={k} max message count changed"
        );
    }

    fn find_row(
        rows: &[super::TreeResidualRow],
        scope: TreeResidualScope,
        k: usize,
    ) -> &super::TreeResidualRow {
        rows.iter()
            .find(|row| row.scope == scope && row.k == k)
            .unwrap()
    }

    fn planted_motif_fixture() -> Vec<Vec<TrigramValue>> {
        let trunk = values(&[118, 119, 120, 121]);
        let motif = [0, 1, 2, 3, 4, 5];
        let mut messages = Vec::new();
        for (start, position) in [(10, 4), (46, 15), (82, 26)] {
            let mut message = trunk.clone();
            let mut tail = sequential_tail(start, 36);
            plant_motif(&mut tail, position, &motif);
            message.extend(tail);
            messages.push(message);
        }
        messages
    }

    fn independent_tail_fixture(
        seed: u64,
        message_count: usize,
        len: usize,
        alphabet_size: u8,
    ) -> Vec<Vec<TrigramValue>> {
        let mut rng = SplitMix64::new(seed);
        let mut messages = Vec::new();
        for _message in 0..message_count {
            let mut values = Vec::new();
            for _position in 0..len {
                let raw = (rng.next_u64() % u64::from(alphabet_size)) as u8;
                values.push(value(raw));
            }
            messages.push(values);
        }
        messages
    }

    fn plant_motif(tail: &mut [TrigramValue], position: usize, motif: &[u8]) {
        for (offset, raw) in motif.iter().copied().enumerate() {
            let Some(slot) = tail.get_mut(position + offset) else {
                panic!("motif does not fit at position {position}");
            };
            *slot = value(raw);
        }
    }

    fn sequential_tail(start: u8, len: usize) -> Vec<TrigramValue> {
        (0..len)
            .map(|offset| value(start + u8::try_from(offset).unwrap()))
            .collect()
    }

    fn message(message_key: &'static str, segments: &[&[u8]]) -> MessageSegments {
        MessageSegments {
            message_key,
            segments: segments.iter().map(|segment| values(segment)).collect(),
        }
    }

    fn values(raw_values: &[u8]) -> Vec<TrigramValue> {
        raw_values.iter().copied().map(value).collect()
    }

    fn value(raw: u8) -> TrigramValue {
        TrigramValue::new(raw).unwrap()
    }
}

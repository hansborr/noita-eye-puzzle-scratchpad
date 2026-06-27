use std::collections::{BTreeMap, BTreeSet};
use std::mem::size_of;

use crate::analysis::orders::{self, ReadingOrder, read_corpus_message_values};
use crate::core::trigram::TrigramValue;
use crate::nulls::null::{
    NullSampler, RandomBoundError, SplitMix64, add_one_p_value, fisher_yates, usize_band,
};
use crate::nulls::perseus::{self, SharedPartition};

use super::{
    CrossTailNullBand, CrossTailStatistic, K_VALUES, MAX_VEC_ALLOCATION_BYTES, MessageTailSummary,
    SIGNIFICANCE_ALPHA, TREE_RESIDUAL_ROW_COUNT, TreeResidualConfig, TreeResidualError,
    TreeResidualReport, TreeResidualRow, TreeResidualScope,
};

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
        .map(crate::analysis::orders::GlyphGrid::message_key)
        .collect::<Vec<_>>();
    let order = orders::accepted_honeycomb_order();
    let message_values = read_corpus_message_values(&grids, order)?;
    report_from_message_values(config, order, &keys, &message_values)
}

pub(super) fn report_from_message_values(
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

    // Both samplers draw from the same per-seed RNG within a trial, residual
    // before full, exactly as the longhand loop did — so the segment-shape
    // sampler keeps that PRNG draw order intact.
    let residual_sampler = ResidualSegmentShuffle {
        messages: residual_messages,
    };
    let full_sampler = ResidualSegmentShuffle {
        messages: full_messages,
    };
    for seed in &seeds {
        let mut rng = SplitMix64::new(*seed);
        for _trial in 0..config.trials {
            let shuffled_residual = residual_sampler.sample(&mut rng)?;
            let shuffled_full = full_sampler.sample(&mut rng)?;
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

pub(super) fn max_vec_capacity_for<T>() -> usize {
    let element_size = size_of::<T>();
    if element_size == 0 {
        return usize::MAX;
    }
    MAX_VEC_ALLOCATION_BYTES / element_size
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct MessageSegments {
    pub(super) message_key: &'static str,
    pub(super) segments: Vec<Vec<TrigramValue>>,
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
        let null = CrossTailNullBand::from(usize_band(&self.samples));
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

pub(super) fn residual_segment_messages(
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

pub(super) fn cross_message_statistic(
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

/// Segment-shape-preserving within-message shuffle for residual tails.
///
/// Pools each message's residual symbols, Fisher-Yates shuffles the pool, then
/// repartitions it back into the original segment lengths — preserving residual
/// length, residual segment shape, and the exact residual multiset.
struct ResidualSegmentShuffle<'a> {
    messages: &'a [MessageSegments],
}

impl NullSampler for ResidualSegmentShuffle<'_> {
    type Draw = Vec<MessageSegments>;

    fn sample(&self, rng: &mut SplitMix64) -> Result<Self::Draw, RandomBoundError> {
        let mut shuffled = Vec::new();
        for message in self.messages {
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

pub(super) fn seed_batches(seed: u64, seed_count: usize) -> Result<Vec<u64>, TreeResidualError> {
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

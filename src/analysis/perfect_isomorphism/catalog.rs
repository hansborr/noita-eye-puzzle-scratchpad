//! Cross-message gap-pattern catalog: records, matched-null significance, and
//! conservative safe-isomorph extents, plus the shared gap-signature primitives.

use std::collections::{BTreeMap, BTreeSet};

use crate::analysis::isomorph::{IsomorphError, PatternSignature};
use crate::core::trigram::TrigramValue;
use crate::nulls::null::{SplitMix64, add_one_p_value, fisher_yates, mix_seed};

use super::breaks::{PairSlice, classify_break};
use super::{
    BreakLocalization, IsomorphCatalogEntry, IsomorphSignificance, MAIN_ISOMORPH_W9,
    MAIN_ISOMORPH_W11, NULL_TAG_BASE, PerfectIsomorphismConfig, PerfectIsomorphismError,
    SIGNIFICANCE_ALPHA, STRONG_MIN_OCCURRENCES, STRONG_MIN_REPEATS, SafeIsomorphExtent, SafeSpan,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Occurrence {
    pub(super) message_index: usize,
    pub(super) key: &'static str,
    pub(super) start: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CatalogRecord {
    pub(super) signature: PatternSignature,
    pub(super) rendered: String,
    pub(super) repeat_count: usize,
    pub(super) occurrences: Vec<Occurrence>,
    pub(super) window: usize,
}

impl CatalogRecord {
    pub(super) fn entry(&self) -> IsomorphCatalogEntry {
        IsomorphCatalogEntry {
            signature: self.rendered.clone(),
            repeat_count: self.repeat_count,
            occurrences: self
                .occurrences
                .iter()
                .map(|occurrence| (occurrence.key, occurrence.start))
                .collect(),
            window: self.window,
        }
    }
}

pub(super) fn build_catalog_records(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    windows: &[usize],
) -> Result<Vec<CatalogRecord>, PerfectIsomorphismError> {
    let mut records = Vec::new();
    for window in windows {
        let mut grouped: BTreeMap<PatternSignature, Vec<Occurrence>> = BTreeMap::new();
        for (message_index, (key, values)) in keys.iter().copied().zip(message_values).enumerate() {
            if *window > values.len() {
                return Err(IsomorphError::InvalidWindow {
                    window: *window,
                    sequence_len: values.len(),
                }
                .into());
            }
            for (start, symbols) in values.windows(*window).enumerate() {
                let signature = PatternSignature::from_window(symbols);
                if repeated_symbol_count(&signature) >= 2 {
                    grouped.entry(signature).or_default().push(Occurrence {
                        message_index,
                        key,
                        start,
                    });
                }
            }
        }
        records.extend(records_from_groups(*window, grouped));
    }
    records.sort_by(compare_catalog_records);
    Ok(records)
}

fn records_from_groups(
    window: usize,
    grouped: BTreeMap<PatternSignature, Vec<Occurrence>>,
) -> Vec<CatalogRecord> {
    let mut records = Vec::new();
    for (signature, mut occurrences) in grouped {
        occurrences.sort_unstable();
        if distinct_message_count(&occurrences) < STRONG_MIN_OCCURRENCES {
            continue;
        }
        let repeat_count = repeated_symbol_count(&signature);
        records.push(CatalogRecord {
            rendered: render_gap_signature(&signature),
            repeat_count,
            occurrences,
            signature,
            window,
        });
    }
    records
}

fn compare_catalog_records(left: &CatalogRecord, right: &CatalogRecord) -> std::cmp::Ordering {
    right
        .repeat_count
        .cmp(&left.repeat_count)
        .then_with(|| right.occurrences.len().cmp(&left.occurrences.len()))
        .then_with(|| left.window.cmp(&right.window))
        .then_with(|| left.rendered.cmp(&right.rendered))
}

pub(super) fn catalog_significance(
    config: PerfectIsomorphismConfig,
    message_values: &[Vec<TrigramValue>],
    records: &[CatalogRecord],
    windows: &[usize],
) -> Result<Vec<IsomorphSignificance>, PerfectIsomorphismError> {
    let mut samples = records
        .iter()
        .map(|_record| Vec::with_capacity(config.trials))
        .collect::<Vec<_>>();
    let mut empirical_counts = vec![0usize; records.len()];

    for trial in 0..config.trials {
        let mut rng = SplitMix64::new(mix_seed(
            config.seed,
            NULL_TAG_BASE ^ u64::try_from(trial).unwrap_or(u64::MAX),
        ));
        let shuffled = shuffled_messages(message_values, &mut rng)?;
        let shuffled_counts = signature_counts(&shuffled, windows);
        for ((sample, empirical_count), record) in samples
            .iter_mut()
            .zip(empirical_counts.iter_mut())
            .zip(records)
        {
            let count = shuffled_counts
                .get(&(record.window, record.signature.clone()))
                .copied()
                .unwrap_or_default();
            sample.push(count);
            if count >= record.occurrences.len() {
                *empirical_count += 1;
            }
        }
    }

    Ok(records
        .iter()
        .zip(samples)
        .zip(empirical_counts)
        .map(|((record, sample), empirical_p_count)| {
            let empirical_p = add_one_p_value(empirical_p_count, config.trials);
            let null_max_occurrences = sample.iter().copied().max().unwrap_or_default();
            IsomorphSignificance {
                signature: record.rendered.clone(),
                window: record.window,
                observed_occurrences: record.occurrences.len(),
                null_mean_occurrences: mean(&sample),
                null_max_occurrences,
                empirical_p_count,
                empirical_p,
                strong: record.repeat_count >= STRONG_MIN_REPEATS
                    && record.occurrences.len() >= STRONG_MIN_OCCURRENCES
                    && empirical_p <= SIGNIFICANCE_ALPHA,
            }
        })
        .collect())
}

fn signature_counts(
    message_values: &[Vec<TrigramValue>],
    windows: &[usize],
) -> BTreeMap<(usize, PatternSignature), usize> {
    let mut counts = BTreeMap::new();
    for window in windows {
        for values in message_values {
            for symbols in values.windows(*window) {
                let signature = PatternSignature::from_window(symbols);
                if repeated_symbol_count(&signature) >= 2 {
                    let entry = counts.entry((*window, signature)).or_insert(0usize);
                    *entry += 1;
                }
            }
        }
    }
    counts
}

pub(super) fn strong_repeat_catalog_records(records: &[CatalogRecord]) -> Vec<&CatalogRecord> {
    records
        .iter()
        .filter(|record| {
            record.repeat_count >= STRONG_MIN_REPEATS
                && record.occurrences.len() >= STRONG_MIN_OCCURRENCES
        })
        .collect()
}

pub(super) fn safe_extent_seed_records<'a>(
    records: &[&'a CatalogRecord],
) -> Vec<&'a CatalogRecord> {
    records
        .iter()
        .copied()
        .filter(|record| {
            (record.window == 9 && record.rendered == MAIN_ISOMORPH_W9)
                || (record.window == 11 && record.rendered == MAIN_ISOMORPH_W11)
        })
        .collect()
}

pub(super) fn localize_extents(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    records: &[&CatalogRecord],
    deduplicate: bool,
) -> (Vec<BreakLocalization>, Vec<SafeIsomorphExtent>) {
    let pairwise = collect_pairwise_extents(keys, message_values, records);
    let mut extents = Vec::new();
    let mut seen = BTreeSet::new();
    for row in pairwise {
        let key = extent_key(&row.extent);
        if !deduplicate || seen.insert(key) {
            extents.push(row.extent);
        }
    }
    extents.sort_by(compare_extents);
    let breaks = extents
        .iter()
        .filter_map(|extent| extent.bounding_break.clone())
        .collect::<Vec<_>>();
    (breaks, extents)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PairwiseExtent {
    left: Occurrence,
    right: Occurrence,
    extent: SafeIsomorphExtent,
}

fn collect_pairwise_extents(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    records: &[&CatalogRecord],
) -> Vec<PairwiseExtent> {
    let mut pairwise = Vec::new();
    for record in records {
        for (left_position, left) in record.occurrences.iter().enumerate() {
            for right in record.occurrences.iter().skip(left_position + 1) {
                if left.message_index == right.message_index {
                    continue;
                }
                let Some(left_values) = message_values.get(left.message_index) else {
                    continue;
                };
                let Some(right_values) = message_values.get(right.message_index) else {
                    continue;
                };
                let extent = extend_occurrence_pair(
                    keys,
                    left_values,
                    right_values,
                    *left,
                    *right,
                    record.window,
                );
                pairwise.push(PairwiseExtent {
                    left: *left,
                    right: *right,
                    extent,
                });
            }
        }
    }
    pairwise
}

pub(super) fn conservative_safe_extents(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    records: &[&CatalogRecord],
) -> Vec<SafeIsomorphExtent> {
    let mut pairwise = collect_pairwise_extents(keys, message_values, records);
    let end_by_occurrence = tightest_end_by_occurrence(&pairwise);
    for row in &mut pairwise {
        if let Some(end) = end_by_occurrence.get(&row.left).copied() {
            clamp_span_end(&mut row.extent.left_span, end);
        }
        if let Some(end) = end_by_occurrence.get(&row.right).copied() {
            clamp_span_end(&mut row.extent.right_span, end);
        }
    }
    let mut extents = pairwise
        .into_iter()
        .map(|row| row.extent)
        .collect::<Vec<_>>();
    extents.sort_by(compare_extents);
    extents
}

fn tightest_end_by_occurrence(pairwise: &[PairwiseExtent]) -> BTreeMap<Occurrence, usize> {
    let mut end_by_occurrence = BTreeMap::new();
    for row in pairwise {
        record_tightest_end(&mut end_by_occurrence, row.left, row.extent.left_span.end());
        record_tightest_end(
            &mut end_by_occurrence,
            row.right,
            row.extent.right_span.end(),
        );
    }
    end_by_occurrence
}

fn record_tightest_end(
    end_by_occurrence: &mut BTreeMap<Occurrence, usize>,
    occurrence: Occurrence,
    end: usize,
) {
    let _stored = end_by_occurrence
        .entry(occurrence)
        .and_modify(|stored| *stored = (*stored).min(end))
        .or_insert(end);
}

fn clamp_span_end(span: &mut SafeSpan, end: usize) {
    span.len = end.saturating_sub(span.start);
}

fn extent_key(
    extent: &SafeIsomorphExtent,
) -> (&'static str, &'static str, usize, usize, usize, usize) {
    (
        extent.pair.0,
        extent.pair.1,
        extent.left_span.start,
        extent.right_span.start,
        extent.left_span.len,
        extent.right_span.len,
    )
}

fn compare_extents(left: &SafeIsomorphExtent, right: &SafeIsomorphExtent) -> std::cmp::Ordering {
    left.pair
        .cmp(&right.pair)
        .then_with(|| left.left_span.start.cmp(&right.left_span.start))
        .then_with(|| left.right_span.start.cmp(&right.right_span.start))
        .then_with(|| left.left_span.len.cmp(&right.left_span.len))
}

fn extend_occurrence_pair(
    _keys: &[&'static str],
    left_values: &[TrigramValue],
    right_values: &[TrigramValue],
    left: Occurrence,
    right: Occurrence,
    window: usize,
) -> SafeIsomorphExtent {
    let mut left_start = left.start;
    let mut right_start = right.start;
    let mut len = window;
    while left_start > 0
        && right_start > 0
        && same_signature(
            left_values,
            left_start - 1,
            right_values,
            right_start - 1,
            len + 1,
        )
    {
        left_start -= 1;
        right_start -= 1;
        len += 1;
    }
    while same_signature(left_values, left_start, right_values, right_start, len + 1) {
        len += 1;
    }
    let bounding_break = if has_position(left_values, left_start + len)
        && has_position(right_values, right_start + len)
    {
        Some(classify_break(PairSlice {
            left_key: left.key,
            right_key: right.key,
            left_values,
            right_values,
            left_start,
            right_start,
            prefix_len: len,
        }))
    } else {
        None
    };
    SafeIsomorphExtent {
        pair: (left.key, right.key),
        left_span: SafeSpan {
            start: left_start,
            len,
        },
        right_span: SafeSpan {
            start: right_start,
            len,
        },
        bounding_break,
    }
}

pub(super) fn shuffled_messages(
    message_values: &[Vec<TrigramValue>],
    rng: &mut SplitMix64,
) -> Result<Vec<Vec<TrigramValue>>, PerfectIsomorphismError> {
    let mut shuffled = message_values.to_vec();
    for values in &mut shuffled {
        fisher_yates(values, rng)?;
    }
    Ok(shuffled)
}

pub(super) fn same_signature(
    left_values: &[TrigramValue],
    left_start: usize,
    right_values: &[TrigramValue],
    right_start: usize,
    len: usize,
) -> bool {
    let Some(left) = left_values.get(left_start..left_start.saturating_add(len)) else {
        return false;
    };
    let Some(right) = right_values.get(right_start..right_start.saturating_add(len)) else {
        return false;
    };
    PatternSignature::from_window(left) == PatternSignature::from_window(right)
}

fn has_position(values: &[TrigramValue], position: usize) -> bool {
    values.get(position).is_some()
}

fn repeated_symbol_count(signature: &PatternSignature) -> usize {
    let mut counts = BTreeMap::new();
    for value in signature.values() {
        let entry = counts.entry(*value).or_insert(0usize);
        *entry += 1;
    }
    counts.values().filter(|count| **count > 1).count()
}

pub(super) fn render_gap_signature(signature: &PatternSignature) -> String {
    let mut counts = BTreeMap::new();
    for value in signature.values() {
        let entry = counts.entry(*value).or_insert(0usize);
        *entry += 1;
    }
    let mut labels = BTreeMap::new();
    let mut next_label = 0usize;
    let mut rendered = String::new();
    for value in signature.values() {
        if counts.get(value).copied().unwrap_or_default() <= 1 {
            rendered.push('.');
        } else {
            let label_index = labels.entry(*value).or_insert_with(|| {
                let assigned = next_label;
                next_label += 1;
                assigned
            });
            rendered.push(label_for_index(*label_index));
        }
    }
    rendered
}

fn label_for_index(index: usize) -> char {
    let Ok(offset) = u8::try_from(index) else {
        return '?';
    };
    char::from(b'A'.saturating_add(offset))
}

fn distinct_message_count(occurrences: &[Occurrence]) -> usize {
    occurrences
        .iter()
        .map(|occurrence| occurrence.message_index)
        .collect::<BTreeSet<_>>()
        .len()
}

pub(super) fn mean(samples: &[usize]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    samples.iter().sum::<usize>() as f64 / samples.len() as f64
}

use std::collections::{BTreeMap, BTreeSet};

use super::{
    ALPHABET_SIZE, ConditionMetrics, MIN_SHARED_RUN_LEN, flatten_values, glyphs_from_values,
};
use crate::analysis::analysis;
use crate::analysis::isomorph::{self, PatternSignature};
use crate::core::trigram::TrigramValue;
use crate::nulls::isomorph_null::{DEFAULT_MAX_WINDOW, DEFAULT_MIN_WINDOW};

pub(super) fn condition_metrics(message_values: &[Vec<TrigramValue>]) -> ConditionMetrics {
    let flattened = flatten_values(message_values);
    let total_symbols = flattened.len();
    let pooled_ioc = analysis::index_of_coincidence(&glyphs_from_values(&flattened));
    let normalized_ioc = pooled_ioc * ALPHABET_SIZE as f64;
    let support = support_metrics(&flattened);
    let shared_runs = same_offset_shared_runs(message_values, MIN_SHARED_RUN_LEN);
    let shared_masks = shared_masks(message_values, &shared_runs);
    let isomorphs = isomorph_metrics(message_values);
    let non_shared_isomorphs = non_shared_isomorph_metrics(message_values, &shared_masks);

    ConditionMetrics {
        message_count: message_values.len(),
        total_symbols,
        pooled_ioc,
        normalized_ioc,
        distinct_in_alphabet: support.distinct_in_alphabet,
        outside_alphabet: support.outside_alphabet,
        min_value: support.min_value,
        max_value: support.max_value,
        shared_run_count: shared_runs.len(),
        longest_shared_run: shared_runs
            .iter()
            .map(|run| run.len)
            .max()
            .unwrap_or_default(),
        varying_prefix_shared_runs: shared_runs
            .iter()
            .filter(|run| run.preceding_values_differ)
            .count(),
        repeated_isomorph_groups: isomorphs.repeated_groups,
        longest_repeated_isomorph: isomorphs.longest_repeated_window,
        near_isomorph_pairs: near_isomorph_pair_count(message_values),
        differing_first_shared_second_cases: differing_first_shared_second_cases(message_values),
        adjacent_equal_count: adjacent_equal_count(message_values),
        non_shared_isomorph_groups: non_shared_isomorphs.repeated_groups,
        non_shared_exact_duplicate_groups: non_shared_isomorphs.exact_duplicate_groups,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SupportMetrics {
    distinct_in_alphabet: usize,
    outside_alphabet: usize,
    min_value: Option<u8>,
    max_value: Option<u8>,
}

fn support_metrics(values: &[TrigramValue]) -> SupportMetrics {
    let mut seen = [false; ALPHABET_SIZE];
    let mut outside_alphabet = 0usize;
    let mut min_value = None;
    let mut max_value = None;
    for value in values {
        let raw = value.get();
        min_value = Some(min_value.map_or(raw, |current: u8| current.min(raw)));
        max_value = Some(max_value.map_or(raw, |current: u8| current.max(raw)));
        let raw_usize = usize::from(raw);
        if let Some(slot) = seen.get_mut(raw_usize) {
            *slot = true;
        } else {
            outside_alphabet += 1;
        }
    }
    SupportMetrics {
        distinct_in_alphabet: seen.iter().filter(|present| **present).count(),
        outside_alphabet,
        min_value,
        max_value,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SharedRun {
    left_index: usize,
    right_index: usize,
    start: usize,
    len: usize,
    preceding_values_differ: bool,
}

fn same_offset_shared_runs(message_values: &[Vec<TrigramValue>], min_len: usize) -> Vec<SharedRun> {
    let mut runs = Vec::new();
    for (left_index, left_values) in message_values.iter().enumerate() {
        for (right_index, right_values) in message_values.iter().enumerate().skip(left_index + 1) {
            collect_shared_runs_for_pair(
                &mut runs,
                PairInput {
                    left_index,
                    right_index,
                    left_values,
                    right_values,
                    min_len,
                },
            );
        }
    }
    runs
}

#[derive(Clone, Copy)]
struct PairInput<'a> {
    left_index: usize,
    right_index: usize,
    left_values: &'a [TrigramValue],
    right_values: &'a [TrigramValue],
    min_len: usize,
}

fn collect_shared_runs_for_pair(runs: &mut Vec<SharedRun>, input: PairInput<'_>) {
    let mut active_start = None;
    let mut active_len = 0usize;
    for (position, (left, right)) in input.left_values.iter().zip(input.right_values).enumerate() {
        if left == right {
            if active_start.is_none() {
                active_start = Some(position);
            }
            active_len += 1;
        } else {
            push_shared_run(runs, input, active_start, active_len);
            active_start = None;
            active_len = 0;
        }
    }
    push_shared_run(runs, input, active_start, active_len);
}

fn push_shared_run(
    runs: &mut Vec<SharedRun>,
    input: PairInput<'_>,
    start: Option<usize>,
    len: usize,
) {
    let Some(start) = start else {
        return;
    };
    if len < input.min_len {
        return;
    }
    runs.push(SharedRun {
        left_index: input.left_index,
        right_index: input.right_index,
        start,
        len,
        preceding_values_differ: preceding_values_differ(
            input.left_values,
            input.right_values,
            start,
        ),
    });
}

fn preceding_values_differ(left: &[TrigramValue], right: &[TrigramValue], start: usize) -> bool {
    let Some(previous_position) = start.checked_sub(1) else {
        return false;
    };
    left.get(previous_position).copied() != right.get(previous_position).copied()
}

fn shared_masks(message_values: &[Vec<TrigramValue>], runs: &[SharedRun]) -> Vec<Vec<bool>> {
    let mut masks = message_values
        .iter()
        .map(|message| vec![false; message.len()])
        .collect::<Vec<_>>();
    for run in runs {
        mark_shared_run(&mut masks, run.left_index, run.start, run.len);
        mark_shared_run(&mut masks, run.right_index, run.start, run.len);
    }
    masks
}

fn mark_shared_run(masks: &mut [Vec<bool>], message_index: usize, start: usize, len: usize) {
    let Some(mask) = masks.get_mut(message_index) else {
        return;
    };
    for slot in mask.iter_mut().skip(start).take(len) {
        *slot = true;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IsomorphMetrics {
    repeated_groups: usize,
    longest_repeated_window: Option<usize>,
}

fn isomorph_metrics(message_values: &[Vec<TrigramValue>]) -> IsomorphMetrics {
    let mut repeated_groups = 0usize;
    let mut longest_repeated_window = None;
    for message in message_values {
        for window in DEFAULT_MIN_WINDOW..=DEFAULT_MAX_WINDOW {
            if window > message.len() {
                continue;
            }
            let Ok(detection) = isomorph::detect_isomorphs(message, window, 1, 1) else {
                continue;
            };
            let groups = detection.repeated_signature_kinds();
            if groups > 0 {
                repeated_groups += groups;
                longest_repeated_window = Some(window);
            }
        }
    }
    IsomorphMetrics {
        repeated_groups,
        longest_repeated_window,
    }
}

fn near_isomorph_pair_count(message_values: &[Vec<TrigramValue>]) -> usize {
    let mut count = 0usize;
    for message in message_values {
        for window in DEFAULT_MIN_WINDOW..=DEFAULT_MAX_WINDOW {
            if window > message.len() {
                continue;
            }
            let signatures = informative_signatures(message, window);
            count += near_pairs_in_signatures(&signatures);
        }
    }
    count
}

fn informative_signatures(message: &[TrigramValue], window: usize) -> Vec<Vec<usize>> {
    let mut signatures = BTreeSet::new();
    for values in message.windows(window) {
        let signature = PatternSignature::from_window(values);
        if signature.has_repeated_symbol() {
            let _inserted = signatures.insert(signature.values().to_vec());
        }
    }
    signatures.into_iter().collect()
}

fn near_pairs_in_signatures(signatures: &[Vec<usize>]) -> usize {
    let mut count = 0usize;
    for (left_index, left) in signatures.iter().enumerate() {
        for right in signatures.iter().skip(left_index + 1) {
            if hamming_distance_one(left, right) {
                count += 1;
            }
        }
    }
    count
}

fn hamming_distance_one(left: &[usize], right: &[usize]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut differences = 0usize;
    for (left_value, right_value) in left.iter().zip(right) {
        if left_value != right_value {
            differences += 1;
            if differences > 1 {
                return false;
            }
        }
    }
    differences == 1
}

fn differing_first_shared_second_cases(message_values: &[Vec<TrigramValue>]) -> usize {
    let mut cases = 0usize;
    for (left_index, left_values) in message_values.iter().enumerate() {
        for right_values in message_values.iter().skip(left_index + 1) {
            for (left_pair, right_pair) in left_values.windows(2).zip(right_values.windows(2)) {
                let Some(left_first) = left_pair.first() else {
                    continue;
                };
                let Some(right_first) = right_pair.first() else {
                    continue;
                };
                let Some(left_second) = left_pair.get(1) else {
                    continue;
                };
                let Some(right_second) = right_pair.get(1) else {
                    continue;
                };
                if left_first != right_first && left_second == right_second {
                    cases += 1;
                }
            }
        }
    }
    cases
}

fn adjacent_equal_count(message_values: &[Vec<TrigramValue>]) -> usize {
    message_values
        .iter()
        .map(|message| {
            message
                .windows(2)
                .filter(|pair| pair.first() == pair.get(1))
                .count()
        })
        .sum()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NonSharedIsomorphMetrics {
    repeated_groups: usize,
    exact_duplicate_groups: usize,
}

fn non_shared_isomorph_metrics(
    message_values: &[Vec<TrigramValue>],
    shared_masks: &[Vec<bool>],
) -> NonSharedIsomorphMetrics {
    let mut occurrence_counts: BTreeMap<(usize, Vec<usize>), usize> = BTreeMap::new();
    let mut value_sets: BTreeMap<(usize, Vec<usize>), BTreeSet<Vec<u8>>> = BTreeMap::new();

    for (message, mask) in message_values.iter().zip(shared_masks) {
        for window in DEFAULT_MIN_WINDOW..=DEFAULT_MAX_WINDOW {
            if window > message.len() {
                continue;
            }
            collect_non_shared_isomorph_windows(
                message,
                mask,
                window,
                &mut occurrence_counts,
                &mut value_sets,
            );
        }
    }

    let mut repeated_groups = 0usize;
    let mut exact_duplicate_groups = 0usize;
    for (key, occurrences) in occurrence_counts {
        if occurrences <= 1 {
            continue;
        }
        repeated_groups += 1;
        let unique_values = value_sets.get(&key).map_or(0, BTreeSet::len);
        if unique_values < occurrences {
            exact_duplicate_groups += 1;
        }
    }

    NonSharedIsomorphMetrics {
        repeated_groups,
        exact_duplicate_groups,
    }
}

fn collect_non_shared_isomorph_windows(
    message: &[TrigramValue],
    mask: &[bool],
    window: usize,
    occurrence_counts: &mut BTreeMap<(usize, Vec<usize>), usize>,
    value_sets: &mut BTreeMap<(usize, Vec<usize>), BTreeSet<Vec<u8>>>,
) {
    for (start, values) in message.windows(window).enumerate() {
        if !mask_window_is_clear(mask, start, window) {
            continue;
        }
        let signature = PatternSignature::from_window(values);
        if !signature.has_repeated_symbol() {
            continue;
        }
        let key = (window, signature.values().to_vec());
        let values = values.iter().map(|value| value.get()).collect::<Vec<_>>();
        *occurrence_counts.entry(key.clone()).or_default() += 1;
        let _inserted = value_sets.entry(key).or_default().insert(values);
    }
}

fn mask_window_is_clear(mask: &[bool], start: usize, window: usize) -> bool {
    mask.iter()
        .skip(start)
        .take(window)
        .filter(|is_shared| **is_shared)
        .count()
        == 0
}

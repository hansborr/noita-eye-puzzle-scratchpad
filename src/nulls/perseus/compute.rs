use std::collections::{BTreeMap, BTreeSet};

use crate::core::trigram::TrigramValue;
use crate::nulls::null::{UsizeBand, usize_band};

use super::{
    CounterpartRunSummary, GlobalSharedPrefix, MIN_SHARED_RUN_LEN, MessagePartitionSummary,
    MessageRecurrenceSummary, PerseusError, RecurrenceNullBand, RecurrenceStatistic,
    SharedPartition, SharedRunRole, SharedRunSummary, SharedSpan,
};

pub(crate) fn build_shared_partition(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
) -> Result<SharedPartition, PerseusError> {
    if keys.len() != message_values.len() {
        return Err(PerseusError::KeyCountMismatch {
            keys: keys.len(),
            messages: message_values.len(),
        });
    }

    let candidates = same_offset_common_runs(keys, message_values, MIN_SHARED_RUN_LEN);
    let leading_start = candidates.iter().map(|run| run.start).min();
    let selected = selected_runs(&candidates, leading_start);
    let mut masks = message_values
        .iter()
        .map(|values| vec![false; values.len()])
        .collect::<Vec<_>>();
    for run in &selected {
        apply_run(&mut masks, run.left_index, run.left_key, run.start, run.len)?;
        apply_run(
            &mut masks,
            run.right_index,
            run.right_key,
            run.start,
            run.len,
        )?;
    }

    Ok(SharedPartition {
        min_shared_run_len: MIN_SHARED_RUN_LEN,
        leading_start,
        global_prefix: global_shared_prefix(leading_start, message_values),
        selected_pair_runs: selected
            .iter()
            .map(|run| SharedRunSummary {
                left_key: run.left_key,
                right_key: run.right_key,
                start: run.start,
                len: run.len,
                role: run.role,
            })
            .collect(),
        counterpart_runs: counterpart_run_summaries(&selected),
        messages: message_partition_summaries(keys, message_values, &masks),
        masks,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CandidateRun {
    left_index: usize,
    right_index: usize,
    left_key: &'static str,
    right_key: &'static str,
    start: usize,
    len: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SelectedRun {
    left_index: usize,
    right_index: usize,
    left_key: &'static str,
    right_key: &'static str,
    start: usize,
    len: usize,
    role: SharedRunRole,
}

fn same_offset_common_runs(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    min_len: usize,
) -> Vec<CandidateRun> {
    let mut runs = Vec::new();
    for (left_index, (left_key, left_values)) in
        keys.iter().copied().zip(message_values).enumerate()
    {
        for (right_index, (right_key, right_values)) in keys
            .iter()
            .copied()
            .zip(message_values)
            .enumerate()
            .skip(left_index + 1)
        {
            collect_pair_runs(
                &mut runs,
                &PairRunInput {
                    left_index,
                    right_index,
                    left_key,
                    right_key,
                    left_values,
                    right_values,
                    min_len,
                },
            );
        }
    }
    runs
}

struct PairRunInput<'a> {
    left_index: usize,
    right_index: usize,
    left_key: &'static str,
    right_key: &'static str,
    left_values: &'a [TrigramValue],
    right_values: &'a [TrigramValue],
    min_len: usize,
}

fn collect_pair_runs(runs: &mut Vec<CandidateRun>, input: &PairRunInput<'_>) {
    let mut active_start = None;
    let mut active_len = 0usize;

    for (position, (left, right)) in input.left_values.iter().zip(input.right_values).enumerate() {
        if left == right {
            if active_start.is_none() {
                active_start = Some(position);
            }
            active_len += 1;
        } else {
            push_candidate_run(runs, input, active_start, active_len);
            active_start = None;
            active_len = 0;
        }
    }
    push_candidate_run(runs, input, active_start, active_len);
}

fn push_candidate_run(
    runs: &mut Vec<CandidateRun>,
    input: &PairRunInput<'_>,
    start: Option<usize>,
    len: usize,
) {
    if let Some(start) = start
        && len >= input.min_len
    {
        runs.push(CandidateRun {
            left_index: input.left_index,
            right_index: input.right_index,
            left_key: input.left_key,
            right_key: input.right_key,
            start,
            len,
        });
    }
}

fn selected_runs(candidates: &[CandidateRun], leading_start: Option<usize>) -> Vec<SelectedRun> {
    let mut selected = Vec::new();
    for candidate in candidates {
        let is_leading = leading_start.is_some_and(|start| candidate.start == start);
        let is_counterpart = is_counterpart_pair(candidate.left_key, candidate.right_key);
        let role = match (is_leading, is_counterpart) {
            (true, true) => Some(SharedRunRole::LeadingCounterpart),
            (true, false) => Some(SharedRunRole::LeadingFamily),
            (false, true) => Some(SharedRunRole::Counterpart),
            (false, false) => None,
        };
        if let Some(role) = role {
            selected.push(SelectedRun {
                left_index: candidate.left_index,
                right_index: candidate.right_index,
                left_key: candidate.left_key,
                right_key: candidate.right_key,
                start: candidate.start,
                len: candidate.len,
                role,
            });
        }
    }
    selected
}

fn is_counterpart_pair(left: &str, right: &str) -> bool {
    match (left.strip_prefix("east"), right.strip_prefix("west")) {
        (Some(left_index), Some(right_index)) => {
            !left_index.is_empty() && left_index == right_index
        }
        _ => match (left.strip_prefix("west"), right.strip_prefix("east")) {
            (Some(left_index), Some(right_index)) => {
                !left_index.is_empty() && left_index == right_index
            }
            _ => false,
        },
    }
}

fn apply_run(
    masks: &mut [Vec<bool>],
    message_index: usize,
    message_key: &'static str,
    start: usize,
    len: usize,
) -> Result<(), PerseusError> {
    let Some(mask) = masks.get_mut(message_index) else {
        return Err(PerseusError::SharedRunOutOfBounds {
            message_key,
            start,
            len,
        });
    };
    let mut marked = 0usize;
    for flag in mask.iter_mut().skip(start).take(len) {
        *flag = true;
        marked += 1;
    }
    if marked == len {
        Ok(())
    } else {
        Err(PerseusError::SharedRunOutOfBounds {
            message_key,
            start,
            len,
        })
    }
}

fn global_shared_prefix(
    leading_start: Option<usize>,
    message_values: &[Vec<TrigramValue>],
) -> Option<GlobalSharedPrefix> {
    let start = leading_start?;
    let mut values = Vec::new();
    let mut position = start;
    while let Some(value) = common_value_at(message_values, position) {
        values.push(value.get());
        position += 1;
    }
    if values.is_empty() {
        None
    } else {
        Some(GlobalSharedPrefix {
            start,
            len: values.len(),
            values,
        })
    }
}

fn common_value_at(message_values: &[Vec<TrigramValue>], position: usize) -> Option<TrigramValue> {
    let mut iter = message_values.iter();
    let first = iter.next()?.get(position).copied()?;
    if iter.all(|values| values.get(position).copied() == Some(first)) {
        Some(first)
    } else {
        None
    }
}

fn counterpart_run_summaries(selected: &[SelectedRun]) -> Vec<CounterpartRunSummary> {
    let mut best: BTreeMap<(&'static str, &'static str), (usize, usize)> = BTreeMap::new();
    for run in selected
        .iter()
        .filter(|run| run.role.includes_counterpart())
    {
        let Some((east_key, west_key)) = east_west_keys(run.left_key, run.right_key) else {
            continue;
        };
        let entry = best
            .entry((east_key, west_key))
            .or_insert((run.start, run.len));
        if run.len > entry.1 || (run.len == entry.1 && run.start < entry.0) {
            *entry = (run.start, run.len);
        }
    }
    best.into_iter()
        .map(
            |((east_key, west_key), (start, len))| CounterpartRunSummary {
                east_key,
                west_key,
                start,
                len,
            },
        )
        .collect()
}

fn east_west_keys(left: &'static str, right: &'static str) -> Option<(&'static str, &'static str)> {
    if left.strip_prefix("east").is_some() && right.strip_prefix("west").is_some() {
        return Some((left, right));
    }
    if left.strip_prefix("west").is_some() && right.strip_prefix("east").is_some() {
        return Some((right, left));
    }
    None
}

fn message_partition_summaries(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    masks: &[Vec<bool>],
) -> Vec<MessagePartitionSummary> {
    keys.iter()
        .copied()
        .zip(message_values)
        .zip(masks)
        .map(|((message_key, values), mask)| {
            let shared_symbols = mask.iter().filter(|is_shared| **is_shared).count();
            MessagePartitionSummary {
                message_key,
                len: values.len(),
                shared_symbols,
                non_shared_symbols: values.len().saturating_sub(shared_symbols),
                shared_spans: shared_spans(mask),
            }
        })
        .collect()
}

fn shared_spans(mask: &[bool]) -> Vec<SharedSpan> {
    let mut spans = Vec::new();
    let mut active_start = None;
    for (position, is_shared) in mask.iter().copied().enumerate() {
        match (active_start, is_shared) {
            (None, true) => active_start = Some(position),
            (Some(start), false) => {
                spans.push(SharedSpan {
                    start,
                    len: position.saturating_sub(start),
                });
                active_start = None;
            }
            _ => {}
        }
    }
    if let Some(start) = active_start {
        spans.push(SharedSpan {
            start,
            len: mask.len().saturating_sub(start),
        });
    }
    spans
}

pub(super) fn recurrence_statistic(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    partition: &SharedPartition,
) -> Result<RecurrenceStatistic, PerseusError> {
    if message_values.len() != partition.masks.len() {
        return Err(PerseusError::MessageMaskMismatch {
            messages: message_values.len(),
            masks: partition.masks.len(),
        });
    }

    let mut non_shared_occurrences = 0usize;
    let mut tested_shared_occurrences = 0usize;
    let mut recurrent_occurrences = 0usize;
    let mut recurrent_symbols = BTreeSet::new();
    let mut messages = Vec::new();

    for ((message_key, values), mask) in keys
        .iter()
        .copied()
        .zip(message_values)
        .zip(&partition.masks)
    {
        if values.len() != mask.len() {
            return Err(PerseusError::MessageMaskMismatch {
                messages: values.len(),
                masks: mask.len(),
            });
        }
        let row = message_recurrence_statistic(message_key, values, mask);
        non_shared_occurrences += row.non_shared_occurrences;
        tested_shared_occurrences += row.tested_shared_occurrences;
        recurrent_occurrences += row.recurrent_occurrences;
        recurrent_symbols.extend(row.recurrent_symbols.iter().copied());
        messages.push(row);
    }

    Ok(RecurrenceStatistic {
        non_shared_occurrences,
        tested_shared_occurrences,
        recurrent_occurrences,
        rate: rate(recurrent_occurrences, tested_shared_occurrences),
        recurrent_symbols: recurrent_symbols.into_iter().collect(),
        messages,
    })
}

fn message_recurrence_statistic(
    message_key: &'static str,
    values: &[TrigramValue],
    mask: &[bool],
) -> MessageRecurrenceSummary {
    let mut seen_non_shared = BTreeSet::new();
    let mut recurrent_symbols = BTreeSet::new();
    let mut non_shared_occurrences = 0usize;
    let mut tested_shared_occurrences = 0usize;
    let mut recurrent_occurrences = 0usize;

    for (value, is_shared) in values.iter().zip(mask) {
        let raw = value.get();
        if *is_shared {
            if !seen_non_shared.is_empty() {
                tested_shared_occurrences += 1;
                if seen_non_shared.contains(&raw) {
                    recurrent_occurrences += 1;
                    let _inserted = recurrent_symbols.insert(raw);
                }
            }
        } else {
            non_shared_occurrences += 1;
            let _inserted = seen_non_shared.insert(raw);
        }
    }

    MessageRecurrenceSummary {
        message_key,
        non_shared_occurrences,
        tested_shared_occurrences,
        recurrent_occurrences,
        rate: rate(recurrent_occurrences, tested_shared_occurrences),
        recurrent_symbols: recurrent_symbols.into_iter().collect(),
    }
}

pub(super) fn recurrence_null_band(samples: &[usize], denominator: usize) -> RecurrenceNullBand {
    let UsizeBand {
        trials,
        mean: count_mean,
        min: count_min,
        q025: count_q025,
        median: count_median,
        q975: count_q975,
        max: count_max,
    } = usize_band(samples);
    RecurrenceNullBand {
        trials,
        count_mean,
        count_min,
        count_q025,
        count_median,
        count_q975,
        count_max,
        rate_mean: rate_f64(count_mean, denominator),
        rate_q025: rate(count_q025, denominator),
        rate_median: rate_f64(count_median, denominator),
        rate_q975: rate(count_q975, denominator),
    }
}

fn rate(numerator: usize, denominator: usize) -> f64 {
    rate_f64(numerator as f64, denominator)
}

fn rate_f64(numerator: f64, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator / denominator as f64
    }
}

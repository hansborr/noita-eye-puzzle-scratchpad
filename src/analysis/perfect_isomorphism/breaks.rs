//! Maximal-extension break classification (mapping-independent) and the matched
//! within-message internal-violation null.

use std::collections::BTreeSet;

use crate::analysis::isomorph::PatternSignature;
use crate::core::trigram::TrigramValue;
use crate::nulls::null::{
    SplitMix64, add_one_p_value, median_usize, mix_seed, scaled_quantile_index,
};

use super::catalog::{
    build_catalog_records, localize_extents, mean, same_signature, shuffled_messages,
};
use super::{
    BenignDesyncRegion, BreakClass, BreakLocalization, InternalViolationNullBand, MAX_ISLAND_COLS,
    MIN_TWO_SIDED_FLANK, NULL_TAG_BASE, POST_MIN, PerfectIsomorphismConfig,
    PerfectIsomorphismError, STRONG_MIN_OCCURRENCES, STRONG_MIN_REPEATS,
};

#[derive(Clone, Copy)]
pub(super) struct PairSlice<'a> {
    pub(super) left_key: &'static str,
    pub(super) right_key: &'static str,
    pub(super) left_values: &'a [TrigramValue],
    pub(super) right_values: &'a [TrigramValue],
    pub(super) left_start: usize,
    pub(super) right_start: usize,
    pub(super) prefix_len: usize,
}

pub(super) fn classify_break(input: PairSlice<'_>) -> BreakLocalization {
    let profile = internal_profile(input);
    let mut class = BreakClass::Boundary;
    if profile.qualifies {
        class = benign_region(input).map_or(BreakClass::InternalCandidate, |region| {
            BreakClass::BenignDesync { region }
        });
    }
    BreakLocalization {
        pair: (input.left_key, input.right_key),
        anchor: (input.left_start, input.right_start),
        left_flank: input.prefix_len,
        right_flank: profile.far_run,
        break_index: input.prefix_len,
        island_cols: profile.island_cols,
        far_run: profile.far_run,
        class,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InternalProfile {
    qualifies: bool,
    island_cols: usize,
    far_run: usize,
}

fn internal_profile(input: PairSlice<'_>) -> InternalProfile {
    if input.prefix_len < MIN_TWO_SIDED_FLANK {
        return InternalProfile {
            qualifies: false,
            island_cols: 0,
            far_run: 0,
        };
    }

    let mut best = InternalProfile {
        qualifies: false,
        island_cols: 0,
        far_run: 0,
    };
    for island_cols in 1..=MAX_ISLAND_COLS {
        let far_run = far_run_after_island(input, island_cols);
        if far_run > best.far_run {
            best.island_cols = island_cols;
            best.far_run = far_run;
        }
        if far_run >= POST_MIN && has_cross_island_back_reference(input, island_cols, far_run) {
            return InternalProfile {
                qualifies: true,
                island_cols,
                far_run,
            };
        }
    }
    best
}

fn far_run_after_island(input: PairSlice<'_>, island_cols: usize) -> usize {
    let mut far_run = 0usize;
    let Some(left_after) = input.prefix_len.checked_add(island_cols) else {
        return far_run;
    };
    while same_signature(
        input.left_values,
        input.left_start + left_after,
        input.right_values,
        input.right_start + left_after,
        far_run + 1,
    ) {
        far_run += 1;
    }
    far_run
}

fn has_cross_island_back_reference(
    input: PairSlice<'_>,
    island_cols: usize,
    far_run: usize,
) -> bool {
    let total_len = input
        .prefix_len
        .saturating_add(island_cols)
        .saturating_add(far_run);
    let Some(left_window) = input
        .left_values
        .get(input.left_start..input.left_start.saturating_add(total_len))
    else {
        return false;
    };
    let Some(right_window) = input
        .right_values
        .get(input.right_start..input.right_start.saturating_add(total_len))
    else {
        return false;
    };
    let left_signature = PatternSignature::from_window(left_window);
    let right_signature = PatternSignature::from_window(right_window);
    let suffix_start = input.prefix_len.saturating_add(island_cols);
    for relative in suffix_start..total_len {
        if has_shared_pre_island_source(
            left_signature.values(),
            right_signature.values(),
            relative,
            input.prefix_len,
        ) {
            return true;
        }
    }
    false
}

fn has_shared_pre_island_source(
    left_values: &[usize],
    right_values: &[usize],
    relative: usize,
    prefix_len: usize,
) -> bool {
    let Some(left_target) = left_values.get(relative).copied() else {
        return false;
    };
    let Some(right_target) = right_values.get(relative).copied() else {
        return false;
    };
    left_values
        .iter()
        .zip(right_values)
        .take(prefix_len)
        .any(|(left_prior, right_prior)| *left_prior == left_target && *right_prior == right_target)
}

fn benign_region(input: PairSlice<'_>) -> Option<BenignDesyncRegion> {
    let left_break = input.left_start + input.prefix_len;
    let right_break = input.right_start + input.prefix_len;
    if is_pair(input.left_key, input.right_key, "east1", "west1")
        && range_overlap(left_break, right_break, 1, 30)
    {
        return Some(BenignDesyncRegion::FunnyLookingObstacle);
    }
    if is_pair(input.left_key, input.right_key, "west1", "east2")
        && range_overlap(left_break, right_break, 35, 95)
    {
        return Some(BenignDesyncRegion::Caboose);
    }
    if all_in_stutter_family(input.left_key, input.right_key)
        && range_overlap(left_break, right_break, 35, 80)
    {
        return Some(BenignDesyncRegion::StutterSection);
    }
    None
}

fn is_pair(left: &str, right: &str, a: &str, b: &str) -> bool {
    (left == a && right == b) || (left == b && right == a)
}

pub(super) fn all_in_stutter_family(left: &str, right: &str) -> bool {
    ["east4", "west4", "east5"].contains(&left) && ["east4", "west4", "east5"].contains(&right)
}

pub(super) fn range_overlap(left: usize, right: usize, start: usize, end: usize) -> bool {
    (start..=end).contains(&left) || (start..=end).contains(&right)
}

pub(super) fn internal_violation_null(
    config: PerfectIsomorphismConfig,
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    windows: &[usize],
    observed: usize,
) -> Result<(InternalViolationNullBand, usize, f64), PerfectIsomorphismError> {
    let mut samples = Vec::with_capacity(config.trials);
    let mut empirical_p_count = 0usize;
    for trial in 0..config.trials {
        let mut rng = SplitMix64::new(mix_seed(
            config.seed,
            NULL_TAG_BASE ^ 0x9e37_0000_0000_0000 ^ u64::try_from(trial).unwrap_or(u64::MAX),
        ));
        let shuffled = shuffled_messages(message_values, &mut rng)?;
        let count = internal_candidate_count_for_messages(keys, &shuffled, windows)?;
        if count >= observed {
            empirical_p_count += 1;
        }
        samples.push(count);
    }
    let mut sorted = samples.clone();
    sorted.sort_unstable();
    let band = InternalViolationNullBand {
        trials: config.trials,
        count_mean: mean(&samples),
        count_median: median_usize(&sorted),
        count_q975: quantile_from_sorted(&sorted, 975, 1_000),
        count_max: sorted.last().copied().unwrap_or_default(),
    };
    Ok((
        band,
        empirical_p_count,
        add_one_p_value(empirical_p_count, config.trials),
    ))
}

fn internal_candidate_count_for_messages(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    windows: &[usize],
) -> Result<usize, PerfectIsomorphismError> {
    let records = build_catalog_records(keys, message_values, windows)?;
    let strong = records
        .iter()
        .filter(|record| {
            record.repeat_count >= STRONG_MIN_REPEATS
                && record.occurrences.len() >= STRONG_MIN_OCCURRENCES
        })
        .collect::<Vec<_>>();
    let (breaks, _extents) = localize_extents(keys, message_values, &strong, true);
    Ok(count_internal_candidates(&breaks))
}

pub(super) fn count_internal_candidates(breaks: &[BreakLocalization]) -> usize {
    let mut events = BTreeSet::new();
    for break_row in breaks {
        if break_row.class == BreakClass::InternalCandidate {
            let _inserted = events.insert((
                break_row.pair,
                break_row.anchor.0 + break_row.break_index,
                break_row.anchor.1 + break_row.break_index,
            ));
        }
    }
    events.len()
}

fn quantile_from_sorted(sorted: &[usize], numerator: usize, denominator: usize) -> usize {
    sorted
        .get(scaled_quantile_index(sorted.len(), numerator, denominator))
        .copied()
        .unwrap_or_default()
}

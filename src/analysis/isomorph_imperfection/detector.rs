//! Break localization, classification, and matched-null core for the
//! isomorph-imperfection scan.
//!
//! Honesty-critical: the word-boundary discount and the loose-vs-robust
//! distinction live here and are preserved verbatim, including every caveat
//! comment. Moved unchanged from the leaf module.

use std::collections::{BTreeMap, BTreeSet};

use crate::analysis::isomorph::PatternSignature;
use crate::analysis::perfect_isomorphism::{
    MAX_ISLAND_COLS, MIN_TWO_SIDED_FLANK, POST_MIN, STRONG_MIN_OCCURRENCES, STRONG_MIN_REPEATS,
};
use crate::nulls::null::{
    RandomBoundError, SplitMix64, add_one_p_value, fisher_yates, mix_seed, usize_band,
};

use super::{
    EXTENDED_WINDOWS, IsomorphImperfectionConfig, IsomorphImperfectionError, LOOSE_NULL_TAG,
    LooseCandidate, NullOutcome, ScanCounts, StutterCandidate,
};

// ===========================================================================
// Break localization and classification (mapping-independent).
//
// These primitives mirror crate::analysis::perfect_isomorphism and reuse its public
// structural constants (MIN_TWO_SIDED_FLANK, MAX_ISLAND_COLS, POST_MIN,
// STRONG_MIN_REPEATS, STRONG_MIN_OCCURRENCES) so the two scans agree on the
// real eyes. They are re-derived here only to add the extended windows, the
// loose-candidate-class counting, and the explicit word-boundary discount
// without growing the size-capped canonical module.
// ===========================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BenignRegion {
    FunnyLookingObstacle,
    Caboose,
    StutterSection,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BreakKind {
    Boundary,
    InternalCandidate,
    Benign(BenignRegion),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct LocalizedBreak {
    left_index: usize,
    right_index: usize,
    anchor: (usize, usize),
    break_index: usize,
    island_cols: usize,
    far_run: usize,
    class: BreakKind,
}

impl LocalizedBreak {
    fn left_offset(&self) -> usize {
        self.anchor.0 + self.break_index
    }

    fn right_offset(&self) -> usize {
        self.anchor.1 + self.break_index
    }

    /// Net internalness after the word-boundary discount: a `Boundary`-class
    /// break is fully discounted to zero (it looks like a plaintext word/segment
    /// boundary); a qualifying internal break keeps its resync far-run length.
    fn internalness(&self) -> usize {
        match self.class {
            BreakKind::Boundary => 0,
            BreakKind::InternalCandidate | BreakKind::Benign(_) => self.far_run,
        }
    }

    fn is_loose_candidate(&self) -> bool {
        self.internalness() > 0
    }

    fn is_robust_violation(&self) -> bool {
        matches!(self.class, BreakKind::InternalCandidate) && self.internalness() > 0
    }
}

#[derive(Clone, Copy)]
struct Occurrence {
    message_index: usize,
    start: usize,
}

struct Record {
    window: usize,
    occurrences: Vec<Occurrence>,
}

pub(super) fn scan_counts(keys: &[&str], messages: &[Vec<u32>], windows: &[usize]) -> ScanCounts {
    counts_from_breaks(&scan_breaks(keys, messages, windows))
}

pub(super) fn counts_from_breaks(breaks: &[LocalizedBreak]) -> ScanCounts {
    ScanCounts {
        robust_internal_violations: breaks
            .iter()
            .filter(|break_row| break_row.is_robust_violation())
            .count(),
        loose_candidates: breaks
            .iter()
            .filter(|break_row| break_row.is_loose_candidate())
            .count(),
    }
}

pub(super) fn scan_breaks(
    keys: &[&str],
    messages: &[Vec<u32>],
    windows: &[usize],
) -> Vec<LocalizedBreak> {
    let records = strong_records(messages, windows);
    let mut breaks = Vec::new();
    let mut seen = BTreeSet::new();
    for record in &records {
        for (position, left) in record.occurrences.iter().enumerate() {
            for right in record.occurrences.iter().skip(position + 1) {
                if left.message_index == right.message_index {
                    continue;
                }
                let (Some(left_values), Some(right_values)) = (
                    messages.get(left.message_index),
                    messages.get(right.message_index),
                ) else {
                    continue;
                };
                if let Some(break_row) = localize_pair(
                    keys,
                    left_values,
                    right_values,
                    *left,
                    *right,
                    record.window,
                ) {
                    let key = (
                        break_row.left_index,
                        break_row.right_index,
                        break_row.left_offset(),
                        break_row.right_offset(),
                    );
                    if seen.insert(key) {
                        breaks.push(break_row);
                    }
                }
            }
        }
    }
    breaks
}

fn strong_records(messages: &[Vec<u32>], windows: &[usize]) -> Vec<Record> {
    let mut records = Vec::new();
    for window in windows {
        let mut grouped: BTreeMap<PatternSignature, Vec<Occurrence>> = BTreeMap::new();
        for (message_index, values) in messages.iter().enumerate() {
            if *window > values.len() {
                continue;
            }
            for (start, symbols) in values.windows(*window).enumerate() {
                let signature = PatternSignature::from_window(symbols);
                if repeated_symbol_count(&signature) >= 2 {
                    grouped.entry(signature).or_default().push(Occurrence {
                        message_index,
                        start,
                    });
                }
            }
        }
        for (signature, mut occurrences) in grouped {
            occurrences.sort_by(|left, right| {
                (left.message_index, left.start).cmp(&(right.message_index, right.start))
            });
            let distinct = occurrences
                .iter()
                .map(|occurrence| occurrence.message_index)
                .collect::<BTreeSet<_>>()
                .len();
            if distinct >= STRONG_MIN_OCCURRENCES
                && repeated_symbol_count(&signature) >= STRONG_MIN_REPEATS
            {
                records.push(Record {
                    window: *window,
                    occurrences,
                });
            }
        }
    }
    records
}

struct PairSlice<'a> {
    left_key: &'a str,
    right_key: &'a str,
    left: &'a [u32],
    right: &'a [u32],
    left_start: usize,
    right_start: usize,
    prefix_len: usize,
}

fn localize_pair(
    keys: &[&str],
    left: &[u32],
    right: &[u32],
    left_occurrence: Occurrence,
    right_occurrence: Occurrence,
    window: usize,
) -> Option<LocalizedBreak> {
    let mut left_start = left_occurrence.start;
    let mut right_start = right_occurrence.start;
    let mut len = window;
    while left_start > 0
        && right_start > 0
        && signature_eq(left, left_start - 1, right, right_start - 1, len + 1)
    {
        left_start -= 1;
        right_start -= 1;
        len += 1;
    }
    while signature_eq(left, left_start, right, right_start, len + 1) {
        len += 1;
    }
    if left.get(left_start + len).is_none() || right.get(right_start + len).is_none() {
        return None;
    }
    let left_key = keys
        .get(left_occurrence.message_index)
        .copied()
        .unwrap_or("");
    let right_key = keys
        .get(right_occurrence.message_index)
        .copied()
        .unwrap_or("");
    let input = PairSlice {
        left_key,
        right_key,
        left,
        right,
        left_start,
        right_start,
        prefix_len: len,
    };
    let (class, island_cols, far_run) = classify_break(&input);
    Some(LocalizedBreak {
        left_index: left_occurrence.message_index,
        right_index: right_occurrence.message_index,
        anchor: (left_start, right_start),
        break_index: len,
        island_cols,
        far_run,
        class,
    })
}

fn classify_break(input: &PairSlice<'_>) -> (BreakKind, usize, usize) {
    let profile = internal_profile(input);
    let class = if profile.qualifies {
        match benign_region(
            input.left_key,
            input.right_key,
            input.left_start + input.prefix_len,
            input.right_start + input.prefix_len,
        ) {
            Some(region) => BreakKind::Benign(region),
            None => BreakKind::InternalCandidate,
        }
    } else {
        BreakKind::Boundary
    };
    (class, profile.island_cols, profile.far_run)
}

#[derive(Clone, Copy)]
struct Profile {
    qualifies: bool,
    island_cols: usize,
    far_run: usize,
}

fn internal_profile(input: &PairSlice<'_>) -> Profile {
    if input.prefix_len < MIN_TWO_SIDED_FLANK {
        return Profile {
            qualifies: false,
            island_cols: 0,
            far_run: 0,
        };
    }
    let mut best = Profile {
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
            return Profile {
                qualifies: true,
                island_cols,
                far_run,
            };
        }
    }
    best
}

fn far_run_after_island(input: &PairSlice<'_>, island_cols: usize) -> usize {
    let mut far_run = 0usize;
    let left_after = input.prefix_len.saturating_add(island_cols);
    while signature_eq(
        input.left,
        input.left_start + left_after,
        input.right,
        input.right_start + left_after,
        far_run + 1,
    ) {
        far_run += 1;
    }
    far_run
}

fn has_cross_island_back_reference(
    input: &PairSlice<'_>,
    island_cols: usize,
    far_run: usize,
) -> bool {
    let total_len = input
        .prefix_len
        .saturating_add(island_cols)
        .saturating_add(far_run);
    let Some(left_window) = input
        .left
        .get(input.left_start..input.left_start.saturating_add(total_len))
    else {
        return false;
    };
    let Some(right_window) = input
        .right
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

fn benign_region(
    left_key: &str,
    right_key: &str,
    left_break: usize,
    right_break: usize,
) -> Option<BenignRegion> {
    if is_pair(left_key, right_key, "east1", "west1")
        && range_overlap(left_break, right_break, 1, 30)
    {
        return Some(BenignRegion::FunnyLookingObstacle);
    }
    if is_pair(left_key, right_key, "west1", "east2")
        && range_overlap(left_break, right_break, 35, 95)
    {
        return Some(BenignRegion::Caboose);
    }
    if all_in_stutter_family(left_key, right_key) && range_overlap(left_break, right_break, 35, 80)
    {
        return Some(BenignRegion::StutterSection);
    }
    None
}

fn is_pair(left: &str, right: &str, first: &str, second: &str) -> bool {
    (left == first && right == second) || (left == second && right == first)
}

fn all_in_stutter_family(left: &str, right: &str) -> bool {
    ["east4", "west4", "east5"].contains(&left) && ["east4", "west4", "east5"].contains(&right)
}

fn range_overlap(left: usize, right: usize, start: usize, end: usize) -> bool {
    (start..=end).contains(&left) || (start..=end).contains(&right)
}

fn signature_eq(
    left: &[u32],
    left_start: usize,
    right: &[u32],
    right_start: usize,
    len: usize,
) -> bool {
    let Some(left_window) = left.get(left_start..left_start.saturating_add(len)) else {
        return false;
    };
    let Some(right_window) = right.get(right_start..right_start.saturating_add(len)) else {
        return false;
    };
    PatternSignature::from_window(left_window) == PatternSignature::from_window(right_window)
}

fn repeated_symbol_count(signature: &PatternSignature) -> usize {
    let mut counts: BTreeMap<usize, usize> = BTreeMap::new();
    for value in signature.values() {
        *counts.entry(*value).or_insert(0) += 1;
    }
    counts.values().filter(|count| **count > 1).count()
}

// ===========================================================================
// Matched nulls and the east4/west4 chase.
// ===========================================================================

/// Computes the loose-candidate-class null and the robust-internal-violation
/// null from a single within-message shuffle pass (shared draws), so each
/// matched null costs one full-corpus scan per trial rather than two.
pub(super) fn matched_nulls(
    keys: &[&str],
    messages: &[Vec<u32>],
    observed: ScanCounts,
    config: IsomorphImperfectionConfig,
) -> Result<(NullOutcome, NullOutcome), IsomorphImperfectionError> {
    let mut loose_samples = Vec::with_capacity(config.null_trials);
    let mut robust_samples = Vec::with_capacity(config.null_trials);
    for trial in 0..config.null_trials {
        let mut rng = SplitMix64::new(mix_seed(
            config.seed,
            LOOSE_NULL_TAG ^ u64::try_from(trial).unwrap_or(u64::MAX),
        ));
        let shuffled = shuffle_messages(messages, &mut rng)?;
        let counts = scan_counts(keys, &shuffled, &EXTENDED_WINDOWS);
        loose_samples.push(counts.loose_candidates);
        robust_samples.push(counts.robust_internal_violations);
    }
    let loose = null_outcome(
        observed.loose_candidates,
        &loose_samples,
        config.null_trials,
    );
    let robust = null_outcome(
        observed.robust_internal_violations,
        &robust_samples,
        config.null_trials,
    );
    Ok((loose, robust))
}

fn shuffle_messages(
    messages: &[Vec<u32>],
    rng: &mut SplitMix64,
) -> Result<Vec<Vec<u32>>, RandomBoundError> {
    let mut shuffled = messages.to_vec();
    for message in &mut shuffled {
        fisher_yates(message, rng)?;
    }
    Ok(shuffled)
}

fn null_outcome(observed: usize, samples: &[usize], trials: usize) -> NullOutcome {
    let upper_tail_count = samples.iter().filter(|count| **count >= observed).count();
    NullOutcome {
        observed,
        band: usize_band(samples),
        upper_tail_count,
        p: add_one_p_value(upper_tail_count, trials),
    }
}

pub(super) fn collect_loose_candidates(
    keys: &[&'static str],
    breaks: &[LocalizedBreak],
) -> Vec<LooseCandidate> {
    breaks
        .iter()
        .filter(|break_row| break_row.is_loose_candidate())
        .map(|break_row| LooseCandidate {
            left_key: keys.get(break_row.left_index).copied().unwrap_or(""),
            right_key: keys.get(break_row.right_index).copied().unwrap_or(""),
            left_offset: break_row.left_offset(),
            right_offset: break_row.right_offset(),
            island_cols: break_row.island_cols,
            far_run: break_row.far_run,
            internalness: break_row.internalness(),
            benign_region: match break_row.class {
                BreakKind::Benign(region) => Some(benign_region_name(region)),
                BreakKind::Boundary | BreakKind::InternalCandidate => None,
            },
            promoted_to_violation: break_row.is_robust_violation(),
        })
        .collect()
}

fn benign_region_name(region: BenignRegion) -> &'static str {
    match region {
        BenignRegion::FunnyLookingObstacle => "FunnyObstacle",
        BenignRegion::Caboose => "Caboose",
        BenignRegion::StutterSection => "Stutter",
    }
}

pub(super) fn locate_stutter_candidate(
    keys: &[&str],
    breaks: &[LocalizedBreak],
) -> Option<StutterCandidate> {
    breaks
        .iter()
        .filter(|break_row| break_row.is_loose_candidate())
        .find(|break_row| {
            let left = keys.get(break_row.left_index).copied().unwrap_or("");
            let right = keys.get(break_row.right_index).copied().unwrap_or("");
            is_pair(left, right, "east4", "west4")
        })
        .map(|break_row| StutterCandidate {
            left_offset: break_row.left_offset(),
            right_offset: break_row.right_offset(),
            island_cols: break_row.island_cols,
            far_run: break_row.far_run,
            internalness: break_row.internalness(),
            benign_stutter: matches!(
                break_row.class,
                BreakKind::Benign(BenignRegion::StutterSection)
            ),
            promoted_to_violation: break_row.is_robust_violation(),
        })
}

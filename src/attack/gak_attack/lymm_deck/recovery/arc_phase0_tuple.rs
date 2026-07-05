//! Tuple-kill estimate for minimized Phase-0 arc reasons.

use std::collections::{BTreeMap, BTreeSet};

use super::AlignedMessage;
use super::arc_phase0::broad_replay_rejects_arc_clause;
use super::arc_phase0_types::{
    GakSwapArcTupleKillEstimate, InternalMinimizedReason, PROJECTION_LETTERS,
};
use super::propagation::{bit, bit_positions};
use super::residual::ResidualDomains;
use crate::attack::gak_attack::lymm_deck::LymmDeckSpec;

pub(super) fn estimate_tuple_kill(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    residual: &ResidualDomains,
    target_domains: &BTreeMap<char, Vec<usize>>,
    targets: &BTreeMap<char, usize>,
    reason: &InternalMinimizedReason,
    spot_check_samples: usize,
) -> GakSwapArcTupleKillEstimate {
    let projected_t = targets.get(&'T').copied();
    let projected_total_for_t = projected_t.map_or(0, |target_t| {
        count_projected_total_for_t(target_domains, target_t)
    });
    let masks = projected_masks_for_reason(residual, target_domains, reason);
    let estimated_killed_tuples =
        projected_t.map_or(0, |target_t| count_projected_with_masks(&masks, target_t));
    let (spot_checked_samples, spot_checked_rejections) = projected_t.map_or((0, 0), |target_t| {
        spot_check_tuple_estimate(
            spec,
            messages,
            residual,
            &masks,
            target_t,
            reason,
            spot_check_samples,
        )
    });
    GakSwapArcTupleKillEstimate {
        projected_t,
        projected_total_for_t,
        estimated_killed_tuples,
        spot_checked_samples,
        spot_checked_rejections,
        construction: "estimate: per-letter target masks induced by letter-local arc/context literals; sampled tuples replay deterministic propagation",
    }
}

fn projected_masks_for_reason(
    residual: &ResidualDomains,
    target_domains: &BTreeMap<char, Vec<usize>>,
    reason: &InternalMinimizedReason,
) -> BTreeMap<char, u128> {
    PROJECTION_LETTERS
        .into_iter()
        .map(|letter| {
            let targets =
                target_values_compatible_with_reason(residual, target_domains, reason, letter);
            let mask = targets
                .into_iter()
                .fold(0u128, |acc, target| acc | bit(target));
            (letter, mask)
        })
        .collect()
}

fn target_values_compatible_with_reason(
    residual: &ResidualDomains,
    target_domains: &BTreeMap<char, Vec<usize>>,
    reason: &InternalMinimizedReason,
    letter: char,
) -> Vec<usize> {
    let context_targets = reason
        .context_targets
        .iter()
        .filter_map(|&(context_letter, target)| (context_letter == letter).then_some(target))
        .collect::<BTreeSet<_>>();
    if context_targets.len() > 1 {
        return Vec::new();
    }
    let letter_arcs = reason
        .arcs
        .iter()
        .copied()
        .filter(|literal| literal.letter == letter)
        .collect::<Vec<_>>();
    if context_targets.is_empty() && letter_arcs.is_empty() {
        return target_domains.get(&letter).cloned().unwrap_or_default();
    }
    let allowed_targets = target_domains
        .get(&letter)
        .into_iter()
        .flat_map(|values| values.iter().copied())
        .collect::<BTreeSet<_>>();
    let mut compatible = residual
        .by_letter
        .get(&letter)
        .into_iter()
        .flat_map(|domain| domain.iter().copied())
        .filter_map(|candidate_index| {
            let candidate = residual.candidates.get(candidate_index)?;
            let top = residual.domains.candidates.get(candidate_index)?.top_image;
            if !allowed_targets.contains(&top) {
                return None;
            }
            if !context_targets.is_empty() && !context_targets.contains(&top) {
                return None;
            }
            letter_arcs
                .iter()
                .all(|literal| {
                    candidate
                        .perm
                        .get(literal.post_position)
                        .is_some_and(|&pre| pre == literal.pre_position)
                })
                .then_some(top)
        })
        .collect::<Vec<_>>();
    compatible.sort_unstable();
    compatible.dedup();
    compatible
}

fn count_projected_total_for_t(domains: &BTreeMap<char, Vec<usize>>, target_t: usize) -> usize {
    let masks = PROJECTION_LETTERS
        .into_iter()
        .map(|letter| {
            let mask = domains
                .get(&letter)
                .into_iter()
                .flat_map(|values| values.iter().copied())
                .fold(0u128, |acc, target| acc | bit(target));
            (letter, mask)
        })
        .collect::<BTreeMap<_, _>>();
    count_projected_with_masks(&masks, target_t)
}

fn count_projected_with_masks(masks: &BTreeMap<char, u128>, target_t: usize) -> usize {
    if target_t == 0 || masks.get(&'T').copied().unwrap_or(0) & bit(target_t) == 0 {
        return 0;
    }
    let e_values = projected_values(masks, 'E', target_t, &[]);
    let h_mask = masks.get(&'H').copied().unwrap_or(0);
    let s_mask = masks.get(&'S').copied().unwrap_or(0);
    let mut total = 0usize;
    for e in e_values {
        for h in bit_positions(h_mask) {
            if h == 0 || h == target_t || h == e {
                continue;
            }
            for s in bit_positions(s_mask) {
                if s == 0 || s == target_t || s == e || s == h {
                    continue;
                }
                let forbidden = [target_t, e, h, s];
                total = total.saturating_add(projected_values(masks, 'Y', 0, &forbidden).len());
            }
        }
    }
    total
}

fn projected_values(
    masks: &BTreeMap<char, u128>,
    letter: char,
    fixed_t: usize,
    forbidden: &[usize],
) -> Vec<usize> {
    bit_positions(masks.get(&letter).copied().unwrap_or(0))
        .filter(|&value| value != 0)
        .filter(|&value| fixed_t == 0 || value != fixed_t)
        .filter(|value| !forbidden.contains(value))
        .collect()
}

fn spot_check_tuple_estimate(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    residual: &ResidualDomains,
    masks: &BTreeMap<char, u128>,
    target_t: usize,
    reason: &InternalMinimizedReason,
    sample_cap: usize,
) -> (usize, usize) {
    if sample_cap == 0 {
        return (0, 0);
    }
    let mut checked = 0usize;
    let mut rejected = 0usize;
    'outer: for tuple in sample_projected_tuples(masks, target_t) {
        let mut targets = reason.context_targets.clone();
        targets.extend(PROJECTION_LETTERS.into_iter().zip(tuple));
        targets.sort_unstable();
        targets.dedup();
        if broad_replay_rejects_arc_clause(spec, messages, residual, &reason.arcs, &targets)
            .unwrap_or(false)
        {
            rejected = rejected.saturating_add(1);
        }
        checked = checked.saturating_add(1);
        if checked >= sample_cap {
            break 'outer;
        }
    }
    (checked, rejected)
}

fn sample_projected_tuples(
    masks: &BTreeMap<char, u128>,
    target_t: usize,
) -> impl Iterator<Item = [usize; PROJECTION_LETTERS.len()]> {
    let e_values = projected_values(masks, 'E', target_t, &[]);
    let h_values = projected_values(masks, 'H', target_t, &[]);
    let s_values = projected_values(masks, 'S', target_t, &[]);
    let y_values = projected_values(masks, 'Y', target_t, &[]);
    e_values.into_iter().flat_map(move |e| {
        let h_values = h_values.clone();
        let s_values = s_values.clone();
        let y_values = y_values.clone();
        h_values.into_iter().flat_map(move |h| {
            let s_values = s_values.clone();
            let y_values = y_values.clone();
            s_values.clone().into_iter().flat_map(move |s| {
                let y_values = y_values.clone();
                y_values.into_iter().filter_map(move |y| {
                    distinct_nonzero([e, h, s, target_t, y]).then_some([e, h, s, target_t, y])
                })
            })
        })
    })
}

fn distinct_nonzero(values: [usize; PROJECTION_LETTERS.len()]) -> bool {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .all(|value| value != 0 && seen.insert(value))
}

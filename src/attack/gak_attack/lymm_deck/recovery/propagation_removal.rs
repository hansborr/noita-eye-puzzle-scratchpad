//! Shared candidate-domain removal bookkeeping for propagation passes.

use std::collections::BTreeMap;

use super::propagation::{bit, trace_conflict};
use super::residual::ResidualDomains;
use super::target_reason::{ArcReason, TargetReasonTracker};
use super::{SwapRecoveryError, SwapRecoveryStats};

pub(super) fn removal_map(residual: &ResidualDomains, value: bool) -> BTreeMap<char, Vec<bool>> {
    residual
        .by_letter
        .iter()
        .map(|(&letter, domain)| (letter, vec![value; domain.len()]))
        .collect()
}

pub(super) fn removal_reason_map(residual: &ResidualDomains) -> BTreeMap<char, Vec<u128>> {
    residual
        .by_letter
        .iter()
        .map(|(&letter, domain)| (letter, vec![0; domain.len()]))
        .collect()
}

pub(super) fn removal_arc_reason_map(residual: &ResidualDomains) -> BTreeMap<char, Vec<ArcReason>> {
    residual
        .by_letter
        .iter()
        .map(|(&letter, domain)| (letter, vec![ArcReason::default(); domain.len()]))
        .collect()
}

pub(super) fn build_target_masks(residual: &ResidualDomains) -> BTreeMap<char, u128> {
    residual
        .by_letter
        .iter()
        .map(|(&letter, domain)| {
            let mask = domain.iter().fold(0u128, |acc, &candidate_index| {
                residual
                    .domains
                    .candidates
                    .get(candidate_index)
                    .map_or(acc, |candidate| acc | bit(candidate.top_image))
            });
            (letter, mask)
        })
        .collect()
}

fn mark_removed(remove: &mut BTreeMap<char, Vec<bool>>, letter: char, indexes: &[usize]) {
    let Some(letter_remove) = remove.get_mut(&letter) else {
        return;
    };
    for &index in indexes {
        if let Some(slot) = letter_remove.get_mut(index) {
            *slot = true;
        }
    }
}

pub(super) fn mark_removed_with_reason(
    remove: &mut BTreeMap<char, Vec<bool>>,
    remove_reasons: Option<&mut BTreeMap<char, Vec<u128>>>,
    letter: char,
    indexes: &[usize],
    reason: u128,
) {
    mark_removed(remove, letter, indexes);
    let Some(reason_map) = remove_reasons else {
        return;
    };
    let Some(letter_reasons) = reason_map.get_mut(&letter) else {
        return;
    };
    for &index in indexes {
        if let Some(slot) = letter_reasons.get_mut(index) {
            *slot |= reason;
        }
    }
}

pub(super) fn mark_removed_with_arc_reason(
    remove_reasons: Option<&mut BTreeMap<char, Vec<ArcReason>>>,
    letter: char,
    indexes: &[usize],
    reason: &ArcReason,
) {
    let Some(reason_map) = remove_reasons else {
        return;
    };
    let Some(letter_reasons) = reason_map.get_mut(&letter) else {
        return;
    };
    for &index in indexes {
        if let Some(slot) = letter_reasons.get_mut(index) {
            slot.union_with(reason);
        }
    }
}

pub(super) fn apply_removals(
    residual: &mut ResidualDomains,
    stats: &mut SwapRecoveryStats,
    remove: BTreeMap<char, Vec<bool>>,
    remove_reasons: Option<&BTreeMap<char, Vec<u128>>>,
    arc_remove_reasons: Option<&BTreeMap<char, Vec<ArcReason>>>,
    mut reason: Option<&mut TargetReasonTracker>,
) -> Result<bool, SwapRecoveryError> {
    let mut changed = false;
    for (letter, removed) in remove {
        if !removed.iter().any(|&drop| drop) {
            continue;
        }
        let removed_reason_values = remove_reasons
            .as_ref()
            .and_then(|reasons| reasons.get(&letter))
            .into_iter()
            .flat_map(|reasons| {
                reasons
                    .iter()
                    .zip(&removed)
                    .filter_map(|(&reason, &drop)| drop.then_some(reason))
            })
            .collect::<Vec<_>>();
        let removal_reason = removed_reason_values
            .iter()
            .copied()
            .fold(0, |acc, reason| acc | reason);
        let shared_removal_reason = removed_reason_values
            .iter()
            .copied()
            .reduce(|acc, reason| acc & reason)
            .unwrap_or(0);
        let arc_removal_reason = arc_remove_reasons
            .as_ref()
            .and_then(|reasons| reasons.get(&letter))
            .into_iter()
            .flat_map(|reasons| {
                reasons
                    .iter()
                    .zip(&removed)
                    .filter_map(|(reason, &drop)| drop.then_some(reason))
            })
            .fold(ArcReason::default(), |mut acc, reason| {
                acc.union_with(reason);
                acc
            });
        let before = residual
            .by_letter
            .get(&letter)
            .map_or(0usize, std::vec::Vec::len);
        let filtered = residual
            .by_letter
            .get(&letter)
            .into_iter()
            .flat_map(|domain| domain.iter().copied().enumerate())
            .filter_map(|(index, candidate)| {
                (!removed.get(index).copied().unwrap_or(true)).then_some(candidate)
            })
            .collect::<Vec<_>>();
        if filtered.is_empty() {
            trace_conflict(&format!("removal pass emptied letter {letter}"));
            if let Some(tracker) = reason.as_deref_mut() {
                let conflict_reason = if shared_removal_reason == 0 {
                    removal_reason
                } else {
                    shared_removal_reason
                };
                if std::env::var_os("NOITA_SWAP_CEGAR_TRACE").is_some() {
                    eprintln!(
                        "cegar: removal conflict letter={letter} reason={:?} shared={:?}",
                        tracker.choices_for(removal_reason),
                        tracker.choices_for(shared_removal_reason)
                    );
                }
                tracker.record_letter_conflict_with_arc_reason(
                    letter,
                    conflict_reason,
                    &arc_removal_reason,
                );
            }
            return Err(SwapRecoveryError::NoResidualCandidate);
        }
        if filtered.len() != before {
            stats.domains_pruned += before.saturating_sub(filtered.len());
            if let Some(tracker) = reason.as_deref_mut() {
                tracker.add_domain_reason(letter, removal_reason);
                tracker.add_domain_arc_reason(letter, &arc_removal_reason);
            }
            let _old = residual.by_letter.insert(letter, filtered);
            changed = true;
        }
    }
    Ok(changed)
}

//! Target-domain pruning rules used by partial-state propagation.

use super::propagation::bit;
use super::propagation_pruning::{
    apply_removals, build_target_masks, mark_removed_with_reason, removal_map, removal_reason_map,
};
use super::residual::ResidualDomains;
use super::target_reason::TargetReasonTracker;
use super::{AlignedMessage, SwapRecoveryError, SwapRecoveryStats};

pub(super) fn prune_target_read_domains(
    messages: &[AlignedMessage],
    state_domains: &[Vec<Vec<u128>>],
    residual: &mut ResidualDomains,
    stats: &mut SwapRecoveryStats,
    full: u128,
    mut reason: Option<&mut TargetReasonTracker>,
) -> Result<bool, SwapRecoveryError> {
    let mut allowed = residual
        .letters
        .iter()
        .copied()
        .map(|letter| (letter, full))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut allowed_reasons = residual
        .letters
        .iter()
        .copied()
        .map(|letter| (letter, 0))
        .collect::<std::collections::BTreeMap<_, _>>();
    for (message_index, message) in messages.iter().enumerate() {
        let Some(message_states) = state_domains.get(message_index) else {
            continue;
        };
        for (event_index, event) in message.events.iter().enumerate() {
            let target_mask = message_states
                .get(event_index)
                .and_then(|state| state.get(event.ct_value))
                .copied()
                .unwrap_or(full);
            let Some(slot) = allowed.get_mut(&event.letter) else {
                continue;
            };
            let mask_reason = reason.as_deref().map_or(0, |tracker| {
                tracker.state_reason(message_index, event_index, event.ct_value)
            });
            *slot &= target_mask;
            if let Some(reason_slot) = allowed_reasons.get_mut(&event.letter) {
                *reason_slot |= mask_reason;
            }
            if *slot == 0 {
                super::propagation::trace_conflict(&format!(
                    "target read emptied allowed targets for {}",
                    event.letter
                ));
                if let Some(tracker) = reason.as_deref_mut() {
                    tracker.record_letter_conflict(
                        event.letter,
                        allowed_reasons.get(&event.letter).copied().unwrap_or(0)
                            | tracker.domain_reason(event.letter),
                    );
                }
                return Err(SwapRecoveryError::NoResidualCandidate);
            }
        }
    }

    let mut remove = removal_map(residual, false);
    let mut remove_reasons = reason.as_ref().map(|_| removal_reason_map(residual));
    for (&letter, domain) in &residual.by_letter {
        let allowed_targets = allowed.get(&letter).copied().unwrap_or(full);
        if allowed_targets == full {
            continue;
        }
        let removal_reason = allowed_reasons.get(&letter).copied().unwrap_or(0);
        let drops = domain
            .iter()
            .enumerate()
            .filter_map(|(domain_index, &candidate_index)| {
                let top = residual
                    .domains
                    .candidates
                    .get(candidate_index)
                    .map(|candidate| candidate.top_image)?;
                (allowed_targets & bit(top) == 0).then_some(domain_index)
            })
            .collect::<Vec<_>>();
        mark_removed_with_reason(
            &mut remove,
            remove_reasons.as_mut(),
            letter,
            &drops,
            removal_reason,
        );
    }
    apply_removals(residual, stats, remove, remove_reasons.as_ref(), reason)
}

pub(super) fn prune_distinct_target_domains(
    residual: &mut ResidualDomains,
    stats: &mut SwapRecoveryStats,
    reason: Option<&mut TargetReasonTracker>,
) -> Result<bool, SwapRecoveryError> {
    let target_masks = build_target_masks(residual);
    let mut remove = removal_map(residual, false);
    let mut remove_reasons = reason.as_ref().map(|_| removal_reason_map(residual));
    for (&letter, domain) in &residual.by_letter {
        let forbidden_reasons = target_masks
            .iter()
            .filter(|&(&other, &mask)| other != letter && mask.is_power_of_two())
            .map(|(&other, &mask)| {
                let reason = reason
                    .as_deref()
                    .map_or(0, |tracker| tracker.domain_reason(other));
                (mask, reason)
            })
            .collect::<Vec<_>>();
        let forbidden = target_masks
            .iter()
            .filter_map(|(&other, &mask)| {
                (other != letter && mask.is_power_of_two()).then_some(mask)
            })
            .fold(bit(0), |acc, mask| acc | mask);
        if forbidden == 0 {
            continue;
        }
        let drops = domain
            .iter()
            .enumerate()
            .filter_map(|(domain_index, &candidate_index)| {
                let top = residual
                    .domains
                    .candidates
                    .get(candidate_index)
                    .map(|candidate| candidate.top_image)?;
                (forbidden & bit(top) != 0).then_some(domain_index)
            })
            .collect::<Vec<_>>();
        for &drop in &drops {
            let top_reason = domain
                .get(drop)
                .and_then(|&candidate_index| residual.domains.candidates.get(candidate_index))
                .map_or(0, |candidate| {
                    forbidden_reasons
                        .iter()
                        .filter_map(|&(mask, reason)| {
                            (mask & bit(candidate.top_image) != 0).then_some(reason)
                        })
                        .fold(0, |acc, reason| acc | reason)
                });
            mark_removed_with_reason(
                &mut remove,
                remove_reasons.as_mut(),
                letter,
                &[drop],
                top_reason,
            );
        }
    }
    apply_removals(residual, stats, remove, remove_reasons.as_ref(), reason)
}

//! Candidate-domain pruning rules used by partial-state propagation.

use super::super::{LymmDeckSpec, TopSwapCandidate};
use super::propagation::{bit, bit_positions, trace_conflict};
use super::propagation_removal::{
    apply_removals, build_target_masks, mark_removed_with_arc_reason, mark_removed_with_reason,
    removal_arc_reason_map, removal_map, removal_reason_map,
};
use super::residual::{CandidateRuntime, ResidualDomains};
use super::target_reason::{ArcLiteral, ArcReason, TargetReasonTracker};
use super::{AlignedMessage, SwapRecoveryError, SwapRecoveryStats};

const MAX_TRANSITION_READ_POSITIONS: u32 = 8;

#[allow(
    clippy::too_many_lines,
    reason = "transition pruning stays in one hot loop so removals and reason masks remain aligned"
)]
pub(super) fn prune_transition_domains(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    state_domains: &[Vec<Vec<u128>>],
    residual: &mut ResidualDomains,
    stats: &mut SwapRecoveryStats,
    full: u128,
    mut reason: Option<&mut TargetReasonTracker>,
) -> Result<bool, SwapRecoveryError> {
    let target_masks = build_target_masks(residual);
    let base_inverse = base_inverse(spec);
    let mut remove = removal_map(residual, false);
    let mut remove_reasons = reason.as_ref().map(|_| removal_reason_map(residual));
    let mut arc_remove_reasons = reason.as_ref().map(|_| removal_arc_reason_map(residual));

    for (message_index, message) in messages.iter().enumerate() {
        let Some(message_states) = state_domains.get(message_index) else {
            continue;
        };
        for (event_index, window) in message.events.windows(2).enumerate() {
            let [first, second] = window else {
                continue;
            };
            let pre_positions = message_states
                .get(event_index)
                .and_then(|state| state.get(second.ct_value))
                .copied()
                .unwrap_or(full);
            if pre_positions == full || pre_positions.count_ones() > MAX_TRANSITION_READ_POSITIONS {
                continue;
            }
            if pre_positions == 0 {
                trace_conflict("adjacent transition has empty pre-position mask");
                if let Some(tracker) = reason.as_deref_mut() {
                    let conflict_reason =
                        tracker.state_reason(message_index, event_index, second.ct_value);
                    let arc_reason =
                        tracker.state_arc_reason(message_index, event_index, second.ct_value);
                    tracker.record_conflict_with_arc_reason(conflict_reason, &arc_reason);
                }
                return Err(SwapRecoveryError::NoResidualCandidate);
            }
            let second_target_mask = target_masks.get(&second.letter).copied().unwrap_or(0);
            if second_target_mask == 0 {
                trace_conflict(&format!(
                    "adjacent transition has empty target mask for {}",
                    second.letter
                ));
                if let Some(tracker) = reason.as_deref_mut() {
                    tracker.record_conflict(tracker.domain_reason(second.letter));
                }
                return Err(SwapRecoveryError::NoResidualCandidate);
            }
            let Some(first_domain) = residual.by_letter.get(&first.letter) else {
                continue;
            };
            let pre_reason = reason.as_deref().map_or(0, |tracker| {
                tracker.state_reason(message_index, event_index, second.ct_value)
            });
            let pre_arc_reason = reason
                .as_deref()
                .map_or_else(ArcReason::default, |tracker| {
                    tracker.state_arc_reason(message_index, event_index, second.ct_value)
                });
            let first_reason = reason
                .as_deref()
                .map_or(0, |tracker| tracker.domain_reason(first.letter));
            let first_arc_reason = reason
                .as_deref()
                .map_or_else(ArcReason::default, |tracker| {
                    tracker.domain_arc_reason(first.letter)
                });
            let second_reason = reason
                .as_deref()
                .map_or(0, |tracker| tracker.domain_reason(second.letter));
            let second_arc_reason = reason
                .as_deref()
                .map_or_else(ArcReason::default, |tracker| {
                    tracker.domain_arc_reason(second.letter)
                });
            let required_first_arc = singleton_position(pre_positions).and_then(|pre_position| {
                singleton_position(second_target_mask).map(|post_position| ArcLiteral {
                    letter: first.letter,
                    post_position,
                    pre_position,
                })
            });

            let mut first_drops = Vec::new();
            let mut supported_second_targets = 0u128;
            for (domain_index, &candidate_index) in first_domain.iter().enumerate() {
                let Some(candidate) = residual.domains.candidates.get(candidate_index) else {
                    first_drops.push(domain_index);
                    continue;
                };
                let allowed_targets =
                    candidate_preimage_mask(candidate, pre_positions, &base_inverse);
                if allowed_targets & second_target_mask == 0 {
                    first_drops.push(domain_index);
                } else {
                    supported_second_targets |= allowed_targets;
                }
            }
            if supported_second_targets == 0 {
                trace_conflict(&format!(
                    "adjacent transition has no supported second targets for {}{}",
                    first.letter, second.letter
                ));
                if let Some(tracker) = reason.as_deref_mut() {
                    let mut arc_reason = pre_arc_reason
                        .clone()
                        .union(&first_arc_reason)
                        .union(&second_arc_reason);
                    if let Some(literal) = required_first_arc {
                        arc_reason.union_with(&ArcReason::from_arc(literal));
                    }
                    tracker.record_conflict_excluding_with_arc_reason(
                        [first.letter, second.letter],
                        pre_reason | first_reason | second_reason,
                        &arc_reason,
                    );
                }
                return Err(SwapRecoveryError::NoResidualCandidate);
            }
            let mut first_drop_arc_reason = pre_arc_reason.clone().union(&second_arc_reason);
            if let Some(literal) = required_first_arc {
                first_drop_arc_reason.union_with(&ArcReason::from_arc(literal));
            }
            mark_removed_with_reason(
                &mut remove,
                remove_reasons.as_mut(),
                first.letter,
                &first_drops,
                pre_reason | second_reason,
            );
            mark_removed_with_arc_reason(
                arc_remove_reasons.as_mut(),
                first.letter,
                &first_drops,
                &first_drop_arc_reason,
            );

            let Some(second_domain) = residual.by_letter.get(&second.letter) else {
                continue;
            };
            let second_drops = second_domain
                .iter()
                .enumerate()
                .filter_map(|(domain_index, &candidate_index)| {
                    let top = residual
                        .domains
                        .candidates
                        .get(candidate_index)
                        .map(|candidate| candidate.top_image)?;
                    (supported_second_targets & bit(top) == 0).then_some(domain_index)
                })
                .collect::<Vec<_>>();
            mark_removed_with_reason(
                &mut remove,
                remove_reasons.as_mut(),
                second.letter,
                &second_drops,
                pre_reason | first_reason,
            );
            let second_drop_arc_reason = pre_arc_reason.clone().union(&first_arc_reason);
            mark_removed_with_arc_reason(
                arc_remove_reasons.as_mut(),
                second.letter,
                &second_drops,
                &second_drop_arc_reason,
            );
        }
    }

    apply_removals(
        residual,
        stats,
        remove,
        remove_reasons.as_ref(),
        arc_remove_reasons.as_ref(),
        reason,
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "two-step pruning stays in one hot loop so removals and reason masks remain aligned"
)]
pub(super) fn prune_two_step_transition_domains(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    state_domains: &[Vec<Vec<u128>>],
    residual: &mut ResidualDomains,
    stats: &mut SwapRecoveryStats,
    full: u128,
    mut reason: Option<&mut TargetReasonTracker>,
) -> Result<bool, SwapRecoveryError> {
    let target_masks = build_target_masks(residual);
    let base_inverse = base_inverse(spec);
    let mut remove = removal_map(residual, false);
    let mut remove_reasons = reason.as_ref().map(|_| removal_reason_map(residual));
    let mut arc_remove_reasons = reason.as_ref().map(|_| removal_arc_reason_map(residual));

    for (message_index, message) in messages.iter().enumerate() {
        let Some(message_states) = state_domains.get(message_index) else {
            continue;
        };
        for (event_index, window) in message.events.windows(3).enumerate() {
            let [first, second, third] = window else {
                continue;
            };
            let pre_positions = message_states
                .get(event_index)
                .and_then(|state| state.get(third.ct_value))
                .copied()
                .unwrap_or(full);
            if pre_positions == full || pre_positions.count_ones() > MAX_TRANSITION_READ_POSITIONS {
                continue;
            }
            if pre_positions == 0 {
                trace_conflict("two-step transition has empty pre-position mask");
                if let Some(tracker) = reason.as_deref_mut() {
                    let conflict_reason =
                        tracker.state_reason(message_index, event_index, third.ct_value);
                    let arc_reason =
                        tracker.state_arc_reason(message_index, event_index, third.ct_value);
                    tracker.record_conflict_with_arc_reason(conflict_reason, &arc_reason);
                }
                return Err(SwapRecoveryError::NoResidualCandidate);
            }
            let third_target_mask = target_masks.get(&third.letter).copied().unwrap_or(0);
            if third_target_mask == 0 {
                trace_conflict(&format!(
                    "two-step transition has empty target mask for {}",
                    third.letter
                ));
                if let Some(tracker) = reason.as_deref_mut() {
                    tracker.record_conflict(tracker.domain_reason(third.letter));
                }
                return Err(SwapRecoveryError::NoResidualCandidate);
            }
            if third_target_mask.count_ones() > MAX_TRANSITION_READ_POSITIONS {
                continue;
            }

            let Some(first_domain) = residual.by_letter.get(&first.letter) else {
                continue;
            };
            let Some(second_domain) = residual.by_letter.get(&second.letter) else {
                continue;
            };
            let pre_reason = reason.as_deref().map_or(0, |tracker| {
                tracker.state_reason(message_index, event_index, third.ct_value)
            });
            let pre_arc_reason = reason
                .as_deref()
                .map_or_else(ArcReason::default, |tracker| {
                    tracker.state_arc_reason(message_index, event_index, third.ct_value)
                });
            let first_reason = reason
                .as_deref()
                .map_or(0, |tracker| tracker.domain_reason(first.letter));
            let first_arc_reason = reason
                .as_deref()
                .map_or_else(ArcReason::default, |tracker| {
                    tracker.domain_arc_reason(first.letter)
                });
            let second_reason = reason
                .as_deref()
                .map_or(0, |tracker| tracker.domain_reason(second.letter));
            let second_arc_reason = reason
                .as_deref()
                .map_or_else(ArcReason::default, |tracker| {
                    tracker.domain_arc_reason(second.letter)
                });
            let third_reason = reason
                .as_deref()
                .map_or(0, |tracker| tracker.domain_reason(third.letter));
            let third_arc_reason = reason
                .as_deref()
                .map_or_else(ArcReason::default, |tracker| {
                    tracker.domain_arc_reason(third.letter)
                });

            let mut second_outputs = Vec::with_capacity(second_domain.len());
            let mut any_second_outputs = 0u128;
            for (domain_index, &candidate_index) in second_domain.iter().enumerate() {
                let Some(candidate) = residual.candidates.get(candidate_index) else {
                    continue;
                };
                let output_mask = candidate_image_mask(candidate, third_target_mask);
                if output_mask == 0 {
                    continue;
                }
                any_second_outputs |= output_mask;
                second_outputs.push((domain_index, output_mask));
            }
            if any_second_outputs == 0 {
                trace_conflict(&format!(
                    "two-step transition has no second outputs for {}{}{}",
                    first.letter, second.letter, third.letter
                ));
                if let Some(tracker) = reason.as_deref_mut() {
                    let arc_reason = second_arc_reason.clone().union(&third_arc_reason);
                    tracker.record_conflict_excluding_with_arc_reason(
                        [second.letter, third.letter],
                        second_reason | third_reason,
                        &arc_reason,
                    );
                }
                return Err(SwapRecoveryError::NoResidualCandidate);
            }

            let mut first_drops = Vec::new();
            let mut any_allowed_inputs = 0u128;
            for (domain_index, &candidate_index) in first_domain.iter().enumerate() {
                let Some(candidate) = residual.domains.candidates.get(candidate_index) else {
                    first_drops.push(domain_index);
                    continue;
                };
                let allowed_inputs =
                    candidate_preimage_mask(candidate, pre_positions, &base_inverse);
                if allowed_inputs & any_second_outputs == 0 {
                    first_drops.push(domain_index);
                } else {
                    any_allowed_inputs |= allowed_inputs;
                }
            }
            if any_allowed_inputs == 0 {
                trace_conflict(&format!(
                    "two-step transition has no allowed first inputs for {}{}{}",
                    first.letter, second.letter, third.letter
                ));
                if let Some(tracker) = reason.as_deref_mut() {
                    let arc_reason = pre_arc_reason
                        .clone()
                        .union(&first_arc_reason)
                        .union(&second_arc_reason)
                        .union(&third_arc_reason);
                    tracker.record_conflict_excluding_with_arc_reason(
                        [first.letter, second.letter, third.letter],
                        pre_reason | first_reason | second_reason | third_reason,
                        &arc_reason,
                    );
                }
                return Err(SwapRecoveryError::NoResidualCandidate);
            }
            let first_drop_arc_reason = singleton_position(pre_positions)
                .and_then(|pre_position| {
                    singleton_position(any_second_outputs).map(|post_position| ArcLiteral {
                        letter: first.letter,
                        post_position,
                        pre_position,
                    })
                })
                .map_or_else(
                    || {
                        pre_arc_reason
                            .clone()
                            .union(&second_arc_reason)
                            .union(&third_arc_reason)
                    },
                    |literal| {
                        pre_arc_reason
                            .clone()
                            .union(&second_arc_reason)
                            .union(&third_arc_reason)
                            .union(&ArcReason::from_arc(literal))
                    },
                );
            mark_removed_with_reason(
                &mut remove,
                remove_reasons.as_mut(),
                first.letter,
                &first_drops,
                pre_reason | second_reason | third_reason,
            );
            mark_removed_with_arc_reason(
                arc_remove_reasons.as_mut(),
                first.letter,
                &first_drops,
                &first_drop_arc_reason,
            );

            let second_drops = second_outputs
                .into_iter()
                .filter_map(|(domain_index, output_mask)| {
                    (output_mask & any_allowed_inputs == 0).then_some(domain_index)
                })
                .collect::<Vec<_>>();
            let second_drop_arc_reason = singleton_position(third_target_mask)
                .and_then(|post_position| {
                    singleton_position(any_allowed_inputs).map(|pre_position| ArcLiteral {
                        letter: second.letter,
                        post_position,
                        pre_position,
                    })
                })
                .map_or_else(
                    || {
                        pre_arc_reason
                            .clone()
                            .union(&first_arc_reason)
                            .union(&third_arc_reason)
                    },
                    |literal| {
                        pre_arc_reason
                            .clone()
                            .union(&first_arc_reason)
                            .union(&third_arc_reason)
                            .union(&ArcReason::from_arc(literal))
                    },
                );
            mark_removed_with_reason(
                &mut remove,
                remove_reasons.as_mut(),
                second.letter,
                &second_drops,
                pre_reason | first_reason | third_reason,
            );
            mark_removed_with_arc_reason(
                arc_remove_reasons.as_mut(),
                second.letter,
                &second_drops,
                &second_drop_arc_reason,
            );
        }
    }

    apply_removals(
        residual,
        stats,
        remove,
        remove_reasons.as_ref(),
        arc_remove_reasons.as_ref(),
        reason,
    )
}

fn base_inverse(spec: &LymmDeckSpec) -> Vec<usize> {
    let mut inverse = vec![0usize; spec.n];
    for (position, &image) in spec.base.iter().enumerate() {
        if let Some(slot) = inverse.get_mut(image) {
            *slot = position;
        }
    }
    inverse
}

fn candidate_preimage_mask(
    candidate: &TopSwapCandidate,
    pre_positions: u128,
    base_inverse: &[usize],
) -> u128 {
    let mut mask = 0u128;
    for pre_position in bit_positions(pre_positions) {
        let Some(&sigma_image) = base_inverse.get(pre_position) else {
            continue;
        };
        let candidate_position = candidate
            .support
            .iter()
            .zip(&candidate.sigma_images)
            .find_map(|(&support_position, &image)| {
                (image == sigma_image).then_some(support_position)
            })
            .unwrap_or(sigma_image);
        mask |= bit(candidate_position);
    }
    mask
}

fn candidate_image_mask(candidate: &CandidateRuntime, input_positions: u128) -> u128 {
    let mut mask = 0u128;
    for input_position in bit_positions(input_positions) {
        if let Some(&output_position) = candidate.perm.get(input_position) {
            mask |= bit(output_position);
        }
    }
    mask
}

fn singleton_position(mask: u128) -> Option<usize> {
    mask.is_power_of_two()
        .then_some(mask.trailing_zeros() as usize)
}

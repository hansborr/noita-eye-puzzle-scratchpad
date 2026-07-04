//! Partial-state propagation for the Lymm swap-recovery residual.

use std::collections::BTreeMap;

use super::super::LymmDeckSpec;
use super::residual::{CandidateRuntime, ResidualDomains};
use super::{AlignedMessage, SwapRecoveryError, SwapRecoveryStats};

#[derive(Clone, Debug, PartialEq, Eq)]
struct DomainRelation {
    post_to_pre: Vec<u128>,
    pre_to_post: Vec<u128>,
}

pub(super) fn propagate_partial_states(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    residual: &mut ResidualDomains,
    stats: &mut SwapRecoveryStats,
) -> Result<(), SwapRecoveryError> {
    let full = full_mask(spec.n);
    let mut state_domains = initial_state_domains(spec, messages, full);

    for _pass in 0..32 {
        let relations = build_domain_relations(spec, residual);
        let state_changed =
            narrow_state_domains(spec, messages, &relations, &mut state_domains, stats)?;
        let domain_changed =
            prune_candidate_domains(spec, messages, &state_domains, residual, stats, full)?;
        let changed = state_changed || domain_changed;
        if !changed {
            break;
        }
    }
    Ok(())
}

fn initial_state_domains(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    full: u128,
) -> Vec<Vec<Vec<u128>>> {
    messages
        .iter()
        .map(|message| {
            let mut message_states = vec![vec![full; spec.n]; message.events.len() + 1];
            for value in 0..spec.n {
                if let Some(slot) = message_states
                    .get_mut(0)
                    .and_then(|state| state.get_mut(value))
                {
                    *slot = bit(value);
                }
            }
            for (index, event) in message.events.iter().enumerate() {
                if let Some(slot) = message_states
                    .get_mut(index.saturating_add(1))
                    .and_then(|state| state.get_mut(event.ct_value))
                {
                    *slot = bit(spec.emit_index);
                }
            }
            message_states
        })
        .collect()
}

fn narrow_state_domains(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    relations: &BTreeMap<char, DomainRelation>,
    state_domains: &mut [Vec<Vec<u128>>],
    stats: &mut SwapRecoveryStats,
) -> Result<bool, SwapRecoveryError> {
    let mut changed = false;
    for (message_index, message) in messages.iter().enumerate() {
        let Some(message_states) = state_domains.get_mut(message_index) else {
            continue;
        };
        for (event_index, event) in message.events.iter().enumerate() {
            let Some(relation) = relations.get(&event.letter) else {
                continue;
            };
            let (left, right) = message_states.split_at_mut(event_index.saturating_add(1));
            let Some(pre) = left.get_mut(event_index) else {
                continue;
            };
            let Some(post) = right.get_mut(0) else {
                continue;
            };
            changed |= narrow_transition_state(spec, pre, post, relation, stats)?;
        }
    }
    Ok(changed)
}

fn narrow_transition_state(
    spec: &LymmDeckSpec,
    pre: &mut [u128],
    post: &mut [u128],
    relation: &DomainRelation,
    stats: &mut SwapRecoveryStats,
) -> Result<bool, SwapRecoveryError> {
    let mut changed = false;
    for value in 0..spec.n {
        let old_pre = pre.get(value).copied().unwrap_or(0);
        let old_post = post.get(value).copied().unwrap_or(0);
        let new_post = old_post & map_pre_to_post(old_pre, relation);
        let new_pre = old_pre & map_post_to_pre(old_post, relation);
        if new_pre == 0 || new_post == 0 {
            return Err(SwapRecoveryError::NoResidualCandidate);
        }
        if new_pre != old_pre {
            if let Some(slot) = pre.get_mut(value) {
                *slot = new_pre;
            }
            stats.deductions += 1;
            changed = true;
        }
        if new_post != old_post {
            if let Some(slot) = post.get_mut(value) {
                *slot = new_post;
            }
            stats.deductions += 1;
            changed = true;
        }
    }
    Ok(changed)
}

fn prune_candidate_domains(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    state_domains: &[Vec<Vec<u128>>],
    residual: &mut ResidualDomains,
    stats: &mut SwapRecoveryStats,
    full: u128,
) -> Result<bool, SwapRecoveryError> {
    let mut changed = false;
    for &letter in &residual.letters {
        let before = residual
            .by_letter
            .get(&letter)
            .map_or(0usize, std::vec::Vec::len);
        let filtered = residual
            .by_letter
            .get(&letter)
            .into_iter()
            .flat_map(|domain| domain.iter().copied())
            .filter(|&candidate_index| {
                candidate_is_arc_consistent(
                    spec,
                    messages,
                    state_domains,
                    residual,
                    letter,
                    candidate_index,
                    full,
                )
            })
            .collect::<Vec<_>>();
        if filtered.is_empty() {
            return Err(SwapRecoveryError::NoResidualCandidate);
        }
        if filtered.len() != before {
            stats.domains_pruned += before.saturating_sub(filtered.len());
            let _old = residual.by_letter.insert(letter, filtered);
            changed = true;
        }
    }
    Ok(changed)
}

fn build_domain_relations(
    spec: &LymmDeckSpec,
    residual: &ResidualDomains,
) -> BTreeMap<char, DomainRelation> {
    let mut relations = BTreeMap::new();
    for (&letter, domain) in &residual.by_letter {
        let mut post_to_pre = vec![0u128; spec.n];
        let mut pre_to_post = vec![0u128; spec.n];
        for &candidate_index in domain {
            if let Some(candidate) = residual.candidates.get(candidate_index) {
                for (post_position, &pre_position) in candidate.perm.iter().enumerate() {
                    if let Some(slot) = post_to_pre.get_mut(post_position) {
                        *slot |= bit(pre_position);
                    }
                    if let Some(slot) = pre_to_post.get_mut(pre_position) {
                        *slot |= bit(post_position);
                    }
                }
            }
        }
        let _old = relations.insert(
            letter,
            DomainRelation {
                post_to_pre,
                pre_to_post,
            },
        );
    }
    relations
}

fn map_pre_to_post(pre_positions: u128, relation: &DomainRelation) -> u128 {
    let mut mapped = 0u128;
    for pre_position in bit_positions(pre_positions) {
        mapped |= relation
            .pre_to_post
            .get(pre_position)
            .copied()
            .unwrap_or_default();
    }
    mapped
}

fn map_post_to_pre(post_positions: u128, relation: &DomainRelation) -> u128 {
    let mut mapped = 0u128;
    for post_position in bit_positions(post_positions) {
        mapped |= relation
            .post_to_pre
            .get(post_position)
            .copied()
            .unwrap_or_default();
    }
    mapped
}

fn candidate_is_arc_consistent(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    states: &[Vec<Vec<u128>>],
    residual: &ResidualDomains,
    letter: char,
    candidate_index: usize,
    full: u128,
) -> bool {
    let Some(candidate) = residual.candidates.get(candidate_index) else {
        return false;
    };
    for (message_index, message) in messages.iter().enumerate() {
        let Some(message_states) = states.get(message_index) else {
            return false;
        };
        for (event_index, event) in message.events.iter().enumerate() {
            if event.letter != letter {
                continue;
            }
            let (Some(pre), Some(post)) = (
                message_states.get(event_index),
                message_states.get(event_index.saturating_add(1)),
            ) else {
                return false;
            };
            for value in 0..spec.n {
                let pre_positions = pre.get(value).copied().unwrap_or_default();
                let post_positions = post.get(value).copied().unwrap_or_default();
                if pre_positions == full && post_positions == full {
                    continue;
                }
                if !candidate_allows_value(candidate, pre_positions, post_positions) {
                    return false;
                }
            }
        }
    }
    true
}

fn candidate_allows_value(
    candidate: &CandidateRuntime,
    pre_positions: u128,
    post_positions: u128,
) -> bool {
    for post_position in bit_positions(post_positions) {
        if candidate
            .perm
            .get(post_position)
            .is_some_and(|&pre_position| pre_positions & bit(pre_position) != 0)
        {
            return true;
        }
    }
    false
}

fn full_mask(n: usize) -> u128 {
    if n >= u128::BITS as usize {
        u128::MAX
    } else {
        (1u128 << n) - 1
    }
}

fn bit(position: usize) -> u128 {
    1u128 << position
}

fn bit_positions(mut mask: u128) -> impl Iterator<Item = usize> {
    std::iter::from_fn(move || {
        if mask == 0 {
            return None;
        }
        let bit = mask & mask.wrapping_neg();
        mask &= !bit;
        Some(bit.trailing_zeros() as usize)
    })
}

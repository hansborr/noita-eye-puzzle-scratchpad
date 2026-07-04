//! Partial-state propagation for the Lymm swap-recovery residual.

use std::collections::BTreeMap;

use super::super::LymmDeckSpec;
use super::propagation_pruning::{prune_transition_domains, prune_two_step_transition_domains};
use super::propagation_target_pruning::{prune_distinct_target_domains, prune_target_read_domains};
use super::residual::{CandidateRuntime, ResidualDomains};
use super::target_reason::TargetReasonTracker;
use super::{AlignedMessage, SwapRecoveryError, SwapRecoveryStats};

#[derive(Clone, Debug, PartialEq, Eq)]
struct DomainRelation {
    letter: char,
    post_to_pre: Vec<u128>,
    pre_to_post: Vec<u128>,
    reason: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PropagationResult {
    pub(super) state_domains: Vec<Vec<Vec<u128>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PropagationOptions {
    pub(super) max_passes: usize,
    pub(super) exhaustive_arc: bool,
}

impl PropagationOptions {
    pub(super) const fn ns2_default() -> Self {
        Self {
            max_passes: 32,
            exhaustive_arc: true,
        }
    }

    pub(super) const fn ns3_broad() -> Self {
        Self {
            max_passes: 3,
            exhaustive_arc: false,
        }
    }
}

pub(super) fn propagate_partial_states(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    residual: &mut ResidualDomains,
    stats: &mut SwapRecoveryStats,
    options: PropagationOptions,
) -> Result<PropagationResult, SwapRecoveryError> {
    propagate_partial_states_inner(spec, messages, residual, stats, options, None)
}

pub(super) fn propagate_partial_states_with_target_reasons(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    residual: &mut ResidualDomains,
    stats: &mut SwapRecoveryStats,
    options: PropagationOptions,
    targets: &BTreeMap<char, usize>,
    tracker: &mut Option<TargetReasonTracker>,
) -> Result<PropagationResult, SwapRecoveryError> {
    *tracker = Some(TargetReasonTracker::new(spec, messages, residual, targets));
    propagate_partial_states_inner(spec, messages, residual, stats, options, tracker.as_mut())
}

fn propagate_partial_states_inner(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    residual: &mut ResidualDomains,
    stats: &mut SwapRecoveryStats,
    options: PropagationOptions,
    mut reason: Option<&mut TargetReasonTracker>,
) -> Result<PropagationResult, SwapRecoveryError> {
    let full = full_mask(spec.n);
    let mut state_domains = initial_state_domains(spec, messages, full);
    let trace = std::env::var_os("NOITA_SWAP_TRACE_PASSES").is_some();
    let skip_arc =
        !options.exhaustive_arc || std::env::var_os("NOITA_SWAP_TRACE_SKIP_ARC").is_some();
    let trace_max_passes = std::env::var("NOITA_SWAP_TRACE_MAX_PASSES")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok());

    for pass in 0..options.max_passes {
        let before = domain_entry_count(residual);
        let permutation_changed = enforce_state_permutation_domains(
            spec,
            &mut state_domains,
            stats,
            reason.as_deref_mut(),
        )?;
        let target_changed = prune_distinct_target_domains(residual, stats, reason.as_deref_mut())?;
        let relations = build_domain_relations(spec, residual, reason.as_deref());
        let state_changed = narrow_state_domains(
            messages,
            &relations,
            &mut state_domains,
            stats,
            reason.as_deref_mut(),
        )?;
        let permutation_changed = enforce_state_permutation_domains(
            spec,
            &mut state_domains,
            stats,
            reason.as_deref_mut(),
        )? || permutation_changed;
        let read_changed = prune_target_read_domains(
            messages,
            &state_domains,
            residual,
            stats,
            full,
            reason.as_deref_mut(),
        )?;
        let transition_changed = prune_transition_domains(
            spec,
            messages,
            &state_domains,
            residual,
            stats,
            full,
            reason.as_deref_mut(),
        )?;
        let two_step_changed = prune_two_step_transition_domains(
            spec,
            messages,
            &state_domains,
            residual,
            stats,
            full,
            reason.as_deref_mut(),
        )?;
        let after_transition = domain_entry_count(residual);
        let domain_changed = if skip_arc {
            false
        } else {
            prune_candidate_domains(
                spec,
                messages,
                &state_domains,
                residual,
                stats,
                full,
                reason.as_deref_mut(),
            )?
        };
        if trace {
            eprintln!(
                "trace pass={} before={} after_transition={} after_arc={} pruned={} deductions={}",
                pass + 1,
                before,
                after_transition,
                domain_entry_count(residual),
                stats.domains_pruned,
                stats.deductions
            );
        }
        let changed = permutation_changed
            || target_changed
            || state_changed
            || read_changed
            || transition_changed
            || two_step_changed
            || domain_changed;
        if trace_max_passes.is_some_and(|max_passes| pass + 1 >= max_passes) {
            break;
        }
        if !changed {
            break;
        }
    }
    Ok(PropagationResult { state_domains })
}

fn enforce_state_permutation_domains(
    spec: &LymmDeckSpec,
    state_domains: &mut [Vec<Vec<u128>>],
    stats: &mut SwapRecoveryStats,
    mut reason: Option<&mut TargetReasonTracker>,
) -> Result<bool, SwapRecoveryError> {
    let mut changed = false;
    for (message_index, message_states) in state_domains.iter_mut().enumerate() {
        for (state_index, state) in message_states.iter_mut().enumerate() {
            changed |= enforce_one_state_permutation_domain(
                spec,
                state,
                stats,
                reason.as_deref_mut(),
                message_index,
                state_index,
            )?;
        }
    }
    Ok(changed)
}

fn enforce_one_state_permutation_domain(
    spec: &LymmDeckSpec,
    value_domains: &mut [u128],
    counters: &mut SwapRecoveryStats,
    mut reason: Option<&mut TargetReasonTracker>,
    message_index: usize,
    state_index: usize,
) -> Result<bool, SwapRecoveryError> {
    let mut changed = false;
    loop {
        let mut pass_changed = false;
        let singleton_positions = value_domains
            .iter()
            .copied()
            .filter(|domain| domain.is_power_of_two())
            .fold(0u128, |acc, domain| acc | domain);
        let state_reason = reason.as_deref().map_or(0, |tracker| {
            tracker.state_union_reason(message_index, state_index)
        });

        for value in 0..value_domains.len() {
            let Some(domain) = value_domains.get_mut(value) else {
                continue;
            };
            if domain.is_power_of_two() {
                continue;
            }
            let narrowed = *domain & !singleton_positions;
            if narrowed == 0 {
                trace_conflict("state singleton position removal emptied a value domain");
                if let Some(tracker) = reason.as_deref_mut() {
                    let conflict_reason =
                        state_reason | tracker.state_reason(message_index, state_index, value);
                    tracker.record_conflict(conflict_reason);
                }
                return Err(SwapRecoveryError::NoResidualCandidate);
            }
            if narrowed != *domain {
                *domain = narrowed;
                if let Some(tracker) = reason.as_deref_mut() {
                    tracker.set_state_reason(message_index, state_index, value, state_reason);
                }
                counters.deductions += 1;
                pass_changed = true;
            }
        }

        for position in 0..spec.n {
            let position_bit = bit(position);
            let mut support = Vec::new();
            for (value, &domain) in value_domains.iter().enumerate() {
                if domain & position_bit != 0 {
                    support.push(value);
                    if support.len() > 1 {
                        break;
                    }
                }
            }
            if support.is_empty() {
                trace_conflict("state position has no supporting value");
                if let Some(tracker) = reason.as_deref_mut() {
                    tracker.record_conflict(state_reason);
                }
                return Err(SwapRecoveryError::NoResidualCandidate);
            }
            if support.len() == 1 {
                let Some(value) = support.first().copied() else {
                    continue;
                };
                if value_domains.get(value).copied().unwrap_or_default() != position_bit {
                    if let Some(domain) = value_domains.get_mut(value) {
                        *domain = position_bit;
                    }
                    if let Some(tracker) = reason.as_deref_mut() {
                        tracker.set_state_reason(message_index, state_index, value, state_reason);
                    }
                    counters.deductions += 1;
                    pass_changed = true;
                }
            }
        }

        if !pass_changed {
            break;
        }
        changed = true;
    }
    Ok(changed)
}

fn domain_entry_count(residual: &ResidualDomains) -> usize {
    residual.by_letter.values().map(std::vec::Vec::len).sum()
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
            for (position, &value) in spec.initial_state.iter().enumerate() {
                if let Some(slot) = message_states
                    .get_mut(0)
                    .and_then(|state| state.get_mut(value))
                {
                    *slot = bit(position);
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
    messages: &[AlignedMessage],
    relations: &BTreeMap<char, DomainRelation>,
    state_domains: &mut [Vec<Vec<u128>>],
    stats: &mut SwapRecoveryStats,
    mut reason: Option<&mut TargetReasonTracker>,
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
            match narrow_transition_state(
                pre,
                post,
                relation,
                stats,
                reason.as_deref_mut(),
                message_index,
                event_index,
            ) {
                Ok(transition_changed) => changed |= transition_changed,
                Err(error) => {
                    trace_conflict(&format!(
                        "transition failure at message {message_index} event {event_index} letter {}",
                        event.letter
                    ));
                    return Err(error);
                }
            }
        }
    }
    Ok(changed)
}

fn narrow_transition_state(
    pre: &mut [u128],
    post: &mut [u128],
    relation: &DomainRelation,
    stats: &mut SwapRecoveryStats,
    mut reason: Option<&mut TargetReasonTracker>,
    message_index: usize,
    event_index: usize,
) -> Result<bool, SwapRecoveryError> {
    let mut changed = false;
    for value in 0..pre.len().min(post.len()) {
        let old_pre = pre.get(value).copied().unwrap_or(0);
        let old_post = post.get(value).copied().unwrap_or(0);
        let new_post = old_post & map_pre_to_post(old_pre, relation);
        let new_pre = old_pre & map_post_to_pre(old_post, relation);
        if new_pre == 0 || new_post == 0 {
            trace_conflict("transition state narrowing emptied a value domain");
            if let Some(tracker) = reason.as_deref_mut() {
                let conflict_reason = relation.reason
                    | tracker.state_reason(message_index, event_index, value)
                    | tracker.state_reason(message_index, event_index.saturating_add(1), value);
                tracker.record_conflict_excluding([relation.letter], conflict_reason);
            }
            return Err(SwapRecoveryError::NoResidualCandidate);
        }
        if new_pre != old_pre {
            if let Some(slot) = pre.get_mut(value) {
                *slot = new_pre;
            }
            if let Some(tracker) = reason.as_deref_mut() {
                let next_reason = relation.reason
                    | tracker.state_reason(message_index, event_index, value)
                    | tracker.state_reason(message_index, event_index.saturating_add(1), value);
                tracker.set_state_reason(message_index, event_index, value, next_reason);
            }
            stats.deductions += 1;
            changed = true;
        }
        if new_post != old_post {
            if let Some(slot) = post.get_mut(value) {
                *slot = new_post;
            }
            if let Some(tracker) = reason.as_deref_mut() {
                let next_reason = relation.reason
                    | tracker.state_reason(message_index, event_index, value)
                    | tracker.state_reason(message_index, event_index.saturating_add(1), value);
                tracker.set_state_reason(
                    message_index,
                    event_index.saturating_add(1),
                    value,
                    next_reason,
                );
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
    mut reason: Option<&mut TargetReasonTracker>,
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
            trace_conflict(&format!("candidate arc emptied letter {letter}"));
            if let Some(tracker) = reason.as_deref_mut() {
                tracker.record_conflict(tracker.domain_reason(letter));
            }
            return Err(SwapRecoveryError::NoResidualCandidate);
        }
        if filtered.len() != before {
            stats.domains_pruned += before.saturating_sub(filtered.len());
            if let Some(tracker) = reason.as_deref_mut() {
                tracker.add_domain_reason(letter, tracker.domain_reason(letter));
            }
            let _old = residual.by_letter.insert(letter, filtered);
            changed = true;
        }
    }
    Ok(changed)
}

fn build_domain_relations(
    spec: &LymmDeckSpec,
    residual: &ResidualDomains,
    reason: Option<&TargetReasonTracker>,
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
                letter,
                post_to_pre,
                pre_to_post,
                reason: reason.map_or(0, |tracker| tracker.domain_reason(letter)),
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

pub(super) fn bit(position: usize) -> u128 {
    1u128 << position
}

pub(super) fn bit_positions(mut mask: u128) -> impl Iterator<Item = usize> {
    std::iter::from_fn(move || {
        if mask == 0 {
            return None;
        }
        let bit = mask & mask.wrapping_neg();
        mask &= !bit;
        Some(bit.trailing_zeros() as usize)
    })
}

pub(super) fn trace_conflict(message: &str) {
    if std::env::var_os("NOITA_SWAP_CONFLICT_TRACE").is_some() {
        eprintln!("conflict: {message}");
    }
}

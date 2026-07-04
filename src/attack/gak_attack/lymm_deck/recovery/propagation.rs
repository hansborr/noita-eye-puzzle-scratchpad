//! Partial-state propagation for the Lymm swap-recovery residual.

use std::collections::BTreeMap;

use super::super::{LymmDeckSpec, TopSwapCandidate};
use super::residual::{CandidateRuntime, ResidualDomains};
use super::{AlignedMessage, SwapRecoveryError, SwapRecoveryStats};

const MAX_TRANSITION_READ_POSITIONS: u32 = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
struct DomainRelation {
    post_to_pre: Vec<u128>,
    pre_to_post: Vec<u128>,
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
        let permutation_changed =
            enforce_state_permutation_domains(spec, &mut state_domains, stats)?;
        let target_changed = prune_distinct_target_domains(residual, stats)?;
        let relations = build_domain_relations(spec, residual);
        let state_changed =
            narrow_state_domains(spec, messages, &relations, &mut state_domains, stats)?;
        let permutation_changed =
            enforce_state_permutation_domains(spec, &mut state_domains, stats)?
                || permutation_changed;
        let read_changed =
            prune_target_read_domains(messages, &state_domains, residual, stats, full)?;
        let transition_changed =
            prune_transition_domains(spec, messages, &state_domains, residual, stats, full)?;
        let two_step_changed = prune_two_step_transition_domains(
            spec,
            messages,
            &state_domains,
            residual,
            stats,
            full,
        )?;
        let after_transition = domain_entry_count(residual);
        let domain_changed = if skip_arc {
            false
        } else {
            prune_candidate_domains(spec, messages, &state_domains, residual, stats, full)?
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
) -> Result<bool, SwapRecoveryError> {
    let mut changed = false;
    for message_states in state_domains {
        for state in message_states {
            changed |= enforce_one_state_permutation_domain(spec, state, stats)?;
        }
    }
    Ok(changed)
}

fn enforce_one_state_permutation_domain(
    spec: &LymmDeckSpec,
    value_domains: &mut [u128],
    counters: &mut SwapRecoveryStats,
) -> Result<bool, SwapRecoveryError> {
    let mut changed = false;
    loop {
        let mut pass_changed = false;
        let singleton_positions = value_domains
            .iter()
            .copied()
            .filter(|domain| domain.is_power_of_two())
            .fold(0u128, |acc, domain| acc | domain);

        for domain in value_domains
            .iter_mut()
            .filter(|domain| !domain.is_power_of_two())
        {
            let narrowed = *domain & !singleton_positions;
            if narrowed == 0 {
                trace_conflict("state singleton position removal emptied a value domain");
                return Err(SwapRecoveryError::NoResidualCandidate);
            }
            if narrowed != *domain {
                *domain = narrowed;
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
            match narrow_transition_state(spec, pre, post, relation, stats) {
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
            trace_conflict("transition state narrowing emptied a value domain");
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
            trace_conflict(&format!("candidate arc emptied letter {letter}"));
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

fn prune_transition_domains(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    state_domains: &[Vec<Vec<u128>>],
    residual: &mut ResidualDomains,
    stats: &mut SwapRecoveryStats,
    full: u128,
) -> Result<bool, SwapRecoveryError> {
    let target_masks = build_target_masks(residual);
    let base_inverse = base_inverse(spec);
    let mut remove = residual
        .by_letter
        .iter()
        .map(|(&letter, domain)| (letter, vec![false; domain.len()]))
        .collect::<BTreeMap<_, _>>();

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
                return Err(SwapRecoveryError::NoResidualCandidate);
            }
            let second_target_mask = target_masks.get(&second.letter).copied().unwrap_or(0);
            if second_target_mask == 0 {
                trace_conflict(&format!(
                    "adjacent transition has empty target mask for {}",
                    second.letter
                ));
                return Err(SwapRecoveryError::NoResidualCandidate);
            }
            let Some(first_domain) = residual.by_letter.get(&first.letter) else {
                continue;
            };

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
                return Err(SwapRecoveryError::NoResidualCandidate);
            }
            mark_removed(&mut remove, first.letter, &first_drops);

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
            mark_removed(&mut remove, second.letter, &second_drops);
        }
    }

    apply_removals(residual, stats, remove)
}

fn prune_two_step_transition_domains(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    state_domains: &[Vec<Vec<u128>>],
    residual: &mut ResidualDomains,
    stats: &mut SwapRecoveryStats,
    full: u128,
) -> Result<bool, SwapRecoveryError> {
    let target_masks = build_target_masks(residual);
    let base_inverse = base_inverse(spec);
    let mut remove = residual
        .by_letter
        .iter()
        .map(|(&letter, domain)| (letter, vec![false; domain.len()]))
        .collect::<BTreeMap<_, _>>();

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
                return Err(SwapRecoveryError::NoResidualCandidate);
            }
            let third_target_mask = target_masks.get(&third.letter).copied().unwrap_or(0);
            if third_target_mask == 0 {
                trace_conflict(&format!(
                    "two-step transition has empty target mask for {}",
                    third.letter
                ));
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
                return Err(SwapRecoveryError::NoResidualCandidate);
            }
            mark_removed(&mut remove, first.letter, &first_drops);

            let second_drops = second_outputs
                .into_iter()
                .filter_map(|(domain_index, output_mask)| {
                    (output_mask & any_allowed_inputs == 0).then_some(domain_index)
                })
                .collect::<Vec<_>>();
            mark_removed(&mut remove, second.letter, &second_drops);
        }
    }

    apply_removals(residual, stats, remove)
}

fn prune_target_read_domains(
    messages: &[AlignedMessage],
    state_domains: &[Vec<Vec<u128>>],
    residual: &mut ResidualDomains,
    stats: &mut SwapRecoveryStats,
    full: u128,
) -> Result<bool, SwapRecoveryError> {
    let mut allowed = residual
        .letters
        .iter()
        .copied()
        .map(|letter| (letter, full))
        .collect::<BTreeMap<_, _>>();
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
            *slot &= target_mask;
            if *slot == 0 {
                trace_conflict(&format!(
                    "target read emptied allowed targets for {}",
                    event.letter
                ));
                return Err(SwapRecoveryError::NoResidualCandidate);
            }
        }
    }

    let mut remove = residual
        .by_letter
        .iter()
        .map(|(&letter, domain)| (letter, vec![false; domain.len()]))
        .collect::<BTreeMap<_, _>>();
    for (&letter, domain) in &residual.by_letter {
        let allowed_targets = allowed.get(&letter).copied().unwrap_or(full);
        if allowed_targets == full {
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
                (allowed_targets & bit(top) == 0).then_some(domain_index)
            })
            .collect::<Vec<_>>();
        mark_removed(&mut remove, letter, &drops);
    }
    apply_removals(residual, stats, remove)
}

fn prune_distinct_target_domains(
    residual: &mut ResidualDomains,
    stats: &mut SwapRecoveryStats,
) -> Result<bool, SwapRecoveryError> {
    let target_masks = build_target_masks(residual);
    let mut remove = residual
        .by_letter
        .iter()
        .map(|(&letter, domain)| (letter, vec![false; domain.len()]))
        .collect::<BTreeMap<_, _>>();
    for (&letter, domain) in &residual.by_letter {
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
        mark_removed(&mut remove, letter, &drops);
    }
    apply_removals(residual, stats, remove)
}

fn build_target_masks(residual: &ResidualDomains) -> BTreeMap<char, u128> {
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

fn apply_removals(
    residual: &mut ResidualDomains,
    stats: &mut SwapRecoveryStats,
    remove: BTreeMap<char, Vec<bool>>,
) -> Result<bool, SwapRecoveryError> {
    let mut changed = false;
    for (letter, removed) in remove {
        if !removed.iter().any(|&drop| drop) {
            continue;
        }
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

fn trace_conflict(message: &str) {
    if std::env::var_os("NOITA_SWAP_CONFLICT_TRACE").is_some() {
        eprintln!("conflict: {message}");
    }
}

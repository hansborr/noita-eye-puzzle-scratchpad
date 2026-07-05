//! Letter-domain relation helpers for partial-state propagation.

use std::collections::BTreeMap;

use super::super::LymmDeckSpec;
use super::AlignedMessage;
use super::propagation::{bit, bit_positions};
use super::residual::{CandidateRuntime, ResidualDomains};
use super::target_reason::{ArcReason, TargetReasonTracker};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DomainRelation {
    pub(super) letter: char,
    pub(super) post_to_pre: Vec<u128>,
    pub(super) pre_to_post: Vec<u128>,
    pub(super) reason: u128,
    pub(super) arc_reason: ArcReason,
}

pub(super) fn build_domain_relations(
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
                arc_reason: reason
                    .map(|tracker| tracker.domain_arc_reason(letter))
                    .unwrap_or_default(),
            },
        );
    }
    relations
}

pub(super) fn map_pre_to_post(pre_positions: u128, relation: &DomainRelation) -> u128 {
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

pub(super) fn map_post_to_pre(post_positions: u128, relation: &DomainRelation) -> u128 {
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

pub(super) fn candidate_is_arc_consistent(
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

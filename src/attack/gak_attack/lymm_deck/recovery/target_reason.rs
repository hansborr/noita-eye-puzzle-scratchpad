//! Target-level reason bookkeeping for ns=3 deterministic propagation.

use std::collections::{BTreeMap, BTreeSet};

use super::AlignedMessage;
use super::propagation::bit;
use super::residual::ResidualDomains;
use crate::attack::gak_attack::lymm_deck::LymmDeckSpec;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ArcLiteral {
    pub(super) letter: char,
    pub(super) post_position: usize,
    pub(super) pre_position: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct ArcReason {
    pub(super) arc_literals: BTreeSet<ArcLiteral>,
    pub(super) context_targets: BTreeSet<(char, usize)>,
    pub(super) opaque_context: bool,
}

impl ArcReason {
    pub(super) fn from_arc(literal: ArcLiteral) -> Self {
        let mut reason = Self::default();
        let _inserted = reason.arc_literals.insert(literal);
        reason
    }

    pub(super) fn from_context_target(letter: char, target: usize) -> Self {
        let mut reason = Self::default();
        let _inserted = reason.context_targets.insert((letter, target));
        reason
    }

    pub(super) fn union_with(&mut self, other: &Self) {
        self.arc_literals.extend(other.arc_literals.iter().copied());
        self.context_targets
            .extend(other.context_targets.iter().copied());
        self.opaque_context |= other.opaque_context;
    }

    pub(super) fn union(mut self, other: &Self) -> Self {
        self.union_with(other);
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TargetReasonTracker {
    choices: BTreeMap<char, usize>,
    letter_bits: BTreeMap<char, u128>,
    domain_reasons: BTreeMap<char, u128>,
    arc_domain_reasons: BTreeMap<char, ArcReason>,
    state_reasons: Vec<Vec<Vec<u128>>>,
    arc_state_reasons: Vec<Vec<Vec<ArcReason>>>,
    conflict: Option<u128>,
    arc_conflict: Option<ArcReason>,
    conflict_exclusions: u128,
}

impl TargetReasonTracker {
    pub(super) fn new(
        spec: &LymmDeckSpec,
        messages: &[AlignedMessage],
        residual: &ResidualDomains,
        targets: &BTreeMap<char, usize>,
    ) -> Self {
        let letter_bits = residual
            .letters
            .iter()
            .enumerate()
            .map(|(index, &letter)| (letter, bit(index)))
            .collect::<BTreeMap<_, _>>();
        let mut domain_reasons = residual
            .letters
            .iter()
            .copied()
            .map(|letter| (letter, 0))
            .collect::<BTreeMap<_, _>>();
        let arc_domain_reasons = residual
            .letters
            .iter()
            .copied()
            .map(|letter| (letter, ArcReason::default()))
            .collect::<BTreeMap<_, _>>();
        for &letter in targets.keys() {
            if let Some(reason_bit) = letter_bits.get(&letter).copied()
                && let Some(reason) = domain_reasons.get_mut(&letter)
            {
                *reason |= reason_bit;
            }
        }
        let state_reasons = messages
            .iter()
            .map(|message| vec![vec![0; spec.n]; message.events.len() + 1])
            .collect();
        let arc_state_reasons = messages
            .iter()
            .map(|message| vec![vec![ArcReason::default(); spec.n]; message.events.len() + 1])
            .collect();
        Self {
            choices: targets.clone(),
            letter_bits,
            domain_reasons,
            arc_domain_reasons,
            state_reasons,
            arc_state_reasons,
            conflict: None,
            arc_conflict: None,
            conflict_exclusions: 0,
        }
    }

    pub(super) fn conflict_choices(&self) -> Option<Vec<(char, usize)>> {
        self.conflict.map(|reason| self.choices_for(reason))
    }

    pub(super) fn focused_conflict_choices(&self) -> Option<Vec<(char, usize)>> {
        let reason = self.conflict?;
        if self.conflict_exclusions == 0 {
            return None;
        }
        let focused = self
            .letter_bits
            .iter()
            .filter_map(|(&letter, &bit)| {
                (reason & bit != 0 && self.conflict_exclusions & bit == 0)
                    .then(|| self.choices.get(&letter).map(|&target| (letter, target)))?
            })
            .collect::<Vec<_>>();
        (!focused.is_empty()).then_some(focused)
    }

    pub(super) fn choices_for(&self, reason: u128) -> Vec<(char, usize)> {
        self.letter_bits
            .iter()
            .filter_map(|(&letter, &bit)| {
                (reason & bit != 0)
                    .then(|| self.choices.get(&letter).map(|&target| (letter, target)))?
            })
            .collect()
    }

    pub(super) fn domain_reason(&self, letter: char) -> u128 {
        self.domain_reasons.get(&letter).copied().unwrap_or(0)
    }

    pub(super) fn domain_arc_reason(&self, letter: char) -> ArcReason {
        let base = self.reason_to_arc_reason(self.domain_reason(letter));
        self.arc_domain_reasons
            .get(&letter)
            .map_or(base.clone(), |arc_reason| base.union(arc_reason))
    }

    pub(super) fn add_domain_reason(&mut self, letter: char, reason: u128) {
        if let Some(slot) = self.domain_reasons.get_mut(&letter) {
            *slot |= reason;
        }
        let arc_reason = self.reason_to_arc_reason(reason);
        self.add_domain_arc_reason(letter, &arc_reason);
    }

    pub(super) fn add_domain_arc_reason(&mut self, letter: char, reason: &ArcReason) {
        if let Some(slot) = self.arc_domain_reasons.get_mut(&letter) {
            slot.union_with(reason);
        }
    }

    pub(super) fn state_reason(
        &self,
        message_index: usize,
        state_index: usize,
        value: usize,
    ) -> u128 {
        self.state_reasons
            .get(message_index)
            .and_then(|message| message.get(state_index))
            .and_then(|state| state.get(value))
            .copied()
            .unwrap_or(0)
    }

    pub(super) fn state_arc_reason(
        &self,
        message_index: usize,
        state_index: usize,
        value: usize,
    ) -> ArcReason {
        self.arc_state_reasons
            .get(message_index)
            .and_then(|message| message.get(state_index))
            .and_then(|state| state.get(value))
            .cloned()
            .unwrap_or_default()
    }

    pub(super) fn set_state_reason(
        &mut self,
        message_index: usize,
        state_index: usize,
        value: usize,
        reason: u128,
    ) {
        let arc_reason = self.reason_to_arc_reason(reason);
        if let Some(slot) = self
            .state_reasons
            .get_mut(message_index)
            .and_then(|message| message.get_mut(state_index))
            .and_then(|state| state.get_mut(value))
        {
            *slot |= reason;
        }
        self.set_state_arc_reason(message_index, state_index, value, &arc_reason);
    }

    pub(super) fn set_state_arc_reason(
        &mut self,
        message_index: usize,
        state_index: usize,
        value: usize,
        reason: &ArcReason,
    ) {
        if let Some(slot) = self
            .arc_state_reasons
            .get_mut(message_index)
            .and_then(|message| message.get_mut(state_index))
            .and_then(|state| state.get_mut(value))
        {
            slot.union_with(reason);
        }
    }

    pub(super) fn state_union_reason(&self, message_index: usize, state_index: usize) -> u128 {
        self.state_reasons
            .get(message_index)
            .and_then(|message| message.get(state_index))
            .into_iter()
            .flat_map(|state| state.iter().copied())
            .fold(0, |acc, reason| acc | reason)
    }

    pub(super) fn state_union_arc_reason(
        &self,
        message_index: usize,
        state_index: usize,
    ) -> ArcReason {
        self.arc_state_reasons
            .get(message_index)
            .and_then(|message| message.get(state_index))
            .into_iter()
            .flat_map(|state| state.iter())
            .fold(ArcReason::default(), |mut acc, reason| {
                acc.union_with(reason);
                acc
            })
    }

    pub(super) fn record_conflict(&mut self, reason: u128) {
        self.conflict = Some(reason);
        self.arc_conflict = Some(self.reason_to_arc_reason(reason));
        self.conflict_exclusions = 0;
    }

    pub(super) fn record_letter_conflict(&mut self, letter: char, reason: u128) {
        self.conflict = Some(reason);
        let arc_reason = self
            .reason_to_arc_reason(reason)
            .union(&self.domain_arc_reason(letter));
        self.arc_conflict = Some(arc_reason);
        self.conflict_exclusions = self.exclusion_mask([letter]);
    }

    pub(super) fn record_conflict_excluding_with_arc_reason<const N: usize>(
        &mut self,
        letters: [char; N],
        reason: u128,
        arc_reason: &ArcReason,
    ) {
        self.conflict = Some(reason);
        let merged = self.reason_to_arc_reason(reason).union(arc_reason);
        self.arc_conflict = Some(merged);
        self.conflict_exclusions = self.exclusion_mask(letters);
    }

    pub(super) fn record_conflict_with_arc_reason(&mut self, reason: u128, arc_reason: &ArcReason) {
        self.conflict = Some(reason);
        let merged = self.reason_to_arc_reason(reason).union(arc_reason);
        self.arc_conflict = Some(merged);
        self.conflict_exclusions = 0;
    }

    pub(super) fn record_letter_conflict_with_arc_reason(
        &mut self,
        letter: char,
        reason: u128,
        arc_reason: &ArcReason,
    ) {
        self.conflict = Some(reason);
        let merged = self
            .reason_to_arc_reason(reason)
            .union(&self.domain_arc_reason(letter))
            .union(arc_reason);
        self.arc_conflict = Some(merged);
        self.conflict_exclusions = self.exclusion_mask([letter]);
    }

    pub(super) fn conflict_arc_reason(&self) -> Option<ArcReason> {
        self.arc_conflict.clone()
    }

    fn exclusion_mask<const N: usize>(&self, letters: [char; N]) -> u128 {
        letters
            .into_iter()
            .filter_map(|letter| self.letter_bits.get(&letter).copied())
            .fold(0, |acc, bit| acc | bit)
    }

    fn reason_to_arc_reason(&self, reason: u128) -> ArcReason {
        self.letter_bits
            .iter()
            .filter_map(|(&letter, &bit)| {
                (reason & bit != 0).then(|| {
                    self.choices
                        .get(&letter)
                        .copied()
                        .map(|target| (letter, target))
                })?
            })
            .fold(ArcReason::default(), |mut acc, (letter, target)| {
                acc.union_with(&ArcReason::from_context_target(letter, target));
                acc
            })
    }
}

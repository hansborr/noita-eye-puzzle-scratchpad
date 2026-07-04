//! Target-level reason bookkeeping for ns=3 deterministic propagation.

use std::collections::BTreeMap;

use super::AlignedMessage;
use super::propagation::bit;
use super::residual::ResidualDomains;
use crate::attack::gak_attack::lymm_deck::LymmDeckSpec;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TargetReasonTracker {
    choices: BTreeMap<char, usize>,
    letter_bits: BTreeMap<char, u128>,
    domain_reasons: BTreeMap<char, u128>,
    state_reasons: Vec<Vec<Vec<u128>>>,
    conflict: Option<u128>,
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
        Self {
            choices: targets.clone(),
            letter_bits,
            domain_reasons,
            state_reasons,
            conflict: None,
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

    pub(super) fn add_domain_reason(&mut self, letter: char, reason: u128) {
        if let Some(slot) = self.domain_reasons.get_mut(&letter) {
            *slot |= reason;
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

    pub(super) fn set_state_reason(
        &mut self,
        message_index: usize,
        state_index: usize,
        value: usize,
        reason: u128,
    ) {
        if let Some(slot) = self
            .state_reasons
            .get_mut(message_index)
            .and_then(|message| message.get_mut(state_index))
            .and_then(|state| state.get_mut(value))
        {
            *slot |= reason;
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

    pub(super) fn record_conflict(&mut self, reason: u128) {
        self.conflict = Some(reason);
        self.conflict_exclusions = 0;
    }

    pub(super) fn record_letter_conflict(&mut self, letter: char, reason: u128) {
        self.conflict = Some(reason);
        self.conflict_exclusions = self.exclusion_mask([letter]);
    }

    pub(super) fn record_conflict_excluding<const N: usize>(
        &mut self,
        letters: [char; N],
        reason: u128,
    ) {
        self.conflict = Some(reason);
        self.conflict_exclusions = self.exclusion_mask(letters);
    }

    fn exclusion_mask<const N: usize>(&self, letters: [char; N]) -> u128 {
        letters
            .into_iter()
            .filter_map(|letter| self.letter_bits.get(&letter).copied())
            .fold(0, |acc, bit| acc | bit)
    }
}

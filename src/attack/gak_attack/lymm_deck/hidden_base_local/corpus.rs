//! Corpus normalization for hidden-base local search.

use std::collections::BTreeMap;

use super::super::{KnownPlaintextPair, LymmDeckError, LymmDeckSpec};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LocalCorpus {
    pub(super) messages: Vec<LocalMessage>,
    observed: Vec<bool>,
    pub(super) anchors: Vec<Option<usize>>,
    pub(super) pair_constraints: Vec<PairConstraint>,
    pub(super) anchor_conflict: bool,
    pub(super) event_count: usize,
}

impl LocalCorpus {
    pub(super) fn new(
        spec: &LymmDeckSpec,
        pairs: &[KnownPlaintextPair],
    ) -> Result<Self, LymmDeckError> {
        if pairs.is_empty() {
            return Err(LymmDeckError::HiddenBaseConfig {
                reason: "known-plaintext pair list must not be empty",
            });
        }
        let letter_index = spec
            .pt_alphabet
            .iter()
            .copied()
            .enumerate()
            .map(|(index, letter)| (letter, index))
            .collect::<BTreeMap<_, _>>();
        let ct_index = spec
            .ct_alphabet
            .iter()
            .copied()
            .enumerate()
            .map(|(index, letter)| (letter, index))
            .collect::<BTreeMap<_, _>>();
        let mut messages = Vec::with_capacity(pairs.len());
        let mut observed = vec![false; spec.pt_alphabet.len()];
        let mut anchors = vec![None; spec.pt_alphabet.len()];
        let mut anchor_conflict = false;
        let mut event_count = 0usize;
        for pair in pairs {
            let message = LocalMessage::new(spec, pair, &letter_index, &ct_index)?;
            if let Some(first) = message.events.first() {
                match anchors.get_mut(first.letter).and_then(Option::as_mut) {
                    Some(previous) if *previous != first.ct_value => {
                        anchor_conflict = true;
                    }
                    Some(_previous) => {}
                    None => {
                        if let Some(slot) = anchors.get_mut(first.letter) {
                            *slot = Some(first.ct_value);
                        }
                    }
                }
            }
            for event in &message.events {
                if let Some(slot) = observed.get_mut(event.letter) {
                    *slot = true;
                }
            }
            event_count = event_count.saturating_add(message.events.len());
            messages.push(message);
        }
        let mut anchor_letter_by_value = vec![None; spec.n];
        for (letter, anchor) in anchors.iter().copied().enumerate() {
            let Some(value) = anchor else {
                continue;
            };
            if let Some(slot) = anchor_letter_by_value.get_mut(value) {
                *slot = Some(letter);
            }
        }
        let pair_constraints = pair_constraints(&messages, &anchors, &anchor_letter_by_value);
        if event_count == 0 {
            return Err(LymmDeckError::HiddenBaseConfig {
                reason: "known plaintext must contain at least one alphabet symbol",
            });
        }
        Ok(Self {
            messages,
            observed,
            anchors,
            pair_constraints,
            anchor_conflict,
            event_count,
        })
    }

    pub(super) fn observed_letters(&self, spec: &LymmDeckSpec) -> Vec<char> {
        spec.pt_alphabet
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(index, letter)| {
                self.observed
                    .get(index)
                    .copied()
                    .unwrap_or(false)
                    .then_some(letter)
            })
            .collect()
    }

    pub(super) fn anchored_letters(&self, spec: &LymmDeckSpec) -> Vec<char> {
        spec.pt_alphabet
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(index, letter)| {
                self.anchors
                    .get(index)
                    .copied()
                    .flatten()
                    .map(|_target| letter)
            })
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LocalMessage {
    pub(super) events: Vec<LocalEvent>,
}

impl LocalMessage {
    fn new(
        spec: &LymmDeckSpec,
        pair: &KnownPlaintextPair,
        letter_index: &BTreeMap<char, usize>,
        ct_index: &BTreeMap<char, usize>,
    ) -> Result<Self, LymmDeckError> {
        let ciphertext = pair.ciphertext.chars().collect::<Vec<_>>();
        let plaintext_alpha_chars = pair
            .plaintext
            .chars()
            .filter(|&ch| spec.is_plaintext_char(ch))
            .count();
        if plaintext_alpha_chars != ciphertext.len() {
            return Err(LymmDeckError::MessageLengthMismatch {
                label: pair.label.clone(),
                plaintext_alpha_chars,
                ciphertext_chars: ciphertext.len(),
            });
        }
        let mut events = Vec::with_capacity(ciphertext.len());
        for (ct_position, plaintext) in pair
            .plaintext
            .chars()
            .filter(|&ch| spec.is_plaintext_char(ch))
            .enumerate()
        {
            let letter = letter_index
                .get(&plaintext)
                .copied()
                .ok_or(LymmDeckError::MissingPlaintextMapping { letter: plaintext })?;
            let ch = ciphertext.get(ct_position).copied().ok_or_else(|| {
                LymmDeckError::MessageLengthMismatch {
                    label: pair.label.clone(),
                    plaintext_alpha_chars,
                    ciphertext_chars: ciphertext.len(),
                }
            })?;
            let ct_value = ct_index.get(&ch).copied().ok_or_else(|| {
                LymmDeckError::UnknownCiphertextSymbol {
                    label: pair.label.clone(),
                    index: ct_position,
                    ch,
                }
            })?;
            events.push(LocalEvent { letter, ct_value });
        }
        Ok(Self { events })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct LocalEvent {
    pub(super) letter: usize,
    pub(super) ct_value: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PairConstraint {
    pub(super) first_letter: usize,
    pub(super) second_anchor_value: usize,
    pub(super) emitted_anchor_letter: usize,
}

fn pair_constraints(
    messages: &[LocalMessage],
    anchors: &[Option<usize>],
    anchor_letter_by_value: &[Option<usize>],
) -> Vec<PairConstraint> {
    let mut constraints = Vec::new();
    for message in messages {
        let Some(first) = message.events.first() else {
            continue;
        };
        let Some(second) = message.events.get(1) else {
            continue;
        };
        let Some(second_anchor_value) = anchors.get(second.letter).copied().flatten() else {
            continue;
        };
        let Some(emitted_anchor_letter) = anchor_letter_by_value
            .get(second.ct_value)
            .copied()
            .flatten()
        else {
            continue;
        };
        constraints.push(PairConstraint {
            first_letter: first.letter,
            second_anchor_value,
            emitted_anchor_letter,
        });
    }
    constraints
}

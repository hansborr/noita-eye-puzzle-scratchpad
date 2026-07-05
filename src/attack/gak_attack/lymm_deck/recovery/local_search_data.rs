//! Data structures for substitution-first local search.

use crate::attack::gak_attack::lymm_deck::{LymmDeckSpec, TopSwapDomains};

use super::{AlignedMessage, SwapRecoveryError};

pub(super) struct LocalCorpus {
    pub(super) messages: Vec<LocalMessage>,
    pub(super) observed_letters: Vec<usize>,
    pub(super) forced: Vec<Option<u16>>,
    pub(super) letter_count: usize,
}

impl LocalCorpus {
    pub(super) fn new(
        spec: &LymmDeckSpec,
        messages: &[AlignedMessage],
    ) -> Result<Self, SwapRecoveryError> {
        let letter_count = spec.pt_alphabet.len();
        let mut observed = vec![false; letter_count];
        let mut local_messages = Vec::with_capacity(messages.len());
        let mut forced = vec![None; letter_count];
        for message in messages {
            let mut events = Vec::with_capacity(message.events.len());
            for event in &message.events {
                let letter = spec
                    .pt_alphabet
                    .iter()
                    .position(|&candidate| candidate == event.letter)
                    .ok_or_else(|| {
                        SwapRecoveryError::SatSolver("aligned unknown letter".to_owned())
                    })?;
                if let Some(slot) = observed.get_mut(letter) {
                    *slot = true;
                }
                events.push(LocalEvent {
                    letter,
                    ct_value: u16::try_from(event.ct_value).map_err(|_error| {
                        SwapRecoveryError::SatSolver(
                            "local-search ciphertext value exceeds u16".to_owned(),
                        )
                    })?,
                });
            }
            if let Some(first) = events.first().copied() {
                let letter = spec.pt_alphabet.get(first.letter).copied().ok_or_else(|| {
                    SwapRecoveryError::SatSolver(
                        "local-search letter index out of range".to_owned(),
                    )
                })?;
                let Some(slot) = forced.get_mut(first.letter) else {
                    return Err(SwapRecoveryError::SatSolver(
                        "local-search forced index out of range".to_owned(),
                    ));
                };
                match slot.replace(first.ct_value) {
                    Some(previous) if previous != first.ct_value => {
                        return Err(SwapRecoveryError::InconsistentTarget {
                            letter,
                            previous: usize::from(previous),
                            observed: usize::from(first.ct_value),
                        });
                    }
                    Some(previous) => {
                        *slot = Some(previous);
                    }
                    None => {}
                }
            }
            local_messages.push(LocalMessage { events });
        }
        Ok(Self {
            messages: local_messages,
            observed_letters: observed
                .into_iter()
                .enumerate()
                .filter_map(|(index, is_observed)| is_observed.then_some(index))
                .collect(),
            forced,
            letter_count,
        })
    }
}

#[derive(Clone, Debug)]
pub(super) struct LocalMessage {
    pub(super) events: Vec<LocalEvent>,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct LocalEvent {
    pub(super) letter: usize,
    pub(super) ct_value: u16,
}

pub(super) struct CandidateCache {
    pub(super) n: usize,
    perms: Vec<u16>,
    pub(super) by_top: Vec<Vec<usize>>,
    pub(super) reps: Vec<usize>,
    pub(super) base_index: usize,
}

impl CandidateCache {
    pub(super) fn new(
        spec: &LymmDeckSpec,
        domains: &TopSwapDomains,
    ) -> Result<Self, SwapRecoveryError> {
        let capacity = domains
            .candidates
            .len()
            .checked_mul(spec.n)
            .ok_or_else(|| {
                SwapRecoveryError::SatSolver("local-search cache overflow".to_owned())
            })?;
        let mut perms = Vec::with_capacity(capacity);
        let mut by_top = vec![Vec::new(); spec.n];
        let mut base_index = None;
        for (index, candidate) in domains.candidates.iter().enumerate() {
            if candidate.support.is_empty() {
                base_index = Some(index);
            }
            let permutation = candidate.permutation(spec);
            for value in permutation {
                perms.push(u16::try_from(value).map_err(|_error| {
                    SwapRecoveryError::SatSolver("local-search permutation exceeds u16".to_owned())
                })?);
            }
            let top = usize::from(self_top(&perms, spec.n, index));
            if let Some(bucket) = by_top.get_mut(top) {
                bucket.push(index);
            }
        }
        let mut reps = Vec::new();
        for bucket in &by_top {
            if let Some(&candidate) = bucket.iter().min_by_key(|&&index| {
                let word_len = domains
                    .candidates
                    .get(index)
                    .map_or(usize::MAX, |candidate| candidate.canonical_swaps.len());
                (word_len, index)
            }) {
                reps.push(candidate);
            }
        }
        Ok(Self {
            n: spec.n,
            perms,
            by_top,
            reps,
            base_index: base_index.unwrap_or(0),
        })
    }

    pub(super) fn perm(&self, candidate: usize) -> &[u16] {
        let start = candidate.saturating_mul(self.n);
        let end = start.saturating_add(self.n);
        self.perms.get(start..end).unwrap_or(&[])
    }

    pub(super) fn candidate_top(&self, candidate: usize) -> Option<usize> {
        self.perm(candidate).first().copied().map(usize::from)
    }

    pub(super) fn bucket_for_top(&self, top: usize) -> &[usize] {
        self.by_top.get(top).map_or(&[], Vec::as_slice)
    }

    pub(super) fn apply(&self, candidate: usize, state: &[u16], out: &mut [u16]) {
        for (slot, &source) in out.iter_mut().zip(self.perm(candidate)) {
            *slot = state.get(usize::from(source)).copied().unwrap_or(0);
        }
    }
}

pub(super) struct Scorer {
    cur: Vec<u16>,
    nxt: Vec<u16>,
}

impl Scorer {
    pub(super) fn new(n: usize) -> Self {
        Self {
            cur: vec![0; n],
            nxt: vec![0; n],
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "hot scoring path keeps parameters explicit to avoid temporary structs"
    )]
    pub(super) fn mismatch(
        &mut self,
        assignment: &[usize],
        corpus: &LocalCorpus,
        cache: &CandidateCache,
        override_letter: Option<usize>,
        override_candidate: usize,
        prefix: usize,
        stop_after: u32,
    ) -> u32 {
        let mut mismatches = 0u32;
        for message in &corpus.messages {
            reset_identity(&mut self.cur);
            let limit = if prefix == 0 {
                message.events.len()
            } else {
                prefix.min(message.events.len())
            };
            for event in message.events.iter().take(limit) {
                let candidate = if override_letter == Some(event.letter) {
                    override_candidate
                } else {
                    assignment
                        .get(event.letter)
                        .copied()
                        .unwrap_or(cache.base_index)
                };
                cache.apply(candidate, &self.cur, &mut self.nxt);
                std::mem::swap(&mut self.cur, &mut self.nxt);
                if self.cur.first().copied().unwrap_or(u16::MAX) != event.ct_value {
                    mismatches = mismatches.saturating_add(1);
                    if mismatches > stop_after {
                        return mismatches;
                    }
                }
            }
        }
        mismatches
    }
}

pub(super) fn reset_identity(values: &mut [u16]) {
    for (index, slot) in values.iter_mut().enumerate() {
        *slot = u16::try_from(index).unwrap_or(u16::MAX);
    }
}

fn self_top(perms: &[u16], n: usize, candidate: usize) -> u16 {
    let index = candidate.saturating_mul(n);
    perms.get(index).copied().unwrap_or(0)
}

//! Private search machinery for hidden-base `s = 1` known-plaintext recovery.

use std::collections::BTreeMap;

use super::hidden_base_s1::{HiddenBaseS1RecoveredKey, HiddenBaseS1SolverConfig};
use super::{
    HiddenBaseRoundTrip, KnownPlaintextPair, LymmDeckError, LymmDeckSpec, encrypt_lymm_deck,
};

pub(super) struct S1Search<'a> {
    pub(super) config: &'a HiddenBaseS1SolverConfig,
    spec: &'a LymmDeckSpec,
    corpus: &'a S1Corpus,
    planted_base: Option<&'a [usize]>,
    pub(super) base_candidates_tested: usize,
    pub(super) exact_candidate_count: usize,
    pub(super) planted_base_recovered: Option<bool>,
    pub(super) search_cap_exceeded: bool,
    pub(super) representative_key: Option<HiddenBaseS1RecoveredKey>,
}

impl<'a> S1Search<'a> {
    pub(super) fn new(
        config: &'a HiddenBaseS1SolverConfig,
        spec: &'a LymmDeckSpec,
        corpus: &'a S1Corpus,
        planted_base: Option<&'a [usize]>,
    ) -> Self {
        Self {
            config,
            spec,
            corpus,
            planted_base,
            base_candidates_tested: 0,
            exact_candidate_count: 0,
            planted_base_recovered: planted_base.map(|_| false),
            search_cap_exceeded: false,
            representative_key: None,
        }
    }

    pub(super) fn run(&mut self) -> Result<(), LymmDeckError> {
        let mut base = (0..self.config.n).collect::<Vec<_>>();
        loop {
            if self
                .config
                .max_base_candidates
                .is_some_and(|cap| self.base_candidates_tested >= cap)
            {
                self.search_cap_exceeded = true;
                break;
            }
            self.base_candidates_tested = self.base_candidates_tested.saturating_add(1);
            self.try_base(&base)?;
            if !next_permutation(&mut base) {
                break;
            }
        }
        Ok(())
    }

    fn try_base(&mut self, base: &[usize]) -> Result<(), LymmDeckError> {
        let Some(letter_swaps) =
            derive_letter_swaps(base, self.corpus, self.spec.pt_alphabet.len())
        else {
            return Ok(());
        };
        let key = recovered_key(self.spec, base, &letter_swaps);
        let round_trip = exact_round_trip_compressed(self.spec, &key.pt_mapping, self.corpus)?;
        if !round_trip.exact {
            return Ok(());
        }
        self.exact_candidate_count = self.exact_candidate_count.saturating_add(1);
        if self
            .planted_base
            .is_some_and(|planted| planted == key.base.as_slice())
        {
            self.planted_base_recovered = Some(true);
        }
        if self.representative_key.is_none() {
            self.representative_key = Some(key);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct S1Corpus {
    messages: Vec<S1Message>,
    observed: Vec<bool>,
    pub(super) event_count: usize,
}

impl S1Corpus {
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
        let mut event_count = 0usize;
        for pair in pairs {
            let message = S1Message::new(spec, pair, &letter_index, &ct_index)?;
            for event in &message.events {
                if let Some(slot) = observed.get_mut(event.letter) {
                    *slot = true;
                }
            }
            event_count = event_count.saturating_add(message.events.len());
            messages.push(message);
        }
        if event_count == 0 {
            return Err(LymmDeckError::HiddenBaseConfig {
                reason: "known plaintext must contain at least one alphabet symbol",
            });
        }
        Ok(Self {
            messages,
            observed,
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
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct S1Message {
    events: Vec<S1Event>,
}

impl S1Message {
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
            events.push(S1Event { letter, ct_value });
        }
        Ok(Self { events })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct S1Event {
    letter: usize,
    ct_value: usize,
}

fn derive_letter_swaps(
    base: &[usize],
    corpus: &S1Corpus,
    letter_count: usize,
) -> Option<Vec<usize>> {
    let inverse_base = invert_permutation(base);
    let mut letter_swaps = vec![None; letter_count];
    let mut state = vec![0usize; base.len()];
    let mut next = vec![0usize; base.len()];
    for message in &corpus.messages {
        reset_identity(&mut state);
        for event in &message.events {
            let swap_index = if let Some(index) = letter_swaps.get(event.letter).copied().flatten()
            {
                index
            } else {
                let target_position = inverse_position(&state, event.ct_value)?;
                let index = inverse_base.get(target_position).copied()?;
                if let Some(slot) = letter_swaps.get_mut(event.letter) {
                    *slot = Some(index);
                }
                index
            };
            apply_base_top_swap(base, swap_index, &state, &mut next);
            if next.first().copied() != Some(event.ct_value) {
                return None;
            }
            std::mem::swap(&mut state, &mut next);
        }
    }
    Some(
        letter_swaps
            .into_iter()
            .map(|swap| swap.unwrap_or(0))
            .collect(),
    )
}

fn recovered_key(
    spec: &LymmDeckSpec,
    base: &[usize],
    letter_swaps: &[usize],
) -> HiddenBaseS1RecoveredKey {
    let mut pt_mapping = BTreeMap::new();
    let mut swaps = BTreeMap::new();
    for (index, &letter) in spec.pt_alphabet.iter().enumerate() {
        let swap_index = letter_swaps.get(index).copied().unwrap_or(0);
        let _old_perm = pt_mapping.insert(letter, permutation_for_base_top_swap(base, swap_index));
        let _old_swap = swaps.insert(letter, swap_index);
    }
    HiddenBaseS1RecoveredKey {
        base: base.to_vec(),
        pt_mapping,
        letter_swaps: swaps,
    }
}

fn exact_round_trip_compressed(
    spec: &LymmDeckSpec,
    pt_mapping: &BTreeMap<char, Vec<usize>>,
    corpus: &S1Corpus,
) -> Result<HiddenBaseRoundTrip, LymmDeckError> {
    let mut matched = 0usize;
    let mut total = 0usize;
    let mut exact = true;
    for message in &corpus.messages {
        let plaintext = message
            .events
            .iter()
            .filter_map(|event| spec.pt_alphabet.get(event.letter).copied())
            .collect::<String>();
        let expected = message
            .events
            .iter()
            .filter_map(|event| spec.ct_alphabet.get(event.ct_value).copied())
            .collect::<Vec<_>>();
        let encrypted = encrypt_lymm_deck(spec, pt_mapping, &plaintext)?;
        let actual = encrypted.chars().collect::<Vec<_>>();
        total = total.saturating_add(expected.len().max(actual.len()));
        matched = matched.saturating_add(
            expected
                .iter()
                .zip(&actual)
                .filter(|(left, right)| left == right)
                .count(),
        );
        exact &= expected == actual;
    }
    Ok(HiddenBaseRoundTrip {
        matched,
        total,
        exact,
    })
}

fn apply_base_top_swap(base: &[usize], swap_index: usize, state: &[usize], out: &mut [usize]) {
    for (position, slot) in out.iter_mut().enumerate() {
        let source = if position == 0 {
            swap_index
        } else if position == swap_index {
            0
        } else {
            position
        };
        *slot = base
            .get(source)
            .and_then(|&base_source| state.get(base_source))
            .copied()
            .unwrap_or(0);
    }
}

fn permutation_for_base_top_swap(base: &[usize], swap_index: usize) -> Vec<usize> {
    let mut permutation = base.to_vec();
    if swap_index < permutation.len() {
        permutation.swap(0, swap_index);
    }
    permutation
}

fn reset_identity(values: &mut [usize]) {
    for (index, slot) in values.iter_mut().enumerate() {
        *slot = index;
    }
}

fn inverse_position(values: &[usize], target: usize) -> Option<usize> {
    values.iter().position(|&value| value == target)
}

fn invert_permutation(perm: &[usize]) -> Vec<usize> {
    let mut inverse = vec![0usize; perm.len()];
    for (position, &image) in perm.iter().enumerate() {
        if let Some(slot) = inverse.get_mut(image) {
            *slot = position;
        }
    }
    inverse
}

fn next_permutation(values: &mut [usize]) -> bool {
    if values.len() < 2 {
        return false;
    }
    let Some(pivot) = (0..values.len() - 1)
        .rev()
        .find(|&index| values.get(index) < values.get(index + 1))
    else {
        return false;
    };
    let Some(successor) = (pivot + 1..values.len())
        .rev()
        .find(|&index| values.get(pivot) < values.get(index))
    else {
        return false;
    };
    values.swap(pivot, successor);
    if let Some(suffix) = values.get_mut(pivot.saturating_add(1)..) {
        suffix.reverse();
    }
    true
}

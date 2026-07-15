//! Objective scoring and representative-key reconstruction for local recovery.

use std::collections::BTreeMap;

use super::super::LymmDeckSpec;
use super::HiddenBaseLocalRecoveredKey;
use super::corpus::LocalCorpus;
use super::search::SigmaDomain;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LocalScore {
    pub(super) objective: usize,
    pub(super) mismatches: usize,
    pub(super) base: Option<Vec<usize>>,
}

pub(super) fn pair_constraint_mismatches(
    corpus: &LocalCorpus,
    domain: &SigmaDomain,
    assignment: &[usize],
) -> usize {
    let mut mismatches = 0usize;
    for constraint in &corpus.pair_constraints {
        let Some(first_candidate) = domain.candidates.get(
            assignment
                .get(constraint.first_letter)
                .copied()
                .unwrap_or(0),
        ) else {
            mismatches = mismatches.saturating_add(1);
            continue;
        };
        let Some(&required_top_source) = first_candidate.sigma.get(constraint.second_anchor_value)
        else {
            mismatches = mismatches.saturating_add(1);
            continue;
        };
        let Some(emitted_candidate) = domain.candidates.get(
            assignment
                .get(constraint.emitted_anchor_letter)
                .copied()
                .unwrap_or(0),
        ) else {
            mismatches = mismatches.saturating_add(1);
            continue;
        };
        if emitted_candidate.top_source != required_top_source {
            mismatches = mismatches.saturating_add(1);
        }
    }
    mismatches
}

pub(super) fn derive_base(
    n: usize,
    corpus: &LocalCorpus,
    domain: &SigmaDomain,
    assignment: &[usize],
) -> Option<Vec<usize>> {
    if corpus.anchor_conflict {
        return None;
    }
    let mut base = vec![None; n];
    let mut value_owner = vec![None; n];
    for (letter, anchor) in corpus.anchors.iter().copied().enumerate() {
        let Some(target) = anchor else {
            continue;
        };
        let candidate = domain
            .candidates
            .get(assignment.get(letter).copied().unwrap_or(0))?;
        let top_source = candidate.top_source;
        if top_source >= n || target >= n {
            return None;
        }
        match base.get_mut(top_source)? {
            Some(existing) if *existing != target => return None,
            Some(_existing) => {}
            slot @ None => {
                if value_owner.get(target).copied().flatten().is_some() {
                    return None;
                }
                *slot = Some(target);
                if let Some(owner) = value_owner.get_mut(target) {
                    *owner = Some(top_source);
                }
            }
        }
    }
    let mut remaining_values = (0..n)
        .filter(|&value| value_owner.get(value).copied().flatten().is_none())
        .collect::<Vec<_>>();
    remaining_values.reverse();
    for slot in &mut base {
        if slot.is_none() {
            *slot = remaining_values.pop();
        }
    }
    base.into_iter().collect()
}

pub(super) fn recovered_key(
    spec: &LymmDeckSpec,
    base: &[usize],
    domain: &SigmaDomain,
    assignment: &[usize],
) -> HiddenBaseLocalRecoveredKey {
    let mut pt_mapping = BTreeMap::new();
    let mut swaps = BTreeMap::new();
    for (index, &letter) in spec.pt_alphabet.iter().enumerate() {
        let candidate = domain
            .candidates
            .get(assignment.get(index).copied().unwrap_or(0));
        let sigma =
            candidate.map_or_else(|| identity_permutation(spec.n), |found| found.sigma.clone());
        let _old_perm = pt_mapping.insert(letter, permutation_for_base_sigma(base, &sigma));
        let _old_swaps = swaps.insert(
            letter,
            candidate.map_or_else(Vec::new, |found| found.canonical_swaps.clone()),
        );
    }
    HiddenBaseLocalRecoveredKey {
        base: base.to_vec(),
        pt_mapping,
        letter_swaps: swaps,
    }
}

pub(super) fn apply_base_sigma(
    base: &[usize],
    sigma: &[usize],
    state: &[usize],
    out: &mut [usize],
) {
    for (position, slot) in out.iter_mut().enumerate() {
        *slot = sigma
            .get(position)
            .and_then(|&source| base.get(source))
            .and_then(|&base_source| state.get(base_source))
            .copied()
            .unwrap_or(0);
    }
}

fn permutation_for_base_sigma(base: &[usize], sigma: &[usize]) -> Vec<usize> {
    sigma
        .iter()
        .filter_map(|&source| base.get(source).copied())
        .collect()
}

fn identity_permutation(n: usize) -> Vec<usize> {
    (0..n).collect()
}

pub(super) fn reset_identity(values: &mut [usize]) {
    for (index, slot) in values.iter_mut().enumerate() {
        *slot = index;
    }
}

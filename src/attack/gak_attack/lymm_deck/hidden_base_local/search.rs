//! Search internals for hidden-base local recovery.

use std::collections::{BTreeMap, BTreeSet};

use crate::nulls::null::{SplitMix64, random_index_below};

use super::super::{
    HiddenBaseRoundTrip, KnownPlaintextPair, LymmDeckError, LymmDeckSpec, TopSwapConstraints,
    enumerate_top_swap_domains,
};
use super::corpus::LocalCorpus;
use super::{HiddenBaseLocalRecoveredKey, HiddenBaseLocalSolverConfig};

pub(super) struct LocalSearchOutput {
    pub(super) sigma_domain_size: usize,
    pub(super) attempts_run: usize,
    pub(super) candidate_evaluations: usize,
    pub(super) exact_candidate_count: usize,
    pub(super) planted_base_recovered: Option<bool>,
    pub(super) observed_letters: Vec<char>,
    pub(super) anchored_letters: Vec<char>,
    pub(super) event_count: usize,
    pub(super) best_mismatches: usize,
    pub(super) best_round_trip: HiddenBaseRoundTrip,
    pub(super) representative_key: Option<HiddenBaseLocalRecoveredKey>,
}

pub(super) fn run_local_search(
    config: &HiddenBaseLocalSolverConfig,
    spec: &LymmDeckSpec,
    pairs: &[KnownPlaintextPair],
    planted_base: Option<&[usize]>,
) -> Result<LocalSearchOutput, LymmDeckError> {
    let corpus = LocalCorpus::new(spec, pairs)?;
    let candidates = sigma_candidates(spec, config.swap_budget)?;
    let sigma_domain_size = candidates.candidates.len();
    let observed_letters = corpus.observed_letters(spec);
    let anchored_letters = corpus.anchored_letters(spec);
    let event_count = corpus.event_count;
    let mut search = LocalSearch::new(config, spec, &corpus, &candidates, planted_base);
    search.run()?;
    Ok(LocalSearchOutput {
        sigma_domain_size,
        attempts_run: search.attempts_run,
        candidate_evaluations: search.candidate_evaluations,
        exact_candidate_count: search.exact_bases.len(),
        planted_base_recovered: search.planted_base_recovered,
        observed_letters,
        anchored_letters,
        event_count,
        best_mismatches: search.best_mismatches,
        best_round_trip: search.best_round_trip(),
        representative_key: search.representative_key,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SigmaCandidate {
    sigma: Vec<usize>,
    canonical_swaps: Vec<usize>,
    top_source: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SigmaDomain {
    candidates: Vec<SigmaCandidate>,
    by_top_source: Vec<Vec<usize>>,
    simplest_by_top_source: Vec<Option<usize>>,
}

fn sigma_candidates(spec: &LymmDeckSpec, swap_budget: usize) -> Result<SigmaDomain, LymmDeckError> {
    let domains = enumerate_top_swap_domains(spec, &TopSwapConstraints::up_to(swap_budget))?;
    let mut candidates = Vec::with_capacity(domains.candidates.len());
    let mut by_top_source = vec![Vec::new(); spec.n];
    for candidate in domains.candidates {
        let sigma = candidate.sigma_permutation(spec.n);
        let top_source = sigma.first().copied().unwrap_or(0);
        let index = candidates.len();
        if let Some(bucket) = by_top_source.get_mut(top_source) {
            bucket.push(index);
        }
        candidates.push(SigmaCandidate {
            sigma,
            canonical_swaps: candidate.canonical_swaps,
            top_source,
        });
    }
    let simplest_by_top_source = by_top_source
        .iter()
        .map(|bucket| {
            bucket.iter().copied().min_by_key(|&index| {
                candidates
                    .get(index)
                    .map_or((usize::MAX, index), |candidate| {
                        (candidate.canonical_swaps.len(), index)
                    })
            })
        })
        .collect();
    Ok(SigmaDomain {
        candidates,
        by_top_source,
        simplest_by_top_source,
    })
}

struct LocalSearch<'a> {
    config: &'a HiddenBaseLocalSolverConfig,
    spec: &'a LymmDeckSpec,
    corpus: &'a LocalCorpus,
    domain: &'a SigmaDomain,
    planted_base: Option<&'a [usize]>,
    attempts_run: usize,
    candidate_evaluations: usize,
    best_mismatches: usize,
    exact_bases: BTreeSet<Vec<usize>>,
    planted_base_recovered: Option<bool>,
    representative_key: Option<HiddenBaseLocalRecoveredKey>,
}

impl<'a> LocalSearch<'a> {
    fn new(
        config: &'a HiddenBaseLocalSolverConfig,
        spec: &'a LymmDeckSpec,
        corpus: &'a LocalCorpus,
        domain: &'a SigmaDomain,
        planted_base: Option<&'a [usize]>,
    ) -> Self {
        Self {
            config,
            spec,
            corpus,
            domain,
            planted_base,
            attempts_run: 0,
            candidate_evaluations: 0,
            best_mismatches: usize::MAX,
            exact_bases: BTreeSet::new(),
            planted_base_recovered: planted_base.map(|_| false),
            representative_key: None,
        }
    }

    fn run(&mut self) -> Result<(), LymmDeckError> {
        let observed = self.corpus.observed_letters(self.spec);
        let mut rng = SplitMix64::new(self.config.seed);
        for attempt in 0..self.config.attempts {
            self.attempts_run = attempt.saturating_add(1);
            let mut assignment = self.seed_assignment(attempt, &mut rng)?;
            let mut score = self.score_assignment(&assignment, usize::MAX);
            for _round in 0..self.config.max_rounds {
                let mut improved = false;
                for &letter in &observed {
                    let Some(letter_index) =
                        self.spec.pt_alphabet.iter().position(|&ch| ch == letter)
                    else {
                        continue;
                    };
                    let current = assignment.get(letter_index).copied().unwrap_or(0);
                    let mut best_candidate = current;
                    let mut best_score = score.clone();
                    for candidate_index in 0..self.domain.candidates.len() {
                        if candidate_index == current {
                            continue;
                        }
                        if let Some(slot) = assignment.get_mut(letter_index) {
                            *slot = candidate_index;
                        }
                        let candidate_score =
                            self.score_assignment(&assignment, best_score.mismatches);
                        if candidate_score.objective < best_score.objective {
                            best_candidate = candidate_index;
                            best_score = candidate_score;
                        }
                    }
                    if let Some(slot) = assignment.get_mut(letter_index) {
                        *slot = best_candidate;
                    }
                    if best_candidate != current {
                        score = best_score;
                        improved = true;
                    }
                }
                if !improved || score.mismatches == 0 {
                    break;
                }
            }
            let final_score = self.score_assignment(&assignment, usize::MAX);
            self.record_score(&assignment, &final_score);
            if self.planted_base_recovered == Some(true) {
                break;
            }
        }
        Ok(())
    }

    fn seed_assignment(
        &self,
        attempt: usize,
        rng: &mut SplitMix64,
    ) -> Result<Vec<usize>, LymmDeckError> {
        let mut assignment = vec![0; self.spec.pt_alphabet.len()];
        let mut top_sources = (0..self.config.n).collect::<Vec<_>>();
        if attempt <= 1 {
            if attempt == 1 {
                top_sources.rotate_left(1);
            }
        } else {
            fisher_yates(&mut top_sources, rng)?;
        }
        let mut top_cursor = 0usize;
        for (letter, slot) in assignment.iter_mut().enumerate() {
            let top_source = if let Some(anchor) =
                self.corpus.anchors.get(letter).copied().flatten()
                && attempt == 0
            {
                anchor
            } else {
                let source = top_sources
                    .get(top_cursor % top_sources.len().max(1))
                    .copied()
                    .unwrap_or(0);
                top_cursor = top_cursor.saturating_add(1);
                source
            };
            let bucket = self
                .domain
                .by_top_source
                .get(top_source)
                .filter(|bucket| !bucket.is_empty());
            *slot = if attempt <= 1 {
                self.domain
                    .simplest_by_top_source
                    .get(top_source)
                    .copied()
                    .flatten()
                    .unwrap_or(0)
            } else if let Some(bucket) = bucket {
                let index = random_index_below(bucket.len(), rng)?;
                bucket.get(index).copied().unwrap_or(0)
            } else {
                random_index_below(self.domain.candidates.len(), rng)?
            };
        }
        Ok(assignment)
    }

    fn score_assignment(&mut self, assignment: &[usize], stop_after: usize) -> LocalScore {
        self.candidate_evaluations = self.candidate_evaluations.saturating_add(1);
        let Some(base) = derive_base(self.config.n, self.corpus, self.domain, assignment) else {
            return LocalScore {
                objective: usize::MAX / 4,
                mismatches: self.corpus.event_count.saturating_add(1),
                base: None,
            };
        };
        let pair_penalty = if self.config.swap_budget >= 3 {
            pair_constraint_mismatches(self.corpus, self.domain, assignment)
        } else {
            0
        };
        let mut mismatches = 0usize;
        let mut state = vec![0; self.config.n];
        let mut next = vec![0; self.config.n];
        for message in &self.corpus.messages {
            reset_identity(&mut state);
            for event in &message.events {
                let candidate_index = assignment.get(event.letter).copied().unwrap_or(0);
                let Some(candidate) = self.domain.candidates.get(candidate_index) else {
                    mismatches = mismatches.saturating_add(1);
                    continue;
                };
                apply_base_sigma(&base, &candidate.sigma, &state, &mut next);
                if next.first().copied() != Some(event.ct_value) {
                    mismatches = mismatches.saturating_add(1);
                    if mismatches > stop_after {
                        return LocalScore {
                            objective: mismatches.saturating_add(
                                pair_penalty.saturating_mul(self.corpus.event_count.max(1)),
                            ),
                            mismatches,
                            base: Some(base),
                        };
                    }
                }
                std::mem::swap(&mut state, &mut next);
            }
        }
        LocalScore {
            objective: mismatches
                .saturating_add(pair_penalty.saturating_mul(self.corpus.event_count.max(1))),
            mismatches,
            base: Some(base),
        }
    }

    fn record_score(&mut self, assignment: &[usize], score: &LocalScore) {
        self.best_mismatches = self.best_mismatches.min(score.mismatches);
        if score.mismatches != 0 {
            return;
        }
        let Some(base) = &score.base else {
            return;
        };
        let key = recovered_key(self.spec, base, self.domain, assignment);
        let is_new = self.exact_bases.insert(base.clone());
        if self
            .planted_base
            .is_some_and(|planted| planted == key.base.as_slice())
        {
            self.planted_base_recovered = Some(true);
        }
        if is_new && self.representative_key.is_none() {
            self.representative_key = Some(key);
        }
    }

    fn best_round_trip(&self) -> HiddenBaseRoundTrip {
        let matched = self
            .corpus
            .event_count
            .saturating_sub(self.best_mismatches.min(self.corpus.event_count));
        HiddenBaseRoundTrip {
            matched,
            total: self.corpus.event_count,
            exact: matched == self.corpus.event_count,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LocalScore {
    objective: usize,
    mismatches: usize,
    base: Option<Vec<usize>>,
}

fn pair_constraint_mismatches(
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

fn derive_base(
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

fn recovered_key(
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

fn apply_base_sigma(base: &[usize], sigma: &[usize], state: &[usize], out: &mut [usize]) {
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

fn reset_identity(values: &mut [usize]) {
    for (index, slot) in values.iter_mut().enumerate() {
        *slot = index;
    }
}

fn fisher_yates(values: &mut [usize], rng: &mut SplitMix64) -> Result<(), LymmDeckError> {
    let mut unswapped = values.len();
    while unswapped > 1 {
        let last = unswapped - 1;
        let partner = random_index_below(unswapped, rng)?;
        values.swap(last, partner);
        unswapped = last;
    }
    Ok(())
}

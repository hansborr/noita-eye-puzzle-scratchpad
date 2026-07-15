//! Search internals for hidden-base local recovery.

use std::collections::{BTreeMap, BTreeSet};

use crate::nulls::null::{SplitMix64, random_index_below};

use super::super::{
    HiddenBaseRoundTrip, KnownPlaintextPair, LymmDeckError, LymmDeckSpec, TopSwapConstraints,
    enumerate_top_swap_domains,
};
use super::corpus::LocalCorpus;
use super::joint::best_joint_move;
use super::top_source::build_top_source_beam;
use super::{HiddenBaseLocalRecoveredKey, HiddenBaseLocalSolverConfig};

pub(super) struct LocalSearchOutput {
    pub(super) sigma_domain_size: usize,
    pub(super) attempts_run: usize,
    pub(super) candidate_evaluations: usize,
    pub(super) joint_move_candidate_evaluations: usize,
    pub(super) joint_moves_accepted: usize,
    pub(super) top_source_hypotheses_retained: usize,
    pub(super) planted_top_source_hypothesis_rank: Option<usize>,
    pub(super) planted_top_source_hypothesis_retained: Option<bool>,
    pub(super) top_source_states_expanded: usize,
    pub(super) top_source_states_pruned: usize,
    pub(super) top_source_states_dropped: usize,
    pub(super) top_source_constraint_evaluations: usize,
    pub(super) top_source_elapsed: std::time::Duration,
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
    let planted_sources = planted_base.map(|base| planted_top_sources(base, &corpus));
    let top_source_beam = build_top_source_beam(
        config.n,
        spec.pt_alphabet.len(),
        config.top_source_beam_width,
        config.attempts,
        &corpus,
        &candidates,
        planted_sources.as_deref(),
    );
    let mut search = LocalSearch::new(
        config,
        spec,
        &corpus,
        &candidates,
        &top_source_beam.hypotheses,
        planted_base,
    );
    search.run()?;
    Ok(LocalSearchOutput {
        sigma_domain_size,
        attempts_run: search.attempts_run,
        candidate_evaluations: search.candidate_evaluations,
        joint_move_candidate_evaluations: search.joint_move_candidate_evaluations,
        joint_moves_accepted: search.joint_moves_accepted,
        top_source_hypotheses_retained: top_source_beam.hypotheses.len(),
        planted_top_source_hypothesis_rank: top_source_beam.planted_hypothesis_rank,
        planted_top_source_hypothesis_retained: top_source_beam.planted_hypothesis_retained,
        top_source_states_expanded: top_source_beam.states_expanded,
        top_source_states_pruned: top_source_beam.states_pruned,
        top_source_states_dropped: top_source_beam.states_dropped,
        top_source_constraint_evaluations: top_source_beam.constraint_evaluations,
        top_source_elapsed: top_source_beam.elapsed,
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

fn planted_top_sources(base: &[usize], corpus: &LocalCorpus) -> Vec<Option<usize>> {
    let mut inverse = vec![0; base.len()];
    for (source, &target) in base.iter().enumerate() {
        if let Some(slot) = inverse.get_mut(target) {
            *slot = source;
        }
    }
    corpus
        .anchors
        .iter()
        .map(|anchor| anchor.and_then(|target| inverse.get(target).copied()))
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SigmaCandidate {
    pub(super) sigma: Vec<usize>,
    canonical_swaps: Vec<usize>,
    top_source: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SigmaDomain {
    pub(super) candidates: Vec<SigmaCandidate>,
    pub(super) by_top_source: Vec<Vec<usize>>,
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
    Ok(SigmaDomain {
        candidates,
        by_top_source,
    })
}

pub(super) struct LocalSearch<'a> {
    pub(super) config: &'a HiddenBaseLocalSolverConfig,
    pub(super) spec: &'a LymmDeckSpec,
    pub(super) corpus: &'a LocalCorpus,
    pub(super) domain: &'a SigmaDomain,
    top_source_hypotheses: &'a [Vec<Option<usize>>],
    planted_base: Option<&'a [usize]>,
    attempts_run: usize,
    candidate_evaluations: usize,
    pub(super) joint_move_candidate_evaluations: usize,
    joint_moves_accepted: usize,
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
        top_source_hypotheses: &'a [Vec<Option<usize>>],
        planted_base: Option<&'a [usize]>,
    ) -> Self {
        Self {
            config,
            spec,
            corpus,
            domain,
            top_source_hypotheses,
            planted_base,
            attempts_run: 0,
            candidate_evaluations: 0,
            joint_move_candidate_evaluations: 0,
            joint_moves_accepted: 0,
            best_mismatches: corpus.event_count,
            exact_bases: BTreeSet::new(),
            planted_base_recovered: planted_base.map(|_| false),
            representative_key: None,
        }
    }

    fn run(&mut self) -> Result<(), LymmDeckError> {
        let observed = self.corpus.observed_letters(self.spec);
        if self.top_source_hypotheses.is_empty() {
            return Ok(());
        }
        let mut rng = SplitMix64::new(self.config.seed);
        for attempt in 0..self.config.attempts {
            self.attempts_run = attempt.saturating_add(1);
            let hypothesis_index = attempt % self.top_source_hypotheses.len();
            let hypothesis: &[Option<usize>] = self
                .top_source_hypotheses
                .get(hypothesis_index)
                .map_or(&[], Vec::as_slice);
            let hypothesis_visit = attempt / self.top_source_hypotheses.len();
            let mut assignment = self.seed_assignment(hypothesis, hypothesis_visit, &mut rng)?;
            let mut score = self.score_assignment(&assignment, usize::MAX);
            let mut joint_evaluations = 0usize;
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
                    let candidate_indices = self.candidates_for_letter(letter_index, hypothesis);
                    for candidate_index in candidate_indices {
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
                if score.mismatches == 0 {
                    break;
                }
                if !improved {
                    let joint_move = best_joint_move(
                        self,
                        &mut assignment,
                        &score,
                        &observed,
                        hypothesis,
                        &mut joint_evaluations,
                    );
                    let Some(joint_move) = joint_move else {
                        break;
                    };
                    if let Some(slot) = assignment.get_mut(joint_move.left_letter) {
                        *slot = joint_move.left_candidate;
                    }
                    if let Some(slot) = assignment.get_mut(joint_move.right_letter) {
                        *slot = joint_move.right_candidate;
                    }
                    score = joint_move.score;
                    self.joint_moves_accepted = self.joint_moves_accepted.saturating_add(1);
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
        hypothesis: &[Option<usize>],
        hypothesis_visit: usize,
        rng: &mut SplitMix64,
    ) -> Result<Vec<usize>, LymmDeckError> {
        let mut assignment = vec![0; self.spec.pt_alphabet.len()];
        for (letter, slot) in assignment.iter_mut().enumerate() {
            let candidates = self.candidates_for_letter(letter, hypothesis);
            *slot = if hypothesis_visit == 0 {
                candidates
                    .iter()
                    .copied()
                    .min_by_key(|&index| {
                        self.domain
                            .candidates
                            .get(index)
                            .map_or((usize::MAX, index), |candidate| {
                                (candidate.canonical_swaps.len(), index)
                            })
                    })
                    .unwrap_or(0)
            } else if !candidates.is_empty() {
                let index = random_index_below(candidates.len(), rng)?;
                candidates.get(index).copied().unwrap_or(0)
            } else {
                random_index_below(self.domain.candidates.len(), rng)?
            };
        }
        Ok(assignment)
    }

    pub(super) fn candidates_for_letter(
        &self,
        letter: usize,
        hypothesis: &[Option<usize>],
    ) -> Vec<usize> {
        let mut candidates = hypothesis
            .get(letter)
            .copied()
            .flatten()
            .and_then(|source| self.domain.by_top_source.get(source))
            .cloned()
            .unwrap_or_else(|| (0..self.domain.candidates.len()).collect());
        candidates
            .retain(|&candidate| self.candidate_matches_hypothesis(letter, candidate, hypothesis));
        candidates
    }

    fn candidate_matches_hypothesis(
        &self,
        letter: usize,
        candidate_index: usize,
        hypothesis: &[Option<usize>],
    ) -> bool {
        let Some(candidate) = self.domain.candidates.get(candidate_index) else {
            return false;
        };
        self.corpus
            .pair_constraints
            .iter()
            .filter(|constraint| constraint.first_letter == letter)
            .all(|constraint| {
                let emitted_source = hypothesis
                    .get(constraint.emitted_anchor_letter)
                    .copied()
                    .flatten();
                emitted_source.is_none()
                    || candidate.sigma.get(constraint.second_anchor_value).copied()
                        == emitted_source
            })
    }

    pub(super) fn score_assignment(
        &mut self,
        assignment: &[usize],
        stop_after: usize,
    ) -> LocalScore {
        self.candidate_evaluations = self.candidate_evaluations.saturating_add(1);
        let Some(base) = derive_base(self.config.n, self.corpus, self.domain, assignment) else {
            return LocalScore {
                objective: usize::MAX / 4,
                mismatches: self.corpus.event_count.saturating_add(1),
                base: None,
            };
        };
        let pair_penalty = pair_constraint_mismatches(self.corpus, self.domain, assignment);
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
pub(super) struct LocalScore {
    pub(super) objective: usize,
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

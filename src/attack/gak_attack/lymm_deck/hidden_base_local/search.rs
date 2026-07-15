//! Search internals for hidden-base local recovery.

use std::collections::{BTreeMap, BTreeSet};

use crate::nulls::null::{SplitMix64, random_index_below};

use super::super::{
    HiddenBaseRoundTrip, KnownPlaintextPair, LymmDeckError, LymmDeckSpec, TopSwapConstraints,
    enumerate_top_swap_domains,
};
use super::corpus::LocalCorpus;
use super::joint::best_joint_move;
use super::score::{
    LocalScore, apply_base_sigma, derive_base, pair_constraint_mismatches, recovered_key,
    reset_identity,
};
use super::top_source::build_top_source_beam;
use super::triple::best_triple_move;
use super::{HiddenBaseLocalRecoveredKey, HiddenBaseLocalSolverConfig};

pub(super) struct LocalSearchOutput {
    pub(super) sigma_domain_size: usize,
    pub(super) attempts_run: usize,
    pub(super) candidate_evaluations: usize,
    pub(super) replay_event_evaluations: usize,
    pub(super) joint_move_candidate_evaluations: usize,
    pub(super) joint_move_replay_event_evaluations: usize,
    pub(super) joint_move_total_budget_exhausted: bool,
    pub(super) joint_moves_accepted: usize,
    pub(super) joint_move_letter_pairs_eligible: usize,
    pub(super) joint_move_letter_pairs_evaluated: usize,
    pub(super) joint_move_pair_evaluations_min: usize,
    pub(super) joint_move_pair_evaluations_max: usize,
    pub(super) triple_move_candidate_evaluations: usize,
    pub(super) triple_move_constraint_evaluations: usize,
    pub(super) triple_move_replay_event_evaluations: usize,
    pub(super) triple_move_total_budget_exhausted: bool,
    pub(super) triple_moves_accepted: usize,
    pub(super) triple_move_prefixes_eligible: usize,
    pub(super) triple_move_prefixes_evaluated: usize,
    pub(super) top_source_hypotheses_retained: usize,
    pub(super) planted_top_source_hypothesis_rank: Option<usize>,
    pub(super) planted_top_source_hypothesis_retained: Option<bool>,
    pub(super) top_source_states_expanded: usize,
    pub(super) top_source_states_pruned: usize,
    pub(super) top_source_states_dropped: usize,
    pub(super) top_source_constraint_evaluations: usize,
    pub(super) top_source_third_symbol_evaluations: usize,
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
        config.top_source_beam_width,
        config.attempts,
        config.rank_top_sources_with_third_symbol,
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
        replay_event_evaluations: search.replay_event_evaluations,
        joint_move_candidate_evaluations: search.joint_move_candidate_evaluations,
        joint_move_replay_event_evaluations: search.joint_move_replay_event_evaluations,
        joint_move_total_budget_exhausted: search.joint_move_total_budget_exhausted(),
        joint_moves_accepted: search.joint_moves_accepted,
        joint_move_letter_pairs_eligible: search.joint_move_letter_pairs_eligible.len(),
        joint_move_letter_pairs_evaluated: search.joint_move_pair_evaluations.len(),
        joint_move_pair_evaluations_min: search.joint_move_pair_evaluations_min(),
        joint_move_pair_evaluations_max: search.joint_move_pair_evaluations_max(),
        triple_move_candidate_evaluations: search.triple_move_candidate_evaluations,
        triple_move_constraint_evaluations: search.triple_move_constraint_evaluations,
        triple_move_replay_event_evaluations: search.triple_move_replay_event_evaluations,
        triple_move_total_budget_exhausted: search.triple_move_total_budget_exhausted(),
        triple_moves_accepted: search.triple_moves_accepted,
        triple_move_prefixes_eligible: search.triple_move_prefixes_eligible.len(),
        triple_move_prefixes_evaluated: search.triple_move_prefix_evaluations.len(),
        top_source_hypotheses_retained: top_source_beam.hypotheses.len(),
        planted_top_source_hypothesis_rank: top_source_beam.planted_hypothesis_rank,
        planted_top_source_hypothesis_retained: top_source_beam.planted_hypothesis_retained,
        top_source_states_expanded: top_source_beam.states_expanded,
        top_source_states_pruned: top_source_beam.states_pruned,
        top_source_states_dropped: top_source_beam.states_dropped,
        top_source_constraint_evaluations: top_source_beam.constraint_evaluations,
        top_source_third_symbol_evaluations: top_source_beam.third_symbol_evaluations,
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
    pub(super) canonical_swaps: Vec<usize>,
    pub(super) top_source: usize,
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
    pub(super) replay_event_evaluations: usize,
    pub(super) joint_move_candidate_evaluations: usize,
    pub(super) joint_move_replay_event_evaluations: usize,
    joint_moves_accepted: usize,
    joint_move_letter_pairs_eligible: BTreeSet<(usize, usize)>,
    joint_move_pair_evaluations: BTreeMap<(usize, usize), usize>,
    pub(super) triple_move_candidate_evaluations: usize,
    pub(super) triple_move_constraint_evaluations: usize,
    pub(super) triple_move_replay_event_evaluations: usize,
    triple_moves_accepted: usize,
    triple_move_prefixes_eligible: BTreeSet<[usize; 3]>,
    triple_move_prefix_evaluations: BTreeMap<[usize; 3], usize>,
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
            replay_event_evaluations: 0,
            joint_move_candidate_evaluations: 0,
            joint_move_replay_event_evaluations: 0,
            joint_moves_accepted: 0,
            joint_move_letter_pairs_eligible: BTreeSet::new(),
            joint_move_pair_evaluations: BTreeMap::new(),
            triple_move_candidate_evaluations: 0,
            triple_move_constraint_evaluations: 0,
            triple_move_replay_event_evaluations: 0,
            triple_moves_accepted: 0,
            triple_move_prefixes_eligible: BTreeSet::new(),
            triple_move_prefix_evaluations: BTreeMap::new(),
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
            self.run_attempt(attempt, &observed, &mut rng)?;
            if self.planted_base_recovered == Some(true) {
                break;
            }
        }
        Ok(())
    }

    fn run_attempt(
        &mut self,
        attempt: usize,
        observed: &[char],
        rng: &mut SplitMix64,
    ) -> Result<(), LymmDeckError> {
        let hypothesis_index = attempt % self.top_source_hypotheses.len();
        let hypothesis: &[Option<usize>] = self
            .top_source_hypotheses
            .get(hypothesis_index)
            .map_or(&[], Vec::as_slice);
        let hypothesis_visit = attempt / self.top_source_hypotheses.len();
        let mut assignment = self.seed_assignment(hypothesis, hypothesis_visit, rng)?;
        let mut score = self.score_assignment(&assignment, usize::MAX);
        let mut joint_evaluations = 0usize;
        let joint_evaluation_cap = self.joint_evaluation_cap_for_attempt(attempt);
        let mut triple_evaluations = 0usize;
        let triple_evaluation_cap = self.triple_evaluation_cap_for_attempt(attempt);
        for _round in 0..self.config.max_rounds {
            let mut improved = false;
            for &letter in observed {
                let Some(letter_index) = self.spec.pt_alphabet.iter().position(|&ch| ch == letter)
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
                    let candidate_score = self.score_assignment(&assignment, best_score.objective);
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
                    observed,
                    hypothesis,
                    &mut joint_evaluations,
                    joint_evaluation_cap,
                );
                if let Some(joint_move) = joint_move {
                    if let Some(slot) = assignment.get_mut(joint_move.left_letter) {
                        *slot = joint_move.left_candidate;
                    }
                    if let Some(slot) = assignment.get_mut(joint_move.right_letter) {
                        *slot = joint_move.right_candidate;
                    }
                    score = joint_move.score;
                    self.joint_moves_accepted = self.joint_moves_accepted.saturating_add(1);
                    continue;
                }
                let triple_move = best_triple_move(
                    self,
                    &mut assignment,
                    &score,
                    hypothesis,
                    &mut triple_evaluations,
                    triple_evaluation_cap,
                );
                let Some(triple_move) = triple_move else {
                    break;
                };
                for (letter, candidate) in
                    triple_move.letters.into_iter().zip(triple_move.candidates)
                {
                    if let Some(slot) = assignment.get_mut(letter) {
                        *slot = candidate;
                    }
                }
                score = triple_move.score;
                self.triple_moves_accepted = self.triple_moves_accepted.saturating_add(1);
            }
        }
        let final_score = self.score_assignment(&assignment, usize::MAX);
        self.record_score(&assignment, &final_score);
        Ok(())
    }

    fn joint_evaluation_cap_for_attempt(&self, attempt: usize) -> usize {
        let attempts = self.config.attempts.max(1);
        let completed = attempt.saturating_add(1).min(attempts);
        let total = self.config.joint_move_total_evaluation_cap;
        let fair_cumulative_cap = (total / attempts)
            .saturating_mul(completed)
            .saturating_add((total % attempts).min(completed));
        self.config
            .joint_move_evaluation_cap
            .min(fair_cumulative_cap.saturating_sub(self.joint_move_candidate_evaluations))
    }

    fn joint_move_total_budget_exhausted(&self) -> bool {
        self.joint_move_candidate_evaluations >= self.config.joint_move_total_evaluation_cap
    }

    fn triple_evaluation_cap_for_attempt(&self, attempt: usize) -> usize {
        let attempts = self.config.attempts.max(1);
        let completed = attempt.saturating_add(1).min(attempts);
        let total = self.config.triple_move_total_evaluation_cap;
        let fair_cumulative_cap = (total / attempts)
            .saturating_mul(completed)
            .saturating_add((total % attempts).min(completed));
        self.config
            .triple_move_evaluation_cap
            .min(fair_cumulative_cap.saturating_sub(self.triple_move_candidate_evaluations))
    }

    fn triple_move_total_budget_exhausted(&self) -> bool {
        self.triple_move_candidate_evaluations >= self.config.triple_move_total_evaluation_cap
    }

    pub(super) fn record_triple_prefix_eligible(&mut self, letters: [usize; 3]) {
        let _inserted = self.triple_move_prefixes_eligible.insert(letters);
    }

    pub(super) fn record_triple_prefix_evaluation(&mut self, letters: [usize; 3]) {
        let count = self
            .triple_move_prefix_evaluations
            .entry(letters)
            .or_default();
        *count = count.saturating_add(1);
    }

    pub(super) fn record_joint_pair_eligible(&mut self, left: usize, right: usize) {
        let _inserted = self.joint_move_letter_pairs_eligible.insert((left, right));
    }

    pub(super) fn record_joint_pair_evaluation(&mut self, left: usize, right: usize) {
        let count = self
            .joint_move_pair_evaluations
            .entry((left, right))
            .or_default();
        *count = count.saturating_add(1);
    }

    fn joint_move_pair_evaluations_min(&self) -> usize {
        self.joint_move_letter_pairs_eligible
            .iter()
            .map(|pair| {
                self.joint_move_pair_evaluations
                    .get(pair)
                    .copied()
                    .unwrap_or(0)
            })
            .min()
            .unwrap_or(0)
    }

    fn joint_move_pair_evaluations_max(&self) -> usize {
        self.joint_move_pair_evaluations
            .values()
            .copied()
            .max()
            .unwrap_or(0)
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
        stop_after_objective: usize,
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
        let weighted_pair_penalty = pair_penalty.saturating_mul(self.corpus.event_count.max(1));
        let mismatch_limit = stop_after_objective.saturating_sub(weighted_pair_penalty);
        let mut mismatches = 0usize;
        let mut state = vec![0; self.config.n];
        let mut next = vec![0; self.config.n];
        for message in &self.corpus.messages {
            reset_identity(&mut state);
            for event in &message.events {
                self.replay_event_evaluations = self.replay_event_evaluations.saturating_add(1);
                let candidate_index = assignment.get(event.letter).copied().unwrap_or(0);
                let Some(candidate) = self.domain.candidates.get(candidate_index) else {
                    mismatches = mismatches.saturating_add(1);
                    continue;
                };
                apply_base_sigma(&base, &candidate.sigma, &state, &mut next);
                if next.first().copied() != Some(event.ct_value) {
                    mismatches = mismatches.saturating_add(1);
                    if mismatches > mismatch_limit {
                        return LocalScore {
                            objective: mismatches.saturating_add(weighted_pair_penalty),
                            mismatches,
                            base: Some(base),
                        };
                    }
                }
                std::mem::swap(&mut state, &mut next);
            }
        }
        LocalScore {
            objective: mismatches.saturating_add(weighted_pair_penalty),
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

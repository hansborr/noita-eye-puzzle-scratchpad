//! Capped fourth-prefix triple repairs for stalled local refinement.

use super::score::{LocalScore, apply_base_sigma};
use super::search::LocalSearch;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TripleMove {
    pub(super) letters: [usize; 3],
    pub(super) candidates: [usize; 3],
    pub(super) score: LocalScore,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PrefixTripleDomain {
    message_index: usize,
    letters: [usize; 3],
    current: [usize; 3],
    candidates: [Vec<usize>; 3],
}

impl PrefixTripleDomain {
    fn product_len(&self) -> usize {
        self.candidates.iter().fold(1usize, |product, candidates| {
            product.saturating_mul(candidates.len())
        })
    }

    fn candidate_at(&self, index: usize) -> Option<[usize; 3]> {
        let middle_right = self.candidates[1]
            .len()
            .saturating_mul(self.candidates[2].len());
        if middle_right == 0 || index >= self.product_len() {
            return None;
        }
        let middle = self.candidates[2].len();
        Some([
            *self.candidates[0].get(index / middle_right)?,
            *self.candidates[1].get((index / middle) % self.candidates[1].len())?,
            *self.candidates[2].get(index % middle)?,
        ])
    }
}

pub(super) fn best_triple_move(
    search: &mut LocalSearch<'_>,
    assignment: &mut [usize],
    score: &LocalScore,
    hypothesis: &[Option<usize>],
    evaluations: &mut usize,
    evaluation_cap: usize,
) -> Option<TripleMove> {
    if search.config.swap_budget != 3 || *evaluations >= evaluation_cap {
        return None;
    }
    let base = score.base.as_deref()?;
    let domains = prefix_triple_domains(search, assignment, hypothesis, base);
    for domain in &domains {
        search.record_triple_prefix_eligible(domain.letters);
    }
    let max_product = domains
        .iter()
        .map(PrefixTripleDomain::product_len)
        .max()
        .unwrap_or(0);
    let mut best = None;
    'candidate: for candidate_index in 0..max_product {
        for domain in &domains {
            if *evaluations >= evaluation_cap {
                break 'candidate;
            }
            evaluate_candidate(
                search,
                assignment,
                score,
                domain,
                candidate_index,
                evaluations,
                &mut best,
            );
        }
    }
    best
}

fn prefix_triple_domains(
    search: &mut LocalSearch<'_>,
    assignment: &[usize],
    hypothesis: &[Option<usize>],
    base: &[usize],
) -> Vec<PrefixTripleDomain> {
    let mut domains = Vec::new();
    for message_index in 0..search.corpus.messages.len() {
        let Some([first, second, third, _fourth]) = search
            .corpus
            .messages
            .get(message_index)
            .and_then(|message| message.events.get(..4))
        else {
            continue;
        };
        let letters = [first.letter, second.letter, third.letter];
        if letters[0] == letters[1]
            || letters[0] == letters[2]
            || letters[1] == letters[2]
            || fourth_prefix_matches(search, assignment, base, message_index)
        {
            continue;
        }
        let current = letters.map(|letter| assignment.get(letter).copied().unwrap_or(0));
        let candidates = letters.map(|letter| {
            search
                .candidates_for_letter(letter, hypothesis)
                .into_iter()
                .filter(|candidate| *candidate != assignment.get(letter).copied().unwrap_or(0))
                .collect::<Vec<_>>()
        });
        if candidates.iter().all(|candidate| !candidate.is_empty()) {
            domains.push(PrefixTripleDomain {
                message_index,
                letters,
                current,
                candidates,
            });
        }
    }
    domains
}

fn evaluate_candidate(
    search: &mut LocalSearch<'_>,
    assignment: &mut [usize],
    score: &LocalScore,
    domain: &PrefixTripleDomain,
    candidate_index: usize,
    evaluations: &mut usize,
    best: &mut Option<TripleMove>,
) {
    let Some(candidates) = domain.candidate_at(candidate_index) else {
        return;
    };
    set_assignment(assignment, domain.letters, candidates);
    *evaluations = evaluations.saturating_add(1);
    search.triple_move_candidate_evaluations =
        search.triple_move_candidate_evaluations.saturating_add(1);
    search.record_triple_prefix_evaluation(domain.letters);
    let repairs_prefix = score
        .base
        .as_deref()
        .is_some_and(|base| fourth_prefix_matches(search, assignment, base, domain.message_index));
    if repairs_prefix {
        let replay_before = search.replay_event_evaluations;
        let incumbent = best
            .as_ref()
            .map_or(score.objective, |triple: &TripleMove| {
                triple.score.objective
            });
        let candidate_score = search.score_assignment(assignment, incumbent);
        search.triple_move_replay_event_evaluations =
            search.triple_move_replay_event_evaluations.saturating_add(
                search
                    .replay_event_evaluations
                    .saturating_sub(replay_before),
            );
        if candidate_score.objective < incumbent {
            *best = Some(TripleMove {
                letters: domain.letters,
                candidates,
                score: candidate_score,
            });
        }
    }
    set_assignment(assignment, domain.letters, domain.current);
}

fn fourth_prefix_matches(
    search: &mut LocalSearch<'_>,
    assignment: &[usize],
    base: &[usize],
    message_index: usize,
) -> bool {
    search.triple_move_constraint_evaluations =
        search.triple_move_constraint_evaluations.saturating_add(1);
    let Some(events) = search
        .corpus
        .messages
        .get(message_index)
        .and_then(|message| message.events.get(..4))
    else {
        return false;
    };
    let mut state = (0..search.config.n).collect::<Vec<_>>();
    let mut next = vec![0; search.config.n];
    for event in events {
        let Some(candidate) = assignment
            .get(event.letter)
            .and_then(|&index| search.domain.candidates.get(index))
        else {
            return false;
        };
        apply_base_sigma(base, &candidate.sigma, &state, &mut next);
        std::mem::swap(&mut state, &mut next);
    }
    state.first().copied() == events.get(3).map(|event| event.ct_value)
}

fn set_assignment(assignment: &mut [usize], letters: [usize; 3], candidates: [usize; 3]) {
    for (letter, candidate) in letters.into_iter().zip(candidates) {
        if let Some(slot) = assignment.get_mut(letter) {
            *slot = candidate;
        }
    }
}

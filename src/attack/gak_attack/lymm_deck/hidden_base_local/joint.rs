//! Capped two-letter moves for stalled hidden-base local refinement.

use super::search::{LocalScore, LocalSearch};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct JointMove {
    pub(super) left_letter: usize,
    pub(super) left_candidate: usize,
    pub(super) right_letter: usize,
    pub(super) right_candidate: usize,
    pub(super) score: LocalScore,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct JointPairDomain {
    left_letter: usize,
    left_current: usize,
    left_candidates: Vec<usize>,
    right_letter: usize,
    right_current: usize,
    right_candidates: Vec<usize>,
}

impl JointPairDomain {
    fn product_len(&self) -> usize {
        self.left_candidates
            .len()
            .saturating_mul(self.right_candidates.len())
    }

    fn candidate_at(&self, index: usize) -> Option<(usize, usize)> {
        let right_len = self.right_candidates.len();
        if right_len == 0 || index >= self.product_len() {
            return None;
        }
        Some((
            *self.left_candidates.get(index / right_len)?,
            *self.right_candidates.get(index % right_len)?,
        ))
    }
}

pub(super) fn best_joint_move(
    search: &mut LocalSearch<'_>,
    assignment: &mut [usize],
    score: &LocalScore,
    observed: &[char],
    hypothesis: &[Option<usize>],
    evaluations: &mut usize,
    evaluation_cap: usize,
) -> Option<JointMove> {
    if search.config.swap_budget != 3 || *evaluations >= evaluation_cap {
        return None;
    }
    let pair_domains = joint_pair_domains(search, assignment, observed, hypothesis);
    for pair in &pair_domains {
        search.record_joint_pair_eligible(pair.left_letter, pair.right_letter);
    }
    if search.config.fair_joint_move_order {
        best_pair_round_robin(
            search,
            assignment,
            score,
            &pair_domains,
            evaluations,
            evaluation_cap,
        )
    } else {
        best_pair_major(
            search,
            assignment,
            score,
            &pair_domains,
            evaluations,
            evaluation_cap,
        )
    }
}

fn joint_pair_domains(
    search: &LocalSearch<'_>,
    assignment: &[usize],
    observed: &[char],
    hypothesis: &[Option<usize>],
) -> Vec<JointPairDomain> {
    let observed_indices = observed
        .iter()
        .filter_map(|letter| {
            search
                .spec
                .pt_alphabet
                .iter()
                .position(|found| found == letter)
        })
        .collect::<Vec<_>>();
    let mut pairs = Vec::new();
    for (left_position, &left_letter) in observed_indices.iter().enumerate() {
        let left_current = assignment.get(left_letter).copied().unwrap_or(0);
        let left_candidates = alternatives(
            search.candidates_for_letter(left_letter, hypothesis),
            left_current,
        );
        for &right_letter in observed_indices
            .iter()
            .skip(left_position.saturating_add(1))
        {
            let right_current = assignment.get(right_letter).copied().unwrap_or(0);
            let right_candidates = alternatives(
                search.candidates_for_letter(right_letter, hypothesis),
                right_current,
            );
            if !left_candidates.is_empty() && !right_candidates.is_empty() {
                pairs.push(JointPairDomain {
                    left_letter,
                    left_current,
                    left_candidates: left_candidates.clone(),
                    right_letter,
                    right_current,
                    right_candidates,
                });
            }
        }
    }
    pairs
}

fn alternatives(candidates: Vec<usize>, current: usize) -> Vec<usize> {
    candidates
        .into_iter()
        .filter(|&candidate| candidate != current)
        .collect()
}

fn best_pair_major(
    search: &mut LocalSearch<'_>,
    assignment: &mut [usize],
    score: &LocalScore,
    pair_domains: &[JointPairDomain],
    evaluations: &mut usize,
    evaluation_cap: usize,
) -> Option<JointMove> {
    let mut best = None;
    for pair in pair_domains {
        for candidate_index in 0..pair.product_len() {
            if *evaluations >= evaluation_cap {
                return best;
            }
            evaluate_candidate(
                search,
                assignment,
                score,
                pair,
                candidate_index,
                evaluations,
                &mut best,
            );
        }
    }
    best
}

fn best_pair_round_robin(
    search: &mut LocalSearch<'_>,
    assignment: &mut [usize],
    score: &LocalScore,
    pair_domains: &[JointPairDomain],
    evaluations: &mut usize,
    evaluation_cap: usize,
) -> Option<JointMove> {
    let mut best = None;
    let max_product = pair_domains
        .iter()
        .map(JointPairDomain::product_len)
        .max()
        .unwrap_or(0);
    for candidate_index in 0..max_product {
        for pair in pair_domains {
            if candidate_index >= pair.product_len() {
                continue;
            }
            if *evaluations >= evaluation_cap {
                return best;
            }
            evaluate_candidate(
                search,
                assignment,
                score,
                pair,
                candidate_index,
                evaluations,
                &mut best,
            );
        }
    }
    best
}

fn evaluate_candidate(
    search: &mut LocalSearch<'_>,
    assignment: &mut [usize],
    score: &LocalScore,
    pair: &JointPairDomain,
    candidate_index: usize,
    evaluations: &mut usize,
    best: &mut Option<JointMove>,
) {
    let Some((left_candidate, right_candidate)) = pair.candidate_at(candidate_index) else {
        return;
    };
    if let Some(slot) = assignment.get_mut(pair.left_letter) {
        *slot = left_candidate;
    }
    if let Some(slot) = assignment.get_mut(pair.right_letter) {
        *slot = right_candidate;
    }
    *evaluations = evaluations.saturating_add(1);
    search.joint_move_candidate_evaluations =
        search.joint_move_candidate_evaluations.saturating_add(1);
    search.record_joint_pair_evaluation(pair.left_letter, pair.right_letter);
    let replay_events_before = search.replay_event_evaluations;
    let incumbent_objective = best
        .as_ref()
        .map_or(score.objective, |joint| joint.score.objective);
    let candidate_score = search.score_assignment(assignment, incumbent_objective);
    search.joint_move_replay_event_evaluations =
        search.joint_move_replay_event_evaluations.saturating_add(
            search
                .replay_event_evaluations
                .saturating_sub(replay_events_before),
        );
    if candidate_score.objective < incumbent_objective {
        *best = Some(JointMove {
            left_letter: pair.left_letter,
            left_candidate,
            right_letter: pair.right_letter,
            right_candidate,
            score: candidate_score,
        });
    }
    if let Some(slot) = assignment.get_mut(pair.left_letter) {
        *slot = pair.left_current;
    }
    if let Some(slot) = assignment.get_mut(pair.right_letter) {
        *slot = pair.right_current;
    }
}

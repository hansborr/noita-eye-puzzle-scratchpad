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

pub(super) fn best_joint_move(
    search: &mut LocalSearch<'_>,
    assignment: &mut [usize],
    score: &LocalScore,
    observed: &[char],
    hypothesis: &[Option<usize>],
    evaluations: &mut usize,
) -> Option<JointMove> {
    if search.config.swap_budget != 3 || *evaluations >= search.config.joint_move_evaluation_cap {
        return None;
    }
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
    let mut best = None;
    let mut exhausted = false;
    for (left_position, &left_letter) in observed_indices.iter().enumerate() {
        let left_current = assignment.get(left_letter).copied().unwrap_or(0);
        let left_candidates = search.candidates_for_letter(left_letter, hypothesis);
        for &right_letter in observed_indices
            .iter()
            .skip(left_position.saturating_add(1))
        {
            let right_current = assignment.get(right_letter).copied().unwrap_or(0);
            let right_candidates = search.candidates_for_letter(right_letter, hypothesis);
            for &left_candidate in &left_candidates {
                if left_candidate == left_current {
                    continue;
                }
                for &right_candidate in &right_candidates {
                    if right_candidate == right_current {
                        continue;
                    }
                    if *evaluations >= search.config.joint_move_evaluation_cap {
                        exhausted = true;
                        break;
                    }
                    if let Some(slot) = assignment.get_mut(left_letter) {
                        *slot = left_candidate;
                    }
                    if let Some(slot) = assignment.get_mut(right_letter) {
                        *slot = right_candidate;
                    }
                    *evaluations = evaluations.saturating_add(1);
                    search.joint_move_candidate_evaluations =
                        search.joint_move_candidate_evaluations.saturating_add(1);
                    let replay_events_before = search.replay_event_evaluations;
                    let incumbent = best
                        .as_ref()
                        .map_or(score, |joint: &JointMove| &joint.score);
                    let candidate_score = search.score_assignment(assignment, incumbent.objective);
                    search.joint_move_replay_event_evaluations =
                        search.joint_move_replay_event_evaluations.saturating_add(
                            search
                                .replay_event_evaluations
                                .saturating_sub(replay_events_before),
                        );
                    if candidate_score.objective < incumbent.objective {
                        best = Some(JointMove {
                            left_letter,
                            left_candidate,
                            right_letter,
                            right_candidate,
                            score: candidate_score,
                        });
                    }
                }
                if exhausted {
                    break;
                }
            }
            if let Some(slot) = assignment.get_mut(right_letter) {
                *slot = right_current;
            }
            if exhausted {
                break;
            }
        }
        if let Some(slot) = assignment.get_mut(left_letter) {
            *slot = left_current;
        }
        if exhausted {
            break;
        }
    }
    best
}

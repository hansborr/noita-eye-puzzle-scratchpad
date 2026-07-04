//! Learned-clause accounting and planted-truth preservation checks.

use std::collections::BTreeMap;

use batsat::{BasicSolver, Lit, SolverInterface};

use super::{SwapRecoveryError, SwapRecoveryStats};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TruthTracker {
    targets: BTreeMap<char, usize>,
    permutations: BTreeMap<char, Vec<usize>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum LearnedClause {
    Target(Vec<(char, usize)>),
    Candidate(Vec<(char, Vec<usize>)>),
}

impl TruthTracker {
    pub(super) fn new(permutations: BTreeMap<char, Vec<usize>>) -> Self {
        let targets = permutations
            .iter()
            .filter_map(|(&letter, permutation)| {
                permutation.first().copied().map(|target| (letter, target))
            })
            .collect();
        Self {
            targets,
            permutations,
        }
    }

    pub(super) fn targets_for_letters(&self, letters: &[char]) -> BTreeMap<char, usize> {
        letters
            .iter()
            .filter_map(|&letter| {
                self.targets
                    .get(&letter)
                    .copied()
                    .map(|target| (letter, target))
            })
            .collect()
    }

    fn assert_preserved(&self, clause: &LearnedClause) -> Result<(), SwapRecoveryError> {
        let preserved = match clause {
            LearnedClause::Target(choices) => choices
                .iter()
                .any(|&(letter, target)| self.targets.get(&letter).copied() != Some(target)),
            LearnedClause::Candidate(choices) => choices
                .iter()
                .any(|(letter, permutation)| self.permutations.get(letter) != Some(permutation)),
        };
        if preserved {
            Ok(())
        } else {
            Err(SwapRecoveryError::TruthPreservationViolated {
                clause_kind: clause.kind(),
                literals: clause.len(),
            })
        }
    }
}

impl LearnedClause {
    const fn kind(&self) -> &'static str {
        match self {
            Self::Target(_) => "target",
            Self::Candidate(_) => "candidate",
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Target(choices) => choices.len(),
            Self::Candidate(choices) => choices.len(),
        }
    }
}

pub(super) fn learn_sat_clause(
    solver: &mut BasicSolver,
    literals: &[Lit],
    learned: &LearnedClause,
    truth: Option<&TruthTracker>,
    stats: &mut SwapRecoveryStats,
) -> Result<(), SwapRecoveryError> {
    if let Some(truth) = truth {
        truth.assert_preserved(learned)?;
        stats.truth_preservation_checks = stats.truth_preservation_checks.saturating_add(1);
    }
    let mut clause = literals.to_vec();
    let _still_satisfiable = solver.add_clause_reuse(&mut clause);
    match learned {
        LearnedClause::Target(_) => {
            stats.target_clauses_learned = stats.target_clauses_learned.saturating_add(1);
        }
        LearnedClause::Candidate(_) => {
            stats.candidate_clauses_learned = stats.candidate_clauses_learned.saturating_add(1);
        }
    }
    Ok(())
}

pub(super) fn add_outer_stats(stats: &mut SwapRecoveryStats, outer: &SwapRecoveryStats) {
    stats.enumerated_candidates = stats.enumerated_candidates.max(outer.enumerated_candidates);
    stats.domains_pruned = stats.domains_pruned.saturating_add(outer.domains_pruned);
    stats.deductions = stats.deductions.saturating_add(outer.deductions);
    stats.target_clauses_learned = stats
        .target_clauses_learned
        .saturating_add(outer.target_clauses_learned);
    stats.target_rejections = stats
        .target_rejections
        .saturating_add(outer.target_rejections);
    stats.target_replay_checks = stats
        .target_replay_checks
        .saturating_add(outer.target_replay_checks);
    stats.target_replay_literals = stats
        .target_replay_literals
        .saturating_add(outer.target_replay_literals);
    stats.truth_preservation_checks = stats
        .truth_preservation_checks
        .saturating_add(outer.truth_preservation_checks);
    if !outer.measured_target_domain_entries.is_empty() {
        stats.measured_target_total_entries = outer.measured_target_total_entries;
        stats.measured_target_max_domain = outer.measured_target_max_domain;
        stats
            .measured_target_domain_entries
            .clone_from(&outer.measured_target_domain_entries);
    }
}

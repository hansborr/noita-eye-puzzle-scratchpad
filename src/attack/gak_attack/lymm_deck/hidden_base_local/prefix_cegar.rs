//! Lazy exact-prefix CEGAR for retained top-source hypotheses.

use std::collections::{BTreeMap, BTreeSet};

use batsat::{BasicSolver, Lit, SolverInterface, lbool};

use super::super::LymmDeckError;
use super::HiddenBaseLocalSolverConfig;
use super::score::{LocalScore, apply_base_sigma, derive_base, reset_identity};
use super::search::LocalSearch;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct PrefixCegarStats {
    pub(super) hypotheses_attempted: usize,
    pub(super) hypotheses_unsat: usize,
    pub(super) hypotheses_capped: usize,
    pub(super) models: usize,
    pub(super) clauses: usize,
    pub(super) replay_events: usize,
    pub(super) exact_models: usize,
    core_size_min: usize,
    pub(super) core_size_max: usize,
}

impl Default for PrefixCegarStats {
    fn default() -> Self {
        Self {
            hypotheses_attempted: 0,
            hypotheses_unsat: 0,
            hypotheses_capped: 0,
            models: 0,
            clauses: 0,
            replay_events: 0,
            exact_models: 0,
            core_size_min: usize::MAX,
            core_size_max: 0,
        }
    }
}

impl PrefixCegarStats {
    pub(super) fn core_size_min(&self) -> usize {
        if self.core_size_min == usize::MAX {
            0
        } else {
            self.core_size_min
        }
    }

    pub(super) fn total_budget_exhausted(&self, config: &HiddenBaseLocalSolverConfig) -> bool {
        config.prefix_cegar_total_node_cap > 0 && self.models >= config.prefix_cegar_total_node_cap
    }

    fn record_core(&mut self, size: usize) {
        self.core_size_min = self.core_size_min.min(size);
        self.core_size_max = self.core_size_max.max(size);
    }
}

pub(super) fn run_prefix_cegar(search: &mut LocalSearch<'_>) -> Result<(), LymmDeckError> {
    let hypotheses = search.top_source_hypotheses.to_vec();
    for (index, hypothesis) in hypotheses.iter().enumerate() {
        let cap = hypothesis_node_cap(search, index, hypotheses.len());
        if cap == 0 {
            continue;
        }
        search.prefix_cegar.hypotheses_attempted =
            search.prefix_cegar.hypotheses_attempted.saturating_add(1);
        let Some(mut solver) = PrefixAssignmentSolver::new(search, hypothesis) else {
            search.prefix_cegar.hypotheses_unsat =
                search.prefix_cegar.hypotheses_unsat.saturating_add(1);
            continue;
        };
        match run_hypothesis(search, &mut solver, cap)? {
            HypothesisOutcome::Exact => return Ok(()),
            HypothesisOutcome::Unsat => {
                search.prefix_cegar.hypotheses_unsat =
                    search.prefix_cegar.hypotheses_unsat.saturating_add(1);
            }
            HypothesisOutcome::Capped => {
                search.prefix_cegar.hypotheses_capped =
                    search.prefix_cegar.hypotheses_capped.saturating_add(1);
            }
        }
    }
    Ok(())
}

fn hypothesis_node_cap(search: &LocalSearch<'_>, index: usize, count: usize) -> usize {
    let completed = index.saturating_add(1).min(count.max(1));
    let total = search.config.prefix_cegar_total_node_cap;
    let fair_cumulative = (total / count.max(1))
        .saturating_mul(completed)
        .saturating_add((total % count.max(1)).min(completed));
    search
        .config
        .prefix_cegar_node_cap
        .min(fair_cumulative.saturating_sub(search.prefix_cegar.models))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HypothesisOutcome {
    Exact,
    Unsat,
    Capped,
}

fn run_hypothesis(
    search: &mut LocalSearch<'_>,
    solver: &mut PrefixAssignmentSolver,
    cap: usize,
) -> Result<HypothesisOutcome, LymmDeckError> {
    for _node in 0..cap {
        let Some(assignment) = solver.next_assignment()? else {
            return Ok(HypothesisOutcome::Unsat);
        };
        search.prefix_cegar.models = search.prefix_cegar.models.saturating_add(1);
        match replay_to_first_mismatch(search, solver, &assignment) {
            ReplayOutcome::Exact(base) => {
                search.prefix_cegar.exact_models =
                    search.prefix_cegar.exact_models.saturating_add(1);
                search.record_score(
                    &assignment,
                    &LocalScore {
                        objective: 0,
                        mismatches: 0,
                        base: Some(base),
                    },
                );
                return Ok(HypothesisOutcome::Exact);
            }
            ReplayOutcome::Mismatch(mut core) => {
                if core.is_empty() {
                    core.extend(solver.letters.iter().copied());
                }
                solver.block_core(&assignment, &core);
                search.prefix_cegar.clauses = search.prefix_cegar.clauses.saturating_add(1);
                search.prefix_cegar.record_core(core.len());
            }
        }
    }
    Ok(HypothesisOutcome::Capped)
}

enum ReplayOutcome {
    Exact(Vec<usize>),
    Mismatch(BTreeSet<usize>),
}

fn replay_to_first_mismatch(
    search: &mut LocalSearch<'_>,
    solver: &PrefixAssignmentSolver,
    assignment: &[usize],
) -> ReplayOutcome {
    let Some(base) = derive_base(search.config.n, search.corpus, search.domain, assignment) else {
        return ReplayOutcome::Mismatch(solver.letters.iter().copied().collect());
    };
    let mut state = vec![0; search.config.n];
    let mut next = vec![0; search.config.n];
    for message in &search.corpus.messages {
        reset_identity(&mut state);
        let mut prefix_letters = BTreeSet::new();
        for event in &message.events {
            search.prefix_cegar.replay_events = search.prefix_cegar.replay_events.saturating_add(1);
            let candidate = assignment
                .get(event.letter)
                .and_then(|&candidate| search.domain.candidates.get(candidate));
            let Some(candidate) = candidate else {
                return ReplayOutcome::Mismatch(solver.letters.iter().copied().collect());
            };
            apply_base_sigma(&base, &candidate.sigma, &state, &mut next);
            if next.first().copied() != Some(event.ct_value) {
                if !solver.source_is_fixed(event.letter) {
                    let _inserted = prefix_letters.insert(event.letter);
                }
                return ReplayOutcome::Mismatch(prefix_letters);
            }
            let _inserted = prefix_letters.insert(event.letter);
            std::mem::swap(&mut state, &mut next);
        }
    }
    ReplayOutcome::Exact(base)
}

struct PrefixAssignmentSolver {
    solver: BasicSolver,
    vars: BTreeMap<(usize, usize), Lit>,
    domains: BTreeMap<usize, Vec<usize>>,
    letters: Vec<usize>,
    source_fixed: BTreeSet<usize>,
    assignment_len: usize,
}

impl PrefixAssignmentSolver {
    fn new(search: &LocalSearch<'_>, hypothesis: &[Option<usize>]) -> Option<Self> {
        let mut solver = BasicSolver::default();
        let letters = observed_letter_indices(search);
        let mut vars = BTreeMap::new();
        let mut domains = BTreeMap::new();
        let mut source_fixed = BTreeSet::new();
        for &letter in &letters {
            let candidates = search.candidates_for_letter(letter, hypothesis);
            if candidates.is_empty() {
                return None;
            }
            let literals = candidates
                .iter()
                .map(|&candidate| {
                    let literal = Lit::new(solver.new_var(lbool::TRUE, true), true);
                    let _old = vars.insert((letter, candidate), literal);
                    literal
                })
                .collect::<Vec<_>>();
            add_exactly_one(&mut solver, &literals);
            let sources = candidates
                .iter()
                .filter_map(|&candidate| search.domain.candidates.get(candidate))
                .map(|candidate| candidate.top_source)
                .collect::<BTreeSet<_>>();
            if sources.len() == 1 {
                let _inserted = source_fixed.insert(letter);
            }
            let _old = domains.insert(letter, candidates);
        }
        Some(Self {
            solver,
            vars,
            domains,
            letters,
            source_fixed,
            assignment_len: search.spec.pt_alphabet.len(),
        })
    }

    fn next_assignment(&mut self) -> Result<Option<Vec<usize>>, LymmDeckError> {
        let status = self.solver.solve_limited(&[]);
        if status == lbool::FALSE {
            Ok(None)
        } else if status == lbool::UNDEF {
            Err(LymmDeckError::HiddenBaseConfig {
                reason: "prefix CEGAR SAT solver returned an indeterminate result",
            })
        } else {
            let mut assignment = vec![0; self.assignment_len];
            for &letter in &self.letters {
                let selected =
                    self.domains
                        .get(&letter)
                        .into_iter()
                        .flatten()
                        .find(|&&candidate| {
                            self.vars.get(&(letter, candidate)).is_some_and(|&literal| {
                                self.solver.value_lit(literal) == lbool::TRUE
                            })
                        });
                let Some(&candidate) = selected else {
                    return Err(LymmDeckError::HiddenBaseConfig {
                        reason: "prefix CEGAR SAT model omitted a letter candidate",
                    });
                };
                if let Some(slot) = assignment.get_mut(letter) {
                    *slot = candidate;
                }
            }
            Ok(Some(assignment))
        }
    }

    fn block_core(&mut self, assignment: &[usize], core: &BTreeSet<usize>) {
        let mut clause = core
            .iter()
            .filter_map(|&letter| {
                assignment
                    .get(letter)
                    .and_then(|&candidate| self.vars.get(&(letter, candidate)))
                    .copied()
                    .map(std::ops::Not::not)
            })
            .collect::<Vec<_>>();
        if clause.is_empty() {
            clause = self
                .letters
                .iter()
                .filter_map(|&letter| {
                    assignment
                        .get(letter)
                        .and_then(|&candidate| self.vars.get(&(letter, candidate)))
                        .copied()
                        .map(std::ops::Not::not)
                })
                .collect();
        }
        let _still_satisfiable = self.solver.add_clause_reuse(&mut clause);
    }

    fn source_is_fixed(&self, letter: usize) -> bool {
        self.source_fixed.contains(&letter)
    }
}

fn observed_letter_indices(search: &LocalSearch<'_>) -> Vec<usize> {
    search
        .corpus
        .observed_letters(search.spec)
        .into_iter()
        .filter_map(|letter| {
            search
                .spec
                .pt_alphabet
                .iter()
                .position(|&found| found == letter)
        })
        .collect()
}

fn add_exactly_one(solver: &mut BasicSolver, literals: &[Lit]) {
    let mut at_least_one = literals.to_vec();
    let _still_satisfiable = solver.add_clause_reuse(&mut at_least_one);
    for (left_index, &left) in literals.iter().enumerate() {
        for &right in literals.iter().skip(left_index.saturating_add(1)) {
            let mut clause = vec![!left, !right];
            let _still_satisfiable = solver.add_clause_reuse(&mut clause);
        }
    }
}

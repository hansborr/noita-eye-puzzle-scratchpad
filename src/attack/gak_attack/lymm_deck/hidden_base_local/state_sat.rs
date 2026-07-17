//! Exact state-channeled SAT for retained top-source hypotheses.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use batsat::{BasicSolver, Lit, SolverInterface, lbool};

use super::super::LymmDeckError;
use super::base_completion::base_completions;
use super::search::LocalSearch;

type RouteDomains = BTreeMap<(usize, usize), Vec<(usize, Lit)>>;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct StateSatStats {
    pub(super) hypotheses_attempted: usize,
    pub(super) hypotheses_unsat: usize,
    pub(super) base_completions_attempted: usize,
    pub(super) base_completions_unsat: usize,
    pub(super) base_completion_cap_exhausted: usize,
    pub(super) exact_models: usize,
    pub(super) variables: usize,
    pub(super) clauses: usize,
    pub(super) replay_events: usize,
    pub(super) elapsed: Duration,
}

pub(super) fn run_state_sat(search: &mut LocalSearch<'_>) -> Result<(), LymmDeckError> {
    let started = Instant::now();
    let hypotheses = search.top_source_hypotheses.to_vec();
    let cap = search.config.state_sat_hypothesis_cap.min(hypotheses.len());
    for hypothesis in hypotheses.iter().take(cap) {
        search.state_sat.hypotheses_attempted =
            search.state_sat.hypotheses_attempted.saturating_add(1);
        let Some((bases, cap_exhausted)) = base_completions(
            search.config.n,
            search.corpus,
            hypothesis,
            search.config.state_sat_base_completion_cap,
        ) else {
            search.state_sat.hypotheses_unsat = search.state_sat.hypotheses_unsat.saturating_add(1);
            continue;
        };
        if cap_exhausted {
            search.state_sat.base_completion_cap_exhausted = search
                .state_sat
                .base_completion_cap_exhausted
                .saturating_add(1);
        }
        let mut all_attempted_unsat = true;
        for base in bases {
            search.state_sat.base_completions_attempted = search
                .state_sat
                .base_completions_attempted
                .saturating_add(1);
            let Some(mut encoding) = StateSatEncoding::new(search, hypothesis, &base)? else {
                search.state_sat.base_completions_unsat =
                    search.state_sat.base_completions_unsat.saturating_add(1);
                continue;
            };
            search.state_sat.variables = search
                .state_sat
                .variables
                .saturating_add(encoding.variables);
            search.state_sat.clauses = search.state_sat.clauses.saturating_add(encoding.clauses);
            let Some(assignment) = encoding.solve()? else {
                search.state_sat.base_completions_unsat =
                    search.state_sat.base_completions_unsat.saturating_add(1);
                continue;
            };
            all_attempted_unsat = false;
            search.state_sat.replay_events = search
                .state_sat
                .replay_events
                .saturating_add(search.corpus.event_count);
            let score = search.score_assignment_with_base(&assignment, &base, usize::MAX);
            if score.mismatches != 0 || score.base.as_deref() != Some(base.as_slice()) {
                return Err(LymmDeckError::HiddenBaseConfig {
                    reason: "state-SAT model failed exact replay",
                });
            }
            search.state_sat.exact_models = search.state_sat.exact_models.saturating_add(1);
            search.record_score(&assignment, &score);
            break;
        }
        if all_attempted_unsat && !cap_exhausted {
            search.state_sat.hypotheses_unsat = search.state_sat.hypotheses_unsat.saturating_add(1);
        }
        if !all_attempted_unsat {
            break;
        }
    }
    search.state_sat.elapsed = started.elapsed();
    Ok(())
}

struct StateSatEncoding {
    solver: BasicSolver,
    selection: BTreeMap<(usize, usize), Lit>,
    domains: BTreeMap<usize, Vec<usize>>,
    assignment_len: usize,
    variables: usize,
    clauses: usize,
}

impl StateSatEncoding {
    fn new(
        search: &LocalSearch<'_>,
        hypothesis: &[Option<usize>],
        base: &[usize],
    ) -> Result<Option<Self>, LymmDeckError> {
        let mut encoding = Self {
            solver: BasicSolver::default(),
            selection: BTreeMap::new(),
            domains: BTreeMap::new(),
            assignment_len: search.spec.pt_alphabet.len(),
            variables: 0,
            clauses: 0,
        };
        let letters = observed_letter_indices(search);
        for &letter in &letters {
            let candidates = search.candidates_for_letter(letter, hypothesis);
            if candidates.is_empty() {
                return Ok(None);
            }
            let mut literals = Vec::with_capacity(candidates.len());
            for &candidate in &candidates {
                let literal = encoding.new_literal();
                let _old = encoding.selection.insert((letter, candidate), literal);
                literals.push(literal);
            }
            encoding.add_exactly_one(&literals);
            let _old = encoding.domains.insert(letter, candidates);
        }
        let routes = encoding.add_letter_routes(search, base, &letters)?;
        encoding.add_message_states(search, &routes)?;
        Ok(Some(encoding))
    }

    fn add_letter_routes(
        &mut self,
        search: &LocalSearch<'_>,
        base: &[usize],
        letters: &[usize],
    ) -> Result<RouteDomains, LymmDeckError> {
        let mut routes = BTreeMap::new();
        for &letter in letters {
            let Some(candidates) = self.domains.get(&letter).cloned() else {
                continue;
            };
            for position in 0..search.config.n {
                let mut sources = BTreeSet::new();
                for &candidate_index in &candidates {
                    let candidate = search.domain.candidates.get(candidate_index).ok_or(
                        LymmDeckError::HiddenBaseConfig {
                            reason: "state-SAT candidate index left the sigma domain",
                        },
                    )?;
                    let sigma_source = candidate.sigma.get(position).copied().ok_or(
                        LymmDeckError::HiddenBaseConfig {
                            reason: "state-SAT sigma position left the deck",
                        },
                    )?;
                    let source =
                        base.get(sigma_source)
                            .copied()
                            .ok_or(LymmDeckError::HiddenBaseConfig {
                                reason: "state-SAT base source left the deck",
                            })?;
                    let _inserted = sources.insert(source);
                }
                let route_literals = sources
                    .into_iter()
                    .map(|source| (source, self.new_literal()))
                    .collect::<Vec<_>>();
                self.add_exactly_one(
                    &route_literals
                        .iter()
                        .map(|(_source, literal)| *literal)
                        .collect::<Vec<_>>(),
                );
                for &candidate_index in &candidates {
                    let candidate = search.domain.candidates.get(candidate_index).ok_or(
                        LymmDeckError::HiddenBaseConfig {
                            reason: "state-SAT candidate index left the sigma domain",
                        },
                    )?;
                    let sigma_source = candidate.sigma.get(position).copied().ok_or(
                        LymmDeckError::HiddenBaseConfig {
                            reason: "state-SAT sigma position left the deck",
                        },
                    )?;
                    let source =
                        base.get(sigma_source)
                            .copied()
                            .ok_or(LymmDeckError::HiddenBaseConfig {
                                reason: "state-SAT base source left the deck",
                            })?;
                    let selection = self
                        .selection
                        .get(&(letter, candidate_index))
                        .copied()
                        .ok_or(LymmDeckError::HiddenBaseConfig {
                            reason: "state-SAT selection literal was not allocated",
                        })?;
                    let route = route_literals
                        .iter()
                        .find_map(|&(found, literal)| (found == source).then_some(literal))
                        .ok_or(LymmDeckError::HiddenBaseConfig {
                            reason: "state-SAT route literal was not allocated",
                        })?;
                    self.add_clause(&[!selection, route]);
                }
                let _old = routes.insert((letter, position), route_literals);
            }
        }
        Ok(routes)
    }

    fn add_message_states(
        &mut self,
        search: &LocalSearch<'_>,
        routes: &RouteDomains,
    ) -> Result<(), LymmDeckError> {
        for message in &search.corpus.messages {
            let mut previous: Option<Vec<Vec<Lit>>> = None;
            for event in &message.events {
                let next = self.new_state(search.config.n);
                for position in 0..search.config.n {
                    let route_literals = routes.get(&(event.letter, position)).ok_or(
                        LymmDeckError::HiddenBaseConfig {
                            reason: "state-SAT event letter has no route domain",
                        },
                    )?;
                    for &(source, route) in route_literals {
                        if let Some(previous) = &previous {
                            for value in 0..search.config.n {
                                let previous_value = previous
                                    .get(source)
                                    .and_then(|row| row.get(value))
                                    .copied()
                                    .ok_or(LymmDeckError::HiddenBaseConfig {
                                        reason: "state-SAT previous state left the deck",
                                    })?;
                                let next_value = next
                                    .get(position)
                                    .and_then(|row| row.get(value))
                                    .copied()
                                    .ok_or(LymmDeckError::HiddenBaseConfig {
                                        reason: "state-SAT next state left the deck",
                                    })?;
                                self.add_clause(&[!route, !previous_value, next_value]);
                            }
                        } else {
                            let next_value = next
                                .get(position)
                                .and_then(|row| row.get(source))
                                .copied()
                                .ok_or(LymmDeckError::HiddenBaseConfig {
                                    reason: "state-SAT identity transition left the deck",
                                })?;
                            self.add_clause(&[!route, next_value]);
                        }
                    }
                }
                let emission = next
                    .first()
                    .and_then(|row| row.get(event.ct_value))
                    .copied()
                    .ok_or(LymmDeckError::HiddenBaseConfig {
                        reason: "state-SAT emission left the ciphertext alphabet",
                    })?;
                self.add_clause(&[emission]);
                previous = Some(next);
            }
        }
        Ok(())
    }

    fn new_state(&mut self, n: usize) -> Vec<Vec<Lit>> {
        (0..n)
            .map(|_position| {
                let row = (0..n).map(|_value| self.new_literal()).collect::<Vec<_>>();
                self.add_exactly_one(&row);
                row
            })
            .collect()
    }

    fn solve(&mut self) -> Result<Option<Vec<usize>>, LymmDeckError> {
        let status = self.solver.solve_limited(&[]);
        if status == lbool::FALSE {
            return Ok(None);
        }
        if status == lbool::UNDEF {
            return Err(LymmDeckError::HiddenBaseConfig {
                reason: "state-SAT solver returned an indeterminate result",
            });
        }
        let mut assignment = vec![0; self.assignment_len];
        for (&letter, candidates) in &self.domains {
            let selected = candidates.iter().find(|&&candidate| {
                self.selection
                    .get(&(letter, candidate))
                    .is_some_and(|&literal| self.solver.value_lit(literal) == lbool::TRUE)
            });
            let Some(&selected) = selected else {
                return Err(LymmDeckError::HiddenBaseConfig {
                    reason: "state-SAT model omitted a letter candidate",
                });
            };
            if let Some(slot) = assignment.get_mut(letter) {
                *slot = selected;
            }
        }
        Ok(Some(assignment))
    }

    fn new_literal(&mut self) -> Lit {
        self.variables = self.variables.saturating_add(1);
        Lit::new(self.solver.new_var(lbool::TRUE, true), true)
    }

    fn add_exactly_one(&mut self, literals: &[Lit]) {
        self.add_clause(literals);
        for (left_index, &left) in literals.iter().enumerate() {
            for &right in literals.iter().skip(left_index.saturating_add(1)) {
                self.add_clause(&[!left, !right]);
            }
        }
    }

    fn add_clause(&mut self, literals: &[Lit]) {
        let mut clause = literals.to_vec();
        let _still_satisfiable = self.solver.add_clause_reuse(&mut clause);
        self.clauses = self.clauses.saturating_add(1);
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

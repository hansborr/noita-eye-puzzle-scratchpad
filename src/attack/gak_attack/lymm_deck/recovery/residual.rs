//! SAT-backed residual solver for Lymm swap recovery.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use batsat::{BasicSolver, Lit, SolverInterface, lbool};

use super::super::{LymmComposeDirection, LymmDeckSpec, TopSwapDomains};
pub(super) use super::domain_build::build_residual_domains;
use super::domain_oracle::{CandidateWitness, LetterDomainOracle};
use super::instrumentation::{trace_residual, trace_stats};
use super::learning::{LearnedClause, TruthTracker, learn_sat_clause};
use super::ns3_cegar::recover_ns3_with_target_cegar;
use super::propagation::{PropagationOptions, propagate_partial_states};
use super::report::build_report_from_assignment;
use super::sat_encoding::{add_adjacent_transition_clauses, add_top_image_channel_clauses};
use super::state::apply_recovered_permutation;
use super::{
    AlignedMessage, RecoveryReport, SwapRecoveryConfig, SwapRecoveryError, SwapRecoveryStats,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ResidualDomains {
    pub(super) domains: TopSwapDomains,
    pub(super) oracle: LetterDomainOracle,
    pub(super) by_letter: BTreeMap<char, Vec<usize>>,
    pub(super) letters: Vec<char>,
}

impl ResidualDomains {
    pub(super) fn candidate_count(&self) -> usize {
        self.domains.candidates.len()
    }

    pub(super) fn image_mask(&self, candidate_index: usize, input_positions: u128) -> u128 {
        self.oracle
            .image_mask(&self.domains, candidate_index, input_positions)
    }

    pub(super) fn preimage_mask(&self, candidate_index: usize, image_positions: u128) -> u128 {
        self.oracle
            .preimage_mask(&self.domains, candidate_index, image_positions)
    }

    pub(super) fn transition_possible(
        &self,
        candidate_index: usize,
        post_position: usize,
        pre_position: usize,
    ) -> bool {
        self.oracle
            .transition_possible(&self.domains, candidate_index, post_position, pre_position)
    }

    pub(super) fn witness(&self, candidate_index: usize) -> Option<CandidateWitness> {
        self.oracle.witness(&self.domains, candidate_index)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct VerificationFailure {
    message_index: usize,
    event_index: usize,
}

#[derive(Clone, Debug, Default)]
struct TargetAssumptionLits {
    by_letter: BTreeMap<char, Lit>,
    lookup: BTreeMap<Lit, (char, usize)>,
    assumptions: Vec<Lit>,
}

struct CandidateConflictContext<'a> {
    messages: &'a [AlignedMessage],
    residual: &'a ResidualDomains,
    vars: &'a BTreeMap<(char, usize), Lit>,
    assignment: &'a BTreeMap<char, usize>,
    failure: &'a VerificationFailure,
}

struct ResidualSatProblem {
    solver: BasicSolver,
    vars: BTreeMap<(char, usize), Lit>,
    target_lits: TargetAssumptionLits,
}

pub(super) fn recover_with_residual(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    config: SwapRecoveryConfig,
) -> Result<RecoveryReport, SwapRecoveryError> {
    if config.max_swaps == 3 {
        if spec.compose_dir != LymmComposeDirection::Left {
            return Err(SwapRecoveryError::UnsupportedBudget {
                max_swaps: config.max_swaps,
            });
        }
        return recover_ns3_with_target_cegar(spec, messages, &config);
    }
    let residual = build_residual_domains(spec, messages, &config)?;
    let propagation_options = match spec.compose_dir {
        LymmComposeDirection::Left => PropagationOptions::ns2_default(),
        LymmComposeDirection::Right => PropagationOptions {
            max_passes: 0,
            exhaustive_arc: false,
        },
    };
    let truth = config.planted_truth().cloned().map(TruthTracker::new);
    recover_with_residual_domains(
        spec,
        messages,
        config,
        residual,
        propagation_options,
        None,
        truth.as_ref(),
    )
}

pub(super) fn recover_with_residual_domains(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    config: SwapRecoveryConfig,
    mut residual: ResidualDomains,
    options: PropagationOptions,
    target_assumptions: Option<&BTreeMap<char, usize>>,
    truth: Option<&TruthTracker>,
) -> Result<RecoveryReport, SwapRecoveryError> {
    let mut stats = SwapRecoveryStats {
        enumerated_candidates: residual.candidate_count(),
        ..SwapRecoveryStats::default()
    };
    let propagation = propagate_partial_states(spec, messages, &mut residual, &mut stats, options)?;
    if trace_residual("candidate", config.max_swaps, &residual, &stats) {
        return Err(SwapRecoveryError::SearchCapExceeded { nodes: stats.nodes });
    }
    let mut problem = build_residual_sat_problem(
        spec,
        messages,
        &propagation.state_domains,
        &residual,
        target_assumptions,
    );

    let started = Instant::now();
    loop {
        enforce_candidate_budget(&config, &stats, started)?;
        let sat = problem
            .solver
            .solve_limited(&problem.target_lits.assumptions);
        if sat == lbool::FALSE {
            trace_stats("candidate unsat", &stats);
            if target_assumptions.is_some() {
                let mut choices = problem
                    .solver
                    .unsat_core()
                    .iter()
                    .filter_map(|literal| problem.target_lits.lookup.get(literal).copied())
                    .collect::<Vec<_>>();
                choices.sort_unstable();
                choices.dedup();
                return Err(SwapRecoveryError::TargetUnsatCore { choices });
            }
            return Err(SwapRecoveryError::NoResidualCandidate);
        }
        if sat == lbool::UNDEF {
            return Err(SwapRecoveryError::SatSolver(
                "Batsat returned an indeterminate result".to_owned(),
            ));
        }

        stats.nodes += 1;
        stats.sat_decisions = usize::try_from(problem.solver.num_decisions()).unwrap_or(usize::MAX);
        stats.sat_conflicts = usize::try_from(problem.solver.num_conflicts()).unwrap_or(usize::MAX);
        let assignment = extract_assignment(&problem.solver, &residual, &problem.vars)?;
        match verify_candidate_assignment(spec, messages, &residual, &assignment)? {
            Ok(()) => {
                return build_report_from_assignment(
                    spec,
                    messages,
                    config,
                    &residual,
                    &assignment,
                    stats,
                );
            }
            Err(failure) => {
                stats.sat_conflicts += 1;
                add_prefix_conflict_clause(
                    &CandidateConflictContext {
                        messages,
                        residual: &residual,
                        vars: &problem.vars,
                        assignment: &assignment,
                        failure: &failure,
                    },
                    &mut problem.solver,
                    truth,
                    &mut stats,
                )?;
            }
        }
    }
}

pub(super) fn residual_formula_is_unsat(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    residual: &ResidualDomains,
    state_domains: &[Vec<Vec<u128>>],
    target_assumptions: Option<&BTreeMap<char, usize>>,
) -> Result<bool, SwapRecoveryError> {
    let mut problem =
        build_residual_sat_problem(spec, messages, state_domains, residual, target_assumptions);
    let sat = problem
        .solver
        .solve_limited(&problem.target_lits.assumptions);
    if sat == lbool::FALSE {
        Ok(true)
    } else if sat == lbool::TRUE {
        Ok(false)
    } else {
        Err(SwapRecoveryError::SatSolver(
            "Batsat returned an indeterminate result".to_owned(),
        ))
    }
}

fn build_residual_sat_problem(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    state_domains: &[Vec<Vec<u128>>],
    residual: &ResidualDomains,
    target_assumptions: Option<&BTreeMap<char, usize>>,
) -> ResidualSatProblem {
    let mut solver = BasicSolver::default();
    let mut vars: BTreeMap<(char, usize), Lit> = BTreeMap::new();
    let target_lits = build_target_assumptions(target_assumptions, &mut solver);

    for (&letter, domain) in &residual.by_letter {
        let literals = domain
            .iter()
            .map(|&candidate_index| {
                let variable = solver.new_var_default();
                let literal = Lit::new(variable, true);
                let _old = vars.insert((letter, candidate_index), literal);
                literal
            })
            .collect::<Vec<_>>();
        add_exactly_one_guarded(
            &mut solver,
            &literals,
            target_lits.by_letter.get(&letter).copied(),
        );
    }

    let top_vars = add_top_image_channel_clauses(spec, residual, &vars, &mut solver);
    add_adjacent_transition_clauses(
        spec,
        messages,
        state_domains,
        residual,
        &vars,
        &top_vars,
        &mut solver,
    );

    ResidualSatProblem {
        solver,
        vars,
        target_lits,
    }
}

fn enforce_candidate_budget(
    config: &SwapRecoveryConfig,
    stats: &SwapRecoveryStats,
    started: Instant,
) -> Result<(), SwapRecoveryError> {
    if let Some(max_nodes) = config.max_nodes
        && stats.nodes >= max_nodes
    {
        trace_stats("candidate cap", stats);
        return Err(SwapRecoveryError::SearchCapExceeded { nodes: stats.nodes });
    }
    if let Some(time_budget) = config.time_budget
        && started.elapsed() >= time_budget
    {
        trace_stats("candidate timeout", stats);
        return Err(SwapRecoveryError::SearchTimeExceeded { nodes: stats.nodes });
    }
    Ok(())
}

pub(super) fn restrict_to_targets(
    residual: &mut ResidualDomains,
    targets: &BTreeMap<char, usize>,
) -> Result<(), SwapRecoveryError> {
    for (&letter, &target) in targets {
        let Some(domain) = residual.by_letter.get(&letter) else {
            continue;
        };
        let filtered = domain
            .iter()
            .copied()
            .filter(|&candidate_index| {
                residual
                    .domains
                    .candidates
                    .get(candidate_index)
                    .is_some_and(|candidate| candidate.top_image == target)
            })
            .collect::<Vec<_>>();
        if filtered.is_empty() {
            return Err(SwapRecoveryError::NoResidualCandidate);
        }
        let _old = residual.by_letter.insert(letter, filtered);
    }
    Ok(())
}

fn build_target_assumptions(
    targets: Option<&BTreeMap<char, usize>>,
    solver: &mut BasicSolver,
) -> TargetAssumptionLits {
    let Some(targets) = targets else {
        return TargetAssumptionLits::default();
    };
    let mut target_lits = TargetAssumptionLits::default();
    for (&letter, &target) in targets {
        let literal = Lit::new(solver.new_var(lbool::TRUE, true), true);
        let _old = target_lits.by_letter.insert(letter, literal);
        let _old = target_lits.lookup.insert(literal, (letter, target));
        target_lits.assumptions.push(literal);
    }
    target_lits
}

fn add_exactly_one_guarded(solver: &mut BasicSolver, literals: &[Lit], guard: Option<Lit>) {
    let mut at_least_one =
        Vec::with_capacity(literals.len().saturating_add(usize::from(guard.is_some())));
    if let Some(guard) = guard {
        at_least_one.push(!guard);
    }
    at_least_one.extend_from_slice(literals);
    add_static_encoding_clause(solver, &at_least_one);
    if literals.len() <= 1 {
        return;
    }
    let mut previous_aux = None;
    for (index, &literal) in literals.iter().enumerate() {
        let is_last = index + 1 == literals.len();
        match (index, is_last, previous_aux) {
            (0, false, None) => {
                let aux = Lit::new(solver.new_var_default(), true);
                add_static_encoding_clause(solver, &[!literal, aux]);
                previous_aux = Some(aux);
            }
            (_, true, Some(prev)) => {
                add_static_encoding_clause(solver, &[!literal, !prev]);
            }
            (_, false, Some(prev)) => {
                let aux = Lit::new(solver.new_var_default(), true);
                add_static_encoding_clause(solver, &[!literal, aux]);
                add_static_encoding_clause(solver, &[!prev, aux]);
                add_static_encoding_clause(solver, &[!literal, !prev]);
                previous_aux = Some(aux);
            }
            _ => {}
        }
    }
}

fn extract_assignment(
    solver: &BasicSolver,
    residual: &ResidualDomains,
    vars: &BTreeMap<(char, usize), Lit>,
) -> Result<BTreeMap<char, usize>, SwapRecoveryError> {
    let mut assignment = BTreeMap::new();
    for &letter in &residual.letters {
        let Some(domain) = residual.by_letter.get(&letter) else {
            continue;
        };
        let selected = domain.iter().find_map(|&candidate_index| {
            vars.get(&(letter, candidate_index))
                .is_some_and(|&literal| solver.value_lit(literal) == lbool::TRUE)
                .then_some(candidate_index)
        });
        let Some(candidate_index) = selected else {
            return Err(SwapRecoveryError::NoResidualCandidate);
        };
        let _old = assignment.insert(letter, candidate_index);
    }
    Ok(assignment)
}

pub(super) fn verify_candidate_assignment(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    residual: &ResidualDomains,
    assignment: &BTreeMap<char, usize>,
) -> Result<Result<(), VerificationFailure>, SwapRecoveryError> {
    for (message_index, message) in messages.iter().enumerate() {
        let mut state = spec.initial_state.clone();
        for (event_index, event) in message.events.iter().enumerate() {
            let Some(&candidate_index) = assignment.get(&event.letter) else {
                return Ok(Err(VerificationFailure {
                    message_index,
                    event_index,
                }));
            };
            let witness = residual
                .witness(candidate_index)
                .ok_or(SwapRecoveryError::NoResidualCandidate)?;
            state = apply_recovered_permutation(spec, &witness.permutation, &state)?;
            if state.get(spec.emit_index).copied() != Some(event.ct_value) {
                return Ok(Err(VerificationFailure {
                    message_index,
                    event_index,
                }));
            }
        }
    }
    Ok(Ok(()))
}

fn add_prefix_conflict_clause(
    context: &CandidateConflictContext<'_>,
    solver: &mut BasicSolver,
    truth: Option<&TruthTracker>,
    stats: &mut SwapRecoveryStats,
) -> Result<(), SwapRecoveryError> {
    let Some(message) = context.messages.get(context.failure.message_index) else {
        return Ok(());
    };
    let mut seen = BTreeSet::new();
    let mut clause = Vec::new();
    let mut choices = Vec::new();
    for event in message
        .events
        .iter()
        .take(context.failure.event_index.saturating_add(1))
    {
        if !seen.insert(event.letter) {
            continue;
        }
        let Some(&candidate_index) = context.assignment.get(&event.letter) else {
            continue;
        };
        if !context
            .residual
            .by_letter
            .get(&event.letter)
            .is_some_and(|domain| domain.contains(&candidate_index))
        {
            continue;
        }
        if let Some(&literal) = context.vars.get(&(event.letter, candidate_index))
            && let Some(witness) = context.residual.witness(candidate_index)
        {
            clause.push(!literal);
            choices.push((event.letter, witness.permutation));
        }
    }
    if !clause.is_empty() {
        learn_sat_clause(
            solver,
            &clause,
            &LearnedClause::Candidate(choices),
            truth,
            stats,
        )?;
    }
    Ok(())
}

fn add_static_encoding_clause(solver: &mut BasicSolver, literals: &[Lit]) {
    debug_assert!(!literals.is_empty());
    // Static residual-encoding clauses only. Learned candidate clauses must go
    // through learn_sat_clause so truth-preservation checks and stats run.
    let mut clause = literals.to_vec();
    let _still_satisfiable = solver.add_clause_reuse(&mut clause);
}

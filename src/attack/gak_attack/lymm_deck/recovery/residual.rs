//! SAT-backed residual solver for Lymm swap recovery.

use std::collections::{BTreeMap, BTreeSet};

use batsat::{BasicSolver, Lit, SolverInterface, lbool};

use super::super::{
    LymmDeckError, LymmDeckSpec, TopSwapConstraints, TopSwapDomains, compose_lymm,
    enumerate_top_swap_domains,
};
use super::propagation::propagate_partial_states;
use super::{
    AlignedEvent, AlignedMessage, LetterRecoveryVerdict, RecoveredLetter, RecoveryReport,
    SwapRecoveryConfig, SwapRecoveryError, SwapRecoveryStats, occurrence_counts,
    pairs_from_messages, report_shell, round_trip_check,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CandidateRuntime {
    pub(super) perm: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ResidualDomains {
    pub(super) domains: TopSwapDomains,
    pub(super) candidates: Vec<CandidateRuntime>,
    pub(super) by_letter: BTreeMap<char, Vec<usize>>,
    pub(super) letters: Vec<char>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VerificationFailure {
    message_index: usize,
    event_index: usize,
}

pub(super) fn recover_with_residual(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    config: SwapRecoveryConfig,
) -> Result<RecoveryReport, SwapRecoveryError> {
    let mut residual = build_residual_domains(spec, messages, config.max_swaps)?;
    let mut stats = SwapRecoveryStats {
        enumerated_candidates: residual.candidates.len(),
        ..SwapRecoveryStats::default()
    };
    propagate_partial_states(spec, messages, &mut residual, &mut stats)?;
    let mut solver = BasicSolver::default();
    let mut vars: BTreeMap<(char, usize), Lit> = BTreeMap::new();

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
        add_exactly_one(&mut solver, &literals);
    }

    add_initial_prefix_clauses(messages, &residual, &vars, &mut solver);

    loop {
        if let Some(max_nodes) = config.max_nodes
            && stats.nodes >= max_nodes
        {
            return Err(SwapRecoveryError::SearchCapExceeded { nodes: stats.nodes });
        }
        let sat = solver.solve_limited(&[]);
        if sat == lbool::FALSE {
            return Err(SwapRecoveryError::NoResidualCandidate);
        }
        if sat == lbool::UNDEF {
            return Err(SwapRecoveryError::SatSolver(
                "Batsat returned an indeterminate result".to_owned(),
            ));
        }

        stats.nodes += 1;
        stats.sat_decisions = usize::try_from(solver.num_decisions()).unwrap_or(usize::MAX);
        stats.sat_conflicts = usize::try_from(solver.num_conflicts()).unwrap_or(usize::MAX);
        let assignment = extract_assignment(&solver, &residual, &vars)?;
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
                    messages,
                    &residual,
                    &vars,
                    &assignment,
                    &failure,
                    &mut solver,
                );
            }
        }
    }
}

fn build_residual_domains(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    max_swaps: usize,
) -> Result<ResidualDomains, SwapRecoveryError> {
    let domains = enumerate_top_swap_domains(spec, &TopSwapConstraints::up_to(max_swaps))?;
    let candidates = domains
        .candidates
        .iter()
        .map(|candidate| CandidateRuntime {
            perm: candidate.permutation(spec),
        })
        .collect::<Vec<_>>();
    let mut observed = occurrence_counts(spec, messages)
        .into_iter()
        .filter_map(|(letter, count)| (count > 0).then_some(letter))
        .collect::<Vec<_>>();
    observed.sort_unstable();

    let initial_targets = identity_restart_targets(messages);
    let mut by_letter = BTreeMap::new();
    for &letter in &observed {
        let domain = match initial_targets.get(&letter).copied() {
            Some(target) => domains
                .by_top_image
                .get(&target)
                .cloned()
                .unwrap_or_default(),
            None => (0..domains.candidates.len()).collect(),
        };
        if domain.is_empty() {
            return Err(SwapRecoveryError::NoCandidateForTarget {
                letter,
                target: initial_targets.get(&letter).copied().unwrap_or(usize::MAX),
            });
        }
        let _old = by_letter.insert(letter, domain);
    }

    Ok(ResidualDomains {
        domains,
        candidates,
        by_letter,
        letters: observed,
    })
}

fn identity_restart_targets(messages: &[AlignedMessage]) -> BTreeMap<char, usize> {
    let mut targets = BTreeMap::new();
    for message in messages {
        if let Some(event) = message.events.first() {
            let _old = targets.entry(event.letter).or_insert(event.ct_value);
        }
    }
    targets
}

fn add_exactly_one(solver: &mut BasicSolver, literals: &[Lit]) {
    add_sat_clause(solver, literals);
    if literals.len() <= 1 {
        return;
    }
    let mut previous_aux = None;
    for (index, &literal) in literals.iter().enumerate() {
        let is_last = index + 1 == literals.len();
        match (index, is_last, previous_aux) {
            (0, false, None) => {
                let aux = Lit::new(solver.new_var_default(), true);
                add_sat_clause(solver, &[!literal, aux]);
                previous_aux = Some(aux);
            }
            (_, true, Some(prev)) => {
                add_sat_clause(solver, &[!literal, !prev]);
            }
            (_, false, Some(prev)) => {
                let aux = Lit::new(solver.new_var_default(), true);
                add_sat_clause(solver, &[!literal, aux]);
                add_sat_clause(solver, &[!prev, aux]);
                add_sat_clause(solver, &[!literal, !prev]);
                previous_aux = Some(aux);
            }
            _ => {}
        }
    }
}

fn add_initial_prefix_clauses(
    messages: &[AlignedMessage],
    residual: &ResidualDomains,
    vars: &BTreeMap<(char, usize), Lit>,
    solver: &mut BasicSolver,
) {
    for message in messages {
        if message.events.len() >= 2
            && let (Some(first), Some(second)) = (message.events.first(), message.events.get(1))
        {
            add_start_bigram_clauses(first, second, residual, vars, solver);
        }
    }
}

fn add_start_bigram_clauses(
    first: &AlignedEvent,
    second: &AlignedEvent,
    residual: &ResidualDomains,
    vars: &BTreeMap<(char, usize), Lit>,
    solver: &mut BasicSolver,
) {
    let Some(first_domain) = residual.by_letter.get(&first.letter) else {
        return;
    };
    let Some(second_domain) = residual.by_letter.get(&second.letter) else {
        return;
    };
    for &first_candidate in first_domain {
        let mut clause = Vec::new();
        if let Some(&literal) = vars.get(&(first.letter, first_candidate)) {
            clause.push(!literal);
        }
        let Some(first_perm) = residual
            .candidates
            .get(first_candidate)
            .map(|candidate| &candidate.perm)
        else {
            continue;
        };
        for &second_candidate in second_domain {
            let Some(second_top) = residual
                .domains
                .candidates
                .get(second_candidate)
                .map(|candidate| candidate.top_image)
            else {
                continue;
            };
            if first_perm.get(second_top).copied() == Some(second.ct_value)
                && let Some(&literal) = vars.get(&(second.letter, second_candidate))
            {
                clause.push(literal);
            }
        }
        if clause.len() > 1 {
            add_sat_clause(solver, &clause);
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

fn verify_candidate_assignment(
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
            let candidate = residual
                .candidates
                .get(candidate_index)
                .ok_or(SwapRecoveryError::NoResidualCandidate)?;
            state = compose_lymm(&candidate.perm, &state).map_err(LymmDeckError::from)?;
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
    messages: &[AlignedMessage],
    residual: &ResidualDomains,
    vars: &BTreeMap<(char, usize), Lit>,
    assignment: &BTreeMap<char, usize>,
    failure: &VerificationFailure,
    solver: &mut BasicSolver,
) {
    let Some(message) = messages.get(failure.message_index) else {
        return;
    };
    let mut seen = BTreeSet::new();
    let mut clause = Vec::new();
    for event in message
        .events
        .iter()
        .take(failure.event_index.saturating_add(1))
    {
        if !seen.insert(event.letter) {
            continue;
        }
        let Some(&candidate_index) = assignment.get(&event.letter) else {
            continue;
        };
        if !residual
            .by_letter
            .get(&event.letter)
            .is_some_and(|domain| domain.contains(&candidate_index))
        {
            continue;
        }
        if let Some(&literal) = vars.get(&(event.letter, candidate_index)) {
            clause.push(!literal);
        }
    }
    if !clause.is_empty() {
        add_sat_clause(solver, &clause);
    }
}

fn add_sat_clause(solver: &mut BasicSolver, literals: &[Lit]) {
    let mut clause = literals.to_vec();
    let _still_satisfiable = solver.add_clause_reuse(&mut clause);
}

fn build_report_from_assignment(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    config: SwapRecoveryConfig,
    residual: &ResidualDomains,
    assignment: &BTreeMap<char, usize>,
    stats: SwapRecoveryStats,
) -> Result<RecoveryReport, SwapRecoveryError> {
    let mut occurrences = occurrence_counts(spec, messages);
    let mut used_targets = BTreeSet::new();
    let mut pt_mapping = BTreeMap::new();
    let mut letters = Vec::with_capacity(spec.pt_alphabet.len());
    for &letter in &spec.pt_alphabet {
        let count = occurrences.remove(&letter).unwrap_or(0);
        let candidate_index = assignment
            .get(&letter)
            .copied()
            .or_else(|| {
                residual
                    .by_letter
                    .get(&letter)
                    .and_then(|domain| domain.first().copied())
            })
            .or(Some(0));
        let candidate = candidate_index.and_then(|index| residual.domains.candidates.get(index));
        let runtime = candidate_index.and_then(|index| residual.candidates.get(index));
        if let Some(found) = runtime {
            let _old = pt_mapping.insert(letter, found.perm.clone());
        }
        let target = candidate.map(|found| found.top_image);
        let no_doubles = target.is_none_or(|value| value != 0 && used_targets.insert(value));
        let equivalent_count = residual
            .by_letter
            .get(&letter)
            .map_or(usize::from(candidate.is_some()), Vec::len);
        let verdict = if count == 0 {
            LetterRecoveryVerdict::NoCandidate
        } else {
            LetterRecoveryVerdict::Candidate
        };
        letters.push(RecoveredLetter {
            letter,
            occurrences: count,
            target,
            support: candidate.map_or_else(Vec::new, |found| found.support.clone()),
            permutation: runtime.map(|found| found.perm.clone()),
            canonical_swaps: candidate.map_or_else(Vec::new, |found| found.canonical_swaps.clone()),
            equivalent_count,
            no_doubles,
            verdict,
        });
    }
    let placeholder = report_shell(config, letters, pt_mapping, stats);
    let pairs = pairs_from_messages(messages);
    let round_trip = round_trip_check(spec, &placeholder, &pairs)?;
    let mut report = placeholder;
    report.round_trip = round_trip;
    Ok(report)
}

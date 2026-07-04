//! SAT-backed residual solver for Lymm swap recovery.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use batsat::{BasicSolver, Lit, SolverInterface, lbool};

use super::super::{
    LymmDeckError, LymmDeckSpec, TopSwapConstraints, TopSwapDomains, compose_lymm,
    enumerate_top_swap_domains,
};
use super::propagation::{PropagationOptions, propagate_partial_states};
use super::sat_encoding::{add_adjacent_transition_clauses, add_top_image_channel_clauses};
use super::target_solver::TargetAssignmentSolver;
use super::{
    AlignedMessage, LetterRecoveryVerdict, RecoveredLetter, RecoveryReport, SwapRecoveryConfig,
    SwapRecoveryError, SwapRecoveryStats, occurrence_counts, pairs_from_messages, report_shell,
    round_trip_check,
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

pub(super) fn recover_with_residual(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    config: SwapRecoveryConfig,
) -> Result<RecoveryReport, SwapRecoveryError> {
    if config.max_swaps == 3 {
        return recover_ns3_with_target_cegar(spec, messages, config);
    }
    let residual = build_residual_domains(spec, messages, config.max_swaps)?;
    recover_with_residual_domains(
        spec,
        messages,
        config,
        residual,
        PropagationOptions::ns2_default(),
        None,
    )
}

fn recover_ns3_with_target_cegar(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    config: SwapRecoveryConfig,
) -> Result<RecoveryReport, SwapRecoveryError> {
    let mut residual = build_residual_domains(spec, messages, config.max_swaps)?;
    let mut stats = SwapRecoveryStats {
        enumerated_candidates: residual.candidates.len(),
        ..SwapRecoveryStats::default()
    };
    let propagation = propagate_partial_states(
        spec,
        messages,
        &mut residual,
        &mut stats,
        PropagationOptions::ns3_broad(),
    )?;
    if trace_residual("target", config.max_swaps, &residual, &stats) {
        return Err(SwapRecoveryError::SearchCapExceeded { nodes: 0 });
    }
    if std::env::var_os("NOITA_SWAP_CEGAR_TRACE").is_some() {
        eprintln!("cegar: building target solver");
    }
    let mut target_solver =
        TargetAssignmentSolver::new(spec, messages, &propagation.state_domains, &residual);
    if std::env::var_os("NOITA_SWAP_CEGAR_TRACE").is_some() {
        eprintln!("cegar: target solver built");
    }
    let mut target_nodes = 0usize;
    loop {
        if let Some(max_nodes) = config.max_nodes
            && target_nodes >= max_nodes
        {
            return Err(SwapRecoveryError::SearchCapExceeded {
                nodes: target_nodes,
            });
        }
        let Some(targets) = target_solver.next_assignment()? else {
            return Err(SwapRecoveryError::NoResidualCandidate);
        };
        target_nodes = target_nodes.saturating_add(1);
        if std::env::var_os("NOITA_SWAP_CEGAR_TRACE").is_some() {
            eprintln!("cegar: target assignment {target_nodes}: {targets:?}");
        }
        let mut targeted = residual.clone();
        restrict_to_targets(&mut targeted, &targets)?;
        if std::env::var_os("NOITA_SWAP_CEGAR_TRACE").is_some() {
            let total = targeted
                .by_letter
                .values()
                .map(std::vec::Vec::len)
                .sum::<usize>();
            let max = targeted
                .by_letter
                .values()
                .map(std::vec::Vec::len)
                .max()
                .unwrap_or(0);
            eprintln!("cegar: targeted entries={total} max_domain={max}");
        }
        match recover_with_residual_domains(
            spec,
            messages,
            config,
            targeted,
            PropagationOptions::ns2_default(),
            Some(&targets),
        ) {
            Ok(mut report) => {
                report.stats.nodes = report.stats.nodes.saturating_add(target_nodes);
                return Ok(report);
            }
            Err(SwapRecoveryError::TargetUnsatCore { choices }) => {
                if std::env::var_os("NOITA_SWAP_CEGAR_TRACE").is_some() {
                    eprintln!("cegar: learned target core size={}", choices.len());
                }
                if choices.is_empty() {
                    target_solver.forbid_assignment(&targets);
                } else {
                    target_solver.forbid_core(&choices);
                }
            }
            Err(SwapRecoveryError::NoResidualCandidate) => {
                target_solver.forbid_assignment(&targets);
            }
            Err(error) => return Err(error),
        }
    }
}

fn recover_with_residual_domains(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    config: SwapRecoveryConfig,
    mut residual: ResidualDomains,
    options: PropagationOptions,
    target_assumptions: Option<&BTreeMap<char, usize>>,
) -> Result<RecoveryReport, SwapRecoveryError> {
    let mut stats = SwapRecoveryStats {
        enumerated_candidates: residual.candidates.len(),
        ..SwapRecoveryStats::default()
    };
    let propagation = propagate_partial_states(spec, messages, &mut residual, &mut stats, options)?;
    if trace_residual("candidate", config.max_swaps, &residual, &stats) {
        return Err(SwapRecoveryError::SearchCapExceeded { nodes: stats.nodes });
    }
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

    let top_vars = add_top_image_channel_clauses(spec, &residual, &vars, &mut solver);
    add_adjacent_transition_clauses(
        spec,
        messages,
        &propagation.state_domains,
        &residual,
        &vars,
        &top_vars,
        &mut solver,
    );

    let started = Instant::now();
    loop {
        if let Some(max_nodes) = config.max_nodes
            && stats.nodes >= max_nodes
        {
            return Err(SwapRecoveryError::SearchCapExceeded { nodes: stats.nodes });
        }
        if let Some(time_budget) = config.time_budget
            && started.elapsed() >= time_budget
        {
            return Err(SwapRecoveryError::SearchTimeExceeded { nodes: stats.nodes });
        }
        let sat = solver.solve_limited(&target_lits.assumptions);
        if sat == lbool::FALSE {
            if target_assumptions.is_some() {
                let mut choices = solver
                    .unsat_core()
                    .iter()
                    .filter_map(|literal| target_lits.lookup.get(literal).copied())
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

pub(super) fn build_residual_domains(
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

fn trace_residual(
    label: &str,
    max_swaps: usize,
    residual: &ResidualDomains,
    stats: &SwapRecoveryStats,
) -> bool {
    if std::env::var_os("NOITA_SWAP_TRACE_ONLY").is_none() {
        return false;
    }
    if let Ok(phase) = std::env::var("NOITA_SWAP_TRACE_PHASE")
        && phase != label
    {
        return false;
    }
    let total = residual
        .by_letter
        .values()
        .map(std::vec::Vec::len)
        .sum::<usize>();
    let max = residual
        .by_letter
        .values()
        .map(std::vec::Vec::len)
        .max()
        .unwrap_or(0);
    eprintln!(
        "trace {label} max_swaps={max_swaps} candidates={} total_domain_entries={total} max_domain={max} pruned={} deductions={}",
        residual.candidates.len(),
        stats.domains_pruned,
        stats.deductions
    );
    for (&letter, domain) in &residual.by_letter {
        eprintln!("trace {label} letter {letter}: {}", domain.len());
    }
    true
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
    add_sat_clause(solver, &at_least_one);
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
        let candidate_permutations =
            residual
                .by_letter
                .get(&letter)
                .map_or_else(Vec::new, |domain| {
                    domain
                        .iter()
                        .filter_map(|&index| residual.candidates.get(index))
                        .map(|candidate| candidate.perm.clone())
                        .collect()
                });
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
            candidate_permutations,
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
    classify_exact_residual_report(&mut report);
    Ok(report)
}

fn classify_exact_residual_report(report: &mut RecoveryReport) {
    if !report.round_trip.exact() {
        report.verdict = LetterRecoveryVerdict::Candidate;
        return;
    }

    let mut all_unique = true;
    let mut any_observed = false;
    for letter in &mut report.letters {
        if letter.occurrences == 0 {
            letter.verdict = LetterRecoveryVerdict::NoCandidate;
            continue;
        }
        any_observed = true;
        if letter.equivalent_count == 1 {
            letter.verdict = LetterRecoveryVerdict::RecoveredUnique;
        } else {
            letter.verdict = LetterRecoveryVerdict::RecoveredAmbiguous;
            all_unique = false;
        }
    }
    report.verdict = if any_observed && all_unique {
        LetterRecoveryVerdict::RecoveredUnique
    } else if any_observed {
        LetterRecoveryVerdict::RecoveredAmbiguous
    } else {
        LetterRecoveryVerdict::NoCandidate
    };
}

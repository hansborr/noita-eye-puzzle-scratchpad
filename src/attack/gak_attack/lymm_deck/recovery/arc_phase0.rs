//! Phase-0 arc-provenance measurement for ns=3 target rejections.

use std::collections::BTreeMap;
use std::time::Instant;

use super::arc_phase0_tuple::estimate_tuple_kill;
use super::arc_phase0_types::{
    GakSwapArcContextBin, GakSwapArcPhase0Config, GakSwapArcPhase0Report, GakSwapArcPhase0Stop,
    GakSwapArcRejection, InternalMinimizedReason,
};
use super::domain_build::build_residual_domains;
use super::propagation::{
    PropagationOptions, propagate_partial_states, propagate_partial_states_with_target_reasons,
};
use super::residual::{ResidualDomains, restrict_to_targets};
use super::target_conflict::{
    broad_residual_rejects_target_choices, extract_deterministic_target_conflict,
};
use super::target_reason::{ArcLiteral, ArcReason};
use super::target_solver::TargetAssignmentSolver;
use super::{
    AlignedMessage, SwapRecoveryConfig, SwapRecoveryError, SwapRecoveryStats, align_pairs,
};
use crate::attack::gak_attack::lymm_deck::{KnownPlaintextPair, LymmDeckSpec};

/// Measures ns=3 deterministic target rejections in the Phase-0 arc vocabulary.
///
/// # Errors
/// Returns [`SwapRecoveryError`] when the input cannot be aligned, domains cannot
/// be built, or a broad replay invariant fails while advancing the target sampler.
pub fn measure_ns3_arc_provenance(
    spec: &LymmDeckSpec,
    pairs: &[KnownPlaintextPair],
    config: GakSwapArcPhase0Config,
) -> Result<GakSwapArcPhase0Report, SwapRecoveryError> {
    let messages = align_pairs(spec, pairs)?;
    let recovery_config = SwapRecoveryConfig::with_max_swaps(3);
    let mut residual = build_residual_domains(spec, &messages, &recovery_config)?;
    let mut broad_stats = SwapRecoveryStats {
        enumerated_candidates: residual.candidates.len(),
        ..SwapRecoveryStats::default()
    };
    let propagation = propagate_partial_states(
        spec,
        &messages,
        &mut residual,
        &mut broad_stats,
        PropagationOptions::ns3_broad(),
    )?;
    let enumerated_candidates = residual.candidates.len();
    let mut target_solver =
        TargetAssignmentSolver::new(spec, &messages, &propagation.state_domains, &residual);
    let target_domains = target_domains(&target_solver, &residual.letters);
    let started = Instant::now();
    let mut target_nodes = 0usize;
    let mut rejections = Vec::new();
    let mut learning_stats = SwapRecoveryStats::default();

    let stop = loop {
        if rejections.len() >= config.max_rejections {
            break GakSwapArcPhase0Stop::RejectionCap;
        }
        if started.elapsed() >= config.wall_time {
            break GakSwapArcPhase0Stop::TimeBudget;
        }
        let Some(targets) = target_solver.next_assignment()? else {
            break GakSwapArcPhase0Stop::TargetExhausted;
        };
        target_nodes = target_nodes.saturating_add(1);
        let Some(raw_reason) =
            extract_arc_reason_for_targets(spec, &messages, &residual, &targets)?
        else {
            break GakSwapArcPhase0Stop::NonDeterministicTargetSlice;
        };
        let minimized = minimize_arc_reason(
            spec,
            &messages,
            &residual,
            &raw_reason,
            config.replays_per_rejection,
        )?;
        let tuple_kill_estimate = minimized.bin.counts_for_go_rule().then(|| {
            estimate_tuple_kill(
                spec,
                &messages,
                &residual,
                &target_domains,
                &targets,
                &minimized,
                config.spot_check_samples,
            )
        });
        rejections.push(GakSwapArcRejection {
            node: target_nodes,
            targets: targets
                .iter()
                .map(|(&letter, &target)| (letter, target))
                .collect(),
            raw_arc_literals: raw_reason
                .arc_literals
                .iter()
                .copied()
                .map(Into::into)
                .collect(),
            raw_context_targets: raw_reason.context_targets.iter().copied().collect(),
            minimized_arc_literals: minimized.arcs.iter().copied().map(Into::into).collect(),
            minimized_context_targets: minimized.context_targets.clone(),
            bin: minimized.bin,
            literal_count: minimized.literal_count,
            literal_count_is_upper_bound: minimized.literal_count_is_upper_bound,
            replay_checks: minimized.replay_checks,
            tuple_kill_estimate,
        });
        learn_existing_target_clause(
            &mut target_solver,
            spec,
            &messages,
            &residual,
            &targets,
            &mut learning_stats,
        )?;
    };

    Ok(GakSwapArcPhase0Report {
        config,
        enumerated_candidates,
        broad_stats,
        target_nodes,
        stop,
        rejections,
    })
}

fn extract_arc_reason_for_targets(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    broad_baseline: &ResidualDomains,
    targets: &BTreeMap<char, usize>,
) -> Result<Option<ArcReason>, SwapRecoveryError> {
    let mut probe = broad_baseline.clone();
    match restrict_to_targets(&mut probe, targets) {
        Ok(()) => {}
        Err(SwapRecoveryError::NoResidualCandidate) => return Ok(Some(context_reason(targets))),
        Err(error) => return Err(error),
    }
    let mut probe_stats = SwapRecoveryStats {
        enumerated_candidates: probe.candidates.len(),
        ..SwapRecoveryStats::default()
    };
    let mut tracker = None;
    match propagate_partial_states_with_target_reasons(
        spec,
        messages,
        &mut probe,
        &mut probe_stats,
        PropagationOptions {
            max_passes: 2,
            exhaustive_arc: false,
        },
        targets,
        &mut tracker,
    ) {
        Ok(_) => Ok(None),
        Err(SwapRecoveryError::NoResidualCandidate) => Ok(tracker
            .and_then(|tracker| tracker.conflict_arc_reason())
            .or_else(|| Some(context_reason(targets)))),
        Err(error) => Err(error),
    }
}

fn context_reason(targets: &BTreeMap<char, usize>) -> ArcReason {
    targets
        .iter()
        .fold(ArcReason::default(), |mut reason, (&letter, &target)| {
            reason.union_with(&ArcReason::from_context_target(letter, target));
            reason
        })
}

pub(super) fn minimize_arc_reason(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    broad_baseline: &ResidualDomains,
    raw_reason: &ArcReason,
    replay_cap: usize,
) -> Result<InternalMinimizedReason, SwapRecoveryError> {
    let mut budget = ReplayBudget::new(replay_cap);
    let raw_arcs = raw_reason.arc_literals.iter().copied().collect::<Vec<_>>();
    if !raw_arcs.is_empty()
        && replay_with_budget(spec, messages, broad_baseline, &raw_arcs, &[], &mut budget)?
    {
        let (arcs, capped) =
            minimize_arc_only(spec, messages, broad_baseline, raw_arcs, &mut budget)?;
        let literal_count = arcs.len();
        return Ok(InternalMinimizedReason {
            arcs,
            context_targets: Vec::new(),
            bin: GakSwapArcContextBin::ContextFree,
            literal_count,
            literal_count_is_upper_bound: capped,
            replay_checks: budget.used,
        });
    }

    let mut arcs = raw_reason.arc_literals.iter().copied().collect::<Vec<_>>();
    let mut context_targets = raw_reason
        .context_targets
        .iter()
        .copied()
        .collect::<Vec<_>>();
    if replay_with_budget(
        spec,
        messages,
        broad_baseline,
        &arcs,
        &context_targets,
        &mut budget,
    )? {
        let capped = minimize_mixed_reason(
            spec,
            messages,
            broad_baseline,
            &mut arcs,
            &mut context_targets,
            &mut budget,
        )?;
        let literal_count = arcs.len().saturating_add(context_targets.len());
        return Ok(InternalMinimizedReason {
            arcs,
            context_targets,
            bin: GakSwapArcContextBin::ContextExpressible,
            literal_count,
            literal_count_is_upper_bound: capped,
            replay_checks: budget.used,
        });
    }

    let literal_count = raw_reason
        .arc_literals
        .len()
        .saturating_add(raw_reason.context_targets.len());
    Ok(InternalMinimizedReason {
        arcs: raw_reason.arc_literals.iter().copied().collect(),
        context_targets: raw_reason.context_targets.iter().copied().collect(),
        bin: GakSwapArcContextBin::ContextOpaque,
        literal_count,
        literal_count_is_upper_bound: budget.exhausted(),
        replay_checks: budget.used,
    })
}

fn minimize_arc_only(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    broad_baseline: &ResidualDomains,
    mut arcs: Vec<ArcLiteral>,
    budget: &mut ReplayBudget,
) -> Result<(Vec<ArcLiteral>, bool), SwapRecoveryError> {
    let mut capped = false;
    let mut index = 0usize;
    while index < arcs.len() {
        if budget.exhausted() {
            capped = true;
            break;
        }
        let removed = arcs.remove(index);
        if replay_with_budget(spec, messages, broad_baseline, &arcs, &[], budget)? {
            continue;
        }
        arcs.insert(index, removed);
        index = index.saturating_add(1);
    }
    Ok((arcs, capped))
}

fn minimize_mixed_reason(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    broad_baseline: &ResidualDomains,
    arcs: &mut Vec<ArcLiteral>,
    context_targets: &mut Vec<(char, usize)>,
    budget: &mut ReplayBudget,
) -> Result<bool, SwapRecoveryError> {
    let mut capped = false;
    let mut context_index = 0usize;
    while context_index < context_targets.len() {
        if budget.exhausted() {
            capped = true;
            break;
        }
        let removed = context_targets.remove(context_index);
        if replay_with_budget(
            spec,
            messages,
            broad_baseline,
            arcs,
            context_targets,
            budget,
        )? {
            continue;
        }
        context_targets.insert(context_index, removed);
        context_index = context_index.saturating_add(1);
    }
    let mut arc_index = 0usize;
    while arc_index < arcs.len() {
        if budget.exhausted() {
            capped = true;
            break;
        }
        let removed = arcs.remove(arc_index);
        if replay_with_budget(
            spec,
            messages,
            broad_baseline,
            arcs,
            context_targets,
            budget,
        )? {
            continue;
        }
        arcs.insert(arc_index, removed);
        arc_index = arc_index.saturating_add(1);
    }
    Ok(capped)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReplayBudget {
    cap: usize,
    used: usize,
}

impl ReplayBudget {
    const fn new(cap: usize) -> Self {
        Self { cap, used: 0 }
    }

    const fn exhausted(&self) -> bool {
        self.used >= self.cap
    }

    fn spend(&mut self) -> bool {
        if self.exhausted() {
            return false;
        }
        self.used = self.used.saturating_add(1);
        true
    }
}

fn replay_with_budget(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    broad_baseline: &ResidualDomains,
    arcs: &[ArcLiteral],
    context_targets: &[(char, usize)],
    budget: &mut ReplayBudget,
) -> Result<bool, SwapRecoveryError> {
    if !budget.spend() {
        return Ok(false);
    }
    broad_replay_rejects_arc_clause(spec, messages, broad_baseline, arcs, context_targets)
}

pub(super) fn broad_replay_rejects_arc_clause(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    broad_baseline: &ResidualDomains,
    arcs: &[ArcLiteral],
    context_targets: &[(char, usize)],
) -> Result<bool, SwapRecoveryError> {
    let mut probe = broad_baseline.clone();
    if !context_targets.is_empty() {
        let targets = context_targets.iter().copied().collect::<BTreeMap<_, _>>();
        match restrict_to_targets(&mut probe, &targets) {
            Ok(()) => {}
            Err(SwapRecoveryError::NoResidualCandidate) => return Ok(true),
            Err(error) => return Err(error),
        }
    }
    match restrict_to_arc_literals(&mut probe, arcs) {
        Ok(()) => {}
        Err(SwapRecoveryError::NoResidualCandidate) => return Ok(true),
        Err(error) => return Err(error),
    }
    let mut probe_stats = SwapRecoveryStats {
        enumerated_candidates: probe.candidates.len(),
        ..SwapRecoveryStats::default()
    };
    match propagate_partial_states(
        spec,
        messages,
        &mut probe,
        &mut probe_stats,
        PropagationOptions {
            max_passes: 2,
            exhaustive_arc: false,
        },
    ) {
        Ok(_) => Ok(false),
        Err(SwapRecoveryError::NoResidualCandidate) => Ok(true),
        Err(error) => Err(error),
    }
}

fn restrict_to_arc_literals(
    residual: &mut ResidualDomains,
    arcs: &[ArcLiteral],
) -> Result<(), SwapRecoveryError> {
    let grouped = arcs_by_letter(arcs);
    for (letter, letter_arcs) in grouped {
        let Some(domain) = residual.by_letter.get(&letter) else {
            continue;
        };
        let filtered = domain
            .iter()
            .copied()
            .filter(|&candidate_index| {
                residual
                    .candidates
                    .get(candidate_index)
                    .is_some_and(|candidate| {
                        letter_arcs.iter().all(|literal| {
                            candidate
                                .perm
                                .get(literal.post_position)
                                .is_some_and(|&pre| pre == literal.pre_position)
                        })
                    })
            })
            .collect::<Vec<_>>();
        if filtered.is_empty() {
            return Err(SwapRecoveryError::NoResidualCandidate);
        }
        let _old = residual.by_letter.insert(letter, filtered);
    }
    Ok(())
}

fn arcs_by_letter(arcs: &[ArcLiteral]) -> BTreeMap<char, Vec<ArcLiteral>> {
    let mut grouped = BTreeMap::<char, Vec<ArcLiteral>>::new();
    for &literal in arcs {
        grouped.entry(literal.letter).or_default().push(literal);
    }
    grouped
}

fn learn_existing_target_clause(
    target_solver: &mut TargetAssignmentSolver,
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    residual: &ResidualDomains,
    targets: &BTreeMap<char, usize>,
    stats: &mut SwapRecoveryStats,
) -> Result<(), SwapRecoveryError> {
    let conflict = extract_deterministic_target_conflict(spec, messages, residual, targets, stats)?;
    if let Some(core) = conflict {
        target_solver.learn_core_clause(&core, None, stats)?;
    } else {
        let choices = targets
            .iter()
            .map(|(&letter, &target)| (letter, target))
            .collect::<Vec<_>>();
        if !broad_residual_rejects_target_choices(spec, messages, residual, &choices)? {
            return Err(SwapRecoveryError::SatSolver(
                "phase-0 deterministic rejection failed target broad replay".to_owned(),
            ));
        }
        target_solver.learn_assignment_clause(targets, None, stats)?;
    }
    stats.target_rejections = stats.target_rejections.saturating_add(1);
    Ok(())
}

fn target_domains(
    target_solver: &TargetAssignmentSolver,
    letters: &[char],
) -> BTreeMap<char, Vec<usize>> {
    letters
        .iter()
        .copied()
        .map(|letter| (letter, target_solver.letter_target_values(letter)))
        .collect()
}

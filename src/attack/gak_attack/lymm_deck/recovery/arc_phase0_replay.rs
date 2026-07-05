//! Broad-replay minimization for the Phase-0 arc-provenance instrument.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use super::arc_phase0_types::{GakSwapArcContextBin, InternalMinimizedReason};
use super::propagation::{PropagationOptions, propagate_partial_states};
use super::residual::{ResidualDomains, restrict_to_targets};
use super::target_reason::{ArcLiteral, ArcReason};
use super::{AlignedMessage, SwapRecoveryError, SwapRecoveryStats};
use crate::attack::gak_attack::lymm_deck::LymmDeckSpec;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ArcReasonMinimizeOutcome {
    Characterized(InternalMinimizedReason),
    WallBeforeValidation,
}

pub(super) fn minimize_arc_reason(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    broad_baseline: &ResidualDomains,
    raw_reason: &ArcReason,
    replay_cap: usize,
) -> Result<InternalMinimizedReason, SwapRecoveryError> {
    let mut deadline = NoPhase0Deadline;
    match minimize_arc_reason_with_deadline(
        spec,
        messages,
        broad_baseline,
        raw_reason,
        replay_cap,
        &mut deadline,
    )? {
        ArcReasonMinimizeOutcome::Characterized(reason) => Ok(reason),
        ArcReasonMinimizeOutcome::WallBeforeValidation => Err(SwapRecoveryError::SatSolver(
            "phase-0 no-deadline minimizer stopped before validation".to_owned(),
        )),
    }
}

pub(super) fn minimize_arc_reason_with_deadline<D>(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    broad_baseline: &ResidualDomains,
    raw_reason: &ArcReason,
    replay_cap: usize,
    deadline: &mut D,
) -> Result<ArcReasonMinimizeOutcome, SwapRecoveryError>
where
    D: Phase0Deadline + ?Sized,
{
    let mut budget = ReplayBudget::new(replay_cap);
    let raw_arcs = raw_reason.arc_literals.iter().copied().collect::<Vec<_>>();
    if !raw_arcs.is_empty() {
        if let Some(true) = replay_with_budget(
            spec,
            messages,
            broad_baseline,
            &raw_arcs,
            &[],
            &mut budget,
            deadline,
        )? {
            let (arcs, capped) = minimize_arc_only(
                spec,
                messages,
                broad_baseline,
                raw_arcs,
                &mut budget,
                deadline,
            )?;
            let literal_count = arcs.len();
            return Ok(ArcReasonMinimizeOutcome::Characterized(
                InternalMinimizedReason {
                    arcs,
                    context_targets: Vec::new(),
                    bin: GakSwapArcContextBin::ContextFree,
                    literal_count,
                    literal_count_is_upper_bound: capped,
                    replay_checks: budget.used,
                    stopped_by_wall: budget.wall_expired,
                },
            ));
        }
        if budget.wall_expired {
            return Ok(ArcReasonMinimizeOutcome::WallBeforeValidation);
        }
    }

    let mut arcs = raw_reason.arc_literals.iter().copied().collect::<Vec<_>>();
    let mut context_targets = raw_reason
        .context_targets
        .iter()
        .copied()
        .collect::<Vec<_>>();
    match replay_with_budget(
        spec,
        messages,
        broad_baseline,
        &arcs,
        &context_targets,
        &mut budget,
        deadline,
    )? {
        Some(true) => {
            let capped = minimize_mixed_reason(
                spec,
                messages,
                broad_baseline,
                &mut arcs,
                &mut context_targets,
                &mut budget,
                deadline,
            )?;
            let literal_count = arcs.len().saturating_add(context_targets.len());
            return Ok(ArcReasonMinimizeOutcome::Characterized(
                InternalMinimizedReason {
                    arcs,
                    context_targets,
                    bin: GakSwapArcContextBin::ContextExpressible,
                    literal_count,
                    literal_count_is_upper_bound: capped,
                    replay_checks: budget.used,
                    stopped_by_wall: budget.wall_expired,
                },
            ));
        }
        None if budget.wall_expired => {
            return Ok(ArcReasonMinimizeOutcome::WallBeforeValidation);
        }
        Some(false) | None => {}
    }

    let literal_count = raw_reason
        .arc_literals
        .len()
        .saturating_add(raw_reason.context_targets.len());
    Ok(ArcReasonMinimizeOutcome::Characterized(
        InternalMinimizedReason {
            arcs: raw_reason.arc_literals.iter().copied().collect(),
            context_targets: raw_reason.context_targets.iter().copied().collect(),
            bin: GakSwapArcContextBin::ContextOpaque,
            literal_count,
            literal_count_is_upper_bound: budget.exhausted() || budget.wall_expired,
            replay_checks: budget.used,
            stopped_by_wall: budget.wall_expired,
        },
    ))
}

fn minimize_arc_only<D>(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    broad_baseline: &ResidualDomains,
    mut arcs: Vec<ArcLiteral>,
    budget: &mut ReplayBudget,
    deadline: &mut D,
) -> Result<(Vec<ArcLiteral>, bool), SwapRecoveryError>
where
    D: Phase0Deadline + ?Sized,
{
    let mut capped = false;
    let mut index = 0usize;
    while index < arcs.len() {
        if budget.exhausted() || budget.wall_expired {
            capped = true;
            break;
        }
        let removed = arcs.remove(index);
        match replay_with_budget(spec, messages, broad_baseline, &arcs, &[], budget, deadline)? {
            Some(true) => continue,
            Some(false) => {}
            None => {
                arcs.insert(index, removed);
                capped = true;
                break;
            }
        }
        arcs.insert(index, removed);
        index = index.saturating_add(1);
    }
    Ok((arcs, capped))
}

fn minimize_mixed_reason<D>(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    broad_baseline: &ResidualDomains,
    arcs: &mut Vec<ArcLiteral>,
    context_targets: &mut Vec<(char, usize)>,
    budget: &mut ReplayBudget,
    deadline: &mut D,
) -> Result<bool, SwapRecoveryError>
where
    D: Phase0Deadline + ?Sized,
{
    let mut capped = false;
    let mut context_index = 0usize;
    while context_index < context_targets.len() {
        if budget.exhausted() || budget.wall_expired {
            capped = true;
            break;
        }
        let removed = context_targets.remove(context_index);
        match replay_with_budget(
            spec,
            messages,
            broad_baseline,
            arcs,
            context_targets,
            budget,
            deadline,
        )? {
            Some(true) => continue,
            Some(false) => {}
            None => {
                context_targets.insert(context_index, removed);
                capped = true;
                break;
            }
        }
        context_targets.insert(context_index, removed);
        context_index = context_index.saturating_add(1);
    }
    let mut arc_index = 0usize;
    while arc_index < arcs.len() {
        if budget.exhausted() || budget.wall_expired {
            capped = true;
            break;
        }
        let removed = arcs.remove(arc_index);
        match replay_with_budget(
            spec,
            messages,
            broad_baseline,
            arcs,
            context_targets,
            budget,
            deadline,
        )? {
            Some(true) => continue,
            Some(false) => {}
            None => {
                arcs.insert(arc_index, removed);
                capped = true;
                break;
            }
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
    wall_expired: bool,
}

impl ReplayBudget {
    const fn new(cap: usize) -> Self {
        Self {
            cap,
            used: 0,
            wall_expired: false,
        }
    }

    const fn exhausted(&self) -> bool {
        self.used >= self.cap
    }

    fn spend(&mut self) {
        self.used = self.used.saturating_add(1);
    }
}

pub(super) trait Phase0Deadline {
    fn start(&mut self);

    fn expired(&mut self) -> bool;
}

#[derive(Clone, Debug)]
pub(super) struct InstantPhase0Deadline {
    started: Option<Instant>,
    wall_time: Duration,
}

impl InstantPhase0Deadline {
    pub(super) fn new(wall_time: Duration) -> Self {
        Self {
            started: None,
            wall_time,
        }
    }
}

impl Phase0Deadline for InstantPhase0Deadline {
    fn start(&mut self) {
        self.started = Some(Instant::now());
    }

    fn expired(&mut self) -> bool {
        self.started
            .is_some_and(|started| started.elapsed() >= self.wall_time)
    }
}

#[derive(Clone, Copy, Debug)]
struct NoPhase0Deadline;

impl Phase0Deadline for NoPhase0Deadline {
    fn start(&mut self) {}

    fn expired(&mut self) -> bool {
        false
    }
}

fn replay_with_budget<D>(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    broad_baseline: &ResidualDomains,
    arcs: &[ArcLiteral],
    context_targets: &[(char, usize)],
    budget: &mut ReplayBudget,
    deadline: &mut D,
) -> Result<Option<bool>, SwapRecoveryError>
where
    D: Phase0Deadline + ?Sized,
{
    if budget.exhausted() {
        return Ok(None);
    }
    if deadline.expired() {
        budget.wall_expired = true;
        return Ok(None);
    }
    budget.spend();
    broad_replay_rejects_arc_clause(spec, messages, broad_baseline, arcs, context_targets).map(Some)
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
        enumerated_candidates: probe.candidate_count(),
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
                letter_arcs.iter().all(|literal| {
                    residual.transition_possible(
                        candidate_index,
                        literal.post_position,
                        literal.pre_position,
                    )
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

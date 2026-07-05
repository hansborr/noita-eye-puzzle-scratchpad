//! Phase-0 arc-provenance measurement for ns=3 target rejections.

use std::collections::BTreeMap;

use super::arc_phase0_replay::{
    ArcReasonMinimizeOutcome, InstantPhase0Deadline, Phase0Deadline,
    minimize_arc_reason_with_deadline,
};
use super::arc_phase0_tuple::{TupleKillEstimateRequest, estimate_tuple_kill_with_deadline};
use super::arc_phase0_types::{
    GakSwapArcPhase0Config, GakSwapArcPhase0Report, GakSwapArcPhase0Stop, GakSwapArcRejection,
    GakSwapArcTupleKillEstimate, InternalMinimizedReason,
};
use super::domain_build::build_residual_domains;
use super::propagation::{
    PropagationOptions, propagate_partial_states, propagate_partial_states_with_target_reasons,
};
use super::residual::{ResidualDomains, restrict_to_targets};
use super::target_conflict::{
    broad_residual_rejects_target_choices, extract_deterministic_target_conflict,
};
use super::target_reason::ArcReason;
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
    measure_ns3_arc_provenance_with_sink(spec, pairs, config, |_| Ok(()))
}

/// Measures ns=3 deterministic target rejections and calls `sink` after each
/// completed rejection row is assembled.
///
/// The aggregate report returned on success is identical to
/// [`measure_ns3_arc_provenance`]; the sink is an observability hook for
/// incremental reporting.
///
/// # Errors
/// Returns [`SwapRecoveryError`] when the input cannot be aligned, domains cannot
/// be built, a broad replay invariant fails while advancing the target sampler,
/// or `sink` returns an error.
pub fn measure_ns3_arc_provenance_with_sink(
    spec: &LymmDeckSpec,
    pairs: &[KnownPlaintextPair],
    config: GakSwapArcPhase0Config,
    sink: impl FnMut(&GakSwapArcRejection) -> Result<(), SwapRecoveryError>,
) -> Result<GakSwapArcPhase0Report, SwapRecoveryError> {
    let mut deadline = InstantPhase0Deadline::new(config.wall_time);
    measure_ns3_arc_provenance_with_deadline(spec, pairs, config, sink, &mut deadline)
}

fn measure_ns3_arc_provenance_with_deadline<D>(
    spec: &LymmDeckSpec,
    pairs: &[KnownPlaintextPair],
    config: GakSwapArcPhase0Config,
    mut sink: impl FnMut(&GakSwapArcRejection) -> Result<(), SwapRecoveryError>,
    deadline: &mut D,
) -> Result<GakSwapArcPhase0Report, SwapRecoveryError>
where
    D: Phase0Deadline + ?Sized,
{
    let messages = align_pairs(spec, pairs)?;
    let recovery_config = SwapRecoveryConfig::with_max_swaps(3);
    let mut residual = build_residual_domains(spec, &messages, &recovery_config)?;
    let mut broad_stats = SwapRecoveryStats {
        enumerated_candidates: residual.candidate_count(),
        ..SwapRecoveryStats::default()
    };
    let propagation = propagate_partial_states(
        spec,
        &messages,
        &mut residual,
        &mut broad_stats,
        PropagationOptions::ns3_broad(),
    )?;
    let enumerated_candidates = residual.candidate_count();
    let mut target_solver =
        TargetAssignmentSolver::new(spec, &messages, &propagation.state_domains, &residual);
    let target_domains = target_domains(&target_solver, &residual.letters);
    deadline.start();
    let mut target_nodes = 0usize;
    let mut rejections = Vec::new();
    let mut learning_stats = SwapRecoveryStats::default();

    let stop = loop {
        if rejections.len() >= config.max_rejections {
            break GakSwapArcPhase0Stop::RejectionCap;
        }
        if deadline.expired() {
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
        let minimized = match minimize_arc_reason_with_deadline(
            spec,
            &messages,
            &residual,
            &raw_reason,
            config.replays_per_rejection,
            deadline,
        )? {
            ArcReasonMinimizeOutcome::Characterized(minimized) => minimized,
            ArcReasonMinimizeOutcome::WallBeforeValidation => {
                break GakSwapArcPhase0Stop::TimeBudget;
            }
        };
        let tuple_request = TupleKillEstimateRequest {
            spec,
            messages: &messages,
            residual: &residual,
            target_domains: &target_domains,
            targets: &targets,
            reason: &minimized,
            spot_check_samples: config.spot_check_samples,
        };
        let (tuple_kill_estimate, tuple_kill_stopped_by_wall) =
            estimate_tuple_kill_until_wall(&tuple_request, deadline);
        let rejection = arc_rejection(
            target_nodes,
            &targets,
            &raw_reason,
            &minimized,
            tuple_kill_estimate,
        );
        sink(&rejection)?;
        let stopped_by_wall =
            minimized.stopped_by_wall || tuple_kill_stopped_by_wall || deadline.expired();
        rejections.push(rejection);
        if stopped_by_wall {
            break GakSwapArcPhase0Stop::TimeBudget;
        }
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

fn estimate_tuple_kill_until_wall<D>(
    request: &TupleKillEstimateRequest<'_>,
    deadline: &mut D,
) -> (Option<GakSwapArcTupleKillEstimate>, bool)
where
    D: Phase0Deadline + ?Sized,
{
    if !request.reason.bin.counts_for_go_rule()
        || request.reason.stopped_by_wall
        || deadline.expired()
    {
        return (None, false);
    }
    let estimate = estimate_tuple_kill_with_deadline(request, deadline);
    let stopped_by_wall = estimate.is_none();
    (estimate, stopped_by_wall)
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
        enumerated_candidates: probe.candidate_count(),
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

fn arc_rejection(
    node: usize,
    targets: &BTreeMap<char, usize>,
    raw_reason: &ArcReason,
    minimized: &InternalMinimizedReason,
    tuple_kill_estimate: Option<GakSwapArcTupleKillEstimate>,
) -> GakSwapArcRejection {
    GakSwapArcRejection {
        node,
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
    }
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::arc_phase0_controls::positive_control_fixture;
    use super::super::arc_phase0_types::{GakSwapArcPhase0Config, GakSwapArcPhase0Stop};
    use super::{
        Phase0Deadline, measure_ns3_arc_provenance_with_deadline,
        measure_ns3_arc_provenance_with_sink,
    };

    #[test]
    fn pre_validation_deadline_does_not_emit_measured_rejection() {
        let (spec, pairs) = positive_control_fixture().expect("positive fixture");
        let config = GakSwapArcPhase0Config {
            max_rejections: 1,
            wall_time: Duration::from_hours(1),
            replays_per_rejection: 32,
            ..GakSwapArcPhase0Config::default()
        };
        let mut deadline = ScriptedDeadline::new(2);
        let mut streamed = Vec::new();
        let report = measure_ns3_arc_provenance_with_deadline(
            &spec,
            &pairs,
            config,
            |rejection| {
                streamed.push(rejection.clone());
                Ok(())
            },
            &mut deadline,
        )
        .expect("wall-truncated measurement must report partial rejection");

        assert_eq!(report.stop, GakSwapArcPhase0Stop::TimeBudget);
        assert_eq!(report.target_nodes, 1);
        assert!(report.rejections.is_empty(), "{report:?}");
        assert!(streamed.is_empty(), "{streamed:?}");
    }

    #[test]
    fn wall_deadline_truncates_validated_rejection_as_upper_bound() {
        let (spec, pairs) = positive_control_fixture().expect("positive fixture");
        let config = GakSwapArcPhase0Config {
            max_rejections: 1,
            wall_time: Duration::from_hours(1),
            replays_per_rejection: 32,
            spot_check_samples: 0,
        };
        let mut deadline = ScriptedDeadline::new(4);
        let mut streamed = Vec::new();
        let report = measure_ns3_arc_provenance_with_deadline(
            &spec,
            &pairs,
            config,
            |rejection| {
                streamed.push(rejection.clone());
                Ok(())
            },
            &mut deadline,
        )
        .expect("wall-truncated measurement must report partial rejection");

        assert_eq!(report.stop, GakSwapArcPhase0Stop::TimeBudget);
        assert_eq!(report.rejections.len(), 1);
        assert_eq!(streamed, report.rejections);
        let rejection = report
            .rejections
            .first()
            .expect("wall-truncated run must keep the partial rejection");
        assert!(rejection.literal_count_is_upper_bound, "{rejection:?}");
        assert!(rejection.replay_checks > 0, "{rejection:?}");
        assert!(rejection.replay_checks < config.replays_per_rejection);
        assert!(
            rejection.tuple_kill_estimate.is_none(),
            "wall-truncated rejection must not spend on tuple-kill: {rejection:?}"
        );
    }

    #[test]
    fn rejection_sink_is_called_before_aggregate_report_returns() {
        let (spec, pairs) = positive_control_fixture().expect("positive fixture");
        let config = GakSwapArcPhase0Config {
            max_rejections: 1,
            replays_per_rejection: 32,
            ..GakSwapArcPhase0Config::default()
        };
        let mut streamed_nodes = Vec::new();
        let report = measure_ns3_arc_provenance_with_sink(&spec, &pairs, config, |rejection| {
            assert!(
                streamed_nodes.is_empty(),
                "single-rejection fixture streamed more than once before return"
            );
            streamed_nodes.push(rejection.node);
            Ok(())
        })
        .expect("positive measurement must run");

        assert_eq!(report.stop, GakSwapArcPhase0Stop::RejectionCap);
        assert_eq!(
            streamed_nodes,
            report
                .rejections
                .iter()
                .map(|rejection| rejection.node)
                .collect::<Vec<_>>()
        );
    }

    #[derive(Clone, Debug)]
    struct ScriptedDeadline {
        checks: usize,
        expire_on: usize,
    }

    impl ScriptedDeadline {
        const fn new(expire_on: usize) -> Self {
            Self {
                checks: 0,
                expire_on,
            }
        }
    }

    impl Phase0Deadline for ScriptedDeadline {
        fn start(&mut self) {}

        fn expired(&mut self) -> bool {
            self.checks = self.checks.saturating_add(1);
            self.checks >= self.expire_on
        }
    }
}

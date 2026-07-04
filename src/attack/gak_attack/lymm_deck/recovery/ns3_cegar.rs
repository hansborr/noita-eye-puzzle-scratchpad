//! Two-tier ns=3 target CEGAR driver.

use std::collections::BTreeMap;

use super::domain_build::build_residual_domains;
use super::instrumentation::{trace_residual, trace_stats};
use super::learning::{TruthTracker, add_outer_stats};
use super::propagation::{PropagationOptions, propagate_partial_states};
use super::residual::{ResidualDomains, recover_with_residual_domains, restrict_to_targets};
use super::target_conflict::{
    broad_residual_rejects_target_choices, measure_truth_target_residual,
    minimize_deterministic_target_conflict,
};
use super::target_solver::TargetAssignmentSolver;
use super::{
    AlignedMessage, RecoveryReport, SwapRecoveryConfig, SwapRecoveryError, SwapRecoveryStats,
};
use crate::attack::gak_attack::lymm_deck::LymmDeckSpec;

pub(super) fn recover_ns3_with_target_cegar(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    config: &SwapRecoveryConfig,
) -> Result<RecoveryReport, SwapRecoveryError> {
    let truth = config.planted_truth().cloned().map(TruthTracker::new);
    let mut residual = build_residual_domains(spec, messages, config)?;
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
    if let Some(truth) = truth.as_ref() {
        measure_truth_target_residual(spec, messages, &residual, truth, &mut stats)?;
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
            trace_stats("target cap", &stats);
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
        trace_targeted_entries(&targeted);
        match recover_with_residual_domains(
            spec,
            messages,
            (*config).clone(),
            targeted,
            ns3_targeted_propagation_options(),
            Some(&targets),
            truth.as_ref(),
        ) {
            Ok(mut report) => {
                trace_stats("target success outer", &stats);
                add_outer_stats(&mut report.stats, &stats);
                report.stats.nodes = report.stats.nodes.saturating_add(target_nodes);
                return Ok(report);
            }
            Err(SwapRecoveryError::TargetUnsatCore { choices }) => {
                if std::env::var_os("NOITA_SWAP_CEGAR_TRACE").is_some() {
                    eprintln!("cegar: learned target core size={}", choices.len());
                }
                learn_sat_unsat_core_target_clause(
                    &mut target_solver,
                    SatTargetCoreClause {
                        spec,
                        messages,
                        residual: &residual,
                        targets: &targets,
                        choices: &choices,
                        truth: truth.as_ref(),
                    },
                    &mut stats,
                )?;
                stats.target_rejections = stats.target_rejections.saturating_add(1);
            }
            Err(SwapRecoveryError::NoResidualCandidate) => {
                learn_no_residual_target_clause(
                    &mut target_solver,
                    spec,
                    messages,
                    &residual,
                    &targets,
                    truth.as_ref(),
                    &mut stats,
                )?;
                stats.target_rejections = stats.target_rejections.saturating_add(1);
            }
            Err(error) => {
                trace_stats("target abort", &stats);
                return Err(error);
            }
        }
    }
}

const fn ns3_targeted_propagation_options() -> PropagationOptions {
    PropagationOptions {
        max_passes: 2,
        exhaustive_arc: false,
    }
}

#[derive(Clone, Copy)]
pub(super) struct SatTargetCoreClause<'a> {
    pub(super) spec: &'a LymmDeckSpec,
    pub(super) messages: &'a [AlignedMessage],
    pub(super) residual: &'a ResidualDomains,
    pub(super) targets: &'a BTreeMap<char, usize>,
    pub(super) choices: &'a [(char, usize)],
    pub(super) truth: Option<&'a TruthTracker>,
}

pub(super) fn learn_sat_unsat_core_target_clause(
    target_solver: &mut TargetAssignmentSolver,
    core: SatTargetCoreClause<'_>,
    stats: &mut SwapRecoveryStats,
) -> Result<(), SwapRecoveryError> {
    if !core.choices.is_empty()
        && broad_residual_rejects_target_choices(
            core.spec,
            core.messages,
            core.residual,
            core.choices,
        )?
    {
        return target_solver.learn_core_clause(core.choices, core.truth, stats);
    }

    let assignment_choices = core
        .targets
        .iter()
        .map(|(&letter, &target)| (letter, target))
        .collect::<Vec<_>>();
    if !broad_residual_rejects_target_choices(
        core.spec,
        core.messages,
        core.residual,
        &assignment_choices,
    )? {
        return Err(SwapRecoveryError::SatSolver(
            "target UNSAT core failed broad-baseline replay".to_owned(),
        ));
    }
    if std::env::var_os("NOITA_SWAP_CEGAR_TRACE").is_some() && !core.choices.is_empty() {
        eprintln!(
            "cegar: target core failed broad replay; learned full assignment size={}",
            assignment_choices.len()
        );
    }
    target_solver.learn_core_clause(&assignment_choices, core.truth, stats)
}

fn trace_targeted_entries(residual: &ResidualDomains) {
    if std::env::var_os("NOITA_SWAP_CEGAR_TRACE").is_none() {
        return;
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
    eprintln!("cegar: targeted entries={total} max_domain={max}");
}

fn learn_no_residual_target_clause(
    target_solver: &mut TargetAssignmentSolver,
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    residual: &ResidualDomains,
    targets: &BTreeMap<char, usize>,
    truth: Option<&TruthTracker>,
    stats: &mut SwapRecoveryStats,
) -> Result<(), SwapRecoveryError> {
    let conflict =
        minimize_deterministic_target_conflict(spec, messages, residual, targets, stats)?;
    if let Some(core) = conflict {
        if std::env::var_os("NOITA_SWAP_CEGAR_TRACE").is_some() {
            eprintln!(
                "cegar: learned deterministic target core size={}",
                core.len()
            );
        }
        target_solver.learn_core_clause(&core, truth, stats)?;
    } else {
        target_solver.learn_assignment_clause(targets, truth, stats)?;
    }
    Ok(())
}

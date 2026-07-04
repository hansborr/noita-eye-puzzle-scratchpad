//! Replay-minimized target conflicts for ns=3 target-level CEGAR.

use std::collections::BTreeMap;

use super::learning::TruthTracker;
use super::propagation::{
    PropagationOptions, propagate_partial_states, propagate_partial_states_with_target_reasons,
};
use super::residual::{ResidualDomains, residual_formula_is_unsat, restrict_to_targets};
use super::target_reason::TargetReasonTracker;
use super::{AlignedMessage, SwapRecoveryError, SwapRecoveryStats};
use crate::attack::gak_attack::lymm_deck::LymmDeckSpec;

pub(super) fn measure_truth_target_residual(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    broad_baseline: &ResidualDomains,
    truth: &TruthTracker,
    stats: &mut SwapRecoveryStats,
) -> Result<(), SwapRecoveryError> {
    let targets = truth.targets_for_letters(&broad_baseline.letters);
    let mut residual = broad_baseline.clone();
    restrict_to_targets(&mut residual, &targets)?;
    let mut measure_stats = SwapRecoveryStats {
        enumerated_candidates: residual.candidates.len(),
        ..SwapRecoveryStats::default()
    };
    let _propagation = propagate_partial_states(
        spec,
        messages,
        &mut residual,
        &mut measure_stats,
        PropagationOptions {
            max_passes: 2,
            exhaustive_arc: false,
        },
    )?;
    let entries = residual
        .letters
        .iter()
        .map(|&letter| {
            (
                letter,
                residual
                    .by_letter
                    .get(&letter)
                    .map_or(0, std::vec::Vec::len),
            )
        })
        .collect::<Vec<_>>();
    stats.measured_target_total_entries = entries.iter().map(|&(_letter, count)| count).sum();
    stats.measured_target_max_domain = entries
        .iter()
        .map(|&(_letter, count)| count)
        .max()
        .unwrap_or(0);
    stats.measured_target_domain_entries = entries;
    Ok(())
}

pub(super) fn extract_deterministic_target_conflict(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    broad_baseline: &ResidualDomains,
    targets: &BTreeMap<char, usize>,
    stats: &mut SwapRecoveryStats,
) -> Result<Option<Vec<(char, usize)>>, SwapRecoveryError> {
    let assignment_choices = targets
        .iter()
        .map(|(&letter, &target)| (letter, target))
        .collect::<Vec<_>>();
    let mut probe = broad_baseline.clone();
    match restrict_to_targets(&mut probe, targets) {
        Ok(()) => {}
        Err(SwapRecoveryError::NoResidualCandidate) => {
            if deterministic_rejects(spec, messages, broad_baseline, &assignment_choices, stats)? {
                stats.target_replay_literals = stats
                    .target_replay_literals
                    .saturating_add(assignment_choices.len());
                return Ok(Some(assignment_choices));
            }
            return Ok(None);
        }
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
        Err(SwapRecoveryError::NoResidualCandidate) => {
            let Some(tracker) = tracker else {
                return Err(SwapRecoveryError::SatSolver(
                    "deterministic target rejection produced no tracked reason".to_owned(),
                ));
            };
            let Some(full_core) = tracker.conflict_choices() else {
                return Err(SwapRecoveryError::SatSolver(
                    "deterministic target rejection produced no tracked reason".to_owned(),
                ));
            };
            let candidates = deterministic_reason_candidates(&tracker, full_core)?;
            for core in candidates {
                if std::env::var_os("NOITA_SWAP_CEGAR_TRACE").is_some() {
                    eprintln!("cegar: tracked deterministic reason candidate {core:?}");
                }
                if deterministic_rejects(spec, messages, broad_baseline, &core, stats)? {
                    if std::env::var_os("NOITA_SWAP_CEGAR_TRACE").is_some() {
                        eprintln!("cegar: tracked deterministic reason {core:?}");
                    }
                    stats.target_replay_literals =
                        stats.target_replay_literals.saturating_add(core.len());
                    return Ok(Some(core));
                }
            }
            Err(SwapRecoveryError::SatSolver(
                "tracked deterministic target reason failed broad-baseline replay".to_owned(),
            ))
        }
        Err(error) => Err(error),
    }
}

fn deterministic_reason_candidates(
    tracker: &TargetReasonTracker,
    full_core: Vec<(char, usize)>,
) -> Result<Vec<Vec<(char, usize)>>, SwapRecoveryError> {
    let mut candidates = Vec::new();
    if let Some(focused) = tracker.focused_conflict_choices() {
        for &choice in focused.iter().rev() {
            push_unique_core(&mut candidates, vec![choice]);
        }
        push_unique_core(&mut candidates, focused);
    }
    for &choice in full_core.iter().rev() {
        push_unique_core(&mut candidates, vec![choice]);
    }
    push_unique_core(&mut candidates, full_core);
    candidates.retain(|core| !core.is_empty());
    if candidates.is_empty() {
        return Err(SwapRecoveryError::SatSolver(
            "deterministic target rejection produced an empty tracked reason".to_owned(),
        ));
    }
    Ok(candidates)
}

fn push_unique_core(candidates: &mut Vec<Vec<(char, usize)>>, core: Vec<(char, usize)>) {
    if !candidates.iter().any(|candidate| candidate == &core) {
        candidates.push(core);
    }
}

pub(super) fn broad_residual_rejects_target_choices(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    broad_baseline: &ResidualDomains,
    choices: &[(char, usize)],
) -> Result<bool, SwapRecoveryError> {
    let targets = choices.iter().copied().collect::<BTreeMap<_, _>>();
    let mut probe = broad_baseline.clone();
    match restrict_to_targets(&mut probe, &targets) {
        Ok(()) => {}
        Err(SwapRecoveryError::NoResidualCandidate) => return Ok(true),
        Err(error) => return Err(error),
    }
    let mut probe_stats = SwapRecoveryStats {
        enumerated_candidates: probe.candidates.len(),
        ..SwapRecoveryStats::default()
    };
    let propagation = match propagate_partial_states(
        spec,
        messages,
        &mut probe,
        &mut probe_stats,
        PropagationOptions {
            max_passes: 2,
            exhaustive_arc: false,
        },
    ) {
        Ok(propagation) => propagation,
        Err(SwapRecoveryError::NoResidualCandidate) => return Ok(true),
        Err(error) => return Err(error),
    };
    residual_formula_is_unsat(spec, messages, &probe, &propagation.state_domains, None)
}

fn deterministic_rejects(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    broad_baseline: &ResidualDomains,
    choices: &[(char, usize)],
    stats: &mut SwapRecoveryStats,
) -> Result<bool, SwapRecoveryError> {
    stats.target_replay_checks = stats.target_replay_checks.saturating_add(1);
    let targets = choices.iter().copied().collect::<BTreeMap<_, _>>();
    let mut probe = broad_baseline.clone();
    match restrict_to_targets(&mut probe, &targets) {
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

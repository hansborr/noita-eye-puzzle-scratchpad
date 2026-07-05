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

const FULL_CORE_FIRST_LITERAL_FLOOR: usize = 4;

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
        enumerated_candidates: residual.candidate_count(),
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
        Err(SwapRecoveryError::NoResidualCandidate) => {
            // Ok(None) tells the caller to use its broad-checked full-assignment
            // fallback when no compact extracted reason survives broad replay.
            let Some(tracker) = tracker else {
                trace_reason_fallback("produced no tracker");
                return Ok(None);
            };
            let Some(full_core) = tracker.conflict_choices() else {
                trace_reason_fallback("produced no tracked reason");
                return Ok(None);
            };
            let full_core_first = prefer_full_core_first(stats);
            let candidates = deterministic_reason_candidates(&tracker, full_core, full_core_first);
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
            trace_reason_fallback("had no compact candidate pass broad replay");
            if full_core_first {
                stats.target_floor_full_assignment_fallbacks = stats
                    .target_floor_full_assignment_fallbacks
                    .saturating_add(1);
            }
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn deterministic_reason_candidates(
    tracker: &TargetReasonTracker,
    full_core: Vec<(char, usize)>,
    full_core_first: bool,
) -> Vec<Vec<(char, usize)>> {
    deterministic_reason_candidates_from_parts(
        tracker.focused_conflict_choices(),
        full_core,
        full_core_first,
    )
}

fn deterministic_reason_candidates_from_parts(
    focused: Option<Vec<(char, usize)>>,
    full_core: Vec<(char, usize)>,
    full_core_first: bool,
) -> Vec<Vec<(char, usize)>> {
    let mut candidates = Vec::new();
    if full_core_first && full_core.len() > 1 {
        push_unique_core(&mut candidates, full_core.clone());
    }
    if let Some(focused) = focused {
        if !full_core_first {
            for &choice in focused.iter().rev() {
                push_unique_core(&mut candidates, vec![choice]);
            }
        }
        if focused.len() > 1 {
            push_unique_core(&mut candidates, focused);
        }
    }
    if !full_core_first {
        for &choice in full_core.iter().rev() {
            push_unique_core(&mut candidates, vec![choice]);
        }
    }
    if full_core.len() > 1 {
        push_unique_core(&mut candidates, full_core);
    }
    candidates.retain(|core| !core.is_empty());
    candidates
}

fn prefer_full_core_first(stats: &SwapRecoveryStats) -> bool {
    stats.target_clauses_learned > 0
        && stats.target_replay_literals
            >= stats
                .target_clauses_learned
                .saturating_mul(FULL_CORE_FIRST_LITERAL_FLOOR)
}

fn push_unique_core(candidates: &mut Vec<Vec<(char, usize)>>, core: Vec<(char, usize)>) {
    if !candidates.iter().any(|candidate| candidate == &core) {
        candidates.push(core);
    }
}

fn trace_reason_fallback(reason: &str) {
    if std::env::var_os("NOITA_SWAP_CEGAR_TRACE").is_some() {
        eprintln!("cegar: deterministic target reason fallback to full assignment: {reason}");
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
        enumerated_candidates: probe.candidate_count(),
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

#[cfg(test)]
mod tests {
    use super::{
        SwapRecoveryStats, deterministic_reason_candidates_from_parts, prefer_full_core_first,
    };

    #[test]
    fn reason_candidates_stay_quality_first_before_multiliteral_floor() {
        let focused = vec![('A', 1), ('B', 2)];
        let full = vec![('A', 1), ('B', 2), ('C', 3)];
        let candidates = deterministic_reason_candidates_from_parts(Some(focused), full, false);

        assert_eq!(
            candidates,
            vec![
                vec![('B', 2)],
                vec![('A', 1)],
                vec![('A', 1), ('B', 2)],
                vec![('C', 3)],
                vec![('A', 1), ('B', 2), ('C', 3)]
            ]
        );
    }

    #[test]
    fn reason_candidates_skip_singletons_after_multiliteral_floor() {
        let focused = vec![('A', 1), ('B', 2)];
        let full = vec![('A', 1), ('B', 2), ('C', 3)];
        let candidates = deterministic_reason_candidates_from_parts(Some(focused), full, true);

        assert_eq!(
            candidates.first(),
            Some(&vec![('A', 1), ('B', 2), ('C', 3)])
        );
        assert_eq!(
            candidates,
            vec![vec![('A', 1), ('B', 2), ('C', 3)], vec![('A', 1), ('B', 2)]]
        );
    }

    #[test]
    fn floor_mode_drops_singleton_full_core() {
        let focused = vec![('A', 1), ('B', 2)];
        let full = vec![('C', 3)];
        let candidates = deterministic_reason_candidates_from_parts(Some(focused), full, true);

        assert_eq!(candidates, vec![vec![('A', 1), ('B', 2)]]);
    }

    #[test]
    fn full_core_first_heuristic_ignores_singleton_control_history() {
        let control_like = SwapRecoveryStats {
            target_clauses_learned: 4,
            target_replay_checks: 5,
            target_replay_literals: 4,
            ..SwapRecoveryStats::default()
        };
        let real_file_like = SwapRecoveryStats {
            target_clauses_learned: 1,
            target_replay_checks: 7,
            target_replay_literals: 5,
            ..SwapRecoveryStats::default()
        };
        let real_file_after_cheap_replays = SwapRecoveryStats {
            target_clauses_learned: 4,
            target_replay_checks: 10,
            target_replay_literals: 20,
            ..SwapRecoveryStats::default()
        };

        assert!(!prefer_full_core_first(&control_like));
        assert!(prefer_full_core_first(&real_file_like));
        assert!(prefer_full_core_first(&real_file_after_cheap_replays));
    }
}

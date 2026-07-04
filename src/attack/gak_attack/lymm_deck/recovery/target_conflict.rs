//! Replay-minimized target conflicts for ns=3 target-level CEGAR.

use std::collections::BTreeMap;

use super::propagation::{PropagationOptions, propagate_partial_states};
use super::residual::{ResidualDomains, restrict_to_targets};
use super::{AlignedMessage, SwapRecoveryError, SwapRecoveryStats};
use crate::attack::gak_attack::lymm_deck::LymmDeckSpec;

pub(super) fn minimize_deterministic_target_conflict(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    broad_baseline: &ResidualDomains,
    targets: &BTreeMap<char, usize>,
    stats: &mut SwapRecoveryStats,
) -> Result<Option<Vec<(char, usize)>>, SwapRecoveryError> {
    let mut core = targets
        .iter()
        .map(|(&letter, &target)| (letter, target))
        .collect::<Vec<_>>();
    if !deterministic_rejects(spec, messages, broad_baseline, &core, stats)? {
        return Ok(None);
    }

    let mut index = 0usize;
    while index < core.len() {
        let mut trial = core.clone();
        let _removed = trial.remove(index);
        if !trial.is_empty()
            && deterministic_rejects(spec, messages, broad_baseline, &trial, stats)?
        {
            core = trial;
        } else {
            index += 1;
        }
    }
    stats.target_replay_literals = stats.target_replay_literals.saturating_add(core.len());
    Ok(Some(core))
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
        PropagationOptions::ns2_default(),
    ) {
        Ok(_) => Ok(false),
        Err(SwapRecoveryError::NoResidualCandidate) => Ok(true),
        Err(error) => Err(error),
    }
}

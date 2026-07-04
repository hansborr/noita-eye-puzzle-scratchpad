//! Residual-domain construction for Lymm generator recovery.

use std::collections::{BTreeMap, BTreeSet};

use super::residual::{CandidateRuntime, ResidualDomains};
use super::state::{ForcedObservation, forced_observation};
use super::{
    AlignedMessage, RecoveryGeneratorSet, SwapRecoveryConfig, SwapRecoveryError, occurrence_counts,
};
use crate::attack::gak_attack::lymm_deck::{
    LymmDeckSpec, TopSwapConstraints, enumerate_generator_domains, enumerate_top_swap_domains,
};

pub(super) fn build_residual_domains(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    config: &SwapRecoveryConfig,
) -> Result<ResidualDomains, SwapRecoveryError> {
    let mut observed = occurrence_counts(spec, messages)
        .into_iter()
        .filter_map(|(letter, count)| (count > 0).then_some(letter))
        .collect::<Vec<_>>();
    observed.sort_unstable();

    let restart_observations = restart_forced_observations(spec, messages)?;
    let constraints =
        explicit_generator_constraints(config, spec, &observed, &restart_observations);
    let domains = match &config.generator_set {
        RecoveryGeneratorSet::TopSwaps => {
            enumerate_top_swap_domains(spec, &TopSwapConstraints::up_to(config.max_swaps))?
        }
        RecoveryGeneratorSet::Explicit(generator_set) => {
            enumerate_generator_domains(spec, generator_set, &constraints)?
        }
    };
    let candidates = domains
        .candidates
        .iter()
        .map(|candidate| CandidateRuntime {
            perm: candidate.permutation(spec),
        })
        .collect::<Vec<_>>();
    validate_distinct_nonzero_target_assumption(
        &candidates,
        spec,
        &observed,
        &restart_observations,
    )?;

    let mut by_letter = BTreeMap::new();
    for &letter in &observed {
        let domain: Vec<usize> = match restart_observations.get(&letter).copied() {
            Some(observation) => candidates
                .iter()
                .enumerate()
                .filter_map(|(index, candidate)| {
                    candidate
                        .perm
                        .get(observation.entry)
                        .is_some_and(|&image| image == observation.target)
                        .then_some(index)
                })
                .collect(),
            None => (0..domains.candidates.len()).collect(),
        };
        if domain.is_empty() {
            return Err(SwapRecoveryError::NoCandidateForTarget {
                letter,
                target: restart_observations
                    .get(&letter)
                    .map_or(usize::MAX, |observation| observation.target),
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

fn explicit_generator_constraints(
    config: &SwapRecoveryConfig,
    spec: &LymmDeckSpec,
    observed: &[char],
    restart_observations: &BTreeMap<char, ForcedObservation>,
) -> TopSwapConstraints {
    let constraints = TopSwapConstraints::up_to(config.max_swaps);
    if config.generator_set.is_top_swaps()
        || !observed
            .iter()
            .all(|letter| restart_observations.contains_key(letter))
        || restart_observations
            .values()
            .any(|observation| observation.entry != spec.emit_index)
    {
        return constraints;
    }
    constraints.with_top_images(
        restart_observations
            .values()
            .map(|observation| observation.target)
            .collect(),
    )
}

fn validate_distinct_nonzero_target_assumption(
    candidates: &[CandidateRuntime],
    spec: &LymmDeckSpec,
    observed: &[char],
    restart_observations: &BTreeMap<char, ForcedObservation>,
) -> Result<(), SwapRecoveryError> {
    let mut required_entries = restart_observations
        .values()
        .map(|observation| observation.entry)
        .collect::<BTreeSet<_>>();
    let _inserted = required_entries.insert(spec.emit_index);
    for entry in required_entries {
        let available_nonzero_targets = candidates
            .iter()
            .filter_map(|candidate| candidate.perm.get(entry).copied())
            .filter(|&target| target != 0)
            .collect::<BTreeSet<_>>()
            .len();
        if available_nonzero_targets >= observed.len() {
            continue;
        }
        return Err(SwapRecoveryError::TargetAssumptionViolated {
            detail: format!(
                "generator surface exposes {available_nonzero_targets} nonzero targets at entry {entry} for {} observed letters",
                observed.len()
            ),
        });
    }

    let observed_set = observed.iter().copied().collect::<BTreeSet<_>>();
    let mut seen = BTreeMap::new();
    for (&letter, &observation) in restart_observations {
        if !observed_set.contains(&letter) {
            continue;
        }
        if observation.target == 0 {
            return Err(SwapRecoveryError::TargetAssumptionViolated {
                detail: format!("identity restart pins {letter:?} to forbidden target 0"),
            });
        }
        if let Some(previous) = seen.insert(observation.target, letter) {
            return Err(SwapRecoveryError::TargetAssumptionViolated {
                detail: format!(
                    "identity restarts pin both {previous:?} and {letter:?} to target {}",
                    observation.target
                ),
            });
        }
    }
    Ok(())
}

fn restart_forced_observations(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
) -> Result<BTreeMap<char, ForcedObservation>, SwapRecoveryError> {
    let mut observations = BTreeMap::new();
    for message in messages {
        if let Some(event) = message.events.first() {
            let observation = forced_observation(spec, &spec.initial_state, event.ct_value)?;
            match observations.insert(event.letter, observation) {
                Some(previous) if previous != observation => {
                    return Err(SwapRecoveryError::InconsistentTarget {
                        letter: event.letter,
                        previous: previous.target,
                        observed: observation.target,
                    });
                }
                Some(previous) => {
                    let _old = observations.insert(event.letter, previous);
                }
                None => {}
            }
        }
    }
    Ok(observations)
}

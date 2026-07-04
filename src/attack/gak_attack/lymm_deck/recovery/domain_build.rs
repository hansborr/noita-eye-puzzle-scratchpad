//! Residual-domain construction for Lymm generator recovery.

use std::collections::{BTreeMap, BTreeSet};

use super::residual::{CandidateRuntime, ResidualDomains};
use super::{
    AlignedMessage, RecoveryGeneratorSet, SwapRecoveryConfig, SwapRecoveryError, occurrence_counts,
};
use crate::attack::gak_attack::lymm_deck::{
    LymmDeckSpec, TopSwapConstraints, TopSwapDomains, enumerate_generator_domains,
    enumerate_top_swap_domains,
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

    let initial_targets = identity_restart_targets(messages);
    let constraints = explicit_generator_constraints(config, &observed, &initial_targets);
    let domains = match &config.generator_set {
        RecoveryGeneratorSet::TopSwaps => {
            enumerate_top_swap_domains(spec, &TopSwapConstraints::up_to(config.max_swaps))?
        }
        RecoveryGeneratorSet::Explicit(generator_set) => {
            enumerate_generator_domains(spec, generator_set, &constraints)?
        }
    };
    validate_distinct_nonzero_target_assumption(&domains, &observed, &initial_targets)?;

    let candidates = domains
        .candidates
        .iter()
        .map(|candidate| CandidateRuntime {
            perm: candidate.permutation(spec),
        })
        .collect::<Vec<_>>();

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

fn explicit_generator_constraints(
    config: &SwapRecoveryConfig,
    observed: &[char],
    initial_targets: &BTreeMap<char, usize>,
) -> TopSwapConstraints {
    let constraints = TopSwapConstraints::up_to(config.max_swaps);
    if config.generator_set.is_top_swaps()
        || !observed
            .iter()
            .all(|letter| initial_targets.contains_key(letter))
    {
        return constraints;
    }
    constraints.with_top_images(initial_targets.values().copied().collect())
}

fn validate_distinct_nonzero_target_assumption(
    domains: &TopSwapDomains,
    observed: &[char],
    initial_targets: &BTreeMap<char, usize>,
) -> Result<(), SwapRecoveryError> {
    let available_nonzero_targets = domains
        .by_top_image
        .keys()
        .filter(|&&target| target != 0)
        .count();
    if available_nonzero_targets < observed.len() {
        return Err(SwapRecoveryError::TargetAssumptionViolated {
            detail: format!(
                "generator surface exposes {available_nonzero_targets} nonzero targets for {} observed letters",
                observed.len()
            ),
        });
    }

    let observed_set = observed.iter().copied().collect::<BTreeSet<_>>();
    let mut seen = BTreeMap::new();
    for (&letter, &target) in initial_targets {
        if !observed_set.contains(&letter) {
            continue;
        }
        if target == 0 {
            return Err(SwapRecoveryError::TargetAssumptionViolated {
                detail: format!("identity restart pins {letter:?} to forbidden target 0"),
            });
        }
        if let Some(previous) = seen.insert(target, letter) {
            return Err(SwapRecoveryError::TargetAssumptionViolated {
                detail: format!(
                    "identity restarts pin both {previous:?} and {letter:?} to target {target}"
                ),
            });
        }
    }
    Ok(())
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

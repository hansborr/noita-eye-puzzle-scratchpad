//! Residual-domain construction for Lymm generator recovery.

use std::collections::{BTreeMap, BTreeSet};

use super::domain_oracle::LetterDomainOracle;
use super::residual::ResidualDomains;
use super::state::{ForcedObservation, forced_observation};
use super::{
    AlignedMessage, RecoveryGeneratorSet, SwapRecoveryConfig, SwapRecoveryError, occurrence_counts,
};
use crate::attack::gak_attack::lymm_deck::generators::enumerate_generator_domains_for_entry_target;
use crate::attack::gak_attack::lymm_deck::{
    GeneratorBranchStrategy, LymmDeckSpec, LymmGeneratorSet, TopSwapCandidate, TopSwapConstraints,
    TopSwapDomains, enumerate_generator_domains, enumerate_top_swap_domains,
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
    match &config.generator_set {
        RecoveryGeneratorSet::TopSwaps => {
            build_top_swap_domains(spec, config, &observed, &restart_observations)
        }
        RecoveryGeneratorSet::Explicit(generator_set) => build_explicit_generator_domains(
            spec,
            generator_set,
            config,
            &observed,
            &restart_observations,
        ),
    }
}

fn build_top_swap_domains(
    spec: &LymmDeckSpec,
    config: &SwapRecoveryConfig,
    observed: &[char],
    restart_observations: &BTreeMap<char, ForcedObservation>,
) -> Result<ResidualDomains, SwapRecoveryError> {
    let domains = enumerate_top_swap_domains(spec, &TopSwapConstraints::up_to(config.max_swaps))?;
    let oracle = LetterDomainOracle::for_domains(spec, &domains);
    validate_distinct_nonzero_target_assumption(
        &domains,
        &oracle,
        spec,
        observed,
        restart_observations,
    )?;
    let by_letter = build_filtered_letters(&domains, &oracle, observed, restart_observations)?;
    Ok(ResidualDomains {
        domains,
        oracle,
        by_letter,
        letters: observed.to_vec(),
    })
}

fn build_explicit_generator_domains(
    spec: &LymmDeckSpec,
    generator_set: &LymmGeneratorSet,
    config: &SwapRecoveryConfig,
    observed: &[char],
    restart_observations: &BTreeMap<char, ForcedObservation>,
) -> Result<ResidualDomains, SwapRecoveryError> {
    let constraints = TopSwapConstraints::up_to(config.max_swaps);
    let mut full_domains = None;
    let mut domain_candidates = Vec::new();
    let mut index_by_sparse = BTreeMap::<(Vec<usize>, Vec<usize>), usize>::new();
    let mut by_letter = BTreeMap::new();
    let mut branch_strategy = None;

    for &letter in observed {
        let letter_domains = if let Some(observation) = restart_observations.get(&letter).copied() {
            enumerate_generator_domains_for_entry_target(
                spec,
                generator_set,
                &constraints,
                observation.entry,
                observation.target,
            )?
        } else {
            full_domains
                .get_or_insert(enumerate_generator_domains(
                    spec,
                    generator_set,
                    &constraints,
                )?)
                .clone()
        };
        branch_strategy = Some(letter_domains.branch_strategy.clone());
        let mut domain = Vec::new();
        for candidate in letter_domains.candidates {
            let key = (candidate.support.clone(), candidate.sigma_images.clone());
            let index = if let Some(index) = index_by_sparse.get(&key).copied() {
                index
            } else {
                let index = domain_candidates.len();
                let _old = index_by_sparse.insert(key, index);
                domain_candidates.push(candidate);
                index
            };
            domain.push(index);
        }
        if domain.is_empty() {
            return Err(SwapRecoveryError::NoCandidateForTarget {
                letter,
                target: restart_observations
                    .get(&letter)
                    .map_or(usize::MAX, |observation| observation.target),
            });
        }
        domain.sort_unstable();
        domain.dedup();
        let _old = by_letter.insert(letter, domain);
    }

    let domains = domains_from_candidates(
        domain_candidates,
        branch_strategy.unwrap_or(GeneratorBranchStrategy::WordMitm { split: 0 }),
    );
    let oracle = LetterDomainOracle::for_domains(spec, &domains);
    validate_distinct_nonzero_target_assumption(
        &domains,
        &oracle,
        spec,
        observed,
        restart_observations,
    )?;

    Ok(ResidualDomains {
        domains,
        oracle,
        by_letter,
        letters: observed.to_vec(),
    })
}

fn build_filtered_letters(
    domains: &TopSwapDomains,
    oracle: &LetterDomainOracle,
    observed: &[char],
    restart_observations: &BTreeMap<char, ForcedObservation>,
) -> Result<BTreeMap<char, Vec<usize>>, SwapRecoveryError> {
    let mut by_letter = BTreeMap::new();
    for &letter in observed {
        let domain: Vec<usize> = match restart_observations.get(&letter).copied() {
            Some(observation) => domains
                .candidates
                .iter()
                .enumerate()
                .filter_map(|(index, candidate)| {
                    oracle
                        .candidate_value(candidate, observation.entry)
                        .is_some_and(|image| image == observation.target)
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
    Ok(by_letter)
}

fn domains_from_candidates(
    candidates: Vec<TopSwapCandidate>,
    branch_strategy: GeneratorBranchStrategy,
) -> TopSwapDomains {
    let mut by_top_image: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    let mut by_support: BTreeMap<Vec<usize>, Vec<usize>> = BTreeMap::new();
    for (index, candidate) in candidates.iter().enumerate() {
        by_top_image
            .entry(candidate.top_image)
            .or_default()
            .push(index);
        by_support
            .entry(candidate.support.clone())
            .or_default()
            .push(index);
    }
    TopSwapDomains {
        candidates,
        by_top_image,
        by_support,
        branch_strategy,
    }
}

fn validate_distinct_nonzero_target_assumption(
    domains: &TopSwapDomains,
    oracle: &LetterDomainOracle,
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
        let available_nonzero_targets = domains
            .candidates
            .iter()
            .filter_map(|candidate| oracle.candidate_value(candidate, entry))
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

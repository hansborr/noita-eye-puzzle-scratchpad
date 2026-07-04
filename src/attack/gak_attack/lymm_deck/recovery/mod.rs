//! Known-plaintext recovery for Lymm's top-swap deck-cipher family.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

mod domain_build;
mod error;
mod inference;
mod instrumentation;
mod learning;
mod ns3_cegar;
#[cfg(test)]
mod ns3_control;
mod propagation;
mod propagation_pruning;
mod propagation_target_pruning;
mod reach;
mod residual;
mod sat_encoding;
mod selftest;
mod state;
mod target_conflict;
mod target_reason;
mod target_solver;

pub use error::SwapRecoveryError;
pub use inference::{
    SUPPORTED_SWAP_RECOVERY_FRONTIER, SWAP_RECOVERY_FRONTIER_MESSAGE, SwapInferenceAttempt,
    SwapInferenceOutcome, SwapInferenceRange, SwapInferenceReport,
    infer_known_plaintext_swap_budget,
};
pub use reach::{
    GakSwapReachStressCase, GakSwapReachStressConfig, GakSwapReachStressReport,
    gak_swap_reach_stress_self_test,
};
pub use selftest::{
    GakSwapSelfTestConfig, GakSwapSelfTestReport, NullControlOutcome, NullControlReport,
    PositiveControlReport, gak_swap_self_test,
};

use super::{
    KnownPlaintextPair, LymmDeckSpec, LymmGeneratorSet, TopSwapConstraints, TopSwapDomains,
    encrypt_lymm_deck, enumerate_top_swap_domains,
};
use residual::recover_with_residual;
use state::{ForcedObservation, apply_recovered_permutation, forced_observation};

/// Default deterministic seed for the swap-recovery controls.
pub const DEFAULT_SWAP_RECOVERY_SEED: u64 = 0x5a17_0200_0000_0002;

/// Generator family admitted by [`recover_known_plaintext_swaps`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryGeneratorSet {
    /// Lymm's original top-swap generator family `{(0 k)}`.
    TopSwaps,
    /// Explicit generator-file family. Words are reported as generator row
    /// indexes rather than top-swap positions.
    Explicit(LymmGeneratorSet),
}

impl RecoveryGeneratorSet {
    /// Returns true for the specialized top-swap family.
    #[must_use]
    pub const fn is_top_swaps(&self) -> bool {
        matches!(self, Self::TopSwaps)
    }
}

/// Search controls for [`recover_known_plaintext_swaps`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapRecoveryConfig {
    /// Maximum generator-word budget to admit into each per-letter domain.
    pub max_swaps: usize,
    /// Generator family used to build per-letter domains.
    pub generator_set: RecoveryGeneratorSet,
    /// Optional cap for residual-solver candidate models.
    pub max_nodes: Option<usize>,
    /// Optional wall-clock budget for the residual solver.
    pub time_budget: Option<Duration>,
    planted_truth: Option<BTreeMap<char, Vec<usize>>>,
}

impl SwapRecoveryConfig {
    /// Builds a config with only the top-swap budget set.
    #[must_use]
    pub const fn with_max_swaps(max_swaps: usize) -> Self {
        Self {
            max_swaps,
            generator_set: RecoveryGeneratorSet::TopSwaps,
            max_nodes: None,
            time_budget: None,
            planted_truth: None,
        }
    }

    /// Replaces the generator family.
    #[must_use]
    pub fn with_generator_set(mut self, generator_set: RecoveryGeneratorSet) -> Self {
        self.generator_set = generator_set;
        self
    }

    /// Adds observational planted truth for production-path soundness controls.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_planted_truth(mut self, planted_truth: BTreeMap<char, Vec<usize>>) -> Self {
        self.planted_truth = Some(planted_truth);
        self
    }

    /// Returns observational planted truth for internal controls.
    pub(super) fn planted_truth(&self) -> Option<&BTreeMap<char, Vec<usize>>> {
        self.planted_truth.as_ref()
    }
}

/// Final classification for a recovered plaintext letter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LetterRecoveryVerdict {
    /// Exactly one candidate permutation remains and it round-trips the corpus.
    RecoveredUnique,
    /// More than one candidate remains, but all reported candidates round-trip.
    RecoveredAmbiguous,
    /// A candidate mapping exists but has not earned full uniqueness.
    Candidate,
    /// No consistent candidate was found.
    NoCandidate,
}

/// One recovered plaintext-letter entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveredLetter {
    /// Plaintext alphabet symbol.
    pub letter: char,
    /// Number of occurrences in the known-plaintext corpus.
    pub occurrences: usize,
    /// Recovered `perm(letter)[emit_index]`, when the corpus constrains it.
    pub target: Option<usize>,
    /// Positions where the final candidate differs from the public base.
    pub support: Vec<usize>,
    /// Final recovered `base o sigma` permutation used for re-encryption.
    pub permutation: Option<Vec<usize>>,
    /// Final candidate permutations still admitted for this letter.
    pub candidate_permutations: Vec<Vec<usize>>,
    /// Canonical shortest word for the reported candidate. For top-swaps these
    /// entries are swap positions; for explicit generator sets they are
    /// generator row indexes.
    pub canonical_swaps: Vec<usize>,
    /// Number of equivalent final candidates still admitted for this letter.
    pub equivalent_count: usize,
    /// Whether this letter's target satisfies the no-doubles condition within the
    /// observed letters.
    pub no_doubles: bool,
    /// Letter-level recovery verdict.
    pub verdict: LetterRecoveryVerdict,
}

/// Aggregate exact round-trip result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundTripReport {
    /// Total matching ciphertext symbols across all message pairs.
    pub matched: usize,
    /// Total ciphertext symbols checked across all message pairs.
    pub total: usize,
    /// Per-message `(label, matched, total)` counts.
    pub per_message: Vec<(String, usize, usize)>,
    /// First divergence as `(label, ciphertext-index, expected, actual)`.
    pub first_divergence: Option<(String, usize, char, char)>,
}

impl RoundTripReport {
    /// Returns true when every checked ciphertext symbol matched.
    #[must_use]
    pub const fn exact(&self) -> bool {
        self.matched == self.total && self.first_divergence.is_none()
    }
}

/// Instrumentation counters from the propagation/residual solver.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SwapRecoveryStats {
    /// Number of enumerated top-swap candidates before per-letter filtering.
    pub enumerated_candidates: usize,
    /// Number of candidate-domain entries removed by deterministic propagation.
    pub domains_pruned: usize,
    /// Number of exact `perm(letter)[i] = value` deductions.
    pub deductions: usize,
    /// Residual solver candidate models or decision nodes checked.
    pub nodes: usize,
    /// Residual solver decisions, when a SAT backend is used.
    pub sat_decisions: usize,
    /// Residual solver conflicts, when a SAT backend is used.
    pub sat_conflicts: usize,
    /// Candidate/domain branches dropped by an optional beam fallback.
    pub beam_drops: usize,
    /// Target assignments rejected by target-level CEGAR.
    pub target_rejections: usize,
    /// Learned target-tuple clauses added by target-level CEGAR.
    pub target_clauses_learned: usize,
    /// Replay checks used to minimize deterministic target conflicts.
    pub target_replay_checks: usize,
    /// Sum of learned target-clause literal counts after replay minimization.
    pub target_replay_literals: usize,
    /// Full-assignment fallbacks taken after floor-mode reason candidates failed.
    pub target_floor_full_assignment_fallbacks: usize,
    /// Learned candidate-tuple clauses added after failed exact re-encryption.
    pub candidate_clauses_learned: usize,
    /// Learned clauses checked against planted truth by observational controls.
    pub truth_preservation_checks: usize,
    /// Total residual entries after applying planted targets and full propagation.
    pub measured_target_total_entries: usize,
    /// Maximum per-letter residual size after applying planted targets.
    pub measured_target_max_domain: usize,
    /// Per-letter residual sizes after applying planted targets.
    pub measured_target_domain_entries: Vec<(char, usize)>,
}

/// Full recovery report returned by [`recover_known_plaintext_swaps`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Config used for this run.
    pub config: SwapRecoveryConfig,
    /// Per-letter recovery records in plaintext alphabet order.
    pub letters: Vec<RecoveredLetter>,
    /// Final mapping used for exact re-encryption checks.
    pub pt_mapping: BTreeMap<char, Vec<usize>>,
    /// Exact compressed-ciphertext round-trip check.
    pub round_trip: RoundTripReport,
    /// Solver instrumentation.
    pub stats: SwapRecoveryStats,
    /// Aggregate verdict over the observed plaintext letters.
    pub verdict: LetterRecoveryVerdict,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AlignedMessage {
    pub(super) label: String,
    pub(super) plaintext: String,
    pub(super) events: Vec<AlignedEvent>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct AlignedEvent {
    pub(super) letter: char,
    pub(super) ct_value: usize,
    pub(super) ct_char: char,
}

/// Recovers Lymm top-swap plaintext mappings from known plaintext/ciphertext pairs.
///
/// # Errors
/// Returns [`SwapRecoveryError`] when the corpus is malformed, deterministic
/// deductions contradict each other, or the requested residual solver is not yet
/// available.
pub fn recover_known_plaintext_swaps(
    spec: &LymmDeckSpec,
    pairs: &[KnownPlaintextPair],
    config: SwapRecoveryConfig,
) -> Result<RecoveryReport, SwapRecoveryError> {
    let aligned = align_pairs(spec, pairs)?;
    if config.max_swaps == 1 && config.generator_set.is_top_swaps() && can_use_ns1_closed_form(spec)
    {
        recover_ns1(spec, &aligned, config)
    } else if (1..=3).contains(&config.max_swaps) {
        recover_with_residual(spec, &aligned, config)
    } else {
        Err(SwapRecoveryError::UnsupportedBudget {
            max_swaps: config.max_swaps,
        })
    }
}

fn can_use_ns1_closed_form(spec: &LymmDeckSpec) -> bool {
    spec.compose_dir == super::LymmComposeDirection::Left && spec.emit_index == 0
}

/// Re-encrypts known plaintext with `report.pt_mapping` and checks the compressed
/// ciphertext streams byte-for-byte.
///
/// # Errors
/// Returns [`SwapRecoveryError`] when encryption fails or a pair cannot be aligned.
pub fn round_trip_check(
    spec: &LymmDeckSpec,
    report: &RecoveryReport,
    pairs: &[KnownPlaintextPair],
) -> Result<RoundTripReport, SwapRecoveryError> {
    let mut per_message = Vec::with_capacity(pairs.len());
    let mut total = 0usize;
    let mut matched = 0usize;
    let mut first_divergence = None;
    for pair in pairs {
        let encrypted = encrypt_lymm_deck(spec, &report.pt_mapping, &pair.plaintext)?;
        let actual = compressed_emissions(spec, &pair.plaintext, &encrypted);
        let expected = pair.ciphertext.chars().collect::<Vec<_>>();
        let pair_total = expected.len();
        let mut pair_matched = 0usize;
        for index in 0..pair_total {
            let Some(&expected_ch) = expected.get(index) else {
                continue;
            };
            let Some(&actual_ch) = actual.get(index) else {
                if first_divergence.is_none() {
                    first_divergence = Some((pair.label.clone(), index, expected_ch, '\0'));
                }
                continue;
            };
            if expected_ch == actual_ch {
                pair_matched += 1;
            } else if first_divergence.is_none() {
                first_divergence = Some((pair.label.clone(), index, expected_ch, actual_ch));
            }
        }
        matched += pair_matched;
        total += pair_total;
        per_message.push((pair.label.clone(), pair_matched, pair_total));
    }
    Ok(RoundTripReport {
        matched,
        total,
        per_message,
        first_divergence,
    })
}

fn recover_ns1(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    config: SwapRecoveryConfig,
) -> Result<RecoveryReport, SwapRecoveryError> {
    let domains = enumerate_top_swap_domains(spec, &TopSwapConstraints::up_to(1))?;
    let mut inferred_targets: BTreeMap<char, usize> = BTreeMap::new();
    let mut occurrences = occurrence_counts(spec, messages);
    let mut stats = SwapRecoveryStats {
        enumerated_candidates: domains.candidates.len(),
        ..SwapRecoveryStats::default()
    };

    for message in messages {
        let mut deck_state = spec.initial_state.clone();
        for event in &message.events {
            let observation = forced_observation(spec, &deck_state, event.ct_value)?;
            match inferred_targets.insert(event.letter, observation.target) {
                Some(previous) if previous != observation.target => {
                    return Err(SwapRecoveryError::InconsistentTarget {
                        letter: event.letter,
                        previous,
                        observed: observation.target,
                    });
                }
                Some(previous) => {
                    let _old = inferred_targets.insert(event.letter, previous);
                }
                None => {
                    stats.deductions += 1;
                }
            }
            let candidate =
                unique_candidate_for_observation(&domains, spec, event.letter, observation)?;
            deck_state =
                apply_recovered_permutation(spec, &candidate.permutation(spec), &deck_state)?;
        }
    }

    let mut used_targets = BTreeSet::new();
    let mut pt_mapping = BTreeMap::new();
    let mut letters = Vec::with_capacity(spec.pt_alphabet.len());
    for &letter in &spec.pt_alphabet {
        let count = occurrences.remove(&letter).unwrap_or(0);
        let target = inferred_targets.get(&letter).copied();
        let candidate = match target {
            Some(value) => Some(unique_candidate_for_observation(
                &domains,
                spec,
                letter,
                ForcedObservation {
                    entry: spec.emit_index,
                    target: value,
                },
            )?),
            None => domains.candidates.first(),
        };
        let permutation = candidate.map(|found| found.permutation(spec));
        let candidate_permutations = permutation.iter().cloned().collect::<Vec<_>>();
        if let Some(perm) = &permutation {
            let _old = pt_mapping.insert(letter, perm.clone());
        }
        let no_doubles = target.is_none_or(|value| value != 0 && used_targets.insert(value));
        let verdict = if count == 0 {
            LetterRecoveryVerdict::NoCandidate
        } else if candidate.is_some() {
            LetterRecoveryVerdict::RecoveredUnique
        } else {
            LetterRecoveryVerdict::NoCandidate
        };
        letters.push(RecoveredLetter {
            letter,
            occurrences: count,
            target,
            support: candidate.map_or_else(Vec::new, |found| found.support.clone()),
            permutation,
            candidate_permutations,
            canonical_swaps: candidate.map_or_else(Vec::new, |found| found.canonical_swaps.clone()),
            equivalent_count: usize::from(candidate.is_some()),
            no_doubles,
            verdict,
        });
    }

    let placeholder = report_shell(config, letters, pt_mapping, stats);
    let pairs = pairs_from_messages(messages);
    let round_trip = round_trip_check(spec, &placeholder, &pairs)?;
    let mut report = placeholder;
    report.round_trip = round_trip;
    report.verdict = if report.round_trip.exact() {
        LetterRecoveryVerdict::RecoveredUnique
    } else {
        LetterRecoveryVerdict::Candidate
    };
    Ok(report)
}

pub(super) fn report_shell(
    config: SwapRecoveryConfig,
    letters: Vec<RecoveredLetter>,
    pt_mapping: BTreeMap<char, Vec<usize>>,
    stats: SwapRecoveryStats,
) -> RecoveryReport {
    RecoveryReport {
        config,
        letters,
        pt_mapping,
        round_trip: RoundTripReport {
            matched: 0,
            total: 0,
            per_message: Vec::new(),
            first_divergence: None,
        },
        stats,
        verdict: LetterRecoveryVerdict::Candidate,
    }
}

pub(super) fn pairs_from_messages(messages: &[AlignedMessage]) -> Vec<KnownPlaintextPair> {
    messages
        .iter()
        .map(|message| KnownPlaintextPair {
            label: message.label.clone(),
            plaintext: message.plaintext.clone(),
            ciphertext: message.events.iter().map(|event| event.ct_char).collect(),
        })
        .collect()
}

fn align_pairs(
    spec: &LymmDeckSpec,
    pairs: &[KnownPlaintextPair],
) -> Result<Vec<AlignedMessage>, SwapRecoveryError> {
    let mut messages = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let ciphertext = pair.ciphertext.chars().collect::<Vec<_>>();
        let plaintext_alpha_chars = pair
            .plaintext
            .chars()
            .filter(|&ch| spec.is_plaintext_char(ch))
            .count();
        if plaintext_alpha_chars != ciphertext.len() {
            return Err(SwapRecoveryError::PairLengthMismatch {
                label: pair.label.clone(),
                plaintext_alpha_chars,
                ciphertext_chars: ciphertext.len(),
            });
        }
        let mut events = Vec::with_capacity(ciphertext.len());
        for (ct_index, letter) in pair
            .plaintext
            .chars()
            .filter(|&ch| spec.is_plaintext_char(ch))
            .enumerate()
        {
            let ch =
                ciphertext
                    .get(ct_index)
                    .copied()
                    .ok_or(SwapRecoveryError::PairLengthMismatch {
                        label: pair.label.clone(),
                        plaintext_alpha_chars,
                        ciphertext_chars: ciphertext.len(),
                    })?;
            let ct_value = spec
                .ct_alphabet
                .iter()
                .position(|&candidate| candidate == ch)
                .ok_or(SwapRecoveryError::UnknownCiphertextSymbol {
                    label: pair.label.clone(),
                    index: ct_index,
                    ch,
                })?;
            events.push(AlignedEvent {
                letter,
                ct_value,
                ct_char: ch,
            });
        }
        messages.push(AlignedMessage {
            label: pair.label.clone(),
            plaintext: pair.plaintext.clone(),
            events,
        });
    }
    Ok(messages)
}

pub(super) fn occurrence_counts(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
) -> BTreeMap<char, usize> {
    let mut counts = spec
        .pt_alphabet
        .iter()
        .copied()
        .map(|letter| (letter, 0usize))
        .collect::<BTreeMap<_, _>>();
    for message in messages {
        for event in &message.events {
            *counts.entry(event.letter).or_default() += 1;
        }
    }
    counts
}

fn unique_candidate_for_observation<'a>(
    domains: &'a TopSwapDomains,
    spec: &LymmDeckSpec,
    letter: char,
    observation: ForcedObservation,
) -> Result<&'a super::TopSwapCandidate, SwapRecoveryError> {
    let matches = domains
        .candidates
        .iter()
        .filter(|candidate| {
            candidate
                .permutation(spec)
                .get(observation.entry)
                .is_some_and(|&image| image == observation.target)
        })
        .collect::<Vec<_>>();
    matches
        .into_iter()
        .next()
        .ok_or(SwapRecoveryError::NoCandidateForTarget {
            letter,
            target: observation.target,
        })
}

fn compressed_emissions(spec: &LymmDeckSpec, plaintext: &str, encrypted: &str) -> Vec<char> {
    plaintext
        .chars()
        .zip(encrypted.chars())
        .filter_map(|(plain, cipher)| spec.is_plaintext_char(plain).then_some(cipher))
        .collect()
}

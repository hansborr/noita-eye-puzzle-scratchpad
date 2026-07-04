//! Known-plaintext recovery for Lymm's top-swap deck-cipher family.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

mod propagation;
mod residual;
mod selftest;

pub use selftest::{
    GakSwapSelfTestConfig, GakSwapSelfTestReport, NullControlOutcome, NullControlReport,
    PositiveControlReport, gak_swap_self_test,
};

use super::{
    KnownPlaintextPair, LymmDeckError, LymmDeckSpec, TopSwapConstraints, TopSwapDomains,
    compose_lymm, encrypt_lymm_deck, enumerate_top_swap_domains,
};
use residual::recover_with_residual;

/// Default deterministic seed for the swap-recovery controls.
pub const DEFAULT_SWAP_RECOVERY_SEED: u64 = 0x5a17_0200_0000_0002;

/// Search controls for [`recover_known_plaintext_swaps`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwapRecoveryConfig {
    /// Maximum top-swap budget to admit into each per-letter domain.
    pub max_swaps: usize,
    /// Optional cap for residual-solver candidate models.
    pub max_nodes: Option<usize>,
    /// Optional wall-clock budget for the residual solver.
    pub time_budget: Option<Duration>,
}

impl SwapRecoveryConfig {
    /// Builds a config with only the top-swap budget set.
    #[must_use]
    pub const fn with_max_swaps(max_swaps: usize) -> Self {
        Self {
            max_swaps,
            max_nodes: None,
            time_budget: None,
        }
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
    /// Recovered `perm(letter)[0]`, when the corpus constrains it.
    pub target: Option<usize>,
    /// Positions where the final candidate differs from the public base.
    pub support: Vec<usize>,
    /// Final recovered `base o sigma` permutation used for re-encryption.
    pub permutation: Option<Vec<usize>>,
    /// Final candidate permutations still admitted for this letter.
    pub candidate_permutations: Vec<Vec<usize>>,
    /// Canonical shortest top-swap word for the reported candidate.
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

/// Error returned by the swap-recovery engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SwapRecoveryError {
    /// Underlying Lymm deck helper failed.
    LymmDeck(LymmDeckError),
    /// A ciphertext symbol was not in the configured ciphertext alphabet.
    UnknownCiphertextSymbol {
        /// Message label.
        label: String,
        /// Symbol index within the compressed ciphertext stream.
        index: usize,
        /// Unrecognized ciphertext character.
        ch: char,
    },
    /// The known-plaintext pair has different plaintext-alpha and ciphertext lengths.
    PairLengthMismatch {
        /// Message label.
        label: String,
        /// Plaintext alphabet character count.
        plaintext_alpha_chars: usize,
        /// Ciphertext symbol count.
        ciphertext_chars: usize,
    },
    /// The ns=1 closed-form sweep found inconsistent targets for one letter.
    InconsistentTarget {
        /// Plaintext letter.
        letter: char,
        /// Previously inferred target.
        previous: usize,
        /// Newly inferred target.
        observed: usize,
    },
    /// No top-swap candidate can realize the inferred target.
    NoCandidateForTarget {
        /// Plaintext letter.
        letter: char,
        /// Required `perm[0]` image.
        target: usize,
    },
    /// Recovery for this swap budget is not implemented yet.
    UnsupportedBudget {
        /// Requested swap budget.
        max_swaps: usize,
    },
    /// The residual solver exhausted its candidate-model cap before finding an
    /// exact round-trip.
    SearchCapExceeded {
        /// Candidate models checked.
        nodes: usize,
    },
    /// The residual solver exhausted its wall-clock budget before finding an
    /// exact round-trip.
    SearchTimeExceeded {
        /// Candidate models checked before the timeout.
        nodes: usize,
    },
    /// The SAT residual became unsatisfiable before any exact round-trip candidate.
    NoResidualCandidate,
    /// The SAT backend returned an internal error.
    SatSolver(String),
}

impl fmt::Display for SwapRecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LymmDeck(error) => write!(f, "{error}"),
            Self::UnknownCiphertextSymbol { label, index, ch } => write!(
                f,
                "message {label:?} ciphertext symbol {index} is not in the ciphertext alphabet: {ch:?}"
            ),
            Self::PairLengthMismatch {
                label,
                plaintext_alpha_chars,
                ciphertext_chars,
            } => write!(
                f,
                "message {label:?} has {plaintext_alpha_chars} plaintext alphabet characters but {ciphertext_chars} ciphertext symbols"
            ),
            Self::InconsistentTarget {
                letter,
                previous,
                observed,
            } => write!(
                f,
                "inconsistent ns=1 target for {letter:?}: previously {previous}, observed {observed}"
            ),
            Self::NoCandidateForTarget { letter, target } => {
                write!(
                    f,
                    "no top-swap candidate for {letter:?} with target {target}"
                )
            }
            Self::UnsupportedBudget { max_swaps } => {
                write!(
                    f,
                    "swap recovery for max_swaps={max_swaps} requires the residual solver"
                )
            }
            Self::SearchCapExceeded { nodes } => {
                write!(
                    f,
                    "swap recovery reached the residual node cap after {nodes} candidates"
                )
            }
            Self::SearchTimeExceeded { nodes } => {
                write!(
                    f,
                    "swap recovery reached the residual time budget after {nodes} candidates"
                )
            }
            Self::NoResidualCandidate => write!(f, "SAT residual has no candidate assignment"),
            Self::SatSolver(error) => write!(f, "SAT residual solver error: {error}"),
        }
    }
}

impl std::error::Error for SwapRecoveryError {}

impl From<LymmDeckError> for SwapRecoveryError {
    fn from(value: LymmDeckError) -> Self {
        Self::LymmDeck(value)
    }
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
    if config.max_swaps == 1 {
        recover_ns1(spec, &aligned, config)
    } else if config.max_swaps == 2 {
        recover_with_residual(spec, &aligned, config)
    } else {
        Err(SwapRecoveryError::UnsupportedBudget {
            max_swaps: config.max_swaps,
        })
    }
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
            let observed = inverse_position(&deck_state, event.ct_value)?;
            match inferred_targets.insert(event.letter, observed) {
                Some(previous) if previous != observed => {
                    return Err(SwapRecoveryError::InconsistentTarget {
                        letter: event.letter,
                        previous,
                        observed,
                    });
                }
                Some(previous) => {
                    let _old = inferred_targets.insert(event.letter, previous);
                }
                None => {
                    stats.deductions += 1;
                }
            }
            let candidate = unique_candidate_for_target(&domains, event.letter, observed)?;
            deck_state = compose_lymm(&candidate.permutation(spec), &deck_state)
                .map_err(LymmDeckError::from)?;
        }
    }

    let mut used_targets = BTreeSet::new();
    let mut pt_mapping = BTreeMap::new();
    let mut letters = Vec::with_capacity(spec.pt_alphabet.len());
    for &letter in &spec.pt_alphabet {
        let count = occurrences.remove(&letter).unwrap_or(0);
        let target = inferred_targets.get(&letter).copied();
        let candidate = match target {
            Some(value) => Some(unique_candidate_for_target(&domains, letter, value)?),
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

fn unique_candidate_for_target(
    domains: &TopSwapDomains,
    letter: char,
    target: usize,
) -> Result<&super::TopSwapCandidate, SwapRecoveryError> {
    let candidates = domains.candidates_with_top_image(target);
    candidates
        .into_iter()
        .next()
        .ok_or(SwapRecoveryError::NoCandidateForTarget { letter, target })
}

fn inverse_position(state: &[usize], value: usize) -> Result<usize, LymmDeckError> {
    state
        .iter()
        .position(|&candidate| candidate == value)
        .ok_or(LymmDeckError::EmitIndexOutOfRange {
            emit_index: value,
            n: state.len(),
        })
}

fn compressed_emissions(spec: &LymmDeckSpec, plaintext: &str, encrypted: &str) -> Vec<char> {
    plaintext
        .chars()
        .zip(encrypted.chars())
        .filter_map(|(plain, cipher)| spec.is_plaintext_char(plain).then_some(cipher))
        .collect()
}

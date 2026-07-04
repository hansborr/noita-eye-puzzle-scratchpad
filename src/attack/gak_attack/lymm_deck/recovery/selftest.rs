//! Planted controls and matched nulls for Lymm swap recovery.

use std::collections::BTreeMap;

use crate::nulls::null::{RandomBoundError, SplitMix64, fisher_yates, shuffled_permutation};

use super::super::{
    KnownPlaintextPair, LymmDeckSpec, encrypt_lymm_deck, generate_random_pt_mapping,
};
use super::{
    DEFAULT_SWAP_RECOVERY_SEED, LetterRecoveryVerdict, RecoveryReport, SwapRecoveryConfig,
    SwapRecoveryError, recover_known_plaintext_swaps,
};

/// Self-test configuration for the supported GAK swap-recovery frontier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GakSwapSelfTestConfig {
    /// Deterministic seed for planted mappings and matched nulls.
    pub seed: u64,
    /// Residual candidate-model cap for solver calls.
    pub max_nodes: Option<usize>,
}

impl Default for GakSwapSelfTestConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_SWAP_RECOVERY_SEED,
            max_nodes: Some(50_000),
        }
    }
}

/// Positive-control result for one planted top-swap budget.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PositiveControlReport {
    /// Planted top-swap budget.
    pub num_swaps: usize,
    /// Whether recovery returned an exact re-encryption candidate.
    pub exact: bool,
    /// Number of recovered observed letters whose final permutation equals the plant.
    pub matched_observed_letters: usize,
    /// Observed letters recovered exactly but still reported as ambiguous.
    pub ambiguous_observed_letters: usize,
    /// Ambiguous observed letters whose candidate set did not contain the plant.
    pub ambiguous_missing_planted_letters: usize,
    /// Observed letters reported unique but not equal to the planted permutation.
    pub mismatched_unique_letters: usize,
    /// Number of observed plaintext letters in the control corpus.
    pub observed_letters: usize,
    /// Candidate-model nodes checked by the residual solver.
    pub nodes: usize,
    /// SAT decisions reported by the backend.
    pub sat_decisions: usize,
    /// SAT conflicts reported by the backend.
    pub sat_conflicts: usize,
}

/// Matched-null result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NullControlReport {
    /// Human-readable null label.
    pub label: &'static str,
    /// Whether the null genuinely failed to recover an exact candidate.
    ///
    /// This is true only for a clean model failure, not for solver resource
    /// exhaustion or a control plumbing error.
    pub failed: bool,
    /// The precise null outcome used to decide whether the failure was genuine.
    pub outcome: NullControlOutcome,
    /// Solver nodes reported by the path that reached this outcome, when known.
    pub nodes: Option<usize>,
}

/// Matched-null outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NullControlOutcome {
    /// The recovery model concluded no exact candidate survived.
    CleanFailure,
    /// The null unexpectedly recovered an exact candidate.
    RecoveredExact,
    /// The solver exhausted its candidate-model cap before reaching a verdict.
    SearchCapExceeded,
    /// The solver exhausted its wall-clock budget before reaching a verdict.
    SearchTimeExceeded,
    /// The control input or solver plumbing failed for a reason other than a
    /// clean model contradiction.
    ControlError,
}

impl NullControlOutcome {
    /// Returns true only for a genuine null failure.
    #[must_use]
    pub const fn is_clean_failure(self) -> bool {
        match self {
            Self::CleanFailure => true,
            Self::RecoveredExact
            | Self::SearchCapExceeded
            | Self::SearchTimeExceeded
            | Self::ControlError => false,
        }
    }

    /// Stable machine-readable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CleanFailure => "clean-failure",
            Self::RecoveredExact => "recovered-exact",
            Self::SearchCapExceeded => "search-cap-exceeded",
            Self::SearchTimeExceeded => "search-time-exceeded",
            Self::ControlError => "control-error",
        }
    }
}

/// Aggregate self-test report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GakSwapSelfTestReport {
    /// Config used for this run.
    pub config: GakSwapSelfTestConfig,
    /// ns=1 planted control.
    pub positive_ns1: PositiveControlReport,
    /// ns=2 planted control.
    pub positive_ns2: PositiveControlReport,
    /// Random full-permutation null at the ns=2 bound.
    pub full_permutation_null: NullControlReport,
    /// ns=2 encrypted text attacked at the ns=1 bound.
    pub over_budget_null: NullControlReport,
    /// The same ns=2 plant recovered at the ns=2 bound.
    pub over_budget_recovery_exact: bool,
    /// Ciphertext-label shuffle null at the ns=2 bound.
    pub label_shuffle_null: NullControlReport,
}

impl GakSwapSelfTestReport {
    /// Returns true when every positive and null control passed.
    #[must_use]
    pub const fn passed(&self) -> bool {
        positive_passed(&self.positive_ns1)
            && positive_passed(&self.positive_ns2)
            && self.full_permutation_null.failed
            && self.over_budget_null.failed
            && self.over_budget_recovery_exact
            && self.label_shuffle_null.failed
    }
}

/// Runs planted controls and matched nulls over the supported ns<=2 frontier.
///
/// # Errors
/// Returns [`SwapRecoveryError`] when the oracle or recovery machinery fails on a
/// positive control that should recover.
pub fn gak_swap_self_test(
    config: GakSwapSelfTestConfig,
) -> Result<GakSwapSelfTestReport, SwapRecoveryError> {
    let spec = LymmDeckSpec::lymm_default()?;
    let plaintexts = control_plaintexts();
    let ns1_mapping = generate_random_pt_mapping(&spec, 1, config.seed ^ 0x11)?;
    let ns1_pairs = encrypt_pairs(&spec, &plaintexts, &ns1_mapping.pt_mapping)?;
    let positive_ns1 = positive_control(&spec, &ns1_pairs, &ns1_mapping.pt_mapping, 1, config)?;

    let ns2_mapping = generate_random_pt_mapping(&spec, 2, config.seed ^ 0x22)?;
    let ns2_pairs = encrypt_pairs(&spec, &plaintexts, &ns2_mapping.pt_mapping)?;
    let positive_ns2 = positive_control(&spec, &ns2_pairs, &ns2_mapping.pt_mapping, 2, config)?;
    let over_budget_recovery_exact = positive_ns2.exact;

    let full_mapping = random_full_mapping(&spec, config.seed ^ 0x33)?;
    let full_pairs = encrypt_pairs(&spec, &plaintexts, &full_mapping)?;
    let full_permutation_null = null_control("full-permutation", &spec, &full_pairs, 2, config);

    let over_budget_null = null_control("over-budget", &spec, &ns2_pairs, 1, config);
    let shuffled_pairs = label_shuffle_pairs(&spec, &ns2_pairs, config.seed ^ 0x44)?;
    let label_shuffle_null = null_control("label-shuffle", &spec, &shuffled_pairs, 2, config);

    Ok(GakSwapSelfTestReport {
        config,
        positive_ns1,
        positive_ns2,
        full_permutation_null,
        over_budget_null,
        over_budget_recovery_exact,
        label_shuffle_null,
    })
}

fn positive_control(
    spec: &LymmDeckSpec,
    pairs: &[KnownPlaintextPair],
    planted: &BTreeMap<char, Vec<usize>>,
    num_swaps: usize,
    config: GakSwapSelfTestConfig,
) -> Result<PositiveControlReport, SwapRecoveryError> {
    let report = recover_known_plaintext_swaps(spec, pairs, recovery_config(num_swaps, config))?;
    let mut matched_observed_letters = 0usize;
    let mut ambiguous_observed_letters = 0usize;
    let mut ambiguous_missing_planted_letters = 0usize;
    let mut mismatched_unique_letters = 0usize;
    let mut observed_letters = 0usize;
    for letter in &report.letters {
        if letter.occurrences == 0 {
            continue;
        }
        observed_letters += 1;
        match letter.verdict {
            LetterRecoveryVerdict::RecoveredUnique => {
                if letter
                    .permutation
                    .as_ref()
                    .is_some_and(|permutation| planted.get(&letter.letter) == Some(permutation))
                {
                    matched_observed_letters += 1;
                } else {
                    mismatched_unique_letters += 1;
                }
            }
            LetterRecoveryVerdict::RecoveredAmbiguous => {
                if planted.get(&letter.letter).is_some_and(|planted_perm| {
                    letter
                        .candidate_permutations
                        .iter()
                        .any(|candidate| candidate == planted_perm)
                }) {
                    ambiguous_observed_letters += 1;
                } else {
                    ambiguous_missing_planted_letters += 1;
                }
            }
            LetterRecoveryVerdict::Candidate | LetterRecoveryVerdict::NoCandidate => {}
        }
    }
    Ok(positive_report(
        num_swaps,
        &report,
        matched_observed_letters,
        ambiguous_observed_letters,
        ambiguous_missing_planted_letters,
        mismatched_unique_letters,
        observed_letters,
    ))
}

fn positive_report(
    num_swaps: usize,
    report: &RecoveryReport,
    matched_observed_letters: usize,
    ambiguous_observed_letters: usize,
    ambiguous_missing_planted_letters: usize,
    mismatched_unique_letters: usize,
    observed_letters: usize,
) -> PositiveControlReport {
    PositiveControlReport {
        num_swaps,
        exact: report.round_trip.exact(),
        matched_observed_letters,
        ambiguous_observed_letters,
        ambiguous_missing_planted_letters,
        mismatched_unique_letters,
        observed_letters,
        nodes: report.stats.nodes,
        sat_decisions: report.stats.sat_decisions,
        sat_conflicts: report.stats.sat_conflicts,
    }
}

const fn positive_passed(report: &PositiveControlReport) -> bool {
    report.exact
        && report.mismatched_unique_letters == 0
        && report.ambiguous_missing_planted_letters == 0
        && report.matched_observed_letters + report.ambiguous_observed_letters
            == report.observed_letters
}

fn null_control(
    label: &'static str,
    spec: &LymmDeckSpec,
    pairs: &[KnownPlaintextPair],
    max_swaps: usize,
    config: GakSwapSelfTestConfig,
) -> NullControlReport {
    let (outcome, nodes) =
        match recover_known_plaintext_swaps(spec, pairs, recovery_config(max_swaps, config)) {
            Ok(report) if report.round_trip.exact() => {
                (NullControlOutcome::RecoveredExact, Some(report.stats.nodes))
            }
            Ok(report) => (NullControlOutcome::CleanFailure, Some(report.stats.nodes)),
            Err(
                SwapRecoveryError::InconsistentTarget { .. }
                | SwapRecoveryError::NoCandidateForTarget { .. }
                | SwapRecoveryError::NoResidualCandidate,
            ) => (NullControlOutcome::CleanFailure, None),
            Err(SwapRecoveryError::SearchCapExceeded { nodes }) => {
                (NullControlOutcome::SearchCapExceeded, Some(nodes))
            }
            Err(SwapRecoveryError::SearchTimeExceeded { nodes }) => {
                (NullControlOutcome::SearchTimeExceeded, Some(nodes))
            }
            Err(
                SwapRecoveryError::LymmDeck(_)
                | SwapRecoveryError::UnknownCiphertextSymbol { .. }
                | SwapRecoveryError::PairLengthMismatch { .. }
                | SwapRecoveryError::UnsupportedBudget { .. }
                | SwapRecoveryError::TargetUnsatCore { .. }
                | SwapRecoveryError::SatSolver(_),
            ) => (NullControlOutcome::ControlError, None),
        };
    NullControlReport {
        label,
        failed: outcome.is_clean_failure(),
        outcome,
        nodes,
    }
}

fn recovery_config(max_swaps: usize, config: GakSwapSelfTestConfig) -> SwapRecoveryConfig {
    let mut recovery = SwapRecoveryConfig::with_max_swaps(max_swaps);
    recovery.max_nodes = config.max_nodes;
    recovery
}

fn encrypt_pairs(
    spec: &LymmDeckSpec,
    plaintexts: &[(String, String)],
    mapping: &BTreeMap<char, Vec<usize>>,
) -> Result<Vec<KnownPlaintextPair>, SwapRecoveryError> {
    plaintexts
        .iter()
        .map(|(label, plaintext)| {
            let ciphertext = encrypt_lymm_deck(spec, mapping, plaintext)?;
            Ok(KnownPlaintextPair {
                label: label.clone(),
                plaintext: plaintext.clone(),
                ciphertext: ciphertext
                    .chars()
                    .filter(|&ch| spec.ct_alphabet.contains(&ch))
                    .collect(),
            })
        })
        .collect()
}

fn random_full_mapping(
    spec: &LymmDeckSpec,
    seed: u64,
) -> Result<BTreeMap<char, Vec<usize>>, SwapRecoveryError> {
    let mut rng = SplitMix64::new(seed);
    let mut mapping = BTreeMap::new();
    for &letter in &spec.pt_alphabet {
        let _old = mapping.insert(
            letter,
            shuffled_permutation(spec.n, &mut rng).map_err(random_bound_error)?,
        );
    }
    Ok(mapping)
}

fn label_shuffle_pairs(
    spec: &LymmDeckSpec,
    pairs: &[KnownPlaintextPair],
    seed: u64,
) -> Result<Vec<KnownPlaintextPair>, SwapRecoveryError> {
    let mut rng = SplitMix64::new(seed);
    let mut shuffled_labels = spec.ct_alphabet.clone();
    fisher_yates(&mut shuffled_labels, &mut rng).map_err(random_bound_error)?;
    if shuffled_labels == spec.ct_alphabet && shuffled_labels.len() > 1 {
        shuffled_labels.rotate_left(1);
    }
    let relabel = spec
        .ct_alphabet
        .iter()
        .copied()
        .zip(shuffled_labels)
        .collect::<BTreeMap<_, _>>();
    Ok(pairs
        .iter()
        .map(|pair| KnownPlaintextPair {
            label: pair.label.clone(),
            plaintext: pair.plaintext.clone(),
            ciphertext: pair
                .ciphertext
                .chars()
                .map(|ch| relabel.get(&ch).copied().unwrap_or(ch))
                .collect(),
        })
        .collect())
}

fn random_bound_error(error: RandomBoundError) -> SwapRecoveryError {
    SwapRecoveryError::SatSolver(format!(
        "deterministic random bound failed: {}",
        error.bound
    ))
}

fn control_plaintexts() -> Vec<(String, String)> {
    include_str!("../../../../../research/data/practice-puzzles/deck-swap/plaintexts.txt")
        .lines()
        .filter_map(|line| line.split_once(": "))
        .map(|(label, plaintext)| (label.to_owned(), plaintext.to_owned()))
        .collect()
}

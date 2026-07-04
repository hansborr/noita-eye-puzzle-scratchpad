//! Swap-budget inference over the supported recovery frontier.

use super::{
    LetterRecoveryVerdict, RecoveryReport, RoundTripReport, SwapRecoveryConfig, SwapRecoveryError,
    SwapRecoveryStats, recover_known_plaintext_swaps,
};
use crate::attack::gak_attack::lymm_deck::{KnownPlaintextPair, LymmDeckSpec};

/// Largest top-swap budget supported by the public recovery CLI today.
pub const SUPPORTED_SWAP_RECOVERY_FRONTIER: usize = 2;

/// Stable measured-frontier wording shared by direct and inferred recovery modes.
pub const SWAP_RECOVERY_FRONTIER_MESSAGE: &str =
    "measured Task-02 frontier is currently ns<=2, and ns=3 remains a recorded wall";

/// Inclusive `--infer-swaps A..B` search range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwapInferenceRange {
    /// First budget to try.
    pub start: usize,
    /// Last requested budget.
    pub end: usize,
}

impl SwapInferenceRange {
    /// Builds an inclusive inference range.
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
}

/// Machine-readable outcome for one inference attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwapInferenceOutcome {
    /// Recovery re-encrypted every ciphertext symbol exactly.
    ExactRoundTrip,
    /// Recovery returned a candidate, but exact re-encryption failed.
    NonExactRoundTrip,
    /// The model rejected this budget without a resource cap.
    ModelRejected,
    /// The residual solver hit its candidate-model cap.
    SearchCapExceeded,
    /// The residual solver hit its wall-clock cap.
    SearchTimeExceeded,
}

impl SwapInferenceOutcome {
    /// Stable machine-readable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExactRoundTrip => "exact-round-trip",
            Self::NonExactRoundTrip => "non-exact-round-trip",
            Self::ModelRejected => "model-rejected",
            Self::SearchCapExceeded => "search-cap-exceeded",
            Self::SearchTimeExceeded => "search-time-exceeded",
        }
    }
}

/// One attempted swap budget in an inference run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapInferenceAttempt {
    /// Top-swap budget tried for this attempt.
    pub max_swaps: usize,
    /// Attempt outcome.
    pub outcome: SwapInferenceOutcome,
    /// Maximum final-permutation support size over observed letters, when a
    /// candidate report existed. This intentionally is not swap-word length.
    pub support_size: Option<usize>,
    /// Exact round-trip counts, when a candidate report existed.
    pub round_trip: Option<RoundTripReport>,
    /// Solver instrumentation, when a candidate report existed.
    pub stats: Option<SwapRecoveryStats>,
    /// Error text for model-rejected or resource-capped attempts.
    pub error: Option<String>,
}

/// Full result for `--infer-swaps`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapInferenceReport {
    /// Requested inclusive range.
    pub requested: SwapInferenceRange,
    /// Effective inclusive range after applying the measured frontier.
    pub attempted: SwapInferenceRange,
    /// True when the requested upper bound exceeded the supported frontier.
    pub frontier_capped: bool,
    /// Attempts run in increasing budget order, stopping at the first exact
    /// round-trip.
    pub attempts: Vec<SwapInferenceAttempt>,
    /// Smallest exact recovery report, if any supported budget closed.
    pub selected: Option<RecoveryReport>,
}

impl SwapInferenceReport {
    /// Returns the smallest exact budget, when inference closed.
    #[must_use]
    pub fn inferred_max_swaps(&self) -> Option<usize> {
        self.selected.as_ref().map(|report| report.config.max_swaps)
    }

    /// Returns the selected maximum final-permutation support size.
    #[must_use]
    pub fn inferred_support_size(&self) -> Option<usize> {
        self.selected.as_ref().map(max_observed_support_size)
    }

    /// Returns true when a supported budget produced exact re-encryption.
    #[must_use]
    pub fn exact(&self) -> bool {
        self.selected
            .as_ref()
            .is_some_and(|report| report.round_trip.exact())
    }
}

/// Infers the smallest supported swap budget whose recovered final-permutation
/// support round-trips the known plaintext/ciphertext pairs exactly.
///
/// The requested range is capped at [`SUPPORTED_SWAP_RECOVERY_FRONTIER`]. A range
/// that starts beyond that frontier fails instead of silently running unsupported
/// budgets.
///
/// # Errors
/// Returns [`SwapRecoveryError`] when the range is invalid, the range starts past
/// the measured frontier, the corpus is malformed, or the recovery engine hits an
/// internal error that is not a clean model rejection for an attempted budget.
pub fn infer_known_plaintext_swap_budget(
    spec: &LymmDeckSpec,
    pairs: &[KnownPlaintextPair],
    range: SwapInferenceRange,
    mut config: SwapRecoveryConfig,
) -> Result<SwapInferenceReport, SwapRecoveryError> {
    if range.start == 0 || range.start > range.end {
        return Err(SwapRecoveryError::InvalidInferenceRange {
            start: range.start,
            end: range.end,
        });
    }
    if range.start > SUPPORTED_SWAP_RECOVERY_FRONTIER {
        return Err(SwapRecoveryError::UnsupportedBudget {
            max_swaps: range.start,
        });
    }

    let attempted =
        SwapInferenceRange::new(range.start, range.end.min(SUPPORTED_SWAP_RECOVERY_FRONTIER));
    let frontier_capped = range.end > SUPPORTED_SWAP_RECOVERY_FRONTIER;
    let mut attempts = Vec::new();
    let mut selected = None;

    for max_swaps in attempted.start..=attempted.end {
        config.max_swaps = max_swaps;
        match recover_known_plaintext_swaps(spec, pairs, config.clone()) {
            Ok(report) => {
                let exact = report.round_trip.exact();
                let attempt = attempt_from_report(max_swaps, &report);
                attempts.push(attempt);
                if exact {
                    selected = Some(report);
                    break;
                }
            }
            Err(error) => {
                let Some(outcome) = recoverable_attempt_error(&error) else {
                    return Err(error);
                };
                attempts.push(SwapInferenceAttempt {
                    max_swaps,
                    outcome,
                    support_size: None,
                    round_trip: None,
                    stats: None,
                    error: Some(error.to_string()),
                });
                if matches!(
                    outcome,
                    SwapInferenceOutcome::SearchCapExceeded
                        | SwapInferenceOutcome::SearchTimeExceeded
                ) {
                    break;
                }
            }
        }
    }

    Ok(SwapInferenceReport {
        requested: range,
        attempted,
        frontier_capped,
        attempts,
        selected,
    })
}

fn attempt_from_report(max_swaps: usize, report: &RecoveryReport) -> SwapInferenceAttempt {
    let outcome = if report.round_trip.exact() {
        SwapInferenceOutcome::ExactRoundTrip
    } else {
        SwapInferenceOutcome::NonExactRoundTrip
    };
    SwapInferenceAttempt {
        max_swaps,
        outcome,
        support_size: Some(max_observed_support_size(report)),
        round_trip: Some(report.round_trip.clone()),
        stats: Some(report.stats.clone()),
        error: None,
    }
}

fn recoverable_attempt_error(error: &SwapRecoveryError) -> Option<SwapInferenceOutcome> {
    match error {
        SwapRecoveryError::InconsistentTarget { .. }
        | SwapRecoveryError::NoCandidateForTarget { .. }
        | SwapRecoveryError::TargetAssumptionViolated { .. }
        | SwapRecoveryError::NoResidualCandidate => Some(SwapInferenceOutcome::ModelRejected),
        SwapRecoveryError::SearchCapExceeded { .. } => {
            Some(SwapInferenceOutcome::SearchCapExceeded)
        }
        SwapRecoveryError::SearchTimeExceeded { .. } => {
            Some(SwapInferenceOutcome::SearchTimeExceeded)
        }
        SwapRecoveryError::LymmDeck(_)
        | SwapRecoveryError::UnknownCiphertextSymbol { .. }
        | SwapRecoveryError::PairLengthMismatch { .. }
        | SwapRecoveryError::UnsupportedBudget { .. }
        | SwapRecoveryError::InvalidInferenceRange { .. }
        | SwapRecoveryError::TargetUnsatCore { .. }
        | SwapRecoveryError::TruthPreservationViolated { .. }
        | SwapRecoveryError::SatSolver(_) => None,
    }
}

fn max_observed_support_size(report: &RecoveryReport) -> usize {
    report
        .letters
        .iter()
        .filter(|letter| letter.occurrences > 0)
        .filter(|letter| {
            matches!(
                letter.verdict,
                LetterRecoveryVerdict::RecoveredUnique
                    | LetterRecoveryVerdict::RecoveredAmbiguous
                    | LetterRecoveryVerdict::Candidate
            )
        })
        .map(|letter| letter.support.len())
        .max()
        .unwrap_or(0)
}

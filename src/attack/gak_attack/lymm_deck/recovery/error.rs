//! Error type for Lymm swap recovery.

use std::fmt;

use super::super::LymmDeckError;

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
    /// The inclusive inference range was malformed.
    InvalidInferenceRange {
        /// First requested budget.
        start: usize,
        /// Last requested budget.
        end: usize,
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
    /// Internal ns=3 CEGAR signal carrying a target-choice unsat core.
    TargetUnsatCore {
        /// Target choices sufficient for the candidate residual contradiction.
        choices: Vec<(char, usize)>,
    },
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
            Self::InvalidInferenceRange { start, end } => write!(
                f,
                "invalid --infer-swaps range {start}..{end}; expected 1 <= start <= end"
            ),
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
            Self::TargetUnsatCore { choices } => {
                write!(
                    f,
                    "SAT residual rejected a target core with {} choices",
                    choices.len()
                )
            }
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

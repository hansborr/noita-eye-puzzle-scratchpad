//! Experiment 7B: alphabet-chaining as a calibrated structural signature.
//!
//! The procedure here is intentionally narrow. For a candidate period `p`, each
//! message is split into columns by `position % p`, resetting the column counter
//! at message boundaries. For every adjacent column pair, including the last
//! column back to column zero, the code chooses the additive alphabet shift that
//! maximizes circular distribution overlap between the two column histograms.
//!
//! The measured signature is:
//!
//! - mean best shifted distribution overlap;
//! - mean pairwise alignment quality, defined as the margin between the best
//!   and second-best shifted overlaps;
//! - the around-cycle residual, `sum(shifts) mod alphabet_size`; and
//! - `chain_score = mean_alignment_quality * cycle_closure`, where
//!   `cycle_closure` is `1.0` at zero residual and decreases linearly to zero at
//!   the maximum circular residual distance.
//!
//! A high score therefore requires both identifiable pairwise shifts and a
//! closed additive cycle. Uniform columns, or columns whose best shifts are not
//! distinguishable from nearby alternatives, have low quality even when some
//! shift can always be chosen.
//!
//! The calibration controls are generated, not reverse-engineered from the eye
//! data. The known-succeed fixture is a Vigenere stream over the same 83-symbol
//! reading alphabet with period `p`; its columns are additive shifts of the same
//! irregular source distribution. The known-fail fixture applies an independent
//! random substitution to each period column, so the columns share the source
//! frequency multiset without being circular shifts of one another. A
//! within-column shuffled copy of the failure fixture is also measured; because
//! this chaining signature uses only column distributions, that shuffle is an
//! invariance check rather than a separate order-sensitive signal.

use std::fmt;

use crate::analysis::orders::{self, GridError, ReadingOrder};
use crate::nulls::null::{median_f64, median_usize, scaled_quantile_index};

mod engine;
mod report;
#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) use engine::{SourceProfile, build_control_fixtures};
pub use engine::{chaining_for_stream, chaining_signature, run_chaining};

/// Default deterministic Monte-Carlo seed for Experiment 7B.
pub const DEFAULT_SEED: u64 = 0x6368_6169_6e37_6221;
/// Default Monte-Carlo trial count for CLI calibration.
pub const DEFAULT_TRIALS: usize = 256;
/// Default minimum candidate period.
pub const DEFAULT_MIN_PERIOD: usize = 2;
/// Default maximum candidate period.
pub const DEFAULT_MAX_PERIOD: usize = 16;
/// Alphabet size for the accepted honeycomb reading-layer stream (`0..=82`).
pub const DEFAULT_ALPHABET_SIZE: usize = orders::READING_LAYER_ALPHABET_SIZE;

/// Configuration for Experiment 7B.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainingConfig {
    /// Explicit deterministic PRNG seed.
    pub seed: u64,
    /// Number of generated control fixtures sampled per candidate period.
    pub trials: usize,
    /// Smallest candidate period to test, inclusive.
    pub min_period: usize,
    /// Largest candidate period to test, inclusive.
    pub max_period: usize,
    /// Additive alphabet size used by the chaining procedure.
    pub alphabet_size: usize,
}

impl Default for ChainingConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_SEED,
            trials: DEFAULT_TRIALS,
            min_period: DEFAULT_MIN_PERIOD,
            max_period: DEFAULT_MAX_PERIOD,
            alphabet_size: DEFAULT_ALPHABET_SIZE,
        }
    }
}

/// Error returned by the Experiment 7B chaining battery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainingError {
    /// The verified corpus could not be reconstructed or read with the order.
    Grid(GridError),
    /// At least one Monte-Carlo trial is required.
    ZeroTrials,
    /// Candidate period range was empty or included the degenerate period one.
    InvalidPeriodRange {
        /// Requested minimum period.
        min_period: usize,
        /// Requested maximum period.
        max_period: usize,
    },
    /// The additive alphabet must fit in the base-5 trigram value type.
    InvalidAlphabetSize {
        /// Requested alphabet size.
        alphabet_size: usize,
    },
    /// A measured stream contained a value outside the configured alphabet.
    ValueOutsideAlphabet {
        /// Offending reading-layer value.
        value: u8,
        /// Configured alphabet size.
        alphabet_size: usize,
    },
    /// A deterministic control fixture could not be generated.
    ControlConstructionFailed,
    /// A random draw bound did not fit the PRNG helper.
    RandomBoundTooLarge {
        /// Requested exclusive upper bound.
        bound: usize,
    },
}

impl From<GridError> for ChainingError {
    fn from(value: GridError) -> Self {
        Self::Grid(value)
    }
}

impl From<crate::nulls::null::RandomBoundError> for ChainingError {
    fn from(error: crate::nulls::null::RandomBoundError) -> Self {
        Self::RandomBoundTooLarge { bound: error.bound }
    }
}

impl fmt::Display for ChainingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Grid(grid_error) => write!(f, "grid/order error: {grid_error:?}"),
            Self::ZeroTrials => write!(f, "at least one Monte-Carlo trial is required"),
            Self::InvalidPeriodRange {
                min_period,
                max_period,
            } => write!(
                f,
                "invalid period range {min_period}..={max_period}; use periods >= 2"
            ),
            Self::InvalidAlphabetSize { alphabet_size } => {
                write!(f, "invalid alphabet size {alphabet_size}; expected 1..=125")
            }
            Self::ValueOutsideAlphabet {
                value,
                alphabet_size,
            } => write!(
                f,
                "stream value {value} is outside configured alphabet size {alphabet_size}"
            ),
            Self::ControlConstructionFailed => {
                write!(f, "generated control fixture could not be constructed")
            }
            Self::RandomBoundTooLarge { bound } => {
                write!(f, "random draw bound {bound} is too large")
            }
        }
    }
}

impl std::error::Error for ChainingError {}

/// Best additive alignment found for one adjacent period-column pair.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PairAlignment {
    /// Source column index.
    pub from_column: usize,
    /// Destination column index.
    pub to_column: usize,
    /// Additive shift relating the source distribution to the destination:
    /// `source[x]` is compared with `destination[x + shift]`.
    pub shift: usize,
    /// Best circular distribution overlap, in `0.0..=1.0`.
    pub best_overlap: f64,
    /// Second-best circular distribution overlap, in `0.0..=1.0`.
    pub second_overlap: f64,
    /// Alignment quality: `best_overlap - second_overlap`.
    pub quality: f64,
}

/// Complete chaining-consistency signature for one period.
#[derive(Clone, Debug, PartialEq)]
pub struct ChainingSignature {
    /// Candidate period.
    pub period: usize,
    /// Additive alphabet size.
    pub alphabet_size: usize,
    /// Total symbols measured.
    pub total_symbols: usize,
    /// Number of symbols assigned to each period column.
    pub column_lengths: Vec<usize>,
    /// Mean of best shifted distribution overlaps across adjacent pairs.
    pub mean_best_overlap: f64,
    /// Mean pairwise alignment quality across adjacent pairs.
    pub mean_alignment_quality: f64,
    /// Raw around-cycle residual, `sum(shifts) mod alphabet_size`.
    pub cycle_residual: usize,
    /// Circular distance from residual to identity.
    pub cycle_residual_distance: usize,
    /// Linear closure factor in `0.0..=1.0`.
    pub cycle_closure: f64,
    /// Scalar signature combining quality and cycle closure.
    pub chain_score: f64,
    /// Pairwise alignments around the full period cycle.
    pub pair_alignments: Vec<PairAlignment>,
}

/// Monte-Carlo band for a floating-point statistic.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ScalarBand {
    /// Number of samples in the band.
    pub trials: usize,
    /// Smallest sampled value.
    pub min: f64,
    /// Mean sampled value.
    pub mean: f64,
    /// Lower pointwise 95% percentile edge.
    pub q025: f64,
    /// Sample median.
    pub median: f64,
    /// Upper pointwise 95% percentile edge.
    pub q975: f64,
    /// Largest sampled value.
    pub max: f64,
}

/// Monte-Carlo band for the integer cycle-residual distance.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ResidualBand {
    /// Number of samples in the band.
    pub trials: usize,
    /// Smallest sampled residual distance.
    pub min: usize,
    /// Lower pointwise 95% percentile edge.
    pub q025: usize,
    /// Sample median.
    pub median: f64,
    /// Upper pointwise 95% percentile edge.
    pub q975: usize,
    /// Largest sampled residual distance.
    pub max: usize,
}

/// Calibration bands for one generated fixture family.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CalibrationBands {
    /// Mean best shifted-overlap band.
    pub mean_best_overlap: ScalarBand,
    /// Mean alignment-quality band.
    pub mean_alignment_quality: ScalarBand,
    /// Around-cycle residual-distance band.
    pub cycle_residual_distance: ResidualBand,
    /// Composite chain-score band.
    pub chain_score: ScalarBand,
}

/// Where the real eye signature falls relative to the calibrated controls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainingClassification {
    /// Succeed/fail control bands overlap, so no calibrated comparison is valid.
    CalibrationOverlaps,
    /// The real score lands inside the known-fail control band.
    MatchesKnownFail,
    /// The real score lands inside the known-succeed control band.
    MatchesKnownSucceed,
    /// The real score lies between the separated fail and succeed bands.
    BetweenBands,
}

/// Real-vs-control row for one candidate period.
#[derive(Clone, Debug, PartialEq)]
pub struct ChainingPeriodReport {
    /// Candidate period.
    pub period: usize,
    /// Real eye signature under the accepted honeycomb order.
    pub real: ChainingSignature,
    /// Known-succeed Vigenere calibration bands.
    pub succeed: CalibrationBands,
    /// Known-fail independent substitution calibration bands.
    pub fail: CalibrationBands,
    /// Within-column shuffled known-fail calibration bands.
    pub shuffled_fail: CalibrationBands,
    /// Whether the fail and succeed score bands are separated.
    pub score_bands_separated: bool,
    /// Real-eye placement relative to the calibrated score bands.
    pub classification: ChainingClassification,
}

/// Complete Experiment 7B report for the accepted eye stream.
#[derive(Clone, Debug, PartialEq)]
pub struct ChainingReport {
    /// Configuration used for the run.
    pub config: ChainingConfig,
    /// Reading order used for the real stream.
    pub order: ReadingOrder,
    /// Per-message stream lengths in corpus order.
    pub message_lengths: Vec<(&'static str, usize)>,
    /// Total number of reading-layer symbols across messages.
    pub total_length: usize,
    /// Per-period rows.
    pub rows: Vec<ChainingPeriodReport>,
}

fn calibration_bands(samples: &[ChainingSignature]) -> CalibrationBands {
    CalibrationBands {
        mean_best_overlap: scalar_band(
            &samples
                .iter()
                .map(|signature| signature.mean_best_overlap)
                .collect::<Vec<_>>(),
        ),
        mean_alignment_quality: scalar_band(
            &samples
                .iter()
                .map(|signature| signature.mean_alignment_quality)
                .collect::<Vec<_>>(),
        ),
        cycle_residual_distance: residual_band(
            &samples
                .iter()
                .map(|signature| signature.cycle_residual_distance)
                .collect::<Vec<_>>(),
        ),
        chain_score: scalar_band(
            &samples
                .iter()
                .map(|signature| signature.chain_score)
                .collect::<Vec<_>>(),
        ),
    }
}

fn scalar_band(samples: &[f64]) -> ScalarBand {
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    ScalarBand {
        trials: samples.len(),
        min: sorted.first().copied().unwrap_or(0.0),
        mean: mean_f64(samples.iter().copied()),
        q025: quantile_f64(&sorted, 25, 1_000),
        median: median_f64(&sorted),
        q975: quantile_f64(&sorted, 975, 1_000),
        max: sorted.last().copied().unwrap_or(0.0),
    }
}

fn residual_band(samples: &[usize]) -> ResidualBand {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    ResidualBand {
        trials: samples.len(),
        min: sorted.first().copied().unwrap_or_default(),
        q025: quantile_usize(&sorted, 25, 1_000),
        median: median_usize(&sorted),
        q975: quantile_usize(&sorted, 975, 1_000),
        max: sorted.last().copied().unwrap_or_default(),
    }
}

fn classify_real_score(
    real_score: f64,
    succeed: &ScalarBand,
    fail: &ScalarBand,
    shuffled_fail: &ScalarBand,
    bands_separated: bool,
) -> ChainingClassification {
    if !bands_separated {
        return ChainingClassification::CalibrationOverlaps;
    }
    let fail_ceiling = fail.q975.max(shuffled_fail.q975);
    if real_score <= fail_ceiling {
        ChainingClassification::MatchesKnownFail
    } else if real_score >= succeed.q025 {
        ChainingClassification::MatchesKnownSucceed
    } else {
        ChainingClassification::BetweenBands
    }
}

fn mean_f64(values: impl IntoIterator<Item = f64>) -> f64 {
    let mut total = 0.0;
    let mut count = 0usize;
    for value in values {
        total += value;
        count += 1;
    }
    if count == 0 {
        0.0
    } else {
        total / count as f64
    }
}

fn quantile_f64(sorted: &[f64], numerator: usize, denominator: usize) -> f64 {
    sorted
        .get(scaled_quantile_index(sorted.len(), numerator, denominator))
        .copied()
        .unwrap_or(0.0)
}

fn quantile_usize(sorted: &[usize], numerator: usize, denominator: usize) -> usize {
    sorted
        .get(scaled_quantile_index(sorted.len(), numerator, denominator))
        .copied()
        .unwrap_or_default()
}

fn cycle_distance(residual: usize, alphabet_size: usize) -> usize {
    let wrapped = residual % alphabet_size;
    wrapped.min(alphabet_size - wrapped)
}

fn cycle_closure(residual_distance: usize, alphabet_size: usize) -> f64 {
    let max_distance = alphabet_size / 2;
    if max_distance == 0 {
        1.0
    } else {
        1.0 - residual_distance as f64 / max_distance as f64
    }
}

//! Cross-message orientation-frequency homogeneity experiment.
//!
//! This experiment works on the engine-fixed single-orientation storage layer:
//! decoded storage symbols `0..=4`, with row delimiter `5` stripped. It does
//! not use a honeycomb traversal, trigram grouping, symbol-to-letter mapping,
//! or language score. The statistic is therefore order-independent and avoids
//! reading-order circularity by construction.
//!
//! The null model pools all observed orientations, then repeatedly repartitions
//! that exact multiset into the true per-message lengths. This is the
//! length-matched conditional null for "all messages share one common
//! orientation distribution." A lower-tail result means the messages are more
//! homogeneous than random repartitions of the same pooled symbols; an
//! upper-tail result means they are more heterogeneous.

use std::fmt;

use crate::data::corpus;
use crate::nulls::null::F64Band;

mod compute;
mod report;
#[cfg(test)]
mod tests;

use compute::{
    engine_orientation_messages, flatten_digits, homogeneity_statistics, pooled_counts,
    positive_control, profiles_from_messages, repartition_null_comparisons, uniform_context,
    validate_config,
};
#[cfg(test)]
use compute::{g_test_homogeneity_statistic, pearson_homogeneity_statistic, repartition_table};

/// Number of engine/rendered orientation digits.
pub const ORIENTATION_BUCKETS: usize = 5;
/// Number of verified eye messages.
pub const MESSAGE_COUNT: usize = 9;
/// Degrees of freedom for the 9x5 homogeneity table.
pub const HOMOGENEITY_DEGREES_OF_FREEDOM: usize = (MESSAGE_COUNT - 1) * (ORIENTATION_BUCKETS - 1);
/// Degrees of freedom for the pooled five-bucket uniform context statistic.
pub const UNIFORM_DEGREES_OF_FREEDOM: usize = ORIENTATION_BUCKETS - 1;
/// Default deterministic seed for the repartition null.
pub const DEFAULT_SEED: u64 = 0x686f_6d6f_6f72_6931;
/// Default number of repartitions sampled per seed.
pub const DEFAULT_TRIALS_PER_SEED: usize = 1_000;
/// Default number of deterministic seeds sampled.
pub const DEFAULT_SEED_COUNT: usize = 5;

const POSITIVE_CONTROL_DOMINANT_IN_TEN: usize = 8;
const POSITIVE_CONTROL_PERIOD: usize = 10;
const SEED_STRIDE: u64 = 0x9e37_79b9_7f4a_7c15;

/// Configuration for the orientation homogeneity experiment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrientationHomogeneityConfig {
    /// First deterministic PRNG seed.
    pub seed: u64,
    /// Number of length-matched repartitions sampled for each seed.
    pub trials_per_seed: usize,
    /// Number of deterministic seed streams to run.
    pub seed_count: usize,
}

impl Default for OrientationHomogeneityConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_SEED,
            trials_per_seed: DEFAULT_TRIALS_PER_SEED,
            seed_count: DEFAULT_SEED_COUNT,
        }
    }
}

/// Error returned by the orientation homogeneity experiment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrientationHomogeneityError {
    /// At least one repartition trial per seed is required.
    ZeroTrials,
    /// At least one deterministic seed stream is required.
    ZeroSeedCount,
    /// The trial count overflowed the add-one empirical p-value denominator.
    TrialCountTooLarge,
    /// The verified corpus did not contain the expected number of messages.
    MessageCountMismatch {
        /// Expected message count.
        expected: usize,
        /// Observed message count.
        observed: usize,
    },
    /// Engine storage emitted a non-delimiter value outside `0..=4`.
    InvalidStorageSymbol {
        /// Message index in [`ENGINE_MESSAGES`](crate::data::generator::ENGINE_MESSAGES).
        message_index: usize,
        /// Invalid decoded storage symbol.
        symbol: i8,
    },
    /// Engine-derived orientation count disagreed with the verified corpus.
    EyeCountMismatch {
        /// Corpus message key.
        message_key: &'static str,
        /// Verified eye count.
        expected: usize,
        /// Engine-derived orientation count.
        observed: usize,
    },
    /// Per-message lengths did not sum to the pooled orientation count.
    LengthTotalMismatch {
        /// Sum of the per-message lengths.
        lengths_total: usize,
        /// Pooled orientation count.
        pooled_total: usize,
    },
    /// A bounded PRNG draw could not represent the requested upper bound.
    RandomBoundTooLarge {
        /// Requested exclusive upper bound.
        bound: usize,
    },
}

impl fmt::Display for OrientationHomogeneityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroTrials => write!(f, "at least one repartition trial per seed is required"),
            Self::ZeroSeedCount => write!(f, "at least one deterministic seed stream is required"),
            Self::TrialCountTooLarge => {
                write!(
                    f,
                    "trial count is too large for add-one p-value calibration"
                )
            }
            Self::MessageCountMismatch { expected, observed } => {
                write!(
                    f,
                    "expected {expected} verified messages, observed {observed}"
                )
            }
            Self::InvalidStorageSymbol {
                message_index,
                symbol,
            } => write!(
                f,
                "storage message {message_index} decoded invalid symbol {symbol}"
            ),
            Self::EyeCountMismatch {
                message_key,
                expected,
                observed,
            } => write!(
                f,
                "{message_key} engine-derived orientation count {observed} did not match verified eye count {expected}"
            ),
            Self::LengthTotalMismatch {
                lengths_total,
                pooled_total,
            } => write!(
                f,
                "per-message lengths sum to {lengths_total}, but pooled orientation count is {pooled_total}"
            ),
            Self::RandomBoundTooLarge { bound } => {
                write!(f, "random draw bound {bound} is too large")
            }
        }
    }
}

impl std::error::Error for OrientationHomogeneityError {}

impl From<crate::nulls::null::RandomBoundError> for OrientationHomogeneityError {
    fn from(error: crate::nulls::null::RandomBoundError) -> Self {
        Self::RandomBoundTooLarge { bound: error.bound }
    }
}

/// Per-message count and relative-frequency profile.
#[derive(Clone, Debug, PartialEq)]
pub struct OrientationProfile {
    /// Corpus message key.
    pub message_key: &'static str,
    /// Number of delimiter-stripped orientations in this message.
    pub length: usize,
    /// Counts for orientation digits `0..=4`.
    pub counts: [usize; ORIENTATION_BUCKETS],
    /// Relative frequencies for orientation digits `0..=4`.
    pub frequencies: [f64; ORIENTATION_BUCKETS],
}

/// Pearson and likelihood-ratio homogeneity statistics for one table.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HomogeneityStatistics {
    /// Pearson chi-square homogeneity statistic.
    pub pearson_chi_square: f64,
    /// Likelihood-ratio `G` statistic for homogeneity.
    pub g_test: f64,
    /// Fixed 9x5-table degrees of freedom for the verified corpus.
    pub degrees_of_freedom: usize,
    /// Asymptotic upper-tail p-value for the Pearson statistic.
    pub pearson_asymptotic_upper_tail_p: Option<f64>,
    /// Asymptotic upper-tail p-value for the `G` statistic.
    pub g_test_asymptotic_upper_tail_p: Option<f64>,
}

/// Pooled five-bucket uniformity context.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct UniformContext {
    /// Counts for pooled orientation digits `0..=4`.
    pub counts: [usize; ORIENTATION_BUCKETS],
    /// Pearson chi-square goodness-of-fit statistic versus uniform `0..=4`.
    pub chi_square_vs_uniform: f64,
    /// Degrees of freedom for the five-bucket uniform reference.
    pub degrees_of_freedom: usize,
    /// Asymptotic upper-tail p-value for the uniformity statistic.
    pub asymptotic_upper_tail_p: Option<f64>,
}

/// Monte-Carlo summary for one scalar statistic.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ScalarNullBand {
    /// Number of sampled repartitions.
    pub trials: usize,
    /// Mean sampled statistic.
    pub mean: f64,
    /// Smallest sampled statistic.
    pub min: f64,
    /// Lower pointwise 95% edge.
    pub q025: f64,
    /// Sample median.
    pub median: f64,
    /// Upper pointwise 95% edge.
    pub q975: f64,
    /// Largest sampled statistic.
    pub max: f64,
}

impl From<F64Band> for ScalarNullBand {
    fn from(band: F64Band) -> Self {
        Self {
            trials: band.trials,
            mean: band.mean,
            min: band.min,
            q025: band.q025,
            median: band.median,
            q975: band.q975,
            max: band.max,
        }
    }
}

/// Empirical placement of the observed statistic in a repartition null.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HomogeneityNullComparison {
    /// Observed statistic.
    pub observed: f64,
    /// Repartition-null distribution summary.
    pub null: ScalarNullBand,
    /// Number of repartitions with statistic less than or equal to observed.
    pub lower_tail_count: usize,
    /// Number of repartitions with statistic greater than or equal to observed.
    pub upper_tail_count: usize,
    /// Add-one lower-tail empirical p-value.
    pub lower_tail_add_one_p: f64,
    /// Add-one upper-tail empirical p-value.
    pub upper_tail_add_one_p: f64,
    /// Add-one two-sided empirical p-value, doubled from the smaller tail.
    pub two_sided_add_one_p: f64,
}

/// Synthetic deliberately heterogeneous positive-control result.
#[derive(Clone, Debug, PartialEq)]
pub struct HomogeneityPositiveControl {
    /// Per-message lengths copied from the real corpus.
    pub message_lengths: Vec<usize>,
    /// Pearson statistic placement for the heterogeneous fixture.
    pub pearson: HomogeneityNullComparison,
    /// `G` statistic placement for the heterogeneous fixture.
    pub g_test: HomogeneityNullComparison,
}

/// Complete orientation homogeneity report.
#[derive(Clone, Debug, PartialEq)]
pub struct OrientationHomogeneityReport {
    /// Configuration used for the real repartition null and positive control.
    pub config: OrientationHomogeneityConfig,
    /// Per-message orientation profiles in corpus order.
    pub profiles: Vec<OrientationProfile>,
    /// Total delimiter-stripped orientations across all messages.
    pub total_orientations: usize,
    /// Sum of verified corpus eye counts, used as an integrity anchor.
    pub total_eye_count: usize,
    /// Pooled five-bucket uniformity context.
    pub pooled_uniform: UniformContext,
    /// Observed homogeneity statistics.
    pub homogeneity: HomogeneityStatistics,
    /// Repartition-null placement for Pearson chi-square.
    pub pearson_null: HomogeneityNullComparison,
    /// Repartition-null placement for the `G` statistic.
    pub g_test_null: HomogeneityNullComparison,
    /// Deliberately heterogeneous positive-control result.
    pub positive_control: HomogeneityPositiveControl,
}

/// Runs the cross-message orientation-frequency homogeneity experiment.
///
/// # Errors
/// Returns [`OrientationHomogeneityError`] if configuration is invalid, engine
/// storage symbols are not the verified orientation/delimiter alphabet, or the
/// engine-derived eye counts fail to match the verified corpus anchors.
pub fn run_orientation_homogeneity(
    config: OrientationHomogeneityConfig,
) -> Result<OrientationHomogeneityReport, OrientationHomogeneityError> {
    validate_config(config)?;

    let messages = engine_orientation_messages()?;
    let profiles = profiles_from_messages(&messages);
    let table = messages
        .iter()
        .map(|message| message.counts)
        .collect::<Vec<_>>();
    let pooled = flatten_digits(&messages);
    let lengths = messages
        .iter()
        .map(|message| message.digits.len())
        .collect::<Vec<_>>();
    let total_orientations = pooled.len();
    let total_eye_count = corpus::messages()
        .iter()
        .map(|message| message.eye_count)
        .sum();
    let pooled_counts = pooled_counts(&table);
    let pooled_uniform = uniform_context(pooled_counts);
    let homogeneity = homogeneity_statistics(&table);
    let (pearson_null, g_test_null) =
        repartition_null_comparisons(config, &pooled, &lengths, &homogeneity)?;
    let positive_control = positive_control(config, &lengths)?;

    Ok(OrientationHomogeneityReport {
        config,
        profiles,
        total_orientations,
        total_eye_count,
        pooled_uniform,
        homogeneity,
        pearson_null,
        g_test_null,
        positive_control,
    })
}

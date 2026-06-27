//! Experiment 5A periodicity and autocorrelation battery.
//!
//! The battery runs over the accepted honeycomb reading-layer stream
//! (`standard36-u012-d012`) and compares apparent period/lag peaks with
//! deterministic same-shape uniform-random streams over the `0..=82`
//! reading-layer alphabet.
//!
//! Message boundaries are preserved throughout. Pooled period columns reset
//! the column counter at the start of each message, autocorrelation never forms
//! cross-message lag pairs, and Kasiski distances are aggregated only from
//! repeats found within individual messages.

use std::fmt;

use crate::analysis::orders::{
    self, GlyphGrid, GridError, ReadingOrder, read_corpus_message_values,
};
use crate::nulls::null::F64Band;

mod compute;
mod report;
#[cfg(test)]
mod tests;

#[cfg(test)]
use compute::kasiski_report_for_messages;
pub use compute::{autocorrelation_values, normalized_ioc_by_period_values};
use compute::{report_from_message_values, validate_config};

/// Default maximum candidate Friedman period.
pub const DEFAULT_MAX_PERIOD: usize = 32;
/// Default maximum autocorrelation lag.
pub const DEFAULT_MAX_LAG: usize = 64;
/// Default minimum Kasiski n-gram length.
pub const DEFAULT_MIN_NGRAM: usize = 2;
/// Default maximum Kasiski n-gram length.
pub const DEFAULT_MAX_NGRAM: usize = 5;
/// Default deterministic Monte-Carlo seed.
pub const DEFAULT_SEED: u64 = 0x6579_652d_7065_7235;
/// Default Monte-Carlo trial count.
pub const DEFAULT_TRIALS: usize = 1_000;
/// Accepted reading-layer alphabet size for the honeycomb winner.
pub const DEFAULT_ALPHABET_SIZE: usize = orders::READING_LAYER_ALPHABET_SIZE;

/// Error returned by the periodicity battery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeriodicityError {
    /// The verified corpus could not be reconstructed as grids.
    Grid(GridError),
    /// At least one Monte-Carlo trial is required for a null band.
    ZeroTrials,
    /// Candidate period range was empty.
    ZeroMaxPeriod,
    /// Candidate lag range was empty.
    ZeroMaxLag,
    /// Kasiski n-gram range was invalid.
    InvalidNgramRange {
        /// Requested minimum n-gram length.
        min: usize,
        /// Requested maximum n-gram length.
        max: usize,
    },
    /// The null alphabet must fit in the base-5 trigram value type.
    InvalidAlphabetSize {
        /// Requested alphabet size.
        alphabet_size: usize,
    },
}

impl fmt::Display for PeriodicityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Grid(grid_error) => write!(f, "grid/order error: {grid_error:?}"),
            Self::ZeroTrials => write!(f, "at least one Monte-Carlo trial is required"),
            Self::ZeroMaxPeriod => write!(f, "max period must be at least 1"),
            Self::ZeroMaxLag => write!(f, "max lag must be at least 1"),
            Self::InvalidNgramRange { min, max } => {
                write!(f, "invalid n-gram range {min}..={max}")
            }
            Self::InvalidAlphabetSize { alphabet_size } => {
                write!(
                    f,
                    "invalid null alphabet size {alphabet_size}; expected 1..=125"
                )
            }
        }
    }
}

impl std::error::Error for PeriodicityError {}

impl From<GridError> for PeriodicityError {
    fn from(value: GridError) -> Self {
        Self::Grid(value)
    }
}

/// Configuration for Experiment 5A.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeriodicityConfig {
    /// Explicit deterministic PRNG seed for the same-shape random null.
    pub seed: u64,
    /// Number of same-shape random streams to sample.
    pub trials: usize,
    /// Largest candidate Friedman period to test, inclusive.
    pub max_period: usize,
    /// Largest autocorrelation lag to test, inclusive.
    pub max_lag: usize,
    /// Smallest Kasiski repeated n-gram length.
    pub min_ngram: usize,
    /// Largest Kasiski repeated n-gram length.
    pub max_ngram: usize,
    /// Uniform null alphabet size. The accepted stream uses `83`.
    pub alphabet_size: usize,
}

impl Default for PeriodicityConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_SEED,
            trials: DEFAULT_TRIALS,
            max_period: DEFAULT_MAX_PERIOD,
            max_lag: DEFAULT_MAX_LAG,
            min_ngram: DEFAULT_MIN_NGRAM,
            max_ngram: DEFAULT_MAX_NGRAM,
            alphabet_size: DEFAULT_ALPHABET_SIZE,
        }
    }
}

/// Monte-Carlo band for one statistic.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NullBand {
    /// Number of same-shape random streams sampled.
    pub trials: usize,
    /// Smallest sampled value.
    pub min: f64,
    /// Lower pointwise 95% band edge.
    pub q025: f64,
    /// Sample median.
    pub median: f64,
    /// Upper pointwise 95% band edge.
    pub q975: f64,
    /// Largest sampled value.
    pub max: f64,
}

impl From<F64Band> for NullBand {
    fn from(band: F64Band) -> Self {
        // `NullBand` carries no `mean` field; the rest map directly.
        Self {
            trials: band.trials,
            min: band.min,
            q025: band.q025,
            median: band.median,
            q975: band.q975,
            max: band.max,
        }
    }
}

/// One IoC-by-period row.
#[derive(Clone, Debug, PartialEq)]
pub struct PeriodIocRow {
    /// Candidate period.
    pub period: usize,
    /// Arithmetic mean of per-column `IoC` probabilities.
    pub mean_ioc: f64,
    /// `mean_ioc * alphabet_size`; a uniform stream is expected near `1.0`.
    pub normalized_ioc: f64,
    /// Pointwise null band for `normalized_ioc`.
    pub null_band: NullBand,
    /// Whether the row is above its pointwise null band.
    pub above_pointwise_band: bool,
    /// Whether the row is above the sampled report-wide null envelope.
    pub above_null_envelope: bool,
}

/// One autocorrelation lag row.
#[derive(Clone, Debug, PartialEq)]
pub struct AutocorrelationRow {
    /// Tested lag.
    pub lag: usize,
    /// Count of equality pairs `symbol[i] == symbol[i + lag]`.
    pub matches: usize,
    /// Count of comparable within-message pairs at this lag.
    pub comparisons: usize,
    /// Equality-pair rate.
    pub rate: f64,
    /// `rate * alphabet_size`; a uniform stream is expected near `1.0`.
    pub normalized_rate: f64,
    /// Pointwise null band for `rate`.
    pub null_band: NullBand,
    /// Whether the row is above its pointwise null band.
    pub above_pointwise_band: bool,
    /// Whether the row is above the sampled report-wide null envelope.
    pub above_null_envelope: bool,
}

/// Kasiski repeated-segment summary for one n-gram size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KasiskiReport {
    /// N-gram length in reading-layer symbols.
    pub n: usize,
    /// Number of distinct n-grams seen more than once.
    pub repeated_ngram_kinds: usize,
    /// Total occurrences belonging to repeated n-gram kinds.
    pub repeated_occurrences: usize,
    /// Number of pairwise within-message distances between repeated n-grams.
    pub distance_count: usize,
    /// Greatest common divisor across all collected distances, or zero when
    /// no distances were collected.
    pub all_distance_gcd: usize,
    /// Most common exact repeated-segment distances, sorted by count then distance.
    pub top_distances: Vec<(usize, usize)>,
    /// GCDs computed per repeated n-gram kind from its own distances.
    pub ngram_gcd_histogram: Vec<(usize, usize)>,
    /// Candidate factors `2..=max_period` and their divisible-distance counts.
    pub factor_counts: Vec<(usize, usize)>,
}

/// Periodicity battery for one message.
#[derive(Clone, Debug, PartialEq)]
pub struct MessagePeriodicityReport {
    /// Message key, such as `east1`.
    pub message_key: &'static str,
    /// Number of reading-layer symbols in this message.
    pub length: usize,
    /// Sampled report-wide null envelope for the IoC-by-period profile.
    pub period_null_envelope_max: f64,
    /// Sampled report-wide null envelope for the autocorrelation profile.
    pub autocorrelation_null_envelope_max: f64,
    /// IoC-by-period profile.
    pub ioc_by_period: Vec<PeriodIocRow>,
    /// Autocorrelation lag profile.
    pub autocorrelation: Vec<AutocorrelationRow>,
    /// Kasiski repeated-segment summaries.
    pub kasiski: Vec<KasiskiReport>,
}

/// Experiment 5A report for the accepted reading stream.
#[derive(Clone, Debug, PartialEq)]
pub struct PeriodicityReport {
    /// Configuration used for the run.
    pub config: PeriodicityConfig,
    /// Reading order used for the real stream.
    pub order: ReadingOrder,
    /// Per-message stream lengths.
    pub message_lengths: Vec<(&'static str, usize)>,
    /// Total pooled length.
    pub pooled_length: usize,
    /// Sampled report-wide null envelope for the IoC-by-period battery.
    pub period_null_envelope_max: f64,
    /// Sampled report-wide null envelope for the autocorrelation battery.
    pub autocorrelation_null_envelope_max: f64,
    /// Pooled IoC-by-period profile.
    pub pooled_ioc_by_period: Vec<PeriodIocRow>,
    /// Pooled autocorrelation lag profile.
    pub pooled_autocorrelation: Vec<AutocorrelationRow>,
    /// Pooled Kasiski summaries, aggregating within-message distances only.
    pub pooled_kasiski: Vec<KasiskiReport>,
    /// Per-message reports.
    pub messages: Vec<MessagePeriodicityReport>,
}

/// Returns the accepted honeycomb reading order for the real stream.
#[must_use]
pub const fn accepted_honeycomb_order() -> ReadingOrder {
    orders::accepted_honeycomb_order()
}

/// Runs Experiment 5A on the verified corpus.
///
/// # Errors
/// Returns [`PeriodicityError`] when the corpus grids cannot be reconstructed
/// or the configuration is invalid.
pub fn run_periodicity(config: PeriodicityConfig) -> Result<PeriodicityReport, PeriodicityError> {
    validate_config(config)?;
    let grids = orders::corpus_grids()?;
    let keys: Vec<&'static str> = grids.iter().map(GlyphGrid::message_key).collect();
    let order = accepted_honeycomb_order();
    let message_values = read_corpus_message_values(&grids, order)?;
    report_from_message_values(config, order, &keys, &message_values)
}

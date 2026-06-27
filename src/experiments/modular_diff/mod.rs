//! Modular finite-difference family fingerprint experiment.
//!
//! This module transforms the accepted honeycomb trigram stream into
//! per-message modular finite differences, then compares those transformed
//! streams with generated structural controls. The transform is
//! mapping-independent: adding a single global offset to every symbol cancels
//! out in `d[i] = (v[i] - v[i - 1]) mod N`.
//!
//! Message boundaries are always hard resets. No raw value or differenced
//! value from one eye message is paired with a value from another message.

use std::fmt;

use crate::analysis::orders::{
    self, GlyphGrid, GridError, ReadingOrder, read_corpus_message_values,
};
use crate::ciphers;
use crate::core::trigram::TrigramValue;
use crate::nulls::null::F64Band;

mod calibration;
mod diff;
mod report;
#[cfg(test)]
mod tests;

pub use diff::modular_difference_messages;
use diff::{report_from_message_values, validate_config};

/// Default deterministic seed for fixture and shuffle calibration.
pub const DEFAULT_SEED: u64 = 0x6d6f_6464_6966_6631;
/// Default number of generated fixtures and shuffles per differencing order.
pub const DEFAULT_TRIALS: usize = 256;
/// Default largest candidate period for differenced-stream `IoC` profiles.
pub const DEFAULT_MAX_PERIOD: usize = 16;
/// Default largest lag for differenced-stream autocorrelation profiles.
pub const DEFAULT_MAX_LAG: usize = 32;
/// Headline modulus: the accepted honeycomb stream uses values `0..=82`.
pub const PRIMARY_MODULUS: usize = orders::READING_LAYER_ALPHABET_SIZE;
/// Secondary modulus: the full base-5 trigram reading layer uses `0..=124`.
pub const SECONDARY_MODULUS: usize = 125;
/// Largest modular finite-difference order reported.
pub const MAX_DIFFERENCE_ORDER: usize = 3;

const WHEEL_STEP: usize = 17;
const VIGENERE_SHIFTS: [usize; 7] = [3, 41, 12, 64, 5, 28, 77];
const CONTROL_FAMILIES: [ControlFamily; 4] = [
    ControlFamily::IncrementingWheel,
    ControlFamily::PeriodicVigenere,
    ControlFamily::DeckS83Keystream,
    ControlFamily::FlatRandom,
];

/// Configuration for the modular-difference fingerprint experiment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModularDiffConfig {
    /// Explicit deterministic PRNG seed.
    pub seed: u64,
    /// Number of generated fixtures and shuffles sampled per row.
    pub trials: usize,
    /// Largest candidate period tested by the differenced-stream profile.
    pub max_period: usize,
    /// Largest lag tested by the differenced-stream autocorrelation profile.
    pub max_lag: usize,
}

impl Default for ModularDiffConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_SEED,
            trials: DEFAULT_TRIALS,
            max_period: DEFAULT_MAX_PERIOD,
            max_lag: DEFAULT_MAX_LAG,
        }
    }
}

/// Error returned by the modular-difference experiment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModularDiffError {
    /// The verified corpus could not be reconstructed or read with the order.
    Grid(GridError),
    /// At least one generated fixture and shuffle trial is required.
    ZeroTrials,
    /// Candidate period range was empty.
    ZeroMaxPeriod,
    /// Candidate lag range was empty.
    ZeroMaxLag,
    /// A modular alphabet must fit in the base-5 trigram value type.
    InvalidModulus {
        /// Requested modulus.
        modulus: usize,
    },
    /// A stream value was outside the modulus before differencing.
    ValueOutsideModulus {
        /// Offending stream value.
        value: u8,
        /// Configured modulus.
        modulus: usize,
    },
    /// A generated cipher fixture could not be constructed or translated.
    Cipher(ciphers::CipherError),
    /// A random draw bound did not fit the PRNG helper.
    RandomBoundTooLarge {
        /// Requested exclusive upper bound.
        bound: usize,
    },
}

impl From<GridError> for ModularDiffError {
    fn from(value: GridError) -> Self {
        Self::Grid(value)
    }
}

impl From<ciphers::CipherError> for ModularDiffError {
    fn from(value: ciphers::CipherError) -> Self {
        Self::Cipher(value)
    }
}

impl From<crate::nulls::null::RandomBoundError> for ModularDiffError {
    fn from(error: crate::nulls::null::RandomBoundError) -> Self {
        Self::RandomBoundTooLarge { bound: error.bound }
    }
}

impl fmt::Display for ModularDiffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Grid(grid_error) => write!(f, "grid/order error: {grid_error:?}"),
            Self::ZeroTrials => {
                write!(
                    f,
                    "at least one generated fixture and shuffle trial is required"
                )
            }
            Self::ZeroMaxPeriod => write!(f, "max period must be at least 1"),
            Self::ZeroMaxLag => write!(f, "max lag must be at least 1"),
            Self::InvalidModulus { modulus } => {
                write!(f, "invalid modulus {modulus}; expected 1..=125")
            }
            Self::ValueOutsideModulus { value, modulus } => {
                write!(
                    f,
                    "stream value {value} is outside configured modulus {modulus}"
                )
            }
            Self::Cipher(cipher_error) => {
                write!(f, "generated fixture cipher error: {cipher_error}")
            }
            Self::RandomBoundTooLarge { bound } => {
                write!(f, "random draw bound {bound} is too large")
            }
        }
    }
}

impl std::error::Error for ModularDiffError {}

/// Generated fixture family used for calibration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlFamily {
    /// Additive-progressive wheel over an all-zero plaintext.
    IncrementingWheel,
    /// Additive periodic Vigenere over a non-uniform source.
    PeriodicVigenere,
    /// Generalized `S_83` deck-keystream cipher over a non-uniform source.
    DeckS83Keystream,
    /// Independent uniform random values over the 83-symbol alphabet.
    FlatRandom,
}

impl ControlFamily {
    /// Human-readable family label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::IncrementingWheel => "wheel",
            Self::PeriodicVigenere => "Vigenere",
            Self::DeckS83Keystream => "deck/S83",
            Self::FlatRandom => "flat",
        }
    }

    /// Known key or generator description for the control fixture.
    #[must_use]
    pub const fn key_summary(self) -> &'static str {
        match self {
            Self::IncrementingWheel => "step=17, random per-message starts",
            Self::PeriodicVigenere => "period=7 shifts=3,41,12,64,5,28,77",
            Self::DeckS83Keystream => "SplitMix64-shuffled S83 deck, controls 81/82",
            Self::FlatRandom => "SplitMix64 iid uniform values",
        }
    }
}

/// Whether two control bands are separated or overlap for the tested scalar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BandSeparation {
    /// The compared bands are ordered without overlap.
    Separated,
    /// The compared bands overlap or a required control band was missing.
    Overlapping,
}

/// Calibration separation checks for one differencing order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlSeparation {
    /// Whether the wheel top-difference-rate band clears every non-wheel band.
    pub wheel_top_rate: BandSeparation,
    /// Whether the Vigenere period-excess band clears the structureless controls.
    pub vigenere_period_excess: BandSeparation,
    /// Whether the deck and flat structure-score bands overlap as one flat band.
    pub deck_flat_structure: BandSeparation,
}

impl ControlSeparation {
    /// Returns whether the positive controls separate enough to classify eyes.
    #[must_use]
    pub const fn is_calibrated(self) -> bool {
        matches!(self.wheel_top_rate, BandSeparation::Separated)
            && matches!(self.vigenere_period_excess, BandSeparation::Separated)
    }
}

/// Eye placement relative to the calibrated fixture bands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FamilyPlacement {
    /// Positive controls did not separate enough for a calibrated placement.
    Uncalibrated,
    /// The eye stream matches the dominant-constant-difference wheel signature.
    WheelLike,
    /// The eye stream matches the periodic Vigenere difference signature.
    VigenereLike,
    /// The eye stream lands in the deck/flat/shuffle structureless band.
    StructurelessLike,
    /// The eye stream is between separated bands.
    BetweenBands,
}

impl FamilyPlacement {
    /// Human-readable placement label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Uncalibrated => "uncalibrated",
            Self::WheelLike => "wheel-like",
            Self::VigenereLike => "Vigenere-like",
            Self::StructurelessLike => "structureless",
            Self::BetweenBands => "between",
        }
    }
}

/// Monte-Carlo band for one scalar fingerprint statistic.
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

impl From<F64Band> for ScalarBand {
    fn from(band: F64Band) -> Self {
        Self {
            trials: band.trials,
            min: band.min,
            mean: band.mean,
            q025: band.q025,
            median: band.median,
            q975: band.q975,
            max: band.max,
        }
    }
}

/// Calibration bands for the scalar fingerprint used by classification.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FingerprintBand {
    /// Message-weighted differenced-stream `IoC` probability band.
    pub ioc: ScalarBand,
    /// `IoC(difference) - IoC(raw)` band.
    pub delta_ioc: ScalarBand,
    /// Largest single difference value's occurrence-rate band.
    pub top_rate: ScalarBand,
    /// Top-rate divided by the uniform expectation band.
    pub top_over_uniform: ScalarBand,
    /// Best period-column normalized `IoC` excess over pooled normalized `IoC`.
    pub period_excess: ScalarBand,
    /// Strongest normalized lag-autocorrelation rate band.
    pub best_lag_normalized_rate: ScalarBand,
    /// Maximum of the top, `IoC`, period, and lag normalized structural scores.
    pub structure_score: ScalarBand,
}

/// Calibration band for one generated fixture family.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ControlFamilyBand {
    /// Fixture family.
    pub family: ControlFamily,
    /// Known key or generator summary for this family.
    pub key_summary: &'static str,
    /// Sampled scalar fingerprint band.
    pub fingerprint: FingerprintBand,
}

/// Control calibration for one modular differencing order.
#[derive(Clone, Debug, PartialEq)]
pub struct ControlOrderReport {
    /// Modular differencing order, where `1` is first difference.
    pub difference_order: usize,
    /// One band per generated fixture family.
    pub family_bands: Vec<ControlFamilyBand>,
    /// Separation checks used before classifying the eye stream.
    pub separation: ControlSeparation,
    /// Eye placement for this differencing order.
    pub eye_placement: FamilyPlacement,
}

/// Most represented single modular difference value.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ValuePeak {
    /// Difference value.
    pub value: u8,
    /// Number of occurrences.
    pub count: usize,
    /// Occurrence rate among all differenced symbols.
    pub rate: f64,
    /// Rate divided by the uniform expectation `1 / modulus`.
    pub over_uniform: f64,
}

/// One differenced-stream `IoC`-by-period row.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PeriodIoc {
    /// Candidate period.
    pub period: usize,
    /// Mean per-column `IoC` probability.
    pub mean_ioc: f64,
    /// `mean_ioc * modulus`; a uniform stream is expected near `1.0`.
    pub normalized_ioc: f64,
}

/// One differenced-stream autocorrelation row.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LagAutocorrelation {
    /// Tested lag.
    pub lag: usize,
    /// Count of exact equality pairs at this lag.
    pub matches: usize,
    /// Count of comparable within-message pairs at this lag.
    pub comparisons: usize,
    /// Equality-pair rate.
    pub rate: f64,
    /// `rate * modulus`; a uniform stream is expected near `1.0`.
    pub normalized_rate: f64,
}

/// Statistics for one differenced stream.
#[derive(Clone, Debug, PartialEq)]
pub struct DifferenceStats {
    /// Modulus used by the finite-difference transform.
    pub modulus: usize,
    /// Modular differencing order, where `1` is first difference.
    pub difference_order: usize,
    /// Total differenced symbols across messages.
    pub length: usize,
    /// Message-weighted raw-stream `IoC` before differencing.
    pub raw_ioc: f64,
    /// Message-weighted differenced-stream `IoC`.
    pub ioc: f64,
    /// `ioc * modulus`; a uniform stream is expected near `1.0`.
    pub normalized_ioc: f64,
    /// `ioc - raw_ioc`.
    pub delta_ioc: f64,
    /// Pearson chi-square statistic against uniform support on the modulus.
    pub chi_square_uniform: f64,
    /// Upper-tail p-value for [`Self::chi_square_uniform`].
    pub chi_square_upper_tail_p_value: Option<f64>,
    /// Count of distinct difference values observed.
    pub distinct_support_size: usize,
    /// Strongest single constant-difference value.
    pub top_difference: ValuePeak,
    /// `IoC`-by-period profile.
    pub period_ioc: Vec<PeriodIoc>,
    /// Best period row by normalized `IoC`.
    pub best_period_ioc: Option<PeriodIoc>,
    /// Best period-column normalized `IoC` excess over pooled normalized `IoC`.
    pub period_excess: f64,
    /// Lag-autocorrelation profile.
    pub autocorrelation: Vec<LagAutocorrelation>,
    /// Best lag row by normalized equality rate.
    pub best_autocorrelation: Option<LagAutocorrelation>,
    /// Maximum of top, `IoC`, period, and lag normalized structural scores.
    pub structure_score: f64,
}

/// Report row for one differencing order under one modulus.
#[derive(Clone, Debug, PartialEq)]
pub struct DifferenceOrderReport {
    /// Modular differencing order, where `1` is first difference.
    pub difference_order: usize,
    /// Eye-stream statistics.
    pub stats: DifferenceStats,
    /// Within-message multiset-preserving shuffle baseline for the same row.
    pub shuffle_baseline: FingerprintBand,
}

/// Report for one modulus view.
#[derive(Clone, Debug, PartialEq)]
pub struct ModulusReport {
    /// Modulus used by every differencing row in this view.
    pub modulus: usize,
    /// Whether this is the headline 83-symbol view.
    pub headline: bool,
    /// Message-weighted raw-stream `IoC` before differencing.
    pub raw_ioc: f64,
    /// Differencing rows for `k = 1..=3`.
    pub differences: Vec<DifferenceOrderReport>,
}

/// Complete modular-difference family fingerprint report.
#[derive(Clone, Debug, PartialEq)]
pub struct ModularDiffReport {
    /// Configuration used for the run.
    pub config: ModularDiffConfig,
    /// Reading order used for the real stream.
    pub order: ReadingOrder,
    /// Per-message stream lengths in corpus order.
    pub message_lengths: Vec<(&'static str, usize)>,
    /// Total number of raw reading-layer symbols across messages.
    pub total_length: usize,
    /// Primary `mod 83` differencing view.
    pub primary: ModulusReport,
    /// Secondary `mod 125` differencing view.
    pub secondary: ModulusReport,
    /// Generated-fixture calibration for the primary modulus.
    pub controls: Vec<ControlOrderReport>,
    /// Headline placement for first differences under `mod 83`.
    pub headline_placement: FamilyPlacement,
}

/// Runs the modular-difference family fingerprint on the verified corpus.
///
/// # Errors
/// Returns [`ModularDiffError`] when the corpus cannot be reconstructed or the
/// configuration is invalid.
pub fn run_modular_diff(config: ModularDiffConfig) -> Result<ModularDiffReport, ModularDiffError> {
    validate_config(config)?;
    let grids = orders::corpus_grids()?;
    let keys: Vec<&'static str> = grids.iter().map(GlyphGrid::message_key).collect();
    let order = orders::accepted_honeycomb_order();
    let message_values = read_corpus_message_values(&grids, order)?;
    report_from_message_values(config, order, &keys, &message_values)
}

fn trigram_from_usize(value: usize, modulus: usize) -> Result<TrigramValue, ModularDiffError> {
    let raw = u8::try_from(value).map_err(|_error| ModularDiffError::InvalidModulus { modulus })?;
    TrigramValue::new(raw).map_err(|_raw| ModularDiffError::InvalidModulus { modulus })
}

fn max_f64(values: impl IntoIterator<Item = f64>) -> f64 {
    values.into_iter().fold(0.0, f64::max)
}

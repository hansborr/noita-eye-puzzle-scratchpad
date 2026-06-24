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

use crate::analysis;
use crate::ciphers::{
    self, DeckCipherKey, IncrementingWheelKey, VigenereKey, deck_cipher_encrypt,
    incrementing_wheel_encrypt, vigenere_encrypt,
};
use crate::glyph::Glyph;
use crate::null::SplitMix64;
use crate::orders::{
    self, GlyphGrid, GridError, ReadingOrder, count_message_lag_comparisons,
    count_message_lag_matches, glyph_messages_from_values, read_corpus_message_values,
};
use crate::periodicity;
use crate::trigram::TrigramValue;

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

/// Computes a per-message modular finite-difference transform.
///
/// `difference_order == 0` returns the input stream after validating that every
/// value is inside `0..modulus`. Higher orders repeatedly apply
/// `(current[i] - current[i - 1]) mod modulus` inside each message. No pair is
/// formed across message boundaries.
///
/// # Errors
/// Returns [`ModularDiffError`] if `modulus` is not representable by
/// [`TrigramValue`] or if any source value is outside the modulus.
pub fn modular_difference_messages(
    message_values: &[Vec<TrigramValue>],
    difference_order: usize,
    modulus: usize,
) -> Result<Vec<Vec<TrigramValue>>, ModularDiffError> {
    validate_modulus(modulus)?;
    validate_values_inside_modulus(message_values, modulus)?;

    let mut current = message_values.to_vec();
    for _order in 0..difference_order {
        current = first_difference_messages(&current, modulus)?;
    }
    Ok(current)
}

fn report_from_message_values(
    config: ModularDiffConfig,
    order: ReadingOrder,
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
) -> Result<ModularDiffReport, ModularDiffError> {
    validate_config(config)?;
    let lengths = message_values.iter().map(Vec::len).collect::<Vec<_>>();
    let total_length = lengths.iter().sum();
    let primary = build_modulus_report(config, message_values, PRIMARY_MODULUS, true)?;
    let secondary = build_modulus_report(config, message_values, SECONDARY_MODULUS, false)?;
    let controls = calibrate_controls(config, &lengths, &primary.differences)?;
    let headline_placement = controls
        .iter()
        .find(|report| report.difference_order == 1)
        .map_or(FamilyPlacement::Uncalibrated, |report| report.eye_placement);

    Ok(ModularDiffReport {
        config,
        order,
        message_lengths: keys.iter().copied().zip(lengths).collect(),
        total_length,
        primary,
        secondary,
        controls,
        headline_placement,
    })
}

fn validate_config(config: ModularDiffConfig) -> Result<(), ModularDiffError> {
    if config.trials == 0 {
        return Err(ModularDiffError::ZeroTrials);
    }
    if config.max_period == 0 {
        return Err(ModularDiffError::ZeroMaxPeriod);
    }
    if config.max_lag == 0 {
        return Err(ModularDiffError::ZeroMaxLag);
    }
    Ok(())
}

fn validate_modulus(modulus: usize) -> Result<(), ModularDiffError> {
    if modulus == 0 || modulus > SECONDARY_MODULUS {
        return Err(ModularDiffError::InvalidModulus { modulus });
    }
    Ok(())
}

fn validate_values_inside_modulus(
    message_values: &[Vec<TrigramValue>],
    modulus: usize,
) -> Result<(), ModularDiffError> {
    for values in message_values {
        for value in values {
            if usize::from(value.get()) >= modulus {
                return Err(ModularDiffError::ValueOutsideModulus {
                    value: value.get(),
                    modulus,
                });
            }
        }
    }
    Ok(())
}

fn build_modulus_report(
    config: ModularDiffConfig,
    message_values: &[Vec<TrigramValue>],
    modulus: usize,
    headline: bool,
) -> Result<ModulusReport, ModularDiffError> {
    validate_values_inside_modulus(message_values, modulus)?;
    let raw_ioc = message_weighted_ioc_values(message_values);
    let mut rows = Vec::new();
    for difference_order in 1..=MAX_DIFFERENCE_ORDER {
        let diff_values = modular_difference_messages(message_values, difference_order, modulus)?;
        let stats = summarize_difference_stream(
            &diff_values,
            raw_ioc,
            modulus,
            difference_order,
            config.max_period,
            config.max_lag,
        )?;
        let shuffle_baseline =
            shuffle_baseline(config, message_values, raw_ioc, modulus, difference_order)?;
        rows.push(DifferenceOrderReport {
            difference_order,
            stats,
            shuffle_baseline,
        });
    }
    Ok(ModulusReport {
        modulus,
        headline,
        raw_ioc,
        differences: rows,
    })
}

fn first_difference_messages(
    message_values: &[Vec<TrigramValue>],
    modulus: usize,
) -> Result<Vec<Vec<TrigramValue>>, ModularDiffError> {
    let mut differenced = Vec::with_capacity(message_values.len());
    for values in message_values {
        let mut message = Vec::with_capacity(values.len().saturating_sub(1));
        for pair in values.windows(2) {
            let Some(previous) = pair.first().copied() else {
                continue;
            };
            let Some(current) = pair.get(1).copied() else {
                continue;
            };
            let raw =
                (usize::from(current.get()) + modulus - usize::from(previous.get())) % modulus;
            message.push(trigram_from_usize(raw, modulus)?);
        }
        differenced.push(message);
    }
    Ok(differenced)
}

fn summarize_difference_stream(
    message_values: &[Vec<TrigramValue>],
    raw_ioc: f64,
    modulus: usize,
    difference_order: usize,
    max_period: usize,
    max_lag: usize,
) -> Result<DifferenceStats, ModularDiffError> {
    validate_values_inside_modulus(message_values, modulus)?;
    let counts = counts_for_messages(message_values, modulus)?;
    let length = counts.iter().sum();
    let distinct_support_size = counts.iter().filter(|count| **count > 0).count();
    let ioc = message_weighted_ioc_values(message_values);
    let normalized_ioc = ioc * modulus as f64;
    let chi_square_uniform = analysis::chi_square_goodness_of_fit_uniform(&counts);
    let chi_square_upper_tail_p_value =
        analysis::chi_square_upper_tail_p_value(chi_square_uniform, modulus.saturating_sub(1));
    let top_difference = top_value_peak(&counts, length, modulus);
    let period_ioc = period_ioc_rows(message_values, max_period, modulus);
    let best_period_ioc = period_ioc
        .iter()
        .copied()
        .max_by(|left, right| left.normalized_ioc.total_cmp(&right.normalized_ioc));
    let period_baseline_normalized_ioc = period_ioc
        .iter()
        .find(|row| row.period == 1)
        .map_or(normalized_ioc, |row| row.normalized_ioc);
    let best_period_normalized_ioc = best_period_ioc.map_or(0.0, |row| row.normalized_ioc);
    let period_excess = (best_period_normalized_ioc - period_baseline_normalized_ioc).max(0.0);
    let autocorrelation = autocorrelation_rows(message_values, max_lag, modulus);
    let best_autocorrelation = autocorrelation
        .iter()
        .copied()
        .max_by(|left, right| left.normalized_rate.total_cmp(&right.normalized_rate));
    let best_lag_normalized_rate = best_autocorrelation.map_or(0.0, |row| row.normalized_rate);
    let structure_score = max_f64([
        top_difference.over_uniform,
        normalized_ioc,
        best_period_normalized_ioc,
        best_lag_normalized_rate,
    ]);

    Ok(DifferenceStats {
        modulus,
        difference_order,
        length,
        raw_ioc,
        ioc,
        normalized_ioc,
        delta_ioc: ioc - raw_ioc,
        chi_square_uniform,
        chi_square_upper_tail_p_value,
        distinct_support_size,
        top_difference,
        period_ioc,
        best_period_ioc,
        period_excess,
        autocorrelation,
        best_autocorrelation,
        structure_score,
    })
}

fn counts_for_messages(
    message_values: &[Vec<TrigramValue>],
    modulus: usize,
) -> Result<Vec<usize>, ModularDiffError> {
    let mut counts = vec![0usize; modulus];
    for values in message_values {
        for value in values {
            let raw = usize::from(value.get());
            let Some(count) = counts.get_mut(raw) else {
                return Err(ModularDiffError::ValueOutsideModulus {
                    value: value.get(),
                    modulus,
                });
            };
            *count += 1;
        }
    }
    Ok(counts)
}

fn top_value_peak(counts: &[usize], length: usize, modulus: usize) -> ValuePeak {
    let mut peak_value = 0usize;
    let mut peak_count = 0usize;
    for (value, &count) in counts.iter().enumerate() {
        if count > peak_count {
            peak_value = value;
            peak_count = count;
        }
    }
    let rate = if length == 0 {
        0.0
    } else {
        peak_count as f64 / length as f64
    };
    ValuePeak {
        value: u8::try_from(peak_value).unwrap_or_default(),
        count: peak_count,
        rate,
        over_uniform: rate * modulus as f64,
    }
}

fn period_ioc_rows(
    message_values: &[Vec<TrigramValue>],
    max_period: usize,
    modulus: usize,
) -> Vec<PeriodIoc> {
    periodicity::normalized_ioc_by_period_values(message_values, max_period, modulus)
        .into_iter()
        .enumerate()
        .map(|(index, normalized_ioc)| PeriodIoc {
            period: index + 1,
            mean_ioc: normalized_ioc / modulus as f64,
            normalized_ioc,
        })
        .collect()
}

fn autocorrelation_rows(
    message_values: &[Vec<TrigramValue>],
    max_lag: usize,
    modulus: usize,
) -> Vec<LagAutocorrelation> {
    periodicity::autocorrelation_values(message_values, max_lag)
        .into_iter()
        .enumerate()
        .map(|(index, rate)| {
            let lag = index + 1;
            LagAutocorrelation {
                lag,
                matches: count_message_lag_matches(message_values, lag),
                comparisons: count_message_lag_comparisons(message_values, lag),
                rate,
                normalized_rate: rate * modulus as f64,
            }
        })
        .collect()
}

fn message_weighted_ioc_values(message_values: &[Vec<TrigramValue>]) -> f64 {
    let message_glyphs = glyph_messages_from_values(message_values);
    message_weighted_ioc_glyphs(&message_glyphs)
}

fn message_weighted_ioc_glyphs(message_glyphs: &[Vec<Glyph>]) -> f64 {
    let mut weighted_ioc = 0.0;
    let mut pair_count_total = 0usize;
    for glyphs in message_glyphs {
        let len = glyphs.len();
        if len < 2 {
            continue;
        }
        let pair_count = len * (len - 1);
        weighted_ioc += analysis::index_of_coincidence(glyphs) * pair_count as f64;
        pair_count_total += pair_count;
    }
    if pair_count_total == 0 {
        0.0
    } else {
        weighted_ioc / pair_count_total as f64
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Fingerprint {
    ioc: f64,
    delta_ioc: f64,
    top_rate: f64,
    top_over_uniform: f64,
    period_excess: f64,
    best_lag_normalized_rate: f64,
    structure_score: f64,
}

impl Fingerprint {
    fn from_stats(stats: &DifferenceStats) -> Self {
        Self {
            ioc: stats.ioc,
            delta_ioc: stats.delta_ioc,
            top_rate: stats.top_difference.rate,
            top_over_uniform: stats.top_difference.over_uniform,
            period_excess: stats.period_excess,
            best_lag_normalized_rate: stats
                .best_autocorrelation
                .map_or(0.0, |row| row.normalized_rate),
            structure_score: stats.structure_score,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct FamilySamples {
    family: ControlFamily,
    fingerprints: Vec<Fingerprint>,
}

impl FamilySamples {
    fn new(family: ControlFamily, capacity: usize) -> Self {
        Self {
            family,
            fingerprints: Vec::with_capacity(capacity),
        }
    }
}

fn calibrate_controls(
    config: ModularDiffConfig,
    lengths: &[usize],
    eye_differences: &[DifferenceOrderReport],
) -> Result<Vec<ControlOrderReport>, ModularDiffError> {
    let mut controls = Vec::new();
    for difference_order in 1..=MAX_DIFFERENCE_ORDER {
        let Some(eye_report) = eye_differences
            .iter()
            .find(|report| report.difference_order == difference_order)
        else {
            continue;
        };
        controls.push(calibrate_control_order(
            config,
            lengths,
            eye_report,
            difference_order,
        )?);
    }
    Ok(controls)
}

fn calibrate_control_order(
    config: ModularDiffConfig,
    lengths: &[usize],
    eye_report: &DifferenceOrderReport,
    difference_order: usize,
) -> Result<ControlOrderReport, ModularDiffError> {
    let mut rng = SplitMix64::new(mix_seed(
        config.seed,
        0x636f_6e74_726f_6c00 ^ difference_order as u64,
    ));
    let source = SourceSampler::new(PRIMARY_MODULUS);
    let mut family_samples = CONTROL_FAMILIES
        .iter()
        .copied()
        .map(|family| FamilySamples::new(family, config.trials))
        .collect::<Vec<_>>();

    for _trial in 0..config.trials {
        for samples in &mut family_samples {
            let fixture = build_control_fixture(samples.family, lengths, &source, &mut rng)?;
            let raw_ioc = message_weighted_ioc_values(&fixture);
            let differenced =
                modular_difference_messages(&fixture, difference_order, PRIMARY_MODULUS)?;
            let stats = summarize_difference_stream(
                &differenced,
                raw_ioc,
                PRIMARY_MODULUS,
                difference_order,
                config.max_period,
                config.max_lag,
            )?;
            samples.fingerprints.push(Fingerprint::from_stats(&stats));
        }
    }

    let family_bands = family_samples
        .iter()
        .map(|samples| ControlFamilyBand {
            family: samples.family,
            key_summary: samples.family.key_summary(),
            fingerprint: fingerprint_band(&samples.fingerprints),
        })
        .collect::<Vec<_>>();
    let separation = separation_from_bands(&family_bands);
    let eye_placement = classify_eye(
        &eye_report.stats,
        &eye_report.shuffle_baseline,
        &family_bands,
        separation,
    );

    Ok(ControlOrderReport {
        difference_order,
        family_bands,
        separation,
        eye_placement,
    })
}

fn separation_from_bands(family_bands: &[ControlFamilyBand]) -> ControlSeparation {
    let Some(wheel) = family_band(family_bands, ControlFamily::IncrementingWheel) else {
        return overlapping_separation();
    };
    let Some(vigenere) = family_band(family_bands, ControlFamily::PeriodicVigenere) else {
        return overlapping_separation();
    };
    let Some(deck) = family_band(family_bands, ControlFamily::DeckS83Keystream) else {
        return overlapping_separation();
    };
    let Some(flat) = family_band(family_bands, ControlFamily::FlatRandom) else {
        return overlapping_separation();
    };

    let nonwheel_top_ceiling = max_f64([
        vigenere.fingerprint.top_rate.q975,
        deck.fingerprint.top_rate.q975,
        flat.fingerprint.top_rate.q975,
    ]);
    let structureless_period_ceiling = deck
        .fingerprint
        .period_excess
        .q975
        .max(flat.fingerprint.period_excess.q975);
    ControlSeparation {
        wheel_top_rate: separated_when(wheel.fingerprint.top_rate.q025 > nonwheel_top_ceiling),
        vigenere_period_excess: separated_when(
            vigenere.fingerprint.period_excess.q025 > structureless_period_ceiling,
        ),
        deck_flat_structure: if bands_overlap(
            deck.fingerprint.structure_score,
            flat.fingerprint.structure_score,
        ) {
            BandSeparation::Overlapping
        } else {
            BandSeparation::Separated
        },
    }
}

fn overlapping_separation() -> ControlSeparation {
    ControlSeparation {
        wheel_top_rate: BandSeparation::Overlapping,
        vigenere_period_excess: BandSeparation::Overlapping,
        deck_flat_structure: BandSeparation::Overlapping,
    }
}

fn classify_eye(
    stats: &DifferenceStats,
    shuffle: &FingerprintBand,
    family_bands: &[ControlFamilyBand],
    separation: ControlSeparation,
) -> FamilyPlacement {
    if !separation.is_calibrated() {
        return FamilyPlacement::Uncalibrated;
    }
    let Some(wheel) = family_band(family_bands, ControlFamily::IncrementingWheel) else {
        return FamilyPlacement::Uncalibrated;
    };
    let Some(vigenere) = family_band(family_bands, ControlFamily::PeriodicVigenere) else {
        return FamilyPlacement::Uncalibrated;
    };
    let Some(deck) = family_band(family_bands, ControlFamily::DeckS83Keystream) else {
        return FamilyPlacement::Uncalibrated;
    };
    let Some(flat) = family_band(family_bands, ControlFamily::FlatRandom) else {
        return FamilyPlacement::Uncalibrated;
    };

    let nonwheel_top_ceiling = max_f64([
        vigenere.fingerprint.top_rate.q975,
        deck.fingerprint.top_rate.q975,
        flat.fingerprint.top_rate.q975,
    ]);
    if stats.top_difference.rate >= wheel.fingerprint.top_rate.q025
        && stats.top_difference.rate > nonwheel_top_ceiling
    {
        return FamilyPlacement::WheelLike;
    }

    let structureless_period_ceiling = max_f64([
        deck.fingerprint.period_excess.q975,
        flat.fingerprint.period_excess.q975,
        shuffle.period_excess.q975,
    ]);
    if stats.period_excess >= vigenere.fingerprint.period_excess.q025
        && stats.period_excess > structureless_period_ceiling
    {
        return FamilyPlacement::VigenereLike;
    }

    let structureless_ceiling = max_f64([
        deck.fingerprint.structure_score.max,
        flat.fingerprint.structure_score.max,
        shuffle.structure_score.max,
    ]);
    if stats.structure_score <= structureless_ceiling {
        FamilyPlacement::StructurelessLike
    } else {
        FamilyPlacement::BetweenBands
    }
}

fn family_band(
    family_bands: &[ControlFamilyBand],
    family: ControlFamily,
) -> Option<&ControlFamilyBand> {
    family_bands.iter().find(|band| band.family == family)
}

fn separated_when(condition: bool) -> BandSeparation {
    if condition {
        BandSeparation::Separated
    } else {
        BandSeparation::Overlapping
    }
}

fn bands_overlap(left: ScalarBand, right: ScalarBand) -> bool {
    left.q025 <= right.q975 && right.q025 <= left.q975
}

fn shuffle_baseline(
    config: ModularDiffConfig,
    message_values: &[Vec<TrigramValue>],
    raw_ioc: f64,
    modulus: usize,
    difference_order: usize,
) -> Result<FingerprintBand, ModularDiffError> {
    let mut rng = SplitMix64::new(mix_seed(
        config.seed,
        0x7368_7566_666c_6500 ^ ((modulus as u64) << 8) ^ difference_order as u64,
    ));
    let mut samples = Vec::with_capacity(config.trials);
    for _trial in 0..config.trials {
        let shuffled = shuffled_messages(message_values, &mut rng)?;
        let differenced = modular_difference_messages(&shuffled, difference_order, modulus)?;
        let stats = summarize_difference_stream(
            &differenced,
            raw_ioc,
            modulus,
            difference_order,
            config.max_period,
            config.max_lag,
        )?;
        samples.push(Fingerprint::from_stats(&stats));
    }
    Ok(fingerprint_band(&samples))
}

fn shuffled_messages(
    message_values: &[Vec<TrigramValue>],
    rng: &mut SplitMix64,
) -> Result<Vec<Vec<TrigramValue>>, ModularDiffError> {
    let mut shuffled = message_values.to_vec();
    for values in &mut shuffled {
        fisher_yates_trigram(values, rng)?;
    }
    Ok(shuffled)
}

fn build_control_fixture(
    family: ControlFamily,
    lengths: &[usize],
    source: &SourceSampler,
    rng: &mut SplitMix64,
) -> Result<Vec<Vec<TrigramValue>>, ModularDiffError> {
    match family {
        ControlFamily::IncrementingWheel => wheel_fixture(lengths, rng),
        ControlFamily::PeriodicVigenere => vigenere_fixture(lengths),
        ControlFamily::DeckS83Keystream => deck_fixture(lengths, source, rng),
        ControlFamily::FlatRandom => flat_random_fixture(lengths, rng),
    }
}

fn wheel_fixture(
    lengths: &[usize],
    rng: &mut SplitMix64,
) -> Result<Vec<Vec<TrigramValue>>, ModularDiffError> {
    let mut messages = Vec::with_capacity(lengths.len());
    for &length in lengths {
        let start = random_index_below(PRIMARY_MODULUS, rng)?;
        let key = IncrementingWheelKey::new(PRIMARY_MODULUS, start, WHEEL_STEP)?;
        let plaintext = vec![Glyph(0); length];
        let ciphertext = incrementing_wheel_encrypt(&plaintext, &key)?;
        messages.push(glyphs_to_trigram_values(&ciphertext, PRIMARY_MODULUS)?);
    }
    Ok(messages)
}

fn vigenere_fixture(lengths: &[usize]) -> Result<Vec<Vec<TrigramValue>>, ModularDiffError> {
    let key = VigenereKey::new(PRIMARY_MODULUS, VIGENERE_SHIFTS.to_vec())?;
    let mut messages = Vec::with_capacity(lengths.len());
    for &length in lengths {
        let plaintext = vec![Glyph(0); length];
        let ciphertext = vigenere_encrypt(&plaintext, &key)?;
        messages.push(glyphs_to_trigram_values(&ciphertext, PRIMARY_MODULUS)?);
    }
    Ok(messages)
}

fn deck_fixture(
    lengths: &[usize],
    source: &SourceSampler,
    rng: &mut SplitMix64,
) -> Result<Vec<Vec<TrigramValue>>, ModularDiffError> {
    let deck = shuffled_permutation(PRIMARY_MODULUS, rng)?;
    let key = DeckCipherKey::new(
        PRIMARY_MODULUS,
        deck,
        PRIMARY_MODULUS - 2,
        PRIMARY_MODULUS - 1,
    )?;
    let mut messages = Vec::with_capacity(lengths.len());
    for &length in lengths {
        let plaintext = source.sample_glyphs(length, rng)?;
        let ciphertext = deck_cipher_encrypt(&plaintext, &key)?;
        messages.push(glyphs_to_trigram_values(&ciphertext, PRIMARY_MODULUS)?);
    }
    Ok(messages)
}

fn flat_random_fixture(
    lengths: &[usize],
    rng: &mut SplitMix64,
) -> Result<Vec<Vec<TrigramValue>>, ModularDiffError> {
    let mut messages = Vec::with_capacity(lengths.len());
    for &length in lengths {
        let mut values = Vec::with_capacity(length);
        for _position in 0..length {
            values.push(trigram_from_usize(
                random_index_below(PRIMARY_MODULUS, rng)?,
                PRIMARY_MODULUS,
            )?);
        }
        messages.push(values);
    }
    Ok(messages)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceSampler {
    population: Vec<usize>,
}

impl SourceSampler {
    fn new(alphabet_size: usize) -> Self {
        let mut population = Vec::new();
        for symbol in 0..alphabet_size {
            let weight = 1 + (stateless_splitmix(symbol as u64 ^ 0x706c_6169_6e5f_7372) % 31);
            for _copy in 0..weight {
                population.push(symbol);
            }
        }
        Self { population }
    }

    fn sample_glyphs(
        &self,
        length: usize,
        rng: &mut SplitMix64,
    ) -> Result<Vec<Glyph>, ModularDiffError> {
        let mut glyphs = Vec::with_capacity(length);
        for _position in 0..length {
            let index = random_index_below(self.population.len(), rng)?;
            let Some(symbol) = self.population.get(index).copied() else {
                return Err(ModularDiffError::RandomBoundTooLarge {
                    bound: self.population.len(),
                });
            };
            glyphs.push(Glyph(symbol as u16));
        }
        Ok(glyphs)
    }
}

fn shuffled_permutation(
    alphabet_size: usize,
    rng: &mut SplitMix64,
) -> Result<Vec<usize>, ModularDiffError> {
    let mut values = (0..alphabet_size).collect::<Vec<_>>();
    fisher_yates_usize(&mut values, rng)?;
    Ok(values)
}

fn fisher_yates_usize(values: &mut [usize], rng: &mut SplitMix64) -> Result<(), ModularDiffError> {
    let mut unswapped = values.len();
    while unswapped > 1 {
        let last = unswapped - 1;
        let partner = random_index_below(unswapped, rng)?;
        values.swap(last, partner);
        unswapped = last;
    }
    Ok(())
}

fn fisher_yates_trigram(
    values: &mut [TrigramValue],
    rng: &mut SplitMix64,
) -> Result<(), ModularDiffError> {
    let mut unswapped = values.len();
    while unswapped > 1 {
        let last = unswapped - 1;
        let partner = random_index_below(unswapped, rng)?;
        values.swap(last, partner);
        unswapped = last;
    }
    Ok(())
}

fn random_index_below(bound: usize, rng: &mut SplitMix64) -> Result<usize, ModularDiffError> {
    let bound_u64 =
        u64::try_from(bound).map_err(|_error| ModularDiffError::RandomBoundTooLarge { bound })?;
    if bound_u64 == 0 {
        return Err(ModularDiffError::RandomBoundTooLarge { bound });
    }
    let rejection_threshold = u64::MAX - (u64::MAX % bound_u64);
    loop {
        let draw = rng.next_u64();
        if draw < rejection_threshold {
            let index_u64 = draw % bound_u64;
            return usize::try_from(index_u64)
                .map_err(|_error| ModularDiffError::RandomBoundTooLarge { bound });
        }
    }
}

fn glyphs_to_trigram_values(
    glyphs: &[Glyph],
    modulus: usize,
) -> Result<Vec<TrigramValue>, ModularDiffError> {
    let mut values = Vec::with_capacity(glyphs.len());
    for glyph in glyphs {
        let raw = usize::from(glyph.0);
        if raw >= modulus {
            return Err(ModularDiffError::ValueOutsideModulus {
                value: u8::try_from(raw).unwrap_or(u8::MAX),
                modulus,
            });
        }
        values.push(trigram_from_usize(raw, modulus)?);
    }
    Ok(values)
}

fn trigram_from_usize(value: usize, modulus: usize) -> Result<TrigramValue, ModularDiffError> {
    let raw = u8::try_from(value).map_err(|_error| ModularDiffError::InvalidModulus { modulus })?;
    TrigramValue::new(raw).map_err(|_raw| ModularDiffError::InvalidModulus { modulus })
}

fn fingerprint_band(samples: &[Fingerprint]) -> FingerprintBand {
    FingerprintBand {
        ioc: scalar_band(&samples.iter().map(|sample| sample.ioc).collect::<Vec<_>>()),
        delta_ioc: scalar_band(
            &samples
                .iter()
                .map(|sample| sample.delta_ioc)
                .collect::<Vec<_>>(),
        ),
        top_rate: scalar_band(
            &samples
                .iter()
                .map(|sample| sample.top_rate)
                .collect::<Vec<_>>(),
        ),
        top_over_uniform: scalar_band(
            &samples
                .iter()
                .map(|sample| sample.top_over_uniform)
                .collect::<Vec<_>>(),
        ),
        period_excess: scalar_band(
            &samples
                .iter()
                .map(|sample| sample.period_excess)
                .collect::<Vec<_>>(),
        ),
        best_lag_normalized_rate: scalar_band(
            &samples
                .iter()
                .map(|sample| sample.best_lag_normalized_rate)
                .collect::<Vec<_>>(),
        ),
        structure_score: scalar_band(
            &samples
                .iter()
                .map(|sample| sample.structure_score)
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

fn median_f64(sorted: &[f64]) -> f64 {
    let len = sorted.len();
    if len == 0 {
        return 0.0;
    }
    let middle = len / 2;
    if len.is_multiple_of(2) {
        match (
            sorted.get(middle.saturating_sub(1)).copied(),
            sorted.get(middle).copied(),
        ) {
            (Some(left), Some(right)) => f64::midpoint(left, right),
            _ => 0.0,
        }
    } else {
        sorted.get(middle).copied().unwrap_or(0.0)
    }
}

fn quantile_f64(sorted: &[f64], numerator: usize, denominator: usize) -> f64 {
    sorted
        .get(scaled_quantile_index(sorted.len(), numerator, denominator))
        .copied()
        .unwrap_or(0.0)
}

fn scaled_quantile_index(len: usize, numerator: usize, denominator: usize) -> usize {
    if len == 0 || denominator == 0 {
        return 0;
    }
    len.saturating_sub(1).saturating_mul(numerator) / denominator
}

fn max_f64(values: impl IntoIterator<Item = f64>) -> f64 {
    values.into_iter().fold(0.0, f64::max)
}

fn mix_seed(seed: u64, tag: u64) -> u64 {
    stateless_splitmix(seed ^ tag.wrapping_mul(0x9e37_79b9_7f4a_7c15))
}

fn stateless_splitmix(seed: u64) -> u64 {
    let mut value = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use super::{
        BandSeparation, ControlFamily, FamilyPlacement, ModularDiffConfig, PRIMARY_MODULUS,
        SourceSampler, build_control_fixture, modular_difference_messages, run_modular_diff,
        summarize_difference_stream,
    };
    use crate::null::SplitMix64;
    use crate::trigram::TrigramValue;

    fn values(raw: &[u8]) -> Vec<TrigramValue> {
        raw.iter()
            .copied()
            .map(|value| TrigramValue::new(value).unwrap())
            .collect()
    }

    fn assert_close(label: &str, actual: f64, expected: f64, tolerance: f64) {
        let difference = (actual - expected).abs();
        assert!(
            difference <= tolerance,
            "{label} changed: actual={actual:.17e} expected={expected:.17e} diff={difference:.17e} tolerance={tolerance:.17e}"
        );
    }

    #[test]
    fn first_difference_resets_at_message_boundaries() {
        let messages = vec![values(&[1, 3, 0]), values(&[5, 2])];
        let differenced = modular_difference_messages(&messages, 1, 7).unwrap();

        assert_eq!(differenced, vec![values(&[2, 4]), values(&[4])]);
    }

    #[test]
    fn higher_order_difference_math_is_modular() {
        let messages = vec![values(&[1, 3, 0, 4])];
        let differenced = modular_difference_messages(&messages, 2, 7).unwrap();

        assert_eq!(differenced, vec![values(&[2, 0])]);
    }

    #[test]
    fn wheel_fixture_has_constant_first_difference() {
        let source = SourceSampler::new(PRIMARY_MODULUS);
        let mut rng = SplitMix64::new(0x5151);
        let fixture = build_control_fixture(
            ControlFamily::IncrementingWheel,
            &[12, 11],
            &source,
            &mut rng,
        )
        .unwrap();
        let differenced = modular_difference_messages(&fixture, 1, PRIMARY_MODULUS).unwrap();
        let stats =
            summarize_difference_stream(&differenced, 0.0, PRIMARY_MODULUS, 1, 8, 8).unwrap();

        assert_eq!(stats.top_difference.value, 17);
        assert_eq!(stats.top_difference.count, 21);
        assert_close("wheel top rate", stats.top_difference.rate, 1.0, 1e-12);
        assert_close("wheel IoC", stats.ioc, 1.0, 1e-12);
    }

    #[test]
    fn calibration_controls_separate_before_eye_classification() {
        let report = run_modular_diff(ModularDiffConfig {
            seed: 0x2222,
            trials: 32,
            max_period: 12,
            max_lag: 12,
        })
        .unwrap();
        let first = report
            .controls
            .iter()
            .find(|row| row.difference_order == 1)
            .unwrap();

        assert_eq!(first.separation.wheel_top_rate, BandSeparation::Separated);
        assert_eq!(
            first.separation.vigenere_period_excess,
            BandSeparation::Separated
        );
        assert!(first.separation.is_calibrated());
    }

    #[test]
    fn real_headline_statistics_are_stable() {
        let report = run_modular_diff(ModularDiffConfig {
            seed: 123,
            trials: 8,
            max_period: 8,
            max_lag: 8,
        })
        .unwrap();
        let first = report.primary.differences.first().unwrap();

        assert_eq!(report.total_length, 1036);
        assert_eq!(first.stats.length, 1027);
        assert_eq!(first.stats.distinct_support_size, 82);
        assert_eq!(first.stats.top_difference.value, 7);
        assert_eq!(first.stats.top_difference.count, 25);
        assert_close(
            "raw IoC",
            first.stats.raw_ioc,
            0.011_708_150_480_720_913,
            1e-15,
        );
        assert_close(
            "diff IoC",
            first.stats.ioc,
            0.012_151_682_999_573_924,
            1e-15,
        );
        assert_close(
            "delta IoC",
            first.stats.delta_ioc,
            0.000_443_532_518_853_010_86,
            1e-15,
        );
        assert_close(
            "top over uniform",
            first.stats.top_difference.over_uniform,
            2.020_447_906_523_856,
            1e-9,
        );
        assert_eq!(
            report.headline_placement,
            FamilyPlacement::StructurelessLike
        );
    }
}

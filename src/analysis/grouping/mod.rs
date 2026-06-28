//! Experiment 8: base-N grouping comparison and state-count calibration.
//!
//! The grouping half treats the accepted honeycomb rendered-orientation stream
//! as non-overlapping base-5 groups of length `1..=4`, preserving message
//! boundaries so no group crosses a join. The storage layer is reported
//! separately from the engine base-7 decode and includes delimiter symbol `5`.
//!
//! The state-count half deliberately does **not** assume the established
//! 83-value reading-layer alphabet. It estimates a collision-equivalent number
//! of states from `IoC`/collision entropy (`N_eff = 1 / IoC`) and calibrates
//! that estimator on deterministic synthetic N-state substitution streams.

use std::fmt;

use crate::analysis::analysis;
use crate::analysis::isomorph::IsomorphError;
use crate::analysis::orders::{self, GridError, ReadingOrder};
use crate::attack::language::LanguageError;
use crate::core::glyph::Glyph;
use crate::nulls::null::SplitMix64;

mod compute;
mod report;
#[cfg(test)]
mod tests;

use compute::{
    calibration_row, compatibility_report, effective_alphabet_from_ioc, grouping_rows,
    language_references, normalized_entropy, orientation_messages_from_values, pow_usize,
    state_count_estimate, synthetic_state_messages,
};

const ORIENTATION_BASE: usize = crate::core::glyph::ORIENTATION_COUNT;
const STORAGE_BASE: usize = crate::core::glyph::ENGINE_STORAGE_BASE;
const DEFAULT_CALIBRATION_SEED: u64 = 0x6578_7038_7374_6174;
const DEFAULT_STATE_MIN_WINDOW: usize = 3;
const DEFAULT_STATE_MAX_WINDOW: usize = 8;
const MIN_CALIBRATION_MARGIN: f64 = 0.05;
const LANGUAGE_ALPHABET_SPAN_DIVISOR: usize = 2;
const MIN_LANGUAGE_ENTROPY_TOLERANCE_BITS: f64 = 0.10;
const CALIBRATION_STATES: [usize; 5] = [5, 25, 50, 83, 125];

/// Error returned by Experiment 8 report construction.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum GroupingError {
    /// The verified corpus grids could not be reconstructed or read.
    Grid(GridError),
    /// A bundled language model could not be built.
    Language(LanguageError),
    /// The shared isomorph detector rejected a generated configuration.
    Isomorph(IsomorphError),
    /// An engine storage symbol was outside the authored rendered range.
    InvalidStorageSymbol {
        /// Message index in [`ENGINE_MESSAGES`](crate::data::generator::ENGINE_MESSAGES).
        message_index: usize,
        /// Invalid decoded symbol.
        symbol: i8,
    },
    /// A synthetic state count was zero.
    ZeroStateCount,
    /// A synthetic state count cannot be represented as a [`Glyph`] index.
    StateCountTooLarge {
        /// Requested state count.
        state_count: usize,
    },
    /// A bounded PRNG draw could not represent the requested upper bound.
    RandomBoundTooLarge {
        /// Requested exclusive upper bound.
        bound: usize,
    },
}

impl fmt::Display for GroupingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Grid(grid_error) => write!(f, "grid/order error: {grid_error:?}"),
            Self::Language(language_error) => write!(f, "language model error: {language_error}"),
            Self::Isomorph(isomorph_error) => {
                write!(f, "isomorph detector error: {isomorph_error:?}")
            }
            Self::InvalidStorageSymbol {
                message_index,
                symbol,
            } => write!(
                f,
                "storage message {message_index} decoded invalid symbol {symbol}"
            ),
            Self::ZeroStateCount => {
                write!(f, "synthetic calibration state count must be at least 1")
            }
            Self::StateCountTooLarge { state_count } => {
                write!(
                    f,
                    "synthetic calibration state count {state_count} is too large"
                )
            }
            Self::RandomBoundTooLarge { bound } => {
                write!(f, "synthetic calibration random bound {bound} is too large")
            }
        }
    }
}

impl std::error::Error for GroupingError {}

impl From<GridError> for GroupingError {
    fn from(value: GridError) -> Self {
        Self::Grid(value)
    }
}

impl From<LanguageError> for GroupingError {
    fn from(value: LanguageError) -> Self {
        Self::Language(value)
    }
}

impl From<IsomorphError> for GroupingError {
    fn from(value: IsomorphError) -> Self {
        Self::Isomorph(value)
    }
}

impl From<crate::nulls::null::RandomBoundError> for GroupingError {
    fn from(error: crate::nulls::null::RandomBoundError) -> Self {
        Self::RandomBoundTooLarge { bound: error.bound }
    }
}

/// A grouping axis reported by Experiment 8.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupingAxis {
    /// Rendered orientation digits grouped in accepted honeycomb order.
    OrientationBase5 {
        /// Number of orientation digits per non-overlapping group.
        width: usize,
    },
    /// Engine storage-layer symbols from the base-7 decoder.
    EngineStorageBase7,
}

impl GroupingAxis {
    /// Human-readable label for this grouping axis.
    #[must_use]
    pub fn label(self) -> String {
        match self {
            Self::OrientationBase5 { width } => match width {
                1 => "single N=1 base5".to_owned(),
                2 => "pairs N=2 base25".to_owned(),
                3 => "trigrams N=3 base125".to_owned(),
                4 => "tetragrams N=4 base625".to_owned(),
                _ => format!("orientation N={width}"),
            },
            Self::EngineStorageBase7 => "engine storage base7".to_owned(),
        }
    }

    /// Nominal alphabet size for this axis.
    #[must_use]
    pub fn nominal_base(self) -> usize {
        match self {
            Self::OrientationBase5 { width } => pow_usize(ORIENTATION_BASE, width),
            Self::EngineStorageBase7 => STORAGE_BASE,
        }
    }
}

/// Entropy, `IoC`, and support size for one grouped symbol stream.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SymbolStats {
    /// Number of symbols in the stream.
    pub symbols: usize,
    /// Number of distinct symbols observed.
    pub used_alphabet: usize,
    /// Shannon entropy in bits per grouped symbol.
    pub entropy_bits_per_symbol: f64,
    /// Entropy divided by `log2(used_alphabet)`.
    pub normalized_entropy: f64,
    /// Index of coincidence in probability form.
    pub ioc: f64,
    /// Collision-equivalent alphabet size, `1 / IoC`.
    pub collision_effective_alphabet: f64,
}

impl SymbolStats {
    fn from_glyphs(glyphs: &[Glyph]) -> Self {
        let frequencies = analysis::frequencies(glyphs);
        let used_alphabet = frequencies.len();
        let entropy_bits_per_symbol = analysis::shannon_entropy(glyphs);
        let normalized_entropy = normalized_entropy(entropy_bits_per_symbol, used_alphabet);
        let ioc = analysis::index_of_coincidence(glyphs);
        Self {
            symbols: glyphs.len(),
            used_alphabet,
            entropy_bits_per_symbol,
            normalized_entropy,
            ioc,
            collision_effective_alphabet: effective_alphabet_from_ioc(ioc),
        }
    }
}

/// Per-message grouping statistics.
#[derive(Clone, Debug, PartialEq)]
pub struct MessageGroupingStats {
    /// Corpus message key.
    pub message_key: &'static str,
    /// Number of source orientation symbols discarded because they did not
    /// complete the final non-overlapping group.
    pub dropped_source_symbols: usize,
    /// Statistics for this message.
    pub stats: SymbolStats,
}

/// One grouping row in the Experiment 8 comparison table.
#[derive(Clone, Debug, PartialEq)]
pub struct GroupingRow {
    /// Grouping axis.
    pub axis: GroupingAxis,
    /// Sum of per-message discarded source symbols.
    pub dropped_source_symbols: usize,
    /// Pooled statistics after grouping within messages.
    pub pooled: SymbolStats,
    /// Message-weighted entropy in bits per grouped symbol.
    pub message_weighted_entropy_bits_per_symbol: f64,
    /// Message-weighted normalized entropy.
    pub message_weighted_normalized_entropy: f64,
    /// Message-weighted `IoC`, weighted by comparable symbol pairs.
    pub message_weighted_ioc: f64,
    /// Per-message rows in corpus order.
    pub messages: Vec<MessageGroupingStats>,
}

/// Natural-language unigram reference row derived from a bundled model.
#[derive(Clone, Debug, PartialEq)]
pub struct LanguageReference {
    /// Language label.
    pub language: &'static str,
    /// Plaintext alphabet size used for compatibility comparison.
    pub nominal_alphabet: usize,
    /// Number of letters actually observed in the bundled sample.
    pub observed_used_alphabet: usize,
    /// Number of normalized letters in the bundled sample.
    pub symbols: usize,
    /// Shannon entropy in bits per letter.
    pub entropy_bits_per_symbol: f64,
    /// Entropy divided by `log2(observed_used_alphabet)`.
    pub normalized_entropy: f64,
    /// Index of coincidence in probability form.
    pub ioc: f64,
    /// Collision-equivalent alphabet size, `1 / IoC`.
    pub collision_effective_alphabet: f64,
}

/// Whether a grouping row is numerically close to language references.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupingCompatibility {
    /// Grouping label.
    pub grouping_label: String,
    /// Whether used alphabet size falls in the measured language alphabet band.
    pub alphabet_compatible: bool,
    /// Whether entropy falls in the measured language entropy band.
    pub entropy_compatible: bool,
}

/// Compatibility bands derived from the bundled language references.
#[derive(Clone, Debug, PartialEq)]
pub struct CompatibilityReport {
    /// Lower accepted alphabet-size bound.
    pub alphabet_min: usize,
    /// Upper accepted alphabet-size bound.
    pub alphabet_max: usize,
    /// Lower accepted entropy bound in bits per symbol.
    pub entropy_min: f64,
    /// Upper accepted entropy bound in bits per symbol.
    pub entropy_max: f64,
    /// Grouping with the nearest used-alphabet size to a reference language.
    pub nearest_alphabet_grouping: String,
    /// Per-grouping compatibility flags.
    pub rows: Vec<GroupingCompatibility>,
}

impl CompatibilityReport {
    /// Returns grouping labels that match both alphabet size and entropy.
    #[must_use]
    pub fn fully_compatible_groupings(&self) -> Vec<String> {
        self.rows
            .iter()
            .filter(|row| row.alphabet_compatible && row.entropy_compatible)
            .map(|row| row.grouping_label.clone())
            .collect()
    }
}

/// Collision-based state-count estimate for the eye reading-layer stream.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CollisionStateEstimate {
    /// `IoC` after pooling already grouped messages.
    pub pooled_ioc: f64,
    /// `1 / pooled_ioc`.
    pub pooled_effective_states: f64,
    /// Message-weighted `IoC`, preserving message boundaries for pair counts.
    pub message_weighted_ioc: f64,
    /// `1 / message_weighted_ioc`.
    pub message_weighted_effective_states: f64,
    /// Shannon entropy of the pooled stream in bits per symbol.
    pub pooled_entropy_bits_per_symbol: f64,
    /// Collision entropy, `-log2(pooled_ioc)`.
    pub collision_entropy_bits: f64,
}

/// Isomorph/window diagnostic used to contextualize the state-count estimate.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct IsomorphStateRow {
    /// Window length in reading-layer symbols.
    pub window: usize,
    /// Total windows scanned within messages.
    pub windows: usize,
    /// Windows whose first-occurrence signature had at least one repeated
    /// symbol.
    pub informative_windows: usize,
    /// Repeated informative signature kinds, summed within messages.
    pub repeated_signature_kinds: usize,
    /// Largest repeated-signature occurrence count within a message.
    pub max_repeat_count: usize,
    /// Birthday-collision state estimate from `informative_windows / windows`.
    pub birthday_effective_states: Option<f64>,
}

/// Approximate internal state-count range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateCountRange {
    /// Lower rounded estimate.
    pub lower: usize,
    /// Upper rounded estimate.
    pub upper: usize,
    /// Whether `83` lies in the rounded range.
    pub includes_83: bool,
}

/// State-count estimate derived from the real corpus.
#[derive(Clone, Debug, PartialEq)]
pub struct StateCountEstimateReport {
    /// Reading order used to obtain the reading-layer stream.
    pub order: ReadingOrder,
    /// Per-message reading-layer lengths.
    pub message_lengths: Vec<(&'static str, usize)>,
    /// Collision-entropy estimate.
    pub collision: CollisionStateEstimate,
    /// Isomorph/window diagnostics over the same stream.
    pub isomorph_rows: Vec<IsomorphStateRow>,
    /// Longest scanned window with at least one repeated real isomorph.
    pub longest_repeated_isomorph: Option<usize>,
    /// Rounded approximate range after applying calibration margin.
    pub range: StateCountRange,
    /// Relative calibration margin applied to the observed point estimates.
    pub calibration_relative_margin: f64,
}

/// One synthetic positive-control row for the state estimator.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StateCalibrationRow {
    /// Known synthetic state count.
    pub true_states: usize,
    /// Distinct symbols actually observed in the generated fixture.
    pub used_alphabet: usize,
    /// Pooled `IoC` measured from generated output.
    pub pooled_ioc: f64,
    /// `1 / pooled_ioc`.
    pub pooled_effective_states: f64,
    /// Message-weighted `1 / IoC`.
    pub message_weighted_effective_states: f64,
    /// Maximum relative error across pooled and message-weighted estimates.
    pub relative_error: f64,
    /// Longest scanned repeated isomorph in the generated fixture.
    pub longest_repeated_isomorph: Option<usize>,
}

/// Synthetic calibration table for the collision state estimator.
#[derive(Clone, Debug, PartialEq)]
pub struct StateCalibrationReport {
    /// PRNG seed used to generate every positive control.
    pub seed: u64,
    /// Calibration rows in increasing known-state order.
    pub rows: Vec<StateCalibrationRow>,
    /// Largest sampled relative error across calibration rows.
    pub max_relative_error: f64,
    /// Applied relative margin after enforcing the minimum report margin.
    pub applied_relative_margin: f64,
}

/// Complete Experiment 8 report.
#[derive(Clone, Debug, PartialEq)]
pub struct Experiment8Report {
    /// Grouping comparison rows.
    pub groupings: Vec<GroupingRow>,
    /// Natural-language reference rows.
    pub language_references: Vec<LanguageReference>,
    /// Compatibility summary derived from groupings and language references.
    pub compatibility: CompatibilityReport,
    /// Independent state-count estimate for the reading-layer stream.
    pub state_estimate: StateCountEstimateReport,
    /// Synthetic positive-control calibration for the state estimator.
    pub calibration: StateCalibrationReport,
}

/// Builds the complete Experiment 8 report.
///
/// # Errors
/// Returns [`GroupingError`] if the corpus cannot be read, language models
/// cannot be built, or synthetic calibration generation fails.
pub fn run_experiment8() -> Result<Experiment8Report, GroupingError> {
    let grids = orders::corpus_grids()?;
    let order = orders::accepted_honeycomb_order();
    let keys: Vec<&'static str> = grids.iter().map(orders::GlyphGrid::message_key).collect();
    let reading_values = orders::read_corpus_message_values(&grids, order)?;
    let orientation_messages = orientation_messages_from_values(&reading_values);
    let groupings = grouping_rows(&keys, &orientation_messages)?;
    let language_references = language_references()?;
    let compatibility = compatibility_report(&groupings, &language_references);
    let message_lengths = reading_values.iter().map(Vec::len).collect::<Vec<_>>();
    let calibration = calibrate_state_count(DEFAULT_CALIBRATION_SEED, &message_lengths)?;
    let state_estimate = state_count_estimate(
        order,
        &keys,
        &reading_values,
        calibration.applied_relative_margin,
    )?;

    Ok(Experiment8Report {
        groupings,
        language_references,
        compatibility,
        state_estimate,
        calibration,
    })
}

/// Calibrates the collision state estimator on deterministic synthetic streams.
///
/// The synthetic fixture keeps the real message lengths. For each known `N`, a
/// uniform `N`-symbol plaintext is passed through `N` deterministic rotational
/// alphabets generated from [`SplitMix64`], then only the output symbols are
/// measured.
///
/// # Errors
/// Returns [`GroupingError`] when a state count is zero, too large, or cannot
/// be sampled.
pub fn calibrate_state_count(
    seed: u64,
    message_lengths: &[usize],
) -> Result<StateCalibrationReport, GroupingError> {
    let mut rows = Vec::new();
    for (index, true_states) in CALIBRATION_STATES.iter().copied().enumerate() {
        let index_u64 = u64::try_from(index)
            .map_err(|_error| GroupingError::RandomBoundTooLarge { bound: index })?;
        let mut rng = SplitMix64::new(seed.wrapping_add(index_u64));
        let messages = synthetic_state_messages(message_lengths, true_states, &mut rng)?;
        rows.push(calibration_row(true_states, &messages)?);
    }
    let max_relative_error = rows
        .iter()
        .map(|row| row.relative_error)
        .fold(0.0, f64::max);
    Ok(StateCalibrationReport {
        seed,
        rows,
        max_relative_error,
        applied_relative_margin: f64::max(max_relative_error, MIN_CALIBRATION_MARGIN),
    })
}

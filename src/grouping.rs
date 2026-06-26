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

use crate::analysis;
use crate::generator::{self, ENGINE_MESSAGES};
use crate::glyph::{Glyph, Orientation};
use crate::isomorph::{self, IsomorphError};
use crate::language::{self, LanguageError, LanguageModel};
use crate::null::{SplitMix64, random_index_below};
use crate::orders::{self, GridError, ReadingOrder};
use crate::report::{self, Report};
use crate::trigram::TrigramValue;

const ORIENTATION_BASE: usize = 5;
const STORAGE_BASE: usize = 7;
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
        /// Message index in [`ENGINE_MESSAGES`].
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

impl From<crate::null::RandomBoundError> for GroupingError {
    fn from(error: crate::null::RandomBoundError) -> Self {
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

impl Report for Experiment8Report {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(&mut out, "Experiment 8 base-N grouping reinterpretation");
        report::appendln!(&mut out, "order: {}", self.state_estimate.order.name());
        report::appendln!(
            &mut out,
            "message lengths: {}",
            report::format_message_lengths(&self.state_estimate.message_lengths)
        );
        report::appendln!(
            &mut out,
            "boundary rule: rendered groups are non-overlapping within each message; incomplete tails are dropped and no group crosses a message join"
        );
        report::appendln!(
            &mut out,
            "storage axis: engine base-7 decoded symbols 0..=5, including delimiter 5, reported separately from rendered orientations"
        );
        report::appendln!(&mut out);
        append_grouping_summary(&mut out, self);
        report::appendln!(&mut out);
        append_grouping_message_detail(&mut out, self);
        report::appendln!(&mut out);
        append_language_reference_rows(&mut out, self);
        report::appendln!(&mut out);
        append_grouping_compatibility(&mut out, self);
        report::appendln!(&mut out);
        append_state_count_estimate(&mut out, self);
        report::appendln!(&mut out);
        append_state_count_calibration(&mut out, self);
        report::appendln!(&mut out);
        append_grouping_interpretation(&mut out, self);
        out
    }
}

fn append_grouping_summary(out: &mut String, experiment: &Experiment8Report) {
    report::appendln!(out, "grouping summary");
    report::appendln!(
        out,
        "{:<24} {:>5} {:>7} {:>6} {:>5} {:>9} {:>8} {:>10} {:>9} {:>10}",
        "grouping",
        "base",
        "symbols",
        "drop",
        "used",
        "H bits",
        "H/log2k",
        "IoC pool",
        "H msg",
        "IoC msg"
    );
    for row in &experiment.groupings {
        report::appendln!(
            out,
            "{:<24} {:>5} {:>7} {:>6} {:>5} {:>9.4} {:>8.4} {:>10.6} {:>9.4} {:>10.6}",
            row.axis.label(),
            row.axis.nominal_base(),
            row.pooled.symbols,
            row.dropped_source_symbols,
            row.pooled.used_alphabet,
            row.pooled.entropy_bits_per_symbol,
            row.pooled.normalized_entropy,
            row.pooled.ioc,
            row.message_weighted_entropy_bits_per_symbol,
            row.message_weighted_ioc
        );
    }
}

fn append_grouping_message_detail(out: &mut String, experiment: &Experiment8Report) {
    report::appendln!(out, "per-message grouping detail");
    report::appendln!(
        out,
        "{:<24} {:<6} {:>6} {:>4} {:>5} {:>9} {:>8} {:>10}",
        "grouping",
        "msg",
        "symbols",
        "drop",
        "used",
        "H bits",
        "H/log2k",
        "IoC"
    );
    for row in &experiment.groupings {
        for message in &row.messages {
            report::appendln!(
                out,
                "{:<24} {:<6} {:>6} {:>4} {:>5} {:>9.4} {:>8.4} {:>10.6}",
                row.axis.label(),
                message.message_key,
                message.stats.symbols,
                message.dropped_source_symbols,
                message.stats.used_alphabet,
                message.stats.entropy_bits_per_symbol,
                message.stats.normalized_entropy,
                message.stats.ioc
            );
        }
    }
}

fn append_language_reference_rows(out: &mut String, experiment: &Experiment8Report) {
    report::appendln!(
        out,
        "natural-language unigram references from bundled language models"
    );
    report::appendln!(
        out,
        "{:<8} {:>7} {:>8} {:>7} {:>9} {:>8} {:>10} {:>9}",
        "lang",
        "nom k",
        "obs k",
        "letters",
        "H bits",
        "H/log2k",
        "IoC",
        "1/IoC"
    );
    for reference in &experiment.language_references {
        report::appendln!(
            out,
            "{:<8} {:>7} {:>8} {:>7} {:>9.4} {:>8.4} {:>10.6} {:>9.2}",
            reference.language,
            reference.nominal_alphabet,
            reference.observed_used_alphabet,
            reference.symbols,
            reference.entropy_bits_per_symbol,
            reference.normalized_entropy,
            reference.ioc,
            reference.collision_effective_alphabet
        );
    }
}

fn append_grouping_compatibility(out: &mut String, experiment: &Experiment8Report) {
    report::appendln!(out, "language-compatibility flags");
    report::appendln!(
        out,
        "derived bands: alphabet {}..={}, entropy {:.4}..{:.4} bits",
        experiment.compatibility.alphabet_min,
        experiment.compatibility.alphabet_max,
        experiment.compatibility.entropy_min,
        experiment.compatibility.entropy_max
    );
    report::appendln!(
        out,
        "{:<24} {:>10} {:>10} {:>10}",
        "grouping",
        "alphabet",
        "entropy",
        "both"
    );
    for row in &experiment.compatibility.rows {
        let both = row.alphabet_compatible && row.entropy_compatible;
        report::appendln!(
            out,
            "{:<24} {:>10} {:>10} {:>10}",
            row.grouping_label,
            report::yes_no(row.alphabet_compatible),
            report::yes_no(row.entropy_compatible),
            report::yes_no(both)
        );
    }
    let compatible = experiment.compatibility.fully_compatible_groupings();
    if compatible.is_empty() {
        report::appendln!(out, "fully compatible groupings: none");
    } else {
        report::appendln!(out, "fully compatible groupings: {}", compatible.join(", "));
    }
    report::appendln!(
        out,
        "nearest alphabet-size match: {}",
        experiment.compatibility.nearest_alphabet_grouping
    );
}

fn append_state_count_estimate(out: &mut String, experiment: &Experiment8Report) {
    let estimate = &experiment.state_estimate;
    let collision = estimate.collision;
    report::appendln!(out, "independent collision state-count estimate");
    report::appendln!(
        out,
        "pooled IoC: {:.6}; 1/IoC: {:.2}; collision entropy: {:.4} bits",
        collision.pooled_ioc,
        collision.pooled_effective_states,
        collision.collision_entropy_bits
    );
    report::appendln!(
        out,
        "message-weighted IoC: {:.6}; 1/IoC: {:.2}; pooled Shannon entropy: {:.4} bits",
        collision.message_weighted_ioc,
        collision.message_weighted_effective_states,
        collision.pooled_entropy_bits_per_symbol
    );
    report::appendln!(
        out,
        "calibrated range: {}..{} states; contains established reading-layer size {}: {}",
        estimate.range.lower,
        estimate.range.upper,
        orders::READING_LAYER_ALPHABET_SIZE,
        report::yes_no(estimate.range.includes_83)
    );
    report::appendln!(
        out,
        "calibration margin applied: {:.1}%",
        estimate.calibration_relative_margin * 100.0
    );
    report::appendln!(
        out,
        "longest repeated isomorph in scanned k={}..={}: {}",
        grouping_state_min_window(experiment),
        grouping_state_max_window(experiment),
        estimate
            .longest_repeated_isomorph
            .map_or_else(|| "none".to_owned(), |window| window.to_string())
    );
    report::appendln!(out);
    report::appendln!(out, "isomorph/window diagnostics");
    report::appendln!(
        out,
        "{:>2} {:>8} {:>8} {:>10} {:>8} {:>12}",
        "k",
        "windows",
        "inform",
        "rep kinds",
        "max rep",
        "birthday N"
    );
    for row in &estimate.isomorph_rows {
        report::appendln!(
            out,
            "{:>2} {:>8} {:>8} {:>10} {:>8} {:>12}",
            row.window,
            row.windows,
            row.informative_windows,
            row.repeated_signature_kinds,
            row.max_repeat_count,
            format_optional_f64(row.birthday_effective_states)
        );
    }
}

fn append_state_count_calibration(out: &mut String, experiment: &Experiment8Report) {
    report::appendln!(out, "synthetic N-state positive-control calibration");
    report::appendln!(out, "seed: {}", experiment.calibration.seed);
    report::appendln!(
        out,
        "model: real message lengths, uniform N-symbol plaintext through N deterministic rotational alphabets"
    );
    report::appendln!(
        out,
        "{:>6} {:>5} {:>10} {:>10} {:>10} {:>8} {:>10}",
        "true N",
        "used",
        "IoC pool",
        "N pool",
        "N msg",
        "rel err",
        "max iso"
    );
    for row in &experiment.calibration.rows {
        report::appendln!(
            out,
            "{:>6} {:>5} {:>10.6} {:>10.2} {:>10.2} {:>8.2}% {:>10}",
            row.true_states,
            row.used_alphabet,
            row.pooled_ioc,
            row.pooled_effective_states,
            row.message_weighted_effective_states,
            row.relative_error * 100.0,
            format_optional_usize(row.longest_repeated_isomorph)
        );
    }
    report::appendln!(
        out,
        "max sampled relative error: {:.2}%; applied margin: {:.2}%",
        experiment.calibration.max_relative_error * 100.0,
        experiment.calibration.applied_relative_margin * 100.0
    );
}

fn append_grouping_interpretation(out: &mut String, experiment: &Experiment8Report) {
    let compatible = experiment.compatibility.fully_compatible_groupings();
    if compatible.is_empty() {
        report::appendln!(
            out,
            "Interpretation: no tested grouping matches both the bundled natural-language alphabet-size band and entropy band as raw plaintext. The nearest alphabet-size match is {}, but its entropy is measured separately above.",
            experiment.compatibility.nearest_alphabet_grouping
        );
    } else {
        report::appendln!(
            out,
            "Interpretation: grouping(s) matching both measured language alphabet size and entropy: {}.",
            compatible.join(", ")
        );
    }

    let range = experiment.state_estimate.range;
    let relation = if range.includes_83 {
        "overlaps"
    } else if range.upper < orders::READING_LAYER_ALPHABET_SIZE {
        "falls below"
    } else {
        "sits above"
    };
    report::appendln!(
        out,
        "The independent collision estimate gives an approximate {}..{} state range, which {relation} the established 83-symbol reading layer. This agreement check does not assume 83, and it does not decode meaning.",
        range.lower,
        range.upper
    );
    report::appendln!(
        out,
        "Near-uniform high entropy remains consistent with a permutation or other structured transformation of data, as in Experiment 4; these numbers constrain plausible encodings only."
    );
}

fn grouping_state_min_window(experiment: &Experiment8Report) -> usize {
    experiment
        .state_estimate
        .isomorph_rows
        .iter()
        .map(|row| row.window)
        .min()
        .unwrap_or_default()
}

fn grouping_state_max_window(experiment: &Experiment8Report) -> usize {
    experiment
        .state_estimate
        .isomorph_rows
        .iter()
        .map(|row| row.window)
        .max()
        .unwrap_or_default()
}

fn format_optional_f64(value: Option<f64>) -> String {
    value.map_or_else(|| "n/a".to_owned(), |number| format!("{number:.2}"))
}

fn format_optional_usize(value: Option<usize>) -> String {
    value.map_or_else(|| "none".to_owned(), |number| number.to_string())
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

fn grouping_rows(
    keys: &[&'static str],
    orientation_messages: &[Vec<Orientation>],
) -> Result<Vec<GroupingRow>, GroupingError> {
    let mut rows = Vec::new();
    for width in 1..=4 {
        let (glyph_messages, dropped) = group_orientation_messages(orientation_messages, width);
        rows.push(grouping_row(
            GroupingAxis::OrientationBase5 { width },
            keys,
            &glyph_messages,
            &dropped,
        ));
    }
    let (storage_messages, storage_dropped) = storage_messages()?;
    rows.push(grouping_row(
        GroupingAxis::EngineStorageBase7,
        keys,
        &storage_messages,
        &storage_dropped,
    ));
    Ok(rows)
}

fn grouping_row(
    axis: GroupingAxis,
    keys: &[&'static str],
    glyph_messages: &[Vec<Glyph>],
    dropped: &[usize],
) -> GroupingRow {
    let pooled_glyphs = flatten_messages(glyph_messages);
    let pooled = SymbolStats::from_glyphs(&pooled_glyphs);
    let messages = keys
        .iter()
        .copied()
        .zip(glyph_messages)
        .zip(dropped.iter().copied())
        .map(
            |((message_key, glyphs), dropped_source_symbols)| MessageGroupingStats {
                message_key,
                dropped_source_symbols,
                stats: SymbolStats::from_glyphs(glyphs),
            },
        )
        .collect::<Vec<_>>();

    GroupingRow {
        axis,
        dropped_source_symbols: dropped.iter().sum(),
        pooled,
        message_weighted_entropy_bits_per_symbol: analysis::message_weighted_entropy(
            glyph_messages,
        ),
        message_weighted_normalized_entropy: message_weighted_normalized_entropy(glyph_messages),
        message_weighted_ioc: analysis::message_weighted_index_of_coincidence(glyph_messages),
        messages,
    }
}

fn orientation_messages_from_values(message_values: &[Vec<TrigramValue>]) -> Vec<Vec<Orientation>> {
    message_values
        .iter()
        .map(|values| {
            values
                .iter()
                .copied()
                .flat_map(orientations_from_trigram_value)
                .collect()
        })
        .collect()
}

fn orientations_from_trigram_value(value: TrigramValue) -> [Orientation; 3] {
    let raw = value.get();
    let first = raw / 25;
    let second = (raw % 25) / 5;
    let third = raw % 5;
    [
        orientation_from_base5_digit(first),
        orientation_from_base5_digit(second),
        orientation_from_base5_digit(third),
    ]
}

fn orientation_from_base5_digit(digit: u8) -> Orientation {
    match digit {
        0 => Orientation::Zero,
        1 => Orientation::One,
        2 => Orientation::Two,
        3 => Orientation::Three,
        _ => Orientation::Four,
    }
}

fn group_orientation_messages(
    orientation_messages: &[Vec<Orientation>],
    width: usize,
) -> (Vec<Vec<Glyph>>, Vec<usize>) {
    let mut grouped_messages = Vec::new();
    let mut dropped = Vec::new();
    for orientations in orientation_messages {
        let mut glyphs = Vec::new();
        for chunk in orientations.chunks_exact(width) {
            glyphs.push(Glyph(group_value(chunk)));
        }
        dropped.push(orientations.len() % width);
        grouped_messages.push(glyphs);
    }
    (grouped_messages, dropped)
}

fn group_value(chunk: &[Orientation]) -> u16 {
    chunk.iter().fold(0u16, |accumulator, orientation| {
        accumulator * ORIENTATION_BASE as u16 + u16::from(orientation.digit())
    })
}

fn storage_messages() -> Result<(Vec<Vec<Glyph>>, Vec<usize>), GroupingError> {
    let mut messages = Vec::new();
    for (message_index, pairs) in ENGINE_MESSAGES.iter().enumerate() {
        let mut glyphs = Vec::new();
        for symbol in generator::decode_message(pairs) {
            if generator::storage_orientation(symbol).is_some() || symbol == 5 {
                let glyph_index = u16::try_from(symbol).map_err(|_error| {
                    GroupingError::InvalidStorageSymbol {
                        message_index,
                        symbol,
                    }
                })?;
                glyphs.push(Glyph(glyph_index));
            } else {
                return Err(GroupingError::InvalidStorageSymbol {
                    message_index,
                    symbol,
                });
            }
        }
        messages.push(glyphs);
    }
    Ok((messages, vec![0; ENGINE_MESSAGES.len()]))
}

fn language_references() -> Result<Vec<LanguageReference>, GroupingError> {
    Ok(vec![
        language_reference("English", 26, &language::english_model()?)?,
        language_reference("Finnish", 29, &language::finnish_model()?)?,
    ])
}

fn language_reference(
    language: &'static str,
    nominal_alphabet: usize,
    model: &LanguageModel,
) -> Result<LanguageReference, GroupingError> {
    let mut glyphs = Vec::new();
    for index in 0..model.alphabet().len() {
        let count = model.unigram_count(index)?;
        for _occurrence in 0..count {
            glyphs.push(Glyph(index as u16));
        }
    }
    let stats = SymbolStats::from_glyphs(&glyphs);
    Ok(LanguageReference {
        language,
        nominal_alphabet,
        observed_used_alphabet: stats.used_alphabet,
        symbols: stats.symbols,
        entropy_bits_per_symbol: stats.entropy_bits_per_symbol,
        normalized_entropy: stats.normalized_entropy,
        ioc: stats.ioc,
        collision_effective_alphabet: stats.collision_effective_alphabet,
    })
}

fn compatibility_report(
    groupings: &[GroupingRow],
    references: &[LanguageReference],
) -> CompatibilityReport {
    let min_nominal = references
        .iter()
        .map(|reference| reference.nominal_alphabet)
        .min()
        .unwrap_or_default();
    let max_nominal = references
        .iter()
        .map(|reference| reference.nominal_alphabet)
        .max()
        .unwrap_or_default();
    let span = max_nominal.saturating_sub(min_nominal);
    let alphabet_tolerance = usize::max(1, span / LANGUAGE_ALPHABET_SPAN_DIVISOR);
    let alphabet_min = min_nominal.saturating_sub(alphabet_tolerance);
    let alphabet_max = max_nominal.saturating_add(alphabet_tolerance);

    let entropy_low = references
        .iter()
        .map(|reference| reference.entropy_bits_per_symbol)
        .min_by(f64::total_cmp)
        .unwrap_or(0.0);
    let entropy_high = references
        .iter()
        .map(|reference| reference.entropy_bits_per_symbol)
        .max_by(f64::total_cmp)
        .unwrap_or(0.0);
    let entropy_tolerance = f64::max(
        entropy_high - entropy_low,
        MIN_LANGUAGE_ENTROPY_TOLERANCE_BITS,
    );
    let entropy_min = (entropy_low - entropy_tolerance).max(0.0);
    let entropy_max = entropy_high + entropy_tolerance;

    let nearest_alphabet_grouping = groupings
        .iter()
        .min_by_key(|row| nearest_reference_gap(row.pooled.used_alphabet, references))
        .map_or_else(|| "none".to_owned(), |row| row.axis.label());
    let rows = groupings
        .iter()
        .map(|row| GroupingCompatibility {
            grouping_label: row.axis.label(),
            alphabet_compatible: (alphabet_min..=alphabet_max).contains(&row.pooled.used_alphabet),
            entropy_compatible: (entropy_min..=entropy_max)
                .contains(&row.pooled.entropy_bits_per_symbol),
        })
        .collect();

    CompatibilityReport {
        alphabet_min,
        alphabet_max,
        entropy_min,
        entropy_max,
        nearest_alphabet_grouping,
        rows,
    }
}

fn nearest_reference_gap(value: usize, references: &[LanguageReference]) -> usize {
    references
        .iter()
        .map(|reference| value.abs_diff(reference.nominal_alphabet))
        .min()
        .unwrap_or(usize::MAX)
}

fn state_count_estimate(
    order: ReadingOrder,
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    calibration_relative_margin: f64,
) -> Result<StateCountEstimateReport, GroupingError> {
    let glyph_messages = orders::glyph_messages_from_values(message_values);
    let message_lengths = keys
        .iter()
        .copied()
        .zip(message_values.iter().map(Vec::len))
        .collect::<Vec<_>>();
    let collision = collision_state_estimate(&glyph_messages);
    let isomorph_rows = isomorph_state_rows(
        &glyph_messages,
        DEFAULT_STATE_MIN_WINDOW,
        DEFAULT_STATE_MAX_WINDOW,
    )?;
    let longest_repeated_isomorph = longest_repeated_isomorph(&isomorph_rows);
    let range = estimate_range(&collision, calibration_relative_margin);

    Ok(StateCountEstimateReport {
        order,
        message_lengths,
        collision,
        isomorph_rows,
        longest_repeated_isomorph,
        range,
        calibration_relative_margin,
    })
}

fn collision_state_estimate(glyph_messages: &[Vec<Glyph>]) -> CollisionStateEstimate {
    let pooled = flatten_messages(glyph_messages);
    let pooled_ioc = analysis::index_of_coincidence(&pooled);
    let message_weighted_ioc = analysis::message_weighted_index_of_coincidence(glyph_messages);
    CollisionStateEstimate {
        pooled_ioc,
        pooled_effective_states: effective_alphabet_from_ioc(pooled_ioc),
        message_weighted_ioc,
        message_weighted_effective_states: effective_alphabet_from_ioc(message_weighted_ioc),
        pooled_entropy_bits_per_symbol: analysis::shannon_entropy(&pooled),
        collision_entropy_bits: collision_entropy_bits(pooled_ioc),
    }
}

fn estimate_range(
    collision: &CollisionStateEstimate,
    calibration_relative_margin: f64,
) -> StateCountRange {
    let low_point = f64::min(
        collision.pooled_effective_states,
        collision.message_weighted_effective_states,
    );
    let high_point = f64::max(
        collision.pooled_effective_states,
        collision.message_weighted_effective_states,
    );
    let lower = rounded_floor_state_count(low_point * (1.0 - calibration_relative_margin));
    let upper =
        rounded_ceil_state_count(high_point * (1.0 + calibration_relative_margin)).max(lower);
    StateCountRange {
        lower,
        upper,
        includes_83: (lower..=upper).contains(&orders::READING_LAYER_ALPHABET_SIZE),
    }
}

#[allow(
    clippy::cast_sign_loss,
    reason = "state-count report values are finite positive estimates clamped before display rounding"
)]
fn rounded_floor_state_count(value: f64) -> usize {
    if !value.is_finite() || value <= 1.0 {
        1
    } else {
        value.floor() as usize
    }
}

#[allow(
    clippy::cast_sign_loss,
    reason = "state-count report values are finite positive estimates clamped before display rounding"
)]
fn rounded_ceil_state_count(value: f64) -> usize {
    if !value.is_finite() || value <= 1.0 {
        1
    } else {
        value.ceil() as usize
    }
}

fn calibration_row(
    true_states: usize,
    glyph_messages: &[Vec<Glyph>],
) -> Result<StateCalibrationRow, GroupingError> {
    let pooled = flatten_messages(glyph_messages);
    let stats = SymbolStats::from_glyphs(&pooled);
    let collision = collision_state_estimate(glyph_messages);
    let isomorph_rows = isomorph_state_rows(
        glyph_messages,
        DEFAULT_STATE_MIN_WINDOW,
        DEFAULT_STATE_MAX_WINDOW,
    )?;
    let longest_repeated_isomorph = longest_repeated_isomorph(&isomorph_rows);
    let relative_error = f64::max(
        relative_error(collision.pooled_effective_states, true_states),
        relative_error(collision.message_weighted_effective_states, true_states),
    );
    Ok(StateCalibrationRow {
        true_states,
        used_alphabet: stats.used_alphabet,
        pooled_ioc: collision.pooled_ioc,
        pooled_effective_states: collision.pooled_effective_states,
        message_weighted_effective_states: collision.message_weighted_effective_states,
        relative_error,
        longest_repeated_isomorph,
    })
}

fn isomorph_state_rows(
    glyph_messages: &[Vec<Glyph>],
    min_window: usize,
    max_window: usize,
) -> Result<Vec<IsomorphStateRow>, GroupingError> {
    let mut rows = Vec::new();
    for window in min_window..=max_window {
        let mut windows = 0usize;
        let mut informative_windows = 0usize;
        let mut repeated_signature_kinds = 0usize;
        let mut max_repeat_count = 0usize;
        for message in glyph_messages {
            if window > message.len() {
                continue;
            }
            windows += message.len() - window + 1;
            let detection = isomorph::detect_isomorphs(message, window, 1, 1)?;
            informative_windows += detection.informative_windows;
            repeated_signature_kinds += detection.repeated_signature_kinds();
            max_repeat_count = max_repeat_count.max(detection.max_repeat_count());
        }
        rows.push(IsomorphStateRow {
            window,
            windows,
            informative_windows,
            repeated_signature_kinds,
            max_repeat_count,
            birthday_effective_states: birthday_state_estimate(
                informative_windows,
                windows,
                window,
            ),
        });
    }
    Ok(rows)
}

fn birthday_state_estimate(
    informative_windows: usize,
    windows: usize,
    window: usize,
) -> Option<f64> {
    if windows == 0 || informative_windows == 0 {
        return None;
    }
    let repeat_rate = informative_windows as f64 / windows as f64;
    if repeat_rate >= 1.0 {
        return Some(window as f64);
    }

    let mut low = window as f64;
    let mut high = f64::max(low * 2.0, 2.0);
    while birthday_repeat_probability(high, window) > repeat_rate {
        high *= 2.0;
    }
    for _iteration in 0..80 {
        let midpoint = f64::midpoint(low, high);
        if birthday_repeat_probability(midpoint, window) > repeat_rate {
            low = midpoint;
        } else {
            high = midpoint;
        }
    }
    Some(high)
}

fn birthday_repeat_probability(states: f64, window: usize) -> f64 {
    if states <= 1.0 {
        return 1.0;
    }
    let mut unique_probability = 1.0;
    for offset in 0..window {
        let remaining = states - offset as f64;
        if remaining <= 0.0 {
            return 1.0;
        }
        unique_probability *= remaining / states;
    }
    1.0 - unique_probability
}

fn synthetic_state_messages(
    message_lengths: &[usize],
    state_count: usize,
    rng: &mut SplitMix64,
) -> Result<Vec<Vec<Glyph>>, GroupingError> {
    if state_count == 0 {
        return Err(GroupingError::ZeroStateCount);
    }
    if state_count > usize::from(u16::MAX) + 1 {
        return Err(GroupingError::StateCountTooLarge { state_count });
    }

    let mut shifts = Vec::new();
    for _state in 0..state_count {
        shifts.push(random_index_below(state_count, rng)?);
    }

    let mut messages = Vec::new();
    for &length in message_lengths {
        let mut message = Vec::new();
        for position in 0..length {
            let plaintext = random_index_below(state_count, rng)?;
            let state = position % state_count;
            let shift = shifts
                .get(state)
                .copied()
                .ok_or(GroupingError::StateCountTooLarge { state_count })?;
            let symbol = (plaintext + shift) % state_count;
            let glyph = u16::try_from(symbol)
                .map(Glyph)
                .map_err(|_error| GroupingError::StateCountTooLarge { state_count })?;
            message.push(glyph);
        }
        messages.push(message);
    }
    Ok(messages)
}

fn flatten_messages(glyph_messages: &[Vec<Glyph>]) -> Vec<Glyph> {
    glyph_messages.iter().flatten().copied().collect()
}

/// Longest scanned window that still contains a repeated isomorph signature.
fn longest_repeated_isomorph(rows: &[IsomorphStateRow]) -> Option<usize> {
    rows.iter()
        .filter(|row| row.repeated_signature_kinds > 0)
        .map(|row| row.window)
        .max()
}

fn message_weighted_normalized_entropy(glyph_messages: &[Vec<Glyph>]) -> f64 {
    let mut weighted = 0.0;
    let mut total = 0usize;
    for glyphs in glyph_messages {
        let len = glyphs.len();
        if len == 0 {
            continue;
        }
        weighted += normalized_shannon_entropy(glyphs) * len as f64;
        total += len;
    }
    if total == 0 {
        0.0
    } else {
        weighted / total as f64
    }
}

/// Shannon entropy of `glyphs` normalized by `log2` of the number of distinct
/// glyphs observed. This is the same quantity as the per-message
/// `normalized_entropy` field, computed directly so the message-weighted
/// aggregate skips the index-of-coincidence pass that `from_glyphs` also runs.
fn normalized_shannon_entropy(glyphs: &[Glyph]) -> f64 {
    normalized_entropy(
        analysis::shannon_entropy(glyphs),
        analysis::frequencies(glyphs).len(),
    )
}

fn normalized_entropy(entropy_bits: f64, used_alphabet: usize) -> f64 {
    if used_alphabet <= 1 {
        0.0
    } else {
        entropy_bits / (used_alphabet as f64).log2()
    }
}

fn effective_alphabet_from_ioc(ioc: f64) -> f64 {
    if ioc <= 0.0 { f64::INFINITY } else { 1.0 / ioc }
}

fn collision_entropy_bits(ioc: f64) -> f64 {
    if ioc <= 0.0 {
        f64::INFINITY
    } else {
        -ioc.log2()
    }
}

fn relative_error(estimate: f64, true_states: usize) -> f64 {
    let true_value = true_states as f64;
    (estimate - true_value).abs() / true_value
}

fn pow_usize(base: usize, exponent: usize) -> usize {
    let mut value = 1usize;
    for _power in 0..exponent {
        value = value.saturating_mul(base);
    }
    value
}

#[cfg(test)]
mod tests {
    use super::{
        CALIBRATION_STATES, GroupingAxis, calibrate_state_count, run_experiment8,
        synthetic_state_messages,
    };
    use crate::analysis;
    use crate::null::SplitMix64;

    fn grouping(report: &super::Experiment8Report, axis: GroupingAxis) -> &super::GroupingRow {
        report
            .groupings
            .iter()
            .find(|row| row.axis == axis)
            .unwrap()
    }

    #[test]
    fn grouping_report_preserves_experiment_4_trigram_anchor() {
        let report = run_experiment8().unwrap();
        let trigram = grouping(&report, GroupingAxis::OrientationBase5 { width: 3 });
        assert_eq!(trigram.axis.nominal_base(), 125);
        assert_eq!(trigram.pooled.symbols, 1036);
        assert_eq!(trigram.pooled.used_alphabet, 83);
        assert_eq!(trigram.dropped_source_symbols, 0);
        assert!(
            (trigram.pooled.entropy_bits_per_symbol - 6.272_507_154_513_793).abs() < 1e-12,
            "trigram entropy changed: {}",
            trigram.pooled.entropy_bits_per_symbol
        );
        assert!(
            (trigram.pooled.ioc * 83.0 - 1.066_043_683_434_987_8).abs() < 1e-12,
            "trigram concatenated x83 IoC changed: {}",
            trigram.pooled.ioc * 83.0
        );
    }

    #[test]
    fn grouping_numbers_are_deterministic_across_axes() {
        let report = run_experiment8().unwrap();
        let singles = grouping(&report, GroupingAxis::OrientationBase5 { width: 1 });
        let pairs = grouping(&report, GroupingAxis::OrientationBase5 { width: 2 });
        let tetragrams = grouping(&report, GroupingAxis::OrientationBase5 { width: 4 });
        let storage = grouping(&report, GroupingAxis::EngineStorageBase7);

        assert_eq!(singles.pooled.used_alphabet, 5);
        assert_eq!(singles.pooled.symbols, 3108);
        assert_eq!(pairs.pooled.used_alphabet, 25);
        assert_eq!(pairs.pooled.symbols, 1552);
        assert_eq!(pairs.dropped_source_symbols, 4);
        assert_eq!(tetragrams.pooled.used_alphabet, 375);
        assert_eq!(tetragrams.pooled.symbols, 774);
        assert_eq!(tetragrams.dropped_source_symbols, 12);
        assert_eq!(storage.pooled.used_alphabet, 6);
        assert_eq!(storage.pooled.symbols, 3194);
    }

    #[test]
    fn compatibility_is_derived_from_language_references() {
        let report = run_experiment8().unwrap();
        assert_eq!(report.language_references.len(), 2);
        assert_eq!(
            report.compatibility.nearest_alphabet_grouping,
            "pairs N=2 base25"
        );
        let fully_compatible = report.compatibility.fully_compatible_groupings();
        assert!(fully_compatible.is_empty());
        let pair_row = report
            .compatibility
            .rows
            .iter()
            .find(|row| row.grouping_label == "pairs N=2 base25")
            .unwrap();
        assert!(pair_row.alphabet_compatible);
        assert!(!pair_row.entropy_compatible);
    }

    #[test]
    fn state_count_estimate_is_collision_based_and_compares_to_83() {
        let report = run_experiment8().unwrap();
        let estimate = &report.state_estimate;
        assert!(estimate.range.includes_83);
        assert!(estimate.range.lower < 83);
        assert!(estimate.range.upper > 83);
        assert!(
            (estimate.collision.pooled_effective_states - 77.857_972_698_228_3).abs() < 1e-12,
            "pooled state estimate changed: {}",
            estimate.collision.pooled_effective_states
        );
        assert!(
            (estimate.collision.message_weighted_effective_states - 85.410_586_552_217_45).abs()
                < 1e-12,
            "message-weighted state estimate changed: {}",
            estimate.collision.message_weighted_effective_states
        );
        assert_eq!(estimate.longest_repeated_isomorph, Some(8));
    }

    #[test]
    fn calibration_tracks_known_state_counts_without_using_used_count_as_estimate() {
        let message_lengths = [99, 103, 118, 102, 137, 124, 119, 120, 114];
        let calibration = calibrate_state_count(0x6578_7038_7374_6174, &message_lengths).unwrap();
        let true_states: Vec<usize> = calibration.rows.iter().map(|row| row.true_states).collect();
        assert_eq!(true_states, CALIBRATION_STATES);
        assert!(calibration.applied_relative_margin < 0.12);
        for row in &calibration.rows {
            assert!(
                row.relative_error < 0.12,
                "state {} estimate drifted too far: pooled {}, message {}",
                row.true_states,
                row.pooled_effective_states,
                row.message_weighted_effective_states
            );
            assert!(
                (row.pooled_effective_states - (1.0 / row.pooled_ioc)).abs() < 1e-12,
                "state {} estimate is not derived from measured IoC",
                row.true_states
            );
            assert!(
                (row.pooled_ioc - (1.0 / row.true_states as f64)).abs() > 1e-8,
                "state {} fixture looks degenerate: measured IoC equals construction floor",
                row.true_states
            );
        }
        for pair in calibration.rows.windows(2) {
            let [left, right] = pair else {
                continue;
            };
            assert!(left.pooled_effective_states < right.pooled_effective_states);
        }
    }

    #[test]
    fn synthetic_fixture_estimator_is_measured_from_generated_symbols() {
        let lengths = [40, 41, 42];
        let mut rng = SplitMix64::new(0x5eed);
        let messages = synthetic_state_messages(&lengths, 25, &mut rng).unwrap();
        let pooled: Vec<_> = messages.iter().flatten().copied().collect();
        let ioc = analysis::index_of_coincidence(&pooled);
        assert!(ioc > 0.0);
        let measured = 1.0 / ioc;
        assert!(measured > 18.0);
        assert!(measured < 34.0);
        assert!((measured - 25.0).abs() > 0.01);
    }
}

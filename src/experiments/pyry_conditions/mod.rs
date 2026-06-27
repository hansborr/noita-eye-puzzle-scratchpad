//! Pyry's Conditions falsification harness.
//!
//! This module turns the community checklist known as "Pyry's Conditions" into
//! explicit predicates over per-message accepted-order trigram-value streams.
//! The predicates are structural: they never score language, never infer a
//! symbol-to-meaning mapping, and never re-select a reading order.
//!
//! The harness evaluates the verified eye corpus once, then evaluates
//! deterministic generated fixtures from named cipher families over the same
//! per-message lengths. Fixture rows are controls for structural
//! discrimination, not attempted decodes.

use std::fmt;

use crate::analysis::orders::{
    self, GlyphGrid, GridError, ReadingOrder, read_corpus_message_values,
};
use crate::ciphers;
use crate::core::glyph::Glyph;
use crate::core::trigram::TrigramValue;
use crate::nulls::perseus;

use conditions::condition_metrics;
use fixtures::evaluate_generated_families;

mod conditions;
mod fixtures;
mod report;
#[cfg(test)]
mod tests;

/// Default deterministic seed for generated fixture sampling.
pub const DEFAULT_SEED: u64 = 0x7079_7279_636f_6e64;
/// Default generated fixture draws per cipher family.
pub const DEFAULT_FIXTURE_DRAWS: usize = 24;
/// Fixed accepted reading-layer alphabet size, values `0..=82`.
pub const ALPHABET_SIZE: usize = orders::READING_LAYER_ALPHABET_SIZE;
/// Maximum normalized pooled `IoC` accepted as "near the random floor".
pub const FLAT_IOC_NORMALIZED_CEILING: f64 = 1.12;
/// Minimum same-offset run length counted as a shared section.
pub const MIN_SHARED_RUN_LEN: usize = perseus::MIN_SHARED_RUN_LEN;
/// Period used by the generated Vigenere control family.
pub const VIGENERE_PERIOD: usize = 7;
/// Incrementing-wheel step used by the generated wheel control family.
pub const WHEEL_STEP: usize = 17;

const SHARED_PREFIX: [usize; 24] = [
    66, 5, 17, 42, 9, 31, 54, 12, 38, 70, 21, 46, 3, 58, 24, 75, 11, 36, 62, 28, 80, 14, 49, 7,
];
const MOTIF_STARTS: [usize; 3] = [40, 61, 82];
const MOTIF_PREDECESSORS: [usize; 3] = [2, 25, 48];
const MOTIF_EXACT_A: [usize; 6] = [4, 18, 29, 4, 51, 18];
const MOTIF_EXACT_B: [usize; 6] = [27, 41, 52, 27, 74, 41];
const MOTIF_NEAR: [usize; 6] = [50, 64, 75, 50, 14, 36];
const VIGENERE_SHIFTS: [usize; VIGENERE_PERIOD] = [3, 41, 12, 64, 5, 28, 77];
/// Configuration for the Pyry's Conditions falsification harness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PyryConditionsConfig {
    /// Explicit deterministic PRNG seed for generated fixtures.
    pub seed: u64,
    /// Number of generated plaintext/key draws per candidate family.
    pub fixture_draws: usize,
}

impl Default for PyryConditionsConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_SEED,
            fixture_draws: DEFAULT_FIXTURE_DRAWS,
        }
    }
}

/// Error returned by the Pyry's Conditions harness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PyryConditionsError {
    /// The verified corpus could not be reconstructed or read.
    Grid(GridError),
    /// At least one generated fixture draw is required.
    ZeroFixtureDraws,
    /// A generated fixture cipher could not be constructed or translated.
    Cipher(ciphers::CipherError),
    /// A random draw bound did not fit the deterministic PRNG helper.
    RandomBoundTooLarge {
        /// Requested exclusive upper bound.
        bound: usize,
    },
    /// A generated glyph was outside the fixed `0..82` reading alphabet.
    GeneratedSymbolOutsideAlphabet {
        /// Offending glyph.
        symbol: Glyph,
        /// Fixed reading alphabet size.
        alphabet_size: usize,
    },
}

impl From<GridError> for PyryConditionsError {
    fn from(value: GridError) -> Self {
        Self::Grid(value)
    }
}

impl From<ciphers::CipherError> for PyryConditionsError {
    fn from(value: ciphers::CipherError) -> Self {
        Self::Cipher(value)
    }
}

impl From<crate::nulls::null::RandomBoundError> for PyryConditionsError {
    fn from(error: crate::nulls::null::RandomBoundError) -> Self {
        Self::RandomBoundTooLarge { bound: error.bound }
    }
}

impl fmt::Display for PyryConditionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Grid(grid_error) => write!(f, "grid/order error: {grid_error:?}"),
            Self::ZeroFixtureDraws => {
                write!(f, "at least one generated fixture draw is required")
            }
            Self::Cipher(cipher_error) => {
                write!(f, "generated fixture cipher error: {cipher_error}")
            }
            Self::RandomBoundTooLarge { bound } => {
                write!(f, "random draw bound {bound} is too large")
            }
            Self::GeneratedSymbolOutsideAlphabet {
                symbol,
                alphabet_size,
            } => write!(
                f,
                "generated symbol {symbol} is outside alphabet size {alphabet_size}"
            ),
        }
    }
}

impl std::error::Error for PyryConditionsError {}

/// One of the nine machine-encoded Pyry conditions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PyryCondition {
    /// `IoC` is near the fixed 83-symbol random floor.
    FlatIoc,
    /// The observed value set is exactly contiguous `0..=82`.
    ContiguousAlphabet,
    /// Same-offset shared runs exist across messages.
    AlignedSharedSections,
    /// Repeated first-occurrence isomorph signatures exist.
    IsomorphsPresent,
    /// A shared run exists whose immediately preceding symbols differ.
    SharedAfterVaryingPrefix,
    /// Near-isomorph signatures with one differing signature position exist.
    NearIsomorphsPresent,
    /// A pair has differing first values and a shared following value.
    DifferingFirstSharedSecond,
    /// No message contains adjacent equal trigram values.
    NoDoubledTrigrams,
    /// Non-shared repeated isomorph signatures do not repeat exact values.
    NonSharedIsomorphsDiffer,
}

impl PyryCondition {
    /// Returns all nine conditions in checklist order.
    #[must_use]
    pub const fn all() -> [Self; CONDITION_COUNT] {
        [
            Self::FlatIoc,
            Self::ContiguousAlphabet,
            Self::AlignedSharedSections,
            Self::IsomorphsPresent,
            Self::SharedAfterVaryingPrefix,
            Self::NearIsomorphsPresent,
            Self::DifferingFirstSharedSecond,
            Self::NoDoubledTrigrams,
            Self::NonSharedIsomorphsDiffer,
        ]
    }

    /// One-based checklist number.
    #[must_use]
    pub const fn number(self) -> usize {
        match self {
            Self::FlatIoc => 1,
            Self::ContiguousAlphabet => 2,
            Self::AlignedSharedSections => 3,
            Self::IsomorphsPresent => 4,
            Self::SharedAfterVaryingPrefix => 5,
            Self::NearIsomorphsPresent => 6,
            Self::DifferingFirstSharedSecond => 7,
            Self::NoDoubledTrigrams => 8,
            Self::NonSharedIsomorphsDiffer => 9,
        }
    }

    /// Short matrix column label.
    #[must_use]
    pub const fn short_label(self) -> &'static str {
        match self {
            Self::FlatIoc => "C1",
            Self::ContiguousAlphabet => "C2",
            Self::AlignedSharedSections => "C3",
            Self::IsomorphsPresent => "C4",
            Self::SharedAfterVaryingPrefix => "C5",
            Self::NearIsomorphsPresent => "C6",
            Self::DifferingFirstSharedSecond => "C7",
            Self::NoDoubledTrigrams => "C8",
            Self::NonSharedIsomorphsDiffer => "C9",
        }
    }

    /// Human-readable condition label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::FlatIoc => "flat IoC",
            Self::ContiguousAlphabet => "0..82 support",
            Self::AlignedSharedSections => "aligned shared runs",
            Self::IsomorphsPresent => "isomorphs",
            Self::SharedAfterVaryingPrefix => "shared after varying prefix",
            Self::NearIsomorphsPresent => "near-isomorphs",
            Self::DifferingFirstSharedSecond => "differing first, shared second",
            Self::NoDoubledTrigrams => "no doubled trigrams",
            Self::NonSharedIsomorphsDiffer => "non-shared isomorphs differ",
        }
    }
}

/// Number of encoded Pyry conditions.
pub const CONDITION_COUNT: usize = 9;

/// Boolean vector for the nine Pyry conditions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConditionVector {
    passed: [bool; CONDITION_COUNT],
}

impl ConditionVector {
    /// Builds a condition vector from checklist-ordered booleans.
    #[must_use]
    pub const fn new(passed: [bool; CONDITION_COUNT]) -> Self {
        Self { passed }
    }

    /// Returns the result for one condition.
    #[must_use]
    pub fn get(self, condition: PyryCondition) -> bool {
        self.passed
            .get(condition.number().saturating_sub(1))
            .copied()
            .unwrap_or(false)
    }

    /// Returns the checklist-ordered booleans.
    #[must_use]
    pub const fn as_array(self) -> [bool; CONDITION_COUNT] {
        self.passed
    }

    /// Returns `true` when all nine conditions pass.
    #[must_use]
    pub fn all_pass(self) -> bool {
        self.passed.iter().all(|passed| *passed)
    }

    /// Number of passed conditions.
    #[must_use]
    pub fn passed_count(self) -> usize {
        self.passed.iter().filter(|passed| **passed).count()
    }
}

/// Scalar diagnostics used to justify a [`ConditionVector`].
#[derive(Clone, Debug, PartialEq)]
pub struct ConditionMetrics {
    /// Number of messages in the evaluated corpus.
    pub message_count: usize,
    /// Total trigram values across all messages.
    pub total_symbols: usize,
    /// Pooled index of coincidence over the flattened stream.
    pub pooled_ioc: f64,
    /// Pooled `IoC` divided by the fixed `1/83` random floor.
    pub normalized_ioc: f64,
    /// Number of distinct in-alphabet values observed.
    pub distinct_in_alphabet: usize,
    /// Number of observed values greater than `82`.
    pub outside_alphabet: usize,
    /// Smallest observed raw trigram value, if any.
    pub min_value: Option<u8>,
    /// Largest observed raw trigram value, if any.
    pub max_value: Option<u8>,
    /// Number of same-offset shared runs of length at least two.
    pub shared_run_count: usize,
    /// Longest same-offset shared run length.
    pub longest_shared_run: usize,
    /// Number of same-offset shared runs after differing preceding values.
    pub varying_prefix_shared_runs: usize,
    /// Number of repeated informative isomorph signature groups.
    pub repeated_isomorph_groups: usize,
    /// Longest scanned window length with a repeated isomorph signature.
    pub longest_repeated_isomorph: Option<usize>,
    /// Number of one-signature-position near-isomorph pairs.
    pub near_isomorph_pairs: usize,
    /// Number of pairwise differing-first/shared-second cases.
    pub differing_first_shared_second_cases: usize,
    /// Count of adjacent equal values inside message boundaries.
    pub adjacent_equal_count: usize,
    /// Number of repeated isomorph-signature groups wholly outside shared runs.
    pub non_shared_isomorph_groups: usize,
    /// Non-shared isomorph groups that also repeat exact value windows.
    pub non_shared_exact_duplicate_groups: usize,
}

/// Condition evaluation for one real or generated corpus.
#[derive(Clone, Debug, PartialEq)]
pub struct ConditionEvaluation {
    /// Human-readable row label.
    pub label: String,
    /// Checklist-ordered boolean condition vector.
    pub vector: ConditionVector,
    /// Scalar diagnostics supporting the condition vector.
    pub metrics: ConditionMetrics,
}

/// Candidate cipher family used for generated structural fixtures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CandidateFamily {
    /// One-to-one permutation substitution over the 83-symbol alphabet.
    MonoalphabeticSubstitution,
    /// Periodic additive Vigenere over the 83-symbol alphabet.
    PeriodicVigenere,
    /// Plaintext-autokey additive self-modifying cipher.
    AutokeyAlbertiStyle,
    /// Generalized `S_83` deck-keystream cipher.
    DeckS83Permutation,
    /// Additive incrementing wheel with per-message starts.
    IncrementingWheel,
}

impl CandidateFamily {
    /// Returns all generated fixture families in report order.
    #[must_use]
    pub const fn all() -> [Self; 5] {
        [
            Self::MonoalphabeticSubstitution,
            Self::PeriodicVigenere,
            Self::AutokeyAlbertiStyle,
            Self::DeckS83Permutation,
            Self::IncrementingWheel,
        ]
    }

    /// Stable report label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MonoalphabeticSubstitution => "monoalphabetic",
            Self::PeriodicVigenere => "periodic Vigenere",
            Self::AutokeyAlbertiStyle => "autokey/Alberti",
            Self::DeckS83Permutation => "deck/S83",
            Self::IncrementingWheel => "incrementing wheel",
        }
    }

    const fn seed_tag(self) -> u64 {
        match self {
            Self::MonoalphabeticSubstitution => 0x6d6f_6e6f_0000_0083,
            Self::PeriodicVigenere => 0x7669_6765_6e65_7265,
            Self::AutokeyAlbertiStyle => 0x6175_746f_6b65_7983,
            Self::DeckS83Permutation => 0x6465_636b_0000_0083,
            Self::IncrementingWheel => 0x7768_6565_6c00_0083,
        }
    }
}

/// One generated fixture draw for a candidate family.
#[derive(Clone, Debug, PartialEq)]
pub struct FixtureDrawReport {
    /// Zero-based draw index.
    pub draw_index: usize,
    /// Known key summary for this generated fixture.
    pub key_summary: String,
    /// Condition evaluation for this fixture ciphertext.
    pub evaluation: ConditionEvaluation,
}

/// Stability summary for one candidate family.
#[derive(Clone, Debug, PartialEq)]
pub struct FamilyFixtureReport {
    /// Candidate family that generated these fixtures.
    pub family: CandidateFamily,
    /// Generated fixture draws.
    pub draws: Vec<FixtureDrawReport>,
    /// Per-condition pass counts over [`Self::draws`].
    pub condition_pass_counts: [usize; CONDITION_COUNT],
    /// Number of draws satisfying all nine conditions jointly.
    pub all_conditions_pass_count: usize,
}

/// Complete Pyry's Conditions report.
#[derive(Clone, Debug, PartialEq)]
pub struct PyryConditionsReport {
    /// Configuration used for the run.
    pub config: PyryConditionsConfig,
    /// Reading order used for the eye stream.
    pub order: ReadingOrder,
    /// Per-message stream lengths in corpus order.
    pub message_lengths: Vec<(&'static str, usize)>,
    /// Total number of eye reading-layer symbols.
    pub total_length: usize,
    /// Eye-corpus condition evaluation.
    pub eyes: ConditionEvaluation,
    /// Generated fixture evaluations by candidate family.
    pub families: Vec<FamilyFixtureReport>,
}

/// Runs Pyry's Conditions on the verified eye corpus and generated fixtures.
///
/// # Errors
/// Returns [`PyryConditionsError`] when the corpus cannot be reconstructed, the
/// configuration is invalid, or a generated fixture cipher fails.
pub fn run_pyry_conditions(
    config: PyryConditionsConfig,
) -> Result<PyryConditionsReport, PyryConditionsError> {
    validate_config(config)?;
    let grids = orders::corpus_grids()?;
    let keys = grids.iter().map(GlyphGrid::message_key).collect::<Vec<_>>();
    let order = orders::accepted_honeycomb_order();
    let eye_values = read_corpus_message_values(&grids, order)?;
    let message_lengths = eye_values.iter().map(Vec::len).collect::<Vec<_>>();
    let total_length = message_lengths.iter().sum();
    let eyes = evaluate_corpus("eyes", &eye_values);
    let families = evaluate_generated_families(config, &message_lengths)?;

    Ok(PyryConditionsReport {
        config,
        order,
        message_lengths: keys.iter().copied().zip(message_lengths).collect(),
        total_length,
        eyes,
        families,
    })
}

/// Evaluates the nine Pyry conditions over arbitrary per-message value streams.
#[must_use]
pub fn evaluate_corpus(
    label: impl Into<String>,
    message_values: &[Vec<TrigramValue>],
) -> ConditionEvaluation {
    let metrics = condition_metrics(message_values);
    let vector = ConditionVector::new([
        metrics.outside_alphabet == 0 && metrics.normalized_ioc <= FLAT_IOC_NORMALIZED_CEILING,
        metrics.outside_alphabet == 0
            && metrics.distinct_in_alphabet == ALPHABET_SIZE
            && metrics.min_value == Some(0)
            && metrics.max_value == Some((ALPHABET_SIZE - 1) as u8),
        metrics.shared_run_count > 0,
        metrics.repeated_isomorph_groups > 0,
        metrics.varying_prefix_shared_runs > 0,
        metrics.near_isomorph_pairs > 0,
        metrics.differing_first_shared_second_cases > 0,
        metrics.adjacent_equal_count == 0,
        metrics.non_shared_isomorph_groups > 0 && metrics.non_shared_exact_duplicate_groups == 0,
    ]);

    ConditionEvaluation {
        label: label.into(),
        vector,
        metrics,
    }
}

fn validate_config(config: PyryConditionsConfig) -> Result<(), PyryConditionsError> {
    if config.fixture_draws == 0 {
        return Err(PyryConditionsError::ZeroFixtureDraws);
    }
    Ok(())
}

fn glyphs_to_values(glyphs: &[Glyph]) -> Result<Vec<TrigramValue>, PyryConditionsError> {
    let mut values = Vec::with_capacity(glyphs.len());
    for glyph in glyphs {
        let symbol = glyph_symbol(*glyph)?;
        values.push(TrigramValue::new(symbol as u8).map_err(|_value| {
            PyryConditionsError::GeneratedSymbolOutsideAlphabet {
                symbol: *glyph,
                alphabet_size: ALPHABET_SIZE,
            }
        })?);
    }
    Ok(values)
}

fn glyph_symbol(glyph: Glyph) -> Result<usize, PyryConditionsError> {
    let symbol = usize::from(glyph.0);
    if symbol >= ALPHABET_SIZE {
        return Err(PyryConditionsError::GeneratedSymbolOutsideAlphabet {
            symbol: glyph,
            alphabet_size: ALPHABET_SIZE,
        });
    }
    Ok(symbol)
}

fn glyphs_from_values(values: &[TrigramValue]) -> Vec<Glyph> {
    values
        .iter()
        .map(|value| Glyph(u16::from(value.get())))
        .collect()
}

fn flatten_values(message_values: &[Vec<TrigramValue>]) -> Vec<TrigramValue> {
    message_values.iter().flatten().copied().collect()
}

fn render_usize_list(values: &[usize]) -> String {
    values
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

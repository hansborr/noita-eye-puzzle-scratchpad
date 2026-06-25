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

use std::collections::{BTreeMap, BTreeSet};

use crate::analysis;
use crate::ciphers::{
    self, DeckCipherKey, IncrementingWheelKey, VigenereKey, deck_cipher_encrypt,
    incrementing_wheel_encrypt, vigenere_encrypt,
};
use crate::glyph::Glyph;
use crate::isomorph::{self, PatternSignature};
use crate::isomorph_null::{DEFAULT_MAX_WINDOW, DEFAULT_MIN_WINDOW};
use crate::null::{
    SplitMix64, mix_seed, random_index_below, shuffled_permutation, stateless_splitmix,
};
use crate::orders::{self, GlyphGrid, GridError, ReadingOrder, read_corpus_message_values};
use crate::perseus;
use crate::trigram::TrigramValue;

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

impl From<crate::null::RandomBoundError> for PyryConditionsError {
    fn from(error: crate::null::RandomBoundError) -> Self {
        Self::RandomBoundTooLarge { bound: error.bound }
    }
}

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

fn condition_metrics(message_values: &[Vec<TrigramValue>]) -> ConditionMetrics {
    let flattened = flatten_values(message_values);
    let total_symbols = flattened.len();
    let pooled_ioc = analysis::index_of_coincidence(&glyphs_from_values(&flattened));
    let normalized_ioc = pooled_ioc * ALPHABET_SIZE as f64;
    let support = support_metrics(&flattened);
    let shared_runs = same_offset_shared_runs(message_values, MIN_SHARED_RUN_LEN);
    let shared_masks = shared_masks(message_values, &shared_runs);
    let isomorphs = isomorph_metrics(message_values);
    let non_shared_isomorphs = non_shared_isomorph_metrics(message_values, &shared_masks);

    ConditionMetrics {
        message_count: message_values.len(),
        total_symbols,
        pooled_ioc,
        normalized_ioc,
        distinct_in_alphabet: support.distinct_in_alphabet,
        outside_alphabet: support.outside_alphabet,
        min_value: support.min_value,
        max_value: support.max_value,
        shared_run_count: shared_runs.len(),
        longest_shared_run: shared_runs
            .iter()
            .map(|run| run.len)
            .max()
            .unwrap_or_default(),
        varying_prefix_shared_runs: shared_runs
            .iter()
            .filter(|run| run.preceding_values_differ)
            .count(),
        repeated_isomorph_groups: isomorphs.repeated_groups,
        longest_repeated_isomorph: isomorphs.longest_repeated_window,
        near_isomorph_pairs: near_isomorph_pair_count(message_values),
        differing_first_shared_second_cases: differing_first_shared_second_cases(message_values),
        adjacent_equal_count: adjacent_equal_count(message_values),
        non_shared_isomorph_groups: non_shared_isomorphs.repeated_groups,
        non_shared_exact_duplicate_groups: non_shared_isomorphs.exact_duplicate_groups,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SupportMetrics {
    distinct_in_alphabet: usize,
    outside_alphabet: usize,
    min_value: Option<u8>,
    max_value: Option<u8>,
}

fn support_metrics(values: &[TrigramValue]) -> SupportMetrics {
    let mut seen = [false; ALPHABET_SIZE];
    let mut outside_alphabet = 0usize;
    let mut min_value = None;
    let mut max_value = None;
    for value in values {
        let raw = value.get();
        min_value = Some(min_value.map_or(raw, |current: u8| current.min(raw)));
        max_value = Some(max_value.map_or(raw, |current: u8| current.max(raw)));
        let raw_usize = usize::from(raw);
        if let Some(slot) = seen.get_mut(raw_usize) {
            *slot = true;
        } else {
            outside_alphabet += 1;
        }
    }
    SupportMetrics {
        distinct_in_alphabet: seen.iter().filter(|present| **present).count(),
        outside_alphabet,
        min_value,
        max_value,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SharedRun {
    left_index: usize,
    right_index: usize,
    start: usize,
    len: usize,
    preceding_values_differ: bool,
}

fn same_offset_shared_runs(message_values: &[Vec<TrigramValue>], min_len: usize) -> Vec<SharedRun> {
    let mut runs = Vec::new();
    for (left_index, left_values) in message_values.iter().enumerate() {
        for (right_index, right_values) in message_values.iter().enumerate().skip(left_index + 1) {
            collect_shared_runs_for_pair(
                &mut runs,
                PairInput {
                    left_index,
                    right_index,
                    left_values,
                    right_values,
                    min_len,
                },
            );
        }
    }
    runs
}

#[derive(Clone, Copy)]
struct PairInput<'a> {
    left_index: usize,
    right_index: usize,
    left_values: &'a [TrigramValue],
    right_values: &'a [TrigramValue],
    min_len: usize,
}

fn collect_shared_runs_for_pair(runs: &mut Vec<SharedRun>, input: PairInput<'_>) {
    let mut active_start = None;
    let mut active_len = 0usize;
    for (position, (left, right)) in input.left_values.iter().zip(input.right_values).enumerate() {
        if left == right {
            if active_start.is_none() {
                active_start = Some(position);
            }
            active_len += 1;
        } else {
            push_shared_run(runs, input, active_start, active_len);
            active_start = None;
            active_len = 0;
        }
    }
    push_shared_run(runs, input, active_start, active_len);
}

fn push_shared_run(
    runs: &mut Vec<SharedRun>,
    input: PairInput<'_>,
    start: Option<usize>,
    len: usize,
) {
    let Some(start) = start else {
        return;
    };
    if len < input.min_len {
        return;
    }
    runs.push(SharedRun {
        left_index: input.left_index,
        right_index: input.right_index,
        start,
        len,
        preceding_values_differ: preceding_values_differ(
            input.left_values,
            input.right_values,
            start,
        ),
    });
}

fn preceding_values_differ(left: &[TrigramValue], right: &[TrigramValue], start: usize) -> bool {
    let Some(previous_position) = start.checked_sub(1) else {
        return false;
    };
    left.get(previous_position).copied() != right.get(previous_position).copied()
}

fn shared_masks(message_values: &[Vec<TrigramValue>], runs: &[SharedRun]) -> Vec<Vec<bool>> {
    let mut masks = message_values
        .iter()
        .map(|message| vec![false; message.len()])
        .collect::<Vec<_>>();
    for run in runs {
        mark_shared_run(&mut masks, run.left_index, run.start, run.len);
        mark_shared_run(&mut masks, run.right_index, run.start, run.len);
    }
    masks
}

fn mark_shared_run(masks: &mut [Vec<bool>], message_index: usize, start: usize, len: usize) {
    let Some(mask) = masks.get_mut(message_index) else {
        return;
    };
    for slot in mask.iter_mut().skip(start).take(len) {
        *slot = true;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IsomorphMetrics {
    repeated_groups: usize,
    longest_repeated_window: Option<usize>,
}

fn isomorph_metrics(message_values: &[Vec<TrigramValue>]) -> IsomorphMetrics {
    let mut repeated_groups = 0usize;
    let mut longest_repeated_window = None;
    for message in message_values {
        for window in DEFAULT_MIN_WINDOW..=DEFAULT_MAX_WINDOW {
            if window > message.len() {
                continue;
            }
            let Ok(detection) = isomorph::detect_isomorphs(message, window, 1, 1) else {
                continue;
            };
            let groups = detection.repeated_signature_kinds();
            if groups > 0 {
                repeated_groups += groups;
                longest_repeated_window = Some(window);
            }
        }
    }
    IsomorphMetrics {
        repeated_groups,
        longest_repeated_window,
    }
}

fn near_isomorph_pair_count(message_values: &[Vec<TrigramValue>]) -> usize {
    let mut count = 0usize;
    for message in message_values {
        for window in DEFAULT_MIN_WINDOW..=DEFAULT_MAX_WINDOW {
            if window > message.len() {
                continue;
            }
            let signatures = informative_signatures(message, window);
            count += near_pairs_in_signatures(&signatures);
        }
    }
    count
}

fn informative_signatures(message: &[TrigramValue], window: usize) -> Vec<Vec<usize>> {
    let mut signatures = BTreeSet::new();
    for values in message.windows(window) {
        let signature = PatternSignature::from_window(values);
        if signature.has_repeated_symbol() {
            let _inserted = signatures.insert(signature.values().to_vec());
        }
    }
    signatures.into_iter().collect()
}

fn near_pairs_in_signatures(signatures: &[Vec<usize>]) -> usize {
    let mut count = 0usize;
    for (left_index, left) in signatures.iter().enumerate() {
        for right in signatures.iter().skip(left_index + 1) {
            if hamming_distance_one(left, right) {
                count += 1;
            }
        }
    }
    count
}

fn hamming_distance_one(left: &[usize], right: &[usize]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut differences = 0usize;
    for (left_value, right_value) in left.iter().zip(right) {
        if left_value != right_value {
            differences += 1;
            if differences > 1 {
                return false;
            }
        }
    }
    differences == 1
}

fn differing_first_shared_second_cases(message_values: &[Vec<TrigramValue>]) -> usize {
    let mut cases = 0usize;
    for (left_index, left_values) in message_values.iter().enumerate() {
        for right_values in message_values.iter().skip(left_index + 1) {
            for (left_pair, right_pair) in left_values.windows(2).zip(right_values.windows(2)) {
                let Some(left_first) = left_pair.first() else {
                    continue;
                };
                let Some(right_first) = right_pair.first() else {
                    continue;
                };
                let Some(left_second) = left_pair.get(1) else {
                    continue;
                };
                let Some(right_second) = right_pair.get(1) else {
                    continue;
                };
                if left_first != right_first && left_second == right_second {
                    cases += 1;
                }
            }
        }
    }
    cases
}

fn adjacent_equal_count(message_values: &[Vec<TrigramValue>]) -> usize {
    message_values
        .iter()
        .map(|message| {
            message
                .windows(2)
                .filter(|pair| pair.first() == pair.get(1))
                .count()
        })
        .sum()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NonSharedIsomorphMetrics {
    repeated_groups: usize,
    exact_duplicate_groups: usize,
}

fn non_shared_isomorph_metrics(
    message_values: &[Vec<TrigramValue>],
    shared_masks: &[Vec<bool>],
) -> NonSharedIsomorphMetrics {
    let mut occurrence_counts: BTreeMap<(usize, Vec<usize>), usize> = BTreeMap::new();
    let mut value_sets: BTreeMap<(usize, Vec<usize>), BTreeSet<Vec<u8>>> = BTreeMap::new();

    for (message, mask) in message_values.iter().zip(shared_masks) {
        for window in DEFAULT_MIN_WINDOW..=DEFAULT_MAX_WINDOW {
            if window > message.len() {
                continue;
            }
            collect_non_shared_isomorph_windows(
                message,
                mask,
                window,
                &mut occurrence_counts,
                &mut value_sets,
            );
        }
    }

    let mut repeated_groups = 0usize;
    let mut exact_duplicate_groups = 0usize;
    for (key, occurrences) in occurrence_counts {
        if occurrences <= 1 {
            continue;
        }
        repeated_groups += 1;
        let unique_values = value_sets.get(&key).map_or(0, BTreeSet::len);
        if unique_values < occurrences {
            exact_duplicate_groups += 1;
        }
    }

    NonSharedIsomorphMetrics {
        repeated_groups,
        exact_duplicate_groups,
    }
}

fn collect_non_shared_isomorph_windows(
    message: &[TrigramValue],
    mask: &[bool],
    window: usize,
    occurrence_counts: &mut BTreeMap<(usize, Vec<usize>), usize>,
    value_sets: &mut BTreeMap<(usize, Vec<usize>), BTreeSet<Vec<u8>>>,
) {
    for (start, values) in message.windows(window).enumerate() {
        if !mask_window_is_clear(mask, start, window) {
            continue;
        }
        let signature = PatternSignature::from_window(values);
        if !signature.has_repeated_symbol() {
            continue;
        }
        let key = (window, signature.values().to_vec());
        let values = values.iter().map(|value| value.get()).collect::<Vec<_>>();
        *occurrence_counts.entry(key.clone()).or_default() += 1;
        let _inserted = value_sets.entry(key).or_default().insert(values);
    }
}

fn mask_window_is_clear(mask: &[bool], start: usize, window: usize) -> bool {
    mask.iter()
        .skip(start)
        .take(window)
        .filter(|is_shared| **is_shared)
        .count()
        == 0
}

fn evaluate_generated_families(
    config: PyryConditionsConfig,
    lengths: &[usize],
) -> Result<Vec<FamilyFixtureReport>, PyryConditionsError> {
    let mut family_reports = Vec::new();
    for family in CandidateFamily::all() {
        family_reports.push(evaluate_family(config, lengths, family)?);
    }
    Ok(family_reports)
}

fn evaluate_family(
    config: PyryConditionsConfig,
    lengths: &[usize],
    family: CandidateFamily,
) -> Result<FamilyFixtureReport, PyryConditionsError> {
    let mut draws = Vec::with_capacity(config.fixture_draws);
    let mut condition_pass_counts = [0usize; CONDITION_COUNT];
    let mut all_conditions_pass_count = 0usize;

    for draw_index in 0..config.fixture_draws {
        let draw_seed = mix_seed(config.seed, draw_index as u64);
        let mut plaintext_rng = SplitMix64::new(mix_seed(draw_seed, 0x0070_6c61_696e));
        let plaintext = build_plaintext_fixture(lengths, &mut plaintext_rng)?;
        let mut family_rng = SplitMix64::new(mix_seed(draw_seed, family.seed_tag()));
        let fixture = encrypt_fixture(family, &plaintext, &mut family_rng)?;
        let evaluation = evaluate_corpus(family.label(), &fixture.values);
        add_condition_counts(evaluation.vector, &mut condition_pass_counts);
        if evaluation.vector.all_pass() {
            all_conditions_pass_count += 1;
        }
        draws.push(FixtureDrawReport {
            draw_index,
            key_summary: fixture.key_summary,
            evaluation,
        });
    }

    Ok(FamilyFixtureReport {
        family,
        draws,
        condition_pass_counts,
        all_conditions_pass_count,
    })
}

fn add_condition_counts(vector: ConditionVector, counts: &mut [usize; CONDITION_COUNT]) {
    for condition in PyryCondition::all() {
        if vector.get(condition) {
            let index = condition.number().saturating_sub(1);
            if let Some(count) = counts.get_mut(index) {
                *count += 1;
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct CipherFixture {
    values: Vec<Vec<TrigramValue>>,
    key_summary: String,
}

fn encrypt_fixture(
    family: CandidateFamily,
    plaintext: &[Vec<Glyph>],
    rng: &mut SplitMix64,
) -> Result<CipherFixture, PyryConditionsError> {
    match family {
        CandidateFamily::MonoalphabeticSubstitution => monoalphabetic_fixture(plaintext, rng),
        CandidateFamily::PeriodicVigenere => vigenere_fixture(plaintext),
        CandidateFamily::AutokeyAlbertiStyle => autokey_fixture(plaintext),
        CandidateFamily::DeckS83Permutation => deck_fixture(plaintext, rng),
        CandidateFamily::IncrementingWheel => wheel_fixture(plaintext, rng),
    }
}

fn monoalphabetic_fixture(
    plaintext: &[Vec<Glyph>],
    rng: &mut SplitMix64,
) -> Result<CipherFixture, PyryConditionsError> {
    let permutation = shuffled_permutation(ALPHABET_SIZE, rng)?;
    let mut messages = Vec::with_capacity(plaintext.len());
    for message in plaintext {
        let mut ciphertext = Vec::with_capacity(message.len());
        for glyph in message {
            let symbol = glyph_symbol(*glyph)?;
            let Some(&cipher_symbol) = permutation.get(symbol) else {
                return Err(PyryConditionsError::GeneratedSymbolOutsideAlphabet {
                    symbol: *glyph,
                    alphabet_size: ALPHABET_SIZE,
                });
            };
            ciphertext.push(Glyph(cipher_symbol as u16));
        }
        messages.push(glyphs_to_values(&ciphertext)?);
    }
    Ok(CipherFixture {
        values: messages,
        key_summary: "random S83 substitution permutation".to_owned(),
    })
}

fn vigenere_fixture(plaintext: &[Vec<Glyph>]) -> Result<CipherFixture, PyryConditionsError> {
    let key = VigenereKey::new(ALPHABET_SIZE, VIGENERE_SHIFTS.to_vec())?;
    let mut messages = Vec::with_capacity(plaintext.len());
    for message in plaintext {
        let ciphertext = vigenere_encrypt(message, &key)?;
        messages.push(glyphs_to_values(&ciphertext)?);
    }
    Ok(CipherFixture {
        values: messages,
        key_summary: format!("period-{VIGENERE_PERIOD} shifts {VIGENERE_SHIFTS:?}"),
    })
}

fn autokey_fixture(plaintext: &[Vec<Glyph>]) -> Result<CipherFixture, PyryConditionsError> {
    let mut messages = Vec::with_capacity(plaintext.len());
    for message in plaintext {
        messages.push(glyphs_to_values(&autokey_encrypt(message, 0)?)?);
    }
    Ok(CipherFixture {
        values: messages,
        key_summary: "plaintext-autokey additive seed shift 0".to_owned(),
    })
}

fn deck_fixture(
    plaintext: &[Vec<Glyph>],
    rng: &mut SplitMix64,
) -> Result<CipherFixture, PyryConditionsError> {
    let deck = shuffled_permutation(ALPHABET_SIZE, rng)?;
    let key = DeckCipherKey::new(ALPHABET_SIZE, deck, ALPHABET_SIZE - 2, ALPHABET_SIZE - 1)?;
    let mut messages = Vec::with_capacity(plaintext.len());
    for message in plaintext {
        let ciphertext = deck_cipher_encrypt(message, &key)?;
        messages.push(glyphs_to_values(&ciphertext)?);
    }
    Ok(CipherFixture {
        values: messages,
        key_summary: "SplitMix64-shuffled S83 deck, controls 81/82".to_owned(),
    })
}

fn wheel_fixture(
    plaintext: &[Vec<Glyph>],
    rng: &mut SplitMix64,
) -> Result<CipherFixture, PyryConditionsError> {
    let mut messages = Vec::with_capacity(plaintext.len());
    let mut starts = Vec::with_capacity(plaintext.len());
    for message in plaintext {
        let start = random_index_below(ALPHABET_SIZE, rng)?;
        starts.push(start);
        let key = IncrementingWheelKey::new(ALPHABET_SIZE, start, WHEEL_STEP)?;
        let ciphertext = incrementing_wheel_encrypt(message, &key)?;
        messages.push(glyphs_to_values(&ciphertext)?);
    }
    Ok(CipherFixture {
        values: messages,
        key_summary: format!(
            "step {WHEEL_STEP}, per-message starts {}",
            render_usize_list(&starts)
        ),
    })
}

fn autokey_encrypt(
    message: &[Glyph],
    seed_shift: usize,
) -> Result<Vec<Glyph>, PyryConditionsError> {
    let mut previous_plain = seed_shift % ALPHABET_SIZE;
    let mut ciphertext = Vec::with_capacity(message.len());
    for glyph in message {
        let plain = glyph_symbol(*glyph)?;
        let cipher = (plain + previous_plain) % ALPHABET_SIZE;
        ciphertext.push(Glyph(cipher as u16));
        previous_plain = plain;
    }
    Ok(ciphertext)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceSampler {
    population: Vec<usize>,
}

impl SourceSampler {
    fn new() -> Self {
        let mut population = Vec::new();
        for symbol in 0..ALPHABET_SIZE {
            let weight = 1 + stateless_splitmix(symbol as u64 ^ 0x7079_7279_7372_6300) % 31;
            for _copy in 0..weight {
                population.push(symbol);
            }
        }
        Self { population }
    }

    fn sample_symbol(&self, rng: &mut SplitMix64) -> Result<usize, PyryConditionsError> {
        let index = random_index_below(self.population.len(), rng)?;
        self.population
            .get(index)
            .copied()
            .ok_or(PyryConditionsError::RandomBoundTooLarge {
                bound: self.population.len(),
            })
    }

    fn sample_symbol_excluding(
        &self,
        excluded: &[usize],
        rng: &mut SplitMix64,
    ) -> Result<usize, PyryConditionsError> {
        loop {
            let symbol = self.sample_symbol(rng)?;
            if !excluded.contains(&symbol) {
                return Ok(symbol);
            }
        }
    }
}

fn build_plaintext_fixture(
    lengths: &[usize],
    rng: &mut SplitMix64,
) -> Result<Vec<Vec<Glyph>>, PyryConditionsError> {
    let sampler = SourceSampler::new();
    let mut messages = Vec::with_capacity(lengths.len());
    let mut fixed_masks = Vec::with_capacity(lengths.len());
    for (message_index, &length) in lengths.iter().enumerate() {
        let mut message = sample_plaintext_message(length, &sampler, rng)?;
        let mut fixed = vec![false; length];
        apply_shared_prefix(message_index, &mut message, &mut fixed, rng)?;
        apply_planted_isomorphs(message_index, &mut message, &mut fixed);
        messages.push(message);
        fixed_masks.push(fixed);
    }
    repair_plaintext_local_repeats(&mut messages, &fixed_masks, &sampler, rng)?;
    Ok(messages)
}

fn sample_plaintext_message(
    length: usize,
    sampler: &SourceSampler,
    rng: &mut SplitMix64,
) -> Result<Vec<Glyph>, PyryConditionsError> {
    let mut message = Vec::with_capacity(length);
    for position in 0..length {
        let excluded = previous_symbols(&message, position);
        let symbol = sampler.sample_symbol_excluding(&excluded, rng)?;
        message.push(Glyph(symbol as u16));
    }
    Ok(message)
}

fn previous_symbols(message: &[Glyph], position: usize) -> Vec<usize> {
    let mut excluded = Vec::new();
    if let Some(previous_position) = position.checked_sub(1)
        && let Some(glyph) = message.get(previous_position)
    {
        excluded.push(usize::from(glyph.0));
    }
    if let Some(previous_position) = position.checked_sub(2)
        && let Some(glyph) = message.get(previous_position)
    {
        excluded.push(usize::from(glyph.0));
    }
    excluded
}

fn apply_shared_prefix(
    message_index: usize,
    message: &mut [Glyph],
    fixed: &mut [bool],
    rng: &mut SplitMix64,
) -> Result<(), PyryConditionsError> {
    if message.is_empty() {
        return Ok(());
    }
    let prefix_second = SHARED_PREFIX.get(1).copied().unwrap_or_default();
    let mut varying_first =
        (message_index * 11 + random_index_below(ALPHABET_SIZE, rng)?) % ALPHABET_SIZE;
    if varying_first == prefix_second {
        varying_first = (varying_first + 1) % ALPHABET_SIZE;
    }
    set_fixed_symbol(message, fixed, 0, varying_first);
    for (offset, symbol) in SHARED_PREFIX.iter().copied().enumerate() {
        let position = offset + 1;
        set_fixed_symbol(message, fixed, position, symbol);
    }
    Ok(())
}

fn apply_planted_isomorphs(message_index: usize, message: &mut [Glyph], fixed: &mut [bool]) {
    if message_index != 0 {
        return;
    }
    apply_motif(
        message,
        fixed,
        MOTIF_STARTS.first().copied(),
        MOTIF_PREDECESSORS.first().copied(),
        &MOTIF_EXACT_A,
    );
    apply_motif(
        message,
        fixed,
        MOTIF_STARTS.get(1).copied(),
        MOTIF_PREDECESSORS.get(1).copied(),
        &MOTIF_EXACT_B,
    );
    apply_motif(
        message,
        fixed,
        MOTIF_STARTS.get(2).copied(),
        MOTIF_PREDECESSORS.get(2).copied(),
        &MOTIF_NEAR,
    );
}

fn apply_motif(
    message: &mut [Glyph],
    fixed: &mut [bool],
    start: Option<usize>,
    predecessor: Option<usize>,
    motif: &[usize],
) {
    let Some(start) = start else {
        return;
    };
    if let Some(previous_position) = start.checked_sub(1)
        && let Some(predecessor) = predecessor
    {
        set_fixed_symbol(message, fixed, previous_position, predecessor);
    }
    for (offset, symbol) in motif.iter().copied().enumerate() {
        set_fixed_symbol(message, fixed, start + offset, symbol);
    }
}

fn set_fixed_symbol(message: &mut [Glyph], fixed: &mut [bool], position: usize, symbol: usize) {
    if let Some(slot) = message.get_mut(position) {
        *slot = Glyph(symbol as u16);
    }
    if let Some(slot) = fixed.get_mut(position) {
        *slot = true;
    }
}

fn repair_plaintext_local_repeats(
    messages: &mut [Vec<Glyph>],
    fixed_masks: &[Vec<bool>],
    sampler: &SourceSampler,
    rng: &mut SplitMix64,
) -> Result<(), PyryConditionsError> {
    for _pass in 0..4 {
        let mut changed = false;
        for (message, fixed) in messages.iter_mut().zip(fixed_masks) {
            changed |= repair_message_local_repeats(message, fixed, sampler, rng)?;
        }
        if !changed {
            return Ok(());
        }
    }
    Ok(())
}

fn repair_message_local_repeats(
    message: &mut [Glyph],
    fixed: &[bool],
    sampler: &SourceSampler,
    rng: &mut SplitMix64,
) -> Result<bool, PyryConditionsError> {
    let mut changed = false;
    for position in 0..message.len() {
        if local_repeat_at(message, position) {
            let repair_position = repair_position(message, fixed, position);
            if let Some(repair_position) = repair_position {
                resample_plaintext_position(message, repair_position, sampler, rng)?;
                changed = true;
            }
        }
    }
    Ok(changed)
}

fn local_repeat_at(message: &[Glyph], position: usize) -> bool {
    let Some(current) = message.get(position) else {
        return false;
    };
    for distance in [1usize, 2] {
        let Some(previous_position) = position.checked_sub(distance) else {
            continue;
        };
        if message.get(previous_position) == Some(current) {
            return true;
        }
    }
    false
}

fn repair_position(message: &[Glyph], fixed: &[bool], position: usize) -> Option<usize> {
    if fixed.get(position).copied() == Some(false) {
        return Some(position);
    }
    for distance in [1usize, 2] {
        let previous_position = position.checked_sub(distance)?;
        if fixed.get(previous_position).copied() == Some(false) && previous_position < message.len()
        {
            return Some(previous_position);
        }
    }
    None
}

fn resample_plaintext_position(
    message: &mut [Glyph],
    position: usize,
    sampler: &SourceSampler,
    rng: &mut SplitMix64,
) -> Result<(), PyryConditionsError> {
    let excluded = neighbor_symbols(message, position);
    let symbol = sampler.sample_symbol_excluding(&excluded, rng)?;
    if let Some(slot) = message.get_mut(position) {
        *slot = Glyph(symbol as u16);
    }
    Ok(())
}

fn neighbor_symbols(message: &[Glyph], position: usize) -> Vec<usize> {
    let mut excluded = Vec::new();
    for distance in [1usize, 2] {
        if let Some(previous_position) = position.checked_sub(distance)
            && let Some(glyph) = message.get(previous_position)
        {
            excluded.push(usize::from(glyph.0));
        }
        if let Some(next_position) = position.checked_add(distance)
            && let Some(glyph) = message.get(next_position)
        {
            excluded.push(usize::from(glyph.0));
        }
    }
    excluded
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

#[cfg(test)]
mod tests {
    use super::{
        ALPHABET_SIZE, CandidateFamily, ConditionVector, PyryCondition, PyryConditionsConfig,
        evaluate_corpus, run_pyry_conditions,
    };
    use crate::trigram::TrigramValue;

    fn values(rows: &[&[u8]]) -> Vec<Vec<TrigramValue>> {
        rows.iter()
            .map(|row| row.iter().copied().map(value).collect())
            .collect()
    }

    fn value(raw: u8) -> TrigramValue {
        TrigramValue::new(raw).unwrap()
    }

    fn full_support_prefix() -> Vec<TrigramValue> {
        (0..ALPHABET_SIZE).map(|raw| value(raw as u8)).collect()
    }

    fn assert_condition(corpus: &[Vec<TrigramValue>], condition: PyryCondition, expected: bool) {
        let evaluation = evaluate_corpus("fixture", corpus);
        assert_eq!(
            evaluation.vector.get(condition),
            expected,
            "{condition:?} metrics: {:?}",
            evaluation.metrics
        );
    }

    #[test]
    fn condition_1_flat_ioc_discriminates() {
        let flat = values(&[&[0, 1, 2, 3, 4, 5, 6, 7], &[8, 9, 10, 11, 12, 13, 14, 15]]);
        let peaked = values(&[&[0, 0, 0, 0, 0, 0, 1, 2]]);
        assert_condition(&flat, PyryCondition::FlatIoc, true);
        assert_condition(&peaked, PyryCondition::FlatIoc, false);
    }

    #[test]
    fn condition_2_contiguous_support_discriminates() {
        let complete = vec![full_support_prefix()];
        let missing = values(&[&[0, 1, 2, 3, 4, 82]]);
        assert_condition(&complete, PyryCondition::ContiguousAlphabet, true);
        assert_condition(&missing, PyryCondition::ContiguousAlphabet, false);
    }

    #[test]
    fn condition_3_aligned_shared_runs_discriminates() {
        let positive = values(&[&[1, 7, 8, 2], &[3, 7, 8, 4]]);
        let negative = values(&[&[1, 7, 9, 2], &[3, 8, 7, 4]]);
        assert_condition(&positive, PyryCondition::AlignedSharedSections, true);
        assert_condition(&negative, PyryCondition::AlignedSharedSections, false);
    }

    #[test]
    fn condition_4_isomorphs_discriminate() {
        let positive = values(&[&[1, 2, 1, 3, 4, 3]]);
        let negative = values(&[&[1, 2, 3, 4, 5, 6]]);
        assert_condition(&positive, PyryCondition::IsomorphsPresent, true);
        assert_condition(&negative, PyryCondition::IsomorphsPresent, false);
    }

    #[test]
    fn condition_5_shared_after_varying_prefix_discriminates() {
        let positive = values(&[&[1, 7, 8, 9], &[2, 7, 8, 9]]);
        let negative = values(&[&[1, 7, 8, 9], &[1, 7, 8, 4]]);
        assert_condition(&positive, PyryCondition::SharedAfterVaryingPrefix, true);
        assert_condition(&negative, PyryCondition::SharedAfterVaryingPrefix, false);
    }

    #[test]
    fn condition_6_near_isomorphs_discriminate() {
        let positive = values(&[&[1, 2, 1, 5, 3, 4, 4]]);
        let negative = values(&[&[1, 2, 3, 4, 5, 6, 7]]);
        assert_condition(&positive, PyryCondition::NearIsomorphsPresent, true);
        assert_condition(&negative, PyryCondition::NearIsomorphsPresent, false);
    }

    #[test]
    fn condition_7_differing_first_shared_second_discriminates() {
        let positive = values(&[&[1, 66, 5], &[2, 66, 5]]);
        let negative = values(&[&[1, 66, 5], &[2, 67, 6]]);
        assert_condition(&positive, PyryCondition::DifferingFirstSharedSecond, true);
        assert_condition(&negative, PyryCondition::DifferingFirstSharedSecond, false);
    }

    #[test]
    fn condition_8_no_doubled_trigrams_discriminates() {
        let positive = values(&[&[1, 2, 3], &[3, 2, 1]]);
        let negative = values(&[&[1, 1, 2]]);
        assert_condition(&positive, PyryCondition::NoDoubledTrigrams, true);
        assert_condition(&negative, PyryCondition::NoDoubledTrigrams, false);
    }

    #[test]
    fn condition_9_non_shared_isomorphs_differ_discriminates() {
        let positive = values(&[&[1, 2, 3, 1, 4, 2, 9, 8, 7, 9, 6, 8]]);
        let negative = values(&[&[1, 2, 3, 1, 4, 2, 1, 2, 3, 1, 4, 2]]);
        assert_condition(&positive, PyryCondition::NonSharedIsomorphsDiffer, true);
        assert_condition(&negative, PyryCondition::NonSharedIsomorphsDiffer, false);
    }

    #[test]
    fn eye_condition_vector_is_pinned() {
        let report = run_pyry_conditions(PyryConditionsConfig {
            seed: 123,
            fixture_draws: 2,
        })
        .unwrap();
        assert_eq!(
            report.eyes.vector.as_array(),
            [true, true, true, true, true, true, true, true, true]
        );
        assert_eq!(report.eyes.metrics.total_symbols, 1_036);
        assert_eq!(report.eyes.metrics.distinct_in_alphabet, 83);
        assert_eq!(report.eyes.metrics.adjacent_equal_count, 0);
    }

    #[test]
    fn generated_family_rows_are_reproducible() {
        let config = PyryConditionsConfig {
            seed: 987,
            fixture_draws: 3,
        };
        let first = run_pyry_conditions(config).unwrap();
        let second = run_pyry_conditions(config).unwrap();
        assert_eq!(first.families, second.families);
        assert_eq!(first.families.len(), CandidateFamily::all().len());
        for family in &first.families {
            assert_eq!(family.draws.len(), config.fixture_draws);
        }
    }

    #[test]
    fn condition_vector_counts_passes() {
        let vector =
            ConditionVector::new([true, false, true, false, true, false, true, false, true]);
        assert_eq!(vector.passed_count(), 5);
        assert!(!vector.all_pass());
    }
}

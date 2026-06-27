//! Experiment 12 language-scoring attack harness for candidate ciphers.
//!
//! This module is deliberately a harness around [`crate::ciphers`], not a
//! source of new cipher primitives. It attacks the accepted honeycomb
//! reading-layer stream (`standard36-u012-d012`) with the candidate ciphers
//! already implemented in [`crate::ciphers`], then compares the best language
//! scores with a same-search within-message shuffle null.
//!
//! The fundamental limitation is part of the experiment: the eye reading layer
//! is an 83-symbol alphabet, while the bundled English and Finnish language
//! models score roughly 26 and 29 letters. Scoring a decrypted 83-symbol stream
//! therefore requires a symbol-to-letter mapping that is unknown and cannot be
//! verified from the eye data alone. Every mapping here is a declared guess.
//! A negative result is the expected defensible outcome.
//! The CLI interpretation therefore derives its conclusion from exceedance
//! rates, multiple-comparison scope, and the effect-size contrast against
//! positive-control plants; small pointwise tails on the eye stream are not
//! near-solutions.
//!
//! Message boundaries are preserved. Stateful ciphers reset at the start of
//! each message, and language scores are weighted across per-message scores so
//! bigrams never cross artificial joins.

use std::fmt;

use crate::analysis::orders::{self, GridError, ReadingOrder};
use crate::attack::language::{
    LanguageError, LanguageModel, LanguageScore, english_model, finnish_model,
};
use crate::ciphers::{CipherError, EYE_READING_ALPHABET_SIZE};
use crate::core::glyph::Glyph;
use crate::core::trigram::TrigramValue;

mod nulls;
mod report;
mod scoring;
mod search;
#[cfg(test)]
mod tests;

use nulls::run_positive_controls;
use search::append_cipher_rows;

/// Default deterministic seed for Experiment 12 attack sampling.
pub const DEFAULT_SEED: u64 = 0x6579_652d_7831_3221;
/// Default sampled-key count for non-exhaustive candidate spaces.
pub const DEFAULT_SAMPLES: usize = 512;
/// Default number of within-message shuffle null trials.
pub const DEFAULT_NULL_TRIALS: usize = 32;
/// Default largest Vigenere period considered by the eye-corpus attack.
pub const DEFAULT_VIGENERE_MAX_PERIOD: usize = 3;

const POSITIVE_CONTROL_NULL_TRIALS: usize = 16;
const POSITIVE_CONTROL_MIN_MARGIN: f64 = 0.10;
const POSITIVE_CONTROL_TEXT: &str = "\
THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG AND THEN THE QUIET READER FINDS \
THAT ORDINARY ENGLISH BIGRAMS ARE EASY TO RECOGNIZE WHEN THE KEY IS KNOWN";
const POSITIVE_CONTROL_CAESAR_SHIFT: usize = 17;
const POSITIVE_CONTROL_VIGENERE_SHIFTS: [usize; 2] = [3, 11];

/// Error returned by the Experiment 12 attack harness.
#[derive(Clone, Debug, PartialEq)]
pub enum CipherAttackError {
    /// The accepted eye corpus could not be reconstructed in the requested
    /// reading order.
    Grid(GridError),
    /// A language model or candidate score failed.
    Language(LanguageError),
    /// A candidate cipher primitive rejected a key or sequence.
    Cipher(CipherError),
    /// At least one sampled key is required for sampled keyspaces.
    ZeroSamples,
    /// At least one null trial is required for empirical p-values.
    ZeroNullTrials,
    /// The Vigenere period range was empty.
    ZeroVigenereMaxPeriod,
    /// A score was requested for an empty message set.
    EmptyCorpus,
    /// A declared symbol-to-letter mapping could not be built.
    EmptyMapping,
    /// A reading-layer value was outside the accepted `0..=82` alphabet.
    ValueOutsideEyeAlphabet {
        /// Offending value.
        value: u16,
    },
    /// A random draw bound was zero or too large for the in-crate sampler.
    RandomBoundTooLarge {
        /// Requested exclusive upper bound.
        bound: usize,
    },
    /// A search evaluated no key candidates.
    NoKeyCandidates {
        /// Cipher whose search was empty.
        cipher: CipherFamily,
    },
    /// The positive-control plant was not recovered cleanly.
    PositiveControlFailed {
        /// Cipher used for the plant.
        cipher: CipherFamily,
        /// Expected key label.
        expected_key: String,
        /// Best recovered key label.
        recovered_key: String,
        /// Best real score.
        real_score: f64,
        /// Largest shuffled-null best score.
        null_max: f64,
    },
}

impl From<GridError> for CipherAttackError {
    fn from(value: GridError) -> Self {
        Self::Grid(value)
    }
}

impl From<LanguageError> for CipherAttackError {
    fn from(value: LanguageError) -> Self {
        Self::Language(value)
    }
}

impl From<CipherError> for CipherAttackError {
    fn from(value: CipherError) -> Self {
        Self::Cipher(value)
    }
}

impl From<crate::nulls::null::RandomBoundError> for CipherAttackError {
    fn from(error: crate::nulls::null::RandomBoundError) -> Self {
        Self::RandomBoundTooLarge { bound: error.bound }
    }
}

impl fmt::Display for CipherAttackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Grid(error) => write!(f, "grid/order error: {error:?}"),
            Self::Language(error) => write!(f, "language model error: {error}"),
            Self::Cipher(error) => write!(f, "cipher primitive error: {error}"),
            Self::ZeroSamples => write!(f, "at least one sampled key is required"),
            Self::ZeroNullTrials => write!(f, "at least one null trial is required"),
            Self::ZeroVigenereMaxPeriod => {
                write!(f, "Vigenere max period must be at least 1")
            }
            Self::EmptyCorpus => write!(f, "the message set is empty"),
            Self::EmptyMapping => write!(f, "declared symbol-to-letter mapping is empty"),
            Self::ValueOutsideEyeAlphabet { value } => {
                write!(f, "reading-layer value {value} is outside 0..=82")
            }
            Self::RandomBoundTooLarge { bound } => {
                write!(f, "random draw bound {bound} is invalid")
            }
            Self::NoKeyCandidates { cipher } => {
                write!(f, "{} search evaluated no key candidates", cipher.label())
            }
            Self::PositiveControlFailed {
                cipher,
                expected_key,
                recovered_key,
                real_score,
                null_max,
            } => write!(
                f,
                "{} positive control failed: expected {expected_key}, recovered {recovered_key}, score {real_score:.6}, null max {null_max:.6}",
                cipher.label()
            ),
        }
    }
}

impl std::error::Error for CipherAttackError {}

/// Configuration for the Experiment 12 attack harness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CipherAttackConfig {
    /// Deterministic seed for key sampling and null shuffles.
    pub seed: u64,
    /// Number of sampled keys for Vigenere when not exhaustive, Chaocipher, and
    /// the deck cipher.
    pub samples: usize,
    /// Number of within-message shuffle null trials.
    pub null_trials: usize,
    /// Largest Vigenere period to search, inclusive.
    pub vigenere_max_period: usize,
}

impl Default for CipherAttackConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_SEED,
            samples: DEFAULT_SAMPLES,
            null_trials: DEFAULT_NULL_TRIALS,
            vigenere_max_period: DEFAULT_VIGENERE_MAX_PERIOD,
        }
    }
}

/// Candidate cipher family attacked by Experiment 12.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherFamily {
    /// Caesar additive shift over the 83-symbol eye alphabet.
    Caesar,
    /// Additive-progressive incrementing wheel over the 83-symbol eye alphabet.
    IncrementingWheel,
    /// Short-period additive Vigenere over the 83-symbol eye alphabet.
    Vigenere,
    /// Generalized 83-symbol Chaocipher.
    Chaocipher,
    /// Generalized `S_N` deck keystream cipher.
    Deck,
}

impl CipherFamily {
    /// Returns the short report label for this cipher family.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Caesar => "Caesar",
            Self::IncrementingWheel => "incrementing-wheel",
            Self::Vigenere => "Vigenere",
            Self::Chaocipher => "Chaocipher",
            Self::Deck => "S_N deck",
        }
    }

    const fn all() -> [Self; 5] {
        [
            Self::Caesar,
            Self::IncrementingWheel,
            Self::Vigenere,
            Self::Chaocipher,
            Self::Deck,
        ]
    }

    const fn seed_tag(self) -> u64 {
        match self {
            Self::Caesar => 0x6361_6573_6172,
            Self::IncrementingWheel => 0x7768_6565_6c21,
            Self::Vigenere => 0x7669_6765_6e65,
            Self::Chaocipher => 0x6368_616f_2121,
            Self::Deck => 0x6465_636b_2121,
        }
    }
}

/// Language model used for scoring one candidate plaintext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LanguageKind {
    /// Bundled English model, scored over `A..Z`.
    English,
    /// Bundled Finnish model, scored over `A..Z` plus Finnish letters.
    Finnish,
}

impl LanguageKind {
    /// Returns a report label for this language model.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::English => "English",
            Self::Finnish => "Finnish",
        }
    }
}

/// Mean per-symbol score retained for a candidate plaintext.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CandidateScore {
    /// Number of mapped symbols scored.
    pub symbols: usize,
    /// Mean unigram natural-log likelihood per symbol.
    pub unigram_mean_log_likelihood: f64,
    /// Mean bigram natural-log likelihood per symbol.
    pub bigram_mean_log_likelihood: f64,
}

impl From<LanguageScore> for CandidateScore {
    fn from(value: LanguageScore) -> Self {
        Self {
            symbols: value.symbols,
            unigram_mean_log_likelihood: value.unigram_mean_log_likelihood,
            bigram_mean_log_likelihood: value.bigram_mean_log_likelihood,
        }
    }
}

/// Best candidate found by one search row.
#[derive(Clone, Debug, PartialEq)]
pub struct BestCandidate {
    /// Best weighted language score. Larger, meaning less negative, is better.
    pub score: CandidateScore,
    /// Human-readable key or deterministic sampled-key descriptor that achieved
    /// the score.
    pub key: String,
}

/// Search method summary for one cipher family.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchSummary {
    /// Human-readable keyspace size or estimate.
    pub key_space: String,
    /// Number of key candidates actually evaluated.
    pub candidates_evaluated: usize,
    /// Whether the declared keyspace was exhausted.
    pub exhaustive: bool,
    /// `SplitMix64` seed used when candidate keys were sampled.
    pub sampling_seed: Option<u64>,
    /// Short method note for CLI output.
    pub note: String,
}

/// One-sided null distribution for best language scores.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ScoreNull {
    /// Number of shuffled null trials.
    pub trials: usize,
    /// Mean of shuffled-null best scores.
    pub mean: f64,
    /// One-sided 95th percentile of shuffled-null best scores.
    pub q95: f64,
    /// Largest shuffled-null best score.
    pub max: f64,
    /// Count of shuffled-null best scores greater than or equal to the real
    /// best score.
    pub empirical_p_count: usize,
    /// Empirical p-value, `empirical_p_count / trials`.
    pub empirical_p: f64,
}

/// One cipher x mapping x language attack row.
#[derive(Clone, Debug, PartialEq)]
pub struct AttackRow {
    /// Candidate cipher family.
    pub cipher: CipherFamily,
    /// Scored language.
    pub language: LanguageKind,
    /// Declared mapping label. Every mapping is an unverified guess.
    pub mapping_label: String,
    /// Mapping caveat shown by the CLI.
    pub mapping_note: String,
    /// Search method used for this cipher.
    pub search: SearchSummary,
    /// Best score on the real accepted eye stream.
    pub real: BestCandidate,
    /// Same-search within-message shuffled null for the best score.
    pub null: ScoreNull,
}

/// Positive-control recovery summary for one planted cipher.
#[derive(Clone, Debug, PartialEq)]
pub struct PlantRecovery {
    /// Cipher family used for the plant.
    pub cipher: CipherFamily,
    /// Number of normalized English plaintext symbols in the plant.
    pub plaintext_symbols: usize,
    /// Expected key label.
    pub expected_key: String,
    /// Best recovered key label.
    pub recovered_key: String,
    /// Best score on the planted ciphertext.
    pub real_score: CandidateScore,
    /// Same-search shuffled-null summary for the planted ciphertext.
    pub null: ScoreNull,
    /// Margin of the plant score over the shuffled-null maximum.
    pub margin_over_null_max: f64,
}

/// Positive controls proving the harness can recover simple plants.
#[derive(Clone, Debug, PartialEq)]
pub struct PositiveControlReport {
    /// Caesar plant recovery.
    pub caesar: PlantRecovery,
    /// Vigenere plant recovery.
    pub vigenere: PlantRecovery,
}

/// Full Experiment 12 attack report.
#[derive(Clone, Debug, PartialEq)]
pub struct CipherAttackReport {
    /// Configuration used for the run.
    pub config: CipherAttackConfig,
    /// Accepted reading order name, `standard36-u012-d012`.
    pub order_name: String,
    /// Per-message lengths in reading-layer symbols.
    pub message_lengths: Vec<(&'static str, usize)>,
    /// Total reading-layer symbols scored.
    pub total_symbols: usize,
    /// Boundary rule used by every search row.
    pub boundary_rule: &'static str,
    /// Null model used by every attack row.
    pub null_model: &'static str,
    /// Attack rows, one per cipher x declared mapping x language.
    pub rows: Vec<AttackRow>,
    /// Positive-control recovery results.
    pub positive_control: PositiveControlReport,
}

/// Runs the Experiment 12 candidate-cipher attack harness.
///
/// # Errors
/// Returns [`CipherAttackError`] when the accepted corpus, language models,
/// cipher primitives, random sampling, or positive controls fail.
pub fn run_cipher_attack(
    config: CipherAttackConfig,
) -> Result<CipherAttackReport, CipherAttackError> {
    validate_config(config)?;
    let accepted = accepted_eye_messages()?;
    let plans = scoring_plans()?;
    let mut rows = Vec::new();

    for cipher in CipherFamily::all() {
        append_cipher_rows(cipher, config, &accepted.messages, &plans, &mut rows)?;
    }

    let positive_control = run_positive_controls(config.seed)?;
    Ok(CipherAttackReport {
        config,
        order_name: accepted.order.name(),
        message_lengths: accepted.message_lengths,
        total_symbols: accepted.total_symbols,
        boundary_rule: "stateful ciphers reset per message; language scores are weighted per message and never form bigrams across joins",
        null_model: "within-message shuffle of the accepted eye stream, preserving message lengths and symbol counts, with the same key search reapplied",
        rows,
        positive_control,
    })
}

fn validate_config(config: CipherAttackConfig) -> Result<(), CipherAttackError> {
    if config.samples == 0 {
        return Err(CipherAttackError::ZeroSamples);
    }
    if config.null_trials == 0 {
        return Err(CipherAttackError::ZeroNullTrials);
    }
    if config.vigenere_max_period == 0 {
        return Err(CipherAttackError::ZeroVigenereMaxPeriod);
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct AcceptedMessages {
    order: ReadingOrder,
    message_lengths: Vec<(&'static str, usize)>,
    total_symbols: usize,
    messages: Vec<Vec<Glyph>>,
}

fn accepted_eye_messages() -> Result<AcceptedMessages, CipherAttackError> {
    let grids = orders::corpus_grids()?;
    let keys = grids.iter().map(orders::GlyphGrid::message_key);
    let order = orders::accepted_honeycomb_order();
    let value_messages = orders::read_corpus_message_values(&grids, order)?;
    let messages = glyph_messages_from_values(&value_messages)?;
    let message_lengths = keys.zip(messages.iter().map(Vec::len)).collect::<Vec<_>>();
    let total_symbols = messages.iter().map(Vec::len).sum();
    if total_symbols == 0 {
        return Err(CipherAttackError::EmptyCorpus);
    }
    Ok(AcceptedMessages {
        order,
        message_lengths,
        total_symbols,
        messages,
    })
}

fn glyph_messages_from_values(
    value_messages: &[Vec<TrigramValue>],
) -> Result<Vec<Vec<Glyph>>, CipherAttackError> {
    let mut messages = Vec::with_capacity(value_messages.len());
    for values in value_messages {
        let mut glyphs = Vec::with_capacity(values.len());
        for value in values {
            let raw = value.get();
            if usize::from(raw) >= EYE_READING_ALPHABET_SIZE {
                return Err(CipherAttackError::ValueOutsideEyeAlphabet {
                    value: u16::from(raw),
                });
            }
            glyphs.push(Glyph(u16::from(raw)));
        }
        messages.push(glyphs);
    }
    Ok(messages)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MappingKind {
    Modulo,
    FrequencyRankCdf,
}

impl MappingKind {
    const fn base_label(self) -> &'static str {
        match self {
            Self::Modulo => "mod",
            Self::FrequencyRankCdf => "rankfreq-cdf",
        }
    }

    const fn note(self) -> &'static str {
        match self {
            Self::Modulo => {
                "unverified guess: map each 83-symbol candidate value by value modulo the target letter count"
            }
            Self::FrequencyRankCdf => {
                "unverified guess: rank candidate 83-symbol frequencies and bucket them into language letter-frequency mass"
            }
        }
    }
}

#[derive(Clone, Debug)]
struct ScoringPlan {
    language: LanguageKind,
    model: LanguageModel,
    mapping: MappingKind,
    target_letters: usize,
}

impl ScoringPlan {
    fn mapping_label(&self) -> String {
        format!("{}{}", self.mapping.base_label(), self.target_letters)
    }

    fn mapping_note(&self) -> &'static str {
        self.mapping.note()
    }
}

fn scoring_plans() -> Result<Vec<ScoringPlan>, CipherAttackError> {
    let english = english_model()?;
    let finnish = finnish_model()?;
    Ok(vec![
        ScoringPlan {
            language: LanguageKind::English,
            model: english.clone(),
            mapping: MappingKind::Modulo,
            target_letters: 26,
        },
        ScoringPlan {
            language: LanguageKind::English,
            model: english,
            mapping: MappingKind::FrequencyRankCdf,
            target_letters: 26,
        },
        ScoringPlan {
            language: LanguageKind::Finnish,
            model: finnish.clone(),
            mapping: MappingKind::Modulo,
            target_letters: 29,
        },
        ScoringPlan {
            language: LanguageKind::Finnish,
            model: finnish,
            mapping: MappingKind::FrequencyRankCdf,
            target_letters: 29,
        },
    ])
}

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

use crate::ciphers::{
    CaesarKey, ChaocipherKey, CipherError, DeckCipherKey, EYE_READING_ALPHABET_SIZE,
    IncrementingWheelKey, VigenereKey, caesar_decrypt, caesar_encrypt, chaocipher_decrypt,
    deck_cipher_decrypt, incrementing_wheel_decrypt, vigenere_decrypt, vigenere_encrypt,
};
use crate::glyph::Glyph;
use crate::language::{LanguageError, LanguageModel, LanguageScore, english_model, finnish_model};
use crate::null::{SplitMix64, fisher_yates, random_index_below};
use crate::orders::{self, GridError, ReadingOrder};
use crate::trigram::TrigramValue;

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

impl From<crate::null::RandomBoundError> for CipherAttackError {
    fn from(error: crate::null::RandomBoundError) -> Self {
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

fn append_cipher_rows(
    cipher: CipherFamily,
    config: CipherAttackConfig,
    messages: &[Vec<Glyph>],
    plans: &[ScoringPlan],
    rows: &mut Vec<AttackRow>,
) -> Result<(), CipherAttackError> {
    let real = search_cipher(cipher, config, messages, plans)?;
    let null_samples = null_samples(cipher, config, messages, plans)?;

    for ((plan, real_best), samples) in plans.iter().zip(real.best).zip(null_samples) {
        rows.push(AttackRow {
            cipher,
            language: plan.language,
            mapping_label: plan.mapping_label(),
            mapping_note: plan.mapping_note().to_owned(),
            search: real.summary.clone(),
            null: summarize_null(real_best.score.bigram_mean_log_likelihood, &samples),
            real: real_best,
        });
    }
    Ok(())
}

fn null_samples(
    cipher: CipherFamily,
    config: CipherAttackConfig,
    messages: &[Vec<Glyph>],
    plans: &[ScoringPlan],
) -> Result<Vec<Vec<f64>>, CipherAttackError> {
    let mut samples = vec![Vec::new(); plans.len()];
    let mut rng = SplitMix64::new(mix_seed(config.seed, cipher.seed_tag() ^ 0x6e75_6c6c));

    for _trial in 0..config.null_trials {
        let shuffled = shuffled_messages(messages, &mut rng)?;
        let outcome = search_cipher(cipher, config, &shuffled, plans)?;
        for (slot, best) in samples.iter_mut().zip(outcome.best) {
            slot.push(best.score.bigram_mean_log_likelihood);
        }
    }

    Ok(samples)
}

#[derive(Clone, Debug, PartialEq)]
struct SearchOutcome {
    summary: SearchSummary,
    best: Vec<BestCandidate>,
}

fn search_cipher(
    cipher: CipherFamily,
    config: CipherAttackConfig,
    messages: &[Vec<Glyph>],
    plans: &[ScoringPlan],
) -> Result<SearchOutcome, CipherAttackError> {
    match cipher {
        CipherFamily::Caesar => search_caesar(messages, plans),
        CipherFamily::IncrementingWheel => search_incrementing_wheel(messages, plans),
        CipherFamily::Vigenere => search_vigenere(config, messages, plans),
        CipherFamily::Chaocipher => search_chaocipher(config, messages, plans),
        CipherFamily::Deck => search_deck(config, messages, plans),
    }
}

fn search_caesar(
    messages: &[Vec<Glyph>],
    plans: &[ScoringPlan],
) -> Result<SearchOutcome, CipherAttackError> {
    let mut trackers = BestTrackers::new(plans.len());
    for shift in 0..EYE_READING_ALPHABET_SIZE {
        let key = CaesarKey::new(EYE_READING_ALPHABET_SIZE, shift)?;
        let decrypted = decrypt_messages(messages, |message| caesar_decrypt(message, &key))?;
        let label = caesar_key_label(shift);
        trackers.update(plans, &decrypted, &label)?;
    }
    Ok(SearchOutcome {
        summary: SearchSummary {
            key_space: "83 shifts".to_owned(),
            candidates_evaluated: EYE_READING_ALPHABET_SIZE,
            exhaustive: true,
            sampling_seed: None,
            note: "brute-forced all 83 shifts".to_owned(),
        },
        best: trackers.finish(CipherFamily::Caesar)?,
    })
}

fn search_incrementing_wheel(
    messages: &[Vec<Glyph>],
    plans: &[ScoringPlan],
) -> Result<SearchOutcome, CipherAttackError> {
    let mut trackers = BestTrackers::new(plans.len());
    let mut candidates = 0usize;
    for start in 0..EYE_READING_ALPHABET_SIZE {
        for step in 0..EYE_READING_ALPHABET_SIZE {
            let key = IncrementingWheelKey::new(EYE_READING_ALPHABET_SIZE, start, step)?;
            let decrypted = decrypt_messages(messages, |message| {
                incrementing_wheel_decrypt(message, &key)
            })?;
            let label = format!("start={start} step={step}");
            trackers.update(plans, &decrypted, &label)?;
            candidates += 1;
        }
    }
    Ok(SearchOutcome {
        summary: SearchSummary {
            key_space: "83 x 83 start/step pairs".to_owned(),
            candidates_evaluated: candidates,
            exhaustive: true,
            sampling_seed: None,
            note: "brute-forced every start and step".to_owned(),
        },
        best: trackers.finish(CipherFamily::IncrementingWheel)?,
    })
}

fn search_vigenere(
    config: CipherAttackConfig,
    messages: &[Vec<Glyph>],
    plans: &[ScoringPlan],
) -> Result<SearchOutcome, CipherAttackError> {
    let total = vigenere_key_space(EYE_READING_ALPHABET_SIZE, config.vigenere_max_period)?;
    let search_seed = mix_seed(config.seed, CipherFamily::Vigenere.seed_tag());
    let exhaustive = config.samples >= total;
    let candidates = if exhaustive { total } else { config.samples };
    let mut trackers = BestTrackers::new(plans.len());
    let mut rng = SplitMix64::new(search_seed);

    for ordinal_index in 0..candidates {
        let ordinal = if exhaustive {
            ordinal_index
        } else {
            random_index_below(total, &mut rng)?
        };
        let shifts = vigenere_shifts_from_ordinal(
            ordinal,
            EYE_READING_ALPHABET_SIZE,
            config.vigenere_max_period,
        )?;
        let key = VigenereKey::new(EYE_READING_ALPHABET_SIZE, shifts.clone())?;
        let decrypted = decrypt_messages(messages, |message| vigenere_decrypt(message, &key))?;
        let label = vigenere_key_label(&shifts);
        trackers.update(plans, &decrypted, &label)?;
    }

    Ok(SearchOutcome {
        summary: SearchSummary {
            key_space: vigenere_key_space_label(config.vigenere_max_period, total),
            candidates_evaluated: candidates,
            exhaustive,
            sampling_seed: if exhaustive { None } else { Some(search_seed) },
            note: vigenere_note(exhaustive, candidates),
        },
        best: trackers.finish(CipherFamily::Vigenere)?,
    })
}

fn search_chaocipher(
    config: CipherAttackConfig,
    messages: &[Vec<Glyph>],
    plans: &[ScoringPlan],
) -> Result<SearchOutcome, CipherAttackError> {
    let search_seed = mix_seed(config.seed, CipherFamily::Chaocipher.seed_tag());
    let mut rng = SplitMix64::new(search_seed);
    let mut trackers = BestTrackers::new(plans.len());

    for sample_index in 0..config.samples {
        let left = random_permutation(EYE_READING_ALPHABET_SIZE, &mut rng)?;
        let right = random_permutation(EYE_READING_ALPHABET_SIZE, &mut rng)?;
        let key = ChaocipherKey::new(EYE_READING_ALPHABET_SIZE, left.clone(), right.clone())?;
        let decrypted = decrypt_messages(messages, |message| chaocipher_decrypt(message, &key))?;
        let label = format!(
            "sample={sample_index} seed={search_seed} left_prefix={} right_prefix={}",
            format_prefix(&left, 8),
            format_prefix(&right, 8)
        );
        trackers.update(plans, &decrypted, &label)?;
    }

    Ok(SearchOutcome {
        summary: SearchSummary {
            key_space: "about 83! x 83! initial alphabet pairs".to_owned(),
            candidates_evaluated: config.samples,
            exhaustive: false,
            sampling_seed: Some(search_seed),
            note: format!(
                "sampled {} Chaocipher keys with SplitMix64; this is not a brute force",
                config.samples
            ),
        },
        best: trackers.finish(CipherFamily::Chaocipher)?,
    })
}

fn search_deck(
    config: CipherAttackConfig,
    messages: &[Vec<Glyph>],
    plans: &[ScoringPlan],
) -> Result<SearchOutcome, CipherAttackError> {
    let search_seed = mix_seed(config.seed, CipherFamily::Deck.seed_tag());
    let mut rng = SplitMix64::new(search_seed);
    let mut trackers = BestTrackers::new(plans.len());

    for sample_index in 0..config.samples {
        let deck = random_permutation(EYE_READING_ALPHABET_SIZE, &mut rng)?;
        let control_a = random_index_below(EYE_READING_ALPHABET_SIZE, &mut rng)?;
        let control_b = random_distinct_control(control_a, &mut rng)?;
        let key = DeckCipherKey::new(
            EYE_READING_ALPHABET_SIZE,
            deck.clone(),
            control_a,
            control_b,
        )?;
        let decrypted = decrypt_messages(messages, |message| deck_cipher_decrypt(message, &key))?;
        let label = format!(
            "sample={sample_index} seed={search_seed} controls=({control_a},{control_b}) deck_prefix={}",
            format_prefix(&deck, 8)
        );
        trackers.update(plans, &decrypted, &label)?;
    }

    Ok(SearchOutcome {
        summary: SearchSummary {
            key_space: "about 83! deck permutations times 83 x 82 controls".to_owned(),
            candidates_evaluated: config.samples,
            exhaustive: false,
            sampling_seed: Some(search_seed),
            note: format!(
                "sampled {} deck keys with SplitMix64; this is not a brute force",
                config.samples
            ),
        },
        best: trackers.finish(CipherFamily::Deck)?,
    })
}

#[derive(Clone, Debug)]
struct BestTrackers {
    best: Vec<Option<BestCandidate>>,
}

impl BestTrackers {
    fn new(plan_count: usize) -> Self {
        Self {
            best: vec![None; plan_count],
        }
    }

    fn update(
        &mut self,
        plans: &[ScoringPlan],
        decrypted: &[Vec<Glyph>],
        key: &str,
    ) -> Result<(), CipherAttackError> {
        for (plan, slot) in plans.iter().zip(self.best.iter_mut()) {
            let score = score_candidate(decrypted, plan)?;
            if slot.as_ref().is_none_or(|best| {
                score.bigram_mean_log_likelihood > best.score.bigram_mean_log_likelihood
            }) {
                *slot = Some(BestCandidate {
                    score,
                    key: key.to_owned(),
                });
            }
        }
        Ok(())
    }

    fn finish(self, cipher: CipherFamily) -> Result<Vec<BestCandidate>, CipherAttackError> {
        let mut best = Vec::with_capacity(self.best.len());
        for candidate in self.best {
            let Some(candidate) = candidate else {
                return Err(CipherAttackError::NoKeyCandidates { cipher });
            };
            best.push(candidate);
        }
        Ok(best)
    }
}

fn decrypt_messages(
    messages: &[Vec<Glyph>],
    mut decrypt: impl FnMut(&[Glyph]) -> Result<Vec<Glyph>, CipherError>,
) -> Result<Vec<Vec<Glyph>>, CipherAttackError> {
    let mut decrypted = Vec::with_capacity(messages.len());
    for message in messages {
        decrypted.push(decrypt(message)?);
    }
    Ok(decrypted)
}

fn score_candidate(
    messages: &[Vec<Glyph>],
    plan: &ScoringPlan,
) -> Result<CandidateScore, CipherAttackError> {
    let mapped = map_messages(messages, plan)?;
    weighted_language_score(&mapped, &plan.model)
}

fn map_messages(
    messages: &[Vec<Glyph>],
    plan: &ScoringPlan,
) -> Result<Vec<Vec<usize>>, CipherAttackError> {
    match plan.mapping {
        MappingKind::Modulo => map_messages_modulo(messages, plan.target_letters),
        MappingKind::FrequencyRankCdf => map_messages_frequency_rank(messages, plan),
    }
}

fn map_messages_modulo(
    messages: &[Vec<Glyph>],
    target_letters: usize,
) -> Result<Vec<Vec<usize>>, CipherAttackError> {
    if target_letters == 0 {
        return Err(CipherAttackError::EmptyMapping);
    }
    let mut mapped_messages = Vec::with_capacity(messages.len());
    for message in messages {
        let mut mapped = Vec::with_capacity(message.len());
        for glyph in message {
            let symbol = eye_symbol(*glyph)?;
            mapped.push(symbol % target_letters);
        }
        mapped_messages.push(mapped);
    }
    Ok(mapped_messages)
}

fn map_messages_frequency_rank(
    messages: &[Vec<Glyph>],
    plan: &ScoringPlan,
) -> Result<Vec<Vec<usize>>, CipherAttackError> {
    let table = frequency_rank_table(messages, plan)?;
    let mut mapped_messages = Vec::with_capacity(messages.len());
    for message in messages {
        let mut mapped = Vec::with_capacity(message.len());
        for glyph in message {
            let symbol = eye_symbol(*glyph)?;
            let Some(&index) = table.get(symbol) else {
                return Err(CipherAttackError::EmptyMapping);
            };
            mapped.push(index);
        }
        mapped_messages.push(mapped);
    }
    Ok(mapped_messages)
}

fn frequency_rank_table(
    messages: &[Vec<Glyph>],
    plan: &ScoringPlan,
) -> Result<Vec<usize>, CipherAttackError> {
    if plan.target_letters == 0 || plan.target_letters > plan.model.alphabet().len() {
        return Err(CipherAttackError::EmptyMapping);
    }

    let mut counts = vec![0usize; EYE_READING_ALPHABET_SIZE];
    for message in messages {
        for glyph in message {
            let symbol = eye_symbol(*glyph)?;
            let Some(count) = counts.get_mut(symbol) else {
                return Err(CipherAttackError::EmptyMapping);
            };
            *count += 1;
        }
    }

    let mut ranked_symbols = counts
        .iter()
        .copied()
        .enumerate()
        .collect::<Vec<(usize, usize)>>();
    ranked_symbols.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    let ranked_letters = ranked_language_letters(plan)?;
    let total_weight = ranked_letters
        .iter()
        .map(|(_index, count)| *count)
        .sum::<usize>();
    if total_weight == 0 {
        return Err(CipherAttackError::EmptyMapping);
    }

    let mut table = vec![0usize; EYE_READING_ALPHABET_SIZE];
    for (rank, (symbol, _count)) in ranked_symbols.iter().copied().enumerate() {
        let fraction = (rank as f64 + 0.5) / EYE_READING_ALPHABET_SIZE as f64;
        let letter = ranked_letter_for_fraction(fraction, &ranked_letters, total_weight)?;
        let Some(slot) = table.get_mut(symbol) else {
            return Err(CipherAttackError::EmptyMapping);
        };
        *slot = letter;
    }
    Ok(table)
}

fn ranked_language_letters(plan: &ScoringPlan) -> Result<Vec<(usize, usize)>, CipherAttackError> {
    let mut ranked = Vec::with_capacity(plan.target_letters);
    for index in 0..plan.target_letters {
        ranked.push((index, plan.model.unigram_count(index)?));
    }
    ranked.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    Ok(ranked)
}

fn ranked_letter_for_fraction(
    fraction: f64,
    ranked_letters: &[(usize, usize)],
    total_weight: usize,
) -> Result<usize, CipherAttackError> {
    let threshold = fraction * total_weight as f64;
    let mut cumulative = 0usize;
    for (index, count) in ranked_letters.iter().copied() {
        cumulative += count;
        if cumulative as f64 >= threshold {
            return Ok(index);
        }
    }
    ranked_letters
        .last()
        .map(|(index, _count)| *index)
        .ok_or(CipherAttackError::EmptyMapping)
}

fn weighted_language_score(
    messages: &[Vec<usize>],
    model: &LanguageModel,
) -> Result<CandidateScore, CipherAttackError> {
    let mut symbols = 0usize;
    let mut unigram = 0.0;
    let mut bigram = 0.0;

    for message in messages {
        if message.is_empty() {
            continue;
        }
        let score = model.score_indices(message)?;
        symbols += score.symbols;
        unigram += score.unigram_mean_log_likelihood * score.symbols as f64;
        bigram += score.bigram_mean_log_likelihood * score.symbols as f64;
    }

    if symbols == 0 {
        return Err(CipherAttackError::EmptyCorpus);
    }

    Ok(CandidateScore {
        symbols,
        unigram_mean_log_likelihood: unigram / symbols as f64,
        bigram_mean_log_likelihood: bigram / symbols as f64,
    })
}

fn eye_symbol(glyph: Glyph) -> Result<usize, CipherAttackError> {
    let symbol = usize::from(glyph.0);
    if symbol >= EYE_READING_ALPHABET_SIZE {
        return Err(CipherAttackError::ValueOutsideEyeAlphabet { value: glyph.0 });
    }
    Ok(symbol)
}

fn summarize_null(real_score: f64, samples: &[f64]) -> ScoreNull {
    let trials = samples.len();
    let mean = if samples.is_empty() {
        0.0
    } else {
        samples.iter().sum::<f64>() / trials as f64
    };
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    let max = sorted.last().copied().unwrap_or(0.0);
    let q95 = quantile_from_sorted(&sorted, 95, 100);
    let empirical_p_count = samples.iter().filter(|&&score| score >= real_score).count();
    ScoreNull {
        trials,
        mean,
        q95,
        max,
        empirical_p_count,
        empirical_p: if trials == 0 {
            0.0
        } else {
            empirical_p_count as f64 / trials as f64
        },
    }
}

fn quantile_from_sorted(sorted: &[f64], numerator: usize, denominator: usize) -> f64 {
    let Some(last_index) = sorted.len().checked_sub(1) else {
        return 0.0;
    };
    let rank = last_index.saturating_mul(numerator) / denominator;
    sorted.get(rank).copied().unwrap_or(0.0)
}

fn vigenere_key_space(alphabet_size: usize, max_period: usize) -> Result<usize, CipherAttackError> {
    if max_period == 0 {
        return Err(CipherAttackError::ZeroVigenereMaxPeriod);
    }
    let mut total = 0usize;
    let mut period_space = 1usize;
    for _period in 1..=max_period {
        period_space = period_space
            .checked_mul(alphabet_size)
            .ok_or(CipherAttackError::RandomBoundTooLarge { bound: usize::MAX })?;
        total = total
            .checked_add(period_space)
            .ok_or(CipherAttackError::RandomBoundTooLarge { bound: usize::MAX })?;
    }
    Ok(total)
}

fn vigenere_shifts_from_ordinal(
    ordinal: usize,
    alphabet_size: usize,
    max_period: usize,
) -> Result<Vec<usize>, CipherAttackError> {
    let mut remaining = ordinal;
    let mut period_space = 1usize;
    for period in 1..=max_period {
        period_space = period_space
            .checked_mul(alphabet_size)
            .ok_or(CipherAttackError::RandomBoundTooLarge { bound: usize::MAX })?;
        if remaining < period_space {
            return Ok(shifts_for_period(remaining, period, alphabet_size));
        }
        remaining -= period_space;
    }
    Err(CipherAttackError::RandomBoundTooLarge { bound: ordinal })
}

fn shifts_for_period(mut ordinal: usize, period: usize, alphabet_size: usize) -> Vec<usize> {
    let mut shifts = Vec::with_capacity(period);
    for _position in 0..period {
        shifts.push(ordinal % alphabet_size);
        ordinal /= alphabet_size;
    }
    shifts
}

fn vigenere_key_space_label(max_period: usize, total: usize) -> String {
    format!("sum 83^p for p=1..={max_period} ({total} keys)")
}

fn vigenere_note(exhaustive: bool, candidates: usize) -> String {
    if exhaustive {
        format!("brute-forced all {candidates} short-period Vigenere keys")
    } else {
        format!("sampled {candidates} short-period Vigenere keys with SplitMix64")
    }
}

fn caesar_key_label(shift: usize) -> String {
    format!("shift={shift}")
}

fn vigenere_key_label(shifts: &[usize]) -> String {
    let values = shifts
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",");
    format!("period={} shifts={values}", shifts.len())
}

fn shuffled_messages(
    messages: &[Vec<Glyph>],
    rng: &mut SplitMix64,
) -> Result<Vec<Vec<Glyph>>, CipherAttackError> {
    let mut shuffled = Vec::with_capacity(messages.len());
    for message in messages {
        let mut local = message.clone();
        fisher_yates(&mut local, rng)?;
        shuffled.push(local);
    }
    Ok(shuffled)
}

fn random_permutation(
    alphabet_size: usize,
    rng: &mut SplitMix64,
) -> Result<Vec<usize>, CipherAttackError> {
    let mut values = (0..alphabet_size).collect::<Vec<_>>();
    fisher_yates(&mut values, rng)?;
    Ok(values)
}

fn random_distinct_control(
    control_a: usize,
    rng: &mut SplitMix64,
) -> Result<usize, CipherAttackError> {
    loop {
        let control_b = random_index_below(EYE_READING_ALPHABET_SIZE, rng)?;
        if control_b != control_a {
            return Ok(control_b);
        }
    }
}

fn mix_seed(seed: u64, tag: u64) -> u64 {
    let mut rng = SplitMix64::new(seed ^ tag);
    rng.next_u64()
}

fn format_prefix(values: &[usize], limit: usize) -> String {
    let mut parts = values
        .iter()
        .take(limit)
        .map(usize::to_string)
        .collect::<Vec<_>>();
    if values.len() > limit {
        parts.push("...".to_owned());
    }
    format!("[{}]", parts.join(","))
}

fn run_positive_controls(seed: u64) -> Result<PositiveControlReport, CipherAttackError> {
    let plaintext = positive_control_plaintext()?;
    let plans = vec![english_modulo_plan()?];
    let control_config = CipherAttackConfig {
        seed: mix_seed(seed, 0x706f_7369_7469_7665),
        samples: 10_000,
        null_trials: POSITIVE_CONTROL_NULL_TRIALS,
        vigenere_max_period: POSITIVE_CONTROL_VIGENERE_SHIFTS.len(),
    };

    let caesar_key = CaesarKey::new(EYE_READING_ALPHABET_SIZE, POSITIVE_CONTROL_CAESAR_SHIFT)?;
    let caesar_ciphertext =
        encrypt_messages(&plaintext, |message| caesar_encrypt(message, &caesar_key))?;
    let caesar = recover_plant(
        CipherFamily::Caesar,
        control_config,
        &caesar_ciphertext,
        &plans,
        caesar_key_label(POSITIVE_CONTROL_CAESAR_SHIFT),
    )?;

    let vigenere_shifts = POSITIVE_CONTROL_VIGENERE_SHIFTS.to_vec();
    let vigenere_key = VigenereKey::new(EYE_READING_ALPHABET_SIZE, vigenere_shifts.clone())?;
    let vigenere_ciphertext = encrypt_messages(&plaintext, |message| {
        vigenere_encrypt(message, &vigenere_key)
    })?;
    let vigenere = recover_plant(
        CipherFamily::Vigenere,
        control_config,
        &vigenere_ciphertext,
        &plans,
        vigenere_key_label(&vigenere_shifts),
    )?;

    Ok(PositiveControlReport { caesar, vigenere })
}

fn english_modulo_plan() -> Result<ScoringPlan, CipherAttackError> {
    Ok(ScoringPlan {
        language: LanguageKind::English,
        model: english_model()?,
        mapping: MappingKind::Modulo,
        target_letters: 26,
    })
}

fn positive_control_plaintext() -> Result<Vec<Vec<Glyph>>, CipherAttackError> {
    let model = english_model()?;
    let indices = model.alphabet().normalize_text(POSITIVE_CONTROL_TEXT)?;
    let mut message = Vec::with_capacity(indices.len());
    for index in indices {
        let value = u16::try_from(index).map_err(|_error| CipherAttackError::EmptyMapping)?;
        message.push(Glyph(value));
    }
    Ok(vec![message])
}

fn encrypt_messages(
    messages: &[Vec<Glyph>],
    mut encrypt: impl FnMut(&[Glyph]) -> Result<Vec<Glyph>, CipherError>,
) -> Result<Vec<Vec<Glyph>>, CipherAttackError> {
    let mut encrypted = Vec::with_capacity(messages.len());
    for message in messages {
        encrypted.push(encrypt(message)?);
    }
    Ok(encrypted)
}

fn recover_plant(
    cipher: CipherFamily,
    config: CipherAttackConfig,
    ciphertext: &[Vec<Glyph>],
    plans: &[ScoringPlan],
    expected_key: String,
) -> Result<PlantRecovery, CipherAttackError> {
    let real = search_cipher(cipher, config, ciphertext, plans)?;
    let Some(best) = real.best.into_iter().next() else {
        return Err(CipherAttackError::NoKeyCandidates { cipher });
    };
    let samples = plant_null_scores(cipher, config, ciphertext, plans)?;
    let null = summarize_null(best.score.bigram_mean_log_likelihood, &samples);
    let margin = best.score.bigram_mean_log_likelihood - null.max;
    if best.key != expected_key || margin < POSITIVE_CONTROL_MIN_MARGIN {
        return Err(CipherAttackError::PositiveControlFailed {
            cipher,
            expected_key,
            recovered_key: best.key,
            real_score: best.score.bigram_mean_log_likelihood,
            null_max: null.max,
        });
    }
    Ok(PlantRecovery {
        cipher,
        plaintext_symbols: best.score.symbols,
        expected_key,
        recovered_key: best.key,
        real_score: best.score,
        null,
        margin_over_null_max: margin,
    })
}

fn plant_null_scores(
    cipher: CipherFamily,
    config: CipherAttackConfig,
    ciphertext: &[Vec<Glyph>],
    plans: &[ScoringPlan],
) -> Result<Vec<f64>, CipherAttackError> {
    let mut samples = Vec::with_capacity(config.null_trials);
    let mut rng = SplitMix64::new(mix_seed(config.seed, cipher.seed_tag() ^ 0x0070_6c61_6e74));
    for _trial in 0..config.null_trials {
        let shuffled = shuffled_messages(ciphertext, &mut rng)?;
        let outcome = search_cipher(cipher, config, &shuffled, plans)?;
        let Some(best) = outcome.best.into_iter().next() else {
            return Err(CipherAttackError::NoKeyCandidates { cipher });
        };
        samples.push(best.score.bigram_mean_log_likelihood);
    }
    Ok(samples)
}

#[cfg(test)]
fn run_cipher_attack_for_test(
    config: CipherAttackConfig,
    messages: &[Vec<Glyph>],
) -> Result<Vec<AttackRow>, CipherAttackError> {
    validate_config(config)?;
    let plans = scoring_plans()?;
    let mut rows = Vec::new();
    for cipher in CipherFamily::all() {
        append_cipher_rows(cipher, config, messages, &plans, &mut rows)?;
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::{
        CipherAttackConfig, CipherFamily, POSITIVE_CONTROL_MIN_MARGIN, run_cipher_attack_for_test,
        run_positive_controls,
    };
    use crate::glyph::Glyph;

    #[test]
    fn shuffle_null_is_deterministic_for_fixed_seed() {
        let config = CipherAttackConfig {
            seed: 0x1234_5678,
            samples: 4,
            null_trials: 2,
            vigenere_max_period: 2,
        };
        let messages = vec![
            glyphs(&[0, 1, 2, 3, 4, 5, 6, 7]),
            glyphs(&[8, 9, 10, 11, 12, 13]),
        ];
        let first = run_cipher_attack_for_test(config, &messages).unwrap();
        let second = run_cipher_attack_for_test(config, &messages).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn positive_control_recovers_caesar_and_vigenere_plants() {
        let report = run_positive_controls(0xfeed_face).unwrap();
        assert_eq!(report.caesar.cipher, CipherFamily::Caesar);
        assert_eq!(report.caesar.expected_key, report.caesar.recovered_key);
        assert!(report.caesar.margin_over_null_max >= POSITIVE_CONTROL_MIN_MARGIN);
        assert_eq!(report.vigenere.cipher, CipherFamily::Vigenere);
        assert_eq!(report.vigenere.expected_key, report.vigenere.recovered_key);
        assert!(report.vigenere.margin_over_null_max >= POSITIVE_CONTROL_MIN_MARGIN);
    }

    fn glyphs(values: &[u16]) -> Vec<Glyph> {
        values.iter().copied().map(Glyph).collect()
    }
}

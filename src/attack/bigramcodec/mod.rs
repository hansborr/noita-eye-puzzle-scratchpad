//! Bigram-order codec probe for base-walk practice puzzles.
//!
//! `bigramcodec` is the converse of `rlcodec`'s quadgram-over-bigram battery: it
//! asks whether simple token streams already carry language at the bigram level.
//! That is exactly where the practice-puzzle hint points, but it is also where
//! the known base-5 walk and GAK repeat can create non-language ordering. For
//! that reason every stream is reported with a readability crib heuristic plus
//! two diagnostic nulls:
//!
//! - order-0: a unigram-preserving shuffle, which has power for token ordering
//!   but is confounded by the walk/repeat structure;
//! - order-1: a Markov resample preserving token bigram transitions, the
//!   confound control. Because the scorer is itself a bigram objective, this null
//!   is deliberately near-powerless as a language discriminator: the self-test
//!   pins a perfectly recovered English plant at only about order-1 z = +0.6,
//!   p = 0.33.
//!
//! A candidate is therefore readable hypothesis text, never a decode. If text is
//! not readable but beats order-0, the measured signal is token-bigram structure,
//! not language. The order-1 table is retained to expose the confound and the
//! statistical gate's lack of power at this carrier budget.

use std::collections::BTreeMap;
use std::fmt;

use crate::analysis::translate_isomorph::{IsoScanError, markov_resample};
use crate::attack::language::{LanguageError, LanguageModel, english_model, finnish_model};
use crate::attack::rlcodec::{RlError, derive_magnitudes};
use crate::core::glyph::Glyph;
use crate::nulls::null::{RandomBoundError, SplitMix64, add_one_p_value, fisher_yates, mix_seed};

mod derive;
mod plant;
mod search;
mod selftest;

#[cfg(test)]
mod tests;

pub use derive::{StreamKind, TokenStream, all_streams, tokenize};
pub use plant::{BIGRAM_PLANT_STREAM, BIGRAM_PLANT_TEXT, planted_magpair_walk};
pub use search::{BigramSubResult, MIN_TOKENS, substitution_search};
pub use selftest::{BigramSelfTestReport, bigramcodec_self_test};

/// Default deterministic seed for `bigramcodec`.
pub const DEFAULT_SEED: u64 = 0x6269_6772_616d_0001;
/// Default null trials per stream/language/null family.
pub const DEFAULT_NULL_TRIALS: usize = 32;
/// Default substitution-search restarts.
pub const DEFAULT_RESTARTS: usize = 8;
/// Default substitution-search proposals per restart.
pub const DEFAULT_ITERS: usize = 900;
/// Gate threshold for add-one p-values.
pub const SURVIVOR_ALPHA: f64 = 0.05;
/// Streams below this alphabet size are explicitly alphabet-capped in reports.
pub const GENERAL_ENGLISH_DISTINCT_FLOOR: usize = 20;
/// Minimum distinct crib-word hits for a decoded text to be considered readable.
///
/// This is a small deterministic crib heuristic, not a language model. It exists
/// because the bigram objective and the bigram-preserving order-1 null cannot by
/// themselves discriminate a recovered English monoalphabetic plant.
pub const READABLE_MIN: usize = 3;

const SIGMA_FLOOR: f64 = 1e-9;
const REAL_TAG: u64 = 0x6269_6772_5ea1_0001;
const ORDER0_TAG: u64 = 0x6269_6772_0000_0001;
const ORDER1_TAG: u64 = 0x6269_6772_0001_0001;

const READABLE_WORDS: &[&str] = &[
    "THAT", "WITH", "HAVE", "THIS", "FROM", "THEY", "WERE", "BEEN", "INTO", "ONTO", "OVER", "THAN",
    "THEN", "WHEN", "RAIN", "WIND", "ROAD", "TREE", "TREES", "LOST", "LAND", "LANDS", "NORTH",
    "RIDER", "RIDERS", "STONE", "WALL", "WALLS", "DEAD", "SLOW", "SEASON", "SEASONS", "SILENT",
    "SHADE", "TIRED", "RODE", "LONE", "SAIL", "SAILED", "TRADE", "TRADED", "HELD",
];

/// Configuration for one bigramcodec run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BigramCfg {
    /// Matched-null trials per null family.
    pub null_trials: usize,
    /// Substitution-search random restarts.
    pub restarts: usize,
    /// Substitution-search proposals per restart.
    pub iters: usize,
    /// Deterministic seed for the real and null searches.
    pub seed: u64,
}

/// Returns the default CLI report budget.
#[must_use]
pub const fn default_bigram_cfg() -> BigramCfg {
    BigramCfg {
        null_trials: DEFAULT_NULL_TRIALS,
        restarts: DEFAULT_RESTARTS,
        iters: DEFAULT_ITERS,
        seed: DEFAULT_SEED,
    }
}

/// Error type for `bigramcodec`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BigramError {
    /// A shared run-length carrier primitive failed.
    Rl(RlError),
    /// The language model or scorer rejected input.
    Language(LanguageError),
    /// The order-1 Markov resampler rejected input.
    Iso(IsoScanError),
    /// An in-crate random draw rejected its bound.
    Random(RandomBoundError),
    /// No stream was selected.
    EmptySelection,
    /// A selected token stream produced no tokens.
    EmptyStream {
        /// The selected stream.
        stream: StreamKind,
    },
    /// `mag-pairs` cannot use the specified base without raw-symbol collisions.
    MagnitudeExceedsBase {
        /// Offending run-length magnitude.
        magnitude: usize,
        /// Declared base.
        base: usize,
    },
    /// Null trials must be positive because both null gates are required.
    ZeroNullTrials,
}

impl From<RlError> for BigramError {
    fn from(error: RlError) -> Self {
        Self::Rl(error)
    }
}

impl From<LanguageError> for BigramError {
    fn from(error: LanguageError) -> Self {
        Self::Language(error)
    }
}

impl From<IsoScanError> for BigramError {
    fn from(error: IsoScanError) -> Self {
        Self::Iso(error)
    }
}

impl From<RandomBoundError> for BigramError {
    fn from(error: RandomBoundError) -> Self {
        Self::Random(error)
    }
}

impl fmt::Display for BigramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Rl(error) => write!(f, "{error}"),
            Self::Language(error) => write!(f, "language model: {error}"),
            Self::Iso(error) => write!(f, "order-1 Markov null: {error}"),
            Self::Random(error) => write!(f, "random draw rejected bound {}", error.bound),
            Self::EmptySelection => write!(f, "no bigramcodec streams were selected"),
            Self::EmptyStream { stream } => {
                write!(f, "stream {} produced no tokens", stream.label())
            }
            Self::MagnitudeExceedsBase { magnitude, base } => write!(
                f,
                "mag-pairs magnitude {magnitude} exceeds base {base}; refusing a colliding raw-symbol encoding"
            ),
            Self::ZeroNullTrials => write!(f, "bigramcodec requires at least one null trial"),
        }
    }
}

impl std::error::Error for BigramError {}

/// Language model selected for one row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BigramLanguage {
    /// English bigram model.
    English,
    /// Finnish bigram model.
    Finnish,
}

impl BigramLanguage {
    /// Report label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::English => "English",
            Self::Finnish => "Finnish",
        }
    }

    const fn seed_tag(self) -> u64 {
        match self {
            Self::English => 0x656e_676c_6973_6801,
            Self::Finnish => 0x6669_6e6e_6973_6801,
        }
    }
}

/// Null family for one gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NullKind {
    /// Unigram-preserving random shuffle.
    Order0,
    /// Order-1 Markov resample preserving token transitions.
    Order1,
}

impl NullKind {
    /// Report label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Order0 => "order-0",
            Self::Order1 => "order-1",
        }
    }
}

/// Calibration statistics for one null family.
#[derive(Clone, Debug, PartialEq)]
pub struct NullStats {
    /// Null family.
    pub kind: NullKind,
    /// Number of valid null searches.
    pub trials: usize,
    /// Mean best score under the null.
    pub mean: f64,
    /// Maximum best score under the null.
    pub ceiling: f64,
    /// z-score of the observed score against this null.
    pub z: f64,
    /// Add-one p-value versus this null.
    pub p: f64,
    /// Whether the observed score beats this null gate.
    pub beats: bool,
}

/// Honest high-level verdict for one stream/language row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HonestVerdict {
    /// The decoded text clears the readability heuristic; still only a candidate
    /// hypothesis, and the text must be inspected by eye.
    Candidate,
    /// The text is not readable, but order-0 cleared: token-bigram artifact.
    Artifact,
    /// The text is not readable and order-0 did not clear.
    Negative,
    /// Search was skipped because the stream was too short or alphabet-rich.
    Skipped,
}

impl HonestVerdict {
    /// Report label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Artifact => "artifact",
            Self::Negative => "negative",
            Self::Skipped => "skipped",
        }
    }
}

/// Counts distinct curated English crib words that occur as substrings of `text`.
///
/// The fixed list is intentionally small and plant-aware. It is a deterministic
/// readability tripwire for human inspection, not a general language model and
/// not evidence of plaintext recovery by itself.
#[must_use]
pub fn readable_coverage(text: &str) -> usize {
    let upper = text.to_ascii_uppercase();
    READABLE_WORDS
        .iter()
        .filter(|word| word.len() >= 4 && upper.contains(*word))
        .count()
}

/// Summary of the derived base-walk carrier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CarrierSummary {
    /// Number of input digits.
    pub n_digits: usize,
    /// Base of the walk.
    pub base: usize,
    /// Number of unit moves.
    pub n_bits: usize,
    /// Number of up moves.
    pub n_up: usize,
    /// Number of down moves.
    pub n_down: usize,
    /// Number of direction-blind run-length magnitudes.
    pub n_magnitudes: usize,
    /// Magnitude distribution as sorted `(magnitude, count)` pairs.
    pub distribution: Vec<(usize, usize)>,
}

/// Result for one language model on one stream.
#[derive(Clone, Debug, PartialEq)]
pub struct LanguageRow {
    /// Language model.
    pub language: BigramLanguage,
    /// Best real substitution result.
    pub real: BigramSubResult,
    /// Order-0 null calibration, absent only when skipped.
    pub order0: Option<NullStats>,
    /// Order-1 null calibration, absent only when skipped.
    pub order1: Option<NullStats>,
    /// Number of distinct curated readability crib words in the best text.
    pub readability_coverage: usize,
    /// Honest verdict.
    pub verdict: HonestVerdict,
}

/// Result for one stream.
#[derive(Clone, Debug, PartialEq)]
pub struct StreamReport {
    /// Token stream summary.
    pub stream: TokenStream,
    /// Per-language rows.
    pub languages: Vec<LanguageRow>,
}

/// Full bigramcodec report.
#[derive(Clone, Debug, PartialEq)]
pub struct BigramReport {
    /// Carrier derivation summary.
    pub carrier: CarrierSummary,
    /// Streams analyzed.
    pub streams: Vec<StreamReport>,
}

impl BigramReport {
    /// True if any stream/language row reached candidate status.
    #[must_use]
    pub fn has_candidate(&self) -> bool {
        self.streams.iter().any(|stream| {
            stream
                .languages
                .iter()
                .any(|row| row.verdict == HonestVerdict::Candidate)
        })
    }
}

/// Runs the bigram-order codec gate on selected token streams.
///
/// # Errors
/// Returns [`BigramError`] if the input is not a clean base walk, a language
/// model fails to build, a token stream is invalid, or a null/search step fails.
pub fn analyze_bigramcodec(
    digits: &[Glyph],
    base: usize,
    selected_streams: &[StreamKind],
    cfg: &BigramCfg,
) -> Result<BigramReport, BigramError> {
    if cfg.null_trials == 0 {
        return Err(BigramError::ZeroNullTrials);
    }
    let streams = resolve_streams(selected_streams)?;
    let derivation = derive_magnitudes(digits, base)?;
    let carrier = summarise(digits.len(), base, &derivation);
    let models = [
        (BigramLanguage::English, english_model()?),
        (BigramLanguage::Finnish, finnish_model()?),
    ];

    let mut stream_reports = Vec::new();
    for stream_kind in streams {
        let stream = tokenize(stream_kind, digits, &derivation.magnitudes, base)?;
        let mut languages = Vec::new();
        for (language, model) in &models {
            languages.push(evaluate_language(&stream, *language, model, cfg)?);
        }
        stream_reports.push(StreamReport { stream, languages });
    }

    Ok(BigramReport {
        carrier,
        streams: stream_reports,
    })
}

fn resolve_streams(selected_streams: &[StreamKind]) -> Result<Vec<StreamKind>, BigramError> {
    let source = if selected_streams.is_empty() {
        all_streams().to_vec()
    } else {
        selected_streams.to_vec()
    };
    let mut out = Vec::new();
    for stream in source {
        if !out.contains(&stream) {
            out.push(stream);
        }
    }
    if out.is_empty() {
        return Err(BigramError::EmptySelection);
    }
    Ok(out)
}

fn evaluate_language(
    stream: &TokenStream,
    language: BigramLanguage,
    model: &LanguageModel,
    cfg: &BigramCfg,
) -> Result<LanguageRow, BigramError> {
    let n_alphabet = stream.distinct_count();
    let seed_tag = stream.kind.seed_tag() ^ language.seed_tag();
    let real = substitution_search(
        &stream.tokens,
        n_alphabet,
        model,
        cfg.restarts,
        cfg.iters,
        mix_seed(cfg.seed, seed_tag ^ REAL_TAG),
    )?;
    if real.skipped {
        return Ok(LanguageRow {
            language,
            real,
            order0: None,
            order1: None,
            readability_coverage: 0,
            verdict: HonestVerdict::Skipped,
        });
    }

    let readability_coverage = readable_coverage(&real.text);
    let order0 = score_null(
        NullKind::Order0,
        &stream.tokens,
        n_alphabet,
        model,
        cfg,
        mix_seed(cfg.seed, seed_tag ^ ORDER0_TAG),
        real.best_mean,
    )?;
    let order1 = score_null(
        NullKind::Order1,
        &stream.tokens,
        n_alphabet,
        model,
        cfg,
        mix_seed(cfg.seed, seed_tag ^ ORDER1_TAG),
        real.best_mean,
    )?;
    let verdict = classify(readability_coverage, &order0);

    Ok(LanguageRow {
        language,
        real,
        order0: Some(order0),
        order1: Some(order1),
        readability_coverage,
        verdict,
    })
}

fn score_null(
    kind: NullKind,
    symbols: &[usize],
    n_alphabet: usize,
    model: &LanguageModel,
    cfg: &BigramCfg,
    seed: u64,
    real_mean: f64,
) -> Result<NullStats, BigramError> {
    let mut rng = SplitMix64::new(seed);
    let real_stream: Vec<u32> = symbols.iter().map(|&symbol| symbol as u32).collect();
    let mut scores = Vec::with_capacity(cfg.null_trials);

    for trial in 0..cfg.null_trials {
        let null_symbols = match kind {
            NullKind::Order0 => {
                let mut shuffled = symbols.to_vec();
                fisher_yates(&mut shuffled, &mut rng)?;
                shuffled
            }
            NullKind::Order1 => markov_resample(&real_stream, n_alphabet, &mut rng)?
                .iter()
                .map(|&symbol| symbol as usize)
                .collect(),
        };
        let result = substitution_search(
            &null_symbols,
            n_alphabet,
            model,
            cfg.restarts,
            cfg.iters,
            mix_seed(seed, trial as u64),
        )?;
        if !result.skipped {
            scores.push(result.best_mean);
        }
    }

    Ok(finalise_null(kind, &scores, real_mean))
}

fn finalise_null(kind: NullKind, scores: &[f64], real_mean: f64) -> NullStats {
    let (mean, std, ceiling) = mean_std_max(scores);
    let reached = scores.iter().filter(|&&score| score >= real_mean).count();
    let p = add_one_p_value(reached, scores.len());
    let beats_mean = real_mean > mean;
    let z = if std > SIGMA_FLOOR {
        (real_mean - mean) / std
    } else if beats_mean {
        f64::INFINITY
    } else {
        0.0
    };
    let beats = beats_mean && p < SURVIVOR_ALPHA;
    NullStats {
        kind,
        trials: scores.len(),
        mean,
        ceiling,
        z,
        p,
        beats,
    }
}

fn classify(readability_coverage: usize, order0: &NullStats) -> HonestVerdict {
    if readability_coverage >= READABLE_MIN {
        HonestVerdict::Candidate
    } else if order0.beats {
        HonestVerdict::Artifact
    } else {
        HonestVerdict::Negative
    }
}

fn mean_std_max(values: &[f64]) -> (f64, f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0, f64::NEG_INFINITY);
    }
    let count = values.len() as f64;
    let mean = values.iter().sum::<f64>() / count;
    let variance = values
        .iter()
        .map(|value| (value - mean) * (value - mean))
        .sum::<f64>()
        / count;
    let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    (mean, variance.sqrt(), max)
}

fn summarise(
    n_digits: usize,
    base: usize,
    derivation: &crate::attack::rlcodec::RunLengthDerivation,
) -> CarrierSummary {
    let mut counts: BTreeMap<usize, usize> = BTreeMap::new();
    for &magnitude in &derivation.magnitudes {
        *counts.entry(magnitude).or_insert(0) += 1;
    }
    CarrierSummary {
        n_digits,
        base,
        n_bits: derivation.n_bits,
        n_up: derivation.n_up,
        n_down: derivation.n_down,
        n_magnitudes: derivation.magnitudes.len(),
        distribution: counts.into_iter().collect(),
    }
}

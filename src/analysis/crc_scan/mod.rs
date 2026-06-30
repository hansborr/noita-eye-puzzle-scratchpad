//! File-driven CRC/hash scanner for stored `u32` word candidates.
//!
//! A hit from this module is a candidate mapping anchor, not a decode. The
//! report always pairs candidates with the analytic and empirical false-alarm
//! calibration induced by the exact dictionary, target set, and digest family.

use std::collections::BTreeSet;

mod hash;
mod stats;
mod targets;

#[cfg(test)]
mod tests;

pub use hash::{HASH_VARIANTS, HashVariant, OutputByteOrder};
pub use stats::{
    AnalyticSignificance, EmpiricalNull, NullCalibrationError, analytic_significance, config_count,
    expected_lambda, poisson_tail_at_least, run_empirical_null,
};
pub use targets::{
    StoredHalf, StoredLocation, StoredObservation, TargetCatalog, TargetParseError,
    parse_target_text,
};

/// Bundled default wordlist path, relative to the repository root.
pub const DEFAULT_WORDLIST_PATH: &str = "research/data/crcscan-default-wordlist.txt";

/// Bundled default wordlist text.
pub const DEFAULT_WORDLIST_TEXT: &str =
    include_str!("../../../research/data/crcscan-default-wordlist.txt");

/// Default deterministic seed for the empirical matched null.
pub const DEFAULT_SEED: u64 = 0x6372_6373_6361_6e00;

/// Default empirical-null trial count.
pub const DEFAULT_NULL_TRIALS: usize = 5_000;

/// Ground-truth positive-control word.
pub const LUMIKKI_WORD: &str = "lumikki";

/// Ground-truth positive-control stored value.
pub const LUMIKKI_STORED_VALUE: u32 = 0xacf6_8674;

/// Ground-truth positive-control raw `CRC-32/BZIP2` value before byte reversal.
pub const LUMIKKI_BZIP2_RAW: u32 = 0x7486_f6ac;

/// Error returned when loading a scanner wordlist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WordlistError {
    /// The wordlist had no nonblank, non-comment lines.
    Empty,
}

impl std::fmt::Display for WordlistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("wordlist is empty"),
        }
    }
}

impl std::error::Error for WordlistError {}

/// Top-level scanner error.
#[derive(Debug)]
pub enum CrcScanError {
    /// Wordlist loading failed.
    Wordlist(WordlistError),
    /// Target input parsing failed.
    Targets(TargetParseError),
    /// Empirical-null calibration failed.
    Null(NullCalibrationError),
    /// The target catalog has no nonzero values to test.
    EmptyTargetSet,
}

impl std::fmt::Display for CrcScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Wordlist(error) => write!(f, "{error}"),
            Self::Targets(error) => write!(f, "{error}"),
            Self::Null(error) => write!(f, "{error}"),
            Self::EmptyTargetSet => f.write_str("target catalog has no nonzero u32 values"),
        }
    }
}

impl std::error::Error for CrcScanError {}

impl From<WordlistError> for CrcScanError {
    fn from(error: WordlistError) -> Self {
        Self::Wordlist(error)
    }
}

impl From<TargetParseError> for CrcScanError {
    fn from(error: TargetParseError) -> Self {
        Self::Targets(error)
    }
}

impl From<NullCalibrationError> for CrcScanError {
    fn from(error: NullCalibrationError) -> Self {
        Self::Null(error)
    }
}

/// One candidate hit row, preserving the stored location that matched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateMatch {
    /// Dictionary word whose digest matched.
    pub word: String,
    /// Digest variant that produced the match.
    pub variant: HashVariant,
    /// Output byte order applied before comparison.
    pub output_order: OutputByteOrder,
    /// Digest value after applying `output_order`.
    pub digest_value: u32,
    /// Raw stored `u32` value that matched `digest_value`.
    pub stored_value: u32,
    /// Stored location of the matched value.
    pub location: StoredLocation,
}

/// Complete scanner report.
#[derive(Clone, Debug, PartialEq)]
pub struct ScanReport {
    /// Number of dictionary entries tested.
    pub dictionary_size: usize,
    /// Number of named digest variants.
    pub variant_count: usize,
    /// Number of variant and output-byte-order configurations.
    pub config_count: usize,
    /// Number of raw stored observations, including zero padding.
    pub stored_u32_count: usize,
    /// Number of unique nonzero stored targets used for calibration.
    pub unique_nonzero_u32_count: usize,
    /// Number of stored pairs represented by the target catalog.
    pub pair_count: usize,
    /// Candidate match rows, including repeated stored locations.
    pub matches: Vec<CandidateMatch>,
    /// Unique word/config/target hit count used as `k`.
    pub statistical_hit_count: usize,
    /// Analytic Poisson false-alarm summary.
    pub analytic: AnalyticSignificance,
    /// Empirical `SplitMix64` matched-null summary.
    pub empirical: EmpiricalNull,
}

/// Self-test result for `crcscan --self-test`.
#[derive(Clone, Debug, PartialEq)]
pub struct SelfTestReport {
    /// Raw `CRC-32/BZIP2("lumikki")` before output byte reversal.
    pub bzip2_raw: u32,
    /// Byte-reversed positive-control value.
    pub bzip2_byte_reversed: u32,
    /// Whether the raw and byte-reversed constants match the planted control.
    pub crc_math_passed: bool,
    /// Whether the scanner recovered the planted `lumikki` row.
    pub planted_recovery_passed: bool,
    /// Analytic lambda used for the empirical null check.
    pub null_lambda: f64,
    /// Empirical null mean.
    pub null_mean: f64,
    /// Whether the empirical null mean agrees with lambda.
    pub null_agrees: bool,
}

impl SelfTestReport {
    /// Overall self-test verdict.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.crc_math_passed && self.planted_recovery_passed && self.null_agrees
    }
}

/// Parses a one-word-per-line wordlist.
///
/// Blank lines and `#` comment lines are ignored; every other trimmed line is
/// tested byte-for-byte as UTF-8.
///
/// # Errors
/// Returns [`WordlistError::Empty`] if no words remain after filtering.
pub fn parse_wordlist(text: &str) -> Result<Vec<String>, WordlistError> {
    let words: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect();
    if words.is_empty() {
        Err(WordlistError::Empty)
    } else {
        Ok(words)
    }
}

/// Parses the bundled default wordlist.
///
/// # Errors
/// Returns [`WordlistError::Empty`] only if the committed resource is malformed.
pub fn default_wordlist() -> Result<Vec<String>, WordlistError> {
    parse_wordlist(DEFAULT_WORDLIST_TEXT)
}

/// Scans `words` against `targets` and computes false-alarm calibration.
///
/// # Errors
/// Returns [`CrcScanError`] if the wordlist or target set is empty, or if the
/// empirical null cannot run.
pub fn run_scan(
    words: &[String],
    targets: &TargetCatalog,
    null_trials: usize,
    seed: u64,
) -> Result<ScanReport, CrcScanError> {
    if words.is_empty() {
        return Err(WordlistError::Empty.into());
    }
    if targets.unique_nonzero_u32_count() == 0 {
        return Err(CrcScanError::EmptyTargetSet);
    }
    let matches = scan_matches(words, targets);
    let statistical_hit_count = statistical_hit_count(&matches);
    let analytic = analytic_significance(
        targets.unique_nonzero_u32_count(),
        words.len(),
        statistical_hit_count,
    );
    let empirical = run_empirical_null(
        &targets.unique_targets(),
        words.len(),
        statistical_hit_count,
        null_trials,
        seed,
    )?;
    Ok(ScanReport {
        dictionary_size: words.len(),
        variant_count: HASH_VARIANTS.len(),
        config_count: stats::config_count(),
        stored_u32_count: targets.stored_u32_count(),
        unique_nonzero_u32_count: targets.unique_nonzero_u32_count(),
        pair_count: targets.pair_count(),
        matches,
        statistical_hit_count,
        analytic,
        empirical,
    })
}

/// Runs the in-process positive control and empirical-null agreement check.
///
/// # Errors
/// Returns [`CrcScanError`] if the bundled wordlist is malformed or the null
/// cannot run.
pub fn run_self_test(null_trials: usize, seed: u64) -> Result<SelfTestReport, CrcScanError> {
    let raw = HashVariant::Crc32Bzip2.digest(LUMIKKI_WORD.as_bytes());
    let reversed = OutputByteOrder::ByteReversed.apply(raw);
    let crc_math_passed = raw == LUMIKKI_BZIP2_RAW && reversed == LUMIKKI_STORED_VALUE;

    let planted_targets = planted_lumikki_targets();
    let planted_words = vec![LUMIKKI_WORD.to_owned()];
    let planted = run_scan(&planted_words, &planted_targets, null_trials, seed)?;
    let planted_recovery_passed = planted.matches.iter().any(is_lumikki_positive_control);

    let default_words = default_wordlist()?;
    let default_targets = TargetCatalog::from_engine_messages();
    let default_targets_set = default_targets.unique_targets();
    let lambda = expected_lambda(default_targets_set.len(), default_words.len());
    let empirical = run_empirical_null(
        &default_targets_set,
        default_words.len(),
        0,
        null_trials,
        seed,
    )?;
    let null_agrees = empirical.agrees_with_lambda(lambda);

    Ok(SelfTestReport {
        bzip2_raw: raw,
        bzip2_byte_reversed: reversed,
        crc_math_passed,
        planted_recovery_passed,
        null_lambda: lambda,
        null_mean: empirical.mean,
        null_agrees,
    })
}

fn scan_matches(words: &[String], targets: &TargetCatalog) -> Vec<CandidateMatch> {
    let mut matches = Vec::new();
    for word in words {
        for variant in HASH_VARIANTS {
            let raw = variant.digest(word.as_bytes());
            for output_order in OutputByteOrder::ALL {
                let digest_value = output_order.apply(raw);
                if let Some(locations) = targets.locations_for(digest_value) {
                    for location in locations {
                        matches.push(CandidateMatch {
                            word: word.clone(),
                            variant,
                            output_order,
                            digest_value,
                            stored_value: digest_value,
                            location: *location,
                        });
                    }
                }
            }
        }
    }
    matches
}

fn statistical_hit_count(matches: &[CandidateMatch]) -> usize {
    matches
        .iter()
        .map(|hit| {
            (
                hit.word.clone(),
                hit.variant,
                hit.output_order,
                hit.stored_value,
            )
        })
        .collect::<BTreeSet<_>>()
        .len()
}

fn planted_lumikki_targets() -> TargetCatalog {
    TargetCatalog::from_observations(
        vec![StoredObservation {
            value: LUMIKKI_STORED_VALUE,
            location: StoredLocation {
                message_index: 0,
                position: 0,
                half: StoredHalf::High,
            },
        }],
        1,
    )
}

fn is_lumikki_positive_control(hit: &CandidateMatch) -> bool {
    hit.word == LUMIKKI_WORD
        && hit.variant == HashVariant::Crc32Bzip2
        && hit.output_order == OutputByteOrder::ByteReversed
        && hit.stored_value == LUMIKKI_STORED_VALUE
}

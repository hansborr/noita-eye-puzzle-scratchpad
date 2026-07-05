//! Crib-free finish over `shadowsearch` residual q-pattern classes.
//!
//! This module consumes the file artifact emitted by `shadowsearch --output`,
//! enumerates the reported two-octal-digit residual surface, applies bounded
//! language discriminators, and reports calibrated plaintext hypotheses. The
//! phase-0 visible-ciphertext re-encode is a replay invariant on this
//! co-searched bijective codec surface, not independent acceptance evidence.

use std::fmt;

use crate::attack::quadgram::{QuadgramError, QuadgramModel};
use crate::nulls::null::add_one_p_value;

mod artifact;
mod control;
mod engine;
mod json;
mod scoring;
mod tables;
#[cfg(test)]
mod tests;

pub use artifact::{FinishClass, PreparedClass, ShadowFinishArtifact};
pub use control::{ShadowFinishSelfTest, shadow_finish_self_test};
pub use tables::{ShadowFinishTable, builtin_tables, parse_table_file};

/// Default deterministic seed for controls and matched nulls.
pub const DEFAULT_SEED: u64 = 0x7368_6164_6f77_6603;
/// Default bounded Tier-A survivors retained per canonical class.
pub const DEFAULT_TOP_K_PER_CLASS: usize = 512;
/// Default matched-null trials for the real finish run.
pub const DEFAULT_NULL_TRIALS: usize = 20;
/// Default vocabulary cap for word-DP scoring.
pub const DEFAULT_VOCAB_CAP: usize = 50_000;
/// Default memory refusal cap.
pub const DEFAULT_MAX_MEM_MIB: usize = 2048;
/// Default candidate significance threshold.
pub const DEFAULT_ALPHA: f64 = 0.05;
/// Scope of the current matched-null calibration.
pub const MATCHED_NULL_SCOPE: &str = "decoy q-pattern label shuffles of the artifact's retained max-soft shadowsearch classes; does not replay stage-ii survivor or non-max selection";
/// Interpretation of the phase-0 re-encode check.
pub const ROUNDTRIP_INVARIANT_NOTE: &str = "vacuous phase-0 replay invariant on the co-searched bijective table/permutation/order surface; every in-range phase-0 interpretation re-encodes through the representative shadow key, so this is not plaintext evidence";

/// Digit order inside each two-octal-digit pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigitOrder {
    /// High-low: `value = first * 8 + second`.
    HighLow,
    /// Low-high: `value = second * 8 + first`.
    LowHigh,
}

impl DigitOrder {
    /// Stable label for reports.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::HighLow => "HL",
            Self::LowHigh => "LH",
        }
    }
}

/// Pairing phase used to read the q-index stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairPhase {
    /// Phase 0: pairs `(0,1), (2,3), ...`.
    Phase0,
    /// Phase 1: pairs `(1,2), (3,4), ...`; edge q-symbols are dropped.
    Phase1,
}

impl PairPhase {
    /// Stable label for reports.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Phase0 => "phase0",
            Self::Phase1 => "phase1",
        }
    }
}

/// Configuration for [`run_shadow_finish`].
#[derive(Clone, Debug, PartialEq)]
pub struct ShadowFinishConfig {
    /// Bounded Tier-A survivors retained per canonical class.
    pub top_k_per_class: usize,
    /// Matched-null trials over decoy q-patterns.
    pub null_trials: usize,
    /// Deterministic seed for null decoys.
    pub seed: u64,
    /// Vocabulary cap for word-DP scoring.
    pub vocab_cap: usize,
    /// Refuse configurations estimated to exceed this memory cap.
    pub max_mem_mib: usize,
    /// Candidate threshold on add-one empirical p-value.
    pub alpha: f64,
    /// Include the phase-1 pairing variant. It drops edge q-symbols and is
    /// reported separately; exact full-stream round-trip is phase-0 only.
    pub include_phase1: bool,
}

impl Default for ShadowFinishConfig {
    fn default() -> Self {
        Self {
            top_k_per_class: DEFAULT_TOP_K_PER_CLASS,
            null_trials: DEFAULT_NULL_TRIALS,
            seed: DEFAULT_SEED,
            vocab_cap: DEFAULT_VOCAB_CAP,
            max_mem_mib: DEFAULT_MAX_MEM_MIB,
            alpha: DEFAULT_ALPHA,
            include_phase1: false,
        }
    }
}

/// Verdict vocabulary for the crib-free finish stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShadowFinishVerdict {
    /// Reserved for fixed-codec ladders; this co-searched finish stage never
    /// emits it because round-trip is vacuous over table/permutation/order.
    RoundTripDecode,
    /// A language-significant plaintext hypothesis cleared the matched null.
    Candidate,
    /// Controls were powered and no candidate cleared the matched null.
    NoCandidate,
    /// Controls or calibration lacked enough power to exclude the surface.
    LowPowerNoExclusion,
    /// A required control failed.
    ControlsFailed,
}

impl ShadowFinishVerdict {
    /// Stable label for reports and JSON.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::RoundTripDecode => "RoundTripDecode",
            Self::Candidate => "Candidate",
            Self::NoCandidate => "NoCandidate",
            Self::LowPowerNoExclusion => "LowPowerNoExclusion",
            Self::ControlsFailed => "ControlsFailed",
        }
    }
}

/// Surface-size and bound accounting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SurfaceReport {
    /// Canonical classes enumerated.
    pub classes: usize,
    /// Digit-label permutations per class.
    pub permutations_per_class: usize,
    /// Digit orders enumerated.
    pub digit_orders: usize,
    /// Charset tables enumerated.
    pub tables: usize,
    /// Pair phases enumerated.
    pub phases: usize,
    /// Exact candidate interpretations scored by Tier A.
    pub total_interpretations: u128,
    /// q-symbols dropped by phase-0 pairing.
    pub phase0_dropped_q_symbols: usize,
    /// q-symbols dropped by phase-1 pairing, when enabled.
    pub phase1_dropped_q_symbols: Option<usize>,
}

/// Tier-A count summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TierAReport {
    /// Candidate interpretations visited.
    pub visited: u128,
    /// Candidates rejected because a table lacked a value.
    pub table_rejects: u128,
    /// Candidates rejected by loose printable/value sanity.
    pub loose_rejects: u128,
    /// Candidates that also satisfied the strict value set.
    pub strict_passes: u128,
    /// Candidates retained for Tier B after bounded per-class top-K.
    pub retained_for_tier_b: usize,
    /// Candidates dropped by the per-class top-K bound.
    pub top_k_dropped: u128,
}

/// Matched-null calibration summary.
#[derive(Clone, Debug, PartialEq)]
pub struct CalibrationReport {
    /// Exact degrees of freedom covered by this matched null.
    pub null_scope: String,
    /// Number of decoy trials.
    pub trials: usize,
    /// Observed best Tier-B score.
    pub observed_best: f64,
    /// Number of null decoy best scores >= observed.
    pub null_ge: usize,
    /// Add-one empirical p-value.
    pub p_emp: f64,
    /// Best score among decoys.
    pub null_max: f64,
    /// Observed minus null max.
    pub margin_vs_null_max: f64,
    /// Decoy best scores in deterministic draw order.
    pub samples: Vec<f64>,
}

/// One retained finish candidate.
#[derive(Clone, Debug, PartialEq)]
pub struct FinishCandidate {
    /// Canonical class index in artifact order.
    pub class_index: usize,
    /// Table name.
    pub table: String,
    /// Pair phase.
    pub phase: PairPhase,
    /// Digit order.
    pub order: DigitOrder,
    /// Canonical-label to octal-digit permutation.
    pub permutation: [u8; 8],
    /// Decoded plaintext bytes.
    pub plaintext: Vec<u8>,
    /// Tier-A quadgram score.
    pub quadgram_score: f64,
    /// Full-text word-DP mean score.
    pub word_score: f32,
    /// Repeated-anchor word-DP mean score.
    pub anchor_score: f32,
    /// Combined Tier-B score.
    pub combined_score: f64,
    /// Whether the strict value set accepted every decoded byte.
    pub strict_valid: bool,
    /// Phase-0 replay invariant result; vacuous on the co-searched surface.
    pub roundtrip: bool,
}

/// Complete finish report.
#[derive(Clone, Debug, PartialEq)]
pub struct ShadowFinishReport {
    /// Final verdict.
    pub verdict: ShadowFinishVerdict,
    /// Parsed artifact class count.
    pub artifact_classes: usize,
    /// Ciphertext length.
    pub input_len: usize,
    /// Charset tables covered.
    pub table_names: Vec<String>,
    /// Surface accounting.
    pub surface: SurfaceReport,
    /// Tier-A accounting.
    pub tier_a: TierAReport,
    /// Matched-null calibration.
    pub calibration: CalibrationReport,
    /// Best retained candidates, sorted by Tier-B score.
    pub top_candidates: Vec<FinishCandidate>,
    /// Estimated peak memory for bounded candidate storage.
    pub estimated_mib: usize,
}

/// Error returned by the crib-free finish instrument.
#[derive(Clone, Debug, PartialEq)]
pub enum ShadowFinishError {
    /// Artifact parse or consistency error.
    Artifact(String),
    /// Charset table error.
    Table(String),
    /// Language-scoring setup error.
    Scoring(String),
    /// Exact round-trip verifier error.
    RoundTrip(String),
    /// Configuration would exceed the explicit memory cap.
    MemoryCap {
        /// Estimated peak in MiB.
        estimated_mib: usize,
        /// Configured cap in MiB.
        cap_mib: usize,
    },
    /// Invalid configuration.
    Config(String),
}

impl fmt::Display for ShadowFinishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Artifact(message) => write!(formatter, "artifact error: {message}"),
            Self::Table(message) => write!(formatter, "table error: {message}"),
            Self::Scoring(message) => write!(formatter, "scoring error: {message}"),
            Self::RoundTrip(message) => write!(formatter, "round-trip error: {message}"),
            Self::MemoryCap {
                estimated_mib,
                cap_mib,
            } => write!(
                formatter,
                "estimated peak memory {estimated_mib} MiB exceeds --max-mem-mib {cap_mib}"
            ),
            Self::Config(message) => write!(formatter, "configuration error: {message}"),
        }
    }
}

impl std::error::Error for ShadowFinishError {}

impl From<QuadgramError> for ShadowFinishError {
    fn from(error: QuadgramError) -> Self {
        Self::Scoring(format!("quadgram model error: {error}"))
    }
}

/// Runs the crib-free finish ladder over a `shadowsearch --output` artifact.
///
/// # Errors
/// Returns [`ShadowFinishError`] for malformed artifacts, bad tables, invalid
/// configuration, memory-cap refusal, or verifier/scoring setup failures.
pub fn run_shadow_finish(
    artifact_text: &str,
    ciphertext: &[u16],
    wordlist_text: &str,
    extra_tables: &[ShadowFinishTable],
    config: &ShadowFinishConfig,
) -> Result<ShadowFinishReport, ShadowFinishError> {
    validate_config(config)?;
    let artifact = ShadowFinishArtifact::parse(artifact_text)?;
    let prepared = artifact.prepare_classes(ciphertext)?;
    let mut tables = builtin_tables()?;
    tables.extend_from_slice(extra_tables);
    let word_model = scoring::WordSegModel::from_wordlist(wordlist_text, config.vocab_cap)?;
    let quadgram = QuadgramModel::english()?;
    let report = engine::run_ladder(
        &artifact,
        &prepared,
        ciphertext,
        &tables,
        &word_model,
        &quadgram,
        config,
        None,
    )?;
    Ok(report)
}

fn validate_config(config: &ShadowFinishConfig) -> Result<(), ShadowFinishError> {
    if config.top_k_per_class == 0 {
        return Err(ShadowFinishError::Config(
            "--top-k-per-class must be at least 1".to_owned(),
        ));
    }
    if !config.alpha.is_finite() || config.alpha <= 0.0 || config.alpha >= 1.0 {
        return Err(ShadowFinishError::Config(
            "--alpha must be finite and inside (0,1)".to_owned(),
        ));
    }
    Ok(())
}

fn calibration_report(observed: f64, samples: Vec<f64>) -> CalibrationReport {
    let null_ge = samples.iter().filter(|&&sample| sample >= observed).count();
    let p_emp = add_one_p_value(null_ge, samples.len());
    let null_max = samples.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    CalibrationReport {
        null_scope: MATCHED_NULL_SCOPE.to_owned(),
        trials: samples.len(),
        observed_best: observed,
        null_ge,
        p_emp,
        null_max,
        margin_vs_null_max: observed - null_max,
        samples,
    }
}

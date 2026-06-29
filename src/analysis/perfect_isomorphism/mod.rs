//! Thread 3 perfect-isomorphism and allomorph-consistency scan.
//!
//! This module is deliberately mapping-independent: it uses only reading-layer
//! symbol equality, first-occurrence gap patterns, and positional alignment. It
//! does not assume any symbol-to-meaning mapping or language model.

mod breaks;
mod catalog;
mod regression;
mod report;
#[cfg(test)]
mod tests;

use std::error::Error;
use std::fmt;

use crate::analysis::isomorph::IsomorphError;
use crate::analysis::orders::{self, GridError, ReadingOrder, read_corpus_message_values};
use crate::core::trigram::TrigramValue;

use breaks::{count_internal_candidates, internal_violation_null};
use catalog::{
    CatalogRecord, build_catalog_records, catalog_significance, conservative_safe_extents,
    localize_extents, safe_extent_seed_records, strong_repeat_catalog_records,
};
use regression::{
    ensure_all_regressions_reproduced, run_positive_control, run_regression_checks,
    synthetic_internal_violation_fires,
};

/// Default deterministic seed for the internal-violation null and sampling.
pub const DEFAULT_SEED: u64 = 0x7065_7266_6973_6f00;
/// Default within-message shuffle trials for the matched internal-violation null.
pub const DEFAULT_TRIALS: usize = 3_000;
/// Minimum gap-pattern window length scanned for cross-message isomorphs.
pub const DEFAULT_MIN_WINDOW: usize = 8;
/// Maximum gap-pattern window length scanned for cross-message isomorphs.
pub const DEFAULT_MAX_WINDOW: usize = 11;
/// Minimum same-offset agreement run flanking a break for it to count internal.
pub const MIN_TWO_SIDED_FLANK: usize = 2;
/// Maximum desync-island width in columns for an internal-violation candidate.
pub const MAX_ISLAND_COLS: usize = 2;
/// Minimum re-synced far-run length after a short island.
pub const POST_MIN: usize = 8;
/// Fixed reading-layer alphabet size, values `0..=82`.
pub const ALPHABET_SIZE: usize = orders::READING_LAYER_ALPHABET_SIZE;
/// Minimum repeated symbols in a gap pattern for strong classification.
pub const STRONG_MIN_REPEATS: usize = 3;
/// Minimum cross-message occurrence count for strong classification.
pub const STRONG_MIN_OCCURRENCES: usize = 2;
/// Pointwise significance threshold for the internal-violation tail.
pub const SIGNIFICANCE_ALPHA: f64 = 0.05;

const CATALOG_WINDOWS: [usize; 3] = [8, 9, 11];
const MAIN_ISOMORPH_W9: &str = "A.B.CB.AC";
const MAIN_ISOMORPH_W11: &str = "ABC.DC.AD.B";
const POSITIVE_CONTROL_MIN_MARGIN: usize = 1;
const POSITIVE_CONTROL_TAG: u64 = 0x706f_7369_7469_7665;
const NULL_TAG_BASE: u64 = 0x6e75_6c6c_7069_736f;

/// Configuration for the perfect-isomorphism scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PerfectIsomorphismConfig {
    /// Deterministic PRNG seed for the internal-violation null.
    pub seed: u64,
    /// Within-message shuffle trials.
    pub trials: usize,
    /// Minimum gap-pattern window length scanned.
    pub min_window: usize,
    /// Maximum gap-pattern window length scanned.
    pub max_window: usize,
}

impl Default for PerfectIsomorphismConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_SEED,
            trials: DEFAULT_TRIALS,
            min_window: DEFAULT_MIN_WINDOW,
            max_window: DEFAULT_MAX_WINDOW,
        }
    }
}

/// Error returned by the perfect-isomorphism scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PerfectIsomorphismError {
    /// The verified corpus could not be reconstructed or read.
    Grid(GridError),
    /// At least one shuffle trial is required.
    ZeroTrials,
    /// The configured window range was empty, zero, or exceeded a message.
    InvalidWindowRange {
        /// Requested minimum window length.
        min_window: usize,
        /// Requested maximum window length.
        max_window: usize,
    },
    /// A random draw bound did not fit the deterministic PRNG helper.
    RandomBoundTooLarge {
        /// Requested exclusive upper bound.
        bound: usize,
    },
    /// An isomorph primitive rejected a window or period configuration.
    Isomorph(IsomorphError),
    /// A pinned wiki regression check failed.
    RegressionCheckFailed {
        /// Regression check that failed to reproduce.
        check: WikiRegressionCheck,
    },
    /// The positive control did not fire on the `A.B.CB.AC` signal.
    PositiveControlFailed {
        /// Human-readable failure detail.
        detail: String,
    },
}

impl From<GridError> for PerfectIsomorphismError {
    fn from(value: GridError) -> Self {
        Self::Grid(value)
    }
}

impl From<crate::nulls::null::RandomBoundError> for PerfectIsomorphismError {
    fn from(error: crate::nulls::null::RandomBoundError) -> Self {
        Self::RandomBoundTooLarge { bound: error.bound }
    }
}

impl From<IsomorphError> for PerfectIsomorphismError {
    fn from(value: IsomorphError) -> Self {
        Self::Isomorph(value)
    }
}

impl fmt::Display for PerfectIsomorphismError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Grid(error) => write!(formatter, "grid/order error: {error:?}"),
            Self::ZeroTrials => {
                write!(
                    formatter,
                    "at least one within-message shuffle trial is required"
                )
            }
            Self::InvalidWindowRange {
                min_window,
                max_window,
            } => write!(
                formatter,
                "invalid perfect-isomorphism window range {min_window}..={max_window}; the vetted catalog windows are 8, 9, and 11"
            ),
            Self::RandomBoundTooLarge { bound } => {
                write!(formatter, "shuffle bound {bound} is too large")
            }
            Self::Isomorph(error) => {
                write!(
                    formatter,
                    "isomorph detector configuration error: {error:?}"
                )
            }
            Self::RegressionCheckFailed { check } => write!(
                formatter,
                "wiki regression check {check:?} failed; methodology/transcription is suspect, not a finding"
            ),
            Self::PositiveControlFailed { detail } => write!(
                formatter,
                "positive control failed ({detail}); methodology is suspect, not a finding"
            ),
        }
    }
}

impl Error for PerfectIsomorphismError {}

/// One cross-message gap-pattern match before maximal extension.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IsomorphCatalogEntry {
    /// Rendered first-occurrence gap pattern.
    pub signature: String,
    /// Number of distinct repeated symbols in the pattern.
    pub repeat_count: usize,
    /// `(message_key, start_offset)` for each occurrence, in corpus order.
    pub occurrences: Vec<(&'static str, usize)>,
    /// Window length of the matched pattern.
    pub window: usize,
}

/// Significance for one catalog entry under the matched within-message null.
#[derive(Clone, Debug, PartialEq)]
pub struct IsomorphSignificance {
    /// Rendered signature this score belongs to.
    pub signature: String,
    /// Window length this score belongs to.
    pub window: usize,
    /// Observed cross-message occurrence count.
    pub observed_occurrences: usize,
    /// Mean occurrence count of this signature under the shuffle null.
    pub null_mean_occurrences: f64,
    /// Maximum occurrence count of this signature under the shuffle null.
    pub null_max_occurrences: usize,
    /// Shuffles whose occurrence count was greater than or equal to observed.
    pub empirical_p_count: usize,
    /// Add-one one-sided empirical p-value.
    pub empirical_p: f64,
    /// Whether this entry clears the pointwise strong-significance bar.
    pub strong: bool,
}

/// How a maximally-extended aligned isomorph pair first diverges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakClass {
    /// Trailing-edge divergence consistent with a plaintext boundary.
    Boundary,
    /// Two-sided, short-island, far-run candidate perfect-isomorphism violation.
    InternalCandidate,
    /// Internal-looking but explained by a named benign desync region.
    BenignDesync {
        /// Named benign region explaining the desync.
        region: BenignDesyncRegion,
    },
}

/// Named benign desync regions already attributed to plaintext or GAK-expected desync.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BenignDesyncRegion {
    /// The Funny-looking Obstacle, messages `east1`/`west1`.
    FunnyLookingObstacle,
    /// The Caboose, messages `west1`/`east2`.
    Caboose,
    /// The Stutter Section, messages `east4`/`west4`/`east5`.
    StutterSection,
}

/// One localized break in a maximally-extended aligned isomorph pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BreakLocalization {
    /// Aligned message pair `(left_key, right_key)`.
    pub pair: (&'static str, &'static str),
    /// Anchor offsets in each message where the shared run began.
    pub anchor: (usize, usize),
    /// Length of confirmed agreement before the break.
    pub left_flank: usize,
    /// Length of re-synced agreement after the break.
    pub right_flank: usize,
    /// First index, relative to the extended window, where gap patterns diverge.
    pub break_index: usize,
    /// Width of the desync island in columns.
    pub island_cols: usize,
    /// Length of the re-synced far run carrying a cross-island back-reference.
    pub far_run: usize,
    /// Break classification.
    pub class: BreakClass,
}

/// Safe isomorph extent for one cross-message aligned isomorph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafeIsomorphExtent {
    /// Aligned message pair `(left_key, right_key)`.
    pub pair: (&'static str, &'static str),
    /// Left-message half-open safe span.
    pub left_span: SafeSpan,
    /// Right-message half-open safe span.
    pub right_span: SafeSpan,
    /// Break that bounds this extent, or `None` if the run reached message end.
    pub bounding_break: Option<BreakLocalization>,
}

/// One half-open safe span represented as `start + len`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SafeSpan {
    /// Zero-based start offset.
    pub start: usize,
    /// Span length.
    pub len: usize,
}

impl SafeSpan {
    /// Exclusive end offset.
    #[must_use]
    pub const fn end(&self) -> usize {
        self.start + self.len
    }
}

/// Matched internal-violation null band.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct InternalViolationNullBand {
    /// Number of shuffle trials sampled.
    pub trials: usize,
    /// Mean internal-candidate count across shuffles.
    pub count_mean: f64,
    /// Sample median internal-candidate count.
    pub count_median: f64,
    /// Upper pointwise 97.5% percentile edge.
    pub count_q975: usize,
    /// Largest sampled internal-candidate count.
    pub count_max: usize,
}

/// Pinned wiki gap-pattern regression checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WikiRegressionCheck {
    /// 3A: East1/West1 shared allomorph.
    Messages12SharedAllomorph,
    /// 3B: East4/West4/East5 shared tail plus message-7 extra repeat.
    Messages789ExtraRepeat,
    /// 3C: single-deletion corruption-theory bound.
    CorruptionTheoryBound,
    /// Main `A.B.CB.AC` isomorph positive control.
    MainIsomorphPositiveControl,
}

/// One regression-check outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WikiRegressionResult {
    /// Check that was evaluated.
    pub check: WikiRegressionCheck,
    /// Gap-pattern strings or load-bearing claims produced by this run.
    pub produced: Vec<String>,
    /// Expected strings or load-bearing claims.
    pub expected: Vec<String>,
    /// Whether the produced values matched the expected values.
    pub reproduced: bool,
    /// For 3C only, the conditional hypothesis label.
    pub hypothesis_label: String,
}

/// Complete perfect-isomorphism scan report.
#[derive(Clone, Debug, PartialEq)]
pub struct PerfectIsomorphismReport {
    /// Configuration used for the run.
    pub config: PerfectIsomorphismConfig,
    /// Reading order used for the real stream.
    pub order: ReadingOrder,
    /// Per-message stream lengths in corpus order.
    pub message_lengths: Vec<(&'static str, usize)>,
    /// Total number of reading-layer symbols.
    pub total_length: usize,
    /// Cross-message gap-pattern catalog.
    pub catalog: Vec<IsomorphCatalogEntry>,
    /// Matched-null significance rows for catalog entries.
    pub significance: Vec<IsomorphSignificance>,
    /// Localized breaks for maximally-extended strong isomorphs.
    pub breaks: Vec<BreakLocalization>,
    /// Count of robust internal-violation candidates at the strong bar.
    pub robust_internal_violations: usize,
    /// Matched internal-violation null band.
    pub internal_violation_null: InternalViolationNullBand,
    /// Shuffles whose internal-candidate count met or exceeded observed.
    pub empirical_p_count: usize,
    /// Add-one upper-tail empirical p-value.
    pub empirical_p: f64,
    /// Conservative safe-isomorph extents exported to downstream threads.
    pub safe_extents: Vec<SafeIsomorphExtent>,
    /// Wiki regression checks.
    pub regression: Vec<WikiRegressionResult>,
    /// Whether the positive control fired.
    pub positive_control_fired: bool,
}

/// Runs the perfect-isomorphism scan on the verified eye corpus.
///
/// # Errors
/// Returns [`PerfectIsomorphismError`] when the corpus cannot be reconstructed,
/// the configuration is invalid, an isomorph primitive rejects a window, a wiki
/// regression check fails to reproduce, or the positive control does not fire.
pub fn run_perfect_isomorphism(
    config: PerfectIsomorphismConfig,
) -> Result<PerfectIsomorphismReport, PerfectIsomorphismError> {
    validate_config(config)?;
    let grids = orders::corpus_grids()?;
    let keys = grids
        .iter()
        .map(crate::analysis::orders::GlyphGrid::message_key)
        .collect::<Vec<_>>();
    let order = orders::accepted_honeycomb_order();
    let message_values = read_corpus_message_values(&grids, order)?;
    report_from_message_values(config, order, &keys, &message_values)
}

/// Runs the perfect-isomorphism scan on an arbitrary single-message stream.
///
/// This is the file-driven path. It computes the same mapping-independent isomorph
/// catalog, break localization, and matched within-message internal-violation null
/// as the eye scan, but under the neutral [`ReadingOrder::RawRows`] label with a
/// single `"input"` message key. It does not run the eye-corpus wiki regression
/// checks or the eye main-isomorph occurrence assertions; instead it self-validates
/// with the stream-independent synthetic short-island internal-violation control, so
/// the emitted report is a structural **candidate** behind a passing positive
/// control, never an eye-provenance decode.
///
/// # Errors
/// Returns [`PerfectIsomorphismError`] when the configuration is invalid, the stream
/// is shorter than the maximum scanned window, an isomorph primitive rejects a
/// window, or the synthetic positive control does not fire.
pub fn perfect_isomorphism_for_stream(
    config: PerfectIsomorphismConfig,
    message_values: &[Vec<TrigramValue>],
) -> Result<PerfectIsomorphismReport, PerfectIsomorphismError> {
    validate_config(config)?;
    validate_message_windows(config, message_values)?;
    let keys: &[&'static str] = &["input"];
    let windows = scanned_windows(config)?;
    let catalog_records = build_catalog_records(keys, message_values, &windows)?;
    let catalog = catalog_records.iter().map(CatalogRecord::entry).collect();
    let significance = catalog_significance(config, message_values, &catalog_records, &windows)?;
    let strong_records = strong_repeat_catalog_records(&catalog_records);
    let safe_records = safe_extent_seed_records(&strong_records);
    let (breaks, _strong_extents) = localize_extents(keys, message_values, &strong_records, true);
    let robust_internal_violations = count_internal_candidates(&breaks);
    let safe_extents = conservative_safe_extents(keys, message_values, &safe_records);
    let (internal_violation_null, empirical_p_count, empirical_p) = internal_violation_null(
        config,
        keys,
        message_values,
        &windows,
        robust_internal_violations,
    )?;
    // Self-validation off-corpus: the eye wiki-regression checks and the
    // A.B.CB.AC / ABC.DC.AD.B occurrence assertions are eye-corpus-specific, so they
    // are not run here. The methodological internal-violation detector is instead
    // exercised by the stream-independent synthetic short-island fixture, which must
    // fire for this candidate report to be trusted.
    let positive_control_fired = synthetic_internal_violation_fires()?;
    if !positive_control_fired {
        return Err(PerfectIsomorphismError::PositiveControlFailed {
            detail: "synthetic short-island internal violation was not detected".to_owned(),
        });
    }
    let lengths = message_values.iter().map(Vec::len).collect::<Vec<_>>();
    let total_length = lengths.iter().sum();

    Ok(PerfectIsomorphismReport {
        config,
        order: ReadingOrder::RawRows,
        message_lengths: keys.iter().copied().zip(lengths).collect(),
        total_length,
        catalog,
        significance,
        breaks,
        robust_internal_violations,
        internal_violation_null,
        empirical_p_count,
        empirical_p,
        safe_extents,
        regression: vec![],
        positive_control_fired,
    })
}

fn report_from_message_values(
    config: PerfectIsomorphismConfig,
    order: ReadingOrder,
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
) -> Result<PerfectIsomorphismReport, PerfectIsomorphismError> {
    validate_config(config)?;
    validate_message_windows(config, message_values)?;
    let windows = scanned_windows(config)?;
    let catalog_records = build_catalog_records(keys, message_values, &windows)?;
    let catalog = catalog_records.iter().map(CatalogRecord::entry).collect();
    let significance = catalog_significance(config, message_values, &catalog_records, &windows)?;
    let strong_records = strong_repeat_catalog_records(&catalog_records);
    let safe_records = safe_extent_seed_records(&strong_records);
    let (breaks, _strong_extents) = localize_extents(keys, message_values, &strong_records, true);
    let robust_internal_violations = count_internal_candidates(&breaks);
    let safe_extents = conservative_safe_extents(keys, message_values, &safe_records);
    let (internal_violation_null, empirical_p_count, empirical_p) = internal_violation_null(
        config,
        keys,
        message_values,
        &windows,
        robust_internal_violations,
    )?;
    let regression = run_regression_checks(keys, message_values, &catalog_records, &breaks)?;
    run_positive_control(&catalog_records, &significance, &breaks)?;
    ensure_all_regressions_reproduced(&regression)?;
    let lengths = message_values.iter().map(Vec::len).collect::<Vec<_>>();
    let total_length = lengths.iter().sum();

    Ok(PerfectIsomorphismReport {
        config,
        order,
        message_lengths: keys.iter().copied().zip(lengths).collect(),
        total_length,
        catalog,
        significance,
        breaks,
        robust_internal_violations,
        internal_violation_null,
        empirical_p_count,
        empirical_p,
        safe_extents,
        regression,
        positive_control_fired: true,
    })
}

fn validate_config(config: PerfectIsomorphismConfig) -> Result<(), PerfectIsomorphismError> {
    if config.trials == 0 {
        return Err(PerfectIsomorphismError::ZeroTrials);
    }
    if config.min_window == 0 || config.min_window > config.max_window {
        return Err(PerfectIsomorphismError::InvalidWindowRange {
            min_window: config.min_window,
            max_window: config.max_window,
        });
    }
    Ok(())
}

fn validate_message_windows(
    config: PerfectIsomorphismConfig,
    message_values: &[Vec<TrigramValue>],
) -> Result<(), PerfectIsomorphismError> {
    let shortest = message_values
        .iter()
        .map(Vec::len)
        .min()
        .unwrap_or_default();
    if config.max_window > shortest {
        return Err(PerfectIsomorphismError::InvalidWindowRange {
            min_window: config.min_window,
            max_window: config.max_window,
        });
    }
    Ok(())
}

fn scanned_windows(
    config: PerfectIsomorphismConfig,
) -> Result<Vec<usize>, PerfectIsomorphismError> {
    let windows = CATALOG_WINDOWS
        .into_iter()
        .filter(|window| *window >= config.min_window && *window <= config.max_window)
        .collect::<Vec<_>>();
    if windows.is_empty() {
        Err(PerfectIsomorphismError::InvalidWindowRange {
            min_window: config.min_window,
            max_window: config.max_window,
        })
    } else {
        Ok(windows)
    }
}

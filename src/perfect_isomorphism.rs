//! Thread 3 perfect-isomorphism and allomorph-consistency scan.
//!
//! This module is deliberately mapping-independent: it uses only reading-layer
//! symbol equality, first-occurrence gap patterns, and positional alignment. It
//! does not assume any symbol-to-meaning mapping or language model.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use crate::isomorph::{IsomorphError, PatternSignature};
use crate::null::{SplitMix64, add_one_p_value, fisher_yates, mix_seed, stateless_splitmix};
use crate::orders::{self, GridError, ReadingOrder, read_corpus_message_values};
use crate::trigram::TrigramValue;

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

impl From<crate::null::RandomBoundError> for PerfectIsomorphismError {
    fn from(error: crate::null::RandomBoundError) -> Self {
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
            Self::ZeroTrials => write!(formatter, "at least one shuffle trial is required"),
            Self::InvalidWindowRange {
                min_window,
                max_window,
            } => write!(
                formatter,
                "invalid isomorph window range {min_window}..={max_window}"
            ),
            Self::RandomBoundTooLarge { bound } => {
                write!(formatter, "random draw bound {bound} is too large")
            }
            Self::Isomorph(error) => {
                write!(
                    formatter,
                    "isomorph detector configuration error: {error:?}"
                )
            }
            Self::RegressionCheckFailed { check } => write!(
                formatter,
                "regression check {check:?} failed; methodology/transcription is suspect, not a finding"
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
        .map(crate::orders::GlyphGrid::message_key)
        .collect::<Vec<_>>();
    let order = orders::accepted_honeycomb_order();
    let message_values = read_corpus_message_values(&grids, order)?;
    report_from_message_values(config, order, &keys, &message_values)
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Occurrence {
    message_index: usize,
    key: &'static str,
    start: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CatalogRecord {
    signature: PatternSignature,
    rendered: String,
    repeat_count: usize,
    occurrences: Vec<Occurrence>,
    window: usize,
}

impl CatalogRecord {
    fn entry(&self) -> IsomorphCatalogEntry {
        IsomorphCatalogEntry {
            signature: self.rendered.clone(),
            repeat_count: self.repeat_count,
            occurrences: self
                .occurrences
                .iter()
                .map(|occurrence| (occurrence.key, occurrence.start))
                .collect(),
            window: self.window,
        }
    }
}

fn build_catalog_records(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    windows: &[usize],
) -> Result<Vec<CatalogRecord>, PerfectIsomorphismError> {
    let mut records = Vec::new();
    for window in windows {
        let mut grouped: BTreeMap<PatternSignature, Vec<Occurrence>> = BTreeMap::new();
        for (message_index, (key, values)) in keys.iter().copied().zip(message_values).enumerate() {
            if *window > values.len() {
                return Err(IsomorphError::InvalidWindow {
                    window: *window,
                    sequence_len: values.len(),
                }
                .into());
            }
            for (start, symbols) in values.windows(*window).enumerate() {
                let signature = PatternSignature::from_window(symbols);
                if repeated_symbol_count(&signature) >= 2 {
                    grouped.entry(signature).or_default().push(Occurrence {
                        message_index,
                        key,
                        start,
                    });
                }
            }
        }
        records.extend(records_from_groups(*window, grouped));
    }
    records.sort_by(compare_catalog_records);
    Ok(records)
}

fn records_from_groups(
    window: usize,
    grouped: BTreeMap<PatternSignature, Vec<Occurrence>>,
) -> Vec<CatalogRecord> {
    let mut records = Vec::new();
    for (signature, mut occurrences) in grouped {
        occurrences.sort_unstable();
        if distinct_message_count(&occurrences) < STRONG_MIN_OCCURRENCES {
            continue;
        }
        let repeat_count = repeated_symbol_count(&signature);
        records.push(CatalogRecord {
            rendered: render_gap_signature(&signature),
            repeat_count,
            occurrences,
            signature,
            window,
        });
    }
    records
}

fn compare_catalog_records(left: &CatalogRecord, right: &CatalogRecord) -> std::cmp::Ordering {
    right
        .repeat_count
        .cmp(&left.repeat_count)
        .then_with(|| right.occurrences.len().cmp(&left.occurrences.len()))
        .then_with(|| left.window.cmp(&right.window))
        .then_with(|| left.rendered.cmp(&right.rendered))
}

fn catalog_significance(
    config: PerfectIsomorphismConfig,
    message_values: &[Vec<TrigramValue>],
    records: &[CatalogRecord],
    windows: &[usize],
) -> Result<Vec<IsomorphSignificance>, PerfectIsomorphismError> {
    let mut samples = records
        .iter()
        .map(|_record| Vec::with_capacity(config.trials))
        .collect::<Vec<_>>();
    let mut empirical_counts = vec![0usize; records.len()];

    for trial in 0..config.trials {
        let mut rng = SplitMix64::new(mix_seed(
            config.seed,
            NULL_TAG_BASE ^ u64::try_from(trial).unwrap_or(u64::MAX),
        ));
        let shuffled = shuffled_messages(message_values, &mut rng)?;
        let shuffled_counts = signature_counts(&shuffled, windows);
        for ((sample, empirical_count), record) in samples
            .iter_mut()
            .zip(empirical_counts.iter_mut())
            .zip(records)
        {
            let count = shuffled_counts
                .get(&(record.window, record.signature.clone()))
                .copied()
                .unwrap_or_default();
            sample.push(count);
            if count >= record.occurrences.len() {
                *empirical_count += 1;
            }
        }
    }

    Ok(records
        .iter()
        .zip(samples)
        .zip(empirical_counts)
        .map(|((record, sample), empirical_p_count)| {
            let empirical_p = add_one_p_value(empirical_p_count, config.trials);
            let null_max_occurrences = sample.iter().copied().max().unwrap_or_default();
            IsomorphSignificance {
                signature: record.rendered.clone(),
                window: record.window,
                observed_occurrences: record.occurrences.len(),
                null_mean_occurrences: mean(&sample),
                null_max_occurrences,
                empirical_p_count,
                empirical_p,
                strong: record.repeat_count >= STRONG_MIN_REPEATS
                    && record.occurrences.len() >= STRONG_MIN_OCCURRENCES
                    && empirical_p <= SIGNIFICANCE_ALPHA,
            }
        })
        .collect())
}

fn signature_counts(
    message_values: &[Vec<TrigramValue>],
    windows: &[usize],
) -> BTreeMap<(usize, PatternSignature), usize> {
    let mut counts = BTreeMap::new();
    for window in windows {
        for values in message_values {
            for symbols in values.windows(*window) {
                let signature = PatternSignature::from_window(symbols);
                if repeated_symbol_count(&signature) >= 2 {
                    let entry = counts.entry((*window, signature)).or_insert(0usize);
                    *entry += 1;
                }
            }
        }
    }
    counts
}

fn strong_repeat_catalog_records(records: &[CatalogRecord]) -> Vec<&CatalogRecord> {
    records
        .iter()
        .filter(|record| {
            record.repeat_count >= STRONG_MIN_REPEATS
                && record.occurrences.len() >= STRONG_MIN_OCCURRENCES
        })
        .collect()
}

fn safe_extent_seed_records<'a>(records: &[&'a CatalogRecord]) -> Vec<&'a CatalogRecord> {
    records
        .iter()
        .copied()
        .filter(|record| {
            (record.window == 9 && record.rendered == MAIN_ISOMORPH_W9)
                || (record.window == 11 && record.rendered == MAIN_ISOMORPH_W11)
        })
        .collect()
}

fn localize_extents(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    records: &[&CatalogRecord],
    deduplicate: bool,
) -> (Vec<BreakLocalization>, Vec<SafeIsomorphExtent>) {
    let pairwise = collect_pairwise_extents(keys, message_values, records);
    let mut extents = Vec::new();
    let mut seen = BTreeSet::new();
    for row in pairwise {
        let key = extent_key(&row.extent);
        if !deduplicate || seen.insert(key) {
            extents.push(row.extent);
        }
    }
    extents.sort_by(compare_extents);
    let breaks = extents
        .iter()
        .filter_map(|extent| extent.bounding_break.clone())
        .collect::<Vec<_>>();
    (breaks, extents)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PairwiseExtent {
    left: Occurrence,
    right: Occurrence,
    extent: SafeIsomorphExtent,
}

fn collect_pairwise_extents(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    records: &[&CatalogRecord],
) -> Vec<PairwiseExtent> {
    let mut pairwise = Vec::new();
    for record in records {
        for (left_position, left) in record.occurrences.iter().enumerate() {
            for right in record.occurrences.iter().skip(left_position + 1) {
                if left.message_index == right.message_index {
                    continue;
                }
                let Some(left_values) = message_values.get(left.message_index) else {
                    continue;
                };
                let Some(right_values) = message_values.get(right.message_index) else {
                    continue;
                };
                let extent = extend_occurrence_pair(
                    keys,
                    left_values,
                    right_values,
                    *left,
                    *right,
                    record.window,
                );
                pairwise.push(PairwiseExtent {
                    left: *left,
                    right: *right,
                    extent,
                });
            }
        }
    }
    pairwise
}

fn conservative_safe_extents(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    records: &[&CatalogRecord],
) -> Vec<SafeIsomorphExtent> {
    let mut pairwise = collect_pairwise_extents(keys, message_values, records);
    let end_by_occurrence = tightest_end_by_occurrence(&pairwise);
    for row in &mut pairwise {
        if let Some(end) = end_by_occurrence.get(&row.left).copied() {
            clamp_span_end(&mut row.extent.left_span, end);
        }
        if let Some(end) = end_by_occurrence.get(&row.right).copied() {
            clamp_span_end(&mut row.extent.right_span, end);
        }
    }
    let mut extents = pairwise
        .into_iter()
        .map(|row| row.extent)
        .collect::<Vec<_>>();
    extents.sort_by(compare_extents);
    extents
}

fn tightest_end_by_occurrence(pairwise: &[PairwiseExtent]) -> BTreeMap<Occurrence, usize> {
    let mut end_by_occurrence = BTreeMap::new();
    for row in pairwise {
        record_tightest_end(&mut end_by_occurrence, row.left, row.extent.left_span.end());
        record_tightest_end(
            &mut end_by_occurrence,
            row.right,
            row.extent.right_span.end(),
        );
    }
    end_by_occurrence
}

fn record_tightest_end(
    end_by_occurrence: &mut BTreeMap<Occurrence, usize>,
    occurrence: Occurrence,
    end: usize,
) {
    let _stored = end_by_occurrence
        .entry(occurrence)
        .and_modify(|stored| *stored = (*stored).min(end))
        .or_insert(end);
}

fn clamp_span_end(span: &mut SafeSpan, end: usize) {
    span.len = end.saturating_sub(span.start);
}

fn extent_key(
    extent: &SafeIsomorphExtent,
) -> (&'static str, &'static str, usize, usize, usize, usize) {
    (
        extent.pair.0,
        extent.pair.1,
        extent.left_span.start,
        extent.right_span.start,
        extent.left_span.len,
        extent.right_span.len,
    )
}

fn compare_extents(left: &SafeIsomorphExtent, right: &SafeIsomorphExtent) -> std::cmp::Ordering {
    left.pair
        .cmp(&right.pair)
        .then_with(|| left.left_span.start.cmp(&right.left_span.start))
        .then_with(|| left.right_span.start.cmp(&right.right_span.start))
        .then_with(|| left.left_span.len.cmp(&right.left_span.len))
}

fn extend_occurrence_pair(
    _keys: &[&'static str],
    left_values: &[TrigramValue],
    right_values: &[TrigramValue],
    left: Occurrence,
    right: Occurrence,
    window: usize,
) -> SafeIsomorphExtent {
    let mut left_start = left.start;
    let mut right_start = right.start;
    let mut len = window;
    while left_start > 0
        && right_start > 0
        && same_signature(
            left_values,
            left_start - 1,
            right_values,
            right_start - 1,
            len + 1,
        )
    {
        left_start -= 1;
        right_start -= 1;
        len += 1;
    }
    while same_signature(left_values, left_start, right_values, right_start, len + 1) {
        len += 1;
    }
    let bounding_break = if has_position(left_values, left_start + len)
        && has_position(right_values, right_start + len)
    {
        Some(classify_break(PairSlice {
            left_key: left.key,
            right_key: right.key,
            left_values,
            right_values,
            left_start,
            right_start,
            prefix_len: len,
        }))
    } else {
        None
    };
    SafeIsomorphExtent {
        pair: (left.key, right.key),
        left_span: SafeSpan {
            start: left_start,
            len,
        },
        right_span: SafeSpan {
            start: right_start,
            len,
        },
        bounding_break,
    }
}

#[derive(Clone, Copy)]
struct PairSlice<'a> {
    left_key: &'static str,
    right_key: &'static str,
    left_values: &'a [TrigramValue],
    right_values: &'a [TrigramValue],
    left_start: usize,
    right_start: usize,
    prefix_len: usize,
}

fn classify_break(input: PairSlice<'_>) -> BreakLocalization {
    let profile = internal_profile(input);
    let mut class = BreakClass::Boundary;
    if profile.qualifies {
        class = benign_region(input).map_or(BreakClass::InternalCandidate, |region| {
            BreakClass::BenignDesync { region }
        });
    }
    BreakLocalization {
        pair: (input.left_key, input.right_key),
        anchor: (input.left_start, input.right_start),
        left_flank: input.prefix_len,
        right_flank: profile.far_run,
        break_index: input.prefix_len,
        island_cols: profile.island_cols,
        far_run: profile.far_run,
        class,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InternalProfile {
    qualifies: bool,
    island_cols: usize,
    far_run: usize,
}

fn internal_profile(input: PairSlice<'_>) -> InternalProfile {
    if input.prefix_len < MIN_TWO_SIDED_FLANK {
        return InternalProfile {
            qualifies: false,
            island_cols: 0,
            far_run: 0,
        };
    }

    let mut best = InternalProfile {
        qualifies: false,
        island_cols: 0,
        far_run: 0,
    };
    for island_cols in 1..=MAX_ISLAND_COLS {
        let far_run = far_run_after_island(input, island_cols);
        if far_run > best.far_run {
            best.island_cols = island_cols;
            best.far_run = far_run;
        }
        if far_run >= POST_MIN && has_cross_island_back_reference(input, island_cols, far_run) {
            return InternalProfile {
                qualifies: true,
                island_cols,
                far_run,
            };
        }
    }
    best
}

fn far_run_after_island(input: PairSlice<'_>, island_cols: usize) -> usize {
    let mut far_run = 0usize;
    let Some(left_after) = input.prefix_len.checked_add(island_cols) else {
        return far_run;
    };
    while same_signature(
        input.left_values,
        input.left_start + left_after,
        input.right_values,
        input.right_start + left_after,
        far_run + 1,
    ) {
        far_run += 1;
    }
    far_run
}

fn has_cross_island_back_reference(
    input: PairSlice<'_>,
    island_cols: usize,
    far_run: usize,
) -> bool {
    let total_len = input
        .prefix_len
        .saturating_add(island_cols)
        .saturating_add(far_run);
    let Some(left_window) = input
        .left_values
        .get(input.left_start..input.left_start.saturating_add(total_len))
    else {
        return false;
    };
    let Some(right_window) = input
        .right_values
        .get(input.right_start..input.right_start.saturating_add(total_len))
    else {
        return false;
    };
    let left_signature = PatternSignature::from_window(left_window);
    let right_signature = PatternSignature::from_window(right_window);
    let suffix_start = input.prefix_len.saturating_add(island_cols);
    for relative in suffix_start..total_len {
        if has_shared_pre_island_source(
            left_signature.values(),
            right_signature.values(),
            relative,
            input.prefix_len,
        ) {
            return true;
        }
    }
    false
}

fn has_shared_pre_island_source(
    left_values: &[usize],
    right_values: &[usize],
    relative: usize,
    prefix_len: usize,
) -> bool {
    let Some(left_target) = left_values.get(relative).copied() else {
        return false;
    };
    let Some(right_target) = right_values.get(relative).copied() else {
        return false;
    };
    left_values
        .iter()
        .zip(right_values)
        .take(prefix_len)
        .any(|(left_prior, right_prior)| *left_prior == left_target && *right_prior == right_target)
}

fn benign_region(input: PairSlice<'_>) -> Option<BenignDesyncRegion> {
    let left_break = input.left_start + input.prefix_len;
    let right_break = input.right_start + input.prefix_len;
    if is_pair(input.left_key, input.right_key, "east1", "west1")
        && range_overlap(left_break, right_break, 1, 30)
    {
        return Some(BenignDesyncRegion::FunnyLookingObstacle);
    }
    if is_pair(input.left_key, input.right_key, "west1", "east2")
        && range_overlap(left_break, right_break, 35, 95)
    {
        return Some(BenignDesyncRegion::Caboose);
    }
    if all_in_stutter_family(input.left_key, input.right_key)
        && range_overlap(left_break, right_break, 35, 80)
    {
        return Some(BenignDesyncRegion::StutterSection);
    }
    None
}

fn is_pair(left: &str, right: &str, a: &str, b: &str) -> bool {
    (left == a && right == b) || (left == b && right == a)
}

fn all_in_stutter_family(left: &str, right: &str) -> bool {
    ["east4", "west4", "east5"].contains(&left) && ["east4", "west4", "east5"].contains(&right)
}

fn range_overlap(left: usize, right: usize, start: usize, end: usize) -> bool {
    (start..=end).contains(&left) || (start..=end).contains(&right)
}

fn internal_violation_null(
    config: PerfectIsomorphismConfig,
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    windows: &[usize],
    observed: usize,
) -> Result<(InternalViolationNullBand, usize, f64), PerfectIsomorphismError> {
    let mut samples = Vec::with_capacity(config.trials);
    let mut empirical_p_count = 0usize;
    for trial in 0..config.trials {
        let mut rng = SplitMix64::new(mix_seed(
            config.seed,
            NULL_TAG_BASE ^ 0x9e37_0000_0000_0000 ^ u64::try_from(trial).unwrap_or(u64::MAX),
        ));
        let shuffled = shuffled_messages(message_values, &mut rng)?;
        let count = internal_candidate_count_for_messages(keys, &shuffled, windows)?;
        if count >= observed {
            empirical_p_count += 1;
        }
        samples.push(count);
    }
    let mut sorted = samples.clone();
    sorted.sort_unstable();
    let band = InternalViolationNullBand {
        trials: config.trials,
        count_mean: mean(&samples),
        count_median: median(&sorted),
        count_q975: quantile_from_sorted(&sorted, 975, 1_000),
        count_max: sorted.last().copied().unwrap_or_default(),
    };
    Ok((
        band,
        empirical_p_count,
        add_one_p_value(empirical_p_count, config.trials),
    ))
}

fn internal_candidate_count_for_messages(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    windows: &[usize],
) -> Result<usize, PerfectIsomorphismError> {
    let records = build_catalog_records(keys, message_values, windows)?;
    let strong = records
        .iter()
        .filter(|record| {
            record.repeat_count >= STRONG_MIN_REPEATS
                && record.occurrences.len() >= STRONG_MIN_OCCURRENCES
        })
        .collect::<Vec<_>>();
    let (breaks, _extents) = localize_extents(keys, message_values, &strong, true);
    Ok(count_internal_candidates(&breaks))
}

fn count_internal_candidates(breaks: &[BreakLocalization]) -> usize {
    let mut events = BTreeSet::new();
    for break_row in breaks {
        if break_row.class == BreakClass::InternalCandidate {
            let _inserted = events.insert((
                break_row.pair,
                break_row.anchor.0 + break_row.break_index,
                break_row.anchor.1 + break_row.break_index,
            ));
        }
    }
    events.len()
}

fn run_regression_checks(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    records: &[CatalogRecord],
    breaks: &[BreakLocalization],
) -> Result<Vec<WikiRegressionResult>, PerfectIsomorphismError> {
    Ok(vec![
        regression_3a(keys, message_values)?,
        regression_3b(keys, message_values, breaks)?,
        regression_3c(),
        regression_main_isomorph(records),
    ])
}

fn regression_3a(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
) -> Result<WikiRegressionResult, PerfectIsomorphismError> {
    let expected = vec![
        "A..BC.D....AB.......DC...".to_owned(),
        "A..BC.D....AB.......DC..D".to_owned(),
        "Boundary@24".to_owned(),
    ];
    let top = fixed_span_signature(
        keys,
        message_values,
        "east1",
        1,
        25,
        WikiRegressionCheck::Messages12SharedAllomorph,
    )?;
    let bottom = fixed_span_signature(
        keys,
        message_values,
        "west1",
        1,
        25,
        WikiRegressionCheck::Messages12SharedAllomorph,
    )?;
    let break_row = fixed_break_classification(
        keys,
        message_values,
        "east1",
        "west1",
        1,
        24,
        WikiRegressionCheck::Messages12SharedAllomorph,
    )?;
    let produced = vec![top, bottom, break_label(&break_row)];
    let reproduced = produced == expected;
    Ok(WikiRegressionResult {
        check: WikiRegressionCheck::Messages12SharedAllomorph,
        produced,
        expected,
        reproduced,
        hypothesis_label: String::new(),
    })
}

fn regression_3b(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    breaks: &[BreakLocalization],
) -> Result<WikiRegressionResult, PerfectIsomorphismError> {
    let expected = vec![
        ".AB......B.A".to_owned(),
        ".AB......B.A".to_owned(),
        ".AB......B.A".to_owned(),
        "msg7 O-repeat @10/16/26".to_owned(),
        "no InternalCandidate in fixed 7/8/9 region".to_owned(),
    ];
    let produced = vec![
        fixed_span_signature(
            keys,
            message_values,
            "east4",
            50,
            12,
            WikiRegressionCheck::Messages789ExtraRepeat,
        )?,
        fixed_span_signature(
            keys,
            message_values,
            "west4",
            52,
            12,
            WikiRegressionCheck::Messages789ExtraRepeat,
        )?,
        fixed_span_signature(
            keys,
            message_values,
            "east5",
            51,
            12,
            WikiRegressionCheck::Messages789ExtraRepeat,
        )?,
        msg7_extra_repeat_claim(keys, message_values)?,
        stutter_region_internal_claim(breaks),
    ];
    let reproduced = produced == expected;
    Ok(WikiRegressionResult {
        check: WikiRegressionCheck::Messages789ExtraRepeat,
        produced,
        expected,
        reproduced,
        hypothesis_label: String::new(),
    })
}

fn regression_3c() -> WikiRegressionResult {
    let row = "+++++xxxxx?????x++++++++++++".to_owned();
    WikiRegressionResult {
        check: WikiRegressionCheck::CorruptionTheoryBound,
        produced: vec![row.clone()],
        expected: vec![row],
        reproduced: true,
        hypothesis_label:
            "fixed cited annotation from Allomorphs.md; conditional on single-deletion assumption; bounds where a difference must be, does not locate it"
                .to_owned(),
    }
}

fn regression_main_isomorph(records: &[CatalogRecord]) -> WikiRegressionResult {
    let produced = records
        .iter()
        .find(|record| record.window == 9 && record.rendered == MAIN_ISOMORPH_W9)
        .map_or_else(Vec::new, |record| {
            vec![
                record.rendered.clone(),
                record.occurrences.len().to_string(),
            ]
        });
    let expected = vec![MAIN_ISOMORPH_W9.to_owned(), "6".to_owned()];
    let reproduced = produced == expected;
    WikiRegressionResult {
        check: WikiRegressionCheck::MainIsomorphPositiveControl,
        produced,
        expected,
        reproduced,
        hypothesis_label: String::new(),
    }
}

fn ensure_all_regressions_reproduced(
    regression: &[WikiRegressionResult],
) -> Result<(), PerfectIsomorphismError> {
    for result in regression {
        if !result.reproduced {
            return Err(PerfectIsomorphismError::RegressionCheckFailed {
                check: result.check,
            });
        }
    }
    Ok(())
}

fn run_positive_control(
    records: &[CatalogRecord],
    significance: &[IsomorphSignificance],
    breaks: &[BreakLocalization],
) -> Result<(), PerfectIsomorphismError> {
    let Some(record) = records
        .iter()
        .find(|record| record.window == 9 && record.rendered == MAIN_ISOMORPH_W9)
    else {
        return Err(PerfectIsomorphismError::PositiveControlFailed {
            detail: "main w9 signature missing".to_owned(),
        });
    };
    let Some(row) = significance
        .iter()
        .find(|row| row.window == 9 && row.signature == MAIN_ISOMORPH_W9)
    else {
        return Err(PerfectIsomorphismError::PositiveControlFailed {
            detail: "main w9 significance row missing".to_owned(),
        });
    };
    let Some(w11_row) = significance
        .iter()
        .find(|row| row.window == 11 && row.signature == MAIN_ISOMORPH_W11)
    else {
        return Err(PerfectIsomorphismError::PositiveControlFailed {
            detail: "main w11 significance row missing".to_owned(),
        });
    };
    if !row.strong
        || row.observed_occurrences != 6
        || row.observed_occurrences < row.null_max_occurrences + POSITIVE_CONTROL_MIN_MARGIN
    {
        return Err(PerfectIsomorphismError::PositiveControlFailed {
            detail: "main w9 signature did not clear the strong matched-null margin".to_owned(),
        });
    }
    if !w11_row.strong
        || w11_row.observed_occurrences != 4
        || w11_row.observed_occurrences < w11_row.null_max_occurrences + POSITIVE_CONTROL_MIN_MARGIN
    {
        return Err(PerfectIsomorphismError::PositiveControlFailed {
            detail: "main w11 signature did not clear the strong matched-null margin".to_owned(),
        });
    }
    if breaks.iter().any(|break_row| {
        main_isomorph_break(record, break_row) && break_row.class == BreakClass::InternalCandidate
    }) {
        return Err(PerfectIsomorphismError::PositiveControlFailed {
            detail: "main w9 trailing divergence classified as internal".to_owned(),
        });
    }
    if !synthetic_internal_violation_fires()? {
        return Err(PerfectIsomorphismError::PositiveControlFailed {
            detail: "synthetic short-island internal violation was not detected".to_owned(),
        });
    }
    Ok(())
}

fn main_isomorph_break(record: &CatalogRecord, break_row: &BreakLocalization) -> bool {
    record.occurrences.iter().any(|occurrence| {
        occurrence.key == break_row.pair.0 && occurrence.start >= break_row.anchor.0
    }) && record.occurrences.iter().any(|occurrence| {
        occurrence.key == break_row.pair.1 && occurrence.start >= break_row.anchor.1
    })
}

fn synthetic_internal_violation_fires() -> Result<bool, PerfectIsomorphismError> {
    let seed = stateless_splitmix(POSITIVE_CONTROL_TAG);
    let keys = ["synthetic-left", "synthetic-right"];
    let message_values = vec![
        synthetic_values(seed, true)?,
        synthetic_values(seed, false)?,
    ];
    let records = build_catalog_records(&keys, &message_values, &CATALOG_WINDOWS)?;
    let strong = strong_repeat_catalog_records(&records);
    let (breaks, _extents) = localize_extents(&keys, &message_values, &strong, true);
    Ok(breaks.iter().any(|break_row| {
        break_row.class == BreakClass::InternalCandidate
            && break_row.island_cols == 1
            && break_row.far_run >= POST_MIN
    }))
}

fn synthetic_values(
    seed: u64,
    left_variant: bool,
) -> Result<Vec<TrigramValue>, PerfectIsomorphismError> {
    let offset = (seed % 7) as u8;
    let raw_values = if left_variant {
        [
            1 + offset,
            2 + offset,
            3 + offset,
            1 + offset,
            4 + offset,
            2 + offset,
            5 + offset,
            3 + offset,
            6 + offset,
            2 + offset,
            7 + offset,
            8 + offset,
            1 + offset,
            9 + offset,
            10 + offset,
            11 + offset,
            12 + offset,
            13 + offset,
            14 + offset,
            15 + offset,
        ]
    } else {
        [
            31 + offset,
            32 + offset,
            33 + offset,
            31 + offset,
            34 + offset,
            32 + offset,
            35 + offset,
            33 + offset,
            36 + offset,
            37 + offset,
            38 + offset,
            39 + offset,
            31 + offset,
            40 + offset,
            41 + offset,
            42 + offset,
            43 + offset,
            44 + offset,
            45 + offset,
            46 + offset,
        ]
    };
    raw_values
        .into_iter()
        .map(|raw| {
            TrigramValue::new(raw).map_err(|value| PerfectIsomorphismError::PositiveControlFailed {
                detail: format!("synthetic value {value} outside trigram range"),
            })
        })
        .collect()
}

fn fixed_span_signature(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    key: &str,
    start: usize,
    len: usize,
    check: WikiRegressionCheck,
) -> Result<String, PerfectIsomorphismError> {
    let Some(values) = values_for_key(keys, message_values, key) else {
        return Err(PerfectIsomorphismError::RegressionCheckFailed { check });
    };
    let Some(window) = values.get(start..start.saturating_add(len)) else {
        return Err(PerfectIsomorphismError::RegressionCheckFailed { check });
    };
    Ok(render_gap_signature(&PatternSignature::from_window(window)))
}

fn fixed_break_classification(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    left_key: &'static str,
    right_key: &'static str,
    start: usize,
    break_index: usize,
    check: WikiRegressionCheck,
) -> Result<BreakLocalization, PerfectIsomorphismError> {
    let Some(left_values) = values_for_key(keys, message_values, left_key) else {
        return Err(PerfectIsomorphismError::RegressionCheckFailed { check });
    };
    let Some(right_values) = values_for_key(keys, message_values, right_key) else {
        return Err(PerfectIsomorphismError::RegressionCheckFailed { check });
    };
    Ok(classify_break(PairSlice {
        left_key,
        right_key,
        left_values,
        right_values,
        left_start: start,
        right_start: start,
        prefix_len: break_index,
    }))
}

fn break_label(break_row: &BreakLocalization) -> String {
    format!(
        "{}@{}",
        break_class_label(break_row.class),
        break_row.break_index
    )
}

fn stutter_region_internal_claim(breaks: &[BreakLocalization]) -> String {
    if breaks.iter().any(|break_row| {
        break_row.class == BreakClass::InternalCandidate
            && all_in_stutter_family(break_row.pair.0, break_row.pair.1)
            && break_overlaps_region(break_row, 35, 80)
    }) {
        "InternalCandidate in fixed 7/8/9 region".to_owned()
    } else {
        "no InternalCandidate in fixed 7/8/9 region".to_owned()
    }
}

fn break_overlaps_region(break_row: &BreakLocalization, start: usize, end: usize) -> bool {
    range_overlap(
        break_row.anchor.0 + break_row.break_index,
        break_row.anchor.1 + break_row.break_index,
        start,
        end,
    )
}

fn msg7_extra_repeat_claim(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
) -> Result<String, PerfectIsomorphismError> {
    let Some(values) = values_for_key(keys, message_values, "east4") else {
        return Err(PerfectIsomorphismError::RegressionCheckFailed {
            check: WikiRegressionCheck::Messages789ExtraRepeat,
        });
    };
    let absolute_positions = [45usize, 51, 61];
    let mut iter = absolute_positions.into_iter();
    let Some(first_position) = iter.next() else {
        return Err(PerfectIsomorphismError::RegressionCheckFailed {
            check: WikiRegressionCheck::Messages789ExtraRepeat,
        });
    };
    let Some(first) = values.get(first_position).copied() else {
        return Err(PerfectIsomorphismError::RegressionCheckFailed {
            check: WikiRegressionCheck::Messages789ExtraRepeat,
        });
    };
    if iter.all(|position| values.get(position).copied() == Some(first)) {
        Ok("msg7 O-repeat @10/16/26".to_owned())
    } else {
        Ok("msg7 O-repeat missing".to_owned())
    }
}

fn values_for_key<'a>(
    keys: &[&str],
    message_values: &'a [Vec<TrigramValue>],
    key: &str,
) -> Option<&'a [TrigramValue]> {
    keys.iter()
        .position(|candidate| *candidate == key)
        .and_then(|index| message_values.get(index))
        .map(Vec::as_slice)
}

fn shuffled_messages(
    message_values: &[Vec<TrigramValue>],
    rng: &mut SplitMix64,
) -> Result<Vec<Vec<TrigramValue>>, PerfectIsomorphismError> {
    let mut shuffled = message_values.to_vec();
    for values in &mut shuffled {
        fisher_yates(values, rng)?;
    }
    Ok(shuffled)
}

fn same_signature(
    left_values: &[TrigramValue],
    left_start: usize,
    right_values: &[TrigramValue],
    right_start: usize,
    len: usize,
) -> bool {
    let Some(left) = left_values.get(left_start..left_start.saturating_add(len)) else {
        return false;
    };
    let Some(right) = right_values.get(right_start..right_start.saturating_add(len)) else {
        return false;
    };
    PatternSignature::from_window(left) == PatternSignature::from_window(right)
}

fn has_position(values: &[TrigramValue], position: usize) -> bool {
    values.get(position).is_some()
}

fn repeated_symbol_count(signature: &PatternSignature) -> usize {
    let mut counts = BTreeMap::new();
    for value in signature.values() {
        let entry = counts.entry(*value).or_insert(0usize);
        *entry += 1;
    }
    counts.values().filter(|count| **count > 1).count()
}

fn render_gap_signature(signature: &PatternSignature) -> String {
    let mut counts = BTreeMap::new();
    for value in signature.values() {
        let entry = counts.entry(*value).or_insert(0usize);
        *entry += 1;
    }
    let mut labels = BTreeMap::new();
    let mut next_label = 0usize;
    let mut rendered = String::new();
    for value in signature.values() {
        if counts.get(value).copied().unwrap_or_default() <= 1 {
            rendered.push('.');
        } else {
            let label_index = labels.entry(*value).or_insert_with(|| {
                let assigned = next_label;
                next_label += 1;
                assigned
            });
            rendered.push(label_for_index(*label_index));
        }
    }
    rendered
}

fn label_for_index(index: usize) -> char {
    let Ok(offset) = u8::try_from(index) else {
        return '?';
    };
    char::from(b'A'.saturating_add(offset))
}

fn distinct_message_count(occurrences: &[Occurrence]) -> usize {
    occurrences
        .iter()
        .map(|occurrence| occurrence.message_index)
        .collect::<BTreeSet<_>>()
        .len()
}

fn break_class_label(class: BreakClass) -> &'static str {
    match class {
        BreakClass::Boundary => "Boundary",
        BreakClass::InternalCandidate => "InternalCandidate",
        BreakClass::BenignDesync { .. } => "BenignDesync",
    }
}

fn mean(samples: &[usize]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    samples.iter().sum::<usize>() as f64 / samples.len() as f64
}

fn median(sorted: &[usize]) -> f64 {
    let len = sorted.len();
    if len == 0 {
        return 0.0;
    }
    let middle = len / 2;
    if len.is_multiple_of(2) {
        match (
            sorted.get(middle.saturating_sub(1)).copied(),
            sorted.get(middle).copied(),
        ) {
            (Some(left), Some(right)) => f64::midpoint(left as f64, right as f64),
            _ => 0.0,
        }
    } else {
        sorted
            .get(middle)
            .copied()
            .map_or(0.0, |value| value as f64)
    }
}

fn quantile_from_sorted(sorted: &[usize], numerator: usize, denominator: usize) -> usize {
    sorted
        .get(scaled_quantile_index(sorted.len(), numerator, denominator))
        .copied()
        .unwrap_or_default()
}

fn scaled_quantile_index(len: usize, numerator: usize, denominator: usize) -> usize {
    if len == 0 || denominator == 0 {
        return 0;
    }
    len.saturating_sub(1).saturating_mul(numerator) / denominator
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        ALPHABET_SIZE, BreakClass, PerfectIsomorphismConfig, WikiRegressionCheck,
        report_from_message_values, run_perfect_isomorphism, synthetic_internal_violation_fires,
    };
    use crate::orders;

    #[test]
    fn perfect_isomorphism_run_is_deterministic_for_fixed_seed() {
        let config = PerfectIsomorphismConfig {
            seed: 0x1234,
            trials: 32,
            ..PerfectIsomorphismConfig::default()
        };

        let first = run_perfect_isomorphism(config).unwrap();
        let second = run_perfect_isomorphism(config).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.order.name(), "standard36-u012-d012");
    }

    #[test]
    fn real_eye_stream_pins_lengths_and_alphabet() {
        let config = PerfectIsomorphismConfig {
            seed: 0x5678,
            trials: 32,
            ..PerfectIsomorphismConfig::default()
        };
        let report = run_perfect_isomorphism(config).unwrap();

        assert_eq!(report.total_length, 1_036);
        assert_eq!(
            report.message_lengths,
            vec![
                ("east1", 99),
                ("west1", 103),
                ("east2", 118),
                ("west2", 102),
                ("east3", 137),
                ("west3", 124),
                ("east4", 119),
                ("west4", 120),
                ("east5", 114),
            ]
        );

        let grids = orders::corpus_grids().unwrap();
        let messages =
            orders::read_corpus_message_values(&grids, orders::accepted_honeycomb_order()).unwrap();
        let distinct = messages
            .iter()
            .flatten()
            .map(|value| value.get())
            .collect::<BTreeSet<_>>();
        assert_eq!(distinct.len(), ALPHABET_SIZE);
    }

    #[test]
    fn positive_control_and_regressions_fire() {
        let config = PerfectIsomorphismConfig {
            seed: 0x9999,
            trials: 32,
            ..PerfectIsomorphismConfig::default()
        };
        let report = run_perfect_isomorphism(config).unwrap();

        assert!(report.positive_control_fired);
        assert_eq!(report.robust_internal_violations, 0);
        assert_eq!(report.safe_extents.len(), 16);
        assert!(report.regression.iter().all(|result| result.reproduced));
        assert!(report.regression.iter().any(|result| {
            result.check == WikiRegressionCheck::CorruptionTheoryBound
                && result.hypothesis_label.contains("conditional")
        }));
    }

    #[test]
    fn synthetic_internal_violation_control_is_detected() {
        assert!(synthetic_internal_violation_fires().unwrap());
    }

    #[test]
    fn invalid_window_range_is_rejected() {
        let config = PerfectIsomorphismConfig {
            seed: 1,
            trials: 1,
            min_window: 10,
            max_window: 10,
        };

        assert!(run_perfect_isomorphism(config).is_err());
    }

    #[test]
    fn hand_built_boundary_negative_stays_boundary() {
        let left = values(&[1, 2, 1, 3, 4, 5, 6]);
        let right = values(&[9, 8, 9, 7, 6, 5, 4]);
        let break_row = super::classify_break(super::PairSlice {
            left_key: "left",
            right_key: "right",
            left_values: &left,
            right_values: &right,
            left_start: 0,
            right_start: 0,
            prefix_len: 3,
        });

        assert_eq!(break_row.class, BreakClass::Boundary);
    }

    #[test]
    fn report_from_message_values_accepts_small_trial_fixture() {
        let grids = orders::corpus_grids().unwrap();
        let keys = grids
            .iter()
            .map(crate::orders::GlyphGrid::message_key)
            .collect::<Vec<_>>();
        let order = orders::accepted_honeycomb_order();
        let message_values = orders::read_corpus_message_values(&grids, order).unwrap();
        let config = PerfectIsomorphismConfig {
            seed: 0x4242,
            trials: 32,
            ..PerfectIsomorphismConfig::default()
        };

        let report = report_from_message_values(config, order, &keys, &message_values).unwrap();

        assert_eq!(report.robust_internal_violations, 0);
    }

    fn values(raw: &[u8]) -> Vec<crate::trigram::TrigramValue> {
        raw.iter()
            .copied()
            .map(crate::trigram::TrigramValue::new)
            .map(Result::unwrap)
            .collect()
    }
}

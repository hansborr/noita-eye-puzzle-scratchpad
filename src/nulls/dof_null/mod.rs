//! Calibrated researcher-degrees-of-freedom null for adaptive headline choice.
//!
//! Experiment 1B in [`crate::nulls::null`] asks a narrower question: after the
//! Toboter-style standard36 honeycomb traversal family is fixed, how often do
//! same-shape random grids reproduce the headline bounded-contiguous trigram
//! result? This module asks the broader look-elsewhere question that remained
//! unbuilt: what happens if the analyst was also free to choose a traversal
//! family, grouping rule, and headline statistic after seeing the data?
//!
//! The candidate statistics are deliberately not combined in raw units. For
//! each `(traversal, grouping, statistic)` cell, same-shape random grids define
//! that cell's marginal null scale. The real eye statistic is converted to an
//! empirical one-sided tail probability inside that cell. The reported "best"
//! eye result is the minimum calibrated marginal p-value across cells, and the
//! adaptive p-value is estimated from an independent second random-grid batch
//! whose minimum calibrated p-values are scored against the same external
//! calibration reference as the eyes.
//!
//! This empirical min-p diagnostic has finite resolution: with `N`
//! calibration grids, any cell's marginal p-value is floored at `1 / (N + 1)`.
//! It therefore cannot represent the eye corpus's analytic
//! `(83 / 125)^1036` bounded-contiguity probability. For that headline cell,
//! this module also reports an analytic multiplicity correction across the
//! configured researcher-`DoF` search space.
//!
//! Important scope nuance: the standard36 honeycomb traversal is
//! data-independent, depending only on grid shape and fixed trigram-position
//! permutations. The genuinely new exposure being calibrated here is therefore
//! concentrated on grouping choice, headline-statistic choice, and the added
//! non-honeycomb traversal controls.

use std::fmt;

use crate::analysis::orders::{self, GlyphGrid, GridError, ReadingOrder};
use crate::nulls::null::{
    self, SplitMix64, WilsonInterval, random_orientation_grids_like, wilson_95,
};

mod cells;
mod report;
#[cfg(test)]
mod tests;

use cells::{
    Quantile, alphabet_size, calibrated_cell_reports, calibrated_sample_min_ps,
    median_effective_comparisons, prepare_cells, sample_statistics_by_cell, sorted_f64,
    sorted_quantile, sorted_samples_by_cell,
};

const DEFAULT_DOF_NULL_SEED: u64 = 0x646f_666e_756c_6c00;
const DEFAULT_DOF_NULL_TRIALS: usize = 1_000;
const ORIENTATION_BASE: usize = crate::core::glyph::ORIENTATION_COUNT;
const ENGINE_STORAGE_BASE: usize = crate::core::glyph::ENGINE_STORAGE_BASE;
const MAX_RECURRENCE_DISTANCE: usize = 6;
const ANALYTIC_HEADLINE_CEILING: f64 = 82.0;

/// Configuration for the calibrated `DoF` null.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DofNullConfig {
    /// Explicit deterministic PRNG seed.
    pub seed: u64,
    /// Number of same-shape random corpora in calibration set A.
    pub calibration_trials: usize,
    /// Number of same-shape random corpora in resampling set B.
    pub trials: usize,
}

impl Default for DofNullConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_DOF_NULL_SEED,
            calibration_trials: DEFAULT_DOF_NULL_TRIALS,
            trials: DEFAULT_DOF_NULL_TRIALS,
        }
    }
}

/// Search space for the calibrated `DoF` null.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DofSearchSpace {
    /// Traversals to search.
    pub orders: Vec<ReadingOrder>,
    /// Grouping rules to apply to each compatible traversal.
    pub groupings: Vec<GroupingRule>,
    /// Headline statistics to calibrate within each compatible cell.
    pub statistics: Vec<HeadlineStatistic>,
}

impl DofSearchSpace {
    /// Returns the repository's default researcher-`DoF` search space.
    ///
    /// This includes the standard36 honeycomb family, raw/linear controls, four
    /// diagonal route controls, orientation grouping widths 1..=4, the engine
    /// storage base-7 grouping, and the four headline statistics.
    #[must_use]
    pub fn researcher_degrees_of_freedom() -> Self {
        Self {
            orders: orders::dof_candidate_orders(),
            groupings: vec![
                GroupingRule::OrientationBase5 { width: 1 },
                GroupingRule::OrientationBase5 { width: 2 },
                GroupingRule::OrientationBase5 { width: 3 },
                GroupingRule::OrientationBase5 { width: 4 },
                GroupingRule::EngineStorageBase7,
            ],
            statistics: vec![
                HeadlineStatistic::DistinctCount,
                HeadlineStatistic::ContiguousBoundedAtMax,
                HeadlineStatistic::ZeroAdjacencyRate,
                HeadlineStatistic::BestRecurrenceRatio,
            ],
        }
    }
}

/// A grouping rule searched by the `DoF` null.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GroupingRule {
    /// Non-overlapping rendered-orientation groups interpreted in base 5.
    OrientationBase5 {
        /// Number of orientation digits per grouped symbol.
        width: usize,
    },
    /// Engine storage-layer symbols in base 7, including row delimiter `5`.
    EngineStorageBase7,
}

impl GroupingRule {
    /// Human-readable grouping label.
    #[must_use]
    pub fn label(self) -> String {
        match self {
            Self::OrientationBase5 { width } => match width {
                1 => "single-base5".to_owned(),
                2 => "pair-base25".to_owned(),
                3 => "trigram-base5".to_owned(),
                4 => "tetragram-base5".to_owned(),
                _ => format!("base5-width-{width}"),
            },
            Self::EngineStorageBase7 => "engine-base7".to_owned(),
        }
    }
}

/// Headline statistic searched by the `DoF` null.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HeadlineStatistic {
    /// Count of distinct grouped symbols; smaller is treated as more extreme.
    DistinctCount,
    /// Zero-based contiguous support bounded by its maximum value.
    ContiguousBoundedAtMax,
    /// Adjacent-equal rate within messages; smaller is more zero-adjacency-like.
    ZeroAdjacencyRate,
    /// Largest recurrence ratio over previous-occurrence distances 1..=6.
    BestRecurrenceRatio,
}

impl HeadlineStatistic {
    /// Human-readable statistic label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DistinctCount => "distinct-count",
            Self::ContiguousBoundedAtMax => "contiguous-bounded-max",
            Self::ZeroAdjacencyRate => "zero-adjacency-rate",
            Self::BestRecurrenceRatio => "best-distance-k-ratio",
        }
    }

    const fn tail(self) -> TailDirection {
        match self {
            Self::DistinctCount | Self::ContiguousBoundedAtMax | Self::ZeroAdjacencyRate => {
                TailDirection::Low
            }
            Self::BestRecurrenceRatio => TailDirection::High,
        }
    }
}

/// One-sided extremeness direction for a calibrated cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TailDirection {
    /// Lower raw values are more extreme.
    Low,
    /// Higher raw values are more extreme.
    High,
}

impl TailDirection {
    /// Human-readable tail label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::High => "high",
        }
    }
}

/// Error returned by the calibrated `DoF` null.
#[derive(Clone, Debug, PartialEq)]
pub enum DofNullError {
    /// The verified or caller-supplied grids could not be read.
    Grid(GridError),
    /// At least one Monte-Carlo trial is required.
    ZeroTrials,
    /// At least one calibration trial is required.
    ZeroCalibrationTrials,
    /// The configured search space has an empty axis.
    EmptySearchSpace,
    /// No compatible `(traversal, grouping, statistic)` cells remained.
    NoValidCells,
    /// Orientation grouping width zero is invalid.
    ZeroGroupingWidth,
    /// The requested base-5 grouping alphabet cannot fit in [`crate::core::glyph::Glyph`].
    GroupingAlphabetTooLarge {
        /// Requested orientation grouping width.
        width: usize,
    },
    /// Internal cell bookkeeping became inconsistent.
    InternalCellMismatch {
        /// Expected cell count.
        expected: usize,
        /// Observed cell count.
        observed: usize,
    },
    /// The add-one empirical denominator overflowed `usize`.
    TrialCountTooLarge,
    /// The configured traversal/grouping/statistic cross-product overflowed `usize`.
    SearchSpaceTooLarge,
}

impl fmt::Display for DofNullError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Grid(grid_error) => write!(f, "grid/order error: {grid_error:?}"),
            Self::ZeroTrials => {
                write!(f, "at least one DoF null resampling trial is required")
            }
            Self::ZeroCalibrationTrials => {
                write!(f, "at least one DoF null calibration trial is required")
            }
            Self::EmptySearchSpace => write!(
                f,
                "the DoF search space must include at least one traversal, grouping, and statistic"
            ),
            Self::NoValidCells => {
                write!(
                    f,
                    "no compatible traversal/grouping/statistic cells remained"
                )
            }
            Self::ZeroGroupingWidth => write!(f, "orientation grouping width must be at least 1"),
            Self::GroupingAlphabetTooLarge { width } => {
                write!(
                    f,
                    "orientation grouping width {width} has too many base-5 states"
                )
            }
            Self::InternalCellMismatch { expected, observed } => write!(
                f,
                "internal DoF cell mismatch: expected {expected}, observed {observed}"
            ),
            Self::TrialCountTooLarge => {
                write!(
                    f,
                    "DoF null trial count is too large for add-one calibration"
                )
            }
            Self::SearchSpaceTooLarge => {
                write!(f, "DoF null search-space cross-product is too large")
            }
        }
    }
}

impl std::error::Error for DofNullError {}

impl From<GridError> for DofNullError {
    fn from(value: GridError) -> Self {
        Self::Grid(value)
    }
}

/// One skipped traversal/grouping combination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkippedCombination {
    /// Traversal that was skipped.
    pub order: ReadingOrder,
    /// Grouping that was skipped.
    pub grouping: GroupingRule,
    /// Reason the combination is undefined for this run.
    pub reason: String,
}

/// Calibrated report row for one `(traversal, grouping, statistic)` cell.
#[derive(Clone, Debug, PartialEq)]
pub struct CellReport {
    /// Traversal used by this cell.
    pub order: ReadingOrder,
    /// Grouping used by this cell.
    pub grouping: GroupingRule,
    /// Statistic used by this cell.
    pub statistic: HeadlineStatistic,
    /// One-sided tail direction used for calibration.
    pub tail: TailDirection,
    /// Nominal grouped-symbol alphabet size.
    pub alphabet_size: usize,
    /// Real grouped-symbol count after within-message grouping.
    pub real_symbols: usize,
    /// Source orientation symbols dropped by incomplete non-overlapping groups.
    pub dropped_source_symbols: usize,
    /// Raw real statistic value in this cell's native units.
    pub real_value: f64,
    /// Number of calibration trials at least as extreme as the real statistic.
    pub marginal_extreme_count: usize,
    /// Rank-based empirical marginal tail probability of the real statistic.
    pub marginal_p: f64,
    /// Smallest calibration-set null statistic value.
    pub null_min: f64,
    /// Median calibration-set null statistic value.
    pub null_median: f64,
    /// Largest calibration-set null statistic value.
    pub null_max: f64,
}

/// Analytic multiplicity correction for the known bounded-contiguity headline.
#[derive(Clone, Debug, PartialEq)]
pub struct DofAnalyticHeadlineBounds {
    /// Empirical cell used as the anchor for the analytic correction.
    pub cell: CellReport,
    /// Number of non-overlapping trigrams in the headline cell.
    pub trigrams: usize,
    /// Probability bound for one fixed order under independent uniform trigrams.
    pub per_order: f64,
    /// Total configured traversal × grouping × statistic cells before skips.
    pub total_configured_cells: usize,
    /// Bonferroni bound over all configured cells.
    pub total_bonferroni: f64,
    /// Sidak family-wise probability over all configured cells.
    pub total_sidak: f64,
    /// Empirical Sidak-equivalent comparison count from the resampling min-p median.
    pub effective_comparisons: f64,
    /// Bonferroni bound over the empirical effective comparison count.
    pub effective_bonferroni: f64,
    /// Sidak family-wise probability over the empirical effective comparison count.
    pub effective_sidak: f64,
}

/// Complete calibrated `DoF` null report.
#[derive(Clone, Debug, PartialEq)]
pub struct DofNullReport {
    /// Configuration used for the run.
    pub config: DofNullConfig,
    /// Number of traversals configured before compatibility skips.
    pub configured_orders: usize,
    /// Number of grouping rules configured before compatibility skips.
    pub configured_groupings: usize,
    /// Number of headline statistics configured.
    pub configured_statistics: usize,
    /// Configured traversal × grouping × statistic cells before compatibility skips.
    pub configured_cell_count: usize,
    /// Number of calibrated valid cells.
    pub valid_cell_count: usize,
    /// Traversal/grouping combinations skipped as undefined.
    pub skipped: Vec<SkippedCombination>,
    /// Per-cell calibrated marginal results.
    pub cells: Vec<CellReport>,
    /// Best eye cell after marginal calibration.
    pub best_cell: CellReport,
    /// Minimum calibrated marginal p-value for the real eyes.
    pub observed_min_p: f64,
    /// Smallest representable empirical marginal p-value for this calibration set.
    pub empirical_marginal_floor: f64,
    /// Count of resampling grids whose own min-p is at least as extreme.
    pub adaptive_extreme_count: usize,
    /// Wilson interval for the add-one adaptive p-value.
    pub adaptive_interval: WilsonInterval,
    /// Sidak-equivalent independent comparisons from the resampling min-p median.
    pub effective_comparisons: f64,
    /// Smallest resampling-grid min-p sampled under the adaptive null.
    pub null_min_p_min: f64,
    /// Median resampling-grid min-p sampled under the adaptive null.
    pub null_min_p_median: f64,
    /// Largest resampling-grid min-p sampled under the adaptive null.
    pub null_min_p_max: f64,
    /// Analytic multiplicity correction for the known bounded-contiguity headline.
    pub analytic_headline_bounds: Option<DofAnalyticHeadlineBounds>,
}

/// Runs the calibrated `DoF` null on the verified eye corpus.
///
/// # Errors
/// Returns [`DofNullError`] if the corpus cannot be reconstructed, the
/// configuration is invalid, or no compatible cells remain.
pub fn run_dof_null(config: DofNullConfig) -> Result<DofNullReport, DofNullError> {
    let grids = orders::corpus_grids()?;
    let space = DofSearchSpace::researcher_degrees_of_freedom();
    run_dof_null_for_grids(config, &grids, &space)
}

/// Runs the calibrated `DoF` null on caller-supplied real grids.
///
/// This is primarily for calibration controls: the same shape-preserving
/// random-grid null is used, but the observed grid may be synthetic.
///
/// # Errors
/// Returns [`DofNullError`] if the configuration or search space is invalid, or
/// if no compatible cells remain.
pub fn run_dof_null_for_grids(
    config: DofNullConfig,
    real_grids: &[GlyphGrid],
    space: &DofSearchSpace,
) -> Result<DofNullReport, DofNullError> {
    run_dof_null_with(config, real_grids, space, random_orientation_grids_like)
}

fn run_dof_null_with(
    config: DofNullConfig,
    real_grids: &[GlyphGrid],
    space: &DofSearchSpace,
    mut generate: impl FnMut(&[GlyphGrid], &mut SplitMix64) -> Vec<GlyphGrid>,
) -> Result<DofNullReport, DofNullError> {
    validate_config(config, space)?;
    let configured_cell_count = configured_cell_count(space)?;
    let empirical_marginal_floor = empirical_marginal_floor(config.calibration_trials)?;
    let prepared = prepare_cells(real_grids, space)?;
    if prepared.cells.is_empty() {
        return Err(DofNullError::NoValidCells);
    }

    let mut rng = SplitMix64::new(config.seed);
    let calibration_samples_by_cell = sample_statistics_by_cell(
        config.calibration_trials,
        real_grids,
        space,
        &prepared.streams,
        prepared.cells.len(),
        &mut rng,
        &mut generate,
    )?;
    let resampling_samples_by_cell = sample_statistics_by_cell(
        config.trials,
        real_grids,
        space,
        &prepared.streams,
        prepared.cells.len(),
        &mut rng,
        &mut generate,
    )?;

    let sorted_calibration_samples = sorted_samples_by_cell(&calibration_samples_by_cell);
    let cells = calibrated_cell_reports(&prepared.cells, &sorted_calibration_samples)?;
    let observed_min_p = cells
        .iter()
        .map(|cell| cell.marginal_p)
        .min_by(f64::total_cmp)
        .ok_or(DofNullError::NoValidCells)?;
    let best_cell = cells
        .iter()
        .min_by(|left, right| {
            left.marginal_p
                .total_cmp(&right.marginal_p)
                .then_with(|| left.statistic.cmp(&right.statistic))
                .then_with(|| left.grouping.cmp(&right.grouping))
                .then_with(|| left.order.cmp(&right.order))
        })
        .cloned()
        .ok_or(DofNullError::NoValidCells)?;
    let null_min_ps = calibrated_sample_min_ps(
        &prepared.cells,
        &resampling_samples_by_cell,
        &sorted_calibration_samples,
    )?;
    let adaptive_extreme_count = null_min_ps
        .iter()
        .filter(|&&min_p| min_p <= observed_min_p)
        .count();
    let sorted_min_ps = sorted_f64(null_min_ps);
    let adaptive_interval = wilson_95(
        adaptive_extreme_count
            .checked_add(1)
            .ok_or(DofNullError::TrialCountTooLarge)?,
        config
            .trials
            .checked_add(1)
            .ok_or(DofNullError::TrialCountTooLarge)?,
    );
    let effective_comparisons =
        median_effective_comparisons(sorted_quantile(&sorted_min_ps, Quantile::Median));
    let analytic_headline_bounds =
        analytic_headline_bounds(&cells, configured_cell_count, effective_comparisons);

    Ok(DofNullReport {
        config,
        configured_orders: space.orders.len(),
        configured_groupings: space.groupings.len(),
        configured_statistics: space.statistics.len(),
        configured_cell_count,
        valid_cell_count: cells.len(),
        skipped: prepared.skipped,
        cells,
        best_cell,
        observed_min_p,
        empirical_marginal_floor,
        adaptive_extreme_count,
        adaptive_interval,
        effective_comparisons,
        null_min_p_min: sorted_quantile(&sorted_min_ps, Quantile::Min),
        null_min_p_median: sorted_quantile(&sorted_min_ps, Quantile::Median),
        null_min_p_max: sorted_quantile(&sorted_min_ps, Quantile::Max),
        analytic_headline_bounds,
    })
}

fn configured_cell_count(space: &DofSearchSpace) -> Result<usize, DofNullError> {
    space
        .orders
        .len()
        .checked_mul(space.groupings.len())
        .and_then(|count| count.checked_mul(space.statistics.len()))
        .ok_or(DofNullError::SearchSpaceTooLarge)
}

fn empirical_marginal_floor(calibration_trials: usize) -> Result<f64, DofNullError> {
    let denominator = calibration_trials
        .checked_add(1)
        .ok_or(DofNullError::TrialCountTooLarge)?;
    Ok(1.0 / denominator as f64)
}

fn analytic_headline_bounds(
    cells: &[CellReport],
    total_configured_cells: usize,
    effective_comparisons: f64,
) -> Option<DofAnalyticHeadlineBounds> {
    let cell = cells
        .iter()
        .find(|cell| {
            cell.order == orders::accepted_honeycomb_order()
                && cell.grouping == (GroupingRule::OrientationBase5 { width: 3 })
                && cell.statistic == HeadlineStatistic::ContiguousBoundedAtMax
                && (cell.real_value - ANALYTIC_HEADLINE_CEILING).abs() <= f64::EPSILON
        })?
        .clone();
    let fixed = null::analytic_headline_bounds(1, cell.real_symbols);
    let total_comparisons = total_configured_cells as f64;
    Some(DofAnalyticHeadlineBounds {
        trigrams: cell.real_symbols,
        per_order: fixed.per_order,
        total_configured_cells,
        total_bonferroni: bonferroni_bound(fixed.per_order, total_comparisons),
        total_sidak: sidak_bound(fixed.per_order, total_comparisons),
        effective_comparisons,
        effective_bonferroni: bonferroni_bound(fixed.per_order, effective_comparisons),
        effective_sidak: sidak_bound(fixed.per_order, effective_comparisons),
        cell,
    })
}

fn bonferroni_bound(per_comparison: f64, comparisons: f64) -> f64 {
    if per_comparison <= 0.0 || comparisons <= 0.0 {
        0.0
    } else {
        (per_comparison * comparisons).min(1.0)
    }
}

fn sidak_bound(per_comparison: f64, comparisons: f64) -> f64 {
    if per_comparison <= 0.0 || comparisons <= 0.0 {
        0.0
    } else if per_comparison >= 1.0 {
        1.0
    } else {
        -f64::exp_m1(comparisons * f64::ln_1p(-per_comparison))
    }
}

fn validate_config(config: DofNullConfig, space: &DofSearchSpace) -> Result<(), DofNullError> {
    if config.calibration_trials == 0 {
        return Err(DofNullError::ZeroCalibrationTrials);
    }
    if config.trials == 0 {
        return Err(DofNullError::ZeroTrials);
    }
    if space.orders.is_empty() || space.groupings.is_empty() || space.statistics.is_empty() {
        return Err(DofNullError::EmptySearchSpace);
    }
    for grouping in &space.groupings {
        let _alphabet_size = alphabet_size(*grouping)?;
    }
    Ok(())
}

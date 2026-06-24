//! Calibrated researcher-degrees-of-freedom null for adaptive headline choice.
//!
//! Experiment 1B in [`crate::null`] asks a narrower question: after the
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
//! adaptive p-value is the fraction of random grids whose own minimum calibrated
//! p-value is at least as extreme.
//!
//! Important scope nuance: the standard36 honeycomb traversal is
//! data-independent, depending only on grid shape and fixed trigram-position
//! permutations. The genuinely new exposure being calibrated here is therefore
//! concentrated on grouping choice, headline-statistic choice, and the added
//! non-honeycomb traversal controls.

use crate::glyph::Orientation;
use crate::null::{SplitMix64, WilsonInterval, random_orientation_grids_like, wilson_95};
use crate::orders::{self, GlyphGrid, GridError, ReadingOrder};

const DEFAULT_DOF_NULL_SEED: u64 = 0x646f_666e_756c_6c00;
const DEFAULT_DOF_NULL_TRIALS: usize = 1_000;
const ORIENTATION_BASE: usize = 5;
const ENGINE_STORAGE_BASE: usize = 7;
const MAX_RECURRENCE_DISTANCE: usize = 6;

/// Configuration for the calibrated `DoF` null.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DofNullConfig {
    /// Explicit deterministic PRNG seed.
    pub seed: u64,
    /// Number of same-shape random corpora to sample.
    pub trials: usize,
}

impl Default for DofNullConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_DOF_NULL_SEED,
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
    /// The configured search space has an empty axis.
    EmptySearchSpace,
    /// No compatible `(traversal, grouping, statistic)` cells remained.
    NoValidCells,
    /// Orientation grouping width zero is invalid.
    ZeroGroupingWidth,
    /// The requested base-5 grouping alphabet cannot fit in [`crate::glyph::Glyph`].
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
}

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
    /// Number of random trials at least as extreme as the real statistic.
    pub marginal_extreme_count: usize,
    /// Rank-based empirical marginal tail probability of the real statistic.
    pub marginal_p: f64,
    /// Smallest sampled null statistic value.
    pub null_min: f64,
    /// Median sampled null statistic value.
    pub null_median: f64,
    /// Largest sampled null statistic value.
    pub null_max: f64,
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
    /// Count of random grids whose own min-p is at least as extreme.
    pub adaptive_extreme_count: usize,
    /// Wilson interval for the adaptive p-value.
    pub adaptive_interval: WilsonInterval,
    /// Sidak-equivalent independent comparisons from the null min-p median.
    pub effective_comparisons: f64,
    /// Smallest random-grid min-p sampled under the adaptive null.
    pub null_min_p_min: f64,
    /// Median random-grid min-p sampled under the adaptive null.
    pub null_min_p_median: f64,
    /// Largest random-grid min-p sampled under the adaptive null.
    pub null_min_p_max: f64,
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
    let prepared = prepare_cells(real_grids, space)?;
    if prepared.cells.is_empty() {
        return Err(DofNullError::NoValidCells);
    }

    let mut rng = SplitMix64::new(config.seed);
    let mut samples_by_cell = vec![Vec::with_capacity(config.trials); prepared.cells.len()];
    for _trial in 0..config.trials {
        let grids = generate(real_grids, &mut rng);
        push_trial_samples(&grids, space, &prepared.streams, &mut samples_by_cell)?;
    }

    let sorted_samples = sorted_samples_by_cell(&samples_by_cell);
    let cells = calibrated_cell_reports(&prepared.cells, &sorted_samples)?;
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
    let null_min_ps = random_grid_min_ps(&prepared.cells, &samples_by_cell, &sorted_samples);
    let adaptive_extreme_count = null_min_ps
        .iter()
        .filter(|&&min_p| min_p <= observed_min_p)
        .count();
    let sorted_min_ps = sorted_f64(null_min_ps);
    let adaptive_interval = wilson_95(adaptive_extreme_count, config.trials);
    let effective_comparisons =
        median_effective_comparisons(sorted_quantile(&sorted_min_ps, Quantile::Median));

    Ok(DofNullReport {
        config,
        configured_orders: space.orders.len(),
        configured_groupings: space.groupings.len(),
        configured_statistics: space.statistics.len(),
        valid_cell_count: cells.len(),
        skipped: prepared.skipped,
        cells,
        best_cell,
        observed_min_p,
        adaptive_extreme_count,
        adaptive_interval,
        effective_comparisons,
        null_min_p_min: sorted_quantile(&sorted_min_ps, Quantile::Min),
        null_min_p_median: sorted_quantile(&sorted_min_ps, Quantile::Median),
        null_min_p_max: sorted_quantile(&sorted_min_ps, Quantile::Max),
    })
}

fn validate_config(config: DofNullConfig, space: &DofSearchSpace) -> Result<(), DofNullError> {
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

#[derive(Clone, Debug)]
struct PreparedCells {
    streams: Vec<StreamDefinition>,
    cells: Vec<CellDefinition>,
    skipped: Vec<SkippedCombination>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StreamDefinition {
    order: ReadingOrder,
    grouping: GroupingRule,
}

#[derive(Clone, Debug, PartialEq)]
struct CellDefinition {
    order: ReadingOrder,
    grouping: GroupingRule,
    statistic: HeadlineStatistic,
    tail: TailDirection,
    alphabet_size: usize,
    real_symbols: usize,
    dropped_source_symbols: usize,
    real_value: f64,
}

fn prepare_cells(
    real_grids: &[GlyphGrid],
    space: &DofSearchSpace,
) -> Result<PreparedCells, DofNullError> {
    let mut streams = Vec::new();
    let mut cells = Vec::new();
    let mut skipped = Vec::new();

    for order in &space.orders {
        for grouping in &space.groupings {
            if is_engine_grouping_undefined(*order, *grouping) {
                skipped.push(SkippedCombination {
                    order: *order,
                    grouping: *grouping,
                    reason: "engine storage base-7 is defined only on raw stored rows".to_owned(),
                });
                continue;
            }
            match grouped_messages(real_grids, *order, *grouping) {
                Ok(grouped) if grouped.symbols == 0 => {
                    skipped.push(SkippedCombination {
                        order: *order,
                        grouping: *grouping,
                        reason: "grouping produced no complete symbols".to_owned(),
                    });
                }
                Ok(grouped) => {
                    let metrics = MetricSummary::from_messages(&grouped.messages);
                    streams.push(StreamDefinition {
                        order: *order,
                        grouping: *grouping,
                    });
                    for statistic in &space.statistics {
                        cells.push(CellDefinition {
                            order: *order,
                            grouping: *grouping,
                            statistic: *statistic,
                            tail: statistic.tail(),
                            alphabet_size: grouped.alphabet_size,
                            real_symbols: grouped.symbols,
                            dropped_source_symbols: grouped.dropped_source_symbols,
                            real_value: metrics.value(*statistic, grouped.alphabet_size),
                        });
                    }
                }
                Err(DofNullError::Grid(error)) => {
                    skipped.push(SkippedCombination {
                        order: *order,
                        grouping: *grouping,
                        reason: format!("grid/order incompatibility: {error:?}"),
                    });
                }
                Err(error) => return Err(error),
            }
        }
    }

    Ok(PreparedCells {
        streams,
        cells,
        skipped,
    })
}

fn is_engine_grouping_undefined(order: ReadingOrder, grouping: GroupingRule) -> bool {
    grouping == GroupingRule::EngineStorageBase7 && order != ReadingOrder::RawRows
}

fn push_trial_samples(
    grids: &[GlyphGrid],
    space: &DofSearchSpace,
    streams: &[StreamDefinition],
    samples_by_cell: &mut [Vec<f64>],
) -> Result<(), DofNullError> {
    let mut cell_index = 0usize;
    for stream in streams {
        let grouped = grouped_messages(grids, stream.order, stream.grouping)?;
        let metrics = MetricSummary::from_messages(&grouped.messages);
        for statistic in &space.statistics {
            let value = metrics.value(*statistic, grouped.alphabet_size);
            let Some(samples) = samples_by_cell.get_mut(cell_index) else {
                return Err(DofNullError::InternalCellMismatch {
                    expected: samples_by_cell.len(),
                    observed: cell_index,
                });
            };
            samples.push(value);
            cell_index += 1;
        }
    }
    if cell_index != samples_by_cell.len() {
        return Err(DofNullError::InternalCellMismatch {
            expected: samples_by_cell.len(),
            observed: cell_index,
        });
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct GroupedMessages {
    messages: Vec<Vec<u16>>,
    symbols: usize,
    dropped_source_symbols: usize,
    alphabet_size: usize,
}

fn grouped_messages(
    grids: &[GlyphGrid],
    order: ReadingOrder,
    grouping: GroupingRule,
) -> Result<GroupedMessages, DofNullError> {
    match grouping {
        GroupingRule::OrientationBase5 { width } => {
            let alphabet_size = alphabet_size(grouping)?;
            let orientation_messages = orders::read_corpus_message_orientations(grids, order)?;
            grouped_orientation_messages(&orientation_messages, width, alphabet_size)
        }
        GroupingRule::EngineStorageBase7 => Ok(storage_symbol_messages(grids)),
    }
}

fn grouped_orientation_messages(
    orientation_messages: &[Vec<Orientation>],
    width: usize,
    alphabet_size: usize,
) -> Result<GroupedMessages, DofNullError> {
    let mut messages = Vec::new();
    let mut dropped_source_symbols = 0usize;
    let mut symbols = 0usize;
    for orientations in orientation_messages {
        let mut message = Vec::new();
        for chunk in orientations.chunks_exact(width) {
            message.push(group_value(chunk)?);
        }
        dropped_source_symbols += orientations.len() % width;
        symbols += message.len();
        messages.push(message);
    }
    Ok(GroupedMessages {
        messages,
        symbols,
        dropped_source_symbols,
        alphabet_size,
    })
}

fn storage_symbol_messages(grids: &[GlyphGrid]) -> GroupedMessages {
    let mut messages = Vec::new();
    let mut symbols = 0usize;
    for grid in grids {
        let mut message = Vec::new();
        for row in grid.orientation_rows() {
            for orientation in row {
                message.push(u16::from(orientation.digit()));
            }
            message.push(5);
        }
        symbols += message.len();
        messages.push(message);
    }
    GroupedMessages {
        messages,
        symbols,
        dropped_source_symbols: 0,
        alphabet_size: ENGINE_STORAGE_BASE,
    }
}

fn group_value(chunk: &[Orientation]) -> Result<u16, DofNullError> {
    let mut value = 0usize;
    for orientation in chunk {
        value = value
            .saturating_mul(ORIENTATION_BASE)
            .saturating_add(usize::from(orientation.digit()));
    }
    u16::try_from(value)
        .map_err(|_error| DofNullError::GroupingAlphabetTooLarge { width: chunk.len() })
}

fn alphabet_size(grouping: GroupingRule) -> Result<usize, DofNullError> {
    match grouping {
        GroupingRule::OrientationBase5 { width } => orientation_alphabet_size(width),
        GroupingRule::EngineStorageBase7 => Ok(ENGINE_STORAGE_BASE),
    }
}

fn orientation_alphabet_size(width: usize) -> Result<usize, DofNullError> {
    if width == 0 {
        return Err(DofNullError::ZeroGroupingWidth);
    }
    let mut value = 1usize;
    for _digit in 0..width {
        value = value
            .checked_mul(ORIENTATION_BASE)
            .ok_or(DofNullError::GroupingAlphabetTooLarge { width })?;
    }
    if value > usize::from(u16::MAX) + 1 {
        return Err(DofNullError::GroupingAlphabetTooLarge { width });
    }
    Ok(value)
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct MetricSummary {
    distinct: usize,
    min: Option<u16>,
    max: Option<u16>,
    contiguous_zero_based: bool,
    adjacent_equal: usize,
    adjacent_comparisons: usize,
    recurrence_distance_1_to_6: [usize; MAX_RECURRENCE_DISTANCE],
}

impl MetricSummary {
    fn from_messages(messages: &[Vec<u16>]) -> Self {
        let mut seen = Vec::new();
        let mut distinct = 0usize;
        let mut min = None;
        let mut max = None;
        let mut adjacent_equal = 0usize;
        let mut adjacent_comparisons = 0usize;
        let mut recurrence_distance_1_to_6 = [0usize; MAX_RECURRENCE_DISTANCE];

        for message in messages {
            for &symbol in message {
                let symbol_index = usize::from(symbol);
                if symbol_index >= seen.len() {
                    seen.resize(symbol_index.saturating_add(1), false);
                }
                if let Some(slot) = seen.get_mut(symbol_index)
                    && !*slot
                {
                    *slot = true;
                    distinct += 1;
                    min = Some(min.map_or(symbol, |current: u16| current.min(symbol)));
                    max = Some(max.map_or(symbol, |current: u16| current.max(symbol)));
                }
            }
            adjacent_equal += count_adjacent_equal(message);
            adjacent_comparisons += message.len().saturating_sub(1);
            add_recurrence(message, &mut recurrence_distance_1_to_6);
        }

        let contiguous_zero_based = min == Some(0)
            && max.is_some_and(|high| usize::from(high).saturating_add(1) == distinct);
        Self {
            distinct,
            min,
            max,
            contiguous_zero_based,
            adjacent_equal,
            adjacent_comparisons,
            recurrence_distance_1_to_6,
        }
    }

    fn value(self, statistic: HeadlineStatistic, alphabet_size: usize) -> f64 {
        match statistic {
            HeadlineStatistic::DistinctCount => self.distinct as f64,
            HeadlineStatistic::ContiguousBoundedAtMax => self.contiguous_ceiling(alphabet_size),
            HeadlineStatistic::ZeroAdjacencyRate => self.adjacent_equal_rate(),
            HeadlineStatistic::BestRecurrenceRatio => self.best_recurrence_ratio(),
        }
    }

    fn contiguous_ceiling(self, alphabet_size: usize) -> f64 {
        if self.contiguous_zero_based {
            self.max.map_or(alphabet_size as f64, f64::from)
        } else {
            alphabet_size as f64
        }
    }

    fn adjacent_equal_rate(self) -> f64 {
        if self.adjacent_comparisons == 0 {
            0.0
        } else {
            self.adjacent_equal as f64 / self.adjacent_comparisons as f64
        }
    }

    fn best_recurrence_ratio(self) -> f64 {
        let total: usize = self.recurrence_distance_1_to_6.iter().sum();
        if total == 0 {
            return 0.0;
        }
        let mean = total as f64 / MAX_RECURRENCE_DISTANCE as f64;
        self.recurrence_distance_1_to_6
            .iter()
            .copied()
            .map(|count| count as f64 / mean)
            .fold(0.0, f64::max)
    }
}

fn count_adjacent_equal(message: &[u16]) -> usize {
    message
        .windows(2)
        .filter(|window| matches!(window, [left, right] if left == right))
        .count()
}

fn add_recurrence(message: &[u16], recurrence: &mut [usize; MAX_RECURRENCE_DISTANCE]) {
    let mut previous_positions = Vec::new();
    for (position, &symbol) in message.iter().enumerate() {
        let symbol_index = usize::from(symbol);
        if symbol_index >= previous_positions.len() {
            previous_positions.resize(symbol_index.saturating_add(1), None);
        }
        if let Some(slot) = previous_positions.get_mut(symbol_index) {
            if let Some(previous) = *slot {
                let distance = position - previous;
                if (1..=MAX_RECURRENCE_DISTANCE).contains(&distance)
                    && let Some(count) = recurrence.get_mut(distance - 1)
                {
                    *count += 1;
                }
            }
            *slot = Some(position);
        }
    }
}

fn sorted_samples_by_cell(samples_by_cell: &[Vec<f64>]) -> Vec<Vec<f64>> {
    samples_by_cell
        .iter()
        .map(|samples| sorted_f64(samples.clone()))
        .collect()
}

fn calibrated_cell_reports(
    cells: &[CellDefinition],
    sorted_samples: &[Vec<f64>],
) -> Result<Vec<CellReport>, DofNullError> {
    let mut reports = Vec::new();
    for (cell, samples) in cells.iter().zip(sorted_samples) {
        let marginal_extreme_count = extreme_count(samples, cell.real_value, cell.tail);
        let marginal_p = empirical_tail_probability(samples, cell.real_value, cell.tail);
        reports.push(CellReport {
            order: cell.order,
            grouping: cell.grouping,
            statistic: cell.statistic,
            tail: cell.tail,
            alphabet_size: cell.alphabet_size,
            real_symbols: cell.real_symbols,
            dropped_source_symbols: cell.dropped_source_symbols,
            real_value: cell.real_value,
            marginal_extreme_count,
            marginal_p,
            null_min: sorted_quantile(samples, Quantile::Min),
            null_median: sorted_quantile(samples, Quantile::Median),
            null_max: sorted_quantile(samples, Quantile::Max),
        });
    }
    if reports.len() != cells.len() {
        return Err(DofNullError::InternalCellMismatch {
            expected: cells.len(),
            observed: reports.len(),
        });
    }
    Ok(reports)
}

fn random_grid_min_ps(
    cells: &[CellDefinition],
    samples_by_cell: &[Vec<f64>],
    sorted_samples: &[Vec<f64>],
) -> Vec<f64> {
    let trials = samples_by_cell.first().map_or(0usize, std::vec::Vec::len);
    let mut min_ps = vec![1.0; trials];
    for ((cell, raw_samples), sorted) in cells.iter().zip(samples_by_cell).zip(sorted_samples) {
        for (min_p, &value) in min_ps.iter_mut().zip(raw_samples) {
            let p = empirical_tail_probability(sorted, value, cell.tail);
            *min_p = f64::min(*min_p, p);
        }
    }
    min_ps
}

fn empirical_tail_probability(sorted_samples: &[f64], value: f64, tail: TailDirection) -> f64 {
    let count = extreme_count(sorted_samples, value, tail);
    (count.saturating_add(1)) as f64 / (sorted_samples.len().saturating_add(1)) as f64
}

fn extreme_count(sorted_samples: &[f64], value: f64, tail: TailDirection) -> usize {
    match tail {
        TailDirection::Low => sorted_samples.partition_point(|sample| *sample <= value),
        TailDirection::High => {
            let below = sorted_samples.partition_point(|sample| *sample < value);
            sorted_samples.len().saturating_sub(below)
        }
    }
}

fn median_effective_comparisons(null_min_p_median: f64) -> f64 {
    if !(0.0..1.0).contains(&null_min_p_median) {
        return 0.0;
    }
    let denominator = f64::ln_1p(-null_min_p_median);
    if denominator.abs() < f64::EPSILON {
        0.0
    } else {
        f64::ln(0.5) / denominator
    }
}

fn sorted_f64(mut values: Vec<f64>) -> Vec<f64> {
    values.sort_by(f64::total_cmp);
    values
}

#[derive(Clone, Copy)]
enum Quantile {
    Min,
    Median,
    Max,
}

fn sorted_quantile(sorted: &[f64], quantile: Quantile) -> f64 {
    match quantile {
        Quantile::Min => sorted.first().copied().unwrap_or(0.0),
        Quantile::Median => median(sorted),
        Quantile::Max => sorted.last().copied().unwrap_or(0.0),
    }
}

fn median(sorted: &[f64]) -> f64 {
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
            (Some(left), Some(right)) => f64::midpoint(left, right),
            _ => 0.0,
        }
    } else {
        sorted.get(middle).copied().unwrap_or(0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DofNullConfig, DofSearchSpace, GroupingRule, HeadlineStatistic, run_dof_null_for_grids,
        run_dof_null_with,
    };
    use crate::glyph::Orientation;
    use crate::null::{SplitMix64, random_orientation_grids_like};
    use crate::orders::{GlyphGrid, ReadingOrder};

    fn row(digits: &[u8]) -> Vec<Orientation> {
        digits
            .iter()
            .copied()
            .map(|digit| Orientation::from_digit(digit).unwrap())
            .collect()
    }

    fn one_row_grid(digits: &[u8]) -> Vec<GlyphGrid> {
        vec![GlyphGrid::from_orientation_rows("toy", vec![row(digits)])]
    }

    fn one_cell_space(statistic: HeadlineStatistic) -> DofSearchSpace {
        DofSearchSpace {
            orders: vec![ReadingOrder::RawRows],
            groupings: vec![GroupingRule::OrientationBase5 { width: 1 }],
            statistics: vec![statistic],
        }
    }

    #[test]
    fn planted_structure_positive_control_has_small_adaptive_p() {
        let real = one_row_grid(&[0; 60]);
        let config = DofNullConfig {
            seed: 0x51a1,
            trials: 64,
        };
        let report = run_dof_null_for_grids(
            config,
            &real,
            &one_cell_space(HeadlineStatistic::DistinctCount),
        )
        .unwrap();

        assert!(report.observed_min_p < 0.05);
        assert!(report.adaptive_interval.estimate < 0.05);
        assert_eq!(report.adaptive_extreme_count, 0);
    }

    #[test]
    fn uniform_random_negative_control_is_not_significant() {
        let template = one_row_grid(&[0; 60]);
        let mut rng = SplitMix64::new(0xdecaf);
        let real = random_orientation_grids_like(&template, &mut rng);
        let config = DofNullConfig {
            seed: 0x000d_ecaf_0001,
            trials: 64,
        };
        let report = run_dof_null_for_grids(
            config,
            &real,
            &one_cell_space(HeadlineStatistic::DistinctCount),
        )
        .unwrap();

        assert!(report.observed_min_p > 0.50);
        assert!(report.adaptive_interval.estimate > 0.50);
    }

    #[test]
    fn marginal_tails_are_probabilities_on_default_space() {
        let real = one_row_grid(&[0, 0, 0, 1, 1, 2, 3, 4]);
        let config = DofNullConfig {
            seed: 0x7072_6f62,
            trials: 16,
        };
        let space = DofSearchSpace {
            orders: vec![ReadingOrder::RawRows],
            groupings: vec![
                GroupingRule::OrientationBase5 { width: 1 },
                GroupingRule::OrientationBase5 { width: 2 },
            ],
            statistics: vec![
                HeadlineStatistic::DistinctCount,
                HeadlineStatistic::ContiguousBoundedAtMax,
                HeadlineStatistic::ZeroAdjacencyRate,
                HeadlineStatistic::BestRecurrenceRatio,
            ],
        };
        let report = run_dof_null_for_grids(config, &real, &space).unwrap();

        for cell in &report.cells {
            assert!((0.0..=1.0).contains(&cell.marginal_p));
        }
        assert!((0.0..=1.0).contains(&report.observed_min_p));
        assert!((0.0..=1.0).contains(&report.adaptive_interval.estimate));
    }

    #[test]
    fn min_p_matches_hand_checked_toy_case() {
        let real = one_row_grid(&[0, 0, 0]);
        let nulls = [
            one_row_grid(&[0, 1, 2]),
            one_row_grid(&[0, 0, 1]),
            one_row_grid(&[2, 2, 2]),
        ];
        let mut index = 0usize;
        let config = DofNullConfig {
            seed: 0,
            trials: nulls.len(),
        };
        let report = run_dof_null_with(
            config,
            &real,
            &one_cell_space(HeadlineStatistic::DistinctCount),
            |_templates, _rng| {
                let grids = nulls.get(index).cloned().unwrap();
                index += 1;
                grids
            },
        )
        .unwrap();

        assert!((report.best_cell.real_value - 1.0).abs() < f64::EPSILON);
        assert_eq!(report.best_cell.marginal_extreme_count, 1);
        assert!((report.observed_min_p - 0.5).abs() < f64::EPSILON);
        assert_eq!(report.adaptive_extreme_count, 1);
        assert!((report.adaptive_interval.estimate - (1.0 / 3.0)).abs() < f64::EPSILON);
    }
}

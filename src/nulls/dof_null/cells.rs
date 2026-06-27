use super::{
    CellReport, DofNullError, DofSearchSpace, ENGINE_STORAGE_BASE, GroupingRule, HeadlineStatistic,
    MAX_RECURRENCE_DISTANCE, ORIENTATION_BASE, SkippedCombination, TailDirection,
};
use crate::analysis::orders::{self, GlyphGrid, ReadingOrder};
use crate::core::glyph::Orientation;
use crate::nulls::null::{SplitMix64, median_f64};

pub(super) fn sample_statistics_by_cell(
    trials: usize,
    templates: &[GlyphGrid],
    space: &DofSearchSpace,
    streams: &[StreamDefinition],
    cell_count: usize,
    rng: &mut SplitMix64,
    generate: &mut impl FnMut(&[GlyphGrid], &mut SplitMix64) -> Vec<GlyphGrid>,
) -> Result<Vec<Vec<f64>>, DofNullError> {
    let mut samples_by_cell = (0..cell_count)
        .map(|_cell| Vec::with_capacity(trials))
        .collect::<Vec<_>>();
    for _trial in 0..trials {
        let grids = generate(templates, rng);
        push_trial_samples(&grids, space, streams, &mut samples_by_cell)?;
    }
    Ok(samples_by_cell)
}

#[derive(Clone, Debug)]
pub(super) struct PreparedCells {
    pub(super) streams: Vec<StreamDefinition>,
    pub(super) cells: Vec<CellDefinition>,
    pub(super) skipped: Vec<SkippedCombination>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct StreamDefinition {
    order: ReadingOrder,
    grouping: GroupingRule,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct CellDefinition {
    order: ReadingOrder,
    grouping: GroupingRule,
    statistic: HeadlineStatistic,
    tail: TailDirection,
    alphabet_size: usize,
    real_symbols: usize,
    dropped_source_symbols: usize,
    real_value: f64,
}

pub(super) fn prepare_cells(
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

pub(super) fn alphabet_size(grouping: GroupingRule) -> Result<usize, DofNullError> {
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

pub(super) fn sorted_samples_by_cell(samples_by_cell: &[Vec<f64>]) -> Vec<Vec<f64>> {
    samples_by_cell
        .iter()
        .map(|samples| sorted_f64(samples.clone()))
        .collect()
}

pub(super) fn calibrated_cell_reports(
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

pub(super) fn calibrated_sample_min_ps(
    cells: &[CellDefinition],
    samples_by_cell: &[Vec<f64>],
    sorted_calibration_samples: &[Vec<f64>],
) -> Result<Vec<f64>, DofNullError> {
    if samples_by_cell.len() != cells.len() {
        return Err(DofNullError::InternalCellMismatch {
            expected: cells.len(),
            observed: samples_by_cell.len(),
        });
    }
    if sorted_calibration_samples.len() != cells.len() {
        return Err(DofNullError::InternalCellMismatch {
            expected: cells.len(),
            observed: sorted_calibration_samples.len(),
        });
    }
    let trials = samples_by_cell.first().map_or(0usize, std::vec::Vec::len);
    let mut min_ps = vec![1.0; trials];
    for ((cell, raw_samples), sorted) in cells
        .iter()
        .zip(samples_by_cell)
        .zip(sorted_calibration_samples)
    {
        if raw_samples.len() != trials {
            return Err(DofNullError::InternalCellMismatch {
                expected: trials,
                observed: raw_samples.len(),
            });
        }
        for (min_p, &value) in min_ps.iter_mut().zip(raw_samples) {
            let p = empirical_tail_probability(sorted, value, cell.tail);
            *min_p = f64::min(*min_p, p);
        }
    }
    Ok(min_ps)
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

pub(super) fn median_effective_comparisons(null_min_p_median: f64) -> f64 {
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

pub(super) fn sorted_f64(mut values: Vec<f64>) -> Vec<f64> {
    values.sort_by(f64::total_cmp);
    values
}

#[derive(Clone, Copy)]
pub(super) enum Quantile {
    Min,
    Median,
    Max,
}

pub(super) fn sorted_quantile(sorted: &[f64], quantile: Quantile) -> f64 {
    match quantile {
        Quantile::Min => sorted.first().copied().unwrap_or(0.0),
        Quantile::Median => median_f64(sorted),
        Quantile::Max => sorted.last().copied().unwrap_or(0.0),
    }
}

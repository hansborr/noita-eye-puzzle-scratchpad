//! Reading-order experiments over the verified eye-message grids.
//!
//! This module reconstructs the rendered two-dimensional glyph grids by
//! splitting corpus strings on the non-rendered `5` row delimiter, then reads
//! those grids under documented order families.
//!
//! The community phrase "36 standard reading orders" is easy to misread. The
//! `ToboterXP` reference brute-forcer in `archive/eyeGlyphs-trigram order
//! bruteforce.py` does not generate 36 different grid walks. It starts from a
//! fixed interlocking-triangle honeycomb walk, then tries all six permutations
//! of the three digits for one triangle parity and all six permutations for
//! the other parity. [`standard36_orders`] implements that exact fixed-walk,
//! `6 * 6` permutation family. Linear row/column controls are exposed
//! separately and are not counted as part of the standard 36.

use std::collections::{BTreeMap, BTreeSet};

use crate::corpus::{CorpusError, Message, messages};
use crate::glyph::Orientation;
use crate::trigram::{ReadingTrigram, TrigramValue};

/// Error returned when a rendered message cannot be treated as a grid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GridError {
    /// The underlying corpus digits were malformed.
    Corpus(CorpusError),
    /// A row delimiter produced an empty row before the final trailing position.
    EmptyInteriorRow {
        /// The message whose grid failed.
        message_key: &'static str,
    },
    /// The interlocking-triangle walk requires rows to be processed in pairs.
    OddRowCount {
        /// The message whose grid failed.
        message_key: &'static str,
        /// Number of reconstructed rows.
        rows: usize,
    },
    /// A requested coordinate did not exist in the ragged row grid.
    MissingCell {
        /// The message whose grid failed.
        message_key: &'static str,
        /// Zero-based row.
        row: usize,
        /// Zero-based column.
        column: usize,
    },
    /// A walk produced a non-trigram-divisible number of rendered digits.
    IncompleteTrigram {
        /// The reading order that failed.
        order: ReadingOrder,
        /// Number of rendered digits produced by the walk.
        digits: usize,
    },
}

impl From<CorpusError> for GridError {
    fn from(value: CorpusError) -> Self {
        Self::Corpus(value)
    }
}

/// One verified message reconstructed as rendered rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlyphGrid {
    message_key: &'static str,
    rows: Vec<Vec<Orientation>>,
}

impl GlyphGrid {
    /// Reconstructs one message grid by splitting on delimiter digit `5`.
    ///
    /// A final trailing delimiter is allowed and does not create an extra row.
    ///
    /// # Errors
    /// Returns [`GridError`] if the corpus digits are malformed or if an
    /// interior delimiter would create an empty row.
    pub fn from_message(message: &Message) -> Result<Self, GridError> {
        let mut rows = Vec::new();
        let mut current = Vec::new();
        for symbol in message.rendered_symbols()? {
            match symbol {
                crate::glyph::RenderedSymbol::Orientation(orientation) => {
                    current.push(orientation);
                }
                crate::glyph::RenderedSymbol::RowDelimiter => {
                    if current.is_empty() {
                        return Err(GridError::EmptyInteriorRow {
                            message_key: message.key,
                        });
                    }
                    rows.push(current);
                    current = Vec::new();
                }
            }
        }
        if !current.is_empty() {
            rows.push(current);
        }
        Ok(Self {
            message_key: message.key,
            rows,
        })
    }

    /// Builds a grid from already-rendered orientation rows.
    ///
    /// This is primarily for structure-matched null corpora: callers preserve
    /// the verified row widths while replacing the cell contents.
    #[must_use]
    pub fn from_orientation_rows(message_key: &'static str, rows: Vec<Vec<Orientation>>) -> Self {
        Self { message_key, rows }
    }

    /// Message key for this grid.
    #[must_use]
    pub const fn message_key(&self) -> &'static str {
        self.message_key
    }

    /// Number of reconstructed rows.
    #[must_use]
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Width of each reconstructed row.
    #[must_use]
    pub fn row_widths(&self) -> Vec<usize> {
        self.rows.iter().map(Vec::len).collect()
    }

    /// Number of rendered orientation digits in the grid.
    #[must_use]
    pub fn eye_count(&self) -> usize {
        self.rows.iter().map(Vec::len).sum()
    }

    /// Maximum row width in this grid.
    #[must_use]
    pub fn max_width(&self) -> usize {
        self.rows.iter().map(Vec::len).max().unwrap_or_default()
    }

    fn cell(&self, row: usize, column: usize) -> Result<Orientation, GridError> {
        self.rows
            .get(row)
            .and_then(|cells| cells.get(column))
            .copied()
            .ok_or(GridError::MissingCell {
                message_key: self.message_key,
                row,
                column,
            })
    }
}

/// Row-width summary across the verified grids.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GridSummary {
    /// Per-message row widths, in corpus message order.
    pub row_widths: Vec<(&'static str, Vec<usize>)>,
    /// Largest observed row width.
    pub max_width: usize,
    /// Whether every message's bottom two rows differ by at most one eye.
    pub bottom_two_rows_differ_by_at_most_one: bool,
}

/// Reconstructs all verified message grids in corpus order.
///
/// # Errors
/// Returns [`GridError`] if any message cannot be reconstructed.
pub fn corpus_grids() -> Result<Vec<GlyphGrid>, GridError> {
    let mut grids = Vec::new();
    for message in messages() {
        grids.push(GlyphGrid::from_message(message)?);
    }
    Ok(grids)
}

/// Summarizes row widths across all verified corpus grids.
#[must_use]
pub fn summarize_grids(grids: &[GlyphGrid]) -> GridSummary {
    let mut row_widths = Vec::new();
    let mut max_width = 0;
    let mut bottom_ok = true;
    for grid in grids {
        let widths = grid.row_widths();
        if let Some(width) = widths.iter().copied().max() {
            max_width = max_width.max(width);
        }
        let bottom_delta = bottom_row_delta(&widths);
        if bottom_delta.is_some_and(|delta| delta > 1) {
            bottom_ok = false;
        }
        row_widths.push((grid.message_key(), widths));
    }
    GridSummary {
        row_widths,
        max_width,
        bottom_two_rows_differ_by_at_most_one: bottom_ok,
    }
}

fn bottom_row_delta(widths: &[usize]) -> Option<usize> {
    let last = widths.last().copied()?;
    let previous = widths.iter().rev().nth(1).copied()?;
    Some(last.abs_diff(previous))
}

/// Direction for row, column, or row-pair traversal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    /// Increasing row or column index.
    Forward,
    /// Decreasing row or column index.
    Reverse,
}

impl Direction {
    fn ordered_indices(self, len: usize) -> Vec<usize> {
        let iter = 0..len;
        match self {
            Self::Forward => iter.collect(),
            Self::Reverse => iter.rev().collect(),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Forward => "fwd",
            Self::Reverse => "rev",
        }
    }
}

/// Within-line direction behavior for linear controls.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LineMode {
    /// Every row or column is read left-to-right / top-to-bottom.
    Straight,
    /// Odd-positioned rows or columns reverse their local direction.
    Boustrophedon,
}

impl LineMode {
    fn name(self) -> &'static str {
        match self {
            Self::Straight => "straight",
            Self::Boustrophedon => "boustro",
        }
    }
}

/// A permutation of the three rendered digits inside one trigram.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrigramPermutation {
    order: [usize; 3],
}

impl TrigramPermutation {
    /// Identity trigram digit order.
    pub const IDENTITY: Self = Self { order: [0, 1, 2] };

    /// All six trigram digit permutations in lexical order.
    pub const ALL: [Self; 6] = [
        Self { order: [0, 1, 2] },
        Self { order: [0, 2, 1] },
        Self { order: [1, 0, 2] },
        Self { order: [1, 2, 0] },
        Self { order: [2, 0, 1] },
        Self { order: [2, 1, 0] },
    ];

    /// Returns the permutation as zero-based source positions.
    #[must_use]
    pub const fn positions(self) -> [usize; 3] {
        self.order
    }

    fn apply(self, tri: [Orientation; 3]) -> [Orientation; 3] {
        let [first, second, third] = tri;
        let source = [first, second, third];
        let [first_position, second_position, third_position] = self.order;
        [
            orientation_at(source, first_position),
            orientation_at(source, second_position),
            orientation_at(source, third_position),
        ]
    }

    fn name(self) -> String {
        let [a, b, c] = self.order;
        format!("{a}{b}{c}")
    }
}

fn orientation_at(source: [Orientation; 3], index: usize) -> Orientation {
    let [first, second, third] = source;
    match index {
        0 => first,
        1 => second,
        _ => third,
    }
}

/// A documented reading order over a reconstructed grid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReadingOrder {
    /// Stored row order with delimiters stripped, then grouped into trigrams.
    RawRows,
    /// Row-major linear control.
    RowMajor {
        /// Row traversal order.
        rows: Direction,
        /// Direction within the first row.
        columns: Direction,
        /// Whether alternate rows reverse local direction.
        mode: LineMode,
    },
    /// Column-major linear control over ragged rows.
    ColumnMajor {
        /// Column traversal order.
        columns: Direction,
        /// Direction within the first column.
        rows: Direction,
        /// Whether alternate columns reverse local direction.
        mode: LineMode,
    },
    /// The fixed honeycomb walk used by `ToboterXP`, with independent
    /// permutations for the two alternating triangle shapes.
    HoneycombStandard {
        /// Permutation for the first triangle shape in each row pair.
        upper: TrigramPermutation,
        /// Permutation for the second triangle shape in each row pair.
        lower: TrigramPermutation,
    },
}

impl ReadingOrder {
    /// Stable machine-readable order name for CLI output and regression tests.
    #[must_use]
    pub fn name(self) -> String {
        match self {
            Self::RawRows => "raw-rows".to_owned(),
            Self::RowMajor {
                rows,
                columns,
                mode,
            } => format!("row-{}-{}-{}", rows.name(), columns.name(), mode.name()),
            Self::ColumnMajor {
                columns,
                rows,
                mode,
            } => format!("col-{}-{}-{}", columns.name(), rows.name(), mode.name()),
            Self::HoneycombStandard { upper, lower } => {
                format!("standard36-u{}-d{}", upper.name(), lower.name())
            }
        }
    }
}

/// Returns the exact Toboter-style `6 * 6` standard honeycomb family.
#[must_use]
pub fn standard36_orders() -> Vec<ReadingOrder> {
    let mut orders = Vec::new();
    for upper in TrigramPermutation::ALL {
        for lower in TrigramPermutation::ALL {
            orders.push(ReadingOrder::HoneycombStandard { upper, lower });
        }
    }
    orders
}

/// Returns supplemental linear controls plus the standard 36 family.
#[must_use]
pub fn audit_orders() -> Vec<ReadingOrder> {
    let mut orders = Vec::new();
    orders.push(ReadingOrder::RawRows);
    for rows in [Direction::Forward, Direction::Reverse] {
        for columns in [Direction::Forward, Direction::Reverse] {
            for mode in [LineMode::Straight, LineMode::Boustrophedon] {
                orders.push(ReadingOrder::RowMajor {
                    rows,
                    columns,
                    mode,
                });
            }
        }
    }
    for columns in [Direction::Forward, Direction::Reverse] {
        for rows in [Direction::Forward, Direction::Reverse] {
            for mode in [LineMode::Straight, LineMode::Boustrophedon] {
                orders.push(ReadingOrder::ColumnMajor {
                    columns,
                    rows,
                    mode,
                });
            }
        }
    }
    orders.extend(standard36_orders());
    orders
}

/// Reads all grids with one order and returns the combined trigram value stream.
///
/// # Errors
/// Returns [`GridError`] if the order is incompatible with any grid shape.
pub fn read_corpus_values(
    grids: &[GlyphGrid],
    order: ReadingOrder,
) -> Result<Vec<TrigramValue>, GridError> {
    let mut values = Vec::new();
    for mut local in read_corpus_message_values(grids, order)? {
        values.append(&mut local);
    }
    Ok(values)
}

/// Reads all grids with one order, preserving message boundaries.
///
/// Distinct/range statistics are normally computed over the flattened stream,
/// while recurrence statistics are summed per message so artificial joins
/// between unrelated messages do not create extra repeats.
///
/// # Errors
/// Returns [`GridError`] if the order is incompatible with any grid shape.
pub fn read_corpus_message_values(
    grids: &[GlyphGrid],
    order: ReadingOrder,
) -> Result<Vec<Vec<TrigramValue>>, GridError> {
    let mut values = Vec::new();
    for grid in grids {
        values.push(read_grid_values(grid, order)?);
    }
    Ok(values)
}

/// Reads one grid with one order and returns its trigram values.
///
/// # Errors
/// Returns [`GridError`] if the order is incompatible with the grid shape.
pub fn read_grid_values(
    grid: &GlyphGrid,
    order: ReadingOrder,
) -> Result<Vec<TrigramValue>, GridError> {
    match order {
        ReadingOrder::HoneycombStandard { upper, lower } => {
            read_honeycomb_values(grid, order, upper, lower)
        }
        _ => digits_to_values(read_grid_digits(grid, order)?, order),
    }
}

fn read_grid_digits(grid: &GlyphGrid, order: ReadingOrder) -> Result<Vec<Orientation>, GridError> {
    match order {
        ReadingOrder::RawRows => Ok(grid.rows.iter().flatten().copied().collect()),
        ReadingOrder::RowMajor {
            rows,
            columns,
            mode,
        } => read_row_major_digits(grid, rows, columns, mode),
        ReadingOrder::ColumnMajor {
            columns,
            rows,
            mode,
        } => read_column_major_digits(grid, columns, rows, mode),
        ReadingOrder::HoneycombStandard { .. } => Ok(Vec::new()),
    }
}

fn read_row_major_digits(
    grid: &GlyphGrid,
    rows: Direction,
    columns: Direction,
    mode: LineMode,
) -> Result<Vec<Orientation>, GridError> {
    let mut out = Vec::new();
    for (line_index, row) in rows
        .ordered_indices(grid.row_count())
        .into_iter()
        .enumerate()
    {
        let width = grid.rows.get(row).map_or(0, Vec::len);
        let local_columns = line_indices(width, columns, mode, line_index);
        for column in local_columns {
            out.push(grid.cell(row, column)?);
        }
    }
    Ok(out)
}

fn read_column_major_digits(
    grid: &GlyphGrid,
    columns: Direction,
    rows: Direction,
    mode: LineMode,
) -> Result<Vec<Orientation>, GridError> {
    let mut out = Vec::new();
    for (line_index, column) in columns
        .ordered_indices(grid.max_width())
        .into_iter()
        .enumerate()
    {
        let local_rows = line_indices(grid.row_count(), rows, mode, line_index);
        for row in local_rows {
            if grid.rows.get(row).is_some_and(|cells| column < cells.len()) {
                out.push(grid.cell(row, column)?);
            }
        }
    }
    Ok(out)
}

fn line_indices(
    len: usize,
    base_direction: Direction,
    mode: LineMode,
    line_index: usize,
) -> Vec<usize> {
    let reverse_for_boustro = mode == LineMode::Boustrophedon && line_index % 2 == 1;
    let direction = if reverse_for_boustro {
        match base_direction {
            Direction::Forward => Direction::Reverse,
            Direction::Reverse => Direction::Forward,
        }
    } else {
        base_direction
    };
    direction.ordered_indices(len)
}

fn read_honeycomb_values(
    grid: &GlyphGrid,
    order: ReadingOrder,
    upper: TrigramPermutation,
    lower: TrigramPermutation,
) -> Result<Vec<TrigramValue>, GridError> {
    if !grid.row_count().is_multiple_of(2) {
        return Err(GridError::OddRowCount {
            message_key: grid.message_key,
            rows: grid.row_count(),
        });
    }

    let mut values = Vec::new();
    let mut row = 0;
    while row < grid.row_count() {
        let Some(next_row) = row.checked_add(1) else {
            return Err(GridError::OddRowCount {
                message_key: grid.message_key,
                rows: grid.row_count(),
            });
        };
        read_honeycomb_row_pair(grid, row, next_row, upper, lower, &mut values)?;
        row = next_row + 1;
    }
    if values.len() * 3 != grid.eye_count() {
        return Err(GridError::IncompleteTrigram {
            order,
            digits: grid.eye_count(),
        });
    }
    Ok(values)
}

fn read_honeycomb_row_pair(
    grid: &GlyphGrid,
    upper_row: usize,
    lower_row: usize,
    upper: TrigramPermutation,
    lower: TrigramPermutation,
    values: &mut Vec<TrigramValue>,
) -> Result<(), GridError> {
    let width = grid.rows.get(upper_row).map_or(0, Vec::len);
    let mut column = 0;
    while column + 1 < width {
        let tri = [
            grid.cell(upper_row, column)?,
            grid.cell(upper_row, column + 1)?,
            grid.cell(lower_row, column)?,
        ];
        values.push(value_from_orientations(upper.apply(tri)));
        column += 2;
        if column >= width {
            break;
        }
        let tri = [
            grid.cell(lower_row, column)?,
            grid.cell(lower_row, column - 1)?,
            grid.cell(upper_row, column)?,
        ];
        values.push(value_from_orientations(lower.apply(tri)));
        column += 1;
    }
    Ok(())
}

fn digits_to_values(
    digits: Vec<Orientation>,
    order: ReadingOrder,
) -> Result<Vec<TrigramValue>, GridError> {
    if !digits.len().is_multiple_of(3) {
        return Err(GridError::IncompleteTrigram {
            order,
            digits: digits.len(),
        });
    }
    let mut values = Vec::new();
    let mut iter = digits.into_iter();
    while let (Some(first), Some(second), Some(third)) = (iter.next(), iter.next(), iter.next()) {
        values.push(ReadingTrigram::new(first, second, third).value());
    }
    Ok(values)
}

fn value_from_orientations(orientations: [Orientation; 3]) -> TrigramValue {
    let [first, second, third] = orientations;
    ReadingTrigram::new(first, second, third).value()
}

/// Structural statistics for one trigram value stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderStats {
    /// Number of trigrams in the stream.
    pub total: usize,
    /// Number of distinct trigram values.
    pub distinct: usize,
    /// Minimum value present, if the stream is non-empty.
    pub min: Option<u8>,
    /// Maximum value present, if the stream is non-empty.
    pub max: Option<u8>,
    /// Whether the distinct value set is exactly contiguous between min/max.
    pub contiguous: bool,
    /// Number of distinct trigram values greater than `82`.
    pub values_above_82: usize,
    /// Count of adjacent equal trigrams.
    pub adjacent_equal: usize,
    /// Distance since previous occurrence histogram for distances `1..=6`.
    pub recurrence_distance_1_to_6: [usize; 6],
}

impl OrderStats {
    /// Computes statistics for a trigram value stream.
    #[must_use]
    pub fn from_values(values: &[TrigramValue]) -> Self {
        let distinct_values: BTreeSet<u8> = values.iter().map(|value| value.get()).collect();
        let min = distinct_values.first().copied();
        let max = distinct_values.last().copied();
        let contiguous = min
            .zip(max)
            .is_some_and(|(low, high)| usize::from(high - low + 1) == distinct_values.len());
        let recurrence = [
            count_recurrence(values, 1),
            count_recurrence(values, 2),
            count_recurrence(values, 3),
            count_recurrence(values, 4),
            count_recurrence(values, 5),
            count_recurrence(values, 6),
        ];
        Self {
            total: values.len(),
            distinct: distinct_values.len(),
            min,
            max,
            contiguous,
            values_above_82: distinct_values.iter().filter(|&&value| value > 82).count(),
            adjacent_equal: count_recurrence(values, 1),
            recurrence_distance_1_to_6: recurrence,
        }
    }

    /// Computes statistics for a corpus stream while preserving message
    /// boundaries for recurrence counts.
    #[must_use]
    pub fn from_message_values(message_values: &[Vec<TrigramValue>]) -> Self {
        let values: Vec<TrigramValue> = message_values.iter().flatten().copied().collect();
        let mut stats = Self::from_values(&values);
        let recurrence = [
            count_message_recurrence(message_values, 1),
            count_message_recurrence(message_values, 2),
            count_message_recurrence(message_values, 3),
            count_message_recurrence(message_values, 4),
            count_message_recurrence(message_values, 5),
            count_message_recurrence(message_values, 6),
        ];
        stats.adjacent_equal = count_message_recurrence(message_values, 1);
        stats.recurrence_distance_1_to_6 = recurrence;
        stats
    }

    /// Returns true for the headline contiguous `0..=82` result.
    #[must_use]
    pub fn is_contiguous_0_to_82(&self) -> bool {
        self.distinct == 83
            && self.contiguous
            && self.min == Some(0)
            && self.max == Some(82)
            && self.values_above_82 == 0
    }
}

fn count_recurrence(values: &[TrigramValue], distance: usize) -> usize {
    if distance == 0 {
        return 0;
    }
    let mut previous_positions = BTreeMap::new();
    let mut count = 0;
    for (position, value) in values.iter().copied().enumerate() {
        if previous_positions
            .insert(value, position)
            .is_some_and(|previous| position - previous == distance)
        {
            count += 1;
        }
    }
    count
}

fn count_message_recurrence(message_values: &[Vec<TrigramValue>], distance: usize) -> usize {
    message_values
        .iter()
        .map(|values| count_recurrence(values, distance))
        .sum()
}

/// Statistics for a named order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamedOrderStats {
    /// The reading order.
    pub order: ReadingOrder,
    /// The computed statistics.
    pub stats: OrderStats,
}

/// Computes stats for every order in [`audit_orders`].
///
/// # Errors
/// Returns [`GridError`] if any order is incompatible with the grids.
pub fn audit_order_stats(grids: &[GlyphGrid]) -> Result<Vec<NamedOrderStats>, GridError> {
    let mut stats = Vec::new();
    for order in audit_orders() {
        let values = read_corpus_message_values(grids, order)?;
        stats.push(NamedOrderStats {
            order,
            stats: OrderStats::from_message_values(&values),
        });
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::{
        OrderStats, ReadingOrder, TrigramPermutation, audit_order_stats, corpus_grids,
        summarize_grids,
    };

    #[test]
    fn raw_order_matches_stage_a_anchor() {
        let grids = corpus_grids().unwrap();
        let stats = audit_order_stats(&grids)
            .unwrap()
            .into_iter()
            .find(|item| item.order == ReadingOrder::RawRows)
            .unwrap()
            .stats;
        assert_eq!(stats.total, 1036);
        assert_eq!(stats.distinct, 114);
        assert_eq!(stats.min, Some(0));
        assert_eq!(stats.max, Some(122));
        assert!(!stats.contiguous);
        assert_eq!(stats.values_above_82, 31);
        assert_eq!(stats.adjacent_equal, 17);
        assert_eq!(stats.recurrence_distance_1_to_6, [17, 12, 15, 10, 10, 9]);
    }

    #[test]
    fn grids_expose_observed_row_widths() {
        let grids = corpus_grids().unwrap();
        let summary = summarize_grids(&grids);
        assert_eq!(summary.max_width, 39);
        assert!(summary.bottom_two_rows_differ_by_at_most_one);
        let widths: Vec<Vec<usize>> = summary
            .row_widths
            .into_iter()
            .map(|(_key, widths)| widths)
            .collect();
        assert_eq!(
            widths,
            vec![
                vec![39, 39, 39, 39, 39, 39, 32, 31],
                vec![39, 39, 39, 39, 39, 39, 38, 37],
                vec![39, 39, 39, 39, 39, 39, 39, 39, 21, 21],
                vec![39, 39, 39, 39, 39, 39, 36, 36],
                vec![39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 11, 10],
                vec![39, 39, 39, 39, 39, 39, 39, 39, 30, 30],
                vec![39, 39, 39, 39, 39, 39, 39, 39, 23, 22],
                vec![39, 39, 39, 39, 39, 39, 39, 39, 24, 24],
                vec![39, 39, 39, 39, 39, 39, 39, 39, 15, 15],
            ]
        );
    }

    #[test]
    fn identity_honeycomb_reproduces_contiguous_anchor() {
        let grids = corpus_grids().unwrap();
        let order = ReadingOrder::HoneycombStandard {
            upper: TrigramPermutation::IDENTITY,
            lower: TrigramPermutation::IDENTITY,
        };
        let values = super::read_corpus_message_values(&grids, order).unwrap();
        let stats = OrderStats::from_message_values(&values);
        assert_eq!(stats.total, 1036);
        assert!(stats.is_contiguous_0_to_82());
        assert_eq!(stats.adjacent_equal, 0);
    }

    #[test]
    fn audit_family_has_one_standard36_contiguous_zero_to_82_order() {
        let grids = corpus_grids().unwrap();
        let stats = audit_order_stats(&grids).unwrap();
        let winners: Vec<String> = stats
            .into_iter()
            .filter(|item| item.stats.is_contiguous_0_to_82())
            .map(|item| item.order.name())
            .collect();
        assert_eq!(winners, vec!["standard36-u012-d012"]);
    }
}

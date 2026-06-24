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

use crate::analysis;
use crate::corpus::{CorpusError, Message, messages};
use crate::glyph::{Glyph, Orientation};
use crate::trigram::{ReadingTrigram, TrigramValue};

/// Size of the community reading-layer alphabet used by the honeycomb winner.
pub const READING_LAYER_ALPHABET_SIZE: usize = 83;

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

    /// Rendered orientation rows for this grid.
    #[must_use]
    pub fn orientation_rows(&self) -> &[Vec<Orientation>] {
        &self.rows
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
    /// Diagonal control over anti-diagonals where `row + column` is constant.
    DiagonalMajor {
        /// Diagonal traversal order.
        diagonals: Direction,
        /// Row traversal order within each diagonal.
        rows: Direction,
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
            Self::DiagonalMajor { diagonals, rows } => {
                format!("diag-{}-{}", diagonals.name(), rows.name())
            }
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

/// Returns the accepted honeycomb order, `standard36-u012-d012`.
#[must_use]
pub const fn accepted_honeycomb_order() -> ReadingOrder {
    ReadingOrder::HoneycombStandard {
        upper: TrigramPermutation::IDENTITY,
        lower: TrigramPermutation::IDENTITY,
    }
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

/// Returns simple diagonal route controls over ragged rows.
#[must_use]
pub fn diagonal_orders() -> Vec<ReadingOrder> {
    let mut orders = Vec::new();
    for diagonals in [Direction::Forward, Direction::Reverse] {
        for rows in [Direction::Forward, Direction::Reverse] {
            orders.push(ReadingOrder::DiagonalMajor { diagonals, rows });
        }
    }
    orders
}

/// Returns the traversal set used by the calibrated `DoF` null.
///
/// This is [`audit_orders`] plus diagonal route controls. The standard36
/// honeycomb family remains data-independent: each honeycomb walk is determined
/// by grid shape plus fixed digit-position permutations, not by the glyph
/// contents.
#[must_use]
pub fn dof_candidate_orders() -> Vec<ReadingOrder> {
    let mut orders = audit_orders();
    orders.extend(diagonal_orders());
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

/// Reads all grids with one order, preserving message boundaries as rendered
/// orientation digits.
///
/// For honeycomb orders this returns the data-independent honeycomb digit
/// stream after the order's trigram-position permutations have been applied.
/// This lets non-trigram grouping rules reuse the same traversal family without
/// inventing a separate honeycomb digit path.
///
/// # Errors
/// Returns [`GridError`] if the order is incompatible with any grid shape.
pub fn read_corpus_message_orientations(
    grids: &[GlyphGrid],
    order: ReadingOrder,
) -> Result<Vec<Vec<Orientation>>, GridError> {
    let mut messages = Vec::new();
    for grid in grids {
        messages.push(read_grid_orientations(grid, order)?);
    }
    Ok(messages)
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

/// Reads one grid with one order and returns rendered orientation digits.
///
/// # Errors
/// Returns [`GridError`] if the order is incompatible with the grid shape.
pub fn read_grid_orientations(
    grid: &GlyphGrid,
    order: ReadingOrder,
) -> Result<Vec<Orientation>, GridError> {
    match order {
        ReadingOrder::HoneycombStandard { .. } => Ok(read_grid_values(grid, order)?
            .into_iter()
            .flat_map(orientations_from_value)
            .collect()),
        _ => read_grid_digits(grid, order),
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
        ReadingOrder::DiagonalMajor { diagonals, rows } => {
            read_diagonal_major_digits(grid, diagonals, rows)
        }
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

fn read_diagonal_major_digits(
    grid: &GlyphGrid,
    diagonals: Direction,
    rows: Direction,
) -> Result<Vec<Orientation>, GridError> {
    let diagonal_count = grid
        .row_count()
        .saturating_add(grid.max_width())
        .saturating_sub(1);
    let mut out = Vec::new();
    for diagonal in diagonals.ordered_indices(diagonal_count) {
        for row in rows.ordered_indices(grid.row_count()) {
            let Some(column) = diagonal.checked_sub(row) else {
                continue;
            };
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

fn orientations_from_value(value: TrigramValue) -> [Orientation; 3] {
    let raw = value.get();
    let first = raw / 25;
    let second = (raw % 25) / 5;
    let third = raw % 5;
    [
        orientation_from_base5_digit(first),
        orientation_from_base5_digit(second),
        orientation_from_base5_digit(third),
    ]
}

fn orientation_from_base5_digit(digit: u8) -> Orientation {
    match digit {
        0 => Orientation::Zero,
        1 => Orientation::One,
        2 => Orientation::Two,
        3 => Orientation::Three,
        _ => Orientation::Four,
    }
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

/// Frequency, entropy, `IoC`, and chi-square flatness stats for one order.
#[derive(Clone, Debug, PartialEq)]
pub struct ReadingLayerFlatnessStats {
    /// Number of trigrams across all messages.
    pub total: usize,
    /// Count of trigrams whose value is in the `0..=82` reading-layer alphabet.
    pub in_alphabet_total: usize,
    /// Count of trigrams outside the `0..=82` reading-layer alphabet.
    pub outside_alphabet_occurrences: usize,
    /// Frequency table for the `0..=82` reading-layer alphabet.
    pub frequencies: Vec<(u8, usize)>,
    /// Uniform expected frequency, `total / 83`.
    pub mean_frequency: f64,
    /// Smallest observed frequency among the `0..=82` buckets.
    pub min_frequency: usize,
    /// Largest observed frequency among the `0..=82` buckets.
    pub max_frequency: usize,
    /// Number of `0..=82` buckets with zero observations.
    pub zero_frequency_symbols: usize,
    /// Per-message weighted Shannon entropy, in bits per trigram.
    pub entropy_bits_per_symbol: f64,
    /// Maximum entropy for a valid 83-symbol uniform stream.
    pub max_entropy_bits_per_symbol: f64,
    /// Per-message weighted `IoC` probability.
    pub ioc_probability: f64,
    /// `IoC` normalized to the 83-symbol uniform baseline (`1.0` means uniform).
    pub normalized_ioc: f64,
    /// Concatenated-corpus `IoC` probability, reported as a community-reference cross-check.
    pub concatenated_ioc_probability: f64,
    /// Concatenated `IoC` normalized to the 83-symbol uniform baseline.
    pub concatenated_normalized_ioc: f64,
    /// Pearson chi-square statistic against uniform support on `0..=82`.
    ///
    /// This is infinite when the order emits any value outside `0..=82`, because
    /// an 83-symbol expected distribution assigns those values probability zero.
    pub chi_square_vs_uniform: f64,
}

impl ReadingLayerFlatnessStats {
    /// Computes reading-layer flatness stats from per-message trigram values.
    #[must_use]
    pub fn from_message_values(message_values: &[Vec<TrigramValue>]) -> Self {
        let message_glyphs = glyph_messages_from_values(message_values);
        let glyphs: Vec<Glyph> = message_glyphs.iter().flatten().copied().collect();
        let counts = analysis::frequencies(&glyphs);
        let mut frequencies = Vec::with_capacity(READING_LAYER_ALPHABET_SIZE);
        for value in 0..READING_LAYER_ALPHABET_SIZE {
            let glyph = Glyph(value as u16);
            frequencies.push((value as u8, counts.get(&glyph).copied().unwrap_or(0)));
        }

        let total = glyphs.len();
        let in_alphabet_total = frequencies.iter().map(|(_value, count)| *count).sum();
        let outside_alphabet_occurrences = total.saturating_sub(in_alphabet_total);
        let min_frequency = frequencies
            .iter()
            .map(|(_value, count)| *count)
            .min()
            .unwrap_or(0);
        let max_frequency = frequencies
            .iter()
            .map(|(_value, count)| *count)
            .max()
            .unwrap_or(0);
        let zero_frequency_symbols = frequencies
            .iter()
            .filter(|(_value, count)| *count == 0)
            .count();
        let frequency_counts: Vec<usize> =
            frequencies.iter().map(|(_value, count)| *count).collect();
        let ioc_probability = message_weighted_ioc(&message_glyphs);
        let concatenated_ioc_probability = analysis::index_of_coincidence(&glyphs);
        let chi_square_vs_uniform = if outside_alphabet_occurrences == 0 {
            analysis::chi_square_goodness_of_fit_uniform(&frequency_counts)
        } else {
            f64::INFINITY
        };

        Self {
            total,
            in_alphabet_total,
            outside_alphabet_occurrences,
            frequencies,
            mean_frequency: total as f64 / READING_LAYER_ALPHABET_SIZE as f64,
            min_frequency,
            max_frequency,
            zero_frequency_symbols,
            entropy_bits_per_symbol: message_weighted_entropy(&message_glyphs),
            max_entropy_bits_per_symbol: (READING_LAYER_ALPHABET_SIZE as f64).log2(),
            ioc_probability,
            normalized_ioc: ioc_probability * READING_LAYER_ALPHABET_SIZE as f64,
            concatenated_ioc_probability,
            concatenated_normalized_ioc: concatenated_ioc_probability
                * READING_LAYER_ALPHABET_SIZE as f64,
            chi_square_vs_uniform,
        }
    }
}

/// Converts per-message reading-layer trigram values into generic glyphs.
///
/// This keeps message boundaries intact for statistics that must not create
/// artificial evidence across joins.
#[must_use]
pub fn glyph_messages_from_values(message_values: &[Vec<TrigramValue>]) -> Vec<Vec<Glyph>> {
    message_values
        .iter()
        .map(|values| {
            values
                .iter()
                .map(|value| Glyph(u16::from(value.get())))
                .collect()
        })
        .collect()
}

fn message_weighted_ioc(message_glyphs: &[Vec<Glyph>]) -> f64 {
    let mut weighted_ioc = 0.0;
    let mut pair_count_total = 0usize;
    for glyphs in message_glyphs {
        let n = glyphs.len();
        if n < 2 {
            continue;
        }
        let pair_count = n * (n - 1);
        weighted_ioc += analysis::index_of_coincidence(glyphs) * pair_count as f64;
        pair_count_total += pair_count;
    }
    if pair_count_total == 0 {
        0.0
    } else {
        weighted_ioc / pair_count_total as f64
    }
}

fn message_weighted_entropy(message_glyphs: &[Vec<Glyph>]) -> f64 {
    let mut weighted_entropy = 0.0;
    let mut total = 0usize;
    for glyphs in message_glyphs {
        let len = glyphs.len();
        if len == 0 {
            continue;
        }
        weighted_entropy += analysis::shannon_entropy(glyphs) * len as f64;
        total += len;
    }
    if total == 0 {
        0.0
    } else {
        weighted_entropy / total as f64
    }
}

/// Counts values whose previous occurrence was exactly `distance` positions ago.
///
/// This is the recurrence convention used by the reading-order audit. It is
/// not the same as all-pair lag autocorrelation: only the immediately previous
/// occurrence of each value is considered.
#[must_use]
pub fn count_recurrence(values: &[TrigramValue], distance: usize) -> usize {
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

/// Sums [`count_recurrence`] over messages without crossing message joins.
#[must_use]
pub fn count_message_recurrence(message_values: &[Vec<TrigramValue>], distance: usize) -> usize {
    message_values
        .iter()
        .map(|values| count_recurrence(values, distance))
        .sum()
}

/// Counts exact equality pairs at a fixed lag in one message.
///
/// For lag `L`, this checks every valid pair `symbol[i] == symbol[i + L]`.
/// Returns zero for lag zero or for lags greater than or equal to the message
/// length.
#[must_use]
pub fn count_lag_matches(values: &[TrigramValue], lag: usize) -> usize {
    if lag == 0 || lag >= values.len() {
        return 0;
    }
    values
        .iter()
        .zip(values.iter().skip(lag))
        .filter(|(left, right)| left == right)
        .count()
}

/// Counts comparable pairs at a fixed lag in one message.
///
/// This is the denominator for [`count_lag_matches`].
#[must_use]
pub fn count_lag_comparisons(values: &[TrigramValue], lag: usize) -> usize {
    if lag == 0 {
        return 0;
    }
    values.len().saturating_sub(lag)
}

/// Sums exact equality pairs at a fixed lag over messages.
///
/// Message boundaries are preserved: no pair is formed from the end of one
/// message to the beginning of another.
#[must_use]
pub fn count_message_lag_matches(message_values: &[Vec<TrigramValue>], lag: usize) -> usize {
    message_values
        .iter()
        .map(|values| count_lag_matches(values, lag))
        .sum()
}

/// Sums comparable fixed-lag pairs over messages without crossing joins.
#[must_use]
pub fn count_message_lag_comparisons(message_values: &[Vec<TrigramValue>], lag: usize) -> usize {
    message_values
        .iter()
        .map(|values| count_lag_comparisons(values, lag))
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

/// Flatness statistics for a named order.
#[derive(Clone, Debug, PartialEq)]
pub struct NamedReadingLayerFlatnessStats {
    /// The reading order.
    pub order: ReadingOrder,
    /// The computed flatness statistics.
    pub flatness: ReadingLayerFlatnessStats,
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

/// Computes flatness stats for one order.
///
/// # Errors
/// Returns [`GridError`] if the order is incompatible with the grids.
pub fn reading_layer_flatness_stats(
    grids: &[GlyphGrid],
    order: ReadingOrder,
) -> Result<ReadingLayerFlatnessStats, GridError> {
    let message_values = read_corpus_message_values(grids, order)?;
    Ok(ReadingLayerFlatnessStats::from_message_values(
        &message_values,
    ))
}

/// Computes flatness stats for every order in [`audit_orders`].
///
/// # Errors
/// Returns [`GridError`] if any order is incompatible with the grids.
pub fn audit_order_flatness_stats(
    grids: &[GlyphGrid],
) -> Result<Vec<NamedReadingLayerFlatnessStats>, GridError> {
    let mut stats = Vec::new();
    for order in audit_orders() {
        stats.push(NamedReadingLayerFlatnessStats {
            order,
            flatness: reading_layer_flatness_stats(grids, order)?,
        });
    }
    Ok(stats)
}

/// Computes flatness stats for the exact Toboter-style standard-36 family.
///
/// # Errors
/// Returns [`GridError`] if any standard order is incompatible with the grids.
pub fn standard36_flatness_stats(
    grids: &[GlyphGrid],
) -> Result<Vec<NamedReadingLayerFlatnessStats>, GridError> {
    let mut stats = Vec::new();
    for order in standard36_orders() {
        stats.push(NamedReadingLayerFlatnessStats {
            order,
            flatness: reading_layer_flatness_stats(grids, order)?,
        });
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::{
        OrderStats, READING_LAYER_ALPHABET_SIZE, ReadingOrder, TrigramPermutation,
        audit_order_stats, corpus_grids, reading_layer_flatness_stats, summarize_grids,
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
    fn accepted_honeycomb_message_lengths_are_distinct() {
        let grids = corpus_grids().unwrap();
        let values =
            super::read_corpus_message_values(&grids, super::accepted_honeycomb_order()).unwrap();
        let observed: Vec<(&str, usize)> = grids
            .iter()
            .zip(values.iter())
            .map(|(grid, values)| (grid.message_key(), values.len()))
            .collect();
        assert_eq!(
            observed,
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

        let mut lengths: Vec<usize> = observed
            .iter()
            .map(|(_message_key, length)| *length)
            .collect();
        let message_count = lengths.len();
        lengths.sort_unstable();
        lengths.dedup();
        assert_eq!(lengths.len(), message_count);
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

    #[test]
    fn experiment_4_honeycomb_flatness_matches_frequency_and_ioc_anchors() {
        let grids = corpus_grids().unwrap();
        let order = ReadingOrder::HoneycombStandard {
            upper: TrigramPermutation::IDENTITY,
            lower: TrigramPermutation::IDENTITY,
        };
        let flatness = reading_layer_flatness_stats(&grids, order).unwrap();

        assert_eq!(flatness.total, 1036);
        assert_eq!(flatness.in_alphabet_total, 1036);
        assert_eq!(flatness.outside_alphabet_occurrences, 0);
        assert_eq!(flatness.frequencies.len(), READING_LAYER_ALPHABET_SIZE);
        assert_eq!(flatness.mean_frequency.to_bits(), 0x4028_f6bf_3a9a_3785);
        assert_eq!(flatness.min_frequency, 3);
        assert_eq!(flatness.max_frequency, 26);
        assert_eq!(flatness.zero_frequency_symbols, 0);
        assert!((flatness.normalized_ioc - flatness.ioc_probability * 83.0).abs() < 1e-12);
        assert!(
            (flatness.normalized_ioc - 0.971_776_489_899_835_8).abs() < 1e-12,
            "per-message normalized IoC changed: {}",
            flatness.normalized_ioc
        );
        assert!(
            (flatness.concatenated_normalized_ioc - flatness.concatenated_ioc_probability * 83.0)
                .abs()
                < 1e-12
        );
        assert_eq!(
            flatness.concatenated_normalized_ioc.to_bits(),
            0x3ff1_0e83_d247_5ed2
        );
        assert_eq!(
            flatness.chi_square_vs_uniform.to_bits(),
            0x4062_cb5d_e64d_18b5
        );
    }

    #[test]
    fn experiment_4_raw_order_is_not_an_83_symbol_stream() {
        let grids = corpus_grids().unwrap();
        let flatness = reading_layer_flatness_stats(&grids, ReadingOrder::RawRows).unwrap();

        assert_eq!(flatness.total, 1036);
        assert!(flatness.outside_alphabet_occurrences > 0);
        assert!(flatness.chi_square_vs_uniform.is_infinite());
    }
}

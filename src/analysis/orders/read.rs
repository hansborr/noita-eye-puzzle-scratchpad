//! Grid traversal and trigram-reading engine for the reading-order families.
//!
//! These functions walk a reconstructed [`GlyphGrid`] under one
//! [`ReadingOrder`] and emit either trigram values or rendered orientation
//! digits, including the data-independent honeycomb walk.

use super::{Direction, GlyphGrid, GridError, LineMode, ReadingOrder, TrigramPermutation};
use crate::core::glyph::Orientation;
use crate::core::trigram::{ReadingTrigram, TrigramValue, base5_digits};

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
    let [first, second, third] = base5_digits(value.get());
    [
        Orientation::from_base5_digit(first),
        Orientation::from_base5_digit(second),
        Orientation::from_base5_digit(third),
    ]
}

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

use crate::core::glyph::Orientation;
use crate::data::corpus::{CorpusError, Message, messages};

mod context;
mod read;
mod stats;
#[cfg(test)]
mod tests;

pub use context::CorpusContext;
pub use read::{
    read_corpus_message_orientations, read_corpus_message_values, read_corpus_values,
    read_grid_orientations, read_grid_values,
};
pub use stats::{
    NamedOrderStats, NamedReadingLayerFlatnessStats, OrderStats, ReadingLayerFlatnessStats,
    audit_order_flatness_stats, audit_order_stats, count_lag_comparisons, count_lag_matches,
    count_message_lag_comparisons, count_message_lag_matches, count_message_recurrence,
    count_recurrence, glyph_messages_from_values, reading_layer_flatness_stats,
    standard36_flatness_stats,
};

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
                crate::core::glyph::RenderedSymbol::Orientation(orientation) => {
                    current.push(orientation);
                }
                crate::core::glyph::RenderedSymbol::RowDelimiter => {
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

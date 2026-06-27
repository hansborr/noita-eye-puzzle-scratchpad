//! Honeycomb lattice construction, contingency statistics, and Monte-Carlo nulls.

use super::{
    HoneycombCoordinate, HoneycombNullReport, HoneycombParity, HoneycombStats, IndependenceStats,
    LatticeTrigram, MessageLattice, NullBand, PairStats, ParitySplitStats,
    PositionConditioningStats, Tail, TailReport,
};
use crate::analysis::analysis;
use crate::analysis::orders::{self, GlyphGrid, GridError, ReadingOrder, TrigramPermutation};
use crate::core::glyph::{Glyph, Orientation};
use crate::core::trigram::{ReadingTrigram, TrigramValue};
use crate::nulls::null::{median_f64, scaled_quantile_index};

const TRIGRAM_VALUE_COUNT: usize = 125;
const VALUE_DECILE_COUNT: usize = 10;

/// Builds the honeycomb lattice for one reconstructed grid.
///
/// # Errors
/// Returns [`GridError`] if the grid has an odd row count, a required cell is
/// absent in a ragged row, or the row-pair geometry does not consume complete
/// trigrams.
pub fn lattice_for_grid(grid: &GlyphGrid) -> Result<MessageLattice, GridError> {
    if !grid.row_count().is_multiple_of(2) {
        return Err(GridError::OddRowCount {
            message_key: grid.message_key(),
            rows: grid.row_count(),
        });
    }

    let (upper_permutation, lower_permutation) = accepted_honeycomb_permutations();
    let order = orders::accepted_honeycomb_order();
    let mut bands = Vec::new();
    let mut row = 0usize;
    let mut band = 0usize;
    let mut sequence_index = 0usize;

    while row < grid.row_count() {
        let Some(lower_row) = row.checked_add(1) else {
            return Err(GridError::OddRowCount {
                message_key: grid.message_key(),
                rows: grid.row_count(),
            });
        };
        let trigrams = read_lattice_row_pair(
            grid,
            RowPair {
                upper_row: row,
                lower_row,
                band,
            },
            upper_permutation,
            lower_permutation,
            &mut sequence_index,
        )?;
        bands.push(trigrams);
        row = lower_row + 1;
        band += 1;
    }

    let lattice = MessageLattice {
        message_key: grid.message_key(),
        bands,
    };
    if lattice.len() * 3 != grid.eye_count() {
        return Err(GridError::IncompleteTrigram {
            order,
            digits: grid.eye_count(),
        });
    }
    Ok(lattice)
}

/// Builds honeycomb lattices for all verified corpus grids.
///
/// # Errors
/// Returns [`GridError`] if any grid is incompatible with the fixed honeycomb
/// row-pair geometry.
pub fn lattices_for_grids(grids: &[GlyphGrid]) -> Result<Vec<MessageLattice>, GridError> {
    let mut lattices = Vec::new();
    for grid in grids {
        lattices.push(lattice_for_grid(grid)?);
    }
    Ok(lattices)
}

#[derive(Clone, Copy)]
pub(super) struct RowPair {
    pub(super) upper_row: usize,
    pub(super) lower_row: usize,
    pub(super) band: usize,
}

fn accepted_honeycomb_permutations() -> (TrigramPermutation, TrigramPermutation) {
    match orders::accepted_honeycomb_order() {
        ReadingOrder::HoneycombStandard { upper, lower } => (upper, lower),
        _ => (TrigramPermutation::IDENTITY, TrigramPermutation::IDENTITY),
    }
}

pub(super) fn read_lattice_row_pair(
    grid: &GlyphGrid,
    row_pair: RowPair,
    upper_permutation: TrigramPermutation,
    lower_permutation: TrigramPermutation,
    sequence_index: &mut usize,
) -> Result<Vec<LatticeTrigram>, GridError> {
    let width = grid
        .orientation_rows()
        .get(row_pair.upper_row)
        .map_or(0, Vec::len);
    let mut trigrams = Vec::new();
    let mut column = 0usize;
    while column < width.saturating_sub(1) {
        let tri = [
            grid_cell(grid, row_pair.upper_row, column)?,
            grid_cell(grid, row_pair.upper_row, column + 1)?,
            grid_cell(grid, row_pair.lower_row, column)?,
        ];
        push_lattice_trigram(
            &mut trigrams,
            row_pair.band,
            HoneycombParity::Upper,
            upper_permutation,
            tri,
            sequence_index,
        );
        column += 2;
        if column >= width {
            break;
        }
        let tri = [
            grid_cell(grid, row_pair.lower_row, column)?,
            grid_cell(grid, row_pair.lower_row, column - 1)?,
            grid_cell(grid, row_pair.upper_row, column)?,
        ];
        push_lattice_trigram(
            &mut trigrams,
            row_pair.band,
            HoneycombParity::Lower,
            lower_permutation,
            tri,
            sequence_index,
        );
        column += 1;
    }
    Ok(trigrams)
}

fn push_lattice_trigram(
    trigrams: &mut Vec<LatticeTrigram>,
    band: usize,
    parity: HoneycombParity,
    permutation: TrigramPermutation,
    tri: [Orientation; 3],
    sequence_index: &mut usize,
) {
    let pos_in_band = trigrams.len();
    trigrams.push(LatticeTrigram {
        coordinate: HoneycombCoordinate {
            band,
            pos_in_band,
            parity,
            sequence_index: *sequence_index,
        },
        value: value_from_orientations(apply_permutation(permutation, tri)),
    });
    *sequence_index += 1;
}

fn grid_cell(grid: &GlyphGrid, row: usize, column: usize) -> Result<Orientation, GridError> {
    grid.orientation_rows()
        .get(row)
        .and_then(|cells| cells.get(column))
        .copied()
        .ok_or(GridError::MissingCell {
            message_key: grid.message_key(),
            row,
            column,
        })
}

fn apply_permutation(
    permutation: TrigramPermutation,
    orientations: [Orientation; 3],
) -> [Orientation; 3] {
    let [first_position, second_position, third_position] = permutation.positions();
    [
        orientation_at(orientations, first_position),
        orientation_at(orientations, second_position),
        orientation_at(orientations, third_position),
    ]
}

fn orientation_at(source: [Orientation; 3], index: usize) -> Orientation {
    let [first, second, third] = source;
    match index {
        0 => first,
        1 => second,
        _ => third,
    }
}

fn value_from_orientations(orientations: [Orientation; 3]) -> TrigramValue {
    let [first, second, third] = orientations;
    ReadingTrigram::new(first, second, third).value()
}

pub(super) fn stats_for_lattices(lattices: &[MessageLattice]) -> HoneycombStats {
    let (vertical, sequence_distance_control) = pair_stats(lattices);
    HoneycombStats {
        total_trigrams: lattices.iter().map(MessageLattice::len).sum(),
        vertical,
        sequence_distance_control,
        position_conditioning: position_conditioning_stats(lattices),
        parity_split: parity_split_stats(lattices),
    }
}

fn pair_stats(lattices: &[MessageLattice]) -> (PairStats, PairStats) {
    let mut vertical = PairStatsBuilder::default();
    let mut sequence_control = PairStatsBuilder::default();

    for lattice in lattices {
        let mut vertical_lags = Vec::new();
        for adjacent_bands in lattice.bands.windows(2) {
            let Some(upper_band) = adjacent_bands.first() else {
                continue;
            };
            let Some(lower_band) = adjacent_bands.get(1) else {
                continue;
            };
            for (upper, lower) in upper_band.iter().zip(lower_band) {
                vertical.add(upper.value, lower.value);
                let Some(lag) = lower
                    .coordinate
                    .sequence_index
                    .checked_sub(upper.coordinate.sequence_index)
                else {
                    continue;
                };
                if lag == 0 {
                    continue;
                }
                vertical_lags.push(lag);
            }
        }
        vertical_lags.sort_unstable();
        vertical_lags.dedup();
        let values = lattice.flattened_values();
        for lag in vertical_lags {
            for (left, right) in values.iter().zip(values.iter().skip(lag)) {
                sequence_control.add(*left, *right);
            }
        }
    }

    (vertical.finish(), sequence_control.finish())
}

#[derive(Default)]
struct PairStatsBuilder {
    pairs: usize,
    exact_equal: usize,
    abs_diff_sum: usize,
}

impl PairStatsBuilder {
    fn add(&mut self, left: TrigramValue, right: TrigramValue) {
        self.pairs += 1;
        if left == right {
            self.exact_equal += 1;
        }
        self.abs_diff_sum += usize::from(left.get().abs_diff(right.get()));
    }

    fn finish(self) -> PairStats {
        if self.pairs == 0 {
            return PairStats::default();
        }
        PairStats {
            pairs: self.pairs,
            exact_equal: self.exact_equal,
            exact_equal_rate: self.exact_equal as f64 / self.pairs as f64,
            mean_abs_diff: self.abs_diff_sum as f64 / self.pairs as f64,
        }
    }
}

fn position_conditioning_stats(lattices: &[MessageLattice]) -> PositionConditioningStats {
    let mut table = vec![Vec::new(); VALUE_DECILE_COUNT];
    for lattice in lattices {
        for trigram in lattice.bands.iter().flatten() {
            let decile = value_decile(trigram.value);
            let pos = trigram.coordinate.pos_in_band;
            if let Some(row) = table.get_mut(decile) {
                if row.len() <= pos {
                    row.resize(pos + 1, 0);
                }
                if let Some(count) = row.get_mut(pos) {
                    *count += 1;
                }
            }
        }
    }
    let independence = chi_square_independence(&table);
    PositionConditioningStats {
        total: independence.total,
        positions: independence.columns,
        value_deciles: independence.rows,
        chi_square: independence.chi_square,
        degrees_of_freedom: independence.degrees_of_freedom,
    }
}

fn value_decile(value: TrigramValue) -> usize {
    usize::from(value.get()) * VALUE_DECILE_COUNT / TRIGRAM_VALUE_COUNT
}

fn parity_split_stats(lattices: &[MessageLattice]) -> ParitySplitStats {
    let mut table = vec![vec![0usize; TRIGRAM_VALUE_COUNT]; 2];
    let mut upper_values = Vec::new();
    let mut lower_values = Vec::new();

    for lattice in lattices {
        for trigram in lattice.bands.iter().flatten() {
            let row = match trigram.coordinate.parity {
                HoneycombParity::Upper => {
                    upper_values.push(trigram.value);
                    0
                }
                HoneycombParity::Lower => {
                    lower_values.push(trigram.value);
                    1
                }
            };
            if let Some(counts) = table.get_mut(row)
                && let Some(count) = counts.get_mut(usize::from(trigram.value.get()))
            {
                *count += 1;
            }
        }
    }

    let independence = chi_square_independence(&table);
    let upper_ioc = ioc_for_values(&upper_values);
    let lower_ioc = ioc_for_values(&lower_values);
    ParitySplitStats {
        upper_total: upper_values.len(),
        lower_total: lower_values.len(),
        chi_square: independence.chi_square,
        degrees_of_freedom: independence.degrees_of_freedom,
        upper_ioc,
        lower_ioc,
        ioc_abs_diff: (upper_ioc - lower_ioc).abs(),
    }
}

fn ioc_for_values(values: &[TrigramValue]) -> f64 {
    let glyphs: Vec<Glyph> = values
        .iter()
        .map(|value| Glyph(u16::from(value.get())))
        .collect();
    analysis::index_of_coincidence(&glyphs)
}

pub(super) fn chi_square_independence(rows: &[Vec<usize>]) -> IndependenceStats {
    let row_totals: Vec<usize> = rows.iter().map(|row| row.iter().sum()).collect();
    let max_columns = rows.iter().map(Vec::len).max().unwrap_or(0);
    let mut column_totals = vec![0usize; max_columns];
    for row in rows {
        for (column, &count) in row.iter().enumerate() {
            if let Some(total) = column_totals.get_mut(column) {
                *total += count;
            }
        }
    }
    let total: usize = row_totals.iter().sum();
    if total == 0 {
        return IndependenceStats::default();
    }

    let nonzero_rows = row_totals.iter().filter(|&&count| count > 0).count();
    let nonzero_columns = column_totals.iter().filter(|&&count| count > 0).count();
    let mut chi_square = 0.0;
    let total_f64 = total as f64;

    for (row, row_total) in rows.iter().zip(row_totals.iter().copied()) {
        if row_total == 0 {
            continue;
        }
        for (column, column_total) in column_totals.iter().copied().enumerate() {
            if column_total == 0 {
                continue;
            }
            let observed = row.get(column).copied().unwrap_or(0) as f64;
            let expected = row_total as f64 * column_total as f64 / total_f64;
            let delta = observed - expected;
            chi_square += delta * delta / expected;
        }
    }

    IndependenceStats {
        total,
        rows: nonzero_rows,
        columns: nonzero_columns,
        chi_square,
        degrees_of_freedom: nonzero_rows
            .saturating_sub(1)
            .saturating_mul(nonzero_columns.saturating_sub(1)),
    }
}

#[derive(Default)]
pub(super) struct NullSamples {
    vertical_equal_rate: Vec<f64>,
    vertical_mean_abs_diff: Vec<f64>,
    sequence_control_equal_rate: Vec<f64>,
    sequence_control_mean_abs_diff: Vec<f64>,
    position_chi_square: Vec<f64>,
    parity_chi_square: Vec<f64>,
    parity_ioc_abs_diff: Vec<f64>,
}

impl NullSamples {
    pub(super) fn push(&mut self, stats: HoneycombStats) {
        self.vertical_equal_rate
            .push(stats.vertical.exact_equal_rate);
        self.vertical_mean_abs_diff
            .push(stats.vertical.mean_abs_diff);
        self.sequence_control_equal_rate
            .push(stats.sequence_distance_control.exact_equal_rate);
        self.sequence_control_mean_abs_diff
            .push(stats.sequence_distance_control.mean_abs_diff);
        self.position_chi_square
            .push(stats.position_conditioning.chi_square);
        self.parity_chi_square.push(stats.parity_split.chi_square);
        self.parity_ioc_abs_diff
            .push(stats.parity_split.ioc_abs_diff);
    }

    pub(super) fn report(&self, observed: HoneycombStats) -> HoneycombNullReport {
        HoneycombNullReport {
            vertical_equal_rate: tail_report(
                observed.vertical.exact_equal_rate,
                &self.vertical_equal_rate,
                Tail::GreaterOrEqual,
            ),
            vertical_mean_abs_diff: tail_report(
                observed.vertical.mean_abs_diff,
                &self.vertical_mean_abs_diff,
                Tail::LessOrEqual,
            ),
            sequence_control_equal_rate: tail_report(
                observed.sequence_distance_control.exact_equal_rate,
                &self.sequence_control_equal_rate,
                Tail::GreaterOrEqual,
            ),
            sequence_control_mean_abs_diff: tail_report(
                observed.sequence_distance_control.mean_abs_diff,
                &self.sequence_control_mean_abs_diff,
                Tail::LessOrEqual,
            ),
            position_chi_square: tail_report(
                observed.position_conditioning.chi_square,
                &self.position_chi_square,
                Tail::GreaterOrEqual,
            ),
            parity_chi_square: tail_report(
                observed.parity_split.chi_square,
                &self.parity_chi_square,
                Tail::GreaterOrEqual,
            ),
            parity_ioc_abs_diff: tail_report(
                observed.parity_split.ioc_abs_diff,
                &self.parity_ioc_abs_diff,
                Tail::GreaterOrEqual,
            ),
        }
    }
}

fn tail_report(observed: f64, samples: &[f64], tail: Tail) -> TailReport {
    let extreme_count = samples
        .iter()
        .filter(|&&sample| match tail {
            Tail::GreaterOrEqual => sample >= observed,
            Tail::LessOrEqual => sample <= observed,
        })
        .count();
    let trials = samples.len();
    TailReport {
        observed,
        band: null_band(samples),
        extreme_count,
        empirical_p: (extreme_count + 1) as f64 / (trials + 1) as f64,
        tail,
    }
}

fn null_band(samples: &[f64]) -> NullBand {
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    NullBand {
        trials: samples.len(),
        min: quantile_from_sorted(&sorted, Quantile::Min),
        q025: quantile_from_sorted(&sorted, Quantile::Q025),
        median: quantile_from_sorted(&sorted, Quantile::Median),
        q975: quantile_from_sorted(&sorted, Quantile::Q975),
        max: quantile_from_sorted(&sorted, Quantile::Max),
    }
}

#[derive(Clone, Copy)]
enum Quantile {
    Min,
    Q025,
    Median,
    Q975,
    Max,
}

fn quantile_from_sorted(sorted: &[f64], quantile: Quantile) -> f64 {
    match quantile {
        Quantile::Min => sorted.first().copied().unwrap_or(0.0),
        Quantile::Q025 => sorted
            .get(scaled_quantile_index(sorted.len(), 25, 1_000))
            .copied()
            .unwrap_or(0.0),
        Quantile::Median => median_f64(sorted),
        Quantile::Q975 => sorted
            .get(scaled_quantile_index(sorted.len(), 975, 1_000))
            .copied()
            .unwrap_or(0.0),
        Quantile::Max => sorted.last().copied().unwrap_or(0.0),
    }
}

//! Honeycomb two-dimensional lattice-structure experiment.
//!
//! This module keeps the accepted Toboter-style honeycomb reading order fixed
//! and asks whether the physical row-pair lattice carries structure beyond the
//! one-dimensional stream. Each emitted trigram is tagged with its row-pair
//! band, its position inside that band, and the interlocking-triangle parity
//! from the same row-pair geometry used by [`crate::orders`].
//!
//! The null preserves the verified row widths, fills rendered cells uniformly
//! from orientation digits `0..=4`, and reuses the fixed accepted honeycomb
//! traversal without reselecting among standard36 permutations.

use std::fmt;

use crate::analysis;
use crate::glyph::{Glyph, Orientation};
use crate::null::{SplitMix64, median_f64, random_orientation_grids_like, scaled_quantile_index};
use crate::orders::{self, GlyphGrid, GridError, ReadingOrder, TrigramPermutation};
use crate::report::{self, Report};
use crate::trigram::{ReadingTrigram, TrigramValue};

/// Default deterministic Monte-Carlo seed for the honeycomb lattice null.
pub const DEFAULT_SEED: u64 = 0x686f_6e65_7963_6f6d;
/// Default Monte-Carlo trial count for the honeycomb lattice null.
pub const DEFAULT_TRIALS: usize = 1_000;

const TRIGRAM_VALUE_COUNT: usize = 125;
const VALUE_DECILE_COUNT: usize = 10;

/// Configuration for the honeycomb two-dimensional lattice experiment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HoneycombConfig {
    /// Explicit deterministic PRNG seed.
    pub seed: u64,
    /// Number of same-row-width random corpora to sample.
    pub trials: usize,
}

impl Default for HoneycombConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_SEED,
            trials: DEFAULT_TRIALS,
        }
    }
}

/// Error returned by the honeycomb lattice experiment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HoneycombError {
    /// The verified corpus could not be reconstructed or read as honeycomb grids.
    Grid(GridError),
    /// At least one Monte-Carlo trial is required.
    ZeroTrials,
}

impl From<GridError> for HoneycombError {
    fn from(value: GridError) -> Self {
        Self::Grid(value)
    }
}

impl fmt::Display for HoneycombError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Grid(grid_error) => write!(f, "grid/order error: {grid_error:?}"),
            Self::ZeroTrials => write!(f, "at least one Monte-Carlo trial is required"),
        }
    }
}

impl std::error::Error for HoneycombError {}

/// Interlocking-triangle branch inside one honeycomb row-pair walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HoneycombParity {
    /// First branch in [`crate::orders`] row-pair geometry.
    Upper,
    /// Second branch in [`crate::orders`] row-pair geometry.
    Lower,
}

/// Physical coordinate assigned to one emitted honeycomb trigram.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HoneycombCoordinate {
    /// Zero-based row-pair band.
    pub band: usize,
    /// Zero-based trigram position inside the row-pair band.
    pub pos_in_band: usize,
    /// Interlocking-triangle branch in the row-pair walk.
    pub parity: HoneycombParity,
    /// Zero-based position in the flattened accepted honeycomb stream for this message.
    pub sequence_index: usize,
}

/// One trigram value with its physical honeycomb coordinate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LatticeTrigram {
    /// Physical honeycomb coordinate.
    pub coordinate: HoneycombCoordinate,
    /// Base-5 trigram value emitted by the accepted honeycomb order.
    pub value: TrigramValue,
}

/// A single message reconstructed as honeycomb row-pair bands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageLattice {
    /// Corpus message key, such as `east1`.
    pub message_key: &'static str,
    /// Row-pair bands in accepted honeycomb sequence order.
    pub bands: Vec<Vec<LatticeTrigram>>,
}

impl MessageLattice {
    /// Number of trigrams in this message lattice.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bands.iter().map(Vec::len).sum()
    }

    /// Returns `true` when the lattice contains no trigrams.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Width of each row-pair band, in trigram units.
    #[must_use]
    pub fn band_widths(&self) -> Vec<usize> {
        self.bands.iter().map(Vec::len).collect()
    }

    /// Flattens the lattice back into the accepted honeycomb trigram stream.
    #[must_use]
    pub fn flattened_values(&self) -> Vec<TrigramValue> {
        self.bands
            .iter()
            .flatten()
            .map(|trigram| trigram.value)
            .collect()
    }
}

/// Pairwise comparison summary for trigram values.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct PairStats {
    /// Number of compared pairs.
    pub pairs: usize,
    /// Number of exact-equality pairs.
    pub exact_equal: usize,
    /// Exact-equality rate, `exact_equal / pairs`.
    pub exact_equal_rate: f64,
    /// Mean absolute numeric value difference.
    pub mean_abs_diff: f64,
}

/// Pearson independence statistic for a contingency table.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct IndependenceStats {
    /// Total observations in the table.
    pub total: usize,
    /// Non-empty row categories.
    pub rows: usize,
    /// Non-empty column categories.
    pub columns: usize,
    /// Pearson chi-square independence statistic.
    pub chi_square: f64,
    /// Reference degrees of freedom after dropping empty marginal categories.
    pub degrees_of_freedom: usize,
}

/// Position-in-band conditioning statistic.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct PositionConditioningStats {
    /// Number of trigrams assigned to position/value-decile cells.
    pub total: usize,
    /// Number of non-empty position-in-band categories.
    pub positions: usize,
    /// Number of non-empty value-decile categories.
    pub value_deciles: usize,
    /// Pearson chi-square statistic for value-decile vs position independence.
    pub chi_square: f64,
    /// Reference degrees of freedom after empty marginals are dropped.
    pub degrees_of_freedom: usize,
}

/// Interlocking-triangle parity split statistic.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ParitySplitStats {
    /// Number of upper-branch trigrams.
    pub upper_total: usize,
    /// Number of lower-branch trigrams.
    pub lower_total: usize,
    /// Pearson chi-square statistic for parity vs exact trigram value.
    pub chi_square: f64,
    /// Reference degrees of freedom after empty value buckets are dropped.
    pub degrees_of_freedom: usize,
    /// Upper-branch index of coincidence.
    pub upper_ioc: f64,
    /// Lower-branch index of coincidence.
    pub lower_ioc: f64,
    /// Absolute difference between upper and lower `IoC`.
    pub ioc_abs_diff: f64,
}

/// Observed statistics for one set of honeycomb lattices.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct HoneycombStats {
    /// Total trigrams across all messages.
    pub total_trigrams: usize,
    /// Vertical same-position row-pair adjacency profile.
    pub vertical: PairStats,
    /// Non-vertical same-sequence-distance control profile.
    pub sequence_distance_control: PairStats,
    /// Value-decile vs physical position-in-band conditioning.
    pub position_conditioning: PositionConditioningStats,
    /// Upper/lower interlocking-triangle parity split.
    pub parity_split: ParitySplitStats,
}

/// One-sided empirical-tail direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tail {
    /// Counts null samples greater than or equal to the observed statistic.
    GreaterOrEqual,
    /// Counts null samples less than or equal to the observed statistic.
    LessOrEqual,
}

impl Tail {
    /// Stable label for report rendering.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::GreaterOrEqual => "p>=real",
            Self::LessOrEqual => "p<=real",
        }
    }
}

/// Monte-Carlo band for one scalar statistic.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct NullBand {
    /// Number of null samples in the band.
    pub trials: usize,
    /// Smallest sampled value.
    pub min: f64,
    /// Lower pointwise 95% band edge.
    pub q025: f64,
    /// Sample median.
    pub median: f64,
    /// Upper pointwise 95% band edge.
    pub q975: f64,
    /// Largest sampled value.
    pub max: f64,
}

/// Empirical one-sided add-one p-value for one statistic.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TailReport {
    /// Real eye statistic.
    pub observed: f64,
    /// Monte-Carlo null band.
    pub band: NullBand,
    /// Number of null samples at least as extreme as the real statistic.
    pub extreme_count: usize,
    /// Add-one empirical p-value, `(extreme_count + 1) / (trials + 1)`.
    pub empirical_p: f64,
    /// Tail direction used for the extreme count.
    pub tail: Tail,
}

/// Fixed-order honeycomb random-grid null summary.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HoneycombNullReport {
    /// Null report for vertical exact-equality rate.
    pub vertical_equal_rate: TailReport,
    /// Null report for vertical mean absolute value difference.
    pub vertical_mean_abs_diff: TailReport,
    /// Null report for the same-sequence-distance control exact-equality rate.
    pub sequence_control_equal_rate: TailReport,
    /// Null report for the same-sequence-distance control mean absolute difference.
    pub sequence_control_mean_abs_diff: TailReport,
    /// Null report for position-in-band chi-square.
    pub position_chi_square: TailReport,
    /// Null report for parity-vs-value chi-square.
    pub parity_chi_square: TailReport,
    /// Null report for upper/lower `IoC` absolute divergence.
    pub parity_ioc_abs_diff: TailReport,
}

/// Complete honeycomb lattice experiment report.
#[derive(Clone, Debug, PartialEq)]
pub struct HoneycombReport {
    /// Configuration used for the run.
    pub config: HoneycombConfig,
    /// Fixed accepted honeycomb order used for eyes and null grids.
    pub order: ReadingOrder,
    /// Per-message accepted-stream lengths in corpus order.
    pub message_lengths: Vec<(&'static str, usize)>,
    /// Per-message row-pair band widths in trigram units.
    pub band_widths: Vec<(&'static str, Vec<usize>)>,
    /// Observed eye-corpus lattice statistics.
    pub observed: HoneycombStats,
    /// Same-row-width fixed-order random-grid null.
    pub null: HoneycombNullReport,
}

impl Report for HoneycombReport {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(&mut out, "Experiment 20 honeycomb 2D lattice structure");
        report::appendln!(&mut out, "order: {}", self.order.name());
        report::appendln!(&mut out, "seed: {}", self.config.seed);
        report::appendln!(&mut out, "trials: {}", self.config.trials);
        report::appendln!(
            &mut out,
            "message lengths: {}",
            report::format_message_lengths(&self.message_lengths)
        );
        report::appendln!(&mut out, "pooled length: {}", self.observed.total_trigrams);
        report::appendln!(&mut out, "band widths:");
        for (message_key, widths) in &self.band_widths {
            report::appendln!(
                &mut out,
                "  {message_key}: {}",
                report::format_widths(widths)
            );
        }
        report::appendln!(
            &mut out,
            "held fixed: accepted honeycomb traversal and trigram digit order; no standard36 re-selection"
        );
        report::appendln!(
            &mut out,
            "null: verified row-width structure with uniform orientation cells 0..=4, read under the same fixed order"
        );
        report::appendln!(
            &mut out,
            "boundary rule: vertical and same-distance sequence pairs are formed within messages only"
        );
        report::appendln!(&mut out);

        append_honeycomb_pair_section(&mut out, self);
        report::appendln!(&mut out);
        append_honeycomb_position_section(&mut out, self);
        report::appendln!(&mut out);
        append_honeycomb_parity_section(&mut out, self);
        report::appendln!(&mut out);
        append_honeycomb_interpretation(&mut out, self);
        out
    }
}

fn append_honeycomb_pair_section(out: &mut String, report: &HoneycombReport) {
    report::appendln!(out, "vertical adjacency");
    append_pair_stats(out, "vertical same pos", report.observed.vertical);
    append_tail_line(out, "  equality null", report.null.vertical_equal_rate);
    append_tail_line(out, "  mean-diff null", report.null.vertical_mean_abs_diff);
    report::appendln!(out, "same-distance 1D control");
    append_pair_stats(
        out,
        "same lag sequence",
        report.observed.sequence_distance_control,
    );
    append_tail_line(
        out,
        "  equality null",
        report.null.sequence_control_equal_rate,
    );
    append_tail_line(
        out,
        "  mean-diff null",
        report.null.sequence_control_mean_abs_diff,
    );
    report::appendln!(
        out,
        "same-lag note: for the verified accepted honeycomb geometry, the sequence-distance-matched lag pool coincides with the vertical pool; this exposes the sequence-distance confound instead of treating it as independent evidence"
    );
    report::appendln!(
        out,
        "mean-diff caveat: value differences are range-sensitive because the accepted eye stream is bounded to 0..=82 while the uniform cell null can emit 0..=124"
    );
}

fn append_pair_stats(out: &mut String, label: &str, stats: PairStats) {
    report::appendln!(
        out,
        "  {label}: {}/{} = {:.6}; mean |diff| {:.3}",
        stats.exact_equal,
        stats.pairs,
        stats.exact_equal_rate,
        stats.mean_abs_diff
    );
}

fn append_honeycomb_position_section(out: &mut String, report: &HoneycombReport) {
    let stats = report.observed.position_conditioning;
    report::appendln!(out, "position-in-band conditioning");
    report::appendln!(
        out,
        "  trigrams: {}; positions: {}; value bands: {}; chi-square: {:.3}; df: {}",
        stats.total,
        stats.positions,
        stats.value_deciles,
        stats.chi_square,
        stats.degrees_of_freedom
    );
    report::appendln!(
        out,
        "  value-band note: only 7 of 10 decile buckets are reachable because reading-layer values are bounded to 0..=82"
    );
    append_tail_line(out, "  chi-square null", report.null.position_chi_square);
}

fn append_honeycomb_parity_section(out: &mut String, report: &HoneycombReport) {
    let stats = report.observed.parity_split;
    report::appendln!(out, "interlock-parity split");
    report::appendln!(
        out,
        "  upper/lower trigrams: {}/{}; chi-square: {:.3}; df: {}",
        stats.upper_total,
        stats.lower_total,
        stats.chi_square,
        stats.degrees_of_freedom
    );
    append_tail_line(out, "  chi-square null", report.null.parity_chi_square);
    report::appendln!(
        out,
        "  IoC upper/lower/diff: {:.6} / {:.6} / {:.6}",
        stats.upper_ioc,
        stats.lower_ioc,
        stats.ioc_abs_diff
    );
    append_tail_line(out, "  IoC-diff null", report.null.parity_ioc_abs_diff);
}

fn append_tail_line(out: &mut String, label: &str, tail: TailReport) {
    report::appendln!(
        out,
        "{label}: observed {:.6}; null 95% {}; {} {} ({}/{})",
        tail.observed,
        format_honeycomb_band(tail.band),
        tail.tail.label(),
        report::format_probability(tail.empirical_p),
        tail.extreme_count,
        tail.band.trials
    );
}

fn format_honeycomb_band(band: NullBand) -> String {
    format!("{:.6}..{:.6}", band.q025, band.q975)
}

fn append_honeycomb_interpretation(out: &mut String, report: &HoneycombReport) {
    const POINTWISE_ALPHA: f64 = 0.05;
    const BORDERLINE_MARGIN: f64 = 0.01;

    let isolated_2d_tails = [
        report.null.position_chi_square.empirical_p,
        report.null.parity_chi_square.empirical_p,
        report.null.parity_ioc_abs_diff.empirical_p,
    ];
    let strongest_isolated_2d_tail = isolated_2d_tails.iter().copied().fold(1.0, f64::min);
    let strongest_isolated_2d_tail_is_borderline =
        (strongest_isolated_2d_tail - POINTWISE_ALPHA).abs() <= BORDERLINE_MARGIN;
    let vertical_tail_is_small = report.null.vertical_equal_rate.empirical_p <= POINTWISE_ALPHA
        || report.null.vertical_mean_abs_diff.empirical_p <= POINTWISE_ALPHA;

    report::appendln!(
        out,
        "Multiplicity note: this experiment evaluates 7 one-sided 5% statistics (at least one pointwise hit is about 30% under the null), so a single p near 0.05 is expected and is not a finding."
    );
    if strongest_isolated_2d_tail_is_borderline {
        report::appendln!(
            out,
            "Interpretation: the strongest position/parity lattice statistic is a borderline pointwise marginal near the 5% threshold, seed-sensitive at the configured trial count. Recheck only after multiplicity adjustment; this is not a plaintext or decryption claim."
        );
    } else if strongest_isolated_2d_tail <= POINTWISE_ALPHA {
        report::appendln!(
            out,
            "Interpretation: at least one position/parity lattice statistic is outside a one-sided 5% Monte-Carlo tail. Treat that as a structural anomaly to recheck against transcription and configuration choices, not as a plaintext or decryption claim."
        );
    } else {
        report::appendln!(
            out,
            "Interpretation: the position-in-band and parity statistics are inside the sampled fixed-order uniform-grid null at the configured resolution. Together with the same-distance control below, this is a negative isolated-2D spatial-layout result for this accepted honeycomb order, not proof that the glyphs are meaningless."
        );
    }
    if vertical_tail_is_small {
        report::appendln!(
            out,
            "Vertical caveat: the vertical adjacency tail is matched by the same-distance 1D control under this geometry, so it does not isolate physical vertical structure from sequence-distance proximity."
        );
    }
    report::appendln!(
        out,
        "The test is conditional on the accepted honeycomb reading order and deliberately avoids order circularity by not searching or reselecting an order for either eyes or null grids."
    );
}

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

/// Runs the fixed-order honeycomb lattice experiment.
///
/// # Errors
/// Returns [`HoneycombError`] if the corpus grids cannot be reconstructed, the
/// honeycomb geometry fails, or zero null trials were requested.
pub fn run_honeycomb(config: HoneycombConfig) -> Result<HoneycombReport, HoneycombError> {
    if config.trials == 0 {
        return Err(HoneycombError::ZeroTrials);
    }

    let templates = orders::corpus_grids()?;
    let lattices = lattices_for_grids(&templates)?;
    let observed = stats_for_lattices(&lattices);
    let mut samples = NullSamples::default();
    let mut rng = SplitMix64::new(config.seed);

    for _trial in 0..config.trials {
        let grids = random_orientation_grids_like(&templates, &mut rng);
        let generated_lattices = lattices_for_grids(&grids)?;
        samples.push(stats_for_lattices(&generated_lattices));
    }

    Ok(HoneycombReport {
        config,
        order: orders::accepted_honeycomb_order(),
        message_lengths: lattices
            .iter()
            .map(|lattice| (lattice.message_key, lattice.len()))
            .collect(),
        band_widths: lattices
            .iter()
            .map(|lattice| (lattice.message_key, lattice.band_widths()))
            .collect(),
        observed,
        null: samples.report(observed),
    })
}

#[derive(Clone, Copy)]
struct RowPair {
    upper_row: usize,
    lower_row: usize,
    band: usize,
}

fn accepted_honeycomb_permutations() -> (TrigramPermutation, TrigramPermutation) {
    match orders::accepted_honeycomb_order() {
        ReadingOrder::HoneycombStandard { upper, lower } => (upper, lower),
        _ => (TrigramPermutation::IDENTITY, TrigramPermutation::IDENTITY),
    }
}

fn read_lattice_row_pair(
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

fn stats_for_lattices(lattices: &[MessageLattice]) -> HoneycombStats {
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

fn chi_square_independence(rows: &[Vec<usize>]) -> IndependenceStats {
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
struct NullSamples {
    vertical_equal_rate: Vec<f64>,
    vertical_mean_abs_diff: Vec<f64>,
    sequence_control_equal_rate: Vec<f64>,
    sequence_control_mean_abs_diff: Vec<f64>,
    position_chi_square: Vec<f64>,
    parity_chi_square: Vec<f64>,
    parity_ioc_abs_diff: Vec<f64>,
}

impl NullSamples {
    fn push(&mut self, stats: HoneycombStats) {
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

    fn report(&self, observed: HoneycombStats) -> HoneycombNullReport {
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

#[cfg(test)]
mod tests {
    use super::{
        HoneycombCoordinate, HoneycombParity, LatticeTrigram, MessageLattice, RowPair,
        chi_square_independence, lattice_for_grid, read_lattice_row_pair, stats_for_lattices,
    };
    use crate::glyph::Orientation;
    use crate::orders::{self, GlyphGrid};
    use crate::trigram::TrigramValue;

    const FLOAT_EPSILON: f64 = 1.0e-12;

    fn value(raw: u8) -> TrigramValue {
        TrigramValue::new(raw).unwrap()
    }

    fn assert_close(actual: f64, expected: f64, label: &str) {
        let difference = (actual - expected).abs();
        assert!(
            difference <= FLOAT_EPSILON,
            "{label} changed: actual={actual:.17e} expected={expected:.17e} diff={difference:.17e}"
        );
    }

    #[test]
    fn lattice_flattening_reproduces_accepted_honeycomb_order() {
        let grids = orders::corpus_grids().unwrap();
        let order = orders::accepted_honeycomb_order();
        for grid in &grids {
            let lattice = lattice_for_grid(grid).unwrap();
            let flattened = lattice.flattened_values();
            let accepted = orders::read_grid_values(grid, order).unwrap();
            assert_eq!(flattened, accepted, "{}", grid.message_key());
        }
    }

    #[test]
    fn row_pair_coordinates_follow_interlocking_triangle_geometry() {
        let grid = GlyphGrid::from_orientation_rows(
            "fixture",
            vec![
                vec![
                    Orientation::Zero,
                    Orientation::One,
                    Orientation::Two,
                    Orientation::Three,
                    Orientation::Four,
                    Orientation::Zero,
                ],
                vec![
                    Orientation::One,
                    Orientation::Two,
                    Orientation::Three,
                    Orientation::Four,
                    Orientation::Zero,
                    Orientation::One,
                ],
            ],
        );
        let mut sequence_index = 0;
        let trigrams = read_lattice_row_pair(
            &grid,
            RowPair {
                upper_row: 0,
                lower_row: 1,
                band: 0,
            },
            crate::orders::TrigramPermutation::IDENTITY,
            crate::orders::TrigramPermutation::IDENTITY,
            &mut sequence_index,
        )
        .unwrap();

        let observed: Vec<(usize, HoneycombParity, u8)> = trigrams
            .iter()
            .map(|trigram| {
                (
                    trigram.coordinate.pos_in_band,
                    trigram.coordinate.parity,
                    trigram.value.get(),
                )
            })
            .collect();
        assert_eq!(
            observed,
            vec![
                (0, HoneycombParity::Upper, 6),
                (1, HoneycombParity::Lower, 87),
                (2, HoneycombParity::Upper, 99),
                (3, HoneycombParity::Lower, 25),
            ]
        );
        assert_eq!(sequence_index, 4);
    }

    #[test]
    fn statistics_cover_vertical_position_and_parity_signals() {
        let lattice = MessageLattice {
            message_key: "fixture",
            bands: vec![
                vec![
                    trigram(0, 0, HoneycombParity::Upper, 0, 0),
                    trigram(0, 1, HoneycombParity::Lower, 1, 80),
                    trigram(0, 2, HoneycombParity::Upper, 2, 0),
                ],
                vec![
                    trigram(1, 0, HoneycombParity::Upper, 3, 0),
                    trigram(1, 1, HoneycombParity::Lower, 4, 81),
                    trigram(1, 2, HoneycombParity::Upper, 5, 40),
                ],
            ],
        };
        let stats = stats_for_lattices(&[lattice]);

        assert_eq!(stats.total_trigrams, 6);
        assert_eq!(stats.vertical.pairs, 3);
        assert_eq!(stats.vertical.exact_equal, 1);
        assert_close(
            stats.vertical.exact_equal_rate,
            1.0 / 3.0,
            "vertical equality",
        );
        assert_close(
            stats.vertical.mean_abs_diff,
            41.0 / 3.0,
            "vertical mean diff",
        );
        assert_eq!(stats.position_conditioning.total, 6);
        assert_eq!(stats.position_conditioning.positions, 3);
        assert!(stats.position_conditioning.chi_square > 0.0);
        assert_eq!(stats.parity_split.upper_total, 4);
        assert_eq!(stats.parity_split.lower_total, 2);
        assert!(stats.parity_split.chi_square > 0.0);
        assert!(stats.parity_split.ioc_abs_diff > 0.0);
    }

    #[test]
    fn independence_statistic_matches_manual_two_by_two_case() {
        let table = vec![vec![8, 2], vec![2, 8]];
        let stats = chi_square_independence(&table);

        assert_eq!(stats.total, 20);
        assert_eq!(stats.rows, 2);
        assert_eq!(stats.columns, 2);
        assert_eq!(stats.degrees_of_freedom, 1);
        assert_close(stats.chi_square, 7.2, "chi-square");
    }

    #[test]
    fn real_eye_lattice_headline_numbers_are_pinned() {
        let grids = orders::corpus_grids().unwrap();
        let lattices = super::lattices_for_grids(&grids).unwrap();
        let stats = stats_for_lattices(&lattices);

        assert_eq!(stats.total_trigrams, 1036);
        assert_eq!(stats.vertical.pairs, 802);
        assert_eq!(stats.vertical.exact_equal, 13);
        assert_close(
            stats.vertical.exact_equal_rate,
            0.016_209_476_309_226_933,
            "real vertical equality rate",
        );
        assert_close(
            stats.vertical.mean_abs_diff,
            26.862_842_892_768_08,
            "real vertical mean absolute difference",
        );
        assert_eq!(stats.sequence_distance_control.pairs, 802);
        assert_eq!(stats.sequence_distance_control.exact_equal, 13);
        assert_close(
            stats.sequence_distance_control.exact_equal_rate,
            stats.vertical.exact_equal_rate,
            "same-lag control equality rate",
        );
        assert_close(
            stats.sequence_distance_control.mean_abs_diff,
            stats.vertical.mean_abs_diff,
            "same-lag control mean absolute difference",
        );
        assert_eq!(stats.position_conditioning.total, 1036);
        assert_eq!(stats.position_conditioning.positions, 26);
        assert_eq!(stats.position_conditioning.value_deciles, 7);
        assert_eq!(stats.position_conditioning.degrees_of_freedom, 150);
        assert_close(
            stats.position_conditioning.chi_square,
            260.202_406_109_249_75,
            "real position chi-square",
        );
        assert_eq!(stats.parity_split.upper_total, 520);
        assert_eq!(stats.parity_split.lower_total, 516);
        assert_eq!(stats.parity_split.degrees_of_freedom, 82);
        assert_close(
            stats.parity_split.chi_square,
            113.161_658_646_215_14,
            "real parity chi-square",
        );
        assert_close(
            stats.parity_split.upper_ioc,
            0.013_250_333_481_547_354,
            "real upper IoC",
        );
        assert_close(
            stats.parity_split.lower_ioc,
            0.013_637_389_930_006_773,
            "real lower IoC",
        );
        assert_close(
            stats.parity_split.ioc_abs_diff,
            0.000_387_056_448_459_419_1,
            "real parity IoC divergence",
        );
    }

    fn trigram(
        band: usize,
        pos_in_band: usize,
        parity: HoneycombParity,
        sequence_index: usize,
        raw_value: u8,
    ) -> LatticeTrigram {
        LatticeTrigram {
            coordinate: HoneycombCoordinate {
                band,
                pos_in_band,
                parity,
                sequence_index,
            },
            value: value(raw_value),
        }
    }
}

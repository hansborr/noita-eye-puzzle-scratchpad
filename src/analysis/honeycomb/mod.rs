//! Honeycomb two-dimensional lattice-structure experiment.
//!
//! This module keeps the accepted Toboter-style honeycomb reading order fixed
//! and asks whether the physical row-pair lattice carries structure beyond the
//! one-dimensional stream. Each emitted trigram is tagged with its row-pair
//! band, its position inside that band, and the interlocking-triangle parity
//! from the same row-pair geometry used by [`crate::analysis::orders`].
//!
//! The null preserves the verified row widths, fills rendered cells uniformly
//! from orientation digits `0..=4`, and reuses the fixed accepted honeycomb
//! traversal without reselecting among standard36 permutations.

use std::fmt;

use crate::analysis::orders::{self, GridError, ReadingOrder};
use crate::core::trigram::TrigramValue;
use crate::nulls::null::{SplitMix64, random_orientation_grids_like};

/// Default deterministic Monte-Carlo seed for the honeycomb lattice null.
pub const DEFAULT_SEED: u64 = 0x686f_6e65_7963_6f6d;
/// Default Monte-Carlo trial count for the honeycomb lattice null.
pub const DEFAULT_TRIALS: usize = 1_000;

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
    /// First branch in [`crate::analysis::orders`] row-pair geometry.
    Upper,
    /// Second branch in [`crate::analysis::orders`] row-pair geometry.
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

mod compute;
mod report;

use compute::{NullSamples, stats_for_lattices};
pub use compute::{lattice_for_grid, lattices_for_grids};

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

#[cfg(test)]
mod tests;

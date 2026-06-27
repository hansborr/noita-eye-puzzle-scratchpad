//! First-order conditional structure and successor-graph experiment.
//!
//! This experiment is mapping-independent: it runs directly on the accepted
//! honeycomb reading-layer trigram values (`0..=82`) and never scores a
//! candidate plaintext language. Message boundaries are preserved throughout,
//! so no transition is formed across a join between the nine verified messages.

use std::fmt;

use crate::analysis::orders::{
    self, GlyphGrid, GridError, ReadingOrder, read_corpus_message_values,
};
use crate::core::trigram::TrigramValue;
use crate::nulls::null::F64Band;

mod nulls;
mod report;
#[cfg(test)]
mod tests;
mod transition;

use nulls::{bias_calibration, no_repeat_null_comparisons, null_comparisons, planted_controls};
use transition::{first_order_stats, matrix_cell_count};

const ADD_CONSTANT_ALPHA: f64 = 1.0;
const NO_REPEAT_BURN_IN_SWEEPS: usize = 100;
const NO_REPEAT_SAMPLE_SWEEPS: usize = 20;
const CONTROL_PATTERN: [usize; 24] = [
    0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 8, 9, 10, 11, 8, 9, 10, 11, 12, 13, 14, 15,
];

/// Default base seed for the conditional-structure shuffle null.
pub const DEFAULT_SEED: u64 = 0x6669_7273_746f_7264;
/// Default number of independent seed streams.
pub const DEFAULT_SEED_COUNT: usize = 5;
/// Default within-seed shuffle trials.
pub const DEFAULT_TRIALS_PER_SEED: usize = 1_000;
/// Accepted reading-layer alphabet size for this experiment.
pub const DEFAULT_ALPHABET_SIZE: usize = orders::READING_LAYER_ALPHABET_SIZE;

/// Configuration for the first-order conditional-structure experiment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConditionalStructureConfig {
    /// Base seed used to derive independent deterministic seed streams.
    pub seed: u64,
    /// Number of independent seed streams.
    pub seed_count: usize,
    /// Number of within-message shuffles sampled per seed stream.
    pub trials_per_seed: usize,
    /// Reading-layer alphabet size. The verified eye stream uses `83`.
    pub alphabet_size: usize,
}

impl Default for ConditionalStructureConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_SEED,
            seed_count: DEFAULT_SEED_COUNT,
            trials_per_seed: DEFAULT_TRIALS_PER_SEED,
            alphabet_size: DEFAULT_ALPHABET_SIZE,
        }
    }
}

impl ConditionalStructureConfig {
    /// Returns the total number of Monte-Carlo samples.
    ///
    /// # Errors
    /// Returns [`ConditionalStructureError::TrialCountTooLarge`] if the
    /// multiplication overflows.
    pub fn total_trials(self) -> Result<usize, ConditionalStructureError> {
        self.seed_count
            .checked_mul(self.trials_per_seed)
            .ok_or(ConditionalStructureError::TrialCountTooLarge)
    }
}

/// Error returned by the first-order conditional-structure experiment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConditionalStructureError {
    /// The verified corpus could not be reconstructed or read.
    Grid(GridError),
    /// At least one seed stream is required.
    ZeroSeeds,
    /// At least one shuffle trial per seed is required.
    ZeroTrials,
    /// The configured alphabet size was empty or cannot fit in `TrigramValue`.
    InvalidAlphabetSize {
        /// Requested alphabet size.
        alphabet_size: usize,
    },
    /// A checked Monte-Carlo trial count overflowed.
    TrialCountTooLarge,
    /// A checked matrix size overflowed.
    MatrixTooLarge {
        /// Requested alphabet size.
        alphabet_size: usize,
    },
    /// A stream value fell outside the configured alphabet.
    ValueOutsideAlphabet {
        /// Message key for the offending value.
        message_key: &'static str,
        /// Offending value.
        value: u8,
        /// Configured alphabet size.
        alphabet_size: usize,
    },
    /// A bounded PRNG draw could not represent the requested upper bound.
    RandomBoundTooLarge {
        /// Requested exclusive upper bound.
        bound: usize,
    },
    /// The no-repeat conditioned null was requested for a message that already
    /// contains an adjacent-equal transition.
    NoRepeatNullRequiresNoAdjacentEqual {
        /// Message key for the offending message.
        message_key: &'static str,
    },
}

impl fmt::Display for ConditionalStructureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Grid(grid_error) => write!(f, "grid/order error: {grid_error:?}"),
            Self::ZeroSeeds => write!(f, "at least one seed stream is required"),
            Self::ZeroTrials => write!(f, "at least one shuffle trial per seed is required"),
            Self::InvalidAlphabetSize { alphabet_size } => {
                write!(f, "invalid alphabet size {alphabet_size}; expected 1..=125")
            }
            Self::TrialCountTooLarge => write!(f, "Monte-Carlo trial count is too large"),
            Self::MatrixTooLarge { alphabet_size } => {
                write!(
                    f,
                    "transition matrix for alphabet size {alphabet_size} is too large"
                )
            }
            Self::ValueOutsideAlphabet {
                message_key,
                value,
                alphabet_size,
            } => write!(
                f,
                "{message_key}: reading-layer value {value} is outside alphabet size {alphabet_size}"
            ),
            Self::RandomBoundTooLarge { bound } => {
                write!(f, "random draw bound {bound} is too large")
            }
            Self::NoRepeatNullRequiresNoAdjacentEqual { message_key } => write!(
                f,
                "{message_key}: no-repeat conditioned null requires an input with no adjacent-equal transitions"
            ),
        }
    }
}

impl std::error::Error for ConditionalStructureError {}
impl From<GridError> for ConditionalStructureError {
    fn from(value: GridError) -> Self {
        Self::Grid(value)
    }
}

impl From<crate::nulls::null::RandomBoundError> for ConditionalStructureError {
    fn from(error: crate::nulls::null::RandomBoundError) -> Self {
        Self::RandomBoundTooLarge { bound: error.bound }
    }
}

/// Entropy and mutual-information estimates for the transition matrix.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EntropyEstimates {
    /// Number of within-message transitions.
    pub transitions: usize,
    /// Maximum possible entropy over the configured alphabet.
    pub max_entropy_bits: f64,
    /// Plug-in entropy of next-symbol marginals.
    pub next_entropy_mle_bits: f64,
    /// Add-constant corrected entropy of next-symbol marginals.
    pub next_entropy_corrected_bits: f64,
    /// Plug-in conditional entropy `H(next | current)`.
    pub conditional_entropy_mle_bits: f64,
    /// Add-constant corrected conditional entropy `H(next | current)`.
    pub conditional_entropy_corrected_bits: f64,
    /// Plug-in first-order mutual information.
    pub mutual_information_mle_bits: f64,
    /// Add-constant corrected first-order mutual information.
    pub mutual_information_corrected_bits: f64,
    /// Additive pseudo-count used by the corrected entropy estimates.
    pub add_constant_alpha: f64,
}

/// Pearson transition-independence chi-square summary.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TransitionChiSquare {
    /// Pearson statistic over active row and column marginals.
    pub statistic: f64,
    /// Asymptotic degrees of freedom, `(active_rows - 1) * (active_cols - 1)`.
    pub degrees_of_freedom: usize,
    /// Rows with at least one outgoing transition.
    pub active_rows: usize,
    /// Columns with at least one incoming transition.
    pub active_columns: usize,
    /// Active row/column cells included in the Pearson sum.
    pub expected_cells: usize,
    /// Included cells with expected count below `1`.
    pub expected_lt_1_cells: usize,
    /// Included cells with expected count below `5`.
    pub expected_lt_5_cells: usize,
}

/// Diagonal contribution from adjacent-equal `x -> x` transitions.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DiagonalTransitionSummary {
    /// Total observed self-transitions on the diagonal.
    pub self_transitions: usize,
    /// Diagonal cells with at least one observed self-transition.
    pub self_transition_edges: usize,
    /// Expected self-transition count under the fitted independence marginals.
    pub expected_self_transitions_independence: f64,
    /// Pearson statistic contribution from the diagonal cells.
    pub chi_square_contribution: f64,
}

/// Transition summary after omitting diagonal `x -> x` cells.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct OffDiagonalTransitionSummary {
    /// Off-diagonal matrix cells, `alphabet_size * (alphabet_size - 1)`.
    pub matrix_cells: usize,
    /// Nonzero directed successor edges with distinct source and target.
    pub distinct_successor_edges: usize,
    /// Nonzero off-diagonal edge density.
    pub edge_density: f64,
    /// Pearson statistic contribution after omitting diagonal cells.
    pub chi_square_statistic: f64,
    /// Active row/column off-diagonal cells included in the Pearson sum.
    pub expected_cells: usize,
    /// Included off-diagonal cells with expected count below `1`.
    pub expected_lt_1_cells: usize,
    /// Included off-diagonal cells with expected count below `5`.
    pub expected_lt_5_cells: usize,
}

/// Sparse transition-matrix occupancy summary.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TransitionMatrixSummary {
    /// Configured alphabet size.
    pub alphabet_size: usize,
    /// Total observed symbols across messages.
    pub symbols: usize,
    /// Total within-message transitions.
    pub transitions: usize,
    /// Matrix cells, `alphabet_size * alphabet_size`.
    pub matrix_cells: usize,
    /// Cells with at least one observed transition.
    pub nonzero_cells: usize,
    /// Nonzero-cell density over all matrix cells.
    pub density: f64,
    /// Mean observed transitions per matrix cell.
    pub mean_transitions_per_cell: f64,
    /// Mean observed symbols per alphabet value.
    pub mean_symbols_per_value: f64,
}

/// Successor graph and deterministic-FSM lower-bound summary.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SuccessorGraphSummary {
    /// Symbols observed anywhere in the corpus.
    pub observed_symbols: usize,
    /// Symbols observed as a transition source.
    pub active_sources: usize,
    /// Symbols observed as a transition target.
    pub active_targets: usize,
    /// Distinct directed successor edges.
    pub distinct_successor_edges: usize,
    /// Directed-edge density over the full configured alphabet square.
    pub edge_density: f64,
    /// Mean out-degree among active source symbols.
    pub mean_out_degree: f64,
    /// Largest source-symbol out-degree.
    pub max_out_degree: usize,
    /// Observed symbols with no outgoing edge because they occur only at
    /// message ends.
    pub observed_zero_out_degree_symbols: usize,
    /// Unweighted mean of per-source empirical successor entropy.
    pub successor_entropy_bits: f64,
    /// Entropy of the observed-symbol out-degree histogram.
    pub out_degree_entropy_bits: f64,
    /// Greedy lower bound on deterministic emit-then-transition FSM states.
    ///
    /// Each observed symbol needs at least one hidden state, and a symbol with
    /// `d` distinct next symbols needs at least `d` hidden states labelled with
    /// that symbol.
    pub greedy_fsm_state_lower_bound: usize,
}

/// Complete first-order statistic bundle for one set of messages.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FirstOrderStats {
    /// Matrix occupancy summary.
    pub matrix: TransitionMatrixSummary,
    /// Entropy and mutual-information estimates.
    pub entropy: EntropyEstimates,
    /// Transition-independence chi-square summary.
    pub chi_square: TransitionChiSquare,
    /// Diagonal/self-transition contribution.
    pub diagonal: DiagonalTransitionSummary,
    /// Off-diagonal-only transition statistics.
    pub off_diagonal: OffDiagonalTransitionSummary,
    /// Successor graph summary.
    pub graph: SuccessorGraphSummary,
}

/// A scalar statistic compared against the shuffle null.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConditionalStatistic {
    /// Add-constant corrected `H(next)`.
    NextEntropyCorrected,
    /// Add-constant corrected `H(next | current)`.
    ConditionalEntropyCorrected,
    /// Add-constant corrected first-order mutual information.
    MutualInformationCorrected,
    /// Pearson transition-independence chi-square statistic.
    TransitionChiSquare,
    /// Pearson transition statistic with diagonal cells omitted.
    TransitionChiSquareOffDiagonal,
    /// Distinct directed successor edges.
    DistinctSuccessorEdges,
    /// Distinct directed successor edges with diagonal cells omitted.
    DistinctSuccessorEdgesOffDiagonal,
    /// Total adjacent-equal self-transitions.
    SelfTransitions,
    /// Unweighted mean per-source successor entropy.
    SuccessorEntropy,
    /// Greedy deterministic-FSM state lower bound.
    GreedyFsmStateLowerBound,
}

impl ConditionalStatistic {
    /// Stable report label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NextEntropyCorrected => "H(next) add-1 bits",
            Self::ConditionalEntropyCorrected => "H(next|cur) add-1 bits",
            Self::MutualInformationCorrected => "MI add-1 bits",
            Self::TransitionChiSquare => "transition chi2",
            Self::TransitionChiSquareOffDiagonal => "offdiag transition chi2",
            Self::DistinctSuccessorEdges => "successor edges",
            Self::DistinctSuccessorEdgesOffDiagonal => "offdiag successor edges",
            Self::SelfTransitions => "self transitions",
            Self::SuccessorEntropy => "successor entropy",
            Self::GreedyFsmStateLowerBound => "FSM lower bound",
        }
    }
}

/// Sampled scalar null band.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ScalarNullBand {
    /// Number of sampled null trials.
    pub trials: usize,
    /// Sample mean.
    pub mean: f64,
    /// Sample minimum.
    pub min: f64,
    /// Lower pointwise 95% percentile edge.
    pub q025: f64,
    /// Sample median.
    pub median: f64,
    /// Upper pointwise 95% percentile edge.
    pub q975: f64,
    /// Sample maximum.
    pub max: f64,
}

impl From<F64Band> for ScalarNullBand {
    fn from(band: F64Band) -> Self {
        Self {
            trials: band.trials,
            mean: band.mean,
            min: band.min,
            q025: band.q025,
            median: band.median,
            q975: band.q975,
            max: band.max,
        }
    }
}

/// Real-vs-null comparison for one scalar statistic.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NullComparison {
    /// Statistic being compared.
    pub statistic: ConditionalStatistic,
    /// Real observed statistic.
    pub observed: f64,
    /// Shuffle-null band.
    pub null: ScalarNullBand,
    /// Count of shuffles with statistic less than or equal to observed.
    pub lower_tail_count: usize,
    /// Count of shuffles with statistic greater than or equal to observed.
    pub upper_tail_count: usize,
    /// Two-sided add-one empirical p-value.
    pub two_sided_add_one_p: f64,
    /// Whether observed is outside the pointwise 95% null interval.
    pub outside_pointwise_95: bool,
}

/// Flat-random calibration for mutual-information estimator bias.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BiasCalibrationReport {
    /// Number of flat-random streams sampled.
    pub trials: usize,
    /// Alphabet size used for the flat streams.
    pub alphabet_size: usize,
    /// True first-order mutual information for the generating model.
    pub true_mutual_information_bits: f64,
    /// Plug-in mutual-information null band.
    pub mle_mutual_information: ScalarNullBand,
    /// Add-constant corrected mutual-information null band.
    pub corrected_mutual_information: ScalarNullBand,
    /// Mean absolute plug-in mutual information.
    pub mle_mean_abs_mutual_information_bits: f64,
    /// Mean absolute add-constant corrected mutual information.
    pub corrected_mean_abs_mutual_information_bits: f64,
}

/// One planted control row and its own shuffle-null comparison.
#[derive(Clone, Debug, PartialEq)]
pub struct PlantedControlReport {
    /// Human-readable control label.
    pub label: &'static str,
    /// Construction note.
    pub construction: &'static str,
    /// Observed first-order statistics.
    pub observed: FirstOrderStats,
    /// Statistic comparisons against this control's own shuffle null.
    pub comparisons: Vec<NullComparison>,
}

/// Positive controls for the conditional-structure panel.
#[derive(Clone, Debug, PartialEq)]
pub struct PlantedControlsReport {
    /// Static monoalphabetic image of a structured source.
    pub static_monoalphabetic: PlantedControlReport,
    /// Position-dependent deck-permuted image of the same source.
    pub deck_permuted: PlantedControlReport,
}

/// No-repeat-conditioned null based on a symmetric within-message swap chain.
#[derive(Clone, Debug, PartialEq)]
pub struct NoRepeatNullReport {
    /// Number of full-message swap sweeps discarded before sampling each seed.
    pub burn_in_sweeps: usize,
    /// Number of full-message swap sweeps between recorded samples.
    pub sample_sweeps: usize,
    /// Real-vs-null comparisons under the no-adjacent-equal constraint.
    pub comparisons: Vec<NullComparison>,
}

/// Complete first-order conditional-structure report.
#[derive(Clone, Debug, PartialEq)]
pub struct ConditionalStructureReport {
    /// Configuration used for the run.
    pub config: ConditionalStructureConfig,
    /// Reading order used for the real stream.
    pub order: ReadingOrder,
    /// Per-message reading-layer lengths in corpus order.
    pub message_lengths: Vec<(&'static str, usize)>,
    /// Observed first-order statistics for the eye stream.
    pub observed: FirstOrderStats,
    /// Real-vs-shuffle comparisons for the eye stream.
    pub comparisons: Vec<NullComparison>,
    /// Real-vs-shuffle comparisons after conditioning shuffles on no repeats.
    pub no_repeat_null: NoRepeatNullReport,
    /// Flat-random bias calibration for the entropy estimator.
    pub bias_calibration: BiasCalibrationReport,
    /// Planted positive controls.
    pub controls: PlantedControlsReport,
}

macro_rules! renderln {
    ($out:expr $(,)?) => {
        report::appendln!($out)
    };
    ($out:expr, $($arg:tt)*) => {
        report::appendln!($out, $($arg)*)
    };
}
pub(crate) use renderln;

const PRIMARY_CONDITIONAL_REPORT_STATISTICS: [ConditionalStatistic; 7] = [
    ConditionalStatistic::NextEntropyCorrected,
    ConditionalStatistic::ConditionalEntropyCorrected,
    ConditionalStatistic::MutualInformationCorrected,
    ConditionalStatistic::TransitionChiSquare,
    ConditionalStatistic::DistinctSuccessorEdges,
    ConditionalStatistic::SuccessorEntropy,
    ConditionalStatistic::GreedyFsmStateLowerBound,
];

/// Runs the first-order conditional-structure experiment on the verified corpus.
///
/// # Errors
/// Returns [`ConditionalStructureError`] if the corpus cannot be reconstructed,
/// the accepted order cannot be read, or the configuration is invalid.
pub fn run_conditional_structure(
    config: ConditionalStructureConfig,
) -> Result<ConditionalStructureReport, ConditionalStructureError> {
    let grids = orders::corpus_grids()?;
    let keys = grids.iter().map(GlyphGrid::message_key).collect::<Vec<_>>();
    let order = orders::accepted_honeycomb_order();
    let messages = read_corpus_message_values(&grids, order)?;
    report_from_message_values(config, order, &keys, &messages)
}

fn report_from_message_values(
    config: ConditionalStructureConfig,
    order: ReadingOrder,
    keys: &[&'static str],
    messages: &[Vec<TrigramValue>],
) -> Result<ConditionalStructureReport, ConditionalStructureError> {
    validate_config(config)?;
    let observed = first_order_stats(keys, messages, config.alphabet_size)?;
    let comparisons = null_comparisons(config, keys, messages, &observed)?;
    let no_repeat_null = no_repeat_null_comparisons(config, keys, messages, &observed)?;
    let lengths = messages.iter().map(Vec::len).collect::<Vec<_>>();
    let bias_calibration = bias_calibration(config, &lengths)?;
    let controls = planted_controls(config, &lengths)?;

    Ok(ConditionalStructureReport {
        config,
        order,
        message_lengths: keys.iter().copied().zip(lengths).collect(),
        observed,
        comparisons,
        no_repeat_null,
        bias_calibration,
        controls,
    })
}

fn validate_config(config: ConditionalStructureConfig) -> Result<(), ConditionalStructureError> {
    if config.seed_count == 0 {
        return Err(ConditionalStructureError::ZeroSeeds);
    }
    if config.trials_per_seed == 0 {
        return Err(ConditionalStructureError::ZeroTrials);
    }
    if config.alphabet_size == 0 || config.alphabet_size > 125 {
        return Err(ConditionalStructureError::InvalidAlphabetSize {
            alphabet_size: config.alphabet_size,
        });
    }
    let _total_trials = config.total_trials()?;
    let _matrix_cells = matrix_cell_count(config.alphabet_size)?;
    Ok(())
}

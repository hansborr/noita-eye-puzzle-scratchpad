//! First-order conditional structure and successor-graph experiment.
//!
//! This experiment is mapping-independent: it runs directly on the accepted
//! honeycomb reading-layer trigram values (`0..=82`) and never scores a
//! candidate plaintext language. Message boundaries are preserved throughout,
//! so no transition is formed across a join between the nine verified messages.

use std::collections::BTreeMap;
use std::fmt;

use crate::null::{
    F64Band, NullSampler, SplitMix64, WithinMessageShuffle, f64_band, fisher_yates,
    random_index_below,
};
use crate::orders::{self, GlyphGrid, GridError, ReadingOrder, read_corpus_message_values};
use crate::report::{self, Report};
use crate::trigram::TrigramValue;

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

impl From<crate::null::RandomBoundError> for ConditionalStructureError {
    fn from(error: crate::null::RandomBoundError) -> Self {
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

const PRIMARY_CONDITIONAL_REPORT_STATISTICS: [ConditionalStatistic; 7] = [
    ConditionalStatistic::NextEntropyCorrected,
    ConditionalStatistic::ConditionalEntropyCorrected,
    ConditionalStatistic::MutualInformationCorrected,
    ConditionalStatistic::TransitionChiSquare,
    ConditionalStatistic::DistinctSuccessorEdges,
    ConditionalStatistic::SuccessorEntropy,
    ConditionalStatistic::GreedyFsmStateLowerBound,
];

impl Report for ConditionalStructureReport {
    fn render(&self) -> String {
        let report = self;
        let mut out = String::new();
        let total_trials = report
            .config
            .seed_count
            .saturating_mul(report.config.trials_per_seed);
        renderln!(
            &mut out,
            "first-order conditional structure & successor graph"
        );
        renderln!(&mut out, "order: {}", report.order.name());
        renderln!(
            &mut out,
            "alphabet: accepted honeycomb reading-layer values 0..={}",
            report.config.alphabet_size.saturating_sub(1)
        );
        renderln!(&mut out, "base seed: {}", report.config.seed);
        renderln!(
            &mut out,
            "shuffle null: {} seeds x {} trials/seed = {} within-message multiset-preserving shuffles",
            report.config.seed_count,
            report.config.trials_per_seed,
            total_trials
        );
        renderln!(
            &mut out,
            "no-repeat null: symmetric swap-chain shuffles conditioned on zero adjacent-equal pairs ({} burn-in sweeps, {} sweeps/sample)",
            report.no_repeat_null.burn_in_sweeps,
            report.no_repeat_null.sample_sweeps
        );
        renderln!(
            &mut out,
            "message lengths: {}",
            report::format_message_lengths(&report.message_lengths)
        );
        renderln!(
            &mut out,
            "boundary rule: transitions are counted within each message only; no transition crosses a message join"
        );
        renderln!(
            &mut out,
            "low-power caveat: {} symbols, {} transitions, and {} cells in an {}x{} matrix (mean {:.3} transitions/cell; {:.2} symbols/value). An inside-shuffle row is only a null-comparison result at this corpus size, not proof of memorylessness.",
            report.observed.matrix.symbols,
            report.observed.matrix.transitions,
            report.observed.matrix.matrix_cells,
            report.observed.matrix.alphabet_size,
            report.observed.matrix.alphabet_size,
            report.observed.matrix.mean_transitions_per_cell,
            report.observed.matrix.mean_symbols_per_value
        );
        renderln!(
            &mut out,
            "entropy correction: add-constant alpha={:.1} over the full {}-symbol next-state support; raw plug-in MI is shown only as a sparse-sample diagnostic",
            report.observed.entropy.add_constant_alpha,
            report.config.alphabet_size
        );
        renderln!(&mut out);
        append_conditional_observed(&mut out, report);
        renderln!(&mut out);
        append_conditional_comparisons(&mut out, report);
        renderln!(&mut out);
        append_conditional_diagonal_accounting(&mut out, report);
        renderln!(&mut out);
        append_conditional_no_repeat_comparisons(&mut out, report);
        renderln!(&mut out);
        append_conditional_bias_calibration(&mut out, report);
        renderln!(&mut out);
        append_conditional_controls(&mut out, report);
        renderln!(&mut out);
        append_conditional_interpretation(&mut out, report);
        out
    }
}

fn append_conditional_observed(out: &mut String, report: &ConditionalStructureReport) {
    let observed = report.observed;
    renderln!(out, "observed transition matrix");
    renderln!(
        out,
        "  nonzero cells: {}/{} ({:.3}% density)",
        observed.matrix.nonzero_cells,
        observed.matrix.matrix_cells,
        observed.matrix.density * 100.0
    );
    renderln!(
        out,
        "  active rows/cols: {}/{}; chi2 df {}; expected cells <1/<5: {}/{}",
        observed.chi_square.active_rows,
        observed.chi_square.active_columns,
        observed.chi_square.degrees_of_freedom,
        observed.chi_square.expected_lt_1_cells,
        observed.chi_square.expected_lt_5_cells
    );
    renderln!(
        out,
        "  H(next) raw/corrected: {:.4}/{:.4} bits; H(next|current) raw/corrected: {:.4}/{:.4} bits",
        observed.entropy.next_entropy_mle_bits,
        observed.entropy.next_entropy_corrected_bits,
        observed.entropy.conditional_entropy_mle_bits,
        observed.entropy.conditional_entropy_corrected_bits
    );
    renderln!(
        out,
        "  MI raw/corrected: {:.4}/{:.6} bits; G raw/corrected from MI: {:.1}/{:.3}; Pearson chi2: {:.3}",
        observed.entropy.mutual_information_mle_bits,
        observed.entropy.mutual_information_corrected_bits,
        likelihood_ratio_g_from_mi_bits(
            observed.entropy.transitions,
            observed.entropy.mutual_information_mle_bits
        ),
        likelihood_ratio_g_from_mi_bits(
            observed.entropy.transitions,
            observed.entropy.mutual_information_corrected_bits
        ),
        observed.chi_square.statistic
    );
    renderln!(
        out,
        "  diagonal: {} self-transitions in {} cells; fitted-independence expectation {:.2}; diagonal Pearson contribution {:.3}",
        observed.diagonal.self_transitions,
        report.config.alphabet_size,
        observed.diagonal.expected_self_transitions_independence,
        observed.diagonal.chi_square_contribution
    );
    renderln!(
        out,
        "  off-diagonal: {} edges over {} cells ({:.3}% density); chi2 contribution {:.3}; expected cells <1/<5: {}/{}",
        observed.off_diagonal.distinct_successor_edges,
        observed.off_diagonal.matrix_cells,
        observed.off_diagonal.edge_density * 100.0,
        observed.off_diagonal.chi_square_statistic,
        observed.off_diagonal.expected_lt_1_cells,
        observed.off_diagonal.expected_lt_5_cells
    );
    renderln!(
        out,
        "  successor graph: {} edges, mean out-degree {:.2}, max out-degree {}, successor entropy {:.4} bits, out-degree entropy {:.4} bits, FSM lower bound {} states",
        observed.graph.distinct_successor_edges,
        observed.graph.mean_out_degree,
        observed.graph.max_out_degree,
        observed.graph.successor_entropy_bits,
        observed.graph.out_degree_entropy_bits,
        observed.graph.greedy_fsm_state_lower_bound
    );
}

fn append_conditional_comparisons(out: &mut String, report: &ConditionalStructureReport) {
    renderln!(
        out,
        "within-message shuffle comparisons (unconstrained, diagonal included)"
    );
    renderln!(
        out,
        "{:<25} {:>12} {:>12} {:>19} {:>12} {:>10}",
        "statistic",
        "observed",
        "null med",
        "null 95%",
        "p two-sided",
        "flag"
    );
    for statistic in PRIMARY_CONDITIONAL_REPORT_STATISTICS {
        if let Some(row) = comparison_for_statistic(&report.comparisons, statistic) {
            append_conditional_comparison_row(out, row);
        }
    }
    renderln!(
        out,
        "p-values are two-sided add-one empirical values and pointwise over {} displayed statistics; no family-wise correction is claimed.",
        PRIMARY_CONDITIONAL_REPORT_STATISTICS.len()
    );
}

fn append_conditional_diagonal_accounting(out: &mut String, report: &ConditionalStructureReport) {
    let observed = report.observed;
    renderln!(out, "diagonal/no-repeat accounting");
    if let Some(row) =
        comparison_for_statistic(&report.comparisons, ConditionalStatistic::SelfTransitions)
    {
        renderln!(
            out,
            "  self transitions: eyes {}, unconstrained shuffle mean {:.2}, 95% {}, p {}; fitted-independence expectation {:.2}",
            format_conditional_statistic(row.statistic, row.observed),
            row.null.mean,
            format_conditional_band(row.statistic, row.null),
            report::format_probability(row.two_sided_add_one_p),
            observed.diagonal.expected_self_transitions_independence
        );
    }
    if let Some(row) = comparison_for_statistic(
        &report.comparisons,
        ConditionalStatistic::DistinctSuccessorEdgesOffDiagonal,
    ) {
        renderln!(
            out,
            "  off-diagonal successor edges vs unconstrained shuffle: eyes {}, 95% {}, flag {}",
            format_conditional_statistic(row.statistic, row.observed),
            format_conditional_band(row.statistic, row.null),
            conditional_flag(row)
        );
    }
    if let Some(row) = comparison_for_statistic(
        &report.comparisons,
        ConditionalStatistic::TransitionChiSquareOffDiagonal,
    ) {
        renderln!(
            out,
            "  off-diagonal Pearson contribution vs unconstrained shuffle: eyes {}, 95% {}, flag {}",
            format_conditional_statistic(row.statistic, row.observed),
            format_conditional_band(row.statistic, row.null),
            conditional_flag(row)
        );
    }
    renderln!(
        out,
        "  diagonal Pearson contribution is {:.3} of the full {:.3}; dropping diagonal cells is a diagnostic, while the no-repeat null below conditions the shuffles on the known zero-adjacency constraint.",
        observed.diagonal.chi_square_contribution,
        observed.chi_square.statistic
    );
}

fn append_conditional_no_repeat_comparisons(out: &mut String, report: &ConditionalStructureReport) {
    renderln!(out, "no-repeat-conditioned shuffle comparisons");
    renderln!(
        out,
        "{:<25} {:>12} {:>12} {:>19} {:>12} {:>10}",
        "statistic",
        "observed",
        "null med",
        "null 95%",
        "p two-sided",
        "flag"
    );
    for row in &report.no_repeat_null.comparisons {
        append_conditional_comparison_row(out, row);
    }
    renderln!(
        out,
        "The chain preserves each message multiset and rejects swaps that would create x->x; p-values are empirical over recorded chain states, not asymptotic chi-square tails."
    );
}

fn append_conditional_comparison_row(out: &mut String, row: &NullComparison) {
    renderln!(
        out,
        "{:<25} {:>12} {:>12} {:>19} {:>12} {:>10}",
        row.statistic.label(),
        format_conditional_statistic(row.statistic, row.observed),
        format_conditional_statistic(row.statistic, row.null.median),
        format_conditional_band(row.statistic, row.null),
        report::format_probability(row.two_sided_add_one_p),
        conditional_flag(row)
    );
}

fn conditional_flag(row: &NullComparison) -> &'static str {
    if row.outside_pointwise_95 {
        "pt95-out"
    } else {
        "inside"
    }
}

fn append_conditional_bias_calibration(out: &mut String, report: &ConditionalStructureReport) {
    let calibration = report.bias_calibration;
    renderln!(out, "flat-random estimator-bias calibration (true MI = 0)");
    renderln!(
        out,
        "  trials: {}; alphabet: {}; matched message lengths",
        calibration.trials,
        calibration.alphabet_size
    );
    renderln!(
        out,
        "  plug-in MI mean {:.4}, abs-mean {:.4}, 95% {}",
        calibration.mle_mutual_information.mean,
        calibration.mle_mean_abs_mutual_information_bits,
        format_conditional_band(
            ConditionalStatistic::MutualInformationCorrected,
            calibration.mle_mutual_information
        )
    );
    renderln!(
        out,
        "  add-1 MI mean {:.6}, abs-mean {:.6}, 95% {}",
        calibration.corrected_mutual_information.mean,
        calibration.corrected_mean_abs_mutual_information_bits,
        format_conditional_band(
            ConditionalStatistic::MutualInformationCorrected,
            calibration.corrected_mutual_information
        )
    );
}

fn append_conditional_controls(out: &mut String, report: &ConditionalStructureReport) {
    renderln!(out, "planted structure controls");
    renderln!(
        out,
        "{:<27} {:>8} {:>10} {:>19} {:>8} {:>17} {:>9} {:>10}",
        "control",
        "MI raw",
        "MI add-1",
        "MI null 95%",
        "edges",
        "edge null 95%",
        "FSM lb",
        "verdict"
    );
    for control in [
        &report.controls.static_monoalphabetic,
        &report.controls.deck_permuted,
    ] {
        let mi = conditional_comparison(control, ConditionalStatistic::MutualInformationCorrected);
        let edges = conditional_comparison(control, ConditionalStatistic::DistinctSuccessorEdges);
        let verdict = conditional_control_verdict(control);
        renderln!(
            out,
            "{:<27} {:>8.3} {:>10} {:>19} {:>8} {:>17} {:>9} {:>10}",
            control.label,
            control.observed.entropy.mutual_information_mle_bits,
            mi.map_or_else(
                || "n/a".to_owned(),
                |row| format_conditional_statistic(row.statistic, row.observed)
            ),
            mi.map_or_else(
                || "n/a".to_owned(),
                |row| format_conditional_band(row.statistic, row.null)
            ),
            edges.map_or_else(
                || "n/a".to_owned(),
                |row| format_conditional_statistic(row.statistic, row.observed)
            ),
            edges.map_or_else(
                || "n/a".to_owned(),
                |row| format_conditional_band(row.statistic, row.null)
            ),
            control.observed.graph.greedy_fsm_state_lower_bound,
            verdict
        );
    }
    renderln!(
        out,
        "control construction: {}; {}.",
        report.controls.static_monoalphabetic.construction,
        report.controls.deck_permuted.construction
    );
}

fn append_conditional_interpretation(out: &mut String, report: &ConditionalStructureReport) {
    let primary_outliers = conditional_primary_outliers(report);
    let off_diagonal_outliers = conditional_off_diagonal_outliers(report);
    let no_repeat_outliers = conditional_no_repeat_outliers(report);

    append_conditional_outlier_framing(
        out,
        report,
        &primary_outliers,
        &off_diagonal_outliers,
        &no_repeat_outliers,
    );
    append_conditional_effect_size(out, report);
    append_conditional_sparse_caveat(out, report);
    renderln!(
        out,
        "Raw unconstrained exceedances are dominated by the known zero-adjacency constraint (above). Any exceedances that survive the no-repeat-conditioned null are not attributable to zero-adjacency (that null controls it) nor to table sparsity (those tails are empirical, not asymptotic); they reflect only a tiny residual arrangement effect whose honest effect size is negligible (corrected MI near zero, above). None of this is a plaintext/decryption claim or evidence of novel first-order memory. The planted controls still verify directionality for truly first-order-structured fixtures."
    );
}

fn conditional_primary_outliers(report: &ConditionalStructureReport) -> Vec<String> {
    PRIMARY_CONDITIONAL_REPORT_STATISTICS
        .iter()
        .filter_map(|&statistic| comparison_for_statistic(&report.comparisons, statistic))
        .filter(|row| row.outside_pointwise_95)
        .map(conditional_outlier_label)
        .collect()
}

fn conditional_off_diagonal_outliers(report: &ConditionalStructureReport) -> Vec<String> {
    [
        ConditionalStatistic::TransitionChiSquareOffDiagonal,
        ConditionalStatistic::DistinctSuccessorEdgesOffDiagonal,
    ]
    .iter()
    .filter_map(|&statistic| comparison_for_statistic(&report.comparisons, statistic))
    .filter(|row| row.outside_pointwise_95)
    .map(conditional_outlier_label)
    .collect()
}

fn conditional_no_repeat_outliers(report: &ConditionalStructureReport) -> Vec<String> {
    report
        .no_repeat_null
        .comparisons
        .iter()
        .filter(|row| {
            row.statistic != ConditionalStatistic::SelfTransitions && row.outside_pointwise_95
        })
        .map(conditional_outlier_label)
        .collect()
}

fn append_conditional_outlier_framing(
    out: &mut String,
    report: &ConditionalStructureReport,
    primary_outliers: &[String],
    off_diagonal_outliers: &[String],
    no_repeat_outliers: &[String],
) {
    append_conditional_primary_outliers(out, primary_outliers);
    if let Some(row) =
        comparison_for_statistic(&report.comparisons, ConditionalStatistic::SelfTransitions)
    {
        renderln!(
            out,
            "Diagonal confound: the accepted eye order has {} adjacent-equal self-transitions, while the unconstrained shuffle null averages {:.2} with 95% {}. Those raw exceedances are therefore dominated by the already-known zero-adjacency constraint.",
            format_conditional_statistic(row.statistic, row.observed),
            row.null.mean,
            format_conditional_band(row.statistic, row.null)
        );
    }
    append_conditional_off_diagonal_framing(out, off_diagonal_outliers);
    append_conditional_no_repeat_framing(out, no_repeat_outliers);
}

fn append_conditional_primary_outliers(out: &mut String, primary_outliers: &[String]) {
    if primary_outliers.is_empty() {
        renderln!(
            out,
            "Interpretation: the original seven-row unconstrained shuffle table has no pointwise exceedances."
        );
    } else {
        renderln!(
            out,
            "Interpretation: the original seven-row unconstrained shuffle table has pointwise exceedances in {}.",
            primary_outliers.join(", ")
        );
    }
}

fn append_conditional_off_diagonal_framing(out: &mut String, off_diagonal_outliers: &[String]) {
    if off_diagonal_outliers.is_empty() {
        renderln!(
            out,
            "Dropping diagonal cells removes the off-diagonal edge/chi-square pointwise flags against the unconstrained shuffle diagnostic."
        );
    } else {
        renderln!(
            out,
            "Dropping diagonal cells alone leaves unconstrained-shuffle diagnostic flags in {}; this is not the final control because that null still permits adjacent repeats.",
            off_diagonal_outliers.join(", ")
        );
    }
}

fn append_conditional_no_repeat_framing(out: &mut String, no_repeat_outliers: &[String]) {
    if no_repeat_outliers.is_empty() {
        renderln!(
            out,
            "After conditioning the shuffle null on zero adjacent-equal pairs, no displayed MI/off-diagonal statistic is outside its pointwise 95% band; no first-order signal survives this control."
        );
    } else {
        renderln!(
            out,
            "After conditioning the shuffle null on zero adjacent-equal pairs, pointwise flags remain in {}. Treat them as a tiny residual arrangement effect with negligible effect size (corrected MI near zero, below), not novel first-order memory.",
            no_repeat_outliers.join(", ")
        );
    }
}

fn append_conditional_effect_size(out: &mut String, report: &ConditionalStructureReport) {
    let observed = report.observed;
    let raw_mi_excess = observed.entropy.mutual_information_mle_bits
        - report.bias_calibration.mle_mutual_information.mean;
    let corrected_mi_excess = observed.entropy.mutual_information_corrected_bits
        - report.bias_calibration.corrected_mutual_information.mean;
    let corrected_mi_fraction = if observed.entropy.max_entropy_bits > 0.0 {
        observed.entropy.mutual_information_corrected_bits / observed.entropy.max_entropy_bits
    } else {
        0.0
    };
    renderln!(
        out,
        "Effect size: corrected MI is {:.6} bits ({:.3e} of the {:.3}-bit maximum); raw plug-in MI exceeds the flat-random null mean by {:.3} bits and collapses to {:.6} bits after correction.",
        observed.entropy.mutual_information_corrected_bits,
        corrected_mi_fraction,
        observed.entropy.max_entropy_bits,
        raw_mi_excess,
        corrected_mi_excess
    );
}

fn append_conditional_sparse_caveat(out: &mut String, report: &ConditionalStructureReport) {
    let observed = report.observed;
    renderln!(
        out,
        "Sparse-table caveat: {}/{} Pearson expected cells are <1 (<5: {}), with mean {:.3}; the asymptotic chi-square df={} tail is invalid. The Pearson value {:.3} is a sparse-table inflation artifact relative to G=2*N*MI: {:.1} from raw MLE MI and {:.3} after add-1 correction.",
        observed.chi_square.expected_lt_1_cells,
        observed.chi_square.expected_cells,
        observed.chi_square.expected_lt_5_cells,
        report::fraction(
            observed.entropy.transitions,
            observed.chi_square.expected_cells
        ),
        observed.chi_square.degrees_of_freedom,
        observed.chi_square.statistic,
        likelihood_ratio_g_from_mi_bits(
            observed.entropy.transitions,
            observed.entropy.mutual_information_mle_bits
        ),
        likelihood_ratio_g_from_mi_bits(
            observed.entropy.transitions,
            observed.entropy.mutual_information_corrected_bits
        )
    );
}

fn conditional_outlier_label(row: &NullComparison) -> String {
    format!(
        "{} (p={})",
        row.statistic.label(),
        report::format_probability(row.two_sided_add_one_p)
    )
}

fn conditional_comparison(
    control: &PlantedControlReport,
    statistic: ConditionalStatistic,
) -> Option<&NullComparison> {
    comparison_for_statistic(&control.comparisons, statistic)
}

fn comparison_for_statistic(
    comparisons: &[NullComparison],
    statistic: ConditionalStatistic,
) -> Option<&NullComparison> {
    comparisons.iter().find(|row| row.statistic == statistic)
}

fn conditional_control_verdict(control: &PlantedControlReport) -> &'static str {
    let mi = conditional_comparison(control, ConditionalStatistic::MutualInformationCorrected);
    let edges = conditional_comparison(control, ConditionalStatistic::DistinctSuccessorEdges);
    match (mi, edges) {
        (Some(mi), Some(edges))
            if mi.observed > mi.null.q975 && edges.observed < edges.null.q025 =>
        {
            "separated"
        }
        (Some(mi), Some(edges)) if !mi.outside_pointwise_95 && !edges.outside_pointwise_95 => {
            "inside"
        }
        _ => "check",
    }
}

fn likelihood_ratio_g_from_mi_bits(transitions: usize, mutual_information_bits: f64) -> f64 {
    2.0 * transitions as f64 * mutual_information_bits * std::f64::consts::LN_2
}

fn format_conditional_band(statistic: ConditionalStatistic, band: ScalarNullBand) -> String {
    format!(
        "{}..{}",
        format_conditional_statistic(statistic, band.q025),
        format_conditional_statistic(statistic, band.q975)
    )
}

fn format_conditional_statistic(statistic: ConditionalStatistic, value: f64) -> String {
    match statistic {
        ConditionalStatistic::TransitionChiSquare
        | ConditionalStatistic::TransitionChiSquareOffDiagonal => {
            format!("{value:.2}")
        }
        ConditionalStatistic::DistinctSuccessorEdges
        | ConditionalStatistic::DistinctSuccessorEdgesOffDiagonal
        | ConditionalStatistic::GreedyFsmStateLowerBound
        | ConditionalStatistic::SelfTransitions => {
            format!("{value:.0}")
        }
        _ => format!("{value:.6}"),
    }
}

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

fn first_order_stats(
    keys: &[&'static str],
    messages: &[Vec<TrigramValue>],
    alphabet_size: usize,
) -> Result<FirstOrderStats, ConditionalStructureError> {
    let counts = TransitionCounts::from_messages(keys, messages, alphabet_size)?;
    Ok(FirstOrderStats {
        matrix: matrix_summary(&counts),
        entropy: entropy_estimates(&counts),
        chi_square: transition_chi_square(&counts),
        diagonal: diagonal_transition_summary(&counts),
        off_diagonal: off_diagonal_transition_summary(&counts),
        graph: successor_graph_summary(&counts),
    })
}

fn statistic_value(stats: &FirstOrderStats, statistic: ConditionalStatistic) -> f64 {
    match statistic {
        ConditionalStatistic::NextEntropyCorrected => stats.entropy.next_entropy_corrected_bits,
        ConditionalStatistic::ConditionalEntropyCorrected => {
            stats.entropy.conditional_entropy_corrected_bits
        }
        ConditionalStatistic::MutualInformationCorrected => {
            stats.entropy.mutual_information_corrected_bits
        }
        ConditionalStatistic::TransitionChiSquare => stats.chi_square.statistic,
        ConditionalStatistic::TransitionChiSquareOffDiagonal => {
            stats.off_diagonal.chi_square_statistic
        }
        ConditionalStatistic::DistinctSuccessorEdges => stats.graph.distinct_successor_edges as f64,
        ConditionalStatistic::DistinctSuccessorEdgesOffDiagonal => {
            stats.off_diagonal.distinct_successor_edges as f64
        }
        ConditionalStatistic::SelfTransitions => stats.diagonal.self_transitions as f64,
        ConditionalStatistic::SuccessorEntropy => stats.graph.successor_entropy_bits,
        ConditionalStatistic::GreedyFsmStateLowerBound => {
            stats.graph.greedy_fsm_state_lower_bound as f64
        }
    }
}

const COMPARISON_STATISTICS: [ConditionalStatistic; 10] = [
    ConditionalStatistic::NextEntropyCorrected,
    ConditionalStatistic::ConditionalEntropyCorrected,
    ConditionalStatistic::MutualInformationCorrected,
    ConditionalStatistic::TransitionChiSquare,
    ConditionalStatistic::TransitionChiSquareOffDiagonal,
    ConditionalStatistic::DistinctSuccessorEdges,
    ConditionalStatistic::DistinctSuccessorEdgesOffDiagonal,
    ConditionalStatistic::SelfTransitions,
    ConditionalStatistic::SuccessorEntropy,
    ConditionalStatistic::GreedyFsmStateLowerBound,
];

const NO_REPEAT_COMPARISON_STATISTICS: [ConditionalStatistic; 4] = [
    ConditionalStatistic::SelfTransitions,
    ConditionalStatistic::MutualInformationCorrected,
    ConditionalStatistic::TransitionChiSquareOffDiagonal,
    ConditionalStatistic::DistinctSuccessorEdgesOffDiagonal,
];

#[derive(Clone, Debug, PartialEq, Eq)]
struct TransitionCounts {
    alphabet_size: usize,
    matrix: Vec<usize>,
    row_totals: Vec<usize>,
    column_totals: Vec<usize>,
    symbol_totals: Vec<usize>,
    symbols: usize,
    transitions: usize,
}

impl TransitionCounts {
    fn from_messages(
        keys: &[&'static str],
        messages: &[Vec<TrigramValue>],
        alphabet_size: usize,
    ) -> Result<Self, ConditionalStructureError> {
        let cells = matrix_cell_count(alphabet_size)?;
        let mut counts = Self {
            alphabet_size,
            matrix: vec![0; cells],
            row_totals: vec![0; alphabet_size],
            column_totals: vec![0; alphabet_size],
            symbol_totals: vec![0; alphabet_size],
            symbols: 0,
            transitions: 0,
        };

        for (message_index, values) in messages.iter().enumerate() {
            let message_key = keys.get(message_index).copied().unwrap_or("synthetic");
            for &value in values {
                let index = value_index(value, alphabet_size).ok_or(
                    ConditionalStructureError::ValueOutsideAlphabet {
                        message_key,
                        value: value.get(),
                        alphabet_size,
                    },
                )?;
                increment(&mut counts.symbol_totals, index, alphabet_size)?;
                counts.symbols = counts.symbols.saturating_add(1);
            }

            for pair in values.windows(2) {
                let [current, next] = pair else {
                    continue;
                };
                let current = value_index(*current, alphabet_size).ok_or(
                    ConditionalStructureError::ValueOutsideAlphabet {
                        message_key,
                        value: current.get(),
                        alphabet_size,
                    },
                )?;
                let next = value_index(*next, alphabet_size).ok_or(
                    ConditionalStructureError::ValueOutsideAlphabet {
                        message_key,
                        value: next.get(),
                        alphabet_size,
                    },
                )?;
                increment(&mut counts.row_totals, current, alphabet_size)?;
                increment(&mut counts.column_totals, next, alphabet_size)?;
                let cell = flat_index(current, next, alphabet_size)?;
                increment(&mut counts.matrix, cell, alphabet_size)?;
                counts.transitions = counts.transitions.saturating_add(1);
            }
        }

        Ok(counts)
    }

    fn row(&self, row: usize) -> Option<&[usize]> {
        let start = row.checked_mul(self.alphabet_size)?;
        let end = start.checked_add(self.alphabet_size)?;
        self.matrix.get(start..end)
    }

    fn cell(&self, row: usize, column: usize) -> Option<usize> {
        let index = flat_index(row, column, self.alphabet_size).ok()?;
        self.matrix.get(index).copied()
    }
}

fn value_index(value: TrigramValue, alphabet_size: usize) -> Option<usize> {
    let index = usize::from(value.get());
    if index < alphabet_size {
        Some(index)
    } else {
        None
    }
}

fn matrix_cell_count(alphabet_size: usize) -> Result<usize, ConditionalStructureError> {
    alphabet_size
        .checked_mul(alphabet_size)
        .ok_or(ConditionalStructureError::MatrixTooLarge { alphabet_size })
}

fn flat_index(
    row: usize,
    column: usize,
    alphabet_size: usize,
) -> Result<usize, ConditionalStructureError> {
    let offset = row
        .checked_mul(alphabet_size)
        .and_then(|base| base.checked_add(column))
        .ok_or(ConditionalStructureError::MatrixTooLarge { alphabet_size })?;
    Ok(offset)
}

fn increment(
    values: &mut [usize],
    index: usize,
    alphabet_size: usize,
) -> Result<(), ConditionalStructureError> {
    let slot = values
        .get_mut(index)
        .ok_or(ConditionalStructureError::MatrixTooLarge { alphabet_size })?;
    *slot = slot.saturating_add(1);
    Ok(())
}

fn matrix_summary(counts: &TransitionCounts) -> TransitionMatrixSummary {
    let matrix_cells = counts.matrix.len();
    let nonzero_cells = counts.matrix.iter().filter(|&&count| count > 0).count();
    TransitionMatrixSummary {
        alphabet_size: counts.alphabet_size,
        symbols: counts.symbols,
        transitions: counts.transitions,
        matrix_cells,
        nonzero_cells,
        density: fraction(nonzero_cells, matrix_cells),
        mean_transitions_per_cell: fraction(counts.transitions, matrix_cells),
        mean_symbols_per_value: fraction(counts.symbols, counts.alphabet_size),
    }
}

fn entropy_estimates(counts: &TransitionCounts) -> EntropyEstimates {
    let transitions = counts.transitions;
    if transitions == 0 {
        return EntropyEstimates {
            transitions,
            max_entropy_bits: (counts.alphabet_size as f64).log2(),
            next_entropy_mle_bits: 0.0,
            next_entropy_corrected_bits: 0.0,
            conditional_entropy_mle_bits: 0.0,
            conditional_entropy_corrected_bits: 0.0,
            mutual_information_mle_bits: 0.0,
            mutual_information_corrected_bits: 0.0,
            add_constant_alpha: ADD_CONSTANT_ALPHA,
        };
    }

    let next_entropy_mle_bits = entropy_from_counts(&counts.column_totals, transitions);
    let next_entropy_corrected_bits = add_constant_entropy(
        &counts.column_totals,
        transitions,
        counts.alphabet_size,
        ADD_CONSTANT_ALPHA,
    );

    let mut conditional_entropy_mle_bits = 0.0;
    let mut conditional_entropy_corrected_bits = 0.0;
    for (row_index, &row_total) in counts.row_totals.iter().enumerate() {
        if row_total == 0 {
            continue;
        }
        let Some(row) = counts.row(row_index) else {
            continue;
        };
        conditional_entropy_mle_bits +=
            row_total as f64 / transitions as f64 * entropy_from_counts(row, row_total);
        conditional_entropy_corrected_bits += row_total as f64 / transitions as f64
            * add_constant_entropy(row, row_total, counts.alphabet_size, ADD_CONSTANT_ALPHA);
    }

    EntropyEstimates {
        transitions,
        max_entropy_bits: (counts.alphabet_size as f64).log2(),
        next_entropy_mle_bits,
        next_entropy_corrected_bits,
        conditional_entropy_mle_bits,
        conditional_entropy_corrected_bits,
        mutual_information_mle_bits: next_entropy_mle_bits - conditional_entropy_mle_bits,
        mutual_information_corrected_bits: next_entropy_corrected_bits
            - conditional_entropy_corrected_bits,
        add_constant_alpha: ADD_CONSTANT_ALPHA,
    }
}

fn transition_chi_square(counts: &TransitionCounts) -> TransitionChiSquare {
    let transitions = counts.transitions;
    let active_rows = nonzero_count(&counts.row_totals);
    let active_columns = nonzero_count(&counts.column_totals);
    if transitions == 0 {
        return TransitionChiSquare {
            statistic: 0.0,
            degrees_of_freedom: 0,
            active_rows,
            active_columns,
            expected_cells: 0,
            expected_lt_1_cells: 0,
            expected_lt_5_cells: 0,
        };
    }

    let mut statistic = 0.0;
    let mut expected_cells = 0usize;
    let mut expected_lt_1_cells = 0usize;
    let mut expected_lt_5_cells = 0usize;
    for (row, &row_total) in counts.row_totals.iter().enumerate() {
        if row_total == 0 {
            continue;
        }
        for (column, &column_total) in counts.column_totals.iter().enumerate() {
            if column_total == 0 {
                continue;
            }
            let expected = row_total as f64 * column_total as f64 / transitions as f64;
            if expected <= 0.0 {
                continue;
            }
            expected_cells = expected_cells.saturating_add(1);
            if expected < 1.0 {
                expected_lt_1_cells = expected_lt_1_cells.saturating_add(1);
            }
            if expected < 5.0 {
                expected_lt_5_cells = expected_lt_5_cells.saturating_add(1);
            }
            let observed = counts.cell(row, column).unwrap_or(0) as f64;
            let delta = observed - expected;
            statistic += delta * delta / expected;
        }
    }

    TransitionChiSquare {
        statistic,
        degrees_of_freedom: active_rows
            .saturating_sub(1)
            .saturating_mul(active_columns.saturating_sub(1)),
        active_rows,
        active_columns,
        expected_cells,
        expected_lt_1_cells,
        expected_lt_5_cells,
    }
}

fn diagonal_transition_summary(counts: &TransitionCounts) -> DiagonalTransitionSummary {
    if counts.transitions == 0 {
        return DiagonalTransitionSummary {
            self_transitions: 0,
            self_transition_edges: 0,
            expected_self_transitions_independence: 0.0,
            chi_square_contribution: 0.0,
        };
    }

    let mut self_transitions = 0usize;
    let mut self_transition_edges = 0usize;
    let mut expected_self_transitions_independence = 0.0;
    let mut chi_square_contribution = 0.0;
    for (index, (&row_total, &column_total)) in counts
        .row_totals
        .iter()
        .zip(counts.column_totals.iter())
        .enumerate()
    {
        let observed = counts.cell(index, index).unwrap_or(0);
        self_transitions = self_transitions.saturating_add(observed);
        if observed > 0 {
            self_transition_edges = self_transition_edges.saturating_add(1);
        }
        let expected = row_total as f64 * column_total as f64 / counts.transitions as f64;
        expected_self_transitions_independence += expected;
        if expected > 0.0 {
            let delta = observed as f64 - expected;
            chi_square_contribution += delta * delta / expected;
        }
    }

    DiagonalTransitionSummary {
        self_transitions,
        self_transition_edges,
        expected_self_transitions_independence,
        chi_square_contribution,
    }
}

fn off_diagonal_transition_summary(counts: &TransitionCounts) -> OffDiagonalTransitionSummary {
    let matrix_cells = counts.matrix.len().saturating_sub(counts.alphabet_size);
    if counts.transitions == 0 {
        return OffDiagonalTransitionSummary {
            matrix_cells,
            distinct_successor_edges: 0,
            edge_density: 0.0,
            chi_square_statistic: 0.0,
            expected_cells: 0,
            expected_lt_1_cells: 0,
            expected_lt_5_cells: 0,
        };
    }

    let mut distinct_successor_edges = 0usize;
    let mut chi_square_statistic = 0.0;
    let mut expected_cells = 0usize;
    let mut expected_lt_1_cells = 0usize;
    let mut expected_lt_5_cells = 0usize;
    for (row_index, &row_total) in counts.row_totals.iter().enumerate() {
        if row_total == 0 {
            continue;
        }
        let Some(row) = counts.row(row_index) else {
            continue;
        };
        for (column_index, (&observed, &column_total)) in
            row.iter().zip(counts.column_totals.iter()).enumerate()
        {
            if row_index == column_index {
                continue;
            }
            if observed > 0 {
                distinct_successor_edges = distinct_successor_edges.saturating_add(1);
            }
            if column_total == 0 {
                continue;
            }
            let expected = row_total as f64 * column_total as f64 / counts.transitions as f64;
            if expected <= 0.0 {
                continue;
            }
            expected_cells = expected_cells.saturating_add(1);
            if expected < 1.0 {
                expected_lt_1_cells = expected_lt_1_cells.saturating_add(1);
            }
            if expected < 5.0 {
                expected_lt_5_cells = expected_lt_5_cells.saturating_add(1);
            }
            let delta = observed as f64 - expected;
            chi_square_statistic += delta * delta / expected;
        }
    }

    OffDiagonalTransitionSummary {
        matrix_cells,
        distinct_successor_edges,
        edge_density: fraction(distinct_successor_edges, matrix_cells),
        chi_square_statistic,
        expected_cells,
        expected_lt_1_cells,
        expected_lt_5_cells,
    }
}

fn successor_graph_summary(counts: &TransitionCounts) -> SuccessorGraphSummary {
    let mut out_degrees = Vec::with_capacity(counts.alphabet_size);
    let mut row_entropy_total = 0.0;
    let mut active_sources = 0usize;
    let mut distinct_successor_edges = 0usize;
    let mut max_out_degree = 0usize;

    for (row_index, &row_total) in counts.row_totals.iter().enumerate() {
        let out_degree = counts.row(row_index).map_or(0, nonzero_count);
        out_degrees.push(out_degree);
        distinct_successor_edges = distinct_successor_edges.saturating_add(out_degree);
        max_out_degree = max_out_degree.max(out_degree);
        if row_total > 0 {
            active_sources = active_sources.saturating_add(1);
            if let Some(row) = counts.row(row_index) {
                row_entropy_total += entropy_from_counts(row, row_total);
            }
        }
    }

    let observed_symbols = nonzero_count(&counts.symbol_totals);
    let observed_zero_out_degree_symbols = counts
        .symbol_totals
        .iter()
        .zip(out_degrees.iter())
        .filter(|(symbol_total, out_degree)| **symbol_total > 0 && **out_degree == 0)
        .count();
    let greedy_fsm_state_lower_bound = counts
        .symbol_totals
        .iter()
        .zip(out_degrees.iter())
        .filter(|(symbol_total, _out_degree)| **symbol_total > 0)
        .map(|(_symbol_total, &out_degree)| out_degree.max(1))
        .sum();

    SuccessorGraphSummary {
        observed_symbols,
        active_sources,
        active_targets: nonzero_count(&counts.column_totals),
        distinct_successor_edges,
        edge_density: fraction(distinct_successor_edges, counts.matrix.len()),
        mean_out_degree: fraction(distinct_successor_edges, active_sources),
        max_out_degree,
        observed_zero_out_degree_symbols,
        successor_entropy_bits: if active_sources == 0 {
            0.0
        } else {
            row_entropy_total / active_sources as f64
        },
        out_degree_entropy_bits: out_degree_histogram_entropy(&counts.symbol_totals, &out_degrees),
        greedy_fsm_state_lower_bound,
    }
}

fn out_degree_histogram_entropy(symbol_totals: &[usize], out_degrees: &[usize]) -> f64 {
    let mut histogram = BTreeMap::new();
    let mut total = 0usize;
    for (&symbol_total, &out_degree) in symbol_totals.iter().zip(out_degrees) {
        if symbol_total == 0 {
            continue;
        }
        *histogram.entry(out_degree).or_insert(0usize) += 1;
        total = total.saturating_add(1);
    }
    let counts = histogram.values().copied().collect::<Vec<_>>();
    entropy_from_counts(&counts, total)
}

fn entropy_from_counts(counts: &[usize], total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let probability = count as f64 / total as f64;
            -probability * probability.log2()
        })
        .sum()
}

fn add_constant_entropy(counts: &[usize], total: usize, categories: usize, alpha: f64) -> f64 {
    if categories == 0 || !alpha.is_finite() || alpha <= 0.0 {
        return 0.0;
    }
    let denominator = total as f64 + alpha * categories as f64;
    if denominator <= 0.0 {
        return 0.0;
    }
    counts
        .iter()
        .take(categories)
        .map(|&count| {
            let probability = (count as f64 + alpha) / denominator;
            -probability * probability.log2()
        })
        .sum()
}

fn nonzero_count(counts: &[usize]) -> usize {
    counts.iter().filter(|&&count| count > 0).count()
}

fn null_comparisons(
    config: ConditionalStructureConfig,
    keys: &[&'static str],
    messages: &[Vec<TrigramValue>],
    observed: &FirstOrderStats,
) -> Result<Vec<NullComparison>, ConditionalStructureError> {
    let total_trials = config.total_trials()?;
    let mut samples = vec![Vec::with_capacity(total_trials); COMPARISON_STATISTICS.len()];
    let shuffle = WithinMessageShuffle { messages };

    // The seed-stream loop stays longhand: each trial scores ten columns from
    // one shared shuffle and the `derived_seed` xor-mix is fallible, so only the
    // resampling step becomes the shared sampler.
    for seed_index in 0..config.seed_count {
        let mut rng = SplitMix64::new(derived_seed(config.seed, seed_index)?);
        for _trial in 0..config.trials_per_seed {
            let shuffled = shuffle.sample(&mut rng)?;
            let stats = first_order_stats(keys, &shuffled, config.alphabet_size)?;
            for (sample_row, &statistic) in samples.iter_mut().zip(COMPARISON_STATISTICS.iter()) {
                sample_row.push(statistic_value(&stats, statistic));
            }
        }
    }

    Ok(COMPARISON_STATISTICS
        .iter()
        .copied()
        .zip(samples.iter())
        .map(|(statistic, statistic_samples)| {
            let observed_value = statistic_value(observed, statistic);
            comparison_from_samples(statistic, observed_value, statistic_samples)
        })
        .collect())
}

fn no_repeat_null_comparisons(
    config: ConditionalStructureConfig,
    keys: &[&'static str],
    messages: &[Vec<TrigramValue>],
    observed: &FirstOrderStats,
) -> Result<NoRepeatNullReport, ConditionalStructureError> {
    validate_no_adjacent_equal(keys, messages)?;
    let total_trials = config.total_trials()?;
    let mut samples = vec![Vec::with_capacity(total_trials); NO_REPEAT_COMPARISON_STATISTICS.len()];

    for seed_index in 0..config.seed_count {
        let seed = derived_seed(config.seed ^ 0x6e6f_7265_7065_6174, seed_index)?;
        let mut rng = SplitMix64::new(seed);
        let mut chain = messages.to_vec();
        run_no_repeat_sweeps(&mut chain, NO_REPEAT_BURN_IN_SWEEPS, &mut rng)?;
        for _trial in 0..config.trials_per_seed {
            run_no_repeat_sweeps(&mut chain, NO_REPEAT_SAMPLE_SWEEPS, &mut rng)?;
            let stats = first_order_stats(keys, &chain, config.alphabet_size)?;
            for (sample_row, &statistic) in samples
                .iter_mut()
                .zip(NO_REPEAT_COMPARISON_STATISTICS.iter())
            {
                sample_row.push(statistic_value(&stats, statistic));
            }
        }
    }

    let comparisons = NO_REPEAT_COMPARISON_STATISTICS
        .iter()
        .copied()
        .zip(samples.iter())
        .map(|(statistic, statistic_samples)| {
            let observed_value = statistic_value(observed, statistic);
            comparison_from_samples(statistic, observed_value, statistic_samples)
        })
        .collect();

    Ok(NoRepeatNullReport {
        burn_in_sweeps: NO_REPEAT_BURN_IN_SWEEPS,
        sample_sweeps: NO_REPEAT_SAMPLE_SWEEPS,
        comparisons,
    })
}

fn validate_no_adjacent_equal(
    keys: &[&'static str],
    messages: &[Vec<TrigramValue>],
) -> Result<(), ConditionalStructureError> {
    for (message_index, values) in messages.iter().enumerate() {
        if has_adjacent_equal(values) {
            return Err(
                ConditionalStructureError::NoRepeatNullRequiresNoAdjacentEqual {
                    message_key: keys.get(message_index).copied().unwrap_or("synthetic"),
                },
            );
        }
    }
    Ok(())
}

fn run_no_repeat_sweeps(
    messages: &mut [Vec<TrigramValue>],
    sweeps: usize,
    rng: &mut SplitMix64,
) -> Result<(), ConditionalStructureError> {
    for _sweep in 0..sweeps {
        for values in messages.iter_mut() {
            run_no_repeat_message_sweep(values, rng)?;
        }
    }
    Ok(())
}

fn run_no_repeat_message_sweep(
    values: &mut [TrigramValue],
    rng: &mut SplitMix64,
) -> Result<(), ConditionalStructureError> {
    for _proposal in 0..values.len() {
        propose_no_repeat_swap(values, rng)?;
    }
    Ok(())
}

fn propose_no_repeat_swap(
    values: &mut [TrigramValue],
    rng: &mut SplitMix64,
) -> Result<(), ConditionalStructureError> {
    if values.len() < 2 {
        return Ok(());
    }
    let left = random_index_below(values.len(), rng)?;
    let right = random_index_below(values.len(), rng)?;
    values.swap(left, right);
    if has_adjacent_equal_around(values, left) || has_adjacent_equal_around(values, right) {
        values.swap(left, right);
    }
    Ok(())
}

fn has_adjacent_equal(values: &[TrigramValue]) -> bool {
    values.windows(2).any(|pair| {
        let [left, right] = pair else {
            return false;
        };
        left == right
    })
}

fn has_adjacent_equal_around(values: &[TrigramValue], position: usize) -> bool {
    let Some(current) = values.get(position) else {
        return false;
    };
    let previous_equal = position
        .checked_sub(1)
        .and_then(|previous| values.get(previous))
        == Some(current);
    let next_equal = position.checked_add(1).and_then(|next| values.get(next)) == Some(current);
    previous_equal || next_equal
}

fn comparison_from_samples(
    statistic: ConditionalStatistic,
    observed: f64,
    samples: &[f64],
) -> NullComparison {
    let lower_tail_count = samples.iter().filter(|&&sample| sample <= observed).count();
    let upper_tail_count = samples.iter().filter(|&&sample| sample >= observed).count();
    let two_sided_add_one_p =
        two_sided_add_one_p(lower_tail_count, upper_tail_count, samples.len());
    let null = ScalarNullBand::from(f64_band(samples));
    NullComparison {
        statistic,
        observed,
        null,
        lower_tail_count,
        upper_tail_count,
        two_sided_add_one_p,
        outside_pointwise_95: observed < null.q025 || observed > null.q975,
    }
}

fn two_sided_add_one_p(lower_tail_count: usize, upper_tail_count: usize, trials: usize) -> f64 {
    let tail_numerator = lower_tail_count.min(upper_tail_count).saturating_add(1);
    let denominator = trials.saturating_add(1);
    if denominator == 0 {
        1.0
    } else {
        (2.0 * tail_numerator as f64 / denominator as f64).min(1.0)
    }
}

fn mean_abs(samples: &[f64]) -> f64 {
    if samples.is_empty() {
        0.0
    } else {
        samples.iter().map(|value| value.abs()).sum::<f64>() / samples.len() as f64
    }
}

fn bias_calibration(
    config: ConditionalStructureConfig,
    lengths: &[usize],
) -> Result<BiasCalibrationReport, ConditionalStructureError> {
    let total_trials = config.total_trials()?;
    let mut mle_samples = Vec::with_capacity(total_trials);
    let mut corrected_samples = Vec::with_capacity(total_trials);
    let keys = synthetic_keys(lengths.len());

    for seed_index in 0..config.seed_count {
        let seed = derived_seed(config.seed ^ 0x6269_6173_0000_0000, seed_index)?;
        let mut rng = SplitMix64::new(seed);
        for _trial in 0..config.trials_per_seed {
            let messages = random_messages_like(lengths, config.alphabet_size, &mut rng)?;
            let stats = first_order_stats(&keys, &messages, config.alphabet_size)?;
            mle_samples.push(stats.entropy.mutual_information_mle_bits);
            corrected_samples.push(stats.entropy.mutual_information_corrected_bits);
        }
    }

    Ok(BiasCalibrationReport {
        trials: total_trials,
        alphabet_size: config.alphabet_size,
        true_mutual_information_bits: 0.0,
        mle_mutual_information: ScalarNullBand::from(f64_band(&mle_samples)),
        corrected_mutual_information: ScalarNullBand::from(f64_band(&corrected_samples)),
        mle_mean_abs_mutual_information_bits: mean_abs(&mle_samples),
        corrected_mean_abs_mutual_information_bits: mean_abs(&corrected_samples),
    })
}

fn planted_controls(
    config: ConditionalStructureConfig,
    lengths: &[usize],
) -> Result<PlantedControlsReport, ConditionalStructureError> {
    let plaintext = structured_plaintext_messages(lengths)?;
    let static_monoalphabetic = static_monoalphabetic_control(config, &plaintext)?;
    let deck_permuted = deck_permuted_control(config, &plaintext)?;
    Ok(PlantedControlsReport {
        static_monoalphabetic,
        deck_permuted,
    })
}

fn static_monoalphabetic_control(
    config: ConditionalStructureConfig,
    plaintext: &[Vec<usize>],
) -> Result<PlantedControlReport, ConditionalStructureError> {
    let mut rng = SplitMix64::new(config.seed ^ 0x7374_6174_6963_0000);
    let key = random_permutation(config.alphabet_size, &mut rng)?;
    let messages = map_plaintext_messages(plaintext, |symbol, _position| {
        key.get(symbol).copied().unwrap_or(symbol)
    })?;
    planted_control_report(
        config,
        "structured monoalphabetic",
        "fixed monoalphabetic substitution of a low-successor structured source",
        &messages,
    )
}

fn deck_permuted_control(
    config: ConditionalStructureConfig,
    plaintext: &[Vec<usize>],
) -> Result<PlantedControlReport, ConditionalStructureError> {
    let mut rng = SplitMix64::new(config.seed ^ 0x6465_636b_0000_0000);
    let mut shifts = Vec::new();
    let total_len = plaintext.iter().map(Vec::len).sum();
    for _position in 0..total_len {
        shifts.push(random_index_below(config.alphabet_size, &mut rng)?);
    }
    let messages = map_plaintext_messages(plaintext, |symbol, position| {
        shifts
            .get(position)
            .map_or(symbol, |shift| (symbol + shift) % config.alphabet_size)
    })?;
    planted_control_report(
        config,
        "structured deck-permuted",
        "same structured source under a position-dependent additive alphabet permutation",
        &messages,
    )
}

fn planted_control_report(
    config: ConditionalStructureConfig,
    label: &'static str,
    construction: &'static str,
    messages: &[Vec<TrigramValue>],
) -> Result<PlantedControlReport, ConditionalStructureError> {
    let keys = synthetic_keys(messages.len());
    let observed = first_order_stats(&keys, messages, config.alphabet_size)?;
    let comparisons = null_comparisons(config, &keys, messages, &observed)?;
    Ok(PlantedControlReport {
        label,
        construction,
        observed,
        comparisons,
    })
}

fn structured_plaintext_messages(
    lengths: &[usize],
) -> Result<Vec<Vec<usize>>, ConditionalStructureError> {
    let mut messages = Vec::new();
    for &length in lengths {
        let mut message = Vec::with_capacity(length);
        for position in 0..length {
            let pattern_index = position % CONTROL_PATTERN.len();
            let symbol = CONTROL_PATTERN
                .get(pattern_index)
                .copied()
                .ok_or(ConditionalStructureError::InvalidAlphabetSize { alphabet_size: 0 })?;
            message.push(symbol);
        }
        messages.push(message);
    }
    Ok(messages)
}

fn map_plaintext_messages(
    plaintext: &[Vec<usize>],
    mut map_symbol: impl FnMut(usize, usize) -> usize,
) -> Result<Vec<Vec<TrigramValue>>, ConditionalStructureError> {
    let mut messages = Vec::new();
    let mut global_position = 0usize;
    for message in plaintext {
        let mut values = Vec::with_capacity(message.len());
        for &symbol in message {
            let mapped = map_symbol(symbol, global_position);
            values.push(trigram_from_index(mapped)?);
            global_position = global_position.saturating_add(1);
        }
        messages.push(values);
    }
    Ok(messages)
}

fn random_messages_like(
    lengths: &[usize],
    alphabet_size: usize,
    rng: &mut SplitMix64,
) -> Result<Vec<Vec<TrigramValue>>, ConditionalStructureError> {
    let mut messages = Vec::new();
    for &length in lengths {
        let mut values = Vec::with_capacity(length);
        for _position in 0..length {
            values.push(trigram_from_index(random_index_below(alphabet_size, rng)?)?);
        }
        messages.push(values);
    }
    Ok(messages)
}

fn random_permutation(
    alphabet_size: usize,
    rng: &mut SplitMix64,
) -> Result<Vec<usize>, ConditionalStructureError> {
    let mut values = (0..alphabet_size).collect::<Vec<_>>();
    fisher_yates(&mut values, rng)?;
    Ok(values)
}

fn trigram_from_index(index: usize) -> Result<TrigramValue, ConditionalStructureError> {
    let raw =
        u8::try_from(index).map_err(|_error| ConditionalStructureError::InvalidAlphabetSize {
            alphabet_size: index,
        })?;
    TrigramValue::new(raw).map_err(|_value| ConditionalStructureError::InvalidAlphabetSize {
        alphabet_size: index,
    })
}

fn derived_seed(base_seed: u64, index: usize) -> Result<u64, ConditionalStructureError> {
    let index_u64 = u64::try_from(index)
        .map_err(|_error| ConditionalStructureError::RandomBoundTooLarge { bound: index })?;
    let mut mixer = SplitMix64::new(
        base_seed
            ^ index_u64
                .wrapping_add(0x9e37_79b9_7f4a_7c15)
                .rotate_left(17),
    );
    Ok(mixer.next_u64())
}

fn synthetic_keys(count: usize) -> Vec<&'static str> {
    const KEYS: [&str; 16] = [
        "synthetic0",
        "synthetic1",
        "synthetic2",
        "synthetic3",
        "synthetic4",
        "synthetic5",
        "synthetic6",
        "synthetic7",
        "synthetic8",
        "synthetic9",
        "synthetic10",
        "synthetic11",
        "synthetic12",
        "synthetic13",
        "synthetic14",
        "synthetic15",
    ];
    KEYS.iter().copied().take(count).collect()
}

fn fraction(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ConditionalStatistic, ConditionalStructureConfig, DEFAULT_ALPHABET_SIZE, bias_calibration,
        comparison_from_samples, first_order_stats, planted_controls, report_from_message_values,
        structured_plaintext_messages, trigram_from_index,
    };
    use crate::orders;
    use crate::trigram::TrigramValue;

    fn values(raw: &[usize]) -> Vec<TrigramValue> {
        raw.iter()
            .copied()
            .map(|value| trigram_from_index(value).unwrap())
            .collect()
    }

    #[test]
    fn deterministic_alternation_has_full_first_order_information() {
        let messages = vec![values(&[0, 1, 0, 1, 0, 1, 0, 1])];
        let stats = first_order_stats(&["fixture"], &messages, 2).unwrap();

        assert_eq!(stats.matrix.symbols, 8);
        assert_eq!(stats.matrix.transitions, 7);
        assert_eq!(stats.graph.distinct_successor_edges, 2);
        assert_eq!(stats.graph.greedy_fsm_state_lower_bound, 2);
        assert!(stats.entropy.conditional_entropy_mle_bits.abs() < 1e-12);
        assert!(stats.entropy.mutual_information_mle_bits > 0.98);
        assert!(stats.entropy.mutual_information_corrected_bits > 0.25);
        assert!(
            stats.entropy.mutual_information_corrected_bits
                < stats.entropy.mutual_information_mle_bits
        );
    }

    #[test]
    fn successor_graph_counts_edges_entropy_and_fsm_bound() {
        let messages = vec![values(&[0, 1, 2, 0, 2])];
        let stats = first_order_stats(&["fixture"], &messages, 3).unwrap();

        assert_eq!(stats.graph.observed_symbols, 3);
        assert_eq!(stats.graph.active_sources, 3);
        assert_eq!(stats.graph.active_targets, 3);
        assert_eq!(stats.graph.distinct_successor_edges, 4);
        assert_eq!(stats.graph.max_out_degree, 2);
        assert_eq!(stats.graph.greedy_fsm_state_lower_bound, 4);
        assert!(
            (stats.graph.successor_entropy_bits - (1.0 / 3.0)).abs() < 1e-12,
            "successor entropy was {}",
            stats.graph.successor_entropy_bits
        );
    }

    #[test]
    fn two_sided_add_one_comparison_is_capped() {
        let comparison = comparison_from_samples(
            ConditionalStatistic::TransitionChiSquare,
            2.0,
            &[1.0, 2.0, 3.0],
        );

        assert_eq!(comparison.lower_tail_count, 2);
        assert_eq!(comparison.upper_tail_count, 2);
        assert!((comparison.two_sided_add_one_p - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn two_sided_add_one_applies_correction_before_doubling() {
        let comparison = comparison_from_samples(
            ConditionalStatistic::TransitionChiSquare,
            0.5,
            &[1.0, 2.0, 3.0],
        );

        assert_eq!(comparison.lower_tail_count, 0);
        assert_eq!(comparison.upper_tail_count, 3);
        assert!((comparison.two_sided_add_one_p - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn add_constant_calibration_reduces_flat_random_mi_bias() {
        let config = ConditionalStructureConfig {
            seed: 0x5150,
            seed_count: 2,
            trials_per_seed: 64,
            alphabet_size: DEFAULT_ALPHABET_SIZE,
        };
        let calibration = bias_calibration(config, &[99, 103, 118, 102]).unwrap();

        assert!(calibration.mle_mutual_information.mean > 0.0);
        assert!(
            calibration.corrected_mean_abs_mutual_information_bits
                < calibration.mle_mean_abs_mutual_information_bits,
            "MLE abs {} corrected abs {}",
            calibration.mle_mean_abs_mutual_information_bits,
            calibration.corrected_mean_abs_mutual_information_bits
        );
        assert!(
            calibration.corrected_mutual_information.mean.abs()
                < calibration.mle_mutual_information.mean
        );
    }

    #[test]
    fn planted_controls_separate_static_from_deck_permuted_structure() {
        let config = ConditionalStructureConfig {
            seed: 0x7777,
            seed_count: 2,
            trials_per_seed: 64,
            alphabet_size: DEFAULT_ALPHABET_SIZE,
        };
        let plaintext = structured_plaintext_messages(&[160, 161, 162]).unwrap();
        let controls = planted_controls(config, &[160, 161, 162]).unwrap();
        assert_eq!(plaintext.len(), 3);

        let static_mi = controls
            .static_monoalphabetic
            .comparisons
            .iter()
            .find(|row| row.statistic == ConditionalStatistic::MutualInformationCorrected)
            .unwrap();
        let static_edges = controls
            .static_monoalphabetic
            .comparisons
            .iter()
            .find(|row| row.statistic == ConditionalStatistic::DistinctSuccessorEdges)
            .unwrap();
        let deck_mi = controls
            .deck_permuted
            .comparisons
            .iter()
            .find(|row| row.statistic == ConditionalStatistic::MutualInformationCorrected)
            .unwrap();
        let deck_edges = controls
            .deck_permuted
            .comparisons
            .iter()
            .find(|row| row.statistic == ConditionalStatistic::DistinctSuccessorEdges)
            .unwrap();

        assert!(static_mi.observed > static_mi.null.q975);
        assert!(static_edges.observed < static_edges.null.q025);
        assert!(!deck_mi.outside_pointwise_95, "deck MI row: {deck_mi:?}");
        assert!(
            !deck_edges.outside_pointwise_95,
            "deck edge row: {deck_edges:?}"
        );
    }

    #[test]
    fn eye_headline_statistics_are_pinned() {
        let config = ConditionalStructureConfig {
            seed: 0x1234,
            seed_count: 1,
            trials_per_seed: 4,
            alphabet_size: DEFAULT_ALPHABET_SIZE,
        };
        let grids = orders::corpus_grids().unwrap();
        let keys = grids
            .iter()
            .map(crate::orders::GlyphGrid::message_key)
            .collect::<Vec<_>>();
        let order = orders::accepted_honeycomb_order();
        let messages = orders::read_corpus_message_values(&grids, order).unwrap();
        let report = report_from_message_values(config, order, &keys, &messages).unwrap();

        assert_eq!(report.observed.matrix.symbols, 1036);
        assert_eq!(report.observed.matrix.transitions, 1027);
        assert_eq!(report.observed.matrix.nonzero_cells, 850);
        assert_eq!(report.observed.chi_square.degrees_of_freedom, 6724);
        assert_eq!(report.observed.graph.distinct_successor_edges, 850);
        assert_eq!(report.observed.graph.greedy_fsm_state_lower_bound, 850);
        assert_eq!(report.observed.diagonal.self_transitions, 0);
        assert_eq!(report.observed.diagonal.self_transition_edges, 0);
        assert_eq!(report.observed.off_diagonal.matrix_cells, 6806);
        assert_eq!(report.observed.off_diagonal.distinct_successor_edges, 850);
        assert_eq!(report.observed.off_diagonal.expected_cells, 6806);
        assert_eq!(report.observed.off_diagonal.expected_lt_1_cells, 6806);
        assert_eq!(report.observed.off_diagonal.expected_lt_5_cells, 6806);
        assert!(
            (report
                .observed
                .diagonal
                .expected_self_transitions_independence
                - report.observed.diagonal.chi_square_contribution)
                .abs()
                < 1e-12
        );
        assert!(
            (report.observed.diagonal.chi_square_contribution
                + report.observed.off_diagonal.chi_square_statistic
                - report.observed.chi_square.statistic)
                .abs()
                < 1e-9
        );
        let no_repeat_self_transitions = report
            .no_repeat_null
            .comparisons
            .iter()
            .find(|row| row.statistic == ConditionalStatistic::SelfTransitions)
            .unwrap();
        assert!(no_repeat_self_transitions.observed.abs() < f64::EPSILON);
        assert!(no_repeat_self_transitions.null.min.abs() < f64::EPSILON);
        assert!(no_repeat_self_transitions.null.max.abs() < f64::EPSILON);
        assert!(
            (report.observed.entropy.mutual_information_corrected_bits
                - 0.000_726_184_362_833_670_6)
                .abs()
                < 1e-12,
            "MI changed: {}",
            report.observed.entropy.mutual_information_corrected_bits
        );
        assert!(
            (report.observed.graph.successor_entropy_bits - 3.186_263_722_367_619).abs() < 1e-12,
            "successor entropy changed: {}",
            report.observed.graph.successor_entropy_bits
        );
    }
}

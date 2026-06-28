//! Tree-residual cross-tail n-gram null.
//!
//! This experiment asks whether cross-message n-gram sharing remains after the
//! aligned tree trunk is removed. The trunk mask is not reconstructed here:
//! it reuses the `perseus` module's Experiment 7C shared-region definition:
//! same-offset common runs of length at least two that belong to the earliest
//! leading-family alignment or an East/West counterpart pair.
//!
//! The residual statistic is position-independent across messages. For each
//! `k` in [`K_VALUES`], it counts distinct k-gram kinds that occur in residual
//! tails of at least two different messages. K-grams are built within one
//! message residual segment at a time; no k-gram crosses a message join or a
//! masked shared span. The null shuffles each message's residual symbols while
//! preserving that message's residual length, residual segment shape, and exact
//! residual multiset.

use std::fmt;

use crate::analysis::orders::{GridError, ReadingOrder};
use crate::nulls::null::UsizeBand;
use crate::nulls::perseus::{self, SharedPartition};
use crate::report::{self, Report};

/// Default deterministic base seed for the tree-residual shuffle null.
pub const DEFAULT_SEED: u64 = 0x7472_6565_7461_696c;
/// Default number of within-tail shuffle trials per seed.
pub const DEFAULT_TRIALS: usize = 1_000;
/// Default number of deterministic seed batches.
pub const DEFAULT_SEED_COUNT: usize = 5;
/// K-gram sizes scanned by this experiment.
pub const K_VALUES: [usize; 2] = [3, 4];
/// Conventional pointwise upper-tail significance cutoff.
pub const SIGNIFICANCE_ALPHA: f64 = 0.05;

const TREE_RESIDUAL_ROW_COUNT: usize = 2 * K_VALUES.len();
const MAX_VEC_ALLOCATION_BYTES: usize = usize::MAX / 2;

/// Configuration for the tree-residual cross-tail n-gram null.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeResidualConfig {
    /// Deterministic base PRNG seed.
    pub seed: u64,
    /// Number of within-tail shuffle trials to sample per seed.
    pub trials: usize,
    /// Number of deterministic seed batches.
    pub seed_count: usize,
}

impl Default for TreeResidualConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_SEED,
            trials: DEFAULT_TRIALS,
            seed_count: DEFAULT_SEED_COUNT,
        }
    }
}

/// Error returned by the tree-residual cross-tail n-gram null.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TreeResidualError {
    /// The verified corpus could not be reconstructed or read.
    Grid(GridError),
    /// The shared-region mask could not be reconstructed.
    Perseus(perseus::PerseusError),
    /// At least one Monte-Carlo trial is required.
    ZeroTrials,
    /// At least one deterministic seed batch is required.
    ZeroSeedCount,
    /// K-gram length must be at least one.
    InvalidK {
        /// Requested k-gram length.
        k: usize,
    },
    /// The caller supplied a different number of keys and message streams.
    KeyCountMismatch {
        /// Number of message keys.
        keys: usize,
        /// Number of message streams.
        messages: usize,
    },
    /// The reconstructed mask count did not match the message count.
    MessageMaskMismatch {
        /// Number of message streams.
        messages: usize,
        /// Number of partition masks.
        masks: usize,
    },
    /// One message's mask length differed from its stream length.
    TailMaskLengthMismatch {
        /// Message key whose mask could not be applied.
        message_key: &'static str,
        /// Reading-layer stream length.
        values: usize,
        /// Mask length.
        mask: usize,
    },
    /// A shuffle bound did not fit in the PRNG draw helper.
    RandomBoundTooLarge {
        /// Requested exclusive upper bound.
        bound: usize,
    },
    /// The configured sample count was too large for allocation or p-values.
    SampleCountTooLarge,
}

impl From<GridError> for TreeResidualError {
    fn from(value: GridError) -> Self {
        Self::Grid(value)
    }
}

impl From<perseus::PerseusError> for TreeResidualError {
    fn from(value: perseus::PerseusError) -> Self {
        Self::Perseus(value)
    }
}

impl From<crate::nulls::null::RandomBoundError> for TreeResidualError {
    fn from(error: crate::nulls::null::RandomBoundError) -> Self {
        Self::RandomBoundTooLarge { bound: error.bound }
    }
}

impl fmt::Display for TreeResidualError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Grid(grid_error) => write!(f, "grid/order error: {grid_error:?}"),
            Self::Perseus(perseus_error) => {
                write!(f, "shared-region reconstruction error: {perseus_error}")
            }
            Self::ZeroTrials => write!(f, "at least one Monte-Carlo trial per seed is required"),
            Self::ZeroSeedCount => write!(f, "at least one deterministic seed batch is required"),
            Self::InvalidK { k } => write!(f, "invalid k-gram length {k}; use k >= 1"),
            Self::KeyCountMismatch { keys, messages } => write!(
                f,
                "internal key/message count mismatch: {keys} keys, {messages} messages"
            ),
            Self::MessageMaskMismatch { messages, masks } => write!(
                f,
                "internal message/mask mismatch: {messages} messages, {masks} masks"
            ),
            Self::TailMaskLengthMismatch {
                message_key,
                values,
                mask,
            } => write!(
                f,
                "internal mask length mismatch for {message_key}: {values} values, {mask} mask flags"
            ),
            Self::RandomBoundTooLarge { bound } => {
                write!(f, "shuffle bound {bound} is too large")
            }
            Self::SampleCountTooLarge => write!(f, "tree-residual sample count is too large"),
        }
    }
}

impl std::error::Error for TreeResidualError {}

/// Stream scope used for one cross-message statistic row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TreeResidualScope {
    /// Residual tails after applying the Experiment 7C shared-region mask.
    ResidualTails,
    /// Full unmasked messages, used as a sanity cross-check.
    FullMessages,
}

impl TreeResidualScope {
    /// Human-readable scope label for reports.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ResidualTails => "residual-tails",
            Self::FullMessages => "full-messages",
        }
    }
}

/// Per-message residual-tail summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageTailSummary {
    /// Message key.
    pub message_key: &'static str,
    /// Number of unmasked residual symbols in this message.
    pub residual_symbols: usize,
    /// Number of contiguous unmasked residual segments.
    pub residual_segments: usize,
    /// Longest contiguous residual segment.
    pub longest_segment: usize,
}

/// Cross-message distinct k-gram overlap statistic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrossTailStatistic {
    /// Number of distinct k-gram kinds seen in at least one message.
    pub total_distinct_ngrams: usize,
    /// Number of distinct k-gram kinds seen in at least two different messages.
    pub shared_distinct_ngrams: usize,
    /// Largest number of messages containing any one k-gram kind.
    pub max_messages_per_ngram: usize,
}

/// Monte-Carlo distribution band for the shared-k-gram count.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CrossTailNullBand {
    /// Number of shuffled samples.
    pub samples: usize,
    /// Mean shared-k-gram count.
    pub mean: f64,
    /// Smallest sampled shared-k-gram count.
    pub min: usize,
    /// Lower pointwise 95% percentile edge.
    pub q025: usize,
    /// Sample median.
    pub median: f64,
    /// Upper pointwise 95% percentile edge.
    pub q975: usize,
    /// Largest sampled shared-k-gram count.
    pub max: usize,
}

impl From<UsizeBand> for CrossTailNullBand {
    fn from(band: UsizeBand) -> Self {
        // `CrossTailNullBand` names its trial count `samples`; the rest map directly.
        Self {
            samples: band.trials,
            mean: band.mean,
            min: band.min,
            q025: band.q025,
            median: band.median,
            q975: band.q975,
            max: band.max,
        }
    }
}

/// Real-vs-null row for one scope and k-gram length.
#[derive(Clone, Debug, PartialEq)]
pub struct TreeResidualRow {
    /// Stream scope for this row.
    pub scope: TreeResidualScope,
    /// K-gram length.
    pub k: usize,
    /// Observed cross-message statistic.
    pub observed: CrossTailStatistic,
    /// Shuffle-null distribution.
    pub null: CrossTailNullBand,
    /// Number of shuffles with count less than or equal to the observed count.
    pub lower_tail_count: usize,
    /// Number of shuffles with count greater than or equal to the observed
    /// count.
    pub upper_tail_count: usize,
    /// Add-one lower-tail empirical p-value.
    pub lower_tail_p: f64,
    /// Add-one upper-tail empirical p-value; this is the reused-motif signal
    /// direction.
    pub upper_tail_p: f64,
    /// Add-one two-sided empirical p-value, capped at one.
    pub two_sided_p: f64,
    /// Whether this row has a pointwise significant upper-tail excess.
    pub significant_excess: bool,
}

/// Complete tree-residual cross-tail n-gram null report.
#[derive(Clone, Debug, PartialEq)]
pub struct TreeResidualReport {
    /// Configuration used for the run.
    pub config: TreeResidualConfig,
    /// Reading order used for the real and shuffled streams.
    pub order: ReadingOrder,
    /// Per-message stream lengths in corpus order.
    pub message_lengths: Vec<(&'static str, usize)>,
    /// Total reading-layer symbols across full messages.
    pub total_length: usize,
    /// Reconstructed shared/non-shared partition reused from Experiment 7C.
    pub partition: SharedPartition,
    /// Per-message residual-tail summaries.
    pub tail_lengths: Vec<MessageTailSummary>,
    /// Total residual-tail symbols across messages.
    pub tail_total_length: usize,
    /// Deterministic seed batches actually sampled.
    pub seeds: Vec<u64>,
    /// Real-vs-null rows for residual tails and full-message sanity checks.
    pub rows: Vec<TreeResidualRow>,
}

impl Report for TreeResidualReport {
    fn render(&self) -> String {
        let mut out = String::new();
        append_tree_residual_header(&mut out, self);
        report::appendln!(&mut out);
        append_tree_residual_rows(&mut out, self);
        report::appendln!(&mut out);
        append_tree_residual_interpretation(&mut out, self);
        out
    }
}

fn append_tree_residual_header(out: &mut String, report: &TreeResidualReport) {
    report::appendln!(out, "tree-residual cross-tail n-gram null");
    report::appendln!(out, "order: {}", report.order.name());
    report::appendln!(out, "seed: {}", report.config.seed);
    report::appendln!(out, "seed batches: {}", report.config.seed_count);
    report::appendln!(out, "trials per seed: {}", report.config.trials);
    report::appendln!(
        out,
        "null samples per row: {}",
        report
            .config
            .trials
            .saturating_mul(report.config.seed_count)
    );
    report::appendln!(
        out,
        "message lengths: {}",
        report::format_message_lengths(&report.message_lengths)
    );
    report::appendln!(out, "pooled full length: {}", report.total_length);
    report::appendln!(
        out,
        "residual tail lengths: {}",
        format_tail_lengths(&report.tail_lengths)
    );
    report::appendln!(out, "pooled residual length: {}", report.tail_total_length);
    report::appendln!(
        out,
        "mask reused: Experiment 7C Perseus shared-region definition, same-offset runs len >= {} in the earliest leading-family alignment or East/West counterpart pairs",
        report.partition.min_shared_run_len
    );
    report::appendln!(
        out,
        "boundary rule: k-grams are built within one message residual segment at a time; no k-gram crosses a message join or a masked shared span"
    );
    report::appendln!(
        out,
        "statistic: distinct k-gram kinds occurring in >=2 different messages, position-independent across message tails"
    );
    report::appendln!(
        out,
        "null: Fisher-Yates shuffle within each message tail, preserving residual segment lengths and that message's exact residual symbol multiset"
    );
    report::appendln!(
        out,
        "full-message sanity: the same statistic and shuffle are also run on unmasked messages to verify that the aligned trunk drives the known sharing"
    );
    report::appendln!(out, "sampled seeds: {}", format_seed_list(&report.seeds));
}

fn append_tree_residual_rows(out: &mut String, report: &TreeResidualReport) {
    report::appendln!(
        out,
        "{:<15} {:>2} {:>8} {:>9} {:>7} {:>10} {:>12} {:>8} {:>9} {:>9} {:>8}",
        "scope",
        "k",
        "shared",
        "distinct",
        "maxmsg",
        "null mean",
        "null 95%",
        "null max",
        "p>=obs",
        "p2",
        "verdict"
    );
    for row in &report.rows {
        report::appendln!(
            out,
            "{:<15} {:>2} {:>8} {:>9} {:>7} {:>10.2} {:>12} {:>8} {:>9} {:>9} {:>8}",
            row.scope.label(),
            row.k,
            row.observed.shared_distinct_ngrams,
            row.observed.total_distinct_ngrams,
            row.observed.max_messages_per_ngram,
            row.null.mean,
            format_tree_residual_band(row.null),
            row.null.max,
            report::format_probability(row.upper_tail_p),
            report::format_probability(row.two_sided_p),
            format_tree_residual_verdict(row)
        );
    }
}

fn append_tree_residual_interpretation(out: &mut String, report: &TreeResidualReport) {
    let residual_excesses = tree_residual_excess_labels(report, TreeResidualScope::ResidualTails);
    let full_excesses = tree_residual_excess_labels(report, TreeResidualScope::FullMessages);

    if residual_excesses.is_empty() {
        report::appendln!(
            out,
            "Interpretation: after the Experiment 7C shared-region mask is removed, the divergent tails do not show a pointwise upper-tail excess of position-independent shared k-grams at the scanned k values. This supports the negative hypothesis: the cross-message sharing is explained by the aligned trunk rather than by a second floating reused-key or repeated-motif layer."
        );
    } else {
        report::appendln!(
            out,
            "Interpretation: residual tails show a pointwise upper-tail excess at {}. This table has 4 pointwise tests (residual/full scopes x k in {{3,4}}), and the reported p values are uncorrected across that family. Treat this as marginal and multiplicity-sensitive, not a plaintext claim. The most parsimonious reading is that the documented Perseus 7C trunk mask is slightly incomplete and leaks a little residual cross-message structure; this is not evidence of a second floating reused-key or repeated-motif layer. It must be integrity-checked against the Experiment-0 corpus before interpretation.",
            residual_excesses.join(", ")
        );
    }

    if full_excesses.is_empty() {
        report::appendln!(
            out,
            "Sanity cross-check: full unmasked messages did not exceed the shuffle band in this configured run, so this run does not validate the trunk-driving expectation."
        );
    } else {
        report::appendln!(
            out,
            "Sanity cross-check: full unmasked messages exceed the shuffle band at {}, confirming that the statistic can see the known aligned sharing before the mask is applied.",
            full_excesses.join(", ")
        );
    }
    report::appendln!(
        out,
        "The result is conditional on the fixed engine-verified honeycomb streams and on the Perseus shared-region operationalization printed above. It uses only integer reading-layer values, with no symbol-meaning guesses or language scoring."
    );
}

fn tree_residual_excess_labels(
    report: &TreeResidualReport,
    scope: TreeResidualScope,
) -> Vec<String> {
    report
        .rows
        .iter()
        .filter(|row| row.scope == scope && row.significant_excess)
        .map(|row| {
            format!(
                "k={} (p>={})",
                row.k,
                report::format_probability(row.upper_tail_p)
            )
        })
        .collect()
}

fn format_tail_lengths(lengths: &[MessageTailSummary]) -> String {
    lengths
        .iter()
        .map(|summary| {
            format!(
                "{}:{}({} segs,max {})",
                summary.message_key,
                summary.residual_symbols,
                summary.residual_segments,
                summary.longest_segment
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_seed_list(seeds: &[u64]) -> String {
    seeds
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_tree_residual_band(band: CrossTailNullBand) -> String {
    format!("{}..{}", band.q025, band.q975)
}

fn format_tree_residual_verdict(row: &TreeResidualRow) -> &'static str {
    if row.significant_excess {
        "excess"
    } else if row.observed.shared_distinct_ngrams < row.null.q025 {
        "low"
    } else {
        "inside"
    }
}

mod compute;
#[cfg(test)]
mod tests;

pub use compute::run_tree_residual;

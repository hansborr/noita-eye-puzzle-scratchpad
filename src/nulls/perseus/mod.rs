//! Experiment 7C: Perseus's shared-region recurrence observation.
//!
//! This module tests one narrow structural claim from the community record:
//! reading-layer symbols that occur in non-shared regions allegedly do not
//! recur in later shared regions of size at least two. The implementation uses
//! the accepted honeycomb trigram streams and a fixed-position region mask
//! reconstructed from same-offset common runs.
//!
//! The operationalization is deliberately conservative and documented in the
//! CLI output: a shared run is selected when it is either part of the earliest
//! leading-family alignment, or is an aligned East/West counterpart run. This
//! matches the repository's documented anchors while avoiding unrelated short
//! incidental repeats elsewhere in the corpus. The null keeps that reconstructed
//! position mask fixed and shuffles each message's symbol values within its own
//! length and multiset.

use std::fmt;

use crate::analysis::orders::{self, GridError, ReadingOrder, read_corpus_message_values};
use crate::core::trigram::TrigramValue;
use crate::nulls::null::{NullTestError, WithinMessageShuffle, add_one_p_value, run_null_test};

mod compute;
mod report;
#[cfg(test)]
mod tests;

pub(crate) use compute::build_shared_partition;
use compute::{recurrence_null_band, recurrence_statistic};

/// Default deterministic Monte-Carlo seed for the Perseus recurrence null.
pub const DEFAULT_SEED: u64 = 0x7065_7273_6575_7357;
/// Default number of within-message shuffle trials.
pub const DEFAULT_TRIALS: usize = 1_000;
/// Minimum length, in reading-layer trigrams, for a shared section.
pub const MIN_SHARED_RUN_LEN: usize = 2;
/// Conventional pointwise lower-tail significance cutoff.
pub const SIGNIFICANCE_ALPHA: f64 = 0.05;
/// Community-quoted chance reference for the strict no-recurrence claim.
pub const DOCUMENTED_REFERENCE_CHANCE: f64 = 0.001_92;

/// Configuration for the Perseus recurrence null.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PerseusConfig {
    /// Explicit deterministic PRNG seed.
    pub seed: u64,
    /// Number of within-message shuffle trials.
    pub trials: usize,
}

impl Default for PerseusConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_SEED,
            trials: DEFAULT_TRIALS,
        }
    }
}

/// Error returned by the Perseus recurrence analysis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PerseusError {
    /// The verified corpus could not be reconstructed or read.
    Grid(GridError),
    /// At least one Monte-Carlo trial is required.
    ZeroTrials,
    /// The caller supplied a different number of keys and message streams.
    KeyCountMismatch {
        /// Number of message keys.
        keys: usize,
        /// Number of message streams.
        messages: usize,
    },
    /// A shuffled stream no longer matched the reconstructed partition shape.
    MessageMaskMismatch {
        /// Number of message streams.
        messages: usize,
        /// Number of partition masks.
        masks: usize,
    },
    /// A reconstructed shared run exceeded the message boundary.
    SharedRunOutOfBounds {
        /// Message key whose mask could not be marked.
        message_key: &'static str,
        /// Shared-run start offset.
        start: usize,
        /// Shared-run length.
        len: usize,
    },
    /// A shuffle bound did not fit in the PRNG draw helper.
    RandomBoundTooLarge {
        /// Requested exclusive upper bound.
        bound: usize,
    },
}

impl From<GridError> for PerseusError {
    fn from(value: GridError) -> Self {
        Self::Grid(value)
    }
}

impl From<crate::nulls::null::RandomBoundError> for PerseusError {
    fn from(error: crate::nulls::null::RandomBoundError) -> Self {
        Self::RandomBoundTooLarge { bound: error.bound }
    }
}

impl fmt::Display for PerseusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Grid(grid_error) => write!(f, "grid/order error: {grid_error:?}"),
            Self::ZeroTrials => write!(f, "at least one Monte-Carlo trial is required"),
            Self::KeyCountMismatch { keys, messages } => write!(
                f,
                "internal key/message count mismatch: {keys} keys, {messages} messages"
            ),
            Self::MessageMaskMismatch { messages, masks } => write!(
                f,
                "internal message/mask mismatch: {messages} messages, {masks} masks"
            ),
            Self::SharedRunOutOfBounds {
                message_key,
                start,
                len,
            } => write!(
                f,
                "shared run {message_key}@{start}+{len} exceeds the message boundary"
            ),
            Self::RandomBoundTooLarge { bound } => {
                write!(f, "shuffle bound {bound} is too large")
            }
        }
    }
}

impl std::error::Error for PerseusError {}

/// Why a pairwise common run was included in the shared-region mask.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SharedRunRole {
    /// The run starts at the earliest same-offset shared position and belongs
    /// to the leading-family alignment.
    LeadingFamily,
    /// The run belongs to a mirrored East/West counterpart pair.
    Counterpart,
    /// The run is both leading-family and counterpart evidence.
    LeadingCounterpart,
}

impl SharedRunRole {
    /// Human-readable role label for reports.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::LeadingFamily => "leading-family",
            Self::Counterpart => "counterpart",
            Self::LeadingCounterpart => "leading+counterpart",
        }
    }

    const fn includes_counterpart(self) -> bool {
        matches!(self, Self::Counterpart | Self::LeadingCounterpart)
    }
}

/// One selected same-offset pairwise shared run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedRunSummary {
    /// Left message key.
    pub left_key: &'static str,
    /// Right message key.
    pub right_key: &'static str,
    /// Zero-based start offset in both aligned message streams.
    pub start: usize,
    /// Run length in reading-layer trigrams.
    pub len: usize,
    /// Inclusion role for this run.
    pub role: SharedRunRole,
}

/// One half-open shared span in a single message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedSpan {
    /// Zero-based start offset.
    pub start: usize,
    /// Span length in reading-layer trigrams.
    pub len: usize,
}

impl SharedSpan {
    /// Exclusive end offset.
    #[must_use]
    pub const fn end(&self) -> usize {
        self.start + self.len
    }
}

/// Per-message shared/non-shared partition summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessagePartitionSummary {
    /// Message key.
    pub message_key: &'static str,
    /// Reading-layer stream length.
    pub len: usize,
    /// Number of positions marked shared.
    pub shared_symbols: usize,
    /// Number of positions marked non-shared.
    pub non_shared_symbols: usize,
    /// Half-open shared spans.
    pub shared_spans: Vec<SharedSpan>,
}

/// All-message common prefix under the reconstructed alignment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalSharedPrefix {
    /// Zero-based start offset.
    pub start: usize,
    /// Prefix length in reading-layer trigrams.
    pub len: usize,
    /// Shared trigram values in the prefix.
    pub values: Vec<u8>,
}

/// Longest selected run for one East/West counterpart pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CounterpartRunSummary {
    /// East message key.
    pub east_key: &'static str,
    /// West message key.
    pub west_key: &'static str,
    /// Zero-based start offset in both aligned message streams.
    pub start: usize,
    /// Run length in reading-layer trigrams.
    pub len: usize,
}

/// Reconstructed shared/non-shared region partition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedPartition {
    /// Minimum selected shared-run length.
    pub min_shared_run_len: usize,
    /// Earliest same-offset shared-run start, used for leading-family runs.
    pub leading_start: Option<usize>,
    /// All-message common prefix at the leading start, when present.
    pub global_prefix: Option<GlobalSharedPrefix>,
    /// Selected pairwise common runs used to mark the mask.
    pub selected_pair_runs: Vec<SharedRunSummary>,
    /// Longest selected run for each East/West counterpart.
    pub counterpart_runs: Vec<CounterpartRunSummary>,
    /// Per-message partition summaries.
    pub messages: Vec<MessagePartitionSummary>,
    masks: Vec<Vec<bool>>,
}

impl SharedPartition {
    pub(crate) fn masks(&self) -> &[Vec<bool>] {
        &self.masks
    }
}

/// Per-message recurrence summary.
#[derive(Clone, Debug, PartialEq)]
pub struct MessageRecurrenceSummary {
    /// Message key.
    pub message_key: &'static str,
    /// Number of non-shared positions scanned.
    pub non_shared_occurrences: usize,
    /// Number of shared positions with at least one earlier non-shared symbol.
    pub tested_shared_occurrences: usize,
    /// Count of tested shared positions whose value had appeared earlier in a
    /// non-shared position in the same message.
    pub recurrent_occurrences: usize,
    /// Recurrence rate for this message.
    pub rate: f64,
    /// Distinct recurrent symbol values for this message.
    pub recurrent_symbols: Vec<u8>,
}

/// Perseus recurrence statistic for real or shuffled streams.
#[derive(Clone, Debug, PartialEq)]
pub struct RecurrenceStatistic {
    /// Count of non-shared positions scanned.
    pub non_shared_occurrences: usize,
    /// Count of shared positions with at least one earlier non-shared symbol.
    pub tested_shared_occurrences: usize,
    /// Count of tested shared positions whose value had appeared earlier in a
    /// non-shared position in the same message.
    pub recurrent_occurrences: usize,
    /// `recurrent_occurrences / tested_shared_occurrences`.
    pub rate: f64,
    /// Distinct recurrent symbol values across messages.
    pub recurrent_symbols: Vec<u8>,
    /// Per-message rows.
    pub messages: Vec<MessageRecurrenceSummary>,
}

/// Monte-Carlo lower-tail band for the recurrence count and rate.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RecurrenceNullBand {
    /// Number of shuffle trials sampled.
    pub trials: usize,
    /// Mean recurrent-occurrence count.
    pub count_mean: f64,
    /// Smallest sampled recurrent-occurrence count.
    pub count_min: usize,
    /// Lower pointwise 95% percentile edge for recurrence count.
    pub count_q025: usize,
    /// Sample median recurrent-occurrence count.
    pub count_median: f64,
    /// Upper pointwise 95% percentile edge for recurrence count.
    pub count_q975: usize,
    /// Largest sampled recurrent-occurrence count.
    pub count_max: usize,
    /// Mean recurrence rate.
    pub rate_mean: f64,
    /// Lower pointwise 95% percentile edge for recurrence rate.
    pub rate_q025: f64,
    /// Sample median recurrence rate.
    pub rate_median: f64,
    /// Upper pointwise 95% percentile edge for recurrence rate.
    pub rate_q975: f64,
}

/// Complete Perseus recurrence-null report.
#[derive(Clone, Debug, PartialEq)]
pub struct PerseusReport {
    /// Configuration used for the run.
    pub config: PerseusConfig,
    /// Reading order used for the real stream.
    pub order: ReadingOrder,
    /// Per-message stream lengths.
    pub message_lengths: Vec<(&'static str, usize)>,
    /// Total reading-layer symbols.
    pub total_length: usize,
    /// Reconstructed shared/non-shared partition.
    pub partition: SharedPartition,
    /// Observed recurrence statistic.
    pub observed: RecurrenceStatistic,
    /// Shuffle-null band.
    pub null: RecurrenceNullBand,
    /// Number of shuffles with recurrence count less than or equal to observed.
    pub empirical_p_count: usize,
    /// Add-one lower-tail empirical p-value.
    pub empirical_p: f64,
    /// Community-quoted chance reference, carried only for comparison.
    pub documented_reference_chance: f64,
    /// Whether the lower-tail result is pointwise significant at 5%.
    pub significant: bool,
}

/// Runs the Perseus recurrence null on the verified eye corpus.
///
/// # Errors
/// Returns [`PerseusError`] when the corpus cannot be reconstructed, the
/// accepted reading order is incompatible with a grid, or the configuration is
/// invalid.
pub fn run_perseus(config: PerseusConfig) -> Result<PerseusReport, PerseusError> {
    validate_config(config)?;
    let grids = orders::corpus_grids()?;
    let keys = grids
        .iter()
        .map(crate::analysis::orders::GlyphGrid::message_key)
        .collect::<Vec<_>>();
    let order = orders::accepted_honeycomb_order();
    let message_values = read_corpus_message_values(&grids, order)?;
    report_from_message_values(config, order, &keys, &message_values)
}

fn report_from_message_values(
    config: PerseusConfig,
    order: ReadingOrder,
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
) -> Result<PerseusReport, PerseusError> {
    validate_config(config)?;
    let partition = build_shared_partition(keys, message_values)?;
    report_from_partition(config, order, keys, message_values, partition)
}

fn report_from_partition(
    config: PerseusConfig,
    order: ReadingOrder,
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    partition: SharedPartition,
) -> Result<PerseusReport, PerseusError> {
    validate_config(config)?;
    let observed = recurrence_statistic(keys, message_values, &partition)?;
    let sampler = WithinMessageShuffle {
        messages: message_values,
    };

    // The recurrence statistic is naturally fallible (a `MessageMaskMismatch`
    // can never fire here because the shuffle preserves per-message length, but
    // the type carries the possibility), so the closure is passed directly and
    // the harness propagates any `Err` as `NullTestError::Statistic`.
    let result = run_null_test(
        |shuffled| {
            recurrence_statistic(keys, shuffled, &partition)
                .map(|statistic| statistic.recurrent_occurrences)
        },
        observed.recurrent_occurrences,
        &sampler,
        config.trials,
        config.seed,
    )
    .map_err(|error| match error {
        NullTestError::Random(bound) => PerseusError::from(bound),
        NullTestError::Statistic(error) => error,
    })?;

    let empirical_p_count = result.lower_tail_count;
    let null = recurrence_null_band(&result.samples, observed.tested_shared_occurrences);
    let empirical_p = add_one_p_value(empirical_p_count, config.trials);
    let significant =
        observed.recurrent_occurrences <= null.count_q025 && empirical_p <= SIGNIFICANCE_ALPHA;
    let lengths = message_values.iter().map(Vec::len).collect::<Vec<_>>();
    let total_length = lengths.iter().sum();

    Ok(PerseusReport {
        config,
        order,
        message_lengths: keys.iter().copied().zip(lengths).collect(),
        total_length,
        partition,
        observed,
        null,
        empirical_p_count,
        empirical_p,
        documented_reference_chance: DOCUMENTED_REFERENCE_CHANCE,
        significant,
    })
}

fn validate_config(config: PerseusConfig) -> Result<(), PerseusError> {
    if config.trials == 0 {
        return Err(PerseusError::ZeroTrials);
    }
    Ok(())
}

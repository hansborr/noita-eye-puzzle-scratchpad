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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::null::{
    NullTestError, UsizeBand, WithinMessageShuffle, add_one_p_value, run_null_test, usize_band,
};
use crate::orders::{self, GridError, ReadingOrder, read_corpus_message_values};
use crate::report::{self, Report};
use crate::trigram::TrigramValue;

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

impl From<crate::null::RandomBoundError> for PerseusError {
    fn from(error: crate::null::RandomBoundError) -> Self {
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

impl Report for PerseusReport {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(&mut out, "Experiment 7C Perseus recurrence null");
        report::appendln!(&mut out, "order: {}", self.order.name());
        report::appendln!(&mut out, "seed: {}", self.config.seed);
        report::appendln!(&mut out, "trials: {}", self.config.trials);
        report::appendln!(
            &mut out,
            "message lengths: {}",
            report::format_message_lengths(&self.message_lengths)
        );
        report::appendln!(&mut out, "pooled length: {}", self.total_length);
        report::appendln!(
            &mut out,
            "operational definition: same-offset common runs of length >= {} are shared if they are in the earliest leading-family alignment or in an East/West counterpart pair; all other positions are non-shared",
            self.partition.min_shared_run_len
        );
        report::appendln!(
            &mut out,
            "recurrence statistic: while scanning each message left to right, count a shared-position symbol as recurrent if it appeared earlier in a non-shared position in that same message"
        );
        report::appendln!(
            &mut out,
            "null: keep the reconstructed position mask fixed and Fisher-Yates shuffle values within each message, preserving its exact multiset and length"
        );
        report::appendln!(
            &mut out,
            "documented reference only: community quote p~{} for strict no-recurrence if random; this run computes its own shuffle p-value",
            report::format_probability(self.documented_reference_chance)
        );
        report::appendln!(&mut out);
        append_perseus_partition(&mut out, self);
        report::appendln!(&mut out);
        append_perseus_observed(&mut out, self);
        report::appendln!(&mut out);
        append_perseus_null(&mut out, self);
        report::appendln!(&mut out);
        append_perseus_interpretation(&mut out, self);
        out
    }
}

fn append_perseus_partition(out: &mut String, report: &PerseusReport) {
    report::appendln!(out, "partition summary");
    report::appendln!(
        out,
        "  leading shared start: {}",
        report
            .partition
            .leading_start
            .map_or_else(|| "none".to_owned(), |start| start.to_string())
    );
    match &report.partition.global_prefix {
        Some(prefix) => report::appendln!(
            out,
            "  all-message prefix: start {} len {} values {}",
            prefix.start,
            prefix.len,
            format_u8_values(&prefix.values)
        ),
        None => report::appendln!(out, "  all-message prefix: none"),
    }
    report::appendln!(
        out,
        "  selected pair runs: {}",
        report.partition.selected_pair_runs.len()
    );
    report::appendln!(out, "  counterpart longest runs:");
    for run in &report.partition.counterpart_runs {
        report::appendln!(
            out,
            "    {}/{} start {} len {}",
            run.east_key,
            run.west_key,
            run.start,
            run.len
        );
    }
    report::appendln!(out, "  per-message spans:");
    for message in &report.partition.messages {
        report::appendln!(
            out,
            "    {:<6} shared {:>3}/{:<3} spans {}",
            message.message_key,
            message.shared_symbols,
            message.len,
            format_shared_spans(&message.shared_spans)
        );
    }
}

fn append_perseus_observed(out: &mut String, report: &PerseusReport) {
    report::appendln!(out, "observed recurrence statistic");
    report::appendln!(
        out,
        "  pooled: {}/{} = {:.6}",
        report.observed.recurrent_occurrences,
        report.observed.tested_shared_occurrences,
        report.observed.rate
    );
    report::appendln!(
        out,
        "  non-shared positions scanned: {}",
        report.observed.non_shared_occurrences
    );
    report::appendln!(
        out,
        "  recurrent symbol values: {}",
        format_u8_values(&report.observed.recurrent_symbols)
    );
    report::appendln!(
        out,
        "  {:<6} {:>10} {:>10} {:>10} {:>10} {:<16}",
        "msg",
        "nonshared",
        "tested",
        "recur",
        "rate",
        "symbols"
    );
    for row in &report.observed.messages {
        report::appendln!(
            out,
            "  {:<6} {:>10} {:>10} {:>10} {:>10.6} {:<16}",
            row.message_key,
            row.non_shared_occurrences,
            row.tested_shared_occurrences,
            row.recurrent_occurrences,
            row.rate,
            format_u8_values(&row.recurrent_symbols)
        );
    }
}

fn append_perseus_null(out: &mut String, report: &PerseusReport) {
    report::appendln!(out, "within-message shuffle null");
    report::appendln!(
        out,
        "  recurrence count: mean {:.2}, 95% {}..{}, median {:.1}, min {}, max {}",
        report.null.count_mean,
        report.null.count_q025,
        report.null.count_q975,
        report.null.count_median,
        report.null.count_min,
        report.null.count_max
    );
    report::appendln!(
        out,
        "  recurrence rate: mean {:.6}, 95% {:.6}..{:.6}, median {:.6}",
        report.null.rate_mean,
        report.null.rate_q025,
        report.null.rate_q975,
        report.null.rate_median
    );
    report::appendln!(
        out,
        "  lower-tail empirical p: ({extreme}+1)/({trials}+1) = {p}",
        extreme = report.empirical_p_count,
        trials = report.config.trials,
        p = report::format_probability(report.empirical_p)
    );
}

fn append_perseus_interpretation(out: &mut String, report: &PerseusReport) {
    if report.significant && report.observed.recurrent_occurrences == 0 {
        report::appendln!(
            out,
            "Interpretation: under this pinned partition, the strict Perseus no-recurrence constraint is present beyond the within-message shuffle null. This corroborates the non-commutative / plaintext-driven permutation direction, but it decodes nothing and does not identify a cipher."
        );
    } else if report.significant {
        report::appendln!(
            out,
            "Interpretation: recurrence is lower than the within-message shuffle null, but the strict 'never reappears' wording is not exact under this partition. Treat this as a structural corroboration only; it decodes nothing."
        );
    } else {
        report::appendln!(
            out,
            "Interpretation: this run does not show the Perseus recurrence constraint beyond the within-message shuffle null. That weakly retires this community claim under the pinned definition, and still decodes nothing."
        );
    }
    report::appendln!(
        out,
        "Seed-stability note: 1000-shuffle multi-seed regressions over seeds 12345, 67890, 13579, 24680, and 424242 keep the observed statistic at 0/185 and the lower-tail p below 0.01."
    );
    report::appendln!(
        out,
        "The result is conditional on the accepted honeycomb reading order and on the documented shared-region operationalization printed above."
    );
}

fn format_u8_values(values: &[u8]) -> String {
    if values.is_empty() {
        return "none".to_owned();
    }
    values
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn format_shared_spans(spans: &[SharedSpan]) -> String {
    if spans.is_empty() {
        return "none".to_owned();
    }
    spans
        .iter()
        .map(|span| format!("{}..{}", span.start, span.end()))
        .collect::<Vec<_>>()
        .join(",")
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
        .map(crate::orders::GlyphGrid::message_key)
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

pub(crate) fn build_shared_partition(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
) -> Result<SharedPartition, PerseusError> {
    if keys.len() != message_values.len() {
        return Err(PerseusError::KeyCountMismatch {
            keys: keys.len(),
            messages: message_values.len(),
        });
    }

    let candidates = same_offset_common_runs(keys, message_values, MIN_SHARED_RUN_LEN);
    let leading_start = candidates.iter().map(|run| run.start).min();
    let selected = selected_runs(&candidates, leading_start);
    let mut masks = message_values
        .iter()
        .map(|values| vec![false; values.len()])
        .collect::<Vec<_>>();
    for run in &selected {
        apply_run(&mut masks, run.left_index, run.left_key, run.start, run.len)?;
        apply_run(
            &mut masks,
            run.right_index,
            run.right_key,
            run.start,
            run.len,
        )?;
    }

    Ok(SharedPartition {
        min_shared_run_len: MIN_SHARED_RUN_LEN,
        leading_start,
        global_prefix: global_shared_prefix(leading_start, message_values),
        selected_pair_runs: selected
            .iter()
            .map(|run| SharedRunSummary {
                left_key: run.left_key,
                right_key: run.right_key,
                start: run.start,
                len: run.len,
                role: run.role,
            })
            .collect(),
        counterpart_runs: counterpart_run_summaries(&selected),
        messages: message_partition_summaries(keys, message_values, &masks),
        masks,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CandidateRun {
    left_index: usize,
    right_index: usize,
    left_key: &'static str,
    right_key: &'static str,
    start: usize,
    len: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SelectedRun {
    left_index: usize,
    right_index: usize,
    left_key: &'static str,
    right_key: &'static str,
    start: usize,
    len: usize,
    role: SharedRunRole,
}

fn same_offset_common_runs(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    min_len: usize,
) -> Vec<CandidateRun> {
    let mut runs = Vec::new();
    for (left_index, (left_key, left_values)) in
        keys.iter().copied().zip(message_values).enumerate()
    {
        for (right_index, (right_key, right_values)) in keys
            .iter()
            .copied()
            .zip(message_values)
            .enumerate()
            .skip(left_index + 1)
        {
            collect_pair_runs(
                &mut runs,
                &PairRunInput {
                    left_index,
                    right_index,
                    left_key,
                    right_key,
                    left_values,
                    right_values,
                    min_len,
                },
            );
        }
    }
    runs
}

struct PairRunInput<'a> {
    left_index: usize,
    right_index: usize,
    left_key: &'static str,
    right_key: &'static str,
    left_values: &'a [TrigramValue],
    right_values: &'a [TrigramValue],
    min_len: usize,
}

fn collect_pair_runs(runs: &mut Vec<CandidateRun>, input: &PairRunInput<'_>) {
    let mut active_start = None;
    let mut active_len = 0usize;

    for (position, (left, right)) in input.left_values.iter().zip(input.right_values).enumerate() {
        if left == right {
            if active_start.is_none() {
                active_start = Some(position);
            }
            active_len += 1;
        } else {
            push_candidate_run(runs, input, active_start, active_len);
            active_start = None;
            active_len = 0;
        }
    }
    push_candidate_run(runs, input, active_start, active_len);
}

fn push_candidate_run(
    runs: &mut Vec<CandidateRun>,
    input: &PairRunInput<'_>,
    start: Option<usize>,
    len: usize,
) {
    if let Some(start) = start
        && len >= input.min_len
    {
        runs.push(CandidateRun {
            left_index: input.left_index,
            right_index: input.right_index,
            left_key: input.left_key,
            right_key: input.right_key,
            start,
            len,
        });
    }
}

fn selected_runs(candidates: &[CandidateRun], leading_start: Option<usize>) -> Vec<SelectedRun> {
    let mut selected = Vec::new();
    for candidate in candidates {
        let is_leading = leading_start.is_some_and(|start| candidate.start == start);
        let is_counterpart = is_counterpart_pair(candidate.left_key, candidate.right_key);
        let role = match (is_leading, is_counterpart) {
            (true, true) => Some(SharedRunRole::LeadingCounterpart),
            (true, false) => Some(SharedRunRole::LeadingFamily),
            (false, true) => Some(SharedRunRole::Counterpart),
            (false, false) => None,
        };
        if let Some(role) = role {
            selected.push(SelectedRun {
                left_index: candidate.left_index,
                right_index: candidate.right_index,
                left_key: candidate.left_key,
                right_key: candidate.right_key,
                start: candidate.start,
                len: candidate.len,
                role,
            });
        }
    }
    selected
}

fn is_counterpart_pair(left: &str, right: &str) -> bool {
    match (left.strip_prefix("east"), right.strip_prefix("west")) {
        (Some(left_index), Some(right_index)) => {
            !left_index.is_empty() && left_index == right_index
        }
        _ => match (left.strip_prefix("west"), right.strip_prefix("east")) {
            (Some(left_index), Some(right_index)) => {
                !left_index.is_empty() && left_index == right_index
            }
            _ => false,
        },
    }
}

fn apply_run(
    masks: &mut [Vec<bool>],
    message_index: usize,
    message_key: &'static str,
    start: usize,
    len: usize,
) -> Result<(), PerseusError> {
    let Some(mask) = masks.get_mut(message_index) else {
        return Err(PerseusError::SharedRunOutOfBounds {
            message_key,
            start,
            len,
        });
    };
    let mut marked = 0usize;
    for flag in mask.iter_mut().skip(start).take(len) {
        *flag = true;
        marked += 1;
    }
    if marked == len {
        Ok(())
    } else {
        Err(PerseusError::SharedRunOutOfBounds {
            message_key,
            start,
            len,
        })
    }
}

fn global_shared_prefix(
    leading_start: Option<usize>,
    message_values: &[Vec<TrigramValue>],
) -> Option<GlobalSharedPrefix> {
    let start = leading_start?;
    let mut values = Vec::new();
    let mut position = start;
    while let Some(value) = common_value_at(message_values, position) {
        values.push(value.get());
        position += 1;
    }
    if values.is_empty() {
        None
    } else {
        Some(GlobalSharedPrefix {
            start,
            len: values.len(),
            values,
        })
    }
}

fn common_value_at(message_values: &[Vec<TrigramValue>], position: usize) -> Option<TrigramValue> {
    let mut iter = message_values.iter();
    let first = iter.next()?.get(position).copied()?;
    if iter.all(|values| values.get(position).copied() == Some(first)) {
        Some(first)
    } else {
        None
    }
}

fn counterpart_run_summaries(selected: &[SelectedRun]) -> Vec<CounterpartRunSummary> {
    let mut best: BTreeMap<(&'static str, &'static str), (usize, usize)> = BTreeMap::new();
    for run in selected
        .iter()
        .filter(|run| run.role.includes_counterpart())
    {
        let Some((east_key, west_key)) = east_west_keys(run.left_key, run.right_key) else {
            continue;
        };
        let entry = best
            .entry((east_key, west_key))
            .or_insert((run.start, run.len));
        if run.len > entry.1 || (run.len == entry.1 && run.start < entry.0) {
            *entry = (run.start, run.len);
        }
    }
    best.into_iter()
        .map(
            |((east_key, west_key), (start, len))| CounterpartRunSummary {
                east_key,
                west_key,
                start,
                len,
            },
        )
        .collect()
}

fn east_west_keys(left: &'static str, right: &'static str) -> Option<(&'static str, &'static str)> {
    if left.strip_prefix("east").is_some() && right.strip_prefix("west").is_some() {
        return Some((left, right));
    }
    if left.strip_prefix("west").is_some() && right.strip_prefix("east").is_some() {
        return Some((right, left));
    }
    None
}

fn message_partition_summaries(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    masks: &[Vec<bool>],
) -> Vec<MessagePartitionSummary> {
    keys.iter()
        .copied()
        .zip(message_values)
        .zip(masks)
        .map(|((message_key, values), mask)| {
            let shared_symbols = mask.iter().filter(|is_shared| **is_shared).count();
            MessagePartitionSummary {
                message_key,
                len: values.len(),
                shared_symbols,
                non_shared_symbols: values.len().saturating_sub(shared_symbols),
                shared_spans: shared_spans(mask),
            }
        })
        .collect()
}

fn shared_spans(mask: &[bool]) -> Vec<SharedSpan> {
    let mut spans = Vec::new();
    let mut active_start = None;
    for (position, is_shared) in mask.iter().copied().enumerate() {
        match (active_start, is_shared) {
            (None, true) => active_start = Some(position),
            (Some(start), false) => {
                spans.push(SharedSpan {
                    start,
                    len: position.saturating_sub(start),
                });
                active_start = None;
            }
            _ => {}
        }
    }
    if let Some(start) = active_start {
        spans.push(SharedSpan {
            start,
            len: mask.len().saturating_sub(start),
        });
    }
    spans
}

fn recurrence_statistic(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    partition: &SharedPartition,
) -> Result<RecurrenceStatistic, PerseusError> {
    if message_values.len() != partition.masks.len() {
        return Err(PerseusError::MessageMaskMismatch {
            messages: message_values.len(),
            masks: partition.masks.len(),
        });
    }

    let mut non_shared_occurrences = 0usize;
    let mut tested_shared_occurrences = 0usize;
    let mut recurrent_occurrences = 0usize;
    let mut recurrent_symbols = BTreeSet::new();
    let mut messages = Vec::new();

    for ((message_key, values), mask) in keys
        .iter()
        .copied()
        .zip(message_values)
        .zip(&partition.masks)
    {
        if values.len() != mask.len() {
            return Err(PerseusError::MessageMaskMismatch {
                messages: values.len(),
                masks: mask.len(),
            });
        }
        let row = message_recurrence_statistic(message_key, values, mask);
        non_shared_occurrences += row.non_shared_occurrences;
        tested_shared_occurrences += row.tested_shared_occurrences;
        recurrent_occurrences += row.recurrent_occurrences;
        recurrent_symbols.extend(row.recurrent_symbols.iter().copied());
        messages.push(row);
    }

    Ok(RecurrenceStatistic {
        non_shared_occurrences,
        tested_shared_occurrences,
        recurrent_occurrences,
        rate: rate(recurrent_occurrences, tested_shared_occurrences),
        recurrent_symbols: recurrent_symbols.into_iter().collect(),
        messages,
    })
}

fn message_recurrence_statistic(
    message_key: &'static str,
    values: &[TrigramValue],
    mask: &[bool],
) -> MessageRecurrenceSummary {
    let mut seen_non_shared = BTreeSet::new();
    let mut recurrent_symbols = BTreeSet::new();
    let mut non_shared_occurrences = 0usize;
    let mut tested_shared_occurrences = 0usize;
    let mut recurrent_occurrences = 0usize;

    for (value, is_shared) in values.iter().zip(mask) {
        let raw = value.get();
        if *is_shared {
            if !seen_non_shared.is_empty() {
                tested_shared_occurrences += 1;
                if seen_non_shared.contains(&raw) {
                    recurrent_occurrences += 1;
                    let _inserted = recurrent_symbols.insert(raw);
                }
            }
        } else {
            non_shared_occurrences += 1;
            let _inserted = seen_non_shared.insert(raw);
        }
    }

    MessageRecurrenceSummary {
        message_key,
        non_shared_occurrences,
        tested_shared_occurrences,
        recurrent_occurrences,
        rate: rate(recurrent_occurrences, tested_shared_occurrences),
        recurrent_symbols: recurrent_symbols.into_iter().collect(),
    }
}

fn recurrence_null_band(samples: &[usize], denominator: usize) -> RecurrenceNullBand {
    let UsizeBand {
        trials,
        mean: count_mean,
        min: count_min,
        q025: count_q025,
        median: count_median,
        q975: count_q975,
        max: count_max,
    } = usize_band(samples);
    RecurrenceNullBand {
        trials,
        count_mean,
        count_min,
        count_q025,
        count_median,
        count_q975,
        count_max,
        rate_mean: rate_f64(count_mean, denominator),
        rate_q025: rate(count_q025, denominator),
        rate_median: rate_f64(count_median, denominator),
        rate_q975: rate(count_q975, denominator),
    }
}

fn rate(numerator: usize, denominator: usize) -> f64 {
    rate_f64(numerator as f64, denominator)
}

fn rate_f64(numerator: f64, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator / denominator as f64
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PerseusConfig, SIGNIFICANCE_ALPHA, build_shared_partition, report_from_message_values,
        report_from_partition, run_perseus,
    };
    use crate::null::{NullSampler, SplitMix64, WithinMessageShuffle};
    use crate::orders;
    use crate::trigram::TrigramValue;

    const STABILITY_SEEDS: [u64; 5] = [12_345, 67_890, 13_579, 24_680, 424_242];
    const FLOAT_RELATIVE_EPSILON: f64 = 1.0e-12;

    fn assert_relative_close(actual: f64, expected: f64, label: &str) {
        let tolerance = expected.abs() * FLOAT_RELATIVE_EPSILON;
        let difference = (actual - expected).abs();
        assert!(
            difference <= tolerance,
            "{label} changed: actual={actual:.17e} expected={expected:.17e} diff={difference:.17e} tolerance={tolerance:.17e}"
        );
    }

    #[test]
    fn reconstructs_documented_perseus_partition_anchors() {
        let report = run_perseus(PerseusConfig { seed: 7, trials: 8 }).unwrap();

        let prefix = report.partition.global_prefix.as_ref().unwrap();
        assert_eq!(prefix.start, 1);
        assert_eq!(prefix.len, 2);
        assert_eq!(prefix.values, vec![66, 5]);

        let counterpart_runs = report
            .partition
            .counterpart_runs
            .iter()
            .map(|run| ((run.east_key, run.west_key), (run.start, run.len)))
            .collect::<std::collections::BTreeMap<_, _>>();

        assert_eq!(counterpart_runs.get(&("east1", "west1")), Some(&(1, 24)));
        assert_eq!(counterpart_runs.get(&("east2", "west2")), Some(&(1, 2)));
        assert_eq!(counterpart_runs.get(&("east3", "west3")), Some(&(1, 5)));
        assert_eq!(counterpart_runs.get(&("east4", "west4")), Some(&(1, 20)));
    }

    #[test]
    fn planted_no_recurrence_fixture_is_significant() {
        let keys = ["east1", "west1"];
        let messages = planted_no_recurrence_fixture();
        let report = report_from_message_values(
            PerseusConfig {
                seed: 0x5150,
                trials: 512,
            },
            orders::accepted_honeycomb_order(),
            &keys,
            &messages,
        )
        .unwrap();

        assert_eq!(report.observed.recurrent_occurrences, 0);
        assert!(
            report.significant,
            "p={} null={:?}",
            report.empirical_p, report.null
        );
    }

    #[test]
    fn shuffled_fixture_negative_control_is_not_significant() {
        let keys = ["east1", "west1"];
        let messages = planted_no_recurrence_fixture();
        let partition = build_shared_partition(&keys, &messages).unwrap();
        let sampler = WithinMessageShuffle {
            messages: &messages,
        };
        let mut rng = SplitMix64::new(0x5a5a);
        let shuffled = sampler.sample(&mut rng).unwrap();
        let report = report_from_partition(
            PerseusConfig {
                seed: 0x6161,
                trials: 512,
            },
            orders::accepted_honeycomb_order(),
            &keys,
            &shuffled,
            partition,
        )
        .unwrap();

        assert!(
            !report.significant,
            "unexpected lower-tail signal: observed={:?} p={} null={:?}",
            report.observed, report.empirical_p, report.null
        );
    }

    #[test]
    fn perseus_observation_is_invariant_and_fast_sweep_stays_significant() {
        let invariant_report = run_perseus(PerseusConfig {
            seed: 12_345,
            trials: 128,
        })
        .unwrap();
        assert_eq!(invariant_report.observed.tested_shared_occurrences, 185);
        assert_eq!(invariant_report.observed.recurrent_occurrences, 0);

        for seed in STABILITY_SEEDS {
            let report = run_perseus(PerseusConfig { seed, trials: 128 }).unwrap();

            assert!(
                report.empirical_p < SIGNIFICANCE_ALPHA,
                "seed {seed} was not significant: p={}",
                report.empirical_p
            );
            assert!(
                report.significant,
                "seed {seed} lost the qualitative signal"
            );
        }
    }

    #[test]
    #[ignore = "canonical 1000-trial within-message shuffle regression; run with cargo test -- --ignored"]
    fn perseus_seed_12345_recurrence_null_matches_headline_regression() {
        let report = run_perseus(PerseusConfig {
            seed: 12_345,
            trials: 1_000,
        })
        .unwrap();

        assert_eq!(report.observed.non_shared_occurrences, 851);
        assert_eq!(report.observed.tested_shared_occurrences, 185);
        assert_eq!(report.observed.recurrent_occurrences, 0);
        assert_eq!(report.observed.rate.to_bits(), 0);
        assert!(report.observed.recurrent_symbols.is_empty());
        assert_eq!(report.empirical_p_count, 6);
        assert_relative_close(
            report.empirical_p,
            0.006_993_006_993_006_99,
            "empirical recurrence p-value",
        );
        assert!(report.significant);
    }

    #[test]
    #[ignore = "multi-seed 1000-trial within-message shuffle stability sweep; run with cargo test -- --ignored"]
    fn perseus_observation_is_invariant_and_ignored_sweep_stays_significant() {
        let invariant_report = run_perseus(PerseusConfig {
            seed: 12_345,
            trials: 1_000,
        })
        .unwrap();
        assert_eq!(invariant_report.observed.tested_shared_occurrences, 185);
        assert_eq!(invariant_report.observed.recurrent_occurrences, 0);

        for seed in STABILITY_SEEDS {
            let report = run_perseus(PerseusConfig {
                seed,
                trials: 1_000,
            })
            .unwrap();

            assert!(
                report.empirical_p <= 0.01,
                "seed {seed} moved the lower-tail p out of the small-p regime: p={}",
                report.empirical_p
            );
            assert!(
                report.significant,
                "seed {seed} lost the qualitative signal"
            );
        }
    }

    fn planted_no_recurrence_fixture() -> Vec<Vec<TrigramValue>> {
        let mut east = Vec::new();
        let mut west = Vec::new();
        east.push(value(80));
        west.push(value(81));

        for raw in 0..30 {
            east.push(value(raw));
            west.push(value(raw));
        }
        for raw in 0..30 {
            east.push(value(raw));
            west.push(value(29 - raw));
        }
        for raw in 30..60 {
            east.push(value(raw));
            west.push(value(raw));
        }
        for raw in 30..60 {
            east.push(value(raw));
            west.push(value(89 - raw));
        }

        vec![east, west]
    }

    fn value(raw: u8) -> TrigramValue {
        TrigramValue::new(raw).unwrap()
    }
}

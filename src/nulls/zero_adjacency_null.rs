//! Experiment 7D: zero-adjacency forbidden-successor null.
//!
//! This module tests whether the accepted honeycomb eye stream's lack of
//! adjacent equal reading-layer values is explained by each message's own
//! symbol frequencies, or whether it is lower than expected for a free
//! arrangement of those exact per-message multisets. The null is deliberately
//! narrow: it preserves every message's exact value multiset and length, then
//! Fisher-Yates shuffles values only within that message.
//!
//! The statistic is counted per message and then pooled. Adjacent pairs are
//! never counted across message joins, the accepted honeycomb order is held
//! fixed, and all values are the engine-verified integer reading-layer values.

use core::convert::Infallible;
use std::collections::BTreeMap;
use std::fmt;

use crate::analysis::orders::{self, GridError, ReadingOrder, read_corpus_message_values};
use crate::core::trigram::TrigramValue;
use crate::nulls::null::{
    NullTestError, SplitMix64, UsizeBand, WithinMessageShuffle, add_one_p_value, fisher_yates,
    run_null_test_streams, usize_band,
};
use crate::report::{self, Report};

/// Default deterministic base seed for the zero-adjacency null.
pub const DEFAULT_SEED: u64 = 0x7a65_726f_6164_6a00;
/// Default number of within-message shuffles sampled for each seed stream.
pub const DEFAULT_TRIALS_PER_SEED: usize = 1_000;
/// Default number of deterministic seed streams sampled.
pub const DEFAULT_SEED_COUNT: usize = 5;
/// Conventional pointwise lower-tail significance cutoff.
pub const SIGNIFICANCE_ALPHA: f64 = 0.05;

const CONTROL_ALPHABET_SIZE: u8 = 12;
const CONTROL_COPIES_PER_SYMBOL: usize = 10;

/// Configuration for the zero-adjacency forbidden-successor null.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZeroAdjacencyNullConfig {
    /// Base deterministic PRNG seed used to derive seed streams.
    pub seed: u64,
    /// Number of Fisher-Yates shuffles to sample for each seed stream.
    pub trials_per_seed: usize,
    /// Number of deterministic seed streams to sample.
    pub seed_count: usize,
}

impl Default for ZeroAdjacencyNullConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_SEED,
            trials_per_seed: DEFAULT_TRIALS_PER_SEED,
            seed_count: DEFAULT_SEED_COUNT,
        }
    }
}

/// Error returned by the zero-adjacency forbidden-successor null.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZeroAdjacencyNullError {
    /// The verified corpus could not be reconstructed or read.
    Grid(GridError),
    /// At least one shuffle trial per seed is required.
    ZeroTrials,
    /// At least one seed stream is required.
    ZeroSeedCount,
    /// The caller supplied a different number of keys and message streams.
    KeyCountMismatch {
        /// Number of message keys.
        keys: usize,
        /// Number of message streams.
        messages: usize,
    },
    /// A shuffle bound did not fit in the PRNG draw helper.
    RandomBoundTooLarge {
        /// Requested exclusive upper bound.
        bound: usize,
    },
    /// The configured trial count was too large for add-one calibration.
    TrialCountTooLarge,
    /// A positive-control fixture attempted to construct an invalid trigram.
    ControlValueOutOfRange {
        /// Invalid raw trigram value.
        value: u8,
    },
}

impl From<GridError> for ZeroAdjacencyNullError {
    fn from(value: GridError) -> Self {
        Self::Grid(value)
    }
}

impl From<crate::nulls::null::RandomBoundError> for ZeroAdjacencyNullError {
    fn from(error: crate::nulls::null::RandomBoundError) -> Self {
        Self::RandomBoundTooLarge { bound: error.bound }
    }
}

impl fmt::Display for ZeroAdjacencyNullError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Grid(grid_error) => write!(f, "grid/order error: {grid_error:?}"),
            Self::ZeroTrials => write!(f, "at least one shuffle trial per seed is required"),
            Self::ZeroSeedCount => write!(f, "at least one seed stream is required"),
            Self::KeyCountMismatch { keys, messages } => write!(
                f,
                "internal key/message count mismatch: {keys} keys, {messages} messages"
            ),
            Self::RandomBoundTooLarge { bound } => write!(f, "shuffle bound {bound} is too large"),
            Self::TrialCountTooLarge => {
                write!(
                    f,
                    "trial count is too large for add-one p-value calibration"
                )
            }
            Self::ControlValueOutOfRange { value } => {
                write!(
                    f,
                    "positive-control trigram value {value} is outside 0..=124"
                )
            }
        }
    }
}

impl std::error::Error for ZeroAdjacencyNullError {}

/// Per-message adjacent-equal summary.
#[derive(Clone, Debug, PartialEq)]
pub struct MessageAdjacencySummary {
    /// Message key.
    pub message_key: &'static str,
    /// Reading-layer stream length.
    pub len: usize,
    /// Number of adjacent-pair comparisons inside this message.
    pub comparisons: usize,
    /// Count of adjacent equal value pairs inside this message.
    pub adjacent_equal: usize,
    /// Expected adjacent equal count for a random arrangement of this
    /// message's exact value multiset.
    pub analytic_expected: f64,
}

/// Pooled adjacent-equal statistic plus per-message rows.
#[derive(Clone, Debug, PartialEq)]
pub struct AdjacencySummary {
    /// Count of adjacent equal value pairs, pooled over messages.
    pub adjacent_equal: usize,
    /// Number of adjacent-pair comparisons, pooled over messages.
    pub comparisons: usize,
    /// `adjacent_equal / comparisons`.
    pub rate: f64,
    /// Expected adjacent equal count for random arrangements of the exact
    /// per-message value multisets.
    pub analytic_expected: f64,
    /// Per-message rows.
    pub messages: Vec<MessageAdjacencySummary>,
}

/// Monte-Carlo distribution for pooled adjacent-equal counts.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AdjacencyNullBand {
    /// Number of within-message shuffle trials sampled.
    pub trials: usize,
    /// Mean adjacent-equal count across shuffles.
    pub mean: f64,
    /// Smallest sampled adjacent-equal count.
    pub min: usize,
    /// Lower pointwise 95% percentile edge.
    pub q025: usize,
    /// Sample median.
    pub median: f64,
    /// Upper pointwise 95% percentile edge.
    pub q975: usize,
    /// Largest sampled adjacent-equal count.
    pub max: usize,
}

impl From<UsizeBand> for AdjacencyNullBand {
    fn from(band: UsizeBand) -> Self {
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

/// Position of the observed statistic relative to the shuffle band.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShuffleBandPosition {
    /// The observed count is below the lower pointwise 95% shuffle edge.
    Below,
    /// The observed count is inside the pointwise 95% shuffle band.
    Within,
    /// The observed count is above the upper pointwise 95% shuffle edge.
    Above,
}

impl ShuffleBandPosition {
    /// Human-readable label for reports.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Below => "below",
            Self::Within => "within",
            Self::Above => "above",
        }
    }
}

/// Positive-control report for one planted fixture.
#[derive(Clone, Debug, PartialEq)]
pub struct PositiveControlReport {
    /// Short control label.
    pub label: &'static str,
    /// Control construction summary.
    pub description: &'static str,
    /// Observed adjacent-equal statistic for the planted fixture.
    pub observed: AdjacencySummary,
    /// Shuffle-null band for the planted fixture's own multiset.
    pub null: AdjacencyNullBand,
    /// Number of shuffles with adjacent-equal count less than or equal to the
    /// planted observation.
    pub empirical_p_count: usize,
    /// Add-one lower-tail empirical p-value.
    pub empirical_p: f64,
    /// Position of the planted observation relative to its shuffle band.
    pub band_position: ShuffleBandPosition,
}

/// Positive controls paired with the zero-adjacency null.
#[derive(Clone, Debug, PartialEq)]
pub struct ZeroAdjacencyPositiveControls {
    /// A free-permutation draw from a fixed multiset, expected to sit inside
    /// the shuffle band near the analytic expectation.
    pub free_permutation: PositiveControlReport,
    /// A no-repeat-successor arrangement of the same multiset, expected to sit
    /// below the shuffle band with zero adjacent equal pairs.
    pub no_repeat_successor: PositiveControlReport,
}

/// Complete zero-adjacency forbidden-successor null report.
#[derive(Clone, Debug, PartialEq)]
pub struct ZeroAdjacencyNullReport {
    /// Configuration used for the run.
    pub config: ZeroAdjacencyNullConfig,
    /// Reading order used for the real and shuffled streams.
    pub order: ReadingOrder,
    /// Per-message stream lengths in corpus order.
    pub message_lengths: Vec<(&'static str, usize)>,
    /// Total number of reading-layer symbols across messages.
    pub total_length: usize,
    /// Observed adjacent-equal statistic.
    pub observed: AdjacencySummary,
    /// Shuffle-null band.
    pub null: AdjacencyNullBand,
    /// Number of shuffles with adjacent-equal count less than or equal to the
    /// observed count.
    pub empirical_p_count: usize,
    /// Add-one lower-tail empirical p-value.
    pub empirical_p: f64,
    /// Position of the real observation relative to its shuffle band.
    pub band_position: ShuffleBandPosition,
    /// Whether the lower-tail result is pointwise significant at 5%.
    pub significant: bool,
    /// Positive controls that show the null distinguishes free arrangements
    /// from no-repeat-successor arrangements when the expected count is nonzero.
    pub controls: ZeroAdjacencyPositiveControls,
}

impl Report for ZeroAdjacencyNullReport {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(
            &mut out,
            "Experiment 7D zero-adjacency forbidden-successor null"
        );
        report::appendln!(&mut out, "order: {}", self.order.name());
        report::appendln!(&mut out, "base seed: {}", self.config.seed);
        report::appendln!(&mut out, "seed streams: {}", self.config.seed_count);
        report::appendln!(&mut out, "trials per seed: {}", self.config.trials_per_seed);
        report::appendln!(&mut out, "total shuffles: {}", self.null.trials);
        report::appendln!(
            &mut out,
            "message lengths: {}",
            report::format_message_lengths(&self.message_lengths)
        );
        report::appendln!(&mut out, "pooled length: {}", self.total_length);
        report::appendln!(
            &mut out,
            "boundary rule: adjacent pairs are counted within each message only; no pair crosses a message join"
        );
        report::appendln!(
            &mut out,
            "null: Fisher-Yates shuffle within each message, preserving that message's exact value multiset and length"
        );
        report::appendln!(
            &mut out,
            "statistic: pooled adjacent-equal reading-layer value pairs under the fixed accepted honeycomb order"
        );
        report::appendln!(&mut out);
        append_zero_adjacency_observed(&mut out, self);
        report::appendln!(&mut out);
        append_zero_adjacency_null(&mut out, self);
        report::appendln!(&mut out);
        append_zero_adjacency_controls(&mut out, &self.controls);
        report::appendln!(&mut out);
        append_zero_adjacency_interpretation(&mut out, self);
        out
    }
}

fn append_zero_adjacency_observed(out: &mut String, report: &ZeroAdjacencyNullReport) {
    report::appendln!(out, "observed eye statistic");
    report::appendln!(
        out,
        "  observed adjacent equal: {}/{} = {:.6}",
        report.observed.adjacent_equal,
        report.observed.comparisons,
        report.observed.rate
    );
    report::appendln!(
        out,
        "  analytic E from per-message multisets: {:.6}",
        report.observed.analytic_expected
    );
    report::appendln!(
        out,
        "  position vs shuffle band: {}",
        report.band_position.label()
    );
    report::appendln!(
        out,
        "  {:<6} {:>6} {:>8} {:>8} {:>10}",
        "msg",
        "len",
        "pairs",
        "adj",
        "E"
    );
    for row in &report.observed.messages {
        report::appendln!(
            out,
            "  {:<6} {:>6} {:>8} {:>8} {:>10.3}",
            row.message_key,
            row.len,
            row.comparisons,
            row.adjacent_equal,
            row.analytic_expected
        );
    }
}

fn append_zero_adjacency_null(out: &mut String, report: &ZeroAdjacencyNullReport) {
    report::appendln!(out, "within-message shuffle null");
    report::appendln!(
        out,
        "  adjacent-equal count: mean {:.2}, 95% {}, median {:.1}, min {}, max {}",
        report.null.mean,
        format_adjacency_band(report.null),
        report.null.median,
        report.null.min,
        report.null.max
    );
    report::appendln!(
        out,
        "  lower-tail add-one p: ({extreme}+1)/({trials}+1) = {p}",
        extreme = report.empirical_p_count,
        trials = report.null.trials,
        p = report::format_probability(report.empirical_p)
    );
}

fn append_zero_adjacency_controls(out: &mut String, controls: &ZeroAdjacencyPositiveControls) {
    report::appendln!(out, "positive controls");
    report::appendln!(
        out,
        "  {:<20} {:>8} {:>10} {:>10} {:>11} {:>8}",
        "control",
        "adj",
        "E",
        "null95",
        "p<=obs",
        "band"
    );
    for control in [&controls.free_permutation, &controls.no_repeat_successor] {
        report::appendln!(
            out,
            "  {:<20} {:>8} {:>10.3} {:>10} {:>11} {:>8}",
            control.label,
            control.observed.adjacent_equal,
            control.observed.analytic_expected,
            format_adjacency_band(control.null),
            report::format_probability(control.empirical_p),
            control.band_position.label()
        );
        report::appendln!(out, "    {}", control.description);
    }
}

fn append_zero_adjacency_interpretation(out: &mut String, report: &ZeroAdjacencyNullReport) {
    if report.significant && report.observed.adjacent_equal == 0 {
        report::appendln!(
            out,
            "Interpretation: observed zero adjacent equal pairs sits below the within-message multiset shuffle band while analytic E={:.6}. That is structural evidence for a no-fixed-successor / forbidden-successor mechanism beyond frequency flatness, but it decodes nothing and does not identify a cipher.",
            report.observed.analytic_expected
        );
    } else if report.band_position == ShuffleBandPosition::Within {
        report::appendln!(
            out,
            "Interpretation: observed adjacency sits within the within-message multiset shuffle band. In this run, the no-doubled-trigram property is explained by the eye messages' own frequencies rather than by a separate forbidden-successor constraint."
        );
    } else {
        report::appendln!(
            out,
            "Interpretation: observed adjacency does not match the lower-tail forbidden-successor prediction under this null. Treat any out-of-band direction as an arrangement diagnostic only; it decodes nothing."
        );
    }
    report::appendln!(
        out,
        "The result is conditional on the Experiment-0-verified transcription and the fixed accepted honeycomb order; the null randomizes arrangement within each message, not reading order or symbol meaning."
    );
}

fn format_adjacency_band(band: AdjacencyNullBand) -> String {
    format!("{}..{}", band.q025, band.q975)
}

/// Runs the zero-adjacency forbidden-successor null on the verified eye corpus.
///
/// # Errors
/// Returns [`ZeroAdjacencyNullError`] when the corpus cannot be reconstructed,
/// the accepted reading order is incompatible with a grid, or the
/// configuration is invalid.
pub fn run_zero_adjacency_null(
    config: ZeroAdjacencyNullConfig,
) -> Result<ZeroAdjacencyNullReport, ZeroAdjacencyNullError> {
    validate_config(config)?;
    let grids = orders::corpus_grids()?;
    let keys: Vec<&'static str> = grids
        .iter()
        .map(crate::analysis::orders::GlyphGrid::message_key)
        .collect();
    let order = orders::accepted_honeycomb_order();
    let message_values = read_corpus_message_values(&grids, order)?;
    report_from_message_values(config, order, &keys, &message_values)
}

#[derive(Clone, Debug, PartialEq)]
struct ZeroAdjacencyAnalysis {
    observed: AdjacencySummary,
    null: AdjacencyNullBand,
    empirical_p_count: usize,
    empirical_p: f64,
    band_position: ShuffleBandPosition,
}

fn report_from_message_values(
    config: ZeroAdjacencyNullConfig,
    order: ReadingOrder,
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
) -> Result<ZeroAdjacencyNullReport, ZeroAdjacencyNullError> {
    let analysis = analyze_message_values(config, keys, message_values)?;
    let controls = positive_controls(config)?;
    let lengths = message_values.iter().map(Vec::len).collect::<Vec<_>>();
    let total_length = lengths.iter().sum();
    let significant = analysis.band_position == ShuffleBandPosition::Below
        && analysis.empirical_p <= SIGNIFICANCE_ALPHA;

    Ok(ZeroAdjacencyNullReport {
        config,
        order,
        message_lengths: keys.iter().copied().zip(lengths).collect(),
        total_length,
        observed: analysis.observed,
        null: analysis.null,
        empirical_p_count: analysis.empirical_p_count,
        empirical_p: analysis.empirical_p,
        band_position: analysis.band_position,
        significant,
        controls,
    })
}

fn analyze_message_values(
    config: ZeroAdjacencyNullConfig,
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
) -> Result<ZeroAdjacencyAnalysis, ZeroAdjacencyNullError> {
    validate_config(config)?;
    let total_trials = total_trials(config)?;
    let observed = adjacency_summary(keys, message_values)?;
    let sampler = WithinMessageShuffle {
        messages: message_values,
    };

    // Each seed stream draws its base seed from one chained base RNG, exactly as
    // the longhand loop did (`SplitMix64::new(stream_rng.next_u64())`). The
    // `FnMut` derivation is what lets the closure advance that captured RNG.
    let mut stream_rng = SplitMix64::new(config.seed);
    let result = run_null_test_streams(
        |shuffled| Ok::<usize, Infallible>(total_adjacent_equal(shuffled)),
        observed.adjacent_equal,
        &sampler,
        config.seed_count,
        config.trials_per_seed,
        |_stream_index| stream_rng.next_u64(),
    )
    .map_err(|error| match error {
        NullTestError::Random(bound) => ZeroAdjacencyNullError::from(bound),
        NullTestError::Statistic(never) => match never {},
    })?;

    let null = AdjacencyNullBand::from(usize_band(&result.samples));
    let empirical_p_count = result.lower_tail_count;
    let empirical_p = add_one_p_value(empirical_p_count, total_trials);
    let band_position = classify_band_position(observed.adjacent_equal, null);

    Ok(ZeroAdjacencyAnalysis {
        observed,
        null,
        empirical_p_count,
        empirical_p,
        band_position,
    })
}

fn validate_config(config: ZeroAdjacencyNullConfig) -> Result<(), ZeroAdjacencyNullError> {
    if config.trials_per_seed == 0 {
        return Err(ZeroAdjacencyNullError::ZeroTrials);
    }
    if config.seed_count == 0 {
        return Err(ZeroAdjacencyNullError::ZeroSeedCount);
    }
    let _total_trials = total_trials(config)?;
    Ok(())
}

fn total_trials(config: ZeroAdjacencyNullConfig) -> Result<usize, ZeroAdjacencyNullError> {
    config
        .trials_per_seed
        .checked_mul(config.seed_count)
        .ok_or(ZeroAdjacencyNullError::TrialCountTooLarge)
}

fn adjacency_summary(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
) -> Result<AdjacencySummary, ZeroAdjacencyNullError> {
    if keys.len() != message_values.len() {
        return Err(ZeroAdjacencyNullError::KeyCountMismatch {
            keys: keys.len(),
            messages: message_values.len(),
        });
    }

    let mut adjacent_equal = 0usize;
    let mut comparisons = 0usize;
    let mut analytic_expected = 0.0;
    let mut messages = Vec::new();

    for (message_key, values) in keys.iter().copied().zip(message_values) {
        let row_adjacent_equal = count_adjacent_equal(values);
        let row_comparisons = values.len().saturating_sub(1);
        let row_expected = analytic_expected_adjacent_equal(values);
        adjacent_equal += row_adjacent_equal;
        comparisons += row_comparisons;
        analytic_expected += row_expected;
        messages.push(MessageAdjacencySummary {
            message_key,
            len: values.len(),
            comparisons: row_comparisons,
            adjacent_equal: row_adjacent_equal,
            analytic_expected: row_expected,
        });
    }

    Ok(AdjacencySummary {
        adjacent_equal,
        comparisons,
        rate: rate(adjacent_equal, comparisons),
        analytic_expected,
        messages,
    })
}

fn analytic_expected_adjacent_equal(values: &[TrigramValue]) -> f64 {
    let denominator = values.len();
    if denominator < 2 {
        return 0.0;
    }
    let mut counts = BTreeMap::new();
    for value in values {
        let entry = counts.entry(value.get()).or_insert(0usize);
        *entry += 1;
    }
    counts
        .values()
        .map(|&count| count.saturating_mul(count.saturating_sub(1)) as f64 / denominator as f64)
        .sum()
}

fn total_adjacent_equal(message_values: &[Vec<TrigramValue>]) -> usize {
    message_values
        .iter()
        .map(|values| count_adjacent_equal(values))
        .sum()
}

fn count_adjacent_equal(values: &[TrigramValue]) -> usize {
    values
        .windows(2)
        .filter(|window| matches!(window, [left, right] if left == right))
        .count()
}

fn classify_band_position(observed: usize, null: AdjacencyNullBand) -> ShuffleBandPosition {
    if observed < null.q025 {
        ShuffleBandPosition::Below
    } else if observed > null.q975 {
        ShuffleBandPosition::Above
    } else {
        ShuffleBandPosition::Within
    }
}

fn rate(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn positive_controls(
    config: ZeroAdjacencyNullConfig,
) -> Result<ZeroAdjacencyPositiveControls, ZeroAdjacencyNullError> {
    let mut free_message = repeated_multiset_message()?;
    let mut fixture_rng = SplitMix64::new(config.seed ^ 0x6672_6565_7065_726d);
    fisher_yates(&mut free_message, &mut fixture_rng)?;

    Ok(ZeroAdjacencyPositiveControls {
        free_permutation: control_report(
            config,
            "free-permutation",
            "one Fisher-Yates draw from a 12-symbol x10 multiset",
            free_message,
        )?,
        no_repeat_successor: control_report(
            config,
            "no-repeat-successor",
            "round-robin arrangement of the same 12-symbol x10 multiset",
            no_repeat_successor_message()?,
        )?,
    })
}

fn control_report(
    config: ZeroAdjacencyNullConfig,
    label: &'static str,
    description: &'static str,
    message: Vec<TrigramValue>,
) -> Result<PositiveControlReport, ZeroAdjacencyNullError> {
    let keys = ["control"];
    let messages = vec![message];
    let analysis = analyze_message_values(config, &keys, &messages)?;
    Ok(PositiveControlReport {
        label,
        description,
        observed: analysis.observed,
        null: analysis.null,
        empirical_p_count: analysis.empirical_p_count,
        empirical_p: analysis.empirical_p,
        band_position: analysis.band_position,
    })
}

fn repeated_multiset_message() -> Result<Vec<TrigramValue>, ZeroAdjacencyNullError> {
    let mut values = Vec::new();
    for raw in 0..CONTROL_ALPHABET_SIZE {
        for _copy in 0..CONTROL_COPIES_PER_SYMBOL {
            push_control_value(&mut values, raw)?;
        }
    }
    Ok(values)
}

fn no_repeat_successor_message() -> Result<Vec<TrigramValue>, ZeroAdjacencyNullError> {
    let mut values = Vec::new();
    for _copy in 0..CONTROL_COPIES_PER_SYMBOL {
        for raw in 0..CONTROL_ALPHABET_SIZE {
            push_control_value(&mut values, raw)?;
        }
    }
    Ok(values)
}

fn push_control_value(
    values: &mut Vec<TrigramValue>,
    raw: u8,
) -> Result<(), ZeroAdjacencyNullError> {
    let value = TrigramValue::new(raw)
        .map_err(|value| ZeroAdjacencyNullError::ControlValueOutOfRange { value })?;
    values.push(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ShuffleBandPosition, ZeroAdjacencyNullConfig, adjacency_summary, analyze_message_values,
        positive_controls, run_zero_adjacency_null,
    };
    use crate::core::trigram::TrigramValue;
    use crate::nulls::null::{NullSampler, SplitMix64, WithinMessageShuffle};

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
    fn analytic_expected_count_matches_hand_calculation() {
        let keys = ["toy"];
        let messages = vec![values(&[1, 1, 1, 2, 2])];

        let summary = adjacency_summary(&keys, &messages).unwrap();

        assert_eq!(summary.adjacent_equal, 3);
        assert_eq!(summary.comparisons, 4);
        assert_relative_close(summary.analytic_expected, 1.6, "analytic expected");
        assert_relative_close(summary.rate, 0.75, "rate");
    }

    #[test]
    fn shuffle_null_preserves_message_multisets_and_lengths() {
        let messages = vec![values(&[0, 0, 1, 1, 2, 2]), values(&[3, 3, 4])];
        let sampler = WithinMessageShuffle {
            messages: &messages,
        };
        let mut rng = SplitMix64::new(0x5151);

        let shuffled = sampler.sample(&mut rng).unwrap();

        assert_eq!(shuffled.len(), messages.len());
        for (original, shuffled_message) in messages.iter().zip(&shuffled) {
            let mut original_sorted = original.clone();
            let mut shuffled_sorted = shuffled_message.clone();
            original_sorted.sort_unstable();
            shuffled_sorted.sort_unstable();
            assert_eq!(shuffled_message.len(), original.len());
            assert_eq!(shuffled_sorted, original_sorted);
        }
    }

    #[test]
    fn shuffle_null_is_reproducible_for_fixed_seed() {
        let config = ZeroAdjacencyNullConfig {
            seed: 0x5eed,
            trials_per_seed: 16,
            seed_count: 2,
        };
        let keys = ["toy"];
        let messages = vec![values(&[0, 0, 0, 1, 1, 1, 2, 2, 2])];

        let first = analyze_message_values(config, &keys, &messages).unwrap();
        let second = analyze_message_values(config, &keys, &messages).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.null.trials, 32);
        assert!(first.null.mean > 0.0);
    }

    #[test]
    fn positive_controls_separate_free_and_no_repeat_regimes() {
        let config = ZeroAdjacencyNullConfig {
            seed: 0x5150,
            trials_per_seed: 256,
            seed_count: 2,
        };

        let controls = positive_controls(config).unwrap();

        assert_eq!(
            controls.free_permutation.band_position,
            ShuffleBandPosition::Within
        );
        assert!(
            controls.free_permutation.observed.adjacent_equal > 0,
            "free control should contain ordinary adjacent equal pairs"
        );
        assert_eq!(
            controls.no_repeat_successor.band_position,
            ShuffleBandPosition::Below
        );
        assert_eq!(controls.no_repeat_successor.observed.adjacent_equal, 0);
        assert!(controls.no_repeat_successor.null.q025 > 0);
        assert!(
            controls.no_repeat_successor.empirical_p <= 0.01,
            "p={}",
            controls.no_repeat_successor.empirical_p
        );
    }

    #[test]
    fn eye_zero_adjacency_headline_numbers_are_pinned() {
        let report = run_zero_adjacency_null(ZeroAdjacencyNullConfig::default()).unwrap();

        assert_eq!(report.order.name(), "standard36-u012-d012");
        assert_eq!(report.observed.adjacent_equal, 0);
        assert_eq!(report.observed.comparisons, 1_027);
        assert_relative_close(
            report.observed.analytic_expected,
            12.008_220_182_690_058,
            "eye analytic expected",
        );
        assert_eq!(report.empirical_p_count, 0);
        assert_relative_close(
            report.empirical_p,
            0.000_199_960_007_998_400_3,
            "eye empirical p",
        );
        assert_eq!(report.band_position, ShuffleBandPosition::Below);
        assert!(report.significant);
    }

    fn values(raw_values: &[u8]) -> Vec<TrigramValue> {
        raw_values
            .iter()
            .copied()
            .map(|raw| TrigramValue::new(raw).unwrap())
            .collect()
    }
}

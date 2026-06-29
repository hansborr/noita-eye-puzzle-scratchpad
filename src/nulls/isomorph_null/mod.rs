//! Experiment 7A: isomorph detection on the real eye stream with a shuffle null.
//!
//! The null used here preserves each message's exact reading-layer symbol
//! multiset and length, then randomizes order within that message. It therefore
//! tests arrangement only; symbol frequencies are held fixed.

use std::fmt;

use crate::analysis::isomorph::{self, IsomorphError};
use crate::analysis::orders::{CorpusContext, GridError, ReadingOrder};
use crate::core::trigram::TrigramValue;
use crate::nulls::null::{
    NullColumnError, UsizeBand, WithinMessageShuffle, add_one_p_value, run_null_test_columns,
    usize_band,
};
use crate::report::{self, Report};

/// Default deterministic Monte-Carlo seed for Experiment 7A.
pub const DEFAULT_SEED: u64 = 0x6973_6f6d_6f72_3761;
/// Default Monte-Carlo trial count.
pub const DEFAULT_TRIALS: usize = 1_000;
/// Default minimum isomorph window length.
pub const DEFAULT_MIN_WINDOW: usize = 3;
/// Default maximum isomorph window length.
pub const DEFAULT_MAX_WINDOW: usize = 8;

/// Configuration for the Experiment 7A isomorph shuffle null.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IsomorphNullConfig {
    /// Explicit deterministic PRNG seed.
    pub seed: u64,
    /// Number of within-message shuffle trials to sample.
    pub trials: usize,
    /// Smallest window length to scan.
    pub min_window: usize,
    /// Largest window length to scan.
    pub max_window: usize,
}

impl Default for IsomorphNullConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_SEED,
            trials: DEFAULT_TRIALS,
            min_window: DEFAULT_MIN_WINDOW,
            max_window: DEFAULT_MAX_WINDOW,
        }
    }
}

/// Error returned by the Experiment 7A isomorph shuffle null.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IsomorphNullError {
    /// The verified corpus could not be reconstructed or read with the order.
    Grid(GridError),
    /// At least one Monte-Carlo trial is required.
    ZeroTrials,
    /// The configured inclusive window range was empty or included zero.
    InvalidWindowRange {
        /// Requested minimum window length.
        min_window: usize,
        /// Requested maximum window length.
        max_window: usize,
    },
    /// The shared isomorph detector rejected a generated configuration.
    Isomorph(IsomorphError),
    /// A shuffle bound did not fit in the PRNG draw helper.
    RandomBoundTooLarge {
        /// Requested exclusive upper bound.
        bound: usize,
    },
}

impl From<GridError> for IsomorphNullError {
    fn from(value: GridError) -> Self {
        Self::Grid(value)
    }
}

impl From<IsomorphError> for IsomorphNullError {
    fn from(value: IsomorphError) -> Self {
        Self::Isomorph(value)
    }
}

impl From<crate::nulls::null::RandomBoundError> for IsomorphNullError {
    fn from(error: crate::nulls::null::RandomBoundError) -> Self {
        Self::RandomBoundTooLarge { bound: error.bound }
    }
}

impl fmt::Display for IsomorphNullError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Grid(grid_error) => write!(f, "grid/order error: {grid_error:?}"),
            Self::ZeroTrials => write!(f, "at least one Monte-Carlo trial is required"),
            Self::InvalidWindowRange {
                min_window,
                max_window,
            } => write!(f, "invalid window range {min_window}..={max_window}"),
            Self::Isomorph(isomorph_error) => {
                write!(f, "detector configuration error: {isomorph_error:?}")
            }
            Self::RandomBoundTooLarge { bound } => write!(f, "shuffle bound {bound} is too large"),
        }
    }
}

impl std::error::Error for IsomorphNullError {}

/// Real or shuffled detector summary for one window length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IsomorphWindowSummary {
    /// Number of scanned windows whose signature contains a repeated symbol.
    pub informative_windows: usize,
    /// Number of repeated informative signatures, summed within messages.
    pub repeated_signature_kinds: usize,
    /// Largest occurrence count for any repeated signature within a message.
    pub max_repeat_count: usize,
}

/// Monte-Carlo distribution for repeated signature kinds at one window length.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct IsomorphNullBand {
    /// Number of shuffle trials sampled.
    pub trials: usize,
    /// Mean repeated-signature kind count across shuffles.
    pub mean: f64,
    /// Lower pointwise 95% percentile edge.
    pub q025: usize,
    /// Sample median.
    pub median: f64,
    /// Upper pointwise 95% percentile edge.
    pub q975: usize,
    /// Largest sampled repeated-signature kind count.
    pub max: usize,
}

impl From<UsizeBand> for IsomorphNullBand {
    fn from(band: UsizeBand) -> Self {
        // `IsomorphNullBand` carries no `min` field; the rest map directly.
        Self {
            trials: band.trials,
            mean: band.mean,
            q025: band.q025,
            median: band.median,
            q975: band.q975,
            max: band.max,
        }
    }
}

/// Real-vs-null row for one isomorph window length.
#[derive(Clone, Debug, PartialEq)]
pub struct IsomorphNullRow {
    /// Window length in reading-layer symbols.
    pub window: usize,
    /// Detector summary for the real eye stream.
    pub real: IsomorphWindowSummary,
    /// Shuffle-null distribution for repeated-signature kinds.
    pub null: IsomorphNullBand,
    /// Number of shuffles whose repeated-signature kind count met or exceeded
    /// the real count.
    pub empirical_p_count: usize,
    /// Add-one Monte-Carlo p-value `(empirical_p_count + 1) / (trials + 1)`.
    pub empirical_p: f64,
}

/// Complete Experiment 7A isomorph shuffle-null report.
#[derive(Clone, Debug, PartialEq)]
pub struct IsomorphNullReport {
    /// Configuration used for the run.
    pub config: IsomorphNullConfig,
    /// Reading order used for the real and shuffled streams.
    pub order: ReadingOrder,
    /// Per-message stream lengths in corpus order.
    pub message_lengths: Vec<(&'static str, usize)>,
    /// Total number of reading-layer symbols across messages.
    pub total_length: usize,
    /// Largest scanned window length with at least one repeated real signature.
    pub longest_real_repeated_isomorph: Option<usize>,
    /// Real-vs-null rows, one per scanned window length.
    pub rows: Vec<IsomorphNullRow>,
}

impl Report for IsomorphNullReport {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(&mut out, "Experiment 7A isomorph shuffle null");
        report::appendln!(&mut out, "order: {}", self.order.name());
        report::appendln!(&mut out, "seed: {}", self.config.seed);
        report::appendln!(&mut out, "trials: {}", self.config.trials);
        report::appendln!(
            &mut out,
            "windows: {}..={}",
            self.config.min_window,
            self.config.max_window
        );
        report::appendln!(
            &mut out,
            "message lengths: {}",
            report::format_message_lengths(&self.message_lengths)
        );
        report::appendln!(&mut out, "pooled length: {}", self.total_length);
        report::appendln!(
            &mut out,
            "boundary rule: detector runs within each message only; no window crosses a message join"
        );
        report::appendln!(
            &mut out,
            "null: Fisher-Yates shuffle within each message, preserving that message's exact symbol multiset and length"
        );
        report::appendln!(
            &mut out,
            "statistic: repeated informative first-occurrence signature kinds, summed over messages; all-distinct windows are ignored"
        );
        report::appendln!(
            &mut out,
            "longest repeated real isomorph in scanned range: {}",
            self.longest_real_repeated_isomorph
                .map_or_else(|| "none".to_owned(), |window| window.to_string())
        );
        report::appendln!(&mut out);
        report::appendln!(
            &mut out,
            "{:>2} {:>10} {:>8} {:>10} {:>12} {:>8} {:>9}",
            "k",
            "real kinds",
            "max rep",
            "null mean",
            "null 95%",
            "null max",
            "p>=real"
        );
        for row in &self.rows {
            report::appendln!(
                &mut out,
                "{:>2} {:>10} {:>8} {:>10.2} {:>12} {:>8} {:>9.4}",
                row.window,
                row.real.repeated_signature_kinds,
                row.real.max_repeat_count,
                row.null.mean,
                format_isomorph_band(row.null),
                row.null.max,
                row.empirical_p
            );
        }
        report::appendln!(&mut out);
        append_isomorph_null_interpretation(&mut out, self);
        out
    }
}

fn append_isomorph_null_interpretation(out: &mut String, report: &IsomorphNullReport) {
    let pointwise_excesses = report
        .rows
        .iter()
        .filter(|row| row.real.repeated_signature_kinds > row.null.q975)
        .map(|row| format!("k={} (p={:.4})", row.window, row.empirical_p))
        .collect::<Vec<_>>();

    if pointwise_excesses.is_empty() {
        report::appendln!(
            out,
            "Interpretation: the real eye stream does not exceed the pointwise 95% within-message shuffle band for repeated-signature kind counts at the scanned k values. Short repeated isomorphs exist, but this run does not show arrangement structure beyond the same messages shuffled against themselves."
        );
    } else {
        report::appendln!(
            out,
            "Interpretation: the real eye stream exceeds the pointwise 95% within-message shuffle band at {}. That is an arrangement signal worth rechecking, not a decryption or plaintext claim.",
            pointwise_excesses.join(", ")
        );
    }
    report::appendln!(
        out,
        "The shuffle null holds symbol frequencies fixed and randomizes only order, so it tests arrangement rather than frequency. The p values are empirical fractions over the configured shuffles and are pointwise over the scanned k values."
    );
    report::appendln!(
        out,
        "Any striking excess should be rechecked against Experiment 0 transcription integrity before interpretation."
    );
}

fn format_isomorph_band(band: IsomorphNullBand) -> String {
    format!("{}..{}", band.q025, band.q975)
}

/// Runs Experiment 7A on the verified eye corpus.
///
/// # Errors
/// Returns [`IsomorphNullError`] when the corpus cannot be reconstructed, when
/// the accepted reading order is incompatible with a grid, or when the
/// configuration is invalid.
pub fn run_isomorph_null(
    config: IsomorphNullConfig,
) -> Result<IsomorphNullReport, IsomorphNullError> {
    validate_config(config)?;
    let CorpusContext {
        order,
        keys,
        message_values,
    } = CorpusContext::load()?;
    report_from_message_values(config, order, &keys, &message_values)
}

/// Runs Experiment 7A on an arbitrary caller-supplied symbol stream.
///
/// The stream is treated as a single message under a neutral
/// [`ReadingOrder::RawRows`] label and the synthetic key `"input"`; no eye
/// traversal is claimed for arbitrary input. The within-message shuffle null is
/// matched to the supplied stream's own length and symbol multiset, so the
/// real-vs-null comparison stays valid for any alphabet — the isomorph statistic
/// is equality-based and alphabet-agnostic.
///
/// # Errors
/// Returns [`IsomorphNullError`] when the configuration is invalid (zero trials
/// or an empty window range) or the shared detector rejects a generated window.
pub fn isomorph_null_for_stream(
    config: IsomorphNullConfig,
    values: &[TrigramValue],
) -> Result<IsomorphNullReport, IsomorphNullError> {
    let message_values = vec![values.to_vec()];
    report_from_message_values(config, ReadingOrder::RawRows, &["input"], &message_values)
}

fn report_from_message_values(
    config: IsomorphNullConfig,
    order: ReadingOrder,
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
) -> Result<IsomorphNullReport, IsomorphNullError> {
    validate_config(config)?;

    let real_summaries =
        summarize_window_range(message_values, config.min_window, config.max_window)?;
    let observed = real_summaries
        .iter()
        .map(|window| window.summary.repeated_signature_kinds)
        .collect::<Vec<usize>>();
    let sampler = WithinMessageShuffle {
        messages: message_values,
    };

    // One column per scanned window length. The row statistic is the
    // naturally-fallible `summarize_window_range`, passed directly; the harness
    // propagates any `Err` as `NullColumnError::Statistic`.
    let columns = run_null_test_columns(
        |shuffled| {
            summarize_window_range(shuffled, config.min_window, config.max_window).map(
                |summaries| {
                    summaries
                        .iter()
                        .map(|window| window.summary.repeated_signature_kinds)
                        .collect()
                },
            )
        },
        observed,
        &sampler,
        config.trials,
        config.seed,
    )
    .map_err(|error| match error {
        NullColumnError::Random(bound) => IsomorphNullError::from(bound),
        NullColumnError::Statistic(error) => error,
        // Unreachable: `summarize_window_range` always returns one summary per
        // window length in `min_window..=max_window`, so the row width is fixed.
        NullColumnError::WidthMismatch { .. } => IsomorphNullError::InvalidWindowRange {
            min_window: config.min_window,
            max_window: config.max_window,
        },
    })?;

    let rows = real_summaries
        .into_iter()
        .zip(columns)
        .map(|(real_summary, column)| {
            let empirical_p_count = column.upper_tail_count;
            let empirical_p = add_one_p_value(empirical_p_count, config.trials);
            IsomorphNullRow {
                window: real_summary.window,
                real: real_summary.summary,
                null: IsomorphNullBand::from(usize_band(&column.samples)),
                empirical_p_count,
                empirical_p,
            }
        })
        .collect::<Vec<_>>();

    let lengths = message_values.iter().map(Vec::len).collect::<Vec<_>>();
    let total_length = lengths.iter().sum();
    let longest_real_repeated_isomorph = rows
        .iter()
        .filter(|row| row.real.repeated_signature_kinds > 0)
        .map(|row| row.window)
        .max();

    Ok(IsomorphNullReport {
        config,
        order,
        message_lengths: keys.iter().copied().zip(lengths).collect(),
        total_length,
        longest_real_repeated_isomorph,
        rows,
    })
}

fn validate_config(config: IsomorphNullConfig) -> Result<(), IsomorphNullError> {
    if config.trials == 0 {
        return Err(IsomorphNullError::ZeroTrials);
    }
    if config.min_window == 0 || config.min_window > config.max_window {
        return Err(IsomorphNullError::InvalidWindowRange {
            min_window: config.min_window,
            max_window: config.max_window,
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WindowComputation {
    window: usize,
    summary: IsomorphWindowSummary,
}

fn summarize_window_range(
    message_values: &[Vec<TrigramValue>],
    min_window: usize,
    max_window: usize,
) -> Result<Vec<WindowComputation>, IsomorphNullError> {
    let mut summaries = Vec::new();
    for window in min_window..=max_window {
        summaries.push(WindowComputation {
            window,
            summary: summarize_window(message_values, window)?,
        });
    }
    Ok(summaries)
}

fn summarize_window(
    message_values: &[Vec<TrigramValue>],
    window: usize,
) -> Result<IsomorphWindowSummary, IsomorphNullError> {
    let mut informative_windows = 0usize;
    let mut repeated_signature_kinds = 0usize;
    let mut max_repeat_count = 0usize;

    for values in message_values {
        if window > values.len() {
            continue;
        }
        let detection = isomorph::detect_isomorphs(values, window, 1, 1)?;
        informative_windows += detection.informative_windows;
        repeated_signature_kinds += detection.repeated_signature_kinds();
        max_repeat_count = max_repeat_count.max(detection.max_repeat_count());
    }

    Ok(IsomorphWindowSummary {
        informative_windows,
        repeated_signature_kinds,
        max_repeat_count,
    })
}

#[cfg(test)]
mod tests;

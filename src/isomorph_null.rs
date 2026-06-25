//! Experiment 7A: isomorph detection on the real eye stream with a shuffle null.
//!
//! The null used here preserves each message's exact reading-layer symbol
//! multiset and length, then randomizes order within that message. It therefore
//! tests arrangement only; symbol frequencies are held fixed.

use crate::isomorph::{self, IsomorphError};
use crate::null::{SplitMix64, add_one_p_value, fisher_yates};
use crate::orders::{self, GridError, ReadingOrder, read_corpus_message_values};
use crate::trigram::TrigramValue;

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

impl From<crate::null::RandomBoundError> for IsomorphNullError {
    fn from(error: crate::null::RandomBoundError) -> Self {
        Self::RandomBoundTooLarge { bound: error.bound }
    }
}

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
    let grids = orders::corpus_grids()?;
    let order = orders::accepted_honeycomb_order();
    let keys: Vec<&'static str> = grids
        .iter()
        .map(crate::orders::GlyphGrid::message_key)
        .collect();
    let message_values = read_corpus_message_values(&grids, order)?;
    report_from_message_values(config, order, &keys, &message_values)
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
    let mut samples_by_window = vec![Vec::new(); real_summaries.len()];
    let mut empirical_p_counts = vec![0usize; real_summaries.len()];
    let mut rng = SplitMix64::new(config.seed);

    for _trial in 0..config.trials {
        let shuffled = shuffled_messages(message_values, &mut rng)?;
        let shuffled_summaries =
            summarize_window_range(&shuffled, config.min_window, config.max_window)?;
        for (((samples, p_count), real_summary), shuffled_summary) in samples_by_window
            .iter_mut()
            .zip(empirical_p_counts.iter_mut())
            .zip(real_summaries.iter())
            .zip(shuffled_summaries)
        {
            samples.push(shuffled_summary.summary.repeated_signature_kinds);
            if shuffled_summary.summary.repeated_signature_kinds
                >= real_summary.summary.repeated_signature_kinds
            {
                *p_count += 1;
            }
        }
    }

    let rows = real_summaries
        .into_iter()
        .zip(samples_by_window)
        .zip(empirical_p_counts)
        .map(|((real_summary, samples), empirical_p_count)| {
            let empirical_p = add_one_p_value(empirical_p_count, config.trials);
            IsomorphNullRow {
                window: real_summary.window,
                real: real_summary.summary,
                null: null_band(&samples),
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

fn shuffled_messages(
    message_values: &[Vec<TrigramValue>],
    rng: &mut SplitMix64,
) -> Result<Vec<Vec<TrigramValue>>, IsomorphNullError> {
    let mut shuffled = message_values.to_vec();
    for values in &mut shuffled {
        fisher_yates(values, rng)?;
    }
    Ok(shuffled)
}

fn null_band(samples: &[usize]) -> IsomorphNullBand {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    IsomorphNullBand {
        trials: samples.len(),
        mean: mean(samples),
        q025: quantile_from_sorted(&sorted, 25, 1_000),
        median: median(&sorted),
        q975: quantile_from_sorted(&sorted, 975, 1_000),
        max: sorted.last().copied().unwrap_or_default(),
    }
}

fn mean(samples: &[usize]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    samples.iter().sum::<usize>() as f64 / samples.len() as f64
}

fn median(sorted: &[usize]) -> f64 {
    let len = sorted.len();
    if len == 0 {
        return 0.0;
    }
    let middle = len / 2;
    if len.is_multiple_of(2) {
        match (
            sorted.get(middle.saturating_sub(1)).copied(),
            sorted.get(middle).copied(),
        ) {
            (Some(left), Some(right)) => f64::midpoint(left as f64, right as f64),
            _ => 0.0,
        }
    } else {
        sorted
            .get(middle)
            .copied()
            .map_or(0.0, |value| value as f64)
    }
}

fn quantile_from_sorted(sorted: &[usize], numerator: usize, denominator: usize) -> usize {
    sorted
        .get(scaled_quantile_index(sorted.len(), numerator, denominator))
        .copied()
        .unwrap_or_default()
}

fn scaled_quantile_index(len: usize, numerator: usize, denominator: usize) -> usize {
    if len == 0 || denominator == 0 {
        return 0;
    }
    len.saturating_sub(1).saturating_mul(numerator) / denominator
}

#[cfg(test)]
mod tests {
    use super::{IsomorphNullConfig, report_from_message_values, run_isomorph_null};
    use crate::null::SplitMix64;
    use crate::orders;
    use crate::trigram::TrigramValue;

    #[test]
    fn isomorph_null_is_reproducible_for_fixed_seed() {
        let config = IsomorphNullConfig {
            seed: 0x5eed,
            trials: 8,
            min_window: 3,
            max_window: 5,
        };

        let first = run_isomorph_null(config).unwrap();
        let second = run_isomorph_null(config).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.order.name(), "standard36-u012-d012");
        assert_eq!(first.rows.len(), 3);
    }

    #[test]
    fn isomorph_rich_fixture_exceeds_its_shuffle_null() {
        let messages = vec![isomorph_rich_values()];
        let config = IsomorphNullConfig {
            seed: 0x7a,
            trials: 64,
            min_window: 12,
            max_window: 12,
        };
        let report = report_from_message_values(
            config,
            orders::accepted_honeycomb_order(),
            &["fixture"],
            &messages,
        )
        .unwrap();
        let row = report.rows.first().unwrap();

        assert!(
            row.real.repeated_signature_kinds > row.null.q975,
            "real={} null={:?}",
            row.real.repeated_signature_kinds,
            row.null
        );
        assert!(row.empirical_p <= 0.05, "p={}", row.empirical_p);
    }

    #[test]
    fn uniform_random_fixture_stays_inside_its_shuffle_null() {
        let messages = vec![uniform_random_values(0x5151, 160, 83)];
        let config = IsomorphNullConfig {
            seed: 0x6161,
            trials: 128,
            min_window: 12,
            max_window: 12,
        };
        let report = report_from_message_values(
            config,
            orders::accepted_honeycomb_order(),
            &["uniform"],
            &messages,
        )
        .unwrap();
        let row = report.rows.first().unwrap();

        assert!(
            row.real.repeated_signature_kinds <= row.null.q975,
            "real={} null={:?}",
            row.real.repeated_signature_kinds,
            row.null
        );
    }

    fn isomorph_rich_values() -> Vec<TrigramValue> {
        let mut values = Vec::new();
        for block in 0u8..10 {
            let base = block * 12;
            for raw in [
                base,
                base + 1,
                base,
                base + 2,
                base + 3,
                base + 2,
                base + 4,
                base + 5,
                base + 6,
                base + 4,
                base + 7,
                base + 8,
                base + 9,
                base + 10,
                base + 11,
                base + 9,
            ] {
                values.push(value(raw));
            }
        }
        values
    }

    fn uniform_random_values(seed: u64, len: usize, alphabet_size: u8) -> Vec<TrigramValue> {
        let mut rng = SplitMix64::new(seed);
        let mut values = Vec::new();
        for _position in 0..len {
            let raw = (rng.next_u64() % u64::from(alphabet_size)) as u8;
            values.push(value(raw));
        }
        values
    }

    fn value(raw: u8) -> TrigramValue {
        TrigramValue::new(raw).unwrap()
    }
}

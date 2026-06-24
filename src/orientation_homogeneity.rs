//! Cross-message orientation-frequency homogeneity experiment.
//!
//! This experiment works on the engine-fixed single-orientation storage layer:
//! decoded storage symbols `0..=4`, with row delimiter `5` stripped. It does
//! not use a honeycomb traversal, trigram grouping, symbol-to-letter mapping,
//! or language score. The statistic is therefore order-independent and avoids
//! reading-order circularity by construction.
//!
//! The null model pools all observed orientations, then repeatedly repartitions
//! that exact multiset into the true per-message lengths. This is the
//! length-matched conditional null for "all messages share one common
//! orientation distribution." A lower-tail result means the messages are more
//! homogeneous than random repartitions of the same pooled symbols; an
//! upper-tail result means they are more heterogeneous.

use crate::analysis;
use crate::corpus;
use crate::generator::{self, ENGINE_MESSAGES};
use crate::glyph::StorageSymbol;
use crate::null::SplitMix64;

/// Number of engine/rendered orientation digits.
pub const ORIENTATION_BUCKETS: usize = 5;
/// Number of verified eye messages.
pub const MESSAGE_COUNT: usize = 9;
/// Degrees of freedom for the 9x5 homogeneity table.
pub const HOMOGENEITY_DEGREES_OF_FREEDOM: usize = (MESSAGE_COUNT - 1) * (ORIENTATION_BUCKETS - 1);
/// Degrees of freedom for the pooled five-bucket uniform context statistic.
pub const UNIFORM_DEGREES_OF_FREEDOM: usize = ORIENTATION_BUCKETS - 1;
/// Default deterministic seed for the repartition null.
pub const DEFAULT_SEED: u64 = 0x686f_6d6f_6f72_6931;
/// Default number of repartitions sampled per seed.
pub const DEFAULT_TRIALS_PER_SEED: usize = 1_000;
/// Default number of deterministic seeds sampled.
pub const DEFAULT_SEED_COUNT: usize = 5;

const POSITIVE_CONTROL_DOMINANT_IN_TEN: usize = 8;
const POSITIVE_CONTROL_PERIOD: usize = 10;
const SEED_STRIDE: u64 = 0x9e37_79b9_7f4a_7c15;

/// Configuration for the orientation homogeneity experiment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrientationHomogeneityConfig {
    /// First deterministic PRNG seed.
    pub seed: u64,
    /// Number of length-matched repartitions sampled for each seed.
    pub trials_per_seed: usize,
    /// Number of deterministic seed streams to run.
    pub seed_count: usize,
}

impl Default for OrientationHomogeneityConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_SEED,
            trials_per_seed: DEFAULT_TRIALS_PER_SEED,
            seed_count: DEFAULT_SEED_COUNT,
        }
    }
}

/// Error returned by the orientation homogeneity experiment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrientationHomogeneityError {
    /// At least one repartition trial per seed is required.
    ZeroTrials,
    /// At least one deterministic seed stream is required.
    ZeroSeedCount,
    /// The trial count overflowed the add-one empirical p-value denominator.
    TrialCountTooLarge,
    /// The verified corpus did not contain the expected number of messages.
    MessageCountMismatch {
        /// Expected message count.
        expected: usize,
        /// Observed message count.
        observed: usize,
    },
    /// Engine storage emitted a non-delimiter value outside `0..=4`.
    InvalidStorageSymbol {
        /// Message index in [`ENGINE_MESSAGES`].
        message_index: usize,
        /// Invalid decoded storage symbol.
        symbol: i8,
    },
    /// Engine-derived orientation count disagreed with the verified corpus.
    EyeCountMismatch {
        /// Corpus message key.
        message_key: &'static str,
        /// Verified eye count.
        expected: usize,
        /// Engine-derived orientation count.
        observed: usize,
    },
    /// Per-message lengths did not sum to the pooled orientation count.
    LengthTotalMismatch {
        /// Sum of the per-message lengths.
        lengths_total: usize,
        /// Pooled orientation count.
        pooled_total: usize,
    },
    /// A bounded PRNG draw could not represent the requested upper bound.
    RandomBoundTooLarge {
        /// Requested exclusive upper bound.
        bound: usize,
    },
}

/// Per-message count and relative-frequency profile.
#[derive(Clone, Debug, PartialEq)]
pub struct OrientationProfile {
    /// Corpus message key.
    pub message_key: &'static str,
    /// Number of delimiter-stripped orientations in this message.
    pub length: usize,
    /// Counts for orientation digits `0..=4`.
    pub counts: [usize; ORIENTATION_BUCKETS],
    /// Relative frequencies for orientation digits `0..=4`.
    pub frequencies: [f64; ORIENTATION_BUCKETS],
}

/// Pearson and likelihood-ratio homogeneity statistics for one table.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HomogeneityStatistics {
    /// Pearson chi-square homogeneity statistic.
    pub pearson_chi_square: f64,
    /// Likelihood-ratio `G` statistic for homogeneity.
    pub g_test: f64,
    /// Fixed 9x5-table degrees of freedom for the verified corpus.
    pub degrees_of_freedom: usize,
    /// Asymptotic upper-tail p-value for the Pearson statistic.
    pub pearson_asymptotic_upper_tail_p: Option<f64>,
    /// Asymptotic upper-tail p-value for the `G` statistic.
    pub g_test_asymptotic_upper_tail_p: Option<f64>,
}

/// Pooled five-bucket uniformity context.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct UniformContext {
    /// Counts for pooled orientation digits `0..=4`.
    pub counts: [usize; ORIENTATION_BUCKETS],
    /// Pearson chi-square goodness-of-fit statistic versus uniform `0..=4`.
    pub chi_square_vs_uniform: f64,
    /// Degrees of freedom for the five-bucket uniform reference.
    pub degrees_of_freedom: usize,
    /// Asymptotic upper-tail p-value for the uniformity statistic.
    pub asymptotic_upper_tail_p: Option<f64>,
}

/// Monte-Carlo summary for one scalar statistic.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ScalarNullBand {
    /// Number of sampled repartitions.
    pub trials: usize,
    /// Mean sampled statistic.
    pub mean: f64,
    /// Smallest sampled statistic.
    pub min: f64,
    /// Lower pointwise 95% edge.
    pub q025: f64,
    /// Sample median.
    pub median: f64,
    /// Upper pointwise 95% edge.
    pub q975: f64,
    /// Largest sampled statistic.
    pub max: f64,
}

/// Empirical placement of the observed statistic in a repartition null.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HomogeneityNullComparison {
    /// Observed statistic.
    pub observed: f64,
    /// Repartition-null distribution summary.
    pub null: ScalarNullBand,
    /// Number of repartitions with statistic less than or equal to observed.
    pub lower_tail_count: usize,
    /// Number of repartitions with statistic greater than or equal to observed.
    pub upper_tail_count: usize,
    /// Add-one lower-tail empirical p-value.
    pub lower_tail_add_one_p: f64,
    /// Add-one upper-tail empirical p-value.
    pub upper_tail_add_one_p: f64,
    /// Add-one two-sided empirical p-value, doubled from the smaller tail.
    pub two_sided_add_one_p: f64,
}

/// Synthetic deliberately heterogeneous positive-control result.
#[derive(Clone, Debug, PartialEq)]
pub struct HomogeneityPositiveControl {
    /// Per-message lengths copied from the real corpus.
    pub message_lengths: Vec<usize>,
    /// Pearson statistic placement for the heterogeneous fixture.
    pub pearson: HomogeneityNullComparison,
    /// `G` statistic placement for the heterogeneous fixture.
    pub g_test: HomogeneityNullComparison,
}

/// Complete orientation homogeneity report.
#[derive(Clone, Debug, PartialEq)]
pub struct OrientationHomogeneityReport {
    /// Configuration used for the real repartition null and positive control.
    pub config: OrientationHomogeneityConfig,
    /// Per-message orientation profiles in corpus order.
    pub profiles: Vec<OrientationProfile>,
    /// Total delimiter-stripped orientations across all messages.
    pub total_orientations: usize,
    /// Sum of verified corpus eye counts, used as an integrity anchor.
    pub total_eye_count: usize,
    /// Pooled five-bucket uniformity context.
    pub pooled_uniform: UniformContext,
    /// Observed homogeneity statistics.
    pub homogeneity: HomogeneityStatistics,
    /// Repartition-null placement for Pearson chi-square.
    pub pearson_null: HomogeneityNullComparison,
    /// Repartition-null placement for the `G` statistic.
    pub g_test_null: HomogeneityNullComparison,
    /// Deliberately heterogeneous positive-control result.
    pub positive_control: HomogeneityPositiveControl,
}

/// Runs the cross-message orientation-frequency homogeneity experiment.
///
/// # Errors
/// Returns [`OrientationHomogeneityError`] if configuration is invalid, engine
/// storage symbols are not the verified orientation/delimiter alphabet, or the
/// engine-derived eye counts fail to match the verified corpus anchors.
pub fn run_orientation_homogeneity(
    config: OrientationHomogeneityConfig,
) -> Result<OrientationHomogeneityReport, OrientationHomogeneityError> {
    validate_config(config)?;

    let messages = engine_orientation_messages()?;
    let profiles = profiles_from_messages(&messages);
    let table = messages
        .iter()
        .map(|message| message.counts)
        .collect::<Vec<_>>();
    let pooled = flatten_digits(&messages);
    let lengths = messages
        .iter()
        .map(|message| message.digits.len())
        .collect::<Vec<_>>();
    let total_orientations = pooled.len();
    let total_eye_count = corpus::messages()
        .iter()
        .map(|message| message.eye_count)
        .sum();
    let pooled_counts = pooled_counts(&table);
    let pooled_uniform = uniform_context(pooled_counts);
    let homogeneity = homogeneity_statistics(&table);
    let (pearson_null, g_test_null) =
        repartition_null_comparisons(config, &pooled, &lengths, &homogeneity)?;
    let positive_control = positive_control(config, &lengths)?;

    Ok(OrientationHomogeneityReport {
        config,
        profiles,
        total_orientations,
        total_eye_count,
        pooled_uniform,
        homogeneity,
        pearson_null,
        g_test_null,
        positive_control,
    })
}

fn validate_config(
    config: OrientationHomogeneityConfig,
) -> Result<(), OrientationHomogeneityError> {
    if config.trials_per_seed == 0 {
        return Err(OrientationHomogeneityError::ZeroTrials);
    }
    if config.seed_count == 0 {
        return Err(OrientationHomogeneityError::ZeroSeedCount);
    }
    let total_trials = total_trials(config)?;
    let _denominator = total_trials
        .checked_add(1)
        .ok_or(OrientationHomogeneityError::TrialCountTooLarge)?;
    Ok(())
}

fn total_trials(
    config: OrientationHomogeneityConfig,
) -> Result<usize, OrientationHomogeneityError> {
    config
        .trials_per_seed
        .checked_mul(config.seed_count)
        .ok_or(OrientationHomogeneityError::TrialCountTooLarge)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OrientationMessage {
    key: &'static str,
    digits: Vec<u8>,
    counts: [usize; ORIENTATION_BUCKETS],
}

fn engine_orientation_messages() -> Result<Vec<OrientationMessage>, OrientationHomogeneityError> {
    let corpus_messages = corpus::messages();
    if corpus_messages.len() != MESSAGE_COUNT || ENGINE_MESSAGES.len() != MESSAGE_COUNT {
        return Err(OrientationHomogeneityError::MessageCountMismatch {
            expected: MESSAGE_COUNT,
            observed: corpus_messages.len().min(ENGINE_MESSAGES.len()),
        });
    }

    let mut messages = Vec::new();
    for (message_index, (message, pairs)) in corpus_messages.iter().zip(ENGINE_MESSAGES).enumerate()
    {
        let mut digits = Vec::new();
        let mut counts = [0usize; ORIENTATION_BUCKETS];
        for symbol in generator::decode_message(pairs) {
            match StorageSymbol::from_value(symbol) {
                Ok(StorageSymbol::Orientation(orientation)) => {
                    let digit = orientation.digit();
                    digits.push(digit);
                    increment_count(&mut counts, digit)?;
                }
                Ok(StorageSymbol::RowDelimiter) => {}
                Ok(StorageSymbol::NegativeOne) | Err(_) => {
                    return Err(OrientationHomogeneityError::InvalidStorageSymbol {
                        message_index,
                        symbol,
                    });
                }
            }
        }
        if digits.len() != message.eye_count {
            return Err(OrientationHomogeneityError::EyeCountMismatch {
                message_key: message.key,
                expected: message.eye_count,
                observed: digits.len(),
            });
        }
        messages.push(OrientationMessage {
            key: message.key,
            digits,
            counts,
        });
    }
    Ok(messages)
}

fn profiles_from_messages(messages: &[OrientationMessage]) -> Vec<OrientationProfile> {
    messages
        .iter()
        .map(|message| OrientationProfile {
            message_key: message.key,
            length: message.digits.len(),
            counts: message.counts,
            frequencies: relative_frequencies(message.counts),
        })
        .collect()
}

fn increment_count(
    counts: &mut [usize; ORIENTATION_BUCKETS],
    digit: u8,
) -> Result<(), OrientationHomogeneityError> {
    let index = usize::from(digit);
    let Some(count) = counts.get_mut(index) else {
        let symbol = i8::try_from(digit).unwrap_or(i8::MAX);
        return Err(OrientationHomogeneityError::InvalidStorageSymbol {
            message_index: 0,
            symbol,
        });
    };
    *count += 1;
    Ok(())
}

fn relative_frequencies(counts: [usize; ORIENTATION_BUCKETS]) -> [f64; ORIENTATION_BUCKETS] {
    let total = counts.iter().sum::<usize>();
    if total == 0 {
        return [0.0; ORIENTATION_BUCKETS];
    }
    std::array::from_fn(|index| {
        counts
            .get(index)
            .copied()
            .map_or(0.0, |count| count as f64 / total as f64)
    })
}

fn flatten_digits(messages: &[OrientationMessage]) -> Vec<u8> {
    messages
        .iter()
        .flat_map(|message| message.digits.iter().copied())
        .collect()
}

fn pooled_counts(table: &[[usize; ORIENTATION_BUCKETS]]) -> [usize; ORIENTATION_BUCKETS] {
    let mut pooled = [0usize; ORIENTATION_BUCKETS];
    for row in table {
        for (slot, &count) in pooled.iter_mut().zip(row) {
            *slot += count;
        }
    }
    pooled
}

fn uniform_context(counts: [usize; ORIENTATION_BUCKETS]) -> UniformContext {
    let chi_square_vs_uniform = analysis::chi_square_goodness_of_fit_uniform(&counts);
    UniformContext {
        counts,
        chi_square_vs_uniform,
        degrees_of_freedom: UNIFORM_DEGREES_OF_FREEDOM,
        asymptotic_upper_tail_p: analysis::chi_square_upper_tail_p_value(
            chi_square_vs_uniform,
            UNIFORM_DEGREES_OF_FREEDOM,
        ),
    }
}

fn homogeneity_statistics(table: &[[usize; ORIENTATION_BUCKETS]]) -> HomogeneityStatistics {
    let pearson_chi_square = pearson_homogeneity_statistic(table);
    let g_test = g_test_homogeneity_statistic(table);
    HomogeneityStatistics {
        pearson_chi_square,
        g_test,
        degrees_of_freedom: HOMOGENEITY_DEGREES_OF_FREEDOM,
        pearson_asymptotic_upper_tail_p: analysis::chi_square_upper_tail_p_value(
            pearson_chi_square,
            HOMOGENEITY_DEGREES_OF_FREEDOM,
        ),
        g_test_asymptotic_upper_tail_p: analysis::chi_square_upper_tail_p_value(
            g_test,
            HOMOGENEITY_DEGREES_OF_FREEDOM,
        ),
    }
}

fn pearson_homogeneity_statistic(table: &[[usize; ORIENTATION_BUCKETS]]) -> f64 {
    let row_totals = row_totals(table);
    let col_totals = pooled_counts(table);
    let total = row_totals.iter().sum::<usize>();
    if total == 0 {
        return 0.0;
    }

    let mut statistic = 0.0;
    for (row, &row_total) in table.iter().zip(&row_totals) {
        for (&observed, &col_total) in row.iter().zip(&col_totals) {
            let expected = expected_count(row_total, col_total, total);
            if expected <= 0.0 {
                continue;
            }
            let delta = observed as f64 - expected;
            statistic += delta * delta / expected;
        }
    }
    statistic
}

fn g_test_homogeneity_statistic(table: &[[usize; ORIENTATION_BUCKETS]]) -> f64 {
    let row_totals = row_totals(table);
    let col_totals = pooled_counts(table);
    let total = row_totals.iter().sum::<usize>();
    if total == 0 {
        return 0.0;
    }

    let mut statistic = 0.0;
    for (row, &row_total) in table.iter().zip(&row_totals) {
        for (&observed, &col_total) in row.iter().zip(&col_totals) {
            if observed == 0 {
                continue;
            }
            let expected = expected_count(row_total, col_total, total);
            if expected <= 0.0 {
                continue;
            }
            let ratio = observed as f64 / expected;
            statistic += 2.0 * observed as f64 * ratio.ln();
        }
    }
    statistic
}

fn row_totals(table: &[[usize; ORIENTATION_BUCKETS]]) -> Vec<usize> {
    table.iter().map(|row| row.iter().sum()).collect()
}

fn expected_count(row_total: usize, col_total: usize, total: usize) -> f64 {
    row_total as f64 * col_total as f64 / total as f64
}

fn repartition_null_comparisons(
    config: OrientationHomogeneityConfig,
    pooled: &[u8],
    lengths: &[usize],
    observed: &HomogeneityStatistics,
) -> Result<(HomogeneityNullComparison, HomogeneityNullComparison), OrientationHomogeneityError> {
    let mut pearson_samples = Vec::with_capacity(total_trials(config)?);
    let mut g_test_samples = Vec::with_capacity(total_trials(config)?);

    for seed_index in 0..config.seed_count {
        let mut rng = SplitMix64::new(seed_for_index(config.seed, seed_index)?);
        for _trial in 0..config.trials_per_seed {
            let table = repartition_table(pooled, lengths, &mut rng)?;
            let statistics = homogeneity_statistics(&table);
            pearson_samples.push(statistics.pearson_chi_square);
            g_test_samples.push(statistics.g_test);
        }
    }

    Ok((
        null_comparison(observed.pearson_chi_square, &pearson_samples)?,
        null_comparison(observed.g_test, &g_test_samples)?,
    ))
}

fn seed_for_index(seed: u64, seed_index: usize) -> Result<u64, OrientationHomogeneityError> {
    let index = u64::try_from(seed_index)
        .map_err(|_error| OrientationHomogeneityError::RandomBoundTooLarge { bound: seed_index })?;
    Ok(seed.wrapping_add(index.wrapping_mul(SEED_STRIDE)))
}

fn repartition_table(
    pooled: &[u8],
    lengths: &[usize],
    rng: &mut SplitMix64,
) -> Result<Vec<[usize; ORIENTATION_BUCKETS]>, OrientationHomogeneityError> {
    let lengths_total = lengths.iter().sum::<usize>();
    if lengths_total != pooled.len() {
        return Err(OrientationHomogeneityError::LengthTotalMismatch {
            lengths_total,
            pooled_total: pooled.len(),
        });
    }

    let mut shuffled = pooled.to_vec();
    fisher_yates(&mut shuffled, rng)?;

    let mut rows = Vec::with_capacity(lengths.len());
    let mut symbols = shuffled.into_iter();
    for &length in lengths {
        let mut counts = [0usize; ORIENTATION_BUCKETS];
        for _position in 0..length {
            let Some(digit) = symbols.next() else {
                return Err(OrientationHomogeneityError::LengthTotalMismatch {
                    lengths_total,
                    pooled_total: pooled.len(),
                });
            };
            increment_count(&mut counts, digit)?;
        }
        rows.push(counts);
    }
    Ok(rows)
}

fn fisher_yates(
    values: &mut [u8],
    rng: &mut SplitMix64,
) -> Result<(), OrientationHomogeneityError> {
    let mut unswapped = values.len();
    while unswapped > 1 {
        let last = unswapped - 1;
        let partner = random_index_below(unswapped, rng)?;
        values.swap(last, partner);
        unswapped = last;
    }
    Ok(())
}

fn random_index_below(
    bound: usize,
    rng: &mut SplitMix64,
) -> Result<usize, OrientationHomogeneityError> {
    let bound_u64 = u64::try_from(bound)
        .map_err(|_error| OrientationHomogeneityError::RandomBoundTooLarge { bound })?;
    if bound_u64 == 0 {
        return Err(OrientationHomogeneityError::RandomBoundTooLarge { bound });
    }
    let rejection_threshold = u64::MAX - (u64::MAX % bound_u64);
    loop {
        let draw = rng.next_u64();
        if draw < rejection_threshold {
            let index_u64 = draw % bound_u64;
            return usize::try_from(index_u64)
                .map_err(|_error| OrientationHomogeneityError::RandomBoundTooLarge { bound });
        }
    }
}

fn null_comparison(
    observed: f64,
    samples: &[f64],
) -> Result<HomogeneityNullComparison, OrientationHomogeneityError> {
    let denominator = samples
        .len()
        .checked_add(1)
        .ok_or(OrientationHomogeneityError::TrialCountTooLarge)?;
    let lower_tail_count = samples.iter().filter(|&&sample| sample <= observed).count();
    let upper_tail_count = samples.iter().filter(|&&sample| sample >= observed).count();
    let lower_tail_add_one_p = (lower_tail_count + 1) as f64 / denominator as f64;
    let upper_tail_add_one_p = (upper_tail_count + 1) as f64 / denominator as f64;
    let two_sided_add_one_p = (2.0 * lower_tail_add_one_p.min(upper_tail_add_one_p)).min(1.0);

    Ok(HomogeneityNullComparison {
        observed,
        null: scalar_null_band(samples),
        lower_tail_count,
        upper_tail_count,
        lower_tail_add_one_p,
        upper_tail_add_one_p,
        two_sided_add_one_p,
    })
}

fn scalar_null_band(samples: &[f64]) -> ScalarNullBand {
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    ScalarNullBand {
        trials: samples.len(),
        mean: mean(samples),
        min: sorted.first().copied().unwrap_or(0.0),
        q025: quantile_from_sorted(&sorted, 25, 1_000),
        median: median(&sorted),
        q975: quantile_from_sorted(&sorted, 975, 1_000),
        max: sorted.last().copied().unwrap_or(0.0),
    }
}

fn mean(samples: &[f64]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    samples.iter().sum::<f64>() / samples.len() as f64
}

fn median(sorted: &[f64]) -> f64 {
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
            (Some(left), Some(right)) => f64::midpoint(left, right),
            _ => 0.0,
        }
    } else {
        sorted.get(middle).copied().unwrap_or(0.0)
    }
}

fn quantile_from_sorted(sorted: &[f64], numerator: usize, denominator: usize) -> f64 {
    sorted
        .get(scaled_quantile_index(sorted.len(), numerator, denominator))
        .copied()
        .unwrap_or(0.0)
}

fn scaled_quantile_index(len: usize, numerator: usize, denominator: usize) -> usize {
    if len == 0 || denominator == 0 {
        return 0;
    }
    len.saturating_sub(1).saturating_mul(numerator) / denominator
}

fn positive_control(
    config: OrientationHomogeneityConfig,
    lengths: &[usize],
) -> Result<HomogeneityPositiveControl, OrientationHomogeneityError> {
    let messages = positive_control_messages(lengths)?;
    let table = messages
        .iter()
        .map(|message| message.counts)
        .collect::<Vec<_>>();
    let pooled = flatten_digits(&messages);
    let observed = homogeneity_statistics(&table);
    let (pearson, g_test) = repartition_null_comparisons(config, &pooled, lengths, &observed)?;
    Ok(HomogeneityPositiveControl {
        message_lengths: lengths.to_vec(),
        pearson,
        g_test,
    })
}

fn positive_control_messages(
    lengths: &[usize],
) -> Result<Vec<OrientationMessage>, OrientationHomogeneityError> {
    let mut messages = Vec::new();
    for (message_index, &length) in lengths.iter().enumerate() {
        let dominant = (message_index % ORIENTATION_BUCKETS) as u8;
        let mut digits = Vec::with_capacity(length);
        let mut counts = [0usize; ORIENTATION_BUCKETS];
        for position in 0..length {
            let digit = if position % POSITIVE_CONTROL_PERIOD < POSITIVE_CONTROL_DOMINANT_IN_TEN {
                dominant
            } else {
                alternative_digit(dominant, position)
            };
            digits.push(digit);
            increment_count(&mut counts, digit)?;
        }
        messages.push(OrientationMessage {
            key: "synthetic",
            digits,
            counts,
        });
    }
    Ok(messages)
}

fn alternative_digit(dominant: u8, position: usize) -> u8 {
    let offset = 1 + ((position / POSITIVE_CONTROL_PERIOD) % (ORIENTATION_BUCKETS - 1));
    let raw = (usize::from(dominant) + offset) % ORIENTATION_BUCKETS;
    raw as u8
}

#[cfg(test)]
mod tests {
    use super::{
        HOMOGENEITY_DEGREES_OF_FREEDOM, HomogeneityNullComparison, ORIENTATION_BUCKETS,
        OrientationHomogeneityConfig, OrientationHomogeneityError, g_test_homogeneity_statistic,
        homogeneity_statistics, pearson_homogeneity_statistic, positive_control, repartition_table,
        run_orientation_homogeneity,
    };
    use crate::null::SplitMix64;

    #[test]
    fn homogeneity_statistics_match_toy_table() {
        let table = [[8, 2, 0, 0, 0], [2, 8, 0, 0, 0]];

        assert_close(pearson_homogeneity_statistic(&table), 7.2, 1e-12);
        assert_close(
            g_test_homogeneity_statistic(&table),
            7.709_790_280_870_3,
            1e-12,
        );

        let statistics = homogeneity_statistics(&table);
        assert_eq!(
            statistics.degrees_of_freedom,
            HOMOGENEITY_DEGREES_OF_FREEDOM
        );
    }

    #[test]
    fn repartition_null_preserves_lengths_and_pooled_counts() {
        let pooled = vec![0, 0, 1, 2, 2, 3, 4, 4, 4];
        let lengths = vec![2, 3, 4];
        let mut rng = SplitMix64::new(0x5eed);

        let table = repartition_table(&pooled, &lengths, &mut rng).unwrap();

        let row_totals = table
            .iter()
            .map(|row| row.iter().sum::<usize>())
            .collect::<Vec<_>>();
        assert_eq!(row_totals, lengths);
        assert_eq!(pooled_counts_for_test(&table), [2, 1, 2, 1, 3]);
    }

    #[test]
    fn repartition_rejects_length_mismatch() {
        let mut rng = SplitMix64::new(0x5eed);
        let error = repartition_table(&[0, 1, 2], &[1, 1], &mut rng).unwrap_err();
        assert_eq!(
            error,
            OrientationHomogeneityError::LengthTotalMismatch {
                lengths_total: 2,
                pooled_total: 3,
            }
        );
    }

    #[test]
    fn heterogeneous_positive_control_lands_in_upper_tail() {
        let config = OrientationHomogeneityConfig {
            seed: 0x7070,
            trials_per_seed: 96,
            seed_count: 2,
        };
        let lengths = [60, 61, 62, 63, 64, 65, 66, 67, 68];

        let control = positive_control(config, &lengths).unwrap();

        assert_upper_tail_signal(control.pearson);
        assert_upper_tail_signal(control.g_test);
    }

    #[test]
    fn real_eye_headline_counts_are_pinned() {
        let config = OrientationHomogeneityConfig {
            seed: 0x5151,
            trials_per_seed: 8,
            seed_count: 2,
        };

        let report = run_orientation_homogeneity(config).unwrap();
        let lengths = report
            .profiles
            .iter()
            .map(|profile| profile.length)
            .collect::<Vec<_>>();

        assert_eq!(lengths, vec![297, 309, 354, 306, 411, 372, 357, 360, 342]);
        assert_eq!(report.total_orientations, 3_108);
        assert_eq!(report.total_eye_count, 3_108);
        assert_eq!(report.pooled_uniform.counts.iter().sum::<usize>(), 3_108);
        assert_eq!(report.pooled_uniform.counts.len(), ORIENTATION_BUCKETS);
    }

    fn assert_upper_tail_signal(comparison: HomogeneityNullComparison) {
        assert!(
            comparison.observed > comparison.null.q975,
            "observed={} null={:?}",
            comparison.observed,
            comparison.null
        );
        assert!(
            comparison.upper_tail_add_one_p <= 0.01,
            "p={} comparison={:?}",
            comparison.upper_tail_add_one_p,
            comparison
        );
    }

    fn pooled_counts_for_test(
        table: &[[usize; ORIENTATION_BUCKETS]],
    ) -> [usize; ORIENTATION_BUCKETS] {
        let mut counts = [0; ORIENTATION_BUCKETS];
        for row in table {
            for (slot, &count) in counts.iter_mut().zip(row) {
                *slot += count;
            }
        }
        counts
    }

    fn assert_close(observed: f64, expected: f64, tolerance: f64) {
        assert!(
            (observed - expected).abs() <= tolerance,
            "observed {observed}, expected {expected}"
        );
    }
}

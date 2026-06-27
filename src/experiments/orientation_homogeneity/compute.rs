//! Compute core for the cross-message orientation-frequency homogeneity battery.
//!
//! Engine-fixed orientation extraction, per-message profiles, the Pearson/`G`
//! homogeneity statistics, the length-matched repartition null, and the
//! heterogeneous positive control, split out of the experiment body.

use crate::analysis::analysis;
use crate::core::glyph::StorageSymbol;
use crate::data::corpus;
use crate::data::generator::{self, ENGINE_MESSAGES};
use crate::nulls::null::{SplitMix64, f64_band, fisher_yates};

use super::{
    HOMOGENEITY_DEGREES_OF_FREEDOM, HomogeneityNullComparison, HomogeneityPositiveControl,
    HomogeneityStatistics, MESSAGE_COUNT, ORIENTATION_BUCKETS, OrientationHomogeneityConfig,
    OrientationHomogeneityError, OrientationProfile, POSITIVE_CONTROL_DOMINANT_IN_TEN,
    POSITIVE_CONTROL_PERIOD, SEED_STRIDE, ScalarNullBand, UNIFORM_DEGREES_OF_FREEDOM,
    UniformContext,
};

pub(super) fn validate_config(
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
pub(super) struct OrientationMessage {
    pub(super) key: &'static str,
    pub(super) digits: Vec<u8>,
    pub(super) counts: [usize; ORIENTATION_BUCKETS],
}

pub(super) fn engine_orientation_messages()
-> Result<Vec<OrientationMessage>, OrientationHomogeneityError> {
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

pub(super) fn profiles_from_messages(messages: &[OrientationMessage]) -> Vec<OrientationProfile> {
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

pub(super) fn flatten_digits(messages: &[OrientationMessage]) -> Vec<u8> {
    messages
        .iter()
        .flat_map(|message| message.digits.iter().copied())
        .collect()
}

pub(super) fn pooled_counts(
    table: &[[usize; ORIENTATION_BUCKETS]],
) -> [usize; ORIENTATION_BUCKETS] {
    let mut pooled = [0usize; ORIENTATION_BUCKETS];
    for row in table {
        for (slot, &count) in pooled.iter_mut().zip(row) {
            *slot += count;
        }
    }
    pooled
}

pub(super) fn uniform_context(counts: [usize; ORIENTATION_BUCKETS]) -> UniformContext {
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

pub(super) fn homogeneity_statistics(
    table: &[[usize; ORIENTATION_BUCKETS]],
) -> HomogeneityStatistics {
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

pub(super) fn pearson_homogeneity_statistic(table: &[[usize; ORIENTATION_BUCKETS]]) -> f64 {
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

pub(super) fn g_test_homogeneity_statistic(table: &[[usize; ORIENTATION_BUCKETS]]) -> f64 {
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

pub(super) fn repartition_null_comparisons(
    config: OrientationHomogeneityConfig,
    pooled: &[u8],
    lengths: &[usize],
    observed: &HomogeneityStatistics,
) -> Result<(HomogeneityNullComparison, HomogeneityNullComparison), OrientationHomogeneityError> {
    let mut pearson_samples = Vec::with_capacity(total_trials(config)?);
    let mut g_test_samples = Vec::with_capacity(total_trials(config)?);

    // The pooled repartition (`repartition_table`) is fallible with the module's
    // own `OrientationHomogeneityError` (length-total / invalid-digit invariants),
    // which the `NullSampler` trait's fixed `RandomBoundError` error channel cannot
    // carry faithfully. Rather than mask that diagnostic behind a lossy
    // `RandomBoundError`, the resampling call stays inline so a genuine failure
    // surfaces as the same error it did before. (The band helper is still shared;
    // see `null_comparison` -> `f64_band`.)
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

pub(super) fn repartition_table(
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
        null: ScalarNullBand::from(f64_band(samples)),
        lower_tail_count,
        upper_tail_count,
        lower_tail_add_one_p,
        upper_tail_add_one_p,
        two_sided_add_one_p,
    })
}

pub(super) fn positive_control(
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

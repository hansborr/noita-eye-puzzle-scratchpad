//! Shuffle and no-repeat null sampling, estimator-bias calibration, and planted controls.

use crate::core::trigram::TrigramValue;
use crate::nulls::null::{
    NullSampler, SplitMix64, WithinMessageShuffle, f64_band, fisher_yates, random_index_below,
};

use super::transition::{
    COMPARISON_STATISTICS, NO_REPEAT_COMPARISON_STATISTICS, first_order_stats, statistic_value,
};
use super::{
    BiasCalibrationReport, CONTROL_PATTERN, ConditionalStatistic, ConditionalStructureConfig,
    ConditionalStructureError, FirstOrderStats, NO_REPEAT_BURN_IN_SWEEPS, NO_REPEAT_SAMPLE_SWEEPS,
    NoRepeatNullReport, NullComparison, PlantedControlReport, PlantedControlsReport,
    ScalarNullBand,
};

pub(super) fn null_comparisons(
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

pub(super) fn no_repeat_null_comparisons(
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

pub(super) fn comparison_from_samples(
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

pub(super) fn bias_calibration(
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

pub(super) fn planted_controls(
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

pub(super) fn structured_plaintext_messages(
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

pub(super) fn trigram_from_index(index: usize) -> Result<TrigramValue, ConditionalStructureError> {
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

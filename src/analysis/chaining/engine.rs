use super::{
    CalibrationBands, ChainingConfig, ChainingError, ChainingPeriodReport, ChainingReport,
    ChainingSignature, PairAlignment, calibration_bands, classify_real_score, cycle_closure,
    cycle_distance, mean_f64,
};
use crate::analysis::orders::{self, ReadingOrder, read_corpus_message_values};
use crate::core::trigram::TrigramValue;
use crate::nulls::null::{SplitMix64, fisher_yates, random_index_below, stateless_splitmix};

/// Runs Experiment 7B on the verified eye corpus.
///
/// # Errors
/// Returns [`ChainingError`] when the corpus cannot be reconstructed, when the
/// accepted reading order is incompatible with a grid, or when the
/// configuration is invalid.
pub fn run_chaining(config: ChainingConfig) -> Result<ChainingReport, ChainingError> {
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

/// Computes the chaining signature for caller-supplied message values.
///
/// This is the single procedure used by the real-eye stream and every control
/// fixture: split by period within each message, compare adjacent column
/// distributions by circular additive shifts, and close the shift cycle.
///
/// # Errors
/// Returns [`ChainingError`] if the period or alphabet is invalid, or if any
/// stream value is outside the configured alphabet.
pub fn chaining_signature(
    message_values: &[Vec<TrigramValue>],
    period: usize,
    alphabet_size: usize,
) -> Result<ChainingSignature, ChainingError> {
    validate_period_and_alphabet(period, alphabet_size)?;
    let columns = split_columns(message_values, period, alphabet_size)?;
    let column_lengths = columns
        .iter()
        .map(|column| column.total)
        .collect::<Vec<_>>();
    let total_symbols = column_lengths.iter().sum();

    let mut pair_alignments = Vec::with_capacity(period);
    for from_column in 0..period {
        let to_column = (from_column + 1) % period;
        let Some(left) = columns.get(from_column) else {
            return Err(ChainingError::ControlConstructionFailed);
        };
        let Some(right) = columns.get(to_column) else {
            return Err(ChainingError::ControlConstructionFailed);
        };
        pair_alignments.push(best_pair_alignment(
            from_column,
            to_column,
            left,
            right,
            alphabet_size,
        ));
    }

    let mean_best_overlap = mean_f64(pair_alignments.iter().map(|pair| pair.best_overlap));
    let mean_alignment_quality = mean_f64(pair_alignments.iter().map(|pair| pair.quality));
    let shift_sum = pair_alignments
        .iter()
        .map(|pair| pair.shift)
        .fold(0usize, |sum, shift| (sum + shift) % alphabet_size);
    let cycle_residual = shift_sum % alphabet_size;
    let cycle_residual_distance = cycle_distance(cycle_residual, alphabet_size);
    let cycle_closure = cycle_closure(cycle_residual_distance, alphabet_size);
    let chain_score = mean_alignment_quality * cycle_closure;

    Ok(ChainingSignature {
        period,
        alphabet_size,
        total_symbols,
        column_lengths,
        mean_best_overlap,
        mean_alignment_quality,
        cycle_residual,
        cycle_residual_distance,
        cycle_closure,
        chain_score,
        pair_alignments,
    })
}

fn report_from_message_values(
    config: ChainingConfig,
    order: ReadingOrder,
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
) -> Result<ChainingReport, ChainingError> {
    validate_config(config)?;
    let lengths = message_values.iter().map(Vec::len).collect::<Vec<_>>();
    let total_length = lengths.iter().sum();
    let source_profile = SourceProfile::new(config.alphabet_size);

    let mut rows = Vec::new();
    for period in config.min_period..=config.max_period {
        let real = chaining_signature(message_values, period, config.alphabet_size)?;
        let mut rng = calibration_rng_for_period(config.seed, period);
        let calibration = calibrate_period(config, period, &lengths, &source_profile, &mut rng)?;
        let score_bands_separated = calibration.fail.chain_score.q975
            < calibration.succeed.chain_score.q025
            && calibration.shuffled_fail.chain_score.q975 < calibration.succeed.chain_score.q025;
        let classification = classify_real_score(
            real.chain_score,
            &calibration.succeed.chain_score,
            &calibration.fail.chain_score,
            &calibration.shuffled_fail.chain_score,
            score_bands_separated,
        );
        rows.push(ChainingPeriodReport {
            period,
            real,
            succeed: calibration.succeed,
            fail: calibration.fail,
            shuffled_fail: calibration.shuffled_fail,
            score_bands_separated,
            classification,
        });
    }

    Ok(ChainingReport {
        config,
        order,
        message_lengths: keys.iter().copied().zip(lengths).collect(),
        total_length,
        rows,
    })
}

fn calibration_rng_for_period(seed: u64, period: usize) -> SplitMix64 {
    let period_word = period as u64;
    let mixed = stateless_splitmix(
        seed ^ 0x7065_7269_6f64_373b ^ period_word.wrapping_mul(0x9e37_79b9_7f4a_7c15),
    );
    SplitMix64::new(mixed)
}

fn validate_config(config: ChainingConfig) -> Result<(), ChainingError> {
    if config.trials == 0 {
        return Err(ChainingError::ZeroTrials);
    }
    validate_period_range(config.min_period, config.max_period)?;
    validate_alphabet(config.alphabet_size)
}

fn validate_period_range(min_period: usize, max_period: usize) -> Result<(), ChainingError> {
    if min_period < 2 || min_period > max_period {
        return Err(ChainingError::InvalidPeriodRange {
            min_period,
            max_period,
        });
    }
    Ok(())
}

fn validate_period_and_alphabet(period: usize, alphabet_size: usize) -> Result<(), ChainingError> {
    validate_period_range(period, period)?;
    validate_alphabet(alphabet_size)
}

fn validate_alphabet(alphabet_size: usize) -> Result<(), ChainingError> {
    if alphabet_size == 0 || alphabet_size > 125 {
        return Err(ChainingError::InvalidAlphabetSize { alphabet_size });
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ColumnCounts {
    counts: Vec<usize>,
    total: usize,
}

fn split_columns(
    message_values: &[Vec<TrigramValue>],
    period: usize,
    alphabet_size: usize,
) -> Result<Vec<ColumnCounts>, ChainingError> {
    let mut columns = (0..period)
        .map(|_column| ColumnCounts {
            counts: vec![0; alphabet_size],
            total: 0,
        })
        .collect::<Vec<_>>();

    for values in message_values {
        for (position, value) in values.iter().copied().enumerate() {
            let raw = usize::from(value.get());
            if raw >= alphabet_size {
                return Err(ChainingError::ValueOutsideAlphabet {
                    value: value.get(),
                    alphabet_size,
                });
            }
            let column_index = position % period;
            let Some(column) = columns.get_mut(column_index) else {
                return Err(ChainingError::ControlConstructionFailed);
            };
            let Some(count) = column.counts.get_mut(raw) else {
                return Err(ChainingError::ControlConstructionFailed);
            };
            *count += 1;
            column.total += 1;
        }
    }

    Ok(columns)
}

fn best_pair_alignment(
    from_column: usize,
    to_column: usize,
    left: &ColumnCounts,
    right: &ColumnCounts,
    alphabet_size: usize,
) -> PairAlignment {
    let mut best_shift = 0usize;
    let mut best_overlap = f64::NEG_INFINITY;
    let mut second_overlap = f64::NEG_INFINITY;

    for shift in 0..alphabet_size {
        let overlap = shifted_overlap(left, right, shift, alphabet_size);
        if overlap > best_overlap {
            second_overlap = best_overlap;
            best_overlap = overlap;
            best_shift = shift;
        } else if overlap > second_overlap {
            second_overlap = overlap;
        }
    }

    if !second_overlap.is_finite() {
        second_overlap = best_overlap.max(0.0);
    }
    let best_overlap = best_overlap.max(0.0);
    let second_overlap = second_overlap.max(0.0);
    PairAlignment {
        from_column,
        to_column,
        shift: best_shift,
        best_overlap,
        second_overlap,
        quality: (best_overlap - second_overlap).max(0.0),
    }
}

fn shifted_overlap(
    left: &ColumnCounts,
    right: &ColumnCounts,
    shift: usize,
    alphabet_size: usize,
) -> f64 {
    if left.total == 0 || right.total == 0 {
        return 0.0;
    }
    let left_total = left.total as f64;
    let right_total = right.total as f64;
    let mut overlap = 0.0;
    for (symbol, &left_count) in left.counts.iter().enumerate() {
        let right_index = (symbol + shift) % alphabet_size;
        if let Some(&right_count) = right.counts.get(right_index) {
            let left_probability = left_count as f64 / left_total;
            let right_probability = right_count as f64 / right_total;
            overlap += left_probability.min(right_probability);
        }
    }
    overlap
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SourceProfile {
    population: Vec<usize>,
    stride: usize,
}

impl SourceProfile {
    pub(crate) fn new(alphabet_size: usize) -> Self {
        let weights = source_weights(alphabet_size);
        let max_weight = weights.iter().copied().max().unwrap_or(1);
        let mut population = Vec::new();
        for rank in 0..max_weight {
            for (symbol, &weight) in weights.iter().enumerate() {
                if rank < weight {
                    population.push(symbol);
                }
            }
        }
        let stride = coprime_stride(population.len(), alphabet_size);
        Self { population, stride }
    }

    fn symbol_at(&self, row: usize, offset: usize) -> Result<usize, ChainingError> {
        if self.population.is_empty() {
            return Err(ChainingError::ControlConstructionFailed);
        }
        let index = (row.wrapping_mul(self.stride).wrapping_add(offset)) % self.population.len();
        self.population
            .get(index)
            .copied()
            .ok_or(ChainingError::ControlConstructionFailed)
    }
}

fn source_weights(alphabet_size: usize) -> Vec<usize> {
    (0..alphabet_size)
        .map(|symbol| {
            let mixed = stateless_splitmix(symbol as u64 ^ 0x9f6d_62f1_4d35_24ab);
            3 + (mixed % 47) as usize
        })
        .collect()
}

fn coprime_stride(total: usize, alphabet_size: usize) -> usize {
    let mut stride = alphabet_size.max(3);
    if stride.is_multiple_of(2) {
        stride += 1;
    }
    while gcd(stride, total) != 1 {
        stride += 2;
    }
    stride
}

fn gcd(mut left: usize, mut right: usize) -> usize {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

#[derive(Clone, Debug, PartialEq)]
struct CalibrationSamples {
    succeed: Vec<ChainingSignature>,
    fail: Vec<ChainingSignature>,
    shuffled_fail: Vec<ChainingSignature>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct PeriodCalibration {
    succeed: CalibrationBands,
    fail: CalibrationBands,
    shuffled_fail: CalibrationBands,
}

fn calibrate_period(
    config: ChainingConfig,
    period: usize,
    lengths: &[usize],
    source_profile: &SourceProfile,
    rng: &mut SplitMix64,
) -> Result<PeriodCalibration, ChainingError> {
    let mut samples = CalibrationSamples {
        succeed: Vec::with_capacity(config.trials),
        fail: Vec::with_capacity(config.trials),
        shuffled_fail: Vec::with_capacity(config.trials),
    };

    for _trial in 0..config.trials {
        let controls =
            build_control_fixtures(lengths, period, config.alphabet_size, source_profile, rng)?;
        samples.succeed.push(chaining_signature(
            &controls.succeed,
            period,
            config.alphabet_size,
        )?);
        samples.fail.push(chaining_signature(
            &controls.fail,
            period,
            config.alphabet_size,
        )?);
        samples.shuffled_fail.push(chaining_signature(
            &controls.shuffled_fail,
            period,
            config.alphabet_size,
        )?);
    }

    Ok(PeriodCalibration {
        succeed: calibration_bands(&samples.succeed),
        fail: calibration_bands(&samples.fail),
        shuffled_fail: calibration_bands(&samples.shuffled_fail),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ControlFixtures {
    pub(crate) succeed: Vec<Vec<TrigramValue>>,
    pub(crate) fail: Vec<Vec<TrigramValue>>,
    pub(crate) shuffled_fail: Vec<Vec<TrigramValue>>,
}

pub(crate) fn build_control_fixtures(
    lengths: &[usize],
    period: usize,
    alphabet_size: usize,
    source_profile: &SourceProfile,
    rng: &mut SplitMix64,
) -> Result<ControlFixtures, ChainingError> {
    let key = random_key(period, alphabet_size, rng)?;
    let substitutions = random_column_substitutions(period, alphabet_size, rng)?;
    let source_offset = random_index_below(source_profile.population.len(), rng)?;
    let mut column_rows = vec![0usize; period];
    let mut succeed = Vec::new();
    let mut fail = Vec::new();

    for &length in lengths {
        let mut succeed_message = Vec::with_capacity(length);
        let mut fail_message = Vec::with_capacity(length);
        for position in 0..length {
            let column = position % period;
            let Some(row) = column_rows.get_mut(column) else {
                return Err(ChainingError::ControlConstructionFailed);
            };
            let plain = source_profile.symbol_at(*row, source_offset)?;
            *row += 1;

            let Some(&shift) = key.get(column) else {
                return Err(ChainingError::ControlConstructionFailed);
            };
            let succeed_raw = (plain + shift) % alphabet_size;
            succeed_message.push(trigram_from_usize(succeed_raw, alphabet_size)?);

            let Some(substitution) = substitutions.get(column) else {
                return Err(ChainingError::ControlConstructionFailed);
            };
            let Some(&fail_raw) = substitution.get(plain) else {
                return Err(ChainingError::ControlConstructionFailed);
            };
            fail_message.push(trigram_from_usize(fail_raw, alphabet_size)?);
        }
        succeed.push(succeed_message);
        fail.push(fail_message);
    }

    let shuffled_fail = shuffle_within_period_columns(&fail, period, rng)?;
    Ok(ControlFixtures {
        succeed,
        fail,
        shuffled_fail,
    })
}

fn random_key(
    period: usize,
    alphabet_size: usize,
    rng: &mut SplitMix64,
) -> Result<Vec<usize>, ChainingError> {
    let mut key = Vec::with_capacity(period);
    for _column in 0..period {
        key.push(random_index_below(alphabet_size, rng)?);
    }
    Ok(key)
}

fn random_column_substitutions(
    period: usize,
    alphabet_size: usize,
    rng: &mut SplitMix64,
) -> Result<Vec<Vec<usize>>, ChainingError> {
    let mut substitutions = Vec::with_capacity(period);
    for _column in 0..period {
        let mut substitution = (0..alphabet_size).collect::<Vec<_>>();
        fisher_yates(&mut substitution, rng)?;
        substitutions.push(substitution);
    }
    Ok(substitutions)
}

fn shuffle_within_period_columns(
    message_values: &[Vec<TrigramValue>],
    period: usize,
    rng: &mut SplitMix64,
) -> Result<Vec<Vec<TrigramValue>>, ChainingError> {
    let mut columns = vec![Vec::new(); period];
    for values in message_values {
        for (position, value) in values.iter().copied().enumerate() {
            let column = position % period;
            let Some(slot) = columns.get_mut(column) else {
                return Err(ChainingError::ControlConstructionFailed);
            };
            slot.push(value);
        }
    }
    for column in &mut columns {
        fisher_yates(column, rng)?;
    }

    let mut column_offsets = vec![0usize; period];
    let mut shuffled = Vec::with_capacity(message_values.len());
    for values in message_values {
        let mut message = Vec::with_capacity(values.len());
        for position in 0..values.len() {
            let column = position % period;
            let Some(offset) = column_offsets.get_mut(column) else {
                return Err(ChainingError::ControlConstructionFailed);
            };
            let Some(column_values) = columns.get(column) else {
                return Err(ChainingError::ControlConstructionFailed);
            };
            let Some(value) = column_values.get(*offset).copied() else {
                return Err(ChainingError::ControlConstructionFailed);
            };
            *offset += 1;
            message.push(value);
        }
        shuffled.push(message);
    }
    Ok(shuffled)
}

fn trigram_from_usize(value: usize, alphabet_size: usize) -> Result<TrigramValue, ChainingError> {
    let raw = u8::try_from(value)
        .map_err(|_error| ChainingError::InvalidAlphabetSize { alphabet_size })?;
    TrigramValue::new(raw).map_err(|_raw| ChainingError::InvalidAlphabetSize { alphabet_size })
}

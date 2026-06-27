//! Compute core for the Experiment 5A periodicity battery.
//!
//! Report assembly + same-shape uniform-random nulls plus the IoC-by-period,
//! autocorrelation, and Kasiski primitives, split out of the battery body.

use std::collections::BTreeMap;

use crate::analysis::analysis;
use crate::analysis::orders::{
    ReadingOrder, count_message_lag_comparisons, count_message_lag_matches,
    glyph_messages_from_values,
};
use crate::core::glyph::Glyph;
use crate::core::trigram::TrigramValue;
use crate::nulls::null::{SplitMix64, f64_band};

use super::{
    AutocorrelationRow, KasiskiReport, MessagePeriodicityReport, NullBand, PeriodIocRow,
    PeriodicityConfig, PeriodicityError, PeriodicityReport,
};

const TOP_KASISKI_ITEMS: usize = 12;

pub(super) fn report_from_message_values(
    config: PeriodicityConfig,
    order: ReadingOrder,
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
) -> Result<PeriodicityReport, PeriodicityError> {
    validate_config(config)?;

    let lengths: Vec<usize> = message_values.iter().map(Vec::len).collect();
    let null = build_null_summary(config, &lengths)?;

    let pooled_length = lengths.iter().sum();
    let pooled_period_values =
        normalized_ioc_by_period_values(message_values, config.max_period, config.alphabet_size);
    let pooled_ioc_by_period = build_period_rows(
        &pooled_period_values,
        &null.pooled_ioc,
        null.global_ioc_envelope_max,
        config.alphabet_size,
    );
    let pooled_autocorrelation_values = autocorrelation_values(message_values, config.max_lag);
    let pooled_autocorrelation = build_autocorrelation_rows(
        message_values,
        &pooled_autocorrelation_values,
        &null.pooled_autocorrelation,
        null.global_autocorrelation_envelope_max,
        config.alphabet_size,
    );
    let pooled_kasiski = kasiski_reports_for_messages(
        message_values,
        config.min_ngram,
        config.max_ngram,
        config.max_period,
    );

    let mut messages = Vec::new();
    for ((key, values), message_null) in keys
        .iter()
        .copied()
        .zip(message_values)
        .zip(null.messages.iter())
    {
        let one_message = [values.clone()];
        let period_values =
            normalized_ioc_by_period_values(&one_message, config.max_period, config.alphabet_size);
        let ioc_by_period = build_period_rows(
            &period_values,
            &message_null.ioc,
            null.global_ioc_envelope_max,
            config.alphabet_size,
        );
        let autocorrelation_values = autocorrelation_values(&one_message, config.max_lag);
        let autocorrelation = build_autocorrelation_rows(
            &one_message,
            &autocorrelation_values,
            &message_null.autocorrelation,
            null.global_autocorrelation_envelope_max,
            config.alphabet_size,
        );
        let kasiski = kasiski_reports_for_messages(
            &one_message,
            config.min_ngram,
            config.max_ngram,
            config.max_period,
        );
        messages.push(MessagePeriodicityReport {
            message_key: key,
            length: values.len(),
            period_null_envelope_max: null.global_ioc_envelope_max,
            autocorrelation_null_envelope_max: null.global_autocorrelation_envelope_max,
            ioc_by_period,
            autocorrelation,
            kasiski,
        });
    }

    Ok(PeriodicityReport {
        config,
        order,
        message_lengths: keys.iter().copied().zip(lengths).collect(),
        pooled_length,
        period_null_envelope_max: null.global_ioc_envelope_max,
        autocorrelation_null_envelope_max: null.global_autocorrelation_envelope_max,
        pooled_ioc_by_period,
        pooled_autocorrelation,
        pooled_kasiski,
        messages,
    })
}

pub(super) fn validate_config(config: PeriodicityConfig) -> Result<(), PeriodicityError> {
    if config.trials == 0 {
        return Err(PeriodicityError::ZeroTrials);
    }
    if config.max_period == 0 {
        return Err(PeriodicityError::ZeroMaxPeriod);
    }
    if config.max_lag == 0 {
        return Err(PeriodicityError::ZeroMaxLag);
    }
    if config.min_ngram == 0 || config.min_ngram > config.max_ngram {
        return Err(PeriodicityError::InvalidNgramRange {
            min: config.min_ngram,
            max: config.max_ngram,
        });
    }
    if config.alphabet_size == 0 || config.alphabet_size > 125 {
        return Err(PeriodicityError::InvalidAlphabetSize {
            alphabet_size: config.alphabet_size,
        });
    }
    Ok(())
}

#[derive(Debug)]
struct NullSummary {
    pooled_ioc: Vec<NullBand>,
    pooled_autocorrelation: Vec<NullBand>,
    global_ioc_envelope_max: f64,
    global_autocorrelation_envelope_max: f64,
    messages: Vec<MessageNullSummary>,
}

#[derive(Debug)]
struct MessageNullSummary {
    ioc: Vec<NullBand>,
    autocorrelation: Vec<NullBand>,
}

fn build_null_summary(
    config: PeriodicityConfig,
    lengths: &[usize],
) -> Result<NullSummary, PeriodicityError> {
    let mut rng = SplitMix64::new(config.seed);
    let mut pooled_ioc_samples = ProfileSamples::new(config.max_period);
    let mut pooled_autocorrelation_samples = ProfileSamples::new(config.max_lag);
    let mut global_ioc_maxima = Vec::new();
    let mut global_autocorrelation_maxima = Vec::new();
    let mut message_ioc_samples: Vec<ProfileSamples> = lengths
        .iter()
        .map(|_length| ProfileSamples::new(config.max_period))
        .collect();
    let mut message_autocorrelation_samples: Vec<ProfileSamples> = lengths
        .iter()
        .map(|_length| ProfileSamples::new(config.max_lag))
        .collect();

    for _trial in 0..config.trials {
        let generated = random_message_values_like(lengths, &mut rng, config.alphabet_size)?;
        let pooled_ioc_profile =
            normalized_ioc_by_period_values(&generated, config.max_period, config.alphabet_size);
        let pooled_autocorrelation_profile = autocorrelation_values(&generated, config.max_lag);
        let mut global_ioc_maximum = profile_maximum(&pooled_ioc_profile);
        let mut global_autocorrelation_maximum = profile_maximum(&pooled_autocorrelation_profile);

        pooled_ioc_samples.push_profile(&pooled_ioc_profile);
        pooled_autocorrelation_samples.push_profile(&pooled_autocorrelation_profile);

        for ((values, ioc_samples), autocorrelation_samples) in generated
            .iter()
            .zip(message_ioc_samples.iter_mut())
            .zip(message_autocorrelation_samples.iter_mut())
        {
            let one_message = [values.clone()];
            let ioc_profile = normalized_ioc_by_period_values(
                &one_message,
                config.max_period,
                config.alphabet_size,
            );
            let autocorrelation_profile = autocorrelation_values(&one_message, config.max_lag);
            global_ioc_maximum = global_ioc_maximum.max(profile_maximum(&ioc_profile));
            global_autocorrelation_maximum =
                global_autocorrelation_maximum.max(profile_maximum(&autocorrelation_profile));
            ioc_samples.push_profile(&ioc_profile);
            autocorrelation_samples.push_profile(&autocorrelation_profile);
        }
        global_ioc_maxima.push(global_ioc_maximum);
        global_autocorrelation_maxima.push(global_autocorrelation_maximum);
    }

    let messages = message_ioc_samples
        .into_iter()
        .zip(message_autocorrelation_samples)
        .map(|(ioc, autocorrelation)| MessageNullSummary {
            ioc: ioc.bands(),
            autocorrelation: autocorrelation.bands(),
        })
        .collect();

    Ok(NullSummary {
        pooled_ioc: pooled_ioc_samples.bands(),
        pooled_autocorrelation: pooled_autocorrelation_samples.bands(),
        global_ioc_envelope_max: sample_maximum(&global_ioc_maxima),
        global_autocorrelation_envelope_max: sample_maximum(&global_autocorrelation_maxima),
        messages,
    })
}

/// Largest value in `samples` under a [`f64::total_cmp`] sort (`0.0` when empty).
///
/// Reproduces the `max` quantile that the removed `quantile_from_samples` used
/// for the report-wide null envelope.
fn sample_maximum(samples: &[f64]) -> f64 {
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    sorted.last().copied().unwrap_or(0.0)
}

fn profile_maximum(values: &[f64]) -> f64 {
    values.iter().copied().fold(0.0, f64::max)
}

#[derive(Debug)]
struct ProfileSamples {
    per_row: Vec<Vec<f64>>,
}

impl ProfileSamples {
    fn new(rows: usize) -> Self {
        Self {
            per_row: vec![Vec::new(); rows],
        }
    }

    fn push_profile(&mut self, values: &[f64]) {
        for (slot, &value) in self.per_row.iter_mut().zip(values) {
            slot.push(value);
        }
    }

    fn bands(&self) -> Vec<NullBand> {
        self.per_row
            .iter()
            .map(|samples| NullBand::from(f64_band(samples)))
            .collect()
    }
}

fn random_message_values_like(
    lengths: &[usize],
    rng: &mut SplitMix64,
    alphabet_size: usize,
) -> Result<Vec<Vec<TrigramValue>>, PeriodicityError> {
    let mut messages = Vec::new();
    let alphabet_size_u64 = alphabet_size as u64;
    for &length in lengths {
        let mut values = Vec::with_capacity(length);
        for _position in 0..length {
            let raw = rng.next_u64() % alphabet_size_u64;
            let value = TrigramValue::new(raw as u8)
                .map_err(|_raw| PeriodicityError::InvalidAlphabetSize { alphabet_size })?;
            values.push(value);
        }
        messages.push(values);
    }
    Ok(messages)
}

fn build_period_rows(
    normalized_ioc_values: &[f64],
    null_bands: &[NullBand],
    null_envelope_max: f64,
    alphabet_size: usize,
) -> Vec<PeriodIocRow> {
    normalized_ioc_values
        .iter()
        .copied()
        .enumerate()
        .zip(null_bands.iter().copied())
        .map(|((index, normalized_ioc), null_band)| {
            let period = index + 1;
            PeriodIocRow {
                period,
                mean_ioc: normalized_ioc / alphabet_size as f64,
                normalized_ioc,
                null_band,
                above_pointwise_band: normalized_ioc > null_band.q975,
                above_null_envelope: normalized_ioc > null_envelope_max,
            }
        })
        .collect()
}

fn build_autocorrelation_rows(
    message_values: &[Vec<TrigramValue>],
    rates: &[f64],
    null_bands: &[NullBand],
    null_envelope_max: f64,
    alphabet_size: usize,
) -> Vec<AutocorrelationRow> {
    rates
        .iter()
        .copied()
        .enumerate()
        .zip(null_bands.iter().copied())
        .map(|((index, rate), null_band)| {
            let lag = index + 1;
            let matches = count_message_lag_matches(message_values, lag);
            let comparisons = count_message_lag_comparisons(message_values, lag);
            AutocorrelationRow {
                lag,
                matches,
                comparisons,
                rate,
                normalized_rate: rate * alphabet_size as f64,
                null_band,
                above_pointwise_band: rate > null_band.q975,
                above_null_envelope: rate > null_envelope_max,
            }
        })
        .collect()
}

/// Computes normalized mean column `IoC` values for candidate periods.
///
/// Message boundaries reset the period column counter: column `0` in one
/// message is never joined to column `0` in another before computing a column
/// `IoC`. Each returned value is multiplied by `alphabet_size`, so an
/// independent uniform stream is expected near `1.0`.
#[must_use]
pub fn normalized_ioc_by_period_values(
    message_values: &[Vec<TrigramValue>],
    max_period: usize,
    alphabet_size: usize,
) -> Vec<f64> {
    let message_glyphs = glyph_messages_from_values(message_values);
    (1..=max_period)
        .map(|period| mean_column_ioc(&message_glyphs, period) * alphabet_size as f64)
        .collect()
}

fn mean_column_ioc(message_glyphs: &[Vec<Glyph>], period: usize) -> f64 {
    if period == 0 {
        return 0.0;
    }
    let mut ioc_total = 0.0;
    let mut column_count = 0usize;
    for glyphs in message_glyphs {
        let mut columns = vec![Vec::new(); period];
        for (position, &glyph) in glyphs.iter().enumerate() {
            let column = position % period;
            if let Some(values) = columns.get_mut(column) {
                values.push(glyph);
            }
        }
        ioc_total += columns
            .iter()
            .map(|column| analysis::index_of_coincidence(column))
            .sum::<f64>();
        column_count += period;
    }
    if column_count == 0 {
        0.0
    } else {
        ioc_total / column_count as f64
    }
}

/// Computes exact-symbol autocorrelation rates for lags `1..=max_lag`.
///
/// Message boundaries are preserved: a lag pair is counted only when both
/// positions are inside the same message.
#[must_use]
pub fn autocorrelation_values(message_values: &[Vec<TrigramValue>], max_lag: usize) -> Vec<f64> {
    (1..=max_lag)
        .map(|lag| {
            let comparisons = count_message_lag_comparisons(message_values, lag);
            if comparisons == 0 {
                0.0
            } else {
                count_message_lag_matches(message_values, lag) as f64 / comparisons as f64
            }
        })
        .collect()
}

fn kasiski_reports_for_messages(
    message_values: &[Vec<TrigramValue>],
    min_ngram: usize,
    max_ngram: usize,
    max_factor: usize,
) -> Vec<KasiskiReport> {
    (min_ngram..=max_ngram)
        .map(|n| kasiski_report_for_messages(message_values, n, max_factor))
        .collect()
}

pub(super) fn kasiski_report_for_messages(
    message_values: &[Vec<TrigramValue>],
    n: usize,
    max_factor: usize,
) -> KasiskiReport {
    let mut repeated_ngram_kinds = 0;
    let mut repeated_occurrences = 0;
    let mut distances = Vec::new();
    let mut ngram_gcd_counts = BTreeMap::new();

    for values in message_values {
        let partial = kasiski_distances_for_values(values, n);
        repeated_ngram_kinds += partial.repeated_ngram_kinds;
        repeated_occurrences += partial.repeated_occurrences;
        for gcd in partial.ngram_gcds {
            *ngram_gcd_counts.entry(gcd).or_default() += 1;
        }
        distances.extend(partial.distances);
    }

    let distance_count = distances.len();
    let all_distance_gcd = gcd_all(distances.iter().copied());
    let top_distances = top_histogram_items(&histogram_usize(&distances), TOP_KASISKI_ITEMS);
    let ngram_gcd_histogram = top_histogram_items(&ngram_gcd_counts, TOP_KASISKI_ITEMS);
    let factor_counts = factor_counts(&distances, max_factor);

    KasiskiReport {
        n,
        repeated_ngram_kinds,
        repeated_occurrences,
        distance_count,
        all_distance_gcd,
        top_distances,
        ngram_gcd_histogram,
        factor_counts,
    }
}

#[derive(Debug)]
struct KasiskiDistances {
    repeated_ngram_kinds: usize,
    repeated_occurrences: usize,
    distances: Vec<usize>,
    ngram_gcds: Vec<usize>,
}

fn kasiski_distances_for_values(values: &[TrigramValue], n: usize) -> KasiskiDistances {
    let mut occurrences: BTreeMap<Vec<u8>, Vec<usize>> = BTreeMap::new();
    if n == 0 || n > values.len() {
        return KasiskiDistances {
            repeated_ngram_kinds: 0,
            repeated_occurrences: 0,
            distances: Vec::new(),
            ngram_gcds: Vec::new(),
        };
    }

    for (position, window) in values.windows(n).enumerate() {
        let key = window.iter().map(|value| value.get()).collect();
        occurrences.entry(key).or_default().push(position);
    }

    let mut repeated_ngram_kinds = 0;
    let mut repeated_occurrences = 0;
    let mut distances = Vec::new();
    let mut ngram_gcds = Vec::new();

    for positions in occurrences.values() {
        if positions.len() < 2 {
            continue;
        }
        repeated_ngram_kinds += 1;
        repeated_occurrences += positions.len();

        let mut local_distances = Vec::new();
        for (left_index, &left) in positions.iter().enumerate() {
            for &right in positions.iter().skip(left_index + 1) {
                let distance = right.saturating_sub(left);
                if distance > 0 {
                    distances.push(distance);
                    local_distances.push(distance);
                }
            }
        }
        let local_gcd = gcd_all(local_distances);
        if local_gcd > 0 {
            ngram_gcds.push(local_gcd);
        }
    }

    KasiskiDistances {
        repeated_ngram_kinds,
        repeated_occurrences,
        distances,
        ngram_gcds,
    }
}

fn factor_counts(distances: &[usize], max_factor: usize) -> Vec<(usize, usize)> {
    (2..=max_factor)
        .map(|factor| {
            let count = distances
                .iter()
                .filter(|&&distance| distance.is_multiple_of(factor))
                .count();
            (factor, count)
        })
        .collect()
}

fn histogram_usize(values: &[usize]) -> BTreeMap<usize, usize> {
    let mut counts = BTreeMap::new();
    for &value in values {
        *counts.entry(value).or_default() += 1;
    }
    counts
}

fn top_histogram_items(histogram: &BTreeMap<usize, usize>, limit: usize) -> Vec<(usize, usize)> {
    let mut items: Vec<(usize, usize)> = histogram
        .iter()
        .map(|(&value, &count)| (value, count))
        .collect();
    items.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    items.truncate(limit);
    items
}

fn gcd_all(values: impl IntoIterator<Item = usize>) -> usize {
    let mut current = 0;
    for value in values {
        current = if current == 0 {
            value
        } else {
            gcd(current, value)
        };
    }
    current
}

fn gcd(mut left: usize, mut right: usize) -> usize {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

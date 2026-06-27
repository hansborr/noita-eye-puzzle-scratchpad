//! Modular finite-difference computation and report assembly.
//!
//! The per-message finite-difference transform, the per-modulus report
//! builder, and the differenced-stream summary primitives, split out of the
//! modular-difference body.

use crate::analysis::analysis;
use crate::analysis::orders::{
    ReadingOrder, count_message_lag_comparisons, count_message_lag_matches,
    glyph_messages_from_values,
};
use crate::core::trigram::TrigramValue;
use crate::experiments::periodicity;

use super::calibration::{calibrate_controls, shuffle_baseline};
use super::{
    DifferenceOrderReport, DifferenceStats, FamilyPlacement, LagAutocorrelation,
    MAX_DIFFERENCE_ORDER, ModularDiffConfig, ModularDiffError, ModularDiffReport, ModulusReport,
    PRIMARY_MODULUS, PeriodIoc, SECONDARY_MODULUS, ValuePeak, max_f64, trigram_from_usize,
};

/// Computes a per-message modular finite-difference transform.
///
/// `difference_order == 0` returns the input stream after validating that every
/// value is inside `0..modulus`. Higher orders repeatedly apply
/// `(current[i] - current[i - 1]) mod modulus` inside each message. No pair is
/// formed across message boundaries.
///
/// # Errors
/// Returns [`ModularDiffError`] if `modulus` is not representable by
/// [`TrigramValue`] or if any source value is outside the modulus.
pub fn modular_difference_messages(
    message_values: &[Vec<TrigramValue>],
    difference_order: usize,
    modulus: usize,
) -> Result<Vec<Vec<TrigramValue>>, ModularDiffError> {
    validate_modulus(modulus)?;
    validate_values_inside_modulus(message_values, modulus)?;

    let mut current = message_values.to_vec();
    for _order in 0..difference_order {
        current = first_difference_messages(&current, modulus)?;
    }
    Ok(current)
}

pub(super) fn report_from_message_values(
    config: ModularDiffConfig,
    order: ReadingOrder,
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
) -> Result<ModularDiffReport, ModularDiffError> {
    validate_config(config)?;
    let lengths = message_values.iter().map(Vec::len).collect::<Vec<_>>();
    let total_length = lengths.iter().sum();
    let primary = build_modulus_report(config, message_values, PRIMARY_MODULUS, true)?;
    let secondary = build_modulus_report(config, message_values, SECONDARY_MODULUS, false)?;
    let controls = calibrate_controls(config, &lengths, &primary.differences)?;
    let headline_placement = controls
        .iter()
        .find(|report| report.difference_order == 1)
        .map_or(FamilyPlacement::Uncalibrated, |report| report.eye_placement);

    Ok(ModularDiffReport {
        config,
        order,
        message_lengths: keys.iter().copied().zip(lengths).collect(),
        total_length,
        primary,
        secondary,
        controls,
        headline_placement,
    })
}

pub(super) fn validate_config(config: ModularDiffConfig) -> Result<(), ModularDiffError> {
    if config.trials == 0 {
        return Err(ModularDiffError::ZeroTrials);
    }
    if config.max_period == 0 {
        return Err(ModularDiffError::ZeroMaxPeriod);
    }
    if config.max_lag == 0 {
        return Err(ModularDiffError::ZeroMaxLag);
    }
    Ok(())
}

fn validate_modulus(modulus: usize) -> Result<(), ModularDiffError> {
    if modulus == 0 || modulus > SECONDARY_MODULUS {
        return Err(ModularDiffError::InvalidModulus { modulus });
    }
    Ok(())
}

fn validate_values_inside_modulus(
    message_values: &[Vec<TrigramValue>],
    modulus: usize,
) -> Result<(), ModularDiffError> {
    for values in message_values {
        for value in values {
            if usize::from(value.get()) >= modulus {
                return Err(ModularDiffError::ValueOutsideModulus {
                    value: value.get(),
                    modulus,
                });
            }
        }
    }
    Ok(())
}

fn build_modulus_report(
    config: ModularDiffConfig,
    message_values: &[Vec<TrigramValue>],
    modulus: usize,
    headline: bool,
) -> Result<ModulusReport, ModularDiffError> {
    validate_values_inside_modulus(message_values, modulus)?;
    let raw_ioc = message_weighted_ioc_values(message_values);
    let mut rows = Vec::new();
    for difference_order in 1..=MAX_DIFFERENCE_ORDER {
        let diff_values = modular_difference_messages(message_values, difference_order, modulus)?;
        let stats = summarize_difference_stream(
            &diff_values,
            raw_ioc,
            modulus,
            difference_order,
            config.max_period,
            config.max_lag,
        )?;
        let shuffle_baseline =
            shuffle_baseline(config, message_values, raw_ioc, modulus, difference_order)?;
        rows.push(DifferenceOrderReport {
            difference_order,
            stats,
            shuffle_baseline,
        });
    }
    Ok(ModulusReport {
        modulus,
        headline,
        raw_ioc,
        differences: rows,
    })
}

fn first_difference_messages(
    message_values: &[Vec<TrigramValue>],
    modulus: usize,
) -> Result<Vec<Vec<TrigramValue>>, ModularDiffError> {
    let mut differenced = Vec::with_capacity(message_values.len());
    for values in message_values {
        let mut message = Vec::with_capacity(values.len().saturating_sub(1));
        for pair in values.windows(2) {
            let [previous, current] = pair else {
                continue;
            };
            let raw =
                (usize::from(current.get()) + modulus - usize::from(previous.get())) % modulus;
            message.push(trigram_from_usize(raw, modulus)?);
        }
        differenced.push(message);
    }
    Ok(differenced)
}

pub(super) fn summarize_difference_stream(
    message_values: &[Vec<TrigramValue>],
    raw_ioc: f64,
    modulus: usize,
    difference_order: usize,
    max_period: usize,
    max_lag: usize,
) -> Result<DifferenceStats, ModularDiffError> {
    validate_values_inside_modulus(message_values, modulus)?;
    let counts = counts_for_messages(message_values, modulus)?;
    let length = counts.iter().sum();
    let distinct_support_size = counts.iter().filter(|count| **count > 0).count();
    let ioc = message_weighted_ioc_values(message_values);
    let normalized_ioc = ioc * modulus as f64;
    let chi_square_uniform = analysis::chi_square_goodness_of_fit_uniform(&counts);
    let chi_square_upper_tail_p_value =
        analysis::chi_square_upper_tail_p_value(chi_square_uniform, modulus.saturating_sub(1));
    let top_difference = top_value_peak(&counts, length, modulus);
    let period_ioc = period_ioc_rows(message_values, max_period, modulus);
    let best_period_ioc = period_ioc
        .iter()
        .copied()
        .max_by(|left, right| left.normalized_ioc.total_cmp(&right.normalized_ioc));
    let period_baseline_normalized_ioc = period_ioc
        .iter()
        .find(|row| row.period == 1)
        .map_or(normalized_ioc, |row| row.normalized_ioc);
    let best_period_normalized_ioc = best_period_ioc.map_or(0.0, |row| row.normalized_ioc);
    let period_excess = (best_period_normalized_ioc - period_baseline_normalized_ioc).max(0.0);
    let autocorrelation = autocorrelation_rows(message_values, max_lag, modulus);
    let best_autocorrelation = autocorrelation
        .iter()
        .copied()
        .max_by(|left, right| left.normalized_rate.total_cmp(&right.normalized_rate));
    let best_lag_normalized_rate = best_autocorrelation.map_or(0.0, |row| row.normalized_rate);
    let structure_score = max_f64([
        top_difference.over_uniform,
        normalized_ioc,
        best_period_normalized_ioc,
        best_lag_normalized_rate,
    ]);

    Ok(DifferenceStats {
        modulus,
        difference_order,
        length,
        raw_ioc,
        ioc,
        normalized_ioc,
        delta_ioc: ioc - raw_ioc,
        chi_square_uniform,
        chi_square_upper_tail_p_value,
        distinct_support_size,
        top_difference,
        period_ioc,
        best_period_ioc,
        period_excess,
        autocorrelation,
        best_autocorrelation,
        structure_score,
    })
}

fn counts_for_messages(
    message_values: &[Vec<TrigramValue>],
    modulus: usize,
) -> Result<Vec<usize>, ModularDiffError> {
    let mut counts = vec![0usize; modulus];
    for values in message_values {
        for value in values {
            let raw = usize::from(value.get());
            let Some(count) = counts.get_mut(raw) else {
                return Err(ModularDiffError::ValueOutsideModulus {
                    value: value.get(),
                    modulus,
                });
            };
            *count += 1;
        }
    }
    Ok(counts)
}

fn top_value_peak(counts: &[usize], length: usize, modulus: usize) -> ValuePeak {
    let mut peak_value = 0usize;
    let mut peak_count = 0usize;
    for (value, &count) in counts.iter().enumerate() {
        if count > peak_count {
            peak_value = value;
            peak_count = count;
        }
    }
    let rate = if length == 0 {
        0.0
    } else {
        peak_count as f64 / length as f64
    };
    ValuePeak {
        value: u8::try_from(peak_value).unwrap_or_default(),
        count: peak_count,
        rate,
        over_uniform: rate * modulus as f64,
    }
}

fn period_ioc_rows(
    message_values: &[Vec<TrigramValue>],
    max_period: usize,
    modulus: usize,
) -> Vec<PeriodIoc> {
    periodicity::normalized_ioc_by_period_values(message_values, max_period, modulus)
        .into_iter()
        .enumerate()
        .map(|(index, normalized_ioc)| PeriodIoc {
            period: index + 1,
            mean_ioc: normalized_ioc / modulus as f64,
            normalized_ioc,
        })
        .collect()
}

fn autocorrelation_rows(
    message_values: &[Vec<TrigramValue>],
    max_lag: usize,
    modulus: usize,
) -> Vec<LagAutocorrelation> {
    periodicity::autocorrelation_values(message_values, max_lag)
        .into_iter()
        .enumerate()
        .map(|(index, rate)| {
            let lag = index + 1;
            LagAutocorrelation {
                lag,
                matches: count_message_lag_matches(message_values, lag),
                comparisons: count_message_lag_comparisons(message_values, lag),
                rate,
                normalized_rate: rate * modulus as f64,
            }
        })
        .collect()
}

pub(super) fn message_weighted_ioc_values(message_values: &[Vec<TrigramValue>]) -> f64 {
    let message_glyphs = glyph_messages_from_values(message_values);
    analysis::message_weighted_index_of_coincidence(&message_glyphs)
}

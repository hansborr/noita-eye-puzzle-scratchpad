//! Experiment 8 compute core: orientation/storage grouping, natural-language
//! reference rows, the collision state-count estimator, and the deterministic
//! synthetic calibration fixtures.

use super::{
    CollisionStateEstimate, CompatibilityReport, DEFAULT_STATE_MAX_WINDOW,
    DEFAULT_STATE_MIN_WINDOW, GroupingAxis, GroupingCompatibility, GroupingError, GroupingRow,
    IsomorphStateRow, LANGUAGE_ALPHABET_SPAN_DIVISOR, LanguageReference,
    MIN_LANGUAGE_ENTROPY_TOLERANCE_BITS, MessageGroupingStats, ORIENTATION_BASE,
    StateCalibrationRow, StateCountEstimateReport, StateCountRange, SymbolStats,
};
use crate::analysis::analysis;
use crate::analysis::isomorph;
use crate::analysis::orders::{self, ReadingOrder};
use crate::attack::language::{self, LanguageModel};
use crate::core::glyph::{Glyph, Orientation};
use crate::core::trigram::{TrigramValue, base5_digits};
use crate::data::generator::{self, ENGINE_MESSAGES};
use crate::nulls::null::{SplitMix64, random_index_below};

pub(super) fn grouping_rows(
    keys: &[&'static str],
    orientation_messages: &[Vec<Orientation>],
) -> Result<Vec<GroupingRow>, GroupingError> {
    let mut rows = Vec::new();
    for width in 1..=4 {
        let (glyph_messages, dropped) = group_orientation_messages(orientation_messages, width);
        rows.push(grouping_row(
            GroupingAxis::OrientationBase5 { width },
            keys,
            &glyph_messages,
            &dropped,
        ));
    }
    let (storage_messages, storage_dropped) = storage_messages()?;
    rows.push(grouping_row(
        GroupingAxis::EngineStorageBase7,
        keys,
        &storage_messages,
        &storage_dropped,
    ));
    Ok(rows)
}

fn grouping_row(
    axis: GroupingAxis,
    keys: &[&'static str],
    glyph_messages: &[Vec<Glyph>],
    dropped: &[usize],
) -> GroupingRow {
    let pooled_glyphs = flatten_messages(glyph_messages);
    let pooled = SymbolStats::from_glyphs(&pooled_glyphs);
    let messages = keys
        .iter()
        .copied()
        .zip(glyph_messages)
        .zip(dropped.iter().copied())
        .map(
            |((message_key, glyphs), dropped_source_symbols)| MessageGroupingStats {
                message_key,
                dropped_source_symbols,
                stats: SymbolStats::from_glyphs(glyphs),
            },
        )
        .collect::<Vec<_>>();

    GroupingRow {
        axis,
        dropped_source_symbols: dropped.iter().sum(),
        pooled,
        message_weighted_entropy_bits_per_symbol: analysis::message_weighted_entropy(
            glyph_messages,
        ),
        message_weighted_normalized_entropy: message_weighted_normalized_entropy(glyph_messages),
        message_weighted_ioc: analysis::message_weighted_index_of_coincidence(glyph_messages),
        messages,
    }
}

pub(super) fn orientation_messages_from_values(
    message_values: &[Vec<TrigramValue>],
) -> Vec<Vec<Orientation>> {
    message_values
        .iter()
        .map(|values| {
            values
                .iter()
                .copied()
                .flat_map(orientations_from_trigram_value)
                .collect()
        })
        .collect()
}

fn orientations_from_trigram_value(value: TrigramValue) -> [Orientation; 3] {
    let [first, second, third] = base5_digits(value.get());
    [
        Orientation::from_base5_digit(first),
        Orientation::from_base5_digit(second),
        Orientation::from_base5_digit(third),
    ]
}

fn group_orientation_messages(
    orientation_messages: &[Vec<Orientation>],
    width: usize,
) -> (Vec<Vec<Glyph>>, Vec<usize>) {
    let mut grouped_messages = Vec::new();
    let mut dropped = Vec::new();
    for orientations in orientation_messages {
        let mut glyphs = Vec::new();
        for chunk in orientations.chunks_exact(width) {
            glyphs.push(Glyph(group_value(chunk)));
        }
        dropped.push(orientations.len() % width);
        grouped_messages.push(glyphs);
    }
    (grouped_messages, dropped)
}

fn group_value(chunk: &[Orientation]) -> u16 {
    chunk.iter().fold(0u16, |accumulator, orientation| {
        accumulator * ORIENTATION_BASE as u16 + u16::from(orientation.digit())
    })
}

fn storage_messages() -> Result<(Vec<Vec<Glyph>>, Vec<usize>), GroupingError> {
    let mut messages = Vec::new();
    for (message_index, pairs) in ENGINE_MESSAGES.iter().enumerate() {
        let mut glyphs = Vec::new();
        for symbol in generator::decode_message(pairs) {
            if generator::storage_orientation(symbol).is_some() || symbol == 5 {
                let glyph_index = u16::try_from(symbol).map_err(|_error| {
                    GroupingError::InvalidStorageSymbol {
                        message_index,
                        symbol,
                    }
                })?;
                glyphs.push(Glyph(glyph_index));
            } else {
                return Err(GroupingError::InvalidStorageSymbol {
                    message_index,
                    symbol,
                });
            }
        }
        messages.push(glyphs);
    }
    Ok((messages, vec![0; ENGINE_MESSAGES.len()]))
}

pub(super) fn language_references() -> Result<Vec<LanguageReference>, GroupingError> {
    Ok(vec![
        language_reference("English", 26, &language::english_model()?)?,
        language_reference("Finnish", 29, &language::finnish_model()?)?,
    ])
}

fn language_reference(
    language: &'static str,
    nominal_alphabet: usize,
    model: &LanguageModel,
) -> Result<LanguageReference, GroupingError> {
    let mut glyphs = Vec::new();
    for index in 0..model.alphabet().len() {
        let count = model.unigram_count(index)?;
        for _occurrence in 0..count {
            glyphs.push(Glyph(index as u16));
        }
    }
    let stats = SymbolStats::from_glyphs(&glyphs);
    Ok(LanguageReference {
        language,
        nominal_alphabet,
        observed_used_alphabet: stats.used_alphabet,
        symbols: stats.symbols,
        entropy_bits_per_symbol: stats.entropy_bits_per_symbol,
        normalized_entropy: stats.normalized_entropy,
        ioc: stats.ioc,
        collision_effective_alphabet: stats.collision_effective_alphabet,
    })
}

pub(super) fn compatibility_report(
    groupings: &[GroupingRow],
    references: &[LanguageReference],
) -> CompatibilityReport {
    let min_nominal = references
        .iter()
        .map(|reference| reference.nominal_alphabet)
        .min()
        .unwrap_or_default();
    let max_nominal = references
        .iter()
        .map(|reference| reference.nominal_alphabet)
        .max()
        .unwrap_or_default();
    let span = max_nominal.saturating_sub(min_nominal);
    let alphabet_tolerance = usize::max(1, span / LANGUAGE_ALPHABET_SPAN_DIVISOR);
    let alphabet_min = min_nominal.saturating_sub(alphabet_tolerance);
    let alphabet_max = max_nominal.saturating_add(alphabet_tolerance);

    let entropy_low = references
        .iter()
        .map(|reference| reference.entropy_bits_per_symbol)
        .min_by(f64::total_cmp)
        .unwrap_or(0.0);
    let entropy_high = references
        .iter()
        .map(|reference| reference.entropy_bits_per_symbol)
        .max_by(f64::total_cmp)
        .unwrap_or(0.0);
    let entropy_tolerance = f64::max(
        entropy_high - entropy_low,
        MIN_LANGUAGE_ENTROPY_TOLERANCE_BITS,
    );
    let entropy_min = (entropy_low - entropy_tolerance).max(0.0);
    let entropy_max = entropy_high + entropy_tolerance;

    let nearest_alphabet_grouping = groupings
        .iter()
        .min_by_key(|row| nearest_reference_gap(row.pooled.used_alphabet, references))
        .map_or_else(|| "none".to_owned(), |row| row.axis.label());
    let rows = groupings
        .iter()
        .map(|row| GroupingCompatibility {
            grouping_label: row.axis.label(),
            alphabet_compatible: (alphabet_min..=alphabet_max).contains(&row.pooled.used_alphabet),
            entropy_compatible: (entropy_min..=entropy_max)
                .contains(&row.pooled.entropy_bits_per_symbol),
        })
        .collect();

    CompatibilityReport {
        alphabet_min,
        alphabet_max,
        entropy_min,
        entropy_max,
        nearest_alphabet_grouping,
        rows,
    }
}

fn nearest_reference_gap(value: usize, references: &[LanguageReference]) -> usize {
    references
        .iter()
        .map(|reference| value.abs_diff(reference.nominal_alphabet))
        .min()
        .unwrap_or(usize::MAX)
}

pub(super) fn state_count_estimate(
    order: ReadingOrder,
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    calibration_relative_margin: f64,
) -> Result<StateCountEstimateReport, GroupingError> {
    let glyph_messages = orders::glyph_messages_from_values(message_values);
    let message_lengths = keys
        .iter()
        .copied()
        .zip(message_values.iter().map(Vec::len))
        .collect::<Vec<_>>();
    let collision = collision_state_estimate(&glyph_messages);
    let isomorph_rows = isomorph_state_rows(
        &glyph_messages,
        DEFAULT_STATE_MIN_WINDOW,
        DEFAULT_STATE_MAX_WINDOW,
    )?;
    let longest_repeated_isomorph = longest_repeated_isomorph(&isomorph_rows);
    let range = estimate_range(&collision, calibration_relative_margin);

    Ok(StateCountEstimateReport {
        order,
        message_lengths,
        collision,
        isomorph_rows,
        longest_repeated_isomorph,
        range,
        calibration_relative_margin,
    })
}

fn collision_state_estimate(glyph_messages: &[Vec<Glyph>]) -> CollisionStateEstimate {
    let pooled = flatten_messages(glyph_messages);
    let pooled_ioc = analysis::index_of_coincidence(&pooled);
    let message_weighted_ioc = analysis::message_weighted_index_of_coincidence(glyph_messages);
    CollisionStateEstimate {
        pooled_ioc,
        pooled_effective_states: effective_alphabet_from_ioc(pooled_ioc),
        message_weighted_ioc,
        message_weighted_effective_states: effective_alphabet_from_ioc(message_weighted_ioc),
        pooled_entropy_bits_per_symbol: analysis::shannon_entropy(&pooled),
        collision_entropy_bits: collision_entropy_bits(pooled_ioc),
    }
}

fn estimate_range(
    collision: &CollisionStateEstimate,
    calibration_relative_margin: f64,
) -> StateCountRange {
    let low_point = f64::min(
        collision.pooled_effective_states,
        collision.message_weighted_effective_states,
    );
    let high_point = f64::max(
        collision.pooled_effective_states,
        collision.message_weighted_effective_states,
    );
    let lower = rounded_floor_state_count(low_point * (1.0 - calibration_relative_margin));
    let upper =
        rounded_ceil_state_count(high_point * (1.0 + calibration_relative_margin)).max(lower);
    StateCountRange {
        lower,
        upper,
        includes_83: (lower..=upper).contains(&orders::READING_LAYER_ALPHABET_SIZE),
    }
}

#[allow(
    clippy::cast_sign_loss,
    reason = "state-count report values are finite positive estimates clamped before display rounding"
)]
fn rounded_floor_state_count(value: f64) -> usize {
    if !value.is_finite() || value <= 1.0 {
        1
    } else {
        value.floor() as usize
    }
}

#[allow(
    clippy::cast_sign_loss,
    reason = "state-count report values are finite positive estimates clamped before display rounding"
)]
fn rounded_ceil_state_count(value: f64) -> usize {
    if !value.is_finite() || value <= 1.0 {
        1
    } else {
        value.ceil() as usize
    }
}

pub(super) fn calibration_row(
    true_states: usize,
    glyph_messages: &[Vec<Glyph>],
) -> Result<StateCalibrationRow, GroupingError> {
    let pooled = flatten_messages(glyph_messages);
    let stats = SymbolStats::from_glyphs(&pooled);
    let collision = collision_state_estimate(glyph_messages);
    let isomorph_rows = isomorph_state_rows(
        glyph_messages,
        DEFAULT_STATE_MIN_WINDOW,
        DEFAULT_STATE_MAX_WINDOW,
    )?;
    let longest_repeated_isomorph = longest_repeated_isomorph(&isomorph_rows);
    let relative_error = f64::max(
        relative_error(collision.pooled_effective_states, true_states),
        relative_error(collision.message_weighted_effective_states, true_states),
    );
    Ok(StateCalibrationRow {
        true_states,
        used_alphabet: stats.used_alphabet,
        pooled_ioc: collision.pooled_ioc,
        pooled_effective_states: collision.pooled_effective_states,
        message_weighted_effective_states: collision.message_weighted_effective_states,
        relative_error,
        longest_repeated_isomorph,
    })
}

fn isomorph_state_rows(
    glyph_messages: &[Vec<Glyph>],
    min_window: usize,
    max_window: usize,
) -> Result<Vec<IsomorphStateRow>, GroupingError> {
    let mut rows = Vec::new();
    for window in min_window..=max_window {
        let mut windows = 0usize;
        let mut informative_windows = 0usize;
        let mut repeated_signature_kinds = 0usize;
        let mut max_repeat_count = 0usize;
        for message in glyph_messages {
            if window > message.len() {
                continue;
            }
            windows += message.len() - window + 1;
            let detection = isomorph::detect_isomorphs(message, window, 1, 1)?;
            informative_windows += detection.informative_windows;
            repeated_signature_kinds += detection.repeated_signature_kinds();
            max_repeat_count = max_repeat_count.max(detection.max_repeat_count());
        }
        rows.push(IsomorphStateRow {
            window,
            windows,
            informative_windows,
            repeated_signature_kinds,
            max_repeat_count,
            birthday_effective_states: birthday_state_estimate(
                informative_windows,
                windows,
                window,
            ),
        });
    }
    Ok(rows)
}

fn birthday_state_estimate(
    informative_windows: usize,
    windows: usize,
    window: usize,
) -> Option<f64> {
    if windows == 0 || informative_windows == 0 {
        return None;
    }
    let repeat_rate = informative_windows as f64 / windows as f64;
    if repeat_rate >= 1.0 {
        return Some(window as f64);
    }

    let mut low = window as f64;
    let mut high = f64::max(low * 2.0, 2.0);
    while birthday_repeat_probability(high, window) > repeat_rate {
        high *= 2.0;
    }
    for _iteration in 0..80 {
        let midpoint = f64::midpoint(low, high);
        if birthday_repeat_probability(midpoint, window) > repeat_rate {
            low = midpoint;
        } else {
            high = midpoint;
        }
    }
    Some(high)
}

fn birthday_repeat_probability(states: f64, window: usize) -> f64 {
    if states <= 1.0 {
        return 1.0;
    }
    let mut unique_probability = 1.0;
    for offset in 0..window {
        let remaining = states - offset as f64;
        if remaining <= 0.0 {
            return 1.0;
        }
        unique_probability *= remaining / states;
    }
    1.0 - unique_probability
}

pub(super) fn synthetic_state_messages(
    message_lengths: &[usize],
    state_count: usize,
    rng: &mut SplitMix64,
) -> Result<Vec<Vec<Glyph>>, GroupingError> {
    if state_count == 0 {
        return Err(GroupingError::ZeroStateCount);
    }
    if state_count > usize::from(u16::MAX) + 1 {
        return Err(GroupingError::StateCountTooLarge { state_count });
    }

    let mut shifts = Vec::new();
    for _state in 0..state_count {
        shifts.push(random_index_below(state_count, rng)?);
    }

    let mut messages = Vec::new();
    for &length in message_lengths {
        let mut message = Vec::new();
        for position in 0..length {
            let plaintext = random_index_below(state_count, rng)?;
            let state = position % state_count;
            let shift = shifts
                .get(state)
                .copied()
                .ok_or(GroupingError::StateCountTooLarge { state_count })?;
            let symbol = (plaintext + shift) % state_count;
            let glyph = u16::try_from(symbol)
                .map(Glyph)
                .map_err(|_error| GroupingError::StateCountTooLarge { state_count })?;
            message.push(glyph);
        }
        messages.push(message);
    }
    Ok(messages)
}

fn flatten_messages(glyph_messages: &[Vec<Glyph>]) -> Vec<Glyph> {
    glyph_messages.iter().flatten().copied().collect()
}

/// Longest scanned window that still contains a repeated isomorph signature.
fn longest_repeated_isomorph(rows: &[IsomorphStateRow]) -> Option<usize> {
    rows.iter()
        .filter(|row| row.repeated_signature_kinds > 0)
        .map(|row| row.window)
        .max()
}

fn message_weighted_normalized_entropy(glyph_messages: &[Vec<Glyph>]) -> f64 {
    let mut weighted = 0.0;
    let mut total = 0usize;
    for glyphs in glyph_messages {
        let len = glyphs.len();
        if len == 0 {
            continue;
        }
        weighted += normalized_shannon_entropy(glyphs) * len as f64;
        total += len;
    }
    if total == 0 {
        0.0
    } else {
        weighted / total as f64
    }
}

/// Shannon entropy of `glyphs` normalized by `log2` of the number of distinct
/// glyphs observed. This is the same quantity as the per-message
/// `normalized_entropy` field, computed directly so the message-weighted
/// aggregate skips the index-of-coincidence pass that `from_glyphs` also runs.
fn normalized_shannon_entropy(glyphs: &[Glyph]) -> f64 {
    normalized_entropy(
        analysis::shannon_entropy(glyphs),
        analysis::frequencies(glyphs).len(),
    )
}

pub(super) fn normalized_entropy(entropy_bits: f64, used_alphabet: usize) -> f64 {
    if used_alphabet <= 1 {
        0.0
    } else {
        entropy_bits / (used_alphabet as f64).log2()
    }
}

pub(super) fn effective_alphabet_from_ioc(ioc: f64) -> f64 {
    if ioc <= 0.0 { f64::INFINITY } else { 1.0 / ioc }
}

fn collision_entropy_bits(ioc: f64) -> f64 {
    if ioc <= 0.0 {
        f64::INFINITY
    } else {
        -ioc.log2()
    }
}

fn relative_error(estimate: f64, true_states: usize) -> f64 {
    let true_value = true_states as f64;
    (estimate - true_value).abs() / true_value
}

pub(super) fn pow_usize(base: usize, exponent: usize) -> usize {
    let mut value = 1usize;
    for _power in 0..exponent {
        value = value.saturating_mul(base);
    }
    value
}

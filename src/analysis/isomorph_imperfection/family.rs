//! Generative imperfectly-isomorphic cipher family that calibrates the detector.
//!
//! Each synthetic message embeds one instance of an irregular motif whose
//! pre-break region is shared across messages: at epsilon = 0 every instance is a
//! perfect isomorph of the reference, so the only breaks are trailing-edge
//! Boundary divergences into disjoint filler. With probability epsilon a
//! non-reference instance has one interior repeat replaced by a fresh singleton,
//! producing the canonical internal violation (two-sided agreement, single-column
//! island, far resync carrying a cross-island back-reference). Mapping-independent
//! throughout. Extracted verbatim from the leaf module so `mod.rs` stays under the
//! file-size cap; the construction and every caveat are unchanged.

use crate::nulls::null::{SplitMix64, mix_seed};

use super::detector::scan_counts;
use super::{
    BREAK_INDEX, CONTROL_TAG, EPSILON_GRID, EXTENDED_WINDOWS, EpsilonFitRow, FAMILY_MESSAGES,
    FAMILY_TAG, FILLER, FILLER_POST_OFFSET, FILLER_PRE_OFFSET, FRESH_BREAK_OFFSET, FamilyFit,
    HIGH_EPSILON, IsomorphImperfectionConfig, IsomorphImperfectionError, MOTIF, MOTIF_BASE_STRIDE,
    ScanCounts,
};

fn build_message(base: u32, broken: bool) -> Vec<u32> {
    let mut values = Vec::with_capacity(FILLER + MOTIF.len() + FILLER);
    for index in 0..FILLER {
        values.push(base + FILLER_PRE_OFFSET + u32::try_from(index).unwrap_or_default());
    }
    for (index, class) in MOTIF.iter().enumerate() {
        if broken && index == BREAK_INDEX {
            values.push(base + FRESH_BREAK_OFFSET);
        } else {
            values.push(base + *class);
        }
    }
    for index in 0..FILLER {
        values.push(base + FILLER_POST_OFFSET + u32::try_from(index).unwrap_or_default());
    }
    values
}

fn uniform01(rng: &mut SplitMix64) -> f64 {
    // 53 high bits give an evenly spaced double in [0, 1).
    let bits = rng.next_u64() >> 11;
    bits as f64 / 9_007_199_254_740_992.0
}

pub(super) fn generate_family(epsilon: f64, seed: u64, messages: usize) -> Vec<Vec<u32>> {
    let mut rng = SplitMix64::new(seed);
    let mut out = Vec::with_capacity(messages);
    for message_index in 0..messages {
        let draw = uniform01(&mut rng);
        let base = u32::try_from(message_index)
            .unwrap_or_default()
            .saturating_add(1)
            .saturating_mul(MOTIF_BASE_STRIDE);
        let broken = message_index != 0 && draw < epsilon;
        out.push(build_message(base, broken));
    }
    out
}

pub(super) fn family_counts(epsilon: f64, seed: u64, messages: usize) -> ScanCounts {
    let family = generate_family(epsilon, seed, messages);
    let keys = vec!["synthetic"; family.len()];
    scan_counts(&keys, &family, &EXTENDED_WINDOWS)
}

pub(super) fn run_family_fit(
    config: IsomorphImperfectionConfig,
    observed_robust: usize,
) -> FamilyFit {
    let mut rows = Vec::with_capacity(EPSILON_GRID.len());
    for (grid_index, epsilon) in EPSILON_GRID.into_iter().enumerate() {
        rows.push(epsilon_row(config, grid_index, epsilon));
    }
    let baseline_mean_robust = rows.first().map_or(0.0, |row| row.mean_robust);
    let high_mean_robust = rows
        .iter()
        .find(|row| row.epsilon >= HIGH_EPSILON)
        .map_or(0.0, |row| row.mean_robust);
    let positive_control_fired = high_mean_robust > baseline_mean_robust + 1.0;
    let detection_threshold = rows
        .iter()
        .find(|row| row.mean_robust >= 1.0)
        .map(|row| row.epsilon);
    let best_fit_epsilon = best_fit_epsilon(&rows, observed_robust);
    FamilyFit {
        messages: FAMILY_MESSAGES,
        trials_per_epsilon: config.family_trials,
        rows,
        baseline_mean_robust,
        high_epsilon: HIGH_EPSILON,
        high_mean_robust,
        positive_control_fired,
        detection_threshold,
        observed_robust,
        best_fit_epsilon,
    }
}

fn epsilon_row(
    config: IsomorphImperfectionConfig,
    grid_index: usize,
    epsilon: f64,
) -> EpsilonFitRow {
    let mut robust = Vec::with_capacity(config.family_trials);
    let mut loose = Vec::with_capacity(config.family_trials);
    for trial in 0..config.family_trials {
        let seed = mix_seed(
            config.seed,
            FAMILY_TAG
                ^ (u64::try_from(grid_index).unwrap_or_default() << 32)
                ^ u64::try_from(trial).unwrap_or(u64::MAX),
        );
        let counts = family_counts(epsilon, seed, FAMILY_MESSAGES);
        robust.push(counts.robust_internal_violations);
        loose.push(counts.loose_candidates);
    }
    EpsilonFitRow {
        epsilon,
        mean_robust: mean_usize(&robust),
        max_robust: robust.iter().copied().max().unwrap_or_default(),
        mean_loose: mean_usize(&loose),
        max_loose: loose.iter().copied().max().unwrap_or_default(),
    }
}

fn best_fit_epsilon(rows: &[EpsilonFitRow], observed_robust: usize) -> f64 {
    let observed = observed_robust as f64;
    let mut best_epsilon = 0.0;
    let mut best_distance = f64::INFINITY;
    for row in rows {
        let distance = (row.mean_robust - observed).abs();
        if distance < best_distance {
            best_distance = distance;
            best_epsilon = row.epsilon;
        }
    }
    best_epsilon
}

pub(super) fn ensure_positive_control(
    config: IsomorphImperfectionConfig,
) -> Result<(), IsomorphImperfectionError> {
    let seed = mix_seed(config.seed, CONTROL_TAG);
    let perfect = family_counts(0.0, seed, FAMILY_MESSAGES).robust_internal_violations;
    let imperfect = family_counts(HIGH_EPSILON, seed, FAMILY_MESSAGES).robust_internal_violations;
    if perfect != 0 {
        return Err(IsomorphImperfectionError::PositiveControlFailed {
            detail: format!("perfect-family baseline produced {perfect} robust violations"),
        });
    }
    if imperfect <= perfect {
        return Err(IsomorphImperfectionError::PositiveControlFailed {
            detail: format!(
                "high-epsilon family produced {imperfect} robust violations, not elevated above the baseline {perfect}"
            ),
        });
    }
    Ok(())
}

fn mean_usize(samples: &[usize]) -> f64 {
    if samples.is_empty() {
        0.0
    } else {
        samples.iter().sum::<usize>() as f64 / samples.len() as f64
    }
}

//! Magnitude census: the exact-repeat structure of the carrier `M`, with each
//! anchor flagged complemented (opposite run-direction parity) and calibrated
//! against an order-1 Markov matched null.

use crate::analysis::translate_isomorph::{find_anchors, markov_resample};
use crate::nulls::null::{SplitMix64, add_one_p_value};

use super::{RlError, magnitude_carrier};

/// Floor on reported anchor length (shorter coincidences are not structural).
const MIN_ANCHOR_LEN: usize = 4;

/// One exact magnitude repeat, with the polarity flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CensusAnchor {
    /// Repeat length in magnitudes.
    pub length: usize,
    /// First (smaller) run index.
    pub first: usize,
    /// Second (larger) run index.
    pub second: usize,
    /// Translation distance `second - first`.
    pub gap: usize,
    /// `true` when the two occurrences start on opposite run-direction parity.
    ///
    /// Run-length runs strictly alternate direction, so run-index parity *is*
    /// direction parity; a complemented repeat is therefore a polarity-blind
    /// (bit-complemented) repeat — the proof the carrier is direction-blind.
    pub complemented: bool,
}

/// The census report: observed longest repeat, the flagged anchors, and the
/// order-1 Markov matched-null calibration.
#[derive(Clone, Debug, PartialEq)]
pub struct CensusReport {
    /// Longest exact repeat length observed in `M`.
    pub observed_max: usize,
    /// Significant anchors (length `>= MIN_ANCHOR_LEN`), longest first.
    pub anchors: Vec<CensusAnchor>,
    /// Mean longest-repeat length across the matched-null trials.
    pub null_max_mean: f64,
    /// Largest longest-repeat any null trial reached.
    pub null_ceiling: usize,
    /// Add-one p-value: fraction of null trials reaching the observed maximum.
    pub p_value: f64,
    /// Whether the observed maximum clears every null trial.
    pub significant: bool,
}

/// Longest exact repeated substring length of `stream`.
fn longest_repeat(stream: &[u32]) -> usize {
    find_anchors(stream, 1, 1)
        .first()
        .map_or(0, |anchor| anchor.length)
}

/// Scans the magnitude carrier for exact repeats and calibrates the longest one
/// against an order-1 Markov-resampled-`M` null.
///
/// A significant repeat is a **structural candidate, not a decode**: it locates
/// *where* the carrier repeats (the bit-complemented blocks that settle the
/// direction-blind reading), not what it means.
///
/// # Errors
/// Returns [`RlError::Iso`] if a Markov resample rejects its input.
pub fn magnitude_census(
    magnitudes: &[usize],
    top_k: usize,
    null_trials: usize,
    seed: u64,
) -> Result<CensusReport, RlError> {
    let (stream, alphabet) = magnitude_carrier(magnitudes);
    let observed_max = longest_repeat(&stream);
    let anchors = find_anchors(&stream, MIN_ANCHOR_LEN, top_k)
        .into_iter()
        .map(|anchor| CensusAnchor {
            length: anchor.length,
            first: anchor.first,
            second: anchor.second,
            gap: anchor.gap,
            complemented: (anchor.first % 2) != (anchor.second % 2),
        })
        .collect();

    let mut rng = SplitMix64::new(seed);
    let mut null_sum = 0u64;
    let mut null_ceiling = 0usize;
    let mut reached = 0usize;
    for _trial in 0..null_trials {
        let resampled = markov_resample(&stream, alphabet, &mut rng)?;
        let trial_max = longest_repeat(&resampled);
        null_sum += trial_max as u64;
        null_ceiling = null_ceiling.max(trial_max);
        if trial_max >= observed_max {
            reached += 1;
        }
    }
    let null_max_mean = if null_trials == 0 {
        0.0
    } else {
        null_sum as f64 / null_trials as f64
    };
    let p_value = add_one_p_value(reached, null_trials);
    let significant = null_trials > 0 && observed_max > null_ceiling;

    Ok(CensusReport {
        observed_max,
        anchors,
        null_max_mean,
        null_ceiling,
        p_value,
        significant,
    })
}

//! Held-out-fold helpers shared by the survival gates (ragbaby, keystream, solve).
//!
//! The generalization gate asks whether a candidate *generalizes*: its score on a
//! held-out fold must beat the matched null's score **on the same kind of fold**.
//! Comparing the fold score against the matched null's *full-stream* mean (an
//! earlier bug, fixed first in `ragbaby.rs` and now centralized here) falsely
//! fails a true decode, because a fold of natural-language text is not itself
//! contiguous text and so scores below the full stream — a penalty the full-stream
//! null never pays. The gate must always compare fold-vs-fold.
//!
//! Two primitives live here:
//! - [`odd_index_fold`] — the alternating held-out fold extraction, shared by the
//!   ragbaby, keystream, and fixed-mapping solve gates (the searched-mapping solve
//!   path uses a *contiguous* split instead — see `solve::search` — because it
//!   re-fits a mapping on the train fold and an alternating split would shred the
//!   bigram adjacency the re-fit must generalize).
//! - [`MatchedNullStats`] / [`matched_null_stats`] — aggregate per-trial
//!   `(full_score, heldout_score)` pairs into the full-stream mean/std (the overfit
//!   bar) plus the held-out fold mean (the apples-to-apples generalization
//!   baseline the candidate's held-out fold must beat).

/// The alternating (odd-index) held-out fold of `stream`: the elements at odd
/// positions `1, 3, 5, …`, preserving order.
///
/// This is the generalization fold used by the keyed-alphabet (ragbaby), keystream,
/// and fixed-mapping survival gates — roughly half the stream, disjoint from the
/// even-index half. Returns an empty vector for a stream shorter than two elements
/// (the caller decides the degenerate-case fallback).
#[must_use]
pub fn odd_index_fold<T: Copy>(stream: &[T]) -> Vec<T> {
    stream
        .iter()
        .copied()
        .enumerate()
        .filter_map(|(position, value)| (position % 2 == 1).then_some(value))
        .collect()
}

/// Matched-null statistics for the survival gate.
///
/// `full_mean`/`full_std` describe the matched null's in-sample (full-stream)
/// scores — the overfit bar a candidate's in-sample score must clear. `heldout_mean`
/// is the mean of the matched null's *held-out fold* scores — the apples-to-apples
/// baseline a candidate's held-out fold must clear to count as generalizing.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MatchedNullStats {
    /// Mean of the per-trial full-stream scores (the overfit bar).
    pub full_mean: f64,
    /// Population standard deviation of the per-trial full-stream scores.
    pub full_std: f64,
    /// Mean of the per-trial held-out fold scores (the generalization baseline).
    pub heldout_mean: f64,
}

impl MatchedNullStats {
    /// All-zero statistics — the value for a disabled null (zero trials).
    pub const ZERO: Self = Self {
        full_mean: 0.0,
        full_std: 0.0,
        heldout_mean: 0.0,
    };
}

/// Aggregates per-trial `(full_score, heldout_score)` pairs into [`MatchedNullStats`].
///
/// Returns [`MatchedNullStats::ZERO`] for an empty input (a disabled null, or one
/// whose trials were all dropped), so a zero-trial null never silently passes a gate
/// — the caller still guards on `trials > 0`.
#[must_use]
pub fn matched_null_stats(trials: &[(f64, f64)]) -> MatchedNullStats {
    if trials.is_empty() {
        return MatchedNullStats::ZERO;
    }
    let count = trials.len() as f64;
    let full_mean = trials.iter().map(|&(full, _)| full).sum::<f64>() / count;
    let variance = trials
        .iter()
        .map(|&(full, _)| {
            let delta = full - full_mean;
            delta * delta
        })
        .sum::<f64>()
        / count;
    let heldout_mean = trials.iter().map(|&(_, heldout)| heldout).sum::<f64>() / count;
    MatchedNullStats {
        full_mean,
        full_std: variance.sqrt(),
        heldout_mean,
    }
}

#[cfg(test)]
mod tests {
    use super::{MatchedNullStats, matched_null_stats, odd_index_fold};

    #[test]
    fn odd_index_fold_keeps_odd_positions_in_order() {
        assert_eq!(odd_index_fold(&[10, 11, 12, 13, 14]), vec![11, 13]);
        assert_eq!(odd_index_fold(&[10, 11]), vec![11]);
    }

    #[test]
    fn odd_index_fold_is_empty_for_short_streams() {
        assert!(odd_index_fold::<u8>(&[]).is_empty());
        assert!(odd_index_fold(&[42]).is_empty());
    }

    #[test]
    fn matched_null_stats_zero_for_empty() {
        assert_eq!(matched_null_stats(&[]), MatchedNullStats::ZERO);
    }

    #[test]
    fn matched_null_stats_separates_full_and_heldout_means() {
        // Full scores {-2, -4} -> mean -3, std 1; held-out scores {-5, -7} -> mean -6.
        let stats = matched_null_stats(&[(-2.0, -5.0), (-4.0, -7.0)]);
        assert!((stats.full_mean - (-3.0)).abs() < 1e-12);
        assert!((stats.full_std - 1.0).abs() < 1e-12);
        assert!((stats.heldout_mean - (-6.0)).abs() < 1e-12);
    }
}

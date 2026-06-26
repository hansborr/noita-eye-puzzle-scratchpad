//! Classical cryptanalysis primitives over glyph sequences.
//!
//! These are deliberately encoding-agnostic: they measure statistical
//! properties (symbol frequencies, entropy, index of coincidence, n-grams)
//! that constrain what kind of cipher — if any — could have produced a
//! sequence, without assuming a particular decoding.

use std::collections::BTreeMap;

use crate::glyph::Glyph;
use statrs::distribution::{ChiSquared, ContinuousCDF};

/// Error returned by [`chi_square_goodness_of_fit`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ChiSquareError {
    /// The observed and expected distributions have different lengths.
    LengthMismatch {
        /// Number of observed buckets.
        observed: usize,
        /// Number of expected buckets.
        expected: usize,
    },
    /// One expected bucket had a non-finite weight.
    NonFiniteExpectedWeight {
        /// Zero-based bucket index.
        index: usize,
        /// The invalid expected weight.
        weight: f64,
    },
    /// One expected bucket had a zero or negative weight.
    NonPositiveExpectedWeight {
        /// Zero-based bucket index.
        index: usize,
        /// The invalid expected weight.
        weight: f64,
    },
}

/// Counts how often each glyph occurs.
#[must_use]
pub fn frequencies(seq: &[Glyph]) -> BTreeMap<Glyph, usize> {
    let mut counts = BTreeMap::new();
    for &g in seq {
        *counts.entry(g).or_default() += 1;
    }
    counts
}

/// Shannon entropy of the sequence in bits per glyph.
///
/// Returns `0.0` for an empty sequence. The maximum value is `log2(k)` where
/// `k` is the number of distinct glyphs, reached when they are equiprobable.
///
/// ```
/// use noita_eye_puzzle::{analysis, corpus};
///
/// let seq = corpus::combined_sequence().expect("the verified corpus decodes");
/// let bits = analysis::shannon_entropy(&seq.glyphs);
/// // Five rendered orientations, so per-glyph entropy cannot exceed log2(5).
/// assert!(bits > 0.0 && bits <= 5f64.log2());
/// ```
#[must_use]
pub fn shannon_entropy(seq: &[Glyph]) -> f64 {
    if seq.is_empty() {
        return 0.0;
    }
    let n = seq.len() as f64;
    frequencies(seq)
        .values()
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Index of coincidence: the probability that two glyphs drawn at random
/// (without replacement) are equal.
///
/// Useful for distinguishing monoalphabetic ciphers (which preserve the source
/// language's `IoC`) from polyalphabetic ones (which flatten it toward
/// uniform).
/// Returns `0.0` for sequences shorter than two glyphs.
#[must_use]
pub fn index_of_coincidence(seq: &[Glyph]) -> f64 {
    let n = seq.len();
    if n < 2 {
        return 0.0;
    }
    let numerator: usize = frequencies(seq).values().map(|&c| c * (c - 1)).sum();
    numerator as f64 / (n * (n - 1)) as f64
}

/// Pair-count-weighted index of coincidence pooled across messages.
///
/// Each message contributes its [`index_of_coincidence`] weighted by its number
/// of ordered glyph pairs `len * (len - 1)`; messages shorter than two glyphs
/// are skipped. Returns `0.0` when no message has at least two glyphs.
#[must_use]
pub fn message_weighted_index_of_coincidence(message_glyphs: &[Vec<Glyph>]) -> f64 {
    let mut weighted = 0.0;
    let mut pair_count_total = 0usize;
    for glyphs in message_glyphs {
        let len = glyphs.len();
        if len < 2 {
            continue;
        }
        let pair_count = len * (len - 1);
        weighted += index_of_coincidence(glyphs) * pair_count as f64;
        pair_count_total += pair_count;
    }
    if pair_count_total == 0 {
        0.0
    } else {
        weighted / pair_count_total as f64
    }
}

/// Length-weighted Shannon entropy (bits per symbol) pooled across messages.
///
/// Each message contributes its [`shannon_entropy`] weighted by its glyph count;
/// empty messages are skipped. Returns `0.0` when every message is empty. This
/// keeps message boundaries intact so per-message entropies are not contaminated
/// by artificial cross-join statistics.
#[must_use]
pub fn message_weighted_entropy(message_glyphs: &[Vec<Glyph>]) -> f64 {
    let mut weighted = 0.0;
    let mut total = 0usize;
    for glyphs in message_glyphs {
        let len = glyphs.len();
        if len == 0 {
            continue;
        }
        weighted += shannon_entropy(glyphs) * len as f64;
        total += len;
    }
    if total == 0 {
        0.0
    } else {
        weighted / total as f64
    }
}

/// Pearson chi-square goodness-of-fit statistic against a uniform distribution.
///
/// Each observed bucket is compared with the same expected count,
/// `sum(observed) / observed.len()`. Returns `0.0` for an empty or all-zero
/// observation vector.
#[must_use]
pub fn chi_square_goodness_of_fit_uniform(observed: &[usize]) -> f64 {
    let total: usize = observed.iter().sum();
    if observed.is_empty() || total == 0 {
        return 0.0;
    }

    let expected = total as f64 / observed.len() as f64;
    observed
        .iter()
        .map(|&count| {
            let delta = count as f64 - expected;
            delta * delta / expected
        })
        .sum()
}

/// Pearson chi-square goodness-of-fit statistic against an expected distribution.
///
/// `expected_weights` are positive finite weights and are normalized internally,
/// so callers may pass probabilities, frequencies, or any proportional expected
/// distribution. Returns `0.0` for an empty or all-zero observation vector.
///
/// # Errors
/// Returns [`ChiSquareError`] if the observed and expected bucket counts differ,
/// or if any expected weight is non-finite, zero, or negative.
pub fn chi_square_goodness_of_fit(
    observed: &[usize],
    expected_weights: &[f64],
) -> Result<f64, ChiSquareError> {
    if observed.len() != expected_weights.len() {
        return Err(ChiSquareError::LengthMismatch {
            observed: observed.len(),
            expected: expected_weights.len(),
        });
    }
    let mut expected_weight_total = 0.0;
    for (index, &weight) in expected_weights.iter().enumerate() {
        if !weight.is_finite() {
            return Err(ChiSquareError::NonFiniteExpectedWeight { index, weight });
        }
        if weight <= 0.0 {
            return Err(ChiSquareError::NonPositiveExpectedWeight { index, weight });
        }
        expected_weight_total += weight;
    }

    let total: usize = observed.iter().sum();
    if observed.is_empty() || total == 0 {
        return Ok(0.0);
    }

    let total = total as f64;
    Ok(observed
        .iter()
        .zip(expected_weights)
        .map(|(&count, &weight)| {
            let expected = total * weight / expected_weight_total;
            let delta = count as f64 - expected;
            delta * delta / expected
        })
        .sum())
}

/// Upper-tail p-value for a chi-square statistic and reference distribution.
///
/// Returns `P(X_df >= statistic)`, where `X_df` is a chi-square random variable
/// with the supplied degrees of freedom. Positive infinity is accepted as the
/// limiting statistic and returns a zero tail probability.
///
/// Returns [`None`] if `degrees_of_freedom` is zero, if `statistic` is `NaN`,
/// or if `statistic` is negative.
#[must_use]
pub fn chi_square_upper_tail_p_value(statistic: f64, degrees_of_freedom: usize) -> Option<f64> {
    if statistic.is_nan() || statistic < 0.0 {
        return None;
    }

    let distribution = ChiSquared::new(degrees_of_freedom as f64).ok()?;
    Some(distribution.sf(statistic))
}

/// Counts contiguous n-grams of length `n`.
///
/// Returns an empty map if `n` is zero or larger than the sequence length.
#[must_use]
pub fn ngrams(seq: &[Glyph], n: usize) -> BTreeMap<Vec<Glyph>, usize> {
    let mut counts = BTreeMap::new();
    if n == 0 || n > seq.len() {
        return counts;
    }
    for window in seq.windows(n) {
        *counts.entry(window.to_vec()).or_default() += 1;
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::{
        ChiSquareError, chi_square_goodness_of_fit, chi_square_goodness_of_fit_uniform,
        chi_square_upper_tail_p_value, frequencies, index_of_coincidence, ngrams, shannon_entropy,
    };
    use crate::glyph::Glyph;

    fn glyphs(indices: &[u16]) -> Vec<Glyph> {
        indices.iter().copied().map(Glyph).collect()
    }

    #[test]
    fn entropy_of_uniform_four_symbols_is_two_bits() {
        let h = shannon_entropy(&glyphs(&[0, 1, 2, 3]));
        assert!((h - 2.0).abs() < 1e-9, "got {h}");
    }

    #[test]
    fn entropy_of_constant_sequence_is_zero() {
        assert!(shannon_entropy(&glyphs(&[7, 7, 7])).abs() < 1e-9);
    }

    #[test]
    fn empty_sequence_is_well_defined() {
        assert!(shannon_entropy(&[]).abs() < f64::EPSILON);
        assert!(index_of_coincidence(&[]).abs() < f64::EPSILON);
        assert!(frequencies(&[]).is_empty());
        assert!(ngrams(&[], 2).is_empty());
    }

    #[test]
    fn ioc_of_constant_sequence_is_one() {
        assert!((index_of_coincidence(&glyphs(&[1, 1, 1, 1])) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn chi_square_uniform_matches_toy_distribution() {
        let statistic = chi_square_goodness_of_fit_uniform(&[10, 10, 20]);
        assert!((statistic - 5.0).abs() < 1e-9, "got {statistic}");
    }

    #[test]
    fn chi_square_arbitrary_expected_distribution_normalizes_weights() {
        let statistic = chi_square_goodness_of_fit(&[9, 1], &[3.0, 1.0]).unwrap();
        assert!((statistic - 1.2).abs() < 1e-9, "got {statistic}");
    }

    #[test]
    fn chi_square_upper_tail_matches_known_distribution() {
        let p_value = chi_square_upper_tail_p_value(10.0, 2).unwrap();
        let expected = (-5.0_f64).exp();
        assert!(
            (p_value - expected).abs() < 1e-15,
            "got {p_value}, expected {expected}"
        );
    }

    #[test]
    fn chi_square_upper_tail_rejects_invalid_inputs() {
        assert_eq!(chi_square_upper_tail_p_value(1.0, 0), None);
        assert_eq!(chi_square_upper_tail_p_value(f64::NAN, 1), None);
        assert_eq!(chi_square_upper_tail_p_value(-1.0, 1), None);
    }

    #[test]
    fn chi_square_rejects_invalid_expected_distribution() {
        assert_eq!(
            chi_square_goodness_of_fit(&[1, 2], &[1.0]),
            Err(ChiSquareError::LengthMismatch {
                observed: 2,
                expected: 1,
            })
        );
        assert_eq!(
            chi_square_goodness_of_fit(&[1, 2], &[1.0, 0.0]),
            Err(ChiSquareError::NonPositiveExpectedWeight {
                index: 1,
                weight: 0.0,
            })
        );
    }

    #[test]
    fn chi_square_validates_expected_distribution_before_zero_observation_return() {
        assert!(matches!(
            chi_square_goodness_of_fit(&[0, 0], &[1.0, f64::NAN]),
            Err(ChiSquareError::NonFiniteExpectedWeight { index: 1, weight })
                if weight.is_nan()
        ));
        assert_eq!(
            chi_square_goodness_of_fit(&[0, 0], &[1.0, 0.0]),
            Err(ChiSquareError::NonPositiveExpectedWeight {
                index: 1,
                weight: 0.0,
            })
        );
        assert_eq!(
            chi_square_goodness_of_fit(&[0, 0], &[1.0, -1.0]),
            Err(ChiSquareError::NonPositiveExpectedWeight {
                index: 1,
                weight: -1.0,
            })
        );
        assert_eq!(chi_square_goodness_of_fit(&[0, 0], &[1.0, 1.0]), Ok(0.0));
    }

    #[test]
    fn bigrams_are_counted() {
        let counts = ngrams(&glyphs(&[0, 1, 0, 1]), 2);
        assert_eq!(counts.get(&glyphs(&[0, 1])), Some(&2));
        assert_eq!(counts.get(&glyphs(&[1, 0])), Some(&1));
    }
}

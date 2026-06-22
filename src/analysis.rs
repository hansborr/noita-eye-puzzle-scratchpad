//! Classical cryptanalysis primitives over glyph sequences.
//!
//! These are deliberately encoding-agnostic: they measure statistical
//! properties (symbol frequencies, entropy, index of coincidence, n-grams)
//! that constrain what kind of cipher — if any — could have produced a
//! sequence, without assuming a particular decoding.

use std::collections::BTreeMap;

use crate::glyph::Glyph;

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
    use super::{frequencies, index_of_coincidence, ngrams, shannon_entropy};
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
    fn bigrams_are_counted() {
        let counts = ngrams(&glyphs(&[0, 1, 0, 1]), 2);
        assert_eq!(counts.get(&glyphs(&[0, 1])), Some(&2));
        assert_eq!(counts.get(&glyphs(&[1, 0])), Some(&1));
    }
}

//! Crib geometry: the run-gap / bit-gap of each census-significant carrier repeat,
//! and the divisibility lattice (`gcd`s and their divisors) those gaps imply.
//!
//! A census-significant exact repeat in the magnitude carrier `M` almost certainly
//! marks a repeated *plaintext* span (the "crib"). Two derived quantities per repeat
//! pair drive the whole filter:
//!
//! - the **run-gap** `second - first` (distance in run indices), and
//! - the **bit-gap** `Σ M[first..second]` (distance in carrier *bits*, the
//!   prefix-sum difference).
//!
//! Under a state/key that advances once per *run*, two occurrences decode
//! identically only when the run-gap is a multiple of the period; under one that
//! advances per *bit*, only when the bit-gap is. So `gcd(run-gaps)` and
//! `gcd(bit-gaps)` bound the admissible periods analytically (see [`families`]).
//!
//! [`families`]: super::families

use std::collections::BTreeSet;

use crate::analysis::translate_isomorph::find_anchors;

use super::CribfitError;
use crate::attack::rlcodec::{CensusReport, magnitude_census};

/// Reporting floor on crib length (shorter coincidences are not structural). The
/// derivation tightens this to *census-significant* repeats; this is only the
/// suffix-array search threshold.
const MIN_CRIB_LEN: usize = 4;

/// One repeated carrier span (a crib): the two run-index occurrences, the repeat
/// length, and the derived run-gap / bit-gap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorPair {
    /// Repeat length, in run-length magnitudes.
    pub length: usize,
    /// First (smaller) run index.
    pub first: usize,
    /// Second (larger) run index.
    pub second: usize,
    /// Run-index distance `second - first`.
    pub run_gap: usize,
    /// Carrier-bit distance `Σ M[first..second]` (the prefix-sum difference).
    pub bit_gap: usize,
}

/// The crib geometry of a carrier: the anchor pairs and the divisibility lattice
/// their gaps imply. Pure arithmetic — the cribs' census significance is carried
/// separately (see [`derive_crib_geometry`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CribGeometry {
    /// Number of carrier magnitudes the geometry was computed over.
    pub n_magnitudes: usize,
    /// The census-significant repeat pairs (longest first), with their gaps.
    pub anchors: Vec<AnchorPair>,
    /// `gcd` of every anchor's run-gap (`0` when there are no anchors).
    pub gcd_run_gaps: usize,
    /// `gcd` of every anchor's bit-gap (`0` when there are no anchors).
    pub gcd_bit_gaps: usize,
    /// Divisors of [`Self::gcd_run_gaps`] — the admissible run-periodic key periods.
    pub run_periods: Vec<usize>,
    /// Divisors of [`Self::gcd_bit_gaps`] — the admissible bit-periodic key periods
    /// (and the admissible cumulative-sum moduli).
    pub bit_periods: Vec<usize>,
}

/// Exclusive prefix sums of `magnitudes`: `prefix[k] = Σ_{j<k} magnitudes[j]`, so
/// `prefix[0] == 0` and `Σ magnitudes[a..b] == prefix[b] - prefix[a]`.
fn prefix_sums(magnitudes: &[usize]) -> Vec<usize> {
    let mut prefix = Vec::with_capacity(magnitudes.len() + 1);
    prefix.push(0usize);
    for &m in magnitudes {
        prefix.push(prefix.last().copied().unwrap_or(0) + m);
    }
    prefix
}

/// Greatest common divisor (`gcd(0, x) == x`).
fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

/// `gcd` of a slice (`0` when empty).
fn gcd_all(values: &[usize]) -> usize {
    values.iter().fold(0usize, |acc, &x| gcd(acc, x))
}

/// The sorted divisors of `value` (`[]` for `0`, `[1]` for `1`).
pub(crate) fn divisors(value: usize) -> Vec<usize> {
    if value == 0 {
        return Vec::new();
    }
    let mut out = BTreeSet::new();
    let mut d = 1usize;
    while d * d <= value {
        if value.is_multiple_of(d) {
            let _ = out.insert(d);
            let _ = out.insert(value / d);
        }
        d += 1;
    }
    out.into_iter().collect()
}

/// All in-order occurrence pairs of every census-significant repeat, expanded so a
/// repeat occurring three+ times contributes *every* pairwise gap.
///
/// [`find_anchors`] returns suffix-array-adjacent pairs and drops nested repeats,
/// so a triple repeat may surface as only one or two of its three pairs. We
/// therefore take each found anchor's content, scan `M` for *all* its occurrences,
/// and emit every `(first < second)` pair — so the `gcd` lattice sees the complete
/// crib geometry regardless of suffix-array ordering.
fn significant_pairs(
    magnitudes: &[usize],
    census: &CensusReport,
    top_k: usize,
) -> Vec<(usize, usize, usize)> {
    // Cribs are repeats that clear the census null ceiling; below that bar a
    // "repeat" is an order-1 coincidence, not a plaintext span.
    let floor = MIN_CRIB_LEN.max(census.null_ceiling + 1);
    let found = find_anchors(magnitudes_as_u32(magnitudes).as_slice(), floor, top_k);
    let mut pairs: BTreeSet<(usize, usize, usize)> = BTreeSet::new();
    for anchor in found {
        let length = anchor.length;
        let Some(content) = magnitudes.get(anchor.first..anchor.first + length) else {
            continue;
        };
        // Every start where this exact content recurs.
        let mut starts = Vec::new();
        let mut start = 0usize;
        while start + length <= magnitudes.len() {
            if magnitudes.get(start..start + length) == Some(content) {
                starts.push(start);
            }
            start += 1;
        }
        for (i, &first) in starts.iter().enumerate() {
            for &second in starts.iter().skip(i + 1) {
                let _ = pairs.insert((length, first, second));
            }
        }
    }
    pairs.into_iter().collect()
}

/// Widens magnitudes to the `u32` stream [`find_anchors`] scans.
fn magnitudes_as_u32(magnitudes: &[usize]) -> Vec<u32> {
    magnitudes
        .iter()
        .map(|&m| u32::try_from(m).unwrap_or(u32::MAX))
        .collect()
}

/// Computes the crib geometry of `magnitudes` from an explicit set of repeat pairs
/// `(length, first, second)` (the form the self-test feeds the documented anchors).
///
/// Each pair's run-gap and bit-gap are derived, then `gcd`s and their divisors.
#[must_use]
pub fn crib_geometry(magnitudes: &[usize], pairs: &[(usize, usize, usize)]) -> CribGeometry {
    let prefix = prefix_sums(magnitudes);
    let mut anchors: Vec<AnchorPair> = pairs
        .iter()
        .filter(|&&(length, first, second)| first < second && second + length <= magnitudes.len())
        .map(|&(length, first, second)| AnchorPair {
            length,
            first,
            second,
            run_gap: second - first,
            bit_gap: prefix.get(second).copied().unwrap_or(0)
                - prefix.get(first).copied().unwrap_or(0),
        })
        .collect();
    anchors.sort_by(|a, b| {
        b.length
            .cmp(&a.length)
            .then_with(|| a.first.cmp(&b.first))
            .then_with(|| a.second.cmp(&b.second))
    });

    let run_gaps: Vec<usize> = anchors.iter().map(|a| a.run_gap).collect();
    let bit_gaps: Vec<usize> = anchors.iter().map(|a| a.bit_gap).collect();
    let gcd_run_gaps = gcd_all(&run_gaps);
    let gcd_bit_gaps = gcd_all(&bit_gaps);

    CribGeometry {
        n_magnitudes: magnitudes.len(),
        anchors,
        gcd_run_gaps,
        gcd_bit_gaps,
        run_periods: divisors(gcd_run_gaps),
        bit_periods: divisors(gcd_bit_gaps),
    }
}

/// Derives the crib geometry of `magnitudes` end-to-end: census the carrier, take
/// the census-significant repeats as cribs, expand to all pairwise gaps, and
/// compute the divisibility lattice. Returns the geometry alongside the census
/// calibration (the cribs' significance) for the report.
///
/// # Errors
/// Returns [`CribfitError`] if the census matched null fails.
pub fn derive_crib_geometry(
    magnitudes: &[usize],
    top_k: usize,
    census_null_trials: usize,
    seed: u64,
) -> Result<(CribGeometry, CensusReport), CribfitError> {
    let census = magnitude_census(magnitudes, top_k, census_null_trials, seed)?;
    let pairs = significant_pairs(magnitudes, &census, top_k);
    Ok((crib_geometry(magnitudes, &pairs), census))
}

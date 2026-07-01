//! Affine-cell enumeration, canonicalization, crib filtering, and stream densifying.

use std::collections::{BTreeMap, BTreeSet};

use crate::attack::cribfit::AnchorPair;
use crate::attack::rlcodec::MIN_LETTERS;

/// One canonical affine running-key cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AffineCell {
    /// Ring size `R`.
    pub ring: usize,
    /// Prefix-sum coefficient `a` modulo `R`.
    pub a: usize,
    /// Run-index coefficient `b` modulo `R`.
    pub b: usize,
}

/// The raw residue stream plus the dense ids used by the substitution search.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct IndexedStream {
    pub(super) raw: Vec<usize>,
    pub(super) dense: Vec<usize>,
    pub(super) alphabet: usize,
}

/// Enumerates one representative per unit-scaling orbit of `(a,b)` for each ring.
pub(super) fn enumerate_canonical_cells(ring_sizes: &[usize], coeff_max: usize) -> Vec<AffineCell> {
    let mut cells = BTreeSet::new();
    for &ring in ring_sizes {
        if ring == 0 {
            continue;
        }
        let limit = coeff_max.min(ring.saturating_sub(1));
        for a in 0..=limit {
            for b in 0..=limit {
                let (a, b) = canonical_pair(ring, a, b);
                let _inserted = cells.insert(AffineCell { ring, a, b });
            }
        }
    }
    cells.into_iter().collect()
}

/// Canonical representative of the unit-scaling orbit of `(a,b) mod R`.
pub(super) fn canonical_pair(ring: usize, a: usize, b: usize) -> (usize, usize) {
    if ring == 0 {
        return (0, 0);
    }
    let a = a % ring;
    let b = b % ring;
    let mut best = (a, b);
    for unit in 1..ring {
        if gcd(unit, ring) != 1 {
            continue;
        }
        let candidate = ((unit * a) % ring, (unit * b) % ring);
        if candidate < best {
            best = candidate;
        }
    }
    best
}

/// Computes `idx[i] = (a*S_i + b*i) mod R`, with `S_i = sum(M[0..i])`.
pub(super) fn affine_stream(magnitudes: &[usize], cell: AffineCell) -> IndexedStream {
    let mut raw = Vec::with_capacity(magnitudes.len());
    let mut prefix_mod = 0usize;
    for (index, &magnitude) in magnitudes.iter().enumerate() {
        let ring = cell.ring;
        let left = (cell.a % ring) * prefix_mod % ring;
        let right = (cell.b % ring) * (index % ring) % ring;
        raw.push((left + right) % ring);
        prefix_mod = (prefix_mod + magnitude % ring) % ring;
    }
    densify(&raw)
}

/// `true` iff the affine cell satisfies every crib modular equality.
pub(super) fn crib_consistent(anchors: &[AnchorPair], cell: AffineCell) -> bool {
    anchors.iter().all(|anchor| {
        let ring = cell.ring;
        let bit = anchor.bit_gap % ring;
        let run = anchor.run_gap % ring;
        let delta = ((cell.a % ring) * bit + (cell.b % ring) * run) % ring;
        delta == 0
    })
}

/// Whether the dense stream can host the English substitution search.
pub(super) fn english_feasible(stream: &IndexedStream, min_effective_alphabet: usize) -> bool {
    stream.dense.len() >= MIN_LETTERS
        && (min_effective_alphabet..=crate::attack::quadgram::ALPHABET_LEN)
            .contains(&stream.alphabet)
}

fn densify(raw: &[usize]) -> IndexedStream {
    let mut ids = BTreeMap::new();
    let mut dense = Vec::with_capacity(raw.len());
    for &value in raw {
        let next = ids.len();
        let id = *ids.entry(value).or_insert(next);
        dense.push(id);
    }
    IndexedStream {
        raw: raw.to_vec(),
        dense,
        alphabet: ids.len(),
    }
}

fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

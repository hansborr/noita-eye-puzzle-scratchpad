//! Analytic combinatorial primitives and Part A empirical-supply compute for
//! the G3 leak-ceiling report.
//!
//! Moved verbatim from the leaf module: the pure combinatorics (factorials,
//! harmonic numbers, coupon-collector demand, the near-identity neighborhood,
//! and the coverage model) plus the read-only supply measurements (successor
//! out-degree, chaining-graph supply, repeated-isomorph occurrence pairs). No
//! logic, numeric literal, or honesty caveat is changed.

use std::collections::{BTreeMap, BTreeSet};

use crate::analysis::chaining_graph;
use crate::analysis::isomorph::PatternSignature;
use crate::core::trigram::TrigramValue;

use super::{ChainingSupply, IsomorphSupply, LeakCeilingError, OutDegreeSupply};

// ---------------------------------------------------------------------------
// Analytic primitives.
// ---------------------------------------------------------------------------

/// Returns `log2(n!)` as a sum of logarithms (overflow-free).
#[must_use]
pub fn log2_factorial(n: usize) -> f64 {
    let mut total = 0.0_f64;
    for value in 2..=n {
        total += (value as f64).log2();
    }
    total
}

/// Returns the `k`-th harmonic number `H_k = Σ_{i=1}^{k} 1/i`.
#[must_use]
pub fn harmonic(k: usize) -> f64 {
    let mut total = 0.0_f64;
    for value in 1..=k {
        total += 1.0 / value as f64;
    }
    total
}

/// Coupon-collector full-pin demand `N·ln N`.
#[must_use]
pub fn coupon_full_pin(n: usize) -> f64 {
    if n == 0 {
        return 0.0;
    }
    n as f64 * (n as f64).ln()
}

/// Coupon-collector demand to observe `c` distinct cosets, `N·(H_N − H_{N−c})`.
#[must_use]
pub fn coupon_demand(n: usize, c: usize) -> f64 {
    if n == 0 || c > n {
        return 0.0;
    }
    n as f64 * (harmonic(n) - harmonic(n - c))
}

/// Binomial coefficient `C(n, r)` as `f64` (overflow-free for our `N ≤ 83`).
#[must_use]
pub fn binomial_f64(n: usize, r: usize) -> f64 {
    if r > n {
        return 0.0;
    }
    let r = r.min(n - r);
    let mut result = 1.0_f64;
    for step in 0..r {
        result = result * (n - step) as f64 / (step + 1) as f64;
    }
    result
}

/// Odd double factorial `(2k−1)!!` (pairings of `2k` points); `k = 0 ⇒ 1`.
#[must_use]
pub fn odd_double_factorial(k: usize) -> f64 {
    let mut result = 1.0_f64;
    let mut value = 2 * k;
    while value > 1 {
        result *= (value - 1) as f64;
        value -= 2;
    }
    result
}

/// Size of the near-identity neighborhood: permutations that are at most
/// `max_swaps` disjoint transpositions, `Σ_{k=0}^{max_swaps} C(N, 2k)·(2k−1)!!`.
#[must_use]
pub fn near_identity_neighborhood(n: usize, max_swaps: usize) -> f64 {
    let mut total = 0.0_f64;
    for k in 0..=max_swaps {
        total += binomial_f64(n, 2 * k) * odd_double_factorial(k);
    }
    total
}

/// Coverage-model decodable transitions for the dominant repeated signature.
///
/// `decodable = min(M, G · occ · (1 − (1 − 1/N)^occ))`, where the factor
/// `(1 − (1 − 1/N)^occ)` is the coupon-collector coset-coverage of one recurring
/// element after `occ` aligned observations, and `G` is the dominant-signature
/// multiplicity. When `occ ≪ N` this collapses ≈ `G·occ²/N`.
#[must_use]
pub fn coverage_decodable(
    cosets: usize,
    stream_len: usize,
    occurrences: usize,
    geometry: f64,
) -> f64 {
    if cosets == 0 {
        return 0.0;
    }
    let occ = occurrences as f64;
    let coset_coverage = 1.0 - (1.0 - 1.0 / cosets as f64).powf(occ);
    (geometry * occ * coset_coverage).min(stream_len as f64)
}

/// Predicted undecidable fraction under the coverage model.
#[must_use]
pub fn coverage_undecidable_fraction(
    cosets: usize,
    stream_len: usize,
    occurrences: usize,
    geometry: f64,
) -> f64 {
    if stream_len == 0 {
        return 1.0;
    }
    let decodable = coverage_decodable(cosets, stream_len, occurrences, geometry);
    (1.0 - decodable / stream_len as f64).clamp(0.0, 1.0)
}

// ---------------------------------------------------------------------------
// Part A — measured supply.
// ---------------------------------------------------------------------------

pub(super) fn out_degree_supply(message_values: &[Vec<TrigramValue>]) -> OutDegreeSupply {
    let mut successors: BTreeMap<u8, BTreeSet<u8>> = BTreeMap::new();
    for values in message_values {
        for pair in values.windows(2) {
            if let (Some(from), Some(to)) = (pair.first(), pair.get(1)) {
                let _inserted = successors.entry(from.get()).or_default().insert(to.get());
            }
        }
    }
    let degrees: Vec<usize> = successors.values().map(BTreeSet::len).collect();
    let source_symbols = degrees.len();
    let sum: usize = degrees.iter().sum();
    let mean = if source_symbols == 0 {
        0.0
    } else {
        sum as f64 / source_symbols as f64
    };
    let mut histogram_map: BTreeMap<usize, usize> = BTreeMap::new();
    for degree in &degrees {
        *histogram_map.entry(*degree).or_default() += 1;
    }
    OutDegreeSupply {
        source_symbols,
        mean,
        min: degrees.iter().copied().min().unwrap_or_default(),
        max: degrees.iter().copied().max().unwrap_or_default(),
        branching_bits: if mean > 0.0 { mean.log2() } else { 0.0 },
        histogram: histogram_map.into_iter().collect(),
    }
}

pub(super) fn chaining_supply(
    message_values: &[Vec<TrigramValue>],
    window_len: usize,
    core_len: usize,
) -> Result<ChainingSupply, LeakCeilingError> {
    let graph = chaining_graph::compute_graph(message_values, window_len, core_len)?;
    let mut edges: BTreeSet<(u32, u8, u8)> = BTreeSet::new();
    for link in &graph.links {
        let _inserted = edges.insert((link.context.as_u32(), link.from.get(), link.to.get()));
    }
    Ok(ChainingSupply {
        window_len,
        core_len,
        links: graph.links.len(),
        distinct_contexts: graph.contexts.len(),
        distinct_edges: edges.len(),
        symbols_touched: graph.coverage.symbols_touched,
        component_count: graph.coverage.component_count,
        largest_component: graph.coverage.largest_component,
        core_supported_symbols: graph.coverage.core_supported_symbols,
        core_largest_component: graph.coverage.core_largest_component,
        core_supported_components: graph.coverage.core_supported_components,
    })
}

pub(super) fn isomorph_supply(
    message_values: &[Vec<TrigramValue>],
    window_len: usize,
) -> IsomorphSupply {
    let mut counts: BTreeMap<PatternSignature, usize> = BTreeMap::new();
    let mut informative_windows = 0usize;
    for values in message_values {
        if values.len() < window_len {
            continue;
        }
        for window in values.windows(window_len) {
            let signature = PatternSignature::from_window(window);
            if signature.has_repeated_symbol() {
                informative_windows += 1;
                *counts.entry(signature).or_default() += 1;
            }
        }
    }
    let mut repeated_signature_kinds = 0usize;
    let mut max_repeat_count = 0usize;
    let mut aligned_occurrence_pairs = 0usize;
    for occ in counts.values().copied() {
        if occ > 1 {
            repeated_signature_kinds += 1;
            aligned_occurrence_pairs += occ * (occ - 1) / 2;
        }
        max_repeat_count = max_repeat_count.max(occ);
    }
    IsomorphSupply {
        window_len,
        repeated_signature_kinds,
        max_repeat_count,
        aligned_occurrence_pairs,
        informative_windows,
    }
}

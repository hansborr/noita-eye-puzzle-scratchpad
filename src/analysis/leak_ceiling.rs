//! G3 — isomorph-leak information ceiling for the Noita eye-glyph puzzle.
//!
//! Converts the wiki's *soft* pessimism — "it might be unrealistic to expect
//! chaining to ever work for the eyes" given ~1036 trigrams against a near-`S₈₃`
//! group — into a stated, mapping-independent feasibility bound. **No new attack**,
//! no symbol→meaning mapping: it measures the leak *supply* the corpus exposes vs
//! the analytic *demand* a chaining recovery needs. Four parts:
//!
//! * **Part A — supply (measured).** Read-only stats of the accepted-honeycomb
//!   reading-layer stream: trigram count `M`, distinct symbols, raw successor
//!   out-degree, chaining-graph edge/coverage supply ([`crate::analysis::chaining_graph`]),
//!   and repeated-isomorph occurrence-pair supply ([`crate::analysis::isomorph`]).
//! * **Part B — demand (analytic).** Edge-overlap certification degree vs the
//!   transitivity regime, and the coupon-collector cost of pinning one element's
//!   action on the cosets of the hidden subgroup.
//! * **Part C — the ceiling.** Per-element recurrence shortfall, an *upper* bound
//!   on leaked bits, the needed per-position keystream entropy (unconstrained
//!   `S_N` and near-identity), and a coverage / undecidable-fraction model.
//! * **Part D — single-point geometry calibration.** The coverage model fed
//!   G1b's `two` parameters, checked against its band — a **single-point,
//!   one-free-parameter** (`G`) fit, **not** a falsifiable positive control (only
//!   `G = 2` lands). The eyes conclusion rests on **robustness** (98.6–99.9% for
//!   any `G ∈ {1,2,3}`), not on it; a scaling sweep over `N` gives the crossings.
//!
//! Honesty labels bind: supply is *measured*; demand/ceiling/coverage are
//! *analytic, model-conditional*; the MI figure is an *upper bound*; the coupon
//! demand is for the maximal `H = S₈₂` (`N = 83`) and scales down with larger `H`.
//! Claim ceiling holds: the eyes remain deterministic, engine-generated,
//! strikingly structured data of unknown meaning; unsolved.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::analysis::chaining_graph::{self, ChainingGraphError};
use crate::analysis::isomorph::PatternSignature;
use crate::analysis::orders::{
    self, GridError, READING_LAYER_ALPHABET_SIZE, ReadingLayerFlatnessStats,
    read_corpus_message_values,
};
use crate::core::trigram::TrigramValue;
use crate::report::{self, Report};

/// Default chaining-graph window length (the wiki D166 triple).
pub const DEFAULT_CHAINING_WINDOW_LEN: usize = 11;
/// Default chaining-graph repeated-core length.
pub const DEFAULT_CHAINING_CORE_LEN: usize = 9;
/// Default short isomorph reference window, matching G1b's length-4 signature.
pub const DEFAULT_ISOMORPH_WINDOW_LEN: usize = 4;

/// Chaining window/core pairs reported as a sensitivity panel around the default.
const CHAINING_SENSITIVITY: [(usize, usize); 2] = [(9, 7), (13, 11)];
/// Isomorph window lengths reported as supply, mirroring G1b's `phrase_len` rows.
const ISOMORPH_WINDOWS: [usize; 4] = [4, 6, 8, 11];

/// Calibrated dominant-signature multiplicity `G` for the coverage model.
///
/// The number of comparably-dominant repeated signatures supplying coverage. It
/// is the model's **single fitted constant** — only `G = 2` lands in G1b's band
/// (`G = 1 → ~89%`, `G = 3 → ~67%`), so it is fit, not predicted; the eyes
/// prediction is robust to it (see [`CalibrationControl::eyes_undecidable_g_band`]).
const CALIBRATED_GEOMETRY: f64 = 2.0;

/// G1b-measured `two` coset count (`Z₃ × S₄` visible symbols).
const TWO_COSETS: usize = 12;
/// G1b-measured `two` stream length in symbols.
const TWO_STREAM_LEN: usize = 698;
/// G1b-measured `two` dominant length-4 isomorph signature occurrence count.
const TWO_DOMINANT_OCCURRENCES: usize = 76;
/// G1b-measured `two` raw readout out-degree (all 12 symbols).
const TWO_OUT_DEGREE: usize = 8;
/// G1b-measured `two` undecidable-fraction band lower edge (`phrase_len` 6).
const TWO_UNDECIDABLE_LOW: f64 = 0.76;
/// G1b-measured `two` undecidable-fraction band upper edge (`phrase_len` 4).
const TWO_UNDECIDABLE_HIGH: f64 = 0.83;

/// Configuration for the leak-ceiling report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeakCeilingConfig {
    /// Chaining-graph isomorph window length used for the headline supply.
    pub chaining_window_len: usize,
    /// Chaining-graph repeated-core length used for the headline supply.
    pub chaining_core_len: usize,
    /// Short isomorph reference window whose dominant signature pins the supply.
    pub isomorph_window_len: usize,
}

impl Default for LeakCeilingConfig {
    fn default() -> Self {
        Self {
            chaining_window_len: DEFAULT_CHAINING_WINDOW_LEN,
            chaining_core_len: DEFAULT_CHAINING_CORE_LEN,
            isomorph_window_len: DEFAULT_ISOMORPH_WINDOW_LEN,
        }
    }
}

/// Error returned by the leak-ceiling report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeakCeilingError {
    /// The verified corpus could not be reconstructed or read with the order.
    Grid(GridError),
    /// A chaining-graph computation failed.
    Chaining(ChainingGraphError),
    /// The configured isomorph reference window was zero.
    ZeroIsomorphWindow,
}

impl From<GridError> for LeakCeilingError {
    fn from(value: GridError) -> Self {
        Self::Grid(value)
    }
}

impl From<ChainingGraphError> for LeakCeilingError {
    fn from(value: ChainingGraphError) -> Self {
        Self::Chaining(value)
    }
}

impl fmt::Display for LeakCeilingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Grid(error) => write!(f, "grid/order error: {error:?}"),
            Self::Chaining(error) => write!(f, "chaining-graph error: {error}"),
            Self::ZeroIsomorphWindow => write!(f, "isomorph reference window must be non-zero"),
        }
    }
}

impl std::error::Error for LeakCeilingError {}

/// Raw per-symbol successor out-degree of the reading-layer stream (Part A).
#[derive(Clone, Debug, PartialEq)]
pub struct OutDegreeSupply {
    /// Number of symbols observed as a transition source (in-message).
    pub source_symbols: usize,
    /// Mean distinct-successor count over source symbols.
    pub mean: f64,
    /// Minimum distinct-successor count over source symbols.
    pub min: usize,
    /// Maximum distinct-successor count over source symbols.
    pub max: usize,
    /// Per-step branching in bits, `log2(mean out-degree)`.
    pub branching_bits: f64,
    /// Out-degree histogram as `(distinct successors, symbol count)` pairs.
    pub histogram: Vec<(usize, usize)>,
}

/// Chaining-graph edge and coverage supply at one window/core (Part A).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainingSupply {
    /// Isomorph window length.
    pub window_len: usize,
    /// Repeated-core length.
    pub core_len: usize,
    /// Total chain links emitted.
    pub links: usize,
    /// Distinct observed contexts (occurrence pairs).
    pub distinct_contexts: usize,
    /// Distinct directed coset edges `(context, from, to)`.
    pub distinct_edges: usize,
    /// Symbols touched by at least one link.
    pub symbols_touched: usize,
    /// Connected components among touched symbols.
    pub component_count: usize,
    /// Largest connected component.
    pub largest_component: usize,
    /// Symbols touched by a repeated-core link.
    pub core_supported_symbols: usize,
    /// Largest repeated-core-only component.
    pub core_largest_component: usize,
    /// Repeated-core-only component count.
    pub core_supported_components: usize,
}

/// Repeated-isomorph occurrence-pair supply at one window (Part A).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IsomorphSupply {
    /// Window length scanned.
    pub window_len: usize,
    /// Distinct repeated informative signature kinds (pooled across messages).
    pub repeated_signature_kinds: usize,
    /// Largest occurrence count for any repeated signature (the dominant one).
    pub max_repeat_count: usize,
    /// Aligned occurrence pairs, `Σ C(occ, 2)` over repeated signatures.
    pub aligned_occurrence_pairs: usize,
    /// Informative (repeated-symbol) windows scanned, summed across messages.
    pub informative_windows: usize,
}

/// Part A — measured empirical supply.
#[derive(Clone, Debug, PartialEq)]
pub struct EmpiricalSupply {
    /// Total trigrams `M` in the accepted reading-layer stream.
    pub total_trigrams: usize,
    /// Distinct symbols observed.
    pub distinct_symbols: usize,
    /// Reading-layer alphabet size (the coset-count upper bound `N`).
    pub alphabet_size: usize,
    /// Per-message stream lengths.
    pub message_lengths: Vec<(&'static str, usize)>,
    /// Raw successor out-degree statistics.
    pub out_degree: OutDegreeSupply,
    /// Chaining supply at the configured headline window/core.
    pub chaining: ChainingSupply,
    /// Chaining supply at the sensitivity windows.
    pub chaining_sensitivity: Vec<ChainingSupply>,
    /// Isomorph occurrence-pair supply across the reported windows.
    pub isomorph: Vec<IsomorphSupply>,
    /// Empirical per-symbol entropy `H_emp`, in bits.
    pub entropy_bits_per_symbol: f64,
    /// Maximum entropy for an `N`-symbol uniform stream, in bits.
    pub max_entropy_bits_per_symbol: f64,
    /// Dominant-signature occurrence count at the isomorph reference window
    /// (length-matched analogue of G1b's `two` length-4 dominant, 76 occ).
    pub dominant_occurrences: usize,
    /// Richest dominant-signature occurrence count across the reported windows.
    pub richest_occurrences: usize,
}

/// Part B — analytic, model-conditional demand.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AnalyticDemand {
    /// Coset count `N` the demand is computed for (maximal `H = S₈₂`).
    pub cosets: usize,
    /// Edge-overlap certification degree in the sharply-transitive `S_N` regime.
    pub cert_degree_sharp: usize,
    /// Edge-overlap certification degree in a low-transitivity (dihedral) regime.
    pub cert_degree_low: usize,
    /// Coupon-collector full-pin demand `N·ln N` for `N = 12`.
    pub coupon_full_pin_n12: f64,
    /// Coupon-collector full-pin demand `N·ln N` for `N = 83`.
    pub coupon_full_pin_n83: f64,
    /// Harmonic-exact full-pin demand `N·(H_N − 1)` for the headline `N`.
    pub coupon_harmonic_exact: f64,
}

/// Part C — the combined recoverability ceiling.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CeilingEstimate {
    /// Per-element exact `≥ N−1` full-pin demand `N·(H_N−1)` (analytic; the
    /// full-collection asymptotic `N·ln N` is slightly larger).
    pub per_element_demand: f64,
    /// Per-element supply: length-matched dominant-signature occurrences.
    pub per_element_supply: usize,
    /// Shortfall ratio `demand / supply` (>1 ⇒ cannot pin even one element).
    pub per_element_shortfall_ratio: f64,
    /// Per-element supply using the richest signature across windows.
    pub per_element_supply_richest: usize,
    /// Shortfall ratio for the richest signature (most generous to recovery).
    pub per_element_shortfall_ratio_richest: f64,
    /// Mutual-information UPPER bound on leaked bits, `M·H_emp`.
    pub mi_upper_bound_bits: f64,
    /// Needed key bits under an unconstrained `S_N` neighborhood, `M·log2(N!)`.
    pub key_bits_unconstrained: f64,
    /// Underdetermination factor for the unconstrained neighborhood.
    pub underdetermination_unconstrained: f64,
    /// `log2` of the near-identity (≤4-swap) per-letter neighborhood.
    pub near_identity_neighborhood_log2: f64,
    /// Needed key bits under the near-identity neighborhood.
    pub key_bits_near_identity: f64,
    /// Underdetermination factor for the near-identity neighborhood.
    pub underdetermination_near_identity: f64,
    /// Predicted undecidable fraction for the eyes (coverage model, w4-matched).
    pub eyes_undecidable_fraction: f64,
    /// Predicted uniquely-covered fraction for the eyes.
    pub eyes_unique_fraction: f64,
    /// Predicted undecidable fraction using the richest signature (robustness).
    pub eyes_undecidable_richest: f64,
}

/// One point on the scaling sweep over coset count `N`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ScalingPoint {
    /// Coset count `N`.
    pub cosets: usize,
    /// Analytic dominant-signature supply `occ(N) = M/N`.
    pub occurrences: f64,
    /// Predicted undecidable fraction at this `N` (fixed `M`).
    pub undecidable_fraction: f64,
}

/// Part D — scaling sweep and crossings.
#[derive(Clone, Debug, PartialEq)]
pub struct ScalingSweep {
    /// Fixed stream length `M` used across the sweep.
    pub fixed_m: usize,
    /// Sweep points for `N = 2 … 83` (the `N = 12 … 83` band is eyes-relevant;
    /// the smaller-`N` tail locates the 50% crossing).
    pub points: Vec<ScalingPoint>,
    /// Smallest `N` whose undecidable fraction crosses 50%.
    pub crossing_50: Option<usize>,
    /// Smallest `N` whose undecidable fraction crosses 90%.
    pub crossing_90: Option<usize>,
}

/// Part D — single-point geometry calibration against G1b's measured `two`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CalibrationControl {
    /// `two` coset count fed to the model.
    pub cosets: usize,
    /// `two` stream length fed to the model.
    pub stream_len: usize,
    /// `two` dominant-signature occurrences fed to the model.
    pub dominant_occurrences: usize,
    /// `two` raw out-degree fed to the model.
    pub out_degree: usize,
    /// Predicted undecidable fraction for `two`.
    pub predicted_undecidable: f64,
    /// Predicted uniquely-covered fraction for `two`.
    pub predicted_unique: f64,
    /// G1b-measured undecidable band lower edge.
    pub measured_undecidable_low: f64,
    /// G1b-measured undecidable band upper edge.
    pub measured_undecidable_high: f64,
    /// Whether the prediction lands inside the measured band.
    pub passes: bool,
    /// Eyes undecidable fractions for `G ∈ {1, 2, 3}` (robustness band).
    pub eyes_undecidable_g_band: [f64; 3],
}

/// Complete leak-ceiling report.
#[derive(Clone, Debug, PartialEq)]
pub struct LeakCeilingReport {
    /// Configuration used for the run.
    pub config: LeakCeilingConfig,
    /// Part A — measured supply.
    pub supply: EmpiricalSupply,
    /// Part B — analytic demand.
    pub demand: AnalyticDemand,
    /// Part C — combined ceiling.
    pub ceiling: CeilingEstimate,
    /// Part D — single-point geometry calibration.
    pub calibration: CalibrationControl,
    /// Part D — scaling sweep.
    pub scaling: ScalingSweep,
}

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

fn out_degree_supply(message_values: &[Vec<TrigramValue>]) -> OutDegreeSupply {
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

fn chaining_supply(
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

fn isomorph_supply(message_values: &[Vec<TrigramValue>], window_len: usize) -> IsomorphSupply {
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

// ---------------------------------------------------------------------------
// Entry point.
// ---------------------------------------------------------------------------

/// Runs the G3 leak-ceiling report over the verified eye corpus.
///
/// # Errors
/// Returns [`LeakCeilingError`] when the corpus cannot be reconstructed, a
/// chaining-graph computation fails, or the isomorph reference window is zero.
pub fn run_leak_ceiling(config: LeakCeilingConfig) -> Result<LeakCeilingReport, LeakCeilingError> {
    if config.isomorph_window_len == 0 {
        return Err(LeakCeilingError::ZeroIsomorphWindow);
    }
    let grids = orders::corpus_grids()?;
    let order = orders::accepted_honeycomb_order();
    let message_values = read_corpus_message_values(&grids, order)?;

    let total_trigrams: usize = message_values.iter().map(Vec::len).sum();
    let distinct_symbols = message_values
        .iter()
        .flat_map(|values| values.iter().map(|value| value.get()))
        .collect::<BTreeSet<u8>>()
        .len();
    let message_lengths: Vec<(&'static str, usize)> = grids
        .iter()
        .map(crate::analysis::orders::GlyphGrid::message_key)
        .zip(message_values.iter().map(Vec::len))
        .collect();

    let out_degree = out_degree_supply(&message_values);
    let chaining = chaining_supply(
        &message_values,
        config.chaining_window_len,
        config.chaining_core_len,
    )?;
    let mut chaining_sensitivity = Vec::with_capacity(CHAINING_SENSITIVITY.len());
    for (window_len, core_len) in CHAINING_SENSITIVITY {
        chaining_sensitivity.push(chaining_supply(&message_values, window_len, core_len)?);
    }
    let isomorph: Vec<IsomorphSupply> = ISOMORPH_WINDOWS
        .iter()
        .map(|window_len| isomorph_supply(&message_values, *window_len))
        .collect();

    let flatness = ReadingLayerFlatnessStats::from_message_values(&message_values);
    let dominant_occurrences =
        isomorph_supply(&message_values, config.isomorph_window_len).max_repeat_count;
    let richest_occurrences = isomorph
        .iter()
        .map(|supply| supply.max_repeat_count)
        .max()
        .unwrap_or(dominant_occurrences);

    let supply = EmpiricalSupply {
        total_trigrams,
        distinct_symbols,
        alphabet_size: READING_LAYER_ALPHABET_SIZE,
        message_lengths,
        out_degree,
        chaining,
        chaining_sensitivity,
        isomorph,
        entropy_bits_per_symbol: flatness.entropy_bits_per_symbol,
        max_entropy_bits_per_symbol: flatness.max_entropy_bits_per_symbol,
        dominant_occurrences,
        richest_occurrences,
    };

    let demand = analytic_demand(READING_LAYER_ALPHABET_SIZE);
    let ceiling = ceiling_estimate(&supply);
    let calibration = calibration_control(&supply);
    let scaling = scaling_sweep(total_trigrams);

    Ok(LeakCeilingReport {
        config,
        supply,
        demand,
        ceiling,
        calibration,
        scaling,
    })
}

fn analytic_demand(cosets: usize) -> AnalyticDemand {
    AnalyticDemand {
        cosets,
        cert_degree_sharp: cosets.saturating_sub(1),
        cert_degree_low: 2,
        coupon_full_pin_n12: coupon_full_pin(TWO_COSETS),
        coupon_full_pin_n83: coupon_full_pin(cosets),
        coupon_harmonic_exact: coupon_demand(cosets, cosets.saturating_sub(1)),
    }
}

fn ceiling_estimate(supply: &EmpiricalSupply) -> CeilingEstimate {
    let n = supply.alphabet_size;
    let m = supply.total_trigrams;
    // Headline demand: exact `>= N-1` cost `N*(H_N-1)` (332.2); `N*ln N` (366.8,
    // in Part B) is the slightly larger full-collection asymptotic.
    let per_element_demand = coupon_demand(n, n.saturating_sub(1));
    let per_element_supply = supply.dominant_occurrences;
    let per_element_supply_richest = supply.richest_occurrences;

    let mi_upper_bound_bits = m as f64 * supply.entropy_bits_per_symbol;
    let key_bits_unconstrained = m as f64 * log2_factorial(n);
    let near_identity = near_identity_neighborhood(n, 4);
    let near_identity_neighborhood_log2 = near_identity.log2();
    let key_bits_near_identity = m as f64 * near_identity_neighborhood_log2;

    let eyes_undecidable_fraction =
        coverage_undecidable_fraction(n, m, per_element_supply, CALIBRATED_GEOMETRY);
    let eyes_undecidable_richest =
        coverage_undecidable_fraction(n, m, per_element_supply_richest, CALIBRATED_GEOMETRY);

    CeilingEstimate {
        per_element_demand,
        per_element_supply,
        per_element_shortfall_ratio: shortfall(per_element_demand, per_element_supply),
        per_element_supply_richest,
        per_element_shortfall_ratio_richest: shortfall(
            per_element_demand,
            per_element_supply_richest,
        ),
        mi_upper_bound_bits,
        key_bits_unconstrained,
        underdetermination_unconstrained: ratio(key_bits_unconstrained, mi_upper_bound_bits),
        near_identity_neighborhood_log2,
        key_bits_near_identity,
        underdetermination_near_identity: ratio(key_bits_near_identity, mi_upper_bound_bits),
        eyes_undecidable_fraction,
        eyes_unique_fraction: 1.0 - eyes_undecidable_fraction,
        eyes_undecidable_richest,
    }
}

fn shortfall(demand: f64, supply: usize) -> f64 {
    if supply == 0 {
        f64::INFINITY
    } else {
        demand / supply as f64
    }
}

fn ratio(numerator: f64, denominator: f64) -> f64 {
    if denominator == 0.0 {
        f64::INFINITY
    } else {
        numerator / denominator
    }
}

fn calibration_control(supply: &EmpiricalSupply) -> CalibrationControl {
    let predicted_undecidable = coverage_undecidable_fraction(
        TWO_COSETS,
        TWO_STREAM_LEN,
        TWO_DOMINANT_OCCURRENCES,
        CALIBRATED_GEOMETRY,
    );
    let passes = (TWO_UNDECIDABLE_LOW..=TWO_UNDECIDABLE_HIGH).contains(&predicted_undecidable);
    let eyes_undecidable_g_band = [1.0, 2.0, 3.0].map(|geometry| {
        coverage_undecidable_fraction(
            supply.alphabet_size,
            supply.total_trigrams,
            supply.dominant_occurrences,
            geometry,
        )
    });
    CalibrationControl {
        cosets: TWO_COSETS,
        stream_len: TWO_STREAM_LEN,
        dominant_occurrences: TWO_DOMINANT_OCCURRENCES,
        out_degree: TWO_OUT_DEGREE,
        predicted_undecidable,
        predicted_unique: 1.0 - predicted_undecidable,
        measured_undecidable_low: TWO_UNDECIDABLE_LOW,
        measured_undecidable_high: TWO_UNDECIDABLE_HIGH,
        passes,
        eyes_undecidable_g_band,
    }
}

fn scaling_sweep(fixed_m: usize) -> ScalingSweep {
    let mut points = Vec::new();
    let mut crossing_50 = None;
    let mut crossing_90 = None;
    for cosets in 2..=READING_LAYER_ALPHABET_SIZE {
        let occ_f = fixed_m as f64 / cosets as f64;
        #[allow(
            clippy::cast_sign_loss,
            reason = "occ_f = M/N is strictly positive, so its rounded value is non-negative"
        )]
        let occ = occ_f.round() as usize;
        let undecidable = coverage_undecidable_fraction(cosets, fixed_m, occ, CALIBRATED_GEOMETRY);
        if crossing_50.is_none() && undecidable >= 0.50 {
            crossing_50 = Some(cosets);
        }
        if crossing_90.is_none() && undecidable >= 0.90 {
            crossing_90 = Some(cosets);
        }
        points.push(ScalingPoint {
            cosets,
            occurrences: occ_f,
            undecidable_fraction: undecidable,
        });
    }
    ScalingSweep {
        fixed_m,
        points,
        crossing_50,
        crossing_90,
    }
}

impl Report for LeakCeilingReport {
    fn render(&self) -> String {
        let mut out = String::new();
        append_header(&mut out, self);
        report::appendln!(&mut out);
        append_supply(&mut out, &self.supply, self.config.isomorph_window_len);
        report::appendln!(&mut out);
        append_demand(&mut out, &self.demand);
        report::appendln!(&mut out);
        append_ceiling(&mut out, &self.ceiling);
        report::appendln!(&mut out);
        append_calibration(&mut out, &self.calibration);
        report::appendln!(&mut out);
        append_scaling(&mut out, &self.scaling);
        report::appendln!(&mut out);
        append_interpretation(&mut out, self);
        out
    }
}

fn append_header(out: &mut String, report: &LeakCeilingReport) {
    report::appendln!(out, "G3 isomorph-leak information ceiling");
    report::appendln!(
        out,
        "order: {} (chaining window/core {}/{}, isomorph reference window {})",
        orders::accepted_honeycomb_order().name(),
        report.config.chaining_window_len,
        report.config.chaining_core_len,
        report.config.isomorph_window_len
    );
    report::appendln!(
        out,
        "labels: supply=MEASURED; demand/ceiling=ANALYTIC & model-conditional; MI figure=UPPER bound; coupon demand for maximal H=S82 (N=83 cosets) and scales DOWN with larger H"
    );
}

fn append_supply(out: &mut String, supply: &EmpiricalSupply, isomorph_window_len: usize) {
    report::appendln!(out, "Part A — empirical supply (MEASURED, read-only)");
    report::appendln!(
        out,
        "  M (trigrams): {}   distinct symbols: {}/{}",
        supply.total_trigrams,
        supply.distinct_symbols,
        supply.alphabet_size
    );
    report::appendln!(
        out,
        "  message lengths: {}",
        report::format_message_lengths(&supply.message_lengths)
    );
    report::appendln!(
        out,
        "  raw successor out-degree: source symbols {} mean {:.3} min {} max {} branching {:.3} bits",
        supply.out_degree.source_symbols,
        supply.out_degree.mean,
        supply.out_degree.min,
        supply.out_degree.max,
        supply.out_degree.branching_bits
    );
    report::appendln!(
        out,
        "    (the eyes' analogue of G1b's flat out-degree 8 on all 12 `two` symbols; here it is uneven, 3..19)"
    );
    report::appendln!(
        out,
        "  out-degree histogram (degree:symbols): {}",
        report::format_histogram(&supply.out_degree.histogram)
    );
    append_chaining_line(out, "chaining supply (headline)", supply.chaining);
    for sensitivity in &supply.chaining_sensitivity {
        append_chaining_line(out, "chaining supply (sensitivity)", *sensitivity);
    }
    report::appendln!(
        out,
        "    caveat: this is the broad gap-isomorph graph (collision-prone); full 83/83 coverage is NOT same-plaintext genuine supply (see chaining_graph.rs)."
    );
    report::appendln!(
        out,
        "  repeated-isomorph occurrence-pair supply (pooled across messages):"
    );
    for iso in &supply.isomorph {
        report::appendln!(
            out,
            "    window {:>2}: kinds {:>2} max-repeat {:>2} aligned-occ-pairs SumC(occ,2) {:>4} (redundant) informative-windows {}",
            iso.window_len,
            iso.repeated_signature_kinds,
            iso.max_repeat_count,
            iso.aligned_occurrence_pairs,
            iso.informative_windows
        );
    }
    report::appendln!(
        out,
        "  dominant signature occurrences: {} (window {}, length-matched to G1b two's 76); richest across windows: {}",
        supply.dominant_occurrences,
        isomorph_window_len,
        supply.richest_occurrences
    );
    report::appendln!(
        out,
        "  empirical per-symbol entropy H_emp: {:.4} bits (message-weighted; uniform ceiling log2(83) = {:.4})",
        supply.entropy_bits_per_symbol,
        supply.max_entropy_bits_per_symbol
    );
}

fn append_chaining_line(out: &mut String, label: &str, supply: ChainingSupply) {
    report::appendln!(
        out,
        "  {label} w{}/c{}: links {} contexts {} distinct-edges {} | touched {} comps {} largest {} | core touched {} core-comps {} core-largest {}",
        supply.window_len,
        supply.core_len,
        supply.links,
        supply.distinct_contexts,
        supply.distinct_edges,
        supply.symbols_touched,
        supply.component_count,
        supply.largest_component,
        supply.core_supported_symbols,
        supply.core_supported_components,
        supply.core_largest_component
    );
}

fn append_demand(out: &mut String, demand: &AnalyticDemand) {
    report::appendln!(out, "Part B — demand (ANALYTIC, model-conditional)");
    report::appendln!(
        out,
        "  edge-overlap certification degree t(N={}): sharp S_N regime t = N-1 = {}; low-transitivity (dihedral) t = {}",
        demand.cosets,
        demand.cert_degree_sharp,
        demand.cert_degree_low
    );
    report::appendln!(
        out,
        "  coupon-collector full-pin demand: exact >=N-1 N*(H_N-1) = {:.1} (N=83; the Part C headline demand); full-collection asymptotic N*lnN slightly larger: N=83 -> {:.1}, N=12 -> {:.1}",
        demand.coupon_harmonic_exact,
        demand.coupon_full_pin_n83,
        demand.coupon_full_pin_n12
    );
    report::appendln!(
        out,
        "  (one keystream element is fully pinned only after observing its permutation on >= N-1 of N cosets)"
    );
}

fn append_ceiling(out: &mut String, ceiling: &CeilingEstimate) {
    report::appendln!(out, "Part C — the ceiling (supply vs demand)");
    report::appendln!(
        out,
        "  per-element recurrence shortfall: demand exact >=N-1 N*(H_N-1) = {:.1} (full-collection N*lnN slightly larger); supply occ (length-matched) = {} -> shortfall {:.1}x; richest occ = {} -> shortfall {:.1}x",
        ceiling.per_element_demand,
        ceiling.per_element_supply,
        ceiling.per_element_shortfall_ratio,
        ceiling.per_element_supply_richest,
        ceiling.per_element_shortfall_ratio_richest
    );
    report::appendln!(
        out,
        "    => cannot fully pin even ONE element's S83 coset-permutation (shortfall >> 1; cf. two's ratio {:.2} < 1)",
        coupon_full_pin(TWO_COSETS) / TWO_DOMINANT_OCCURRENCES as f64
    );
    report::appendln!(
        out,
        "  MI UPPER bound on leaked bits (bounds the per-position keystream, NOT a GAK seed): M*H_emp = {:.0} bits",
        ceiling.mi_upper_bound_bits
    );
    report::appendln!(
        out,
        "  needed per-position keystream entropy (i) unconstrained S_N: M*log2(N!) = {:.0} bits -> underdetermination {:.1}x",
        ceiling.key_bits_unconstrained,
        ceiling.underdetermination_unconstrained
    );
    report::appendln!(
        out,
        "  needed per-position keystream entropy (ii) near-identity (<=4 swaps/letter): log2(neighborhood) = {:.1} bits/letter, M* = {:.0} bits -> underdetermination {:.1}x (per-symbol 41.9/5.79, independent of the M=1036 budget)",
        ceiling.near_identity_neighborhood_log2,
        ceiling.key_bits_near_identity,
        ceiling.underdetermination_near_identity
    );
    report::appendln!(
        out,
        "    => the near-identity prior is what makes recovery even conceivable ({:.0}x -> {:.0}x), but it is still > 1: too little to PIN THE PER-POSITION KEYSTREAM (a model-free chaining recovery's object), not a GAK deck seed (~log2(83!)~414 bits, which 6002 bits over-determines). This treats all M positions as independent S_N draws (maximal H=S82); under a smaller hidden subgroup the leak could suffice.",
        ceiling.underdetermination_unconstrained,
        ceiling.underdetermination_near_identity
    );
    report::appendln!(
        out,
        "  coverage model -> eyes undecidable fraction: {} (w4-matched); {} (richest signature)",
        report::format_percent(ceiling.eyes_undecidable_fraction),
        report::format_percent(ceiling.eyes_undecidable_richest)
    );
}

fn append_calibration(out: &mut String, calibration: &CalibrationControl) {
    report::appendln!(
        out,
        "Part D — single-point geometry calibration (one fitted constant; sanity check, not a licensing gate)"
    );
    report::appendln!(
        out,
        "  feed G1b two: N={} M={} dominant-occ={} out-degree={}",
        calibration.cosets,
        calibration.stream_len,
        calibration.dominant_occurrences,
        calibration.out_degree
    );
    report::appendln!(
        out,
        "  model predicts undecidable {} (unique {}); G1b measured band {}..{} undecidable -> single-point fit {} (one free constant G fit to one band; only G=2 lands: G=1->~89%, G=3->~67% -> a fit, not an independent prediction)",
        report::format_percent(calibration.predicted_undecidable),
        report::format_percent(calibration.predicted_unique),
        report::format_percent(calibration.measured_undecidable_low),
        report::format_percent(calibration.measured_undecidable_high),
        if calibration.passes {
            "IN-BAND"
        } else {
            "OUT-OF-BAND"
        }
    );
    report::appendln!(
        out,
        "    weakness (a) length-matched miss: fed two's L=4 occ=76 the model says 78.3% undecidable but G1b MEASURED L=4 is 83% (band's high edge); decodable 151.8 vs measured uniquely-covered 105 (~45% optimistic) -- only lands in band because [0.76,0.83] also spans the L=6 row.\n    weakness (b) regime mismatch: for two occ=76>N=12 the coverage factor (1-(1-1/N)^occ)=0.9987 is SATURATED (~1) and was never exercised; for the eyes occ<<N so that factor (0.10/0.27) is load-bearing -- eyes survive even at coverage=1 (~95% undecidable)."
    );
    let [g1, g2, g3] = calibration.eyes_undecidable_g_band;
    report::appendln!(
        out,
        "  eyes undecidable robustness over geometry G in {{1,2,3}}: {} / {} / {} (THIS robustness, not the calibration, carries the conclusion)",
        report::format_percent(g1),
        report::format_percent(g2),
        report::format_percent(g3)
    );
    report::appendln!(
        out,
        "  scope: calibrated at the length-4 reference window; coverage-saturated regime; not claimed to track G1b's phrase-length dependence; eyes conclusion robust to G."
    );
}

fn append_scaling(out: &mut String, scaling: &ScalingSweep) {
    report::appendln!(
        out,
        "Part D — scaling sweep undecidable_fraction(N) at fixed M = {}",
        scaling.fixed_m
    );
    report::appendln!(
        out,
        "  occ(N) = M/N (near-uniform dominant-repeat rate); geometry G = {:.0} (G1b-calibrated)",
        CALIBRATED_GEOMETRY
    );
    report::appendln!(
        out,
        "  crosses 50% at N = {}; crosses 90% at N = {}",
        scaling
            .crossing_50
            .map_or_else(|| "n/a".to_owned(), |n| n.to_string()),
        scaling
            .crossing_90
            .map_or_else(|| "n/a".to_owned(), |n| n.to_string())
    );
    for point in &scaling.points {
        if matches!(point.cosets, 4 | 12 | 20 | 32 | 50 | 83) {
            report::appendln!(
                out,
                "    N {:>2}: occ {:>5.1} undecidable {}",
                point.cosets,
                point.occurrences,
                report::format_percent(point.undecidable_fraction)
            );
        }
    }
    report::appendln!(
        out,
        "  anchors: two ~ N=12 (measured ~78-83% undecidable); eyes = N=83."
    );
}

fn append_interpretation(out: &mut String, report: &LeakCeilingReport) {
    report::appendln!(out, "Interpretation");
    report::appendln!(
        out,
        "  Wiki question \"is chaining recovery even possible for the eyes?\": the answer is a quantified NO at this trigram budget. The richest aligned isomorph signature ({} occurrences) falls {:.0}x short of the {:.0} aligned observations needed to pin even one S83 coset-permutation, and the coverage model (calibrated to reproduce G1b's two collapse) predicts ~{} of the {} transitions undecidable.",
        report.ceiling.per_element_supply_richest,
        report.ceiling.per_element_shortfall_ratio_richest,
        report.ceiling.per_element_demand,
        report::format_percent(report.ceiling.eyes_undecidable_richest),
        report.supply.total_trigrams
    );
    report::appendln!(
        out,
        "  This bounds RECOVERABILITY only; it makes NO claim that the eyes are or are not GAK. Assumptions: coupon demand for maximal H=S82 (scales down with larger H); MI figure is an UPPER bound; coverage model is analytic with one G1b-calibrated geometry constant."
    );
    report::appendln!(
        out,
        "  Claim ceiling: the eyes remain deterministic, engine-generated, strikingly structured data of unknown meaning; unsolved; no primary developer source confirms recoverable plaintext."
    );
}

#[cfg(test)]
mod tests {
    use super::{
        CALIBRATED_GEOMETRY, LeakCeilingConfig, TWO_COSETS, TWO_DOMINANT_OCCURRENCES,
        TWO_STREAM_LEN, binomial_f64, coupon_full_pin, coverage_undecidable_fraction, harmonic,
        log2_factorial, near_identity_neighborhood, odd_double_factorial, run_leak_ceiling,
    };
    use crate::report::Report;

    fn close(actual: f64, expected: f64, eps: f64) {
        assert!(
            (actual - expected).abs() <= eps,
            "expected {expected}, got {actual} (eps {eps})"
        );
    }

    #[test]
    fn analytic_primitives_are_exact() {
        close(log2_factorial(0), 0.0, 1e-12);
        close(log2_factorial(1), 0.0, 1e-12);
        close(log2_factorial(2), 1.0, 1e-12);
        close(harmonic(1), 1.0, 1e-12);
        close(harmonic(2), 1.5, 1e-12);
        close(binomial_f64(5, 2), 10.0, 1e-9);
        close(binomial_f64(83, 2), 3403.0, 1e-6);
        close(odd_double_factorial(0), 1.0, 1e-12);
        close(odd_double_factorial(1), 1.0, 1e-12);
        close(odd_double_factorial(2), 3.0, 1e-12);
        close(odd_double_factorial(3), 15.0, 1e-12);
        close(odd_double_factorial(4), 105.0, 1e-12);
        close(near_identity_neighborhood(83, 0), 1.0, 1e-12);
        close(coupon_full_pin(12), 29.818_879_797_456_006, 1e-9);
        close(coupon_full_pin(83), 366.763_770_447_117_7, 1e-9);
    }

    #[test]
    fn coverage_model_edge_cases() {
        // Empty stream is fully undecidable.
        close(coverage_undecidable_fraction(83, 0, 10, 2.0), 1.0, 1e-12);
        // Saturating occurrences drive the decodable fraction to the cap.
        close(coverage_undecidable_fraction(4, 100, 1000, 2.0), 0.0, 1e-12);
    }

    #[test]
    fn measured_supply_is_pinned() {
        let report = run_leak_ceiling(LeakCeilingConfig::default()).unwrap();
        let supply = &report.supply;
        assert_eq!(supply.total_trigrams, 1036);
        assert_eq!(supply.distinct_symbols, 83);
        assert_eq!(supply.alphabet_size, 83);
        assert_eq!(supply.out_degree.source_symbols, 83);
        assert_eq!(supply.out_degree.min, 3);
        assert_eq!(supply.out_degree.max, 19);
        close(supply.out_degree.mean, 10.240_963_855_421_686, 1e-9);
        // Headline chaining supply (broad gap-isomorph graph, deterministic).
        assert_eq!(supply.chaining.window_len, 11);
        assert_eq!(supply.chaining.links, 23232);
        assert_eq!(supply.chaining.distinct_contexts, 2112);
        assert_eq!(supply.chaining.distinct_edges, 20982);
        assert_eq!(supply.chaining.symbols_touched, 83);
        assert_eq!(supply.chaining.component_count, 1);
        assert_eq!(supply.chaining.largest_component, 83);
        // Isomorph occurrence-pair supply: scarce at short windows.
        let window4 = supply
            .isomorph
            .iter()
            .find(|iso| iso.window_len == 4)
            .unwrap();
        assert_eq!(window4.repeated_signature_kinds, 3);
        assert_eq!(window4.max_repeat_count, 9);
        assert_eq!(window4.aligned_occurrence_pairs, 56);
        assert_eq!(supply.dominant_occurrences, 9);
        assert_eq!(supply.richest_occurrences, 26);
        // Empirical entropy is near (but below) the flat 83-symbol ceiling.
        close(supply.entropy_bits_per_symbol, 5.793_2, 1e-3);
        assert!(supply.entropy_bits_per_symbol < supply.max_entropy_bits_per_symbol);
    }

    #[test]
    fn demand_and_ceiling_are_consistent() {
        let report = run_leak_ceiling(LeakCeilingConfig::default()).unwrap();
        let demand = &report.demand;
        assert_eq!(demand.cert_degree_sharp, 82);
        assert_eq!(demand.cert_degree_low, 2);
        close(demand.coupon_full_pin_n83, 366.763_770_447_117_7, 1e-6);

        let ceiling = &report.ceiling;
        // Cannot pin even one S83 element: shortfall >> 1 either way.
        assert!(ceiling.per_element_shortfall_ratio > 10.0);
        assert!(ceiling.per_element_shortfall_ratio_richest > 5.0);
        // Underdetermination: unconstrained hopeless, near-identity far closer but still > 1.
        assert!(ceiling.underdetermination_unconstrained > 50.0);
        assert!(ceiling.underdetermination_near_identity > 1.0);
        assert!(
            ceiling.underdetermination_near_identity < ceiling.underdetermination_unconstrained
        );
        // The eyes are essentially fully undecidable at this budget.
        assert!(ceiling.eyes_undecidable_fraction > 0.95);
        assert!(ceiling.eyes_undecidable_richest > 0.95);
        close(
            ceiling.eyes_unique_fraction,
            1.0 - ceiling.eyes_undecidable_fraction,
            1e-12,
        );
    }

    #[test]
    fn two_calibration_lands_in_band() {
        // Sanity check (NOT a falsifiable positive control): the single-point,
        // one-free-parameter (G) fit pins the arithmetic; only G=2 lands in band.
        let report = run_leak_ceiling(LeakCeilingConfig::default()).unwrap();
        let calibration = &report.calibration;
        let predicted = coverage_undecidable_fraction(
            TWO_COSETS,
            TWO_STREAM_LEN,
            TWO_DOMINANT_OCCURRENCES,
            CALIBRATED_GEOMETRY,
        );
        // G1b measured 76-83% undecidable (15-24% uniquely covered).
        assert!(
            (0.76..=0.83).contains(&predicted),
            "two undecidable {predicted} outside measured band 0.76..=0.83"
        );
        assert!(calibration.passes);
        assert!((0.15..=0.24).contains(&calibration.predicted_unique));
        // The eyes prediction is robust to the single geometry constant.
        for fraction in calibration.eyes_undecidable_g_band {
            assert!(
                fraction > 0.95,
                "eyes undecidable {fraction} not robustly high across G"
            );
        }
    }

    #[test]
    fn scaling_sweep_crossings_are_located() {
        let report = run_leak_ceiling(LeakCeilingConfig::default()).unwrap();
        let scaling = &report.scaling;
        assert_eq!(scaling.fixed_m, 1036);
        assert_eq!(scaling.crossing_50, Some(4));
        assert_eq!(scaling.crossing_90, Some(20));
        // The curve is monotone non-decreasing across the swept N.
        let mut previous = 0.0_f64;
        for point in &scaling.points {
            assert!(
                point.undecidable_fraction >= previous - 1e-9,
                "non-monotone at N={}",
                point.cosets
            );
            previous = point.undecidable_fraction;
        }
        // The eyes endpoint sits near the top of the curve.
        let eyes = scaling.points.last().unwrap();
        assert_eq!(eyes.cosets, 83);
        assert!(eyes.undecidable_fraction > 0.99);
    }

    #[test]
    fn report_is_deterministic_and_renders() {
        let first = run_leak_ceiling(LeakCeilingConfig::default()).unwrap();
        let second = run_leak_ceiling(LeakCeilingConfig::default()).unwrap();
        assert_eq!(first, second);
        let rendered = first.render();
        assert!(rendered.contains("G3 isomorph-leak information ceiling"));
        assert!(rendered.contains("Part D — single-point geometry calibration"));
        assert!(rendered.contains("IN-BAND"));
        assert!(rendered.contains("Claim ceiling"));
    }

    #[test]
    fn zero_isomorph_window_is_rejected() {
        let config = LeakCeilingConfig {
            isomorph_window_len: 0,
            ..LeakCeilingConfig::default()
        };
        assert!(run_leak_ceiling(config).is_err());
    }
}

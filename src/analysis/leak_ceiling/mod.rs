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

use std::collections::BTreeSet;
use std::fmt;

use crate::analysis::chaining_graph::ChainingGraphError;
use crate::analysis::orders::{
    CorpusContext, GridError, READING_LAYER_ALPHABET_SIZE, ReadingLayerFlatnessStats,
};

mod math;
mod report;
#[cfg(test)]
mod tests;

pub use math::{
    binomial_f64, coupon_demand, coupon_full_pin, coverage_decodable,
    coverage_undecidable_fraction, harmonic, log2_factorial, near_identity_neighborhood,
    odd_double_factorial,
};
use math::{chaining_supply, isomorph_supply, out_degree_supply};

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
    let CorpusContext {
        keys,
        message_values,
        ..
    } = CorpusContext::load()?;

    let total_trigrams: usize = message_values.iter().map(Vec::len).sum();
    let distinct_symbols = message_values
        .iter()
        .flat_map(|values| values.iter().map(|value| value.get()))
        .collect::<BTreeSet<u8>>()
        .len();
    let message_lengths: Vec<(&'static str, usize)> = keys
        .iter()
        .copied()
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

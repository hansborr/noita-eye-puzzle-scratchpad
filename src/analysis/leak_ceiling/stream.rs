//! File-driven stream path for the leak-supply / demand / bounds instrument.
//!
//! This is the deliberately **narrowed** off-corpus path. It exposes only the
//! transparent, control-free pieces of the leak-ceiling analysis:
//!
//! * **Part A — measured supply** (input-dependent): successor out-degree, the
//!   chaining-graph edge/coverage supply (with the *caller's* alphabet size as the
//!   coverage denominator), and repeated-isomorph occurrence counts.
//! * **Part B — analytic demand**: the coupon-collector quantities `N·ln N` and
//!   `N·(H_N − H_{N−1})` — a pure textbook function of the alphabet size `N`, with
//!   no fitted parameter.
//! * **Part C — transparent bounds**: the per-element evidence-demand / measured-
//!   supply ratio (a counting bound), the mutual-information *upper* bound
//!   `M·H_emp`, and the underdetermination factors `M·log2(neighborhood) / (M·H_emp)`.
//!   These are inequalities and counting bounds, not fitted predictions.
//!
//! The fitted coverage / "undecidable fraction" model (its free constant `G` was
//! reverse-fit to a single real measurement with no matched null and no buildable
//! positive control), the circular calibration "control", and the scaling sweep are
//! **deliberately omitted** from this path: they have no non-circular control, so
//! this instrument makes **no prediction of how much is recoverable**. The eye path
//! ([`super::run_leak_ceiling`]) keeps them unchanged.

use std::collections::BTreeSet;

use crate::analysis::analysis::message_weighted_entropy;
use crate::analysis::orders::{ReadingOrder, glyph_messages_from_values};
use crate::core::trigram::TrigramValue;

use super::math::{
    chaining_supply, coupon_demand, coupon_full_pin, isomorph_supply, log2_factorial,
    near_identity_neighborhood, out_degree_supply,
};
use super::{
    CHAINING_SENSITIVITY, EmpiricalSupply, ISOMORPH_WINDOWS, IsomorphSupply, LeakCeilingConfig,
    LeakCeilingError, ratio, shortfall,
};

/// Part B — analytic demand for a stream, a pure function of the alphabet size `N`.
///
/// No fitted parameter: every field is a textbook combinatorial quantity of `N`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StreamDemand {
    /// Alphabet size `N` (the coset-count upper bound) the demand is computed for.
    pub cosets: usize,
    /// Edge-overlap certification degree in the sharply-transitive `S_N` regime, `N-1`.
    pub cert_degree_sharp: usize,
    /// Edge-overlap certification degree in a low-transitivity (dihedral) regime, `2`.
    pub cert_degree_low: usize,
    /// Coupon-collector full-collection asymptotic demand `N·ln N`.
    pub coupon_full_pin: f64,
    /// Coupon-collector exact `>= N-1` full-pin demand `N·(H_N − H_{N−1})`.
    pub coupon_harmonic_exact: f64,
}

/// Part C — transparent bounds for a stream.
///
/// Every field is an inequality or a counting bound — there is **no** fitted
/// coverage/undecidable-fraction prediction here (that model is omitted on the
/// stream path because it has no non-circular control).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StreamCeilingBounds {
    /// Per-element exact `>= N-1` full-pin demand `N·(H_N−1)` (analytic).
    pub per_element_demand: f64,
    /// Per-element supply: length-matched dominant-signature occurrences (measured).
    pub per_element_supply: usize,
    /// Demand/supply ratio (>1 ⇒ insufficient evidence to pin even one element).
    pub per_element_shortfall_ratio: f64,
    /// Per-element supply using the richest signature across windows (most generous).
    pub per_element_supply_richest: usize,
    /// Demand/supply ratio for the richest signature.
    pub per_element_shortfall_ratio_richest: f64,
    /// Mutual-information *upper* bound on leaked bits, `M·H_emp`.
    pub mi_upper_bound_bits: f64,
    /// Needed key bits under an unconstrained `S_N` neighborhood, `M·log2(N!)`.
    pub key_bits_unconstrained: f64,
    /// Underdetermination factor for the unconstrained neighborhood (needed / leaked).
    pub underdetermination_unconstrained: f64,
    /// `log2` of the near-identity (≤4-swap) per-element neighborhood.
    pub near_identity_neighborhood_log2: f64,
    /// Needed key bits under the near-identity neighborhood, `M·log2(neighborhood)`.
    pub key_bits_near_identity: f64,
    /// Underdetermination factor for the near-identity neighborhood (needed / leaked).
    pub underdetermination_near_identity: f64,
}

/// A file-driven leak supply/demand/bounds report (the narrowed stream path).
///
/// Carries only the transparent, control-free pieces: measured supply (Part A),
/// analytic coupon-collector demand (Part B), and information-theoretic / counting
/// bounds (Part C). It does **not** carry the fitted coverage model, the calibration
/// "control", or the scaling sweep — those are gated to the eye path only.
#[derive(Clone, Debug, PartialEq)]
pub struct LeakCeilingStreamReport {
    /// Configuration used for the run.
    pub config: LeakCeilingConfig,
    /// Neutral reading order; always [`ReadingOrder::RawRows`] on the stream path.
    pub order: ReadingOrder,
    /// Part A — measured supply (alphabet size is the caller's declared `N`).
    pub supply: EmpiricalSupply,
    /// Part B — analytic coupon-collector demand over the caller's `N`.
    pub demand: StreamDemand,
    /// Part C — transparent information-theoretic / counting bounds (no prediction).
    pub bounds: StreamCeilingBounds,
}

/// Runs the narrowed leak supply/demand/bounds compute on an arbitrary
/// caller-supplied stream of one or more messages.
///
/// This is the file-driven path. It computes only the transparent, control-free
/// pieces under the neutral [`ReadingOrder::RawRows`] label, threading the caller's
/// `alphabet_size` into the chaining-graph coverage denominator (Part A), the
/// coupon-collector `N` (Part B), and the `log2(N!)` key budget (Part C). The
/// fitted coverage / undecidable-fraction model, its single-point calibration, and
/// the scaling sweep are **not** computed here — those have no non-circular control,
/// so this path makes no prediction of recoverability; it emits measurements and
/// textbook bounds only.
///
/// `keys` provides one display label per message, in the same order as
/// `message_values` (e.g. `&["input"]` for a lone stream, `&["m0", "m1", ...]` for
/// several). The labels are display-only.
///
/// # Errors
/// Returns [`LeakCeilingError`] when the isomorph reference window is zero or a
/// chaining-graph computation fails.
pub fn leak_ceiling_for_stream(
    config: LeakCeilingConfig,
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    alphabet_size: usize,
) -> Result<LeakCeilingStreamReport, LeakCeilingError> {
    if config.isomorph_window_len == 0 {
        return Err(LeakCeilingError::ZeroIsomorphWindow);
    }

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

    let out_degree = out_degree_supply(message_values);
    let chaining = chaining_supply(
        message_values,
        config.chaining_window_len,
        config.chaining_core_len,
        alphabet_size,
    )?;
    let mut chaining_sensitivity = Vec::with_capacity(CHAINING_SENSITIVITY.len());
    for (window_len, core_len) in CHAINING_SENSITIVITY {
        chaining_sensitivity.push(chaining_supply(
            message_values,
            window_len,
            core_len,
            alphabet_size,
        )?);
    }
    let isomorph: Vec<IsomorphSupply> = ISOMORPH_WINDOWS
        .iter()
        .map(|window_len| isomorph_supply(message_values, *window_len))
        .collect();

    let dominant_occurrences =
        isomorph_supply(message_values, config.isomorph_window_len).max_repeat_count;
    let richest_occurrences = isomorph
        .iter()
        .map(|supply| supply.max_repeat_count)
        .max()
        .unwrap_or(dominant_occurrences);

    let entropy_bits_per_symbol =
        message_weighted_entropy(&glyph_messages_from_values(message_values));
    let max_entropy_bits_per_symbol = if alphabet_size > 0 {
        (alphabet_size as f64).log2()
    } else {
        0.0
    };

    let supply = EmpiricalSupply {
        total_trigrams,
        distinct_symbols,
        alphabet_size,
        message_lengths,
        out_degree,
        chaining,
        chaining_sensitivity,
        isomorph,
        entropy_bits_per_symbol,
        max_entropy_bits_per_symbol,
        dominant_occurrences,
        richest_occurrences,
    };

    let demand = stream_demand(alphabet_size);
    let bounds = stream_ceiling_bounds(&supply);

    Ok(LeakCeilingStreamReport {
        config,
        order: ReadingOrder::RawRows,
        supply,
        demand,
        bounds,
    })
}

fn stream_demand(cosets: usize) -> StreamDemand {
    StreamDemand {
        cosets,
        cert_degree_sharp: cosets.saturating_sub(1),
        cert_degree_low: 2,
        coupon_full_pin: coupon_full_pin(cosets),
        coupon_harmonic_exact: coupon_demand(cosets, cosets.saturating_sub(1)),
    }
}

fn stream_ceiling_bounds(supply: &EmpiricalSupply) -> StreamCeilingBounds {
    let n = supply.alphabet_size;
    let m = supply.total_trigrams;
    let per_element_demand = coupon_demand(n, n.saturating_sub(1));
    let mi_upper_bound_bits = m as f64 * supply.entropy_bits_per_symbol;
    let key_bits_unconstrained = m as f64 * log2_factorial(n);
    let near_identity = near_identity_neighborhood(n, 4);
    let near_identity_neighborhood_log2 = near_identity.log2();
    let key_bits_near_identity = m as f64 * near_identity_neighborhood_log2;

    StreamCeilingBounds {
        per_element_demand,
        per_element_supply: supply.dominant_occurrences,
        per_element_shortfall_ratio: shortfall(per_element_demand, supply.dominant_occurrences),
        per_element_supply_richest: supply.richest_occurrences,
        per_element_shortfall_ratio_richest: shortfall(
            per_element_demand,
            supply.richest_occurrences,
        ),
        mi_upper_bound_bits,
        key_bits_unconstrained,
        underdetermination_unconstrained: ratio(key_bits_unconstrained, mi_upper_bound_bits),
        near_identity_neighborhood_log2,
        key_bits_near_identity,
        underdetermination_near_identity: ratio(key_bits_near_identity, mi_upper_bound_bits),
    }
}

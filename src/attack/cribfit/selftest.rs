//! The in-process self-test: a planted positive control that *must* fire through
//! `cribfit`'s gate, a discrimination control the filter *must* reject, and the
//! real-`one` honest negative with its documented (verified) crib anchors.

use std::collections::BTreeSet;

use crate::attack::quadgram::QuadgramModel;
use crate::attack::rlcodec::{
    BatteryCfg, RlError, derive_magnitudes, one_practice_digits, planted_positive_symbols,
};

use super::crib::crib_geometry;
use super::families::{
    AnchorConsistency, ConsistencyVerdict, CribCandidate, Tokenization, cumsum_candidate,
    mtf_candidate,
};
use super::gate::gate_candidates;
use super::{AnchorPair, run_cribfit};

/// Base of the synthetic `±1` walk / real puzzle `one`.
const BASE: usize = 5;

/// Positive-control matched-null trials (`>= 20` so the add-one p-value can clear
/// `0.05` with `ge == 0`).
const POSITIVE_NULL_TRIALS: usize = 24;
/// Positive-control search restarts (the long planted stream needs enough restarts
/// for the anneal to reliably find its English optimum).
const POSITIVE_RESTARTS: usize = 12;
/// Positive-control search proposals per restart.
const POSITIVE_ITERS: usize = 3_000;

/// Negative-control matched-null trials (the honest negative is robust to budget).
const NEGATIVE_NULL_TRIALS: usize = 20;
/// Negative-control search restarts.
const NEGATIVE_RESTARTS: usize = 6;
/// Negative-control search proposals per restart.
const NEGATIVE_ITERS: usize = 1_800;
/// Self-test census matched-null trials.
const SELFTEST_CENSUS_TRIALS: usize = 60;
/// Self-test census top-k anchors.
const SELFTEST_TOP_K: usize = 8;

/// Outcome of the self-test.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "self-test report DTO: each bool is an independent control verdict (MTF/cumsum consistency, positive/negative survival) surfaced verbatim, not a packed state machine"
)]
pub struct CribfitSelfTest {
    /// `gcd` of real `one`'s documented bit-gaps (must be `21`).
    pub gcd_bit_gaps: usize,
    /// `gcd` of real `one`'s documented run-gaps (must be `1`).
    pub gcd_run_gaps: usize,
    /// Divisors of `gcd(bit-gaps)` — the derived admissible bit-periods / cumsum
    /// moduli (`{1, 3, 7, 21}`).
    pub bit_periods: Vec<usize>,
    /// Output agreements between the two len-26 windows under single-magnitude MTF
    /// on real `one` (verified `22`; the carrier value is *not* `0`, but `< 26`).
    pub mtf_single_len26_agreements: usize,
    /// Positions compared on that anchor (must be `26`).
    pub mtf_single_len26_compared: usize,
    /// Whether single-magnitude MTF is crib-consistent on real `one` (must be
    /// `false` — it is the documented inconsistency that proves the filter bites).
    pub mtf_single_consistent: bool,
    /// Whether the discrimination control's matching-modulus cumulative-sum code is
    /// crib-consistent (must be `true` — the filter is not reject-everything).
    pub control_cumsum_consistent: bool,
    /// Whether the discrimination control's MTF is crib-consistent (must be `false`
    /// — the filter rejects a memoryful codec that breaks occurrence-equality).
    pub control_mtf_consistent: bool,
    /// Whether the planted English positive control fired through `cribfit`'s gate
    /// (must be `true`).
    pub positive_survivor: bool,
    /// Whether real `one`'s full filter produced any survivor (must be `false`).
    pub negative_overall_survivor: bool,
}

impl CribfitSelfTest {
    /// `true` only if the geometry matches the documented constraints, single-mag
    /// MTF is crib-inconsistent, the discrimination control passes a matching
    /// modulus and rejects MTF, the positive control fires, and real `one` is a
    /// negative.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.gcd_bit_gaps == 21
            && self.gcd_run_gaps == 1
            && self.bit_periods == [1, 3, 7, 21]
            && !self.mtf_single_consistent
            && self.mtf_single_len26_agreements < self.mtf_single_len26_compared
            && self.mtf_single_len26_compared == 26
            && self.control_cumsum_consistent
            && !self.control_mtf_consistent
            && self.positive_survivor
            && !self.negative_overall_survivor
    }
}

/// The positive-control gate budget (a single planted candidate can afford the
/// larger search its reliable English recovery needs).
fn positive_cfg(seed: u64) -> BatteryCfg {
    BatteryCfg {
        null_trials: POSITIVE_NULL_TRIALS,
        restarts: POSITIVE_RESTARTS,
        iters: POSITIVE_ITERS,
        top_k: SELFTEST_TOP_K,
        census_null_trials: SELFTEST_CENSUS_TRIALS,
        seed,
    }
}

/// The negative-control budget (the whole real-`one` filter, kept small).
fn negative_cfg(seed: u64) -> BatteryCfg {
    BatteryCfg {
        null_trials: NEGATIVE_NULL_TRIALS,
        restarts: NEGATIVE_RESTARTS,
        iters: NEGATIVE_ITERS,
        top_k: SELFTEST_TOP_K,
        census_null_trials: SELFTEST_CENSUS_TRIALS,
        seed,
    }
}

/// Distinct-symbol count.
fn distinct(symbols: &[usize]) -> usize {
    symbols.iter().copied().collect::<BTreeSet<usize>>().len()
}

/// A synthetic carrier with a planted exact repeat (length 8) at two run offsets
/// separated by a `[2,2,2]` filler. Its bit-gap is `27 = 3³`, so a
/// cumulative-sum-mod-3 code is crib-consistent while move-to-front (memoryful) is
/// not. Positions are computed (not hardcoded) so the anchor is exact.
fn discrimination_carrier() -> (Vec<usize>, AnchorPair) {
    let repeat = [1usize, 2, 3, 4, 1, 5, 2, 3];
    let mut magnitudes = vec![5usize, 4, 5];
    let first = magnitudes.len();
    magnitudes.extend(repeat);
    magnitudes.extend([2usize, 2, 2]);
    let second = magnitudes.len();
    magnitudes.extend(repeat);
    magnitudes.extend([3usize, 1]);
    let bit_gap: usize = magnitudes.iter().skip(first).take(second - first).sum();
    let anchor = AnchorPair {
        length: repeat.len(),
        first,
        second,
        run_gap: second - first,
        bit_gap,
    };
    (magnitudes, anchor)
}

/// Builds a pre-classified candidate around an already-gateable symbol stream (the
/// planted positive control), so the gate path itself is exercised.
fn positive_candidate(symbols: Vec<usize>) -> CribCandidate {
    let alphabet = distinct(&symbols);
    CribCandidate {
        name: "PositiveControl{plant=english-via-comma}".to_owned(),
        english_viable: true,
        alphabet,
        consistency: ConsistencyVerdict {
            anchors: vec![AnchorConsistency {
                length: symbols.len(),
                compared: symbols.len(),
                agreements: symbols.len(),
                aligned: true,
            }],
            consistent: true,
        },
        symbols,
    }
}

/// Runs the planted positive control, the discrimination control, and the real-`one`
/// honest negative.
///
/// # Errors
/// Returns [`RlError`] if the embedded fixtures fail to derive or a gate / census /
/// search step fails (it should not in a correct build).
pub fn cribfit_self_test(seed: u64) -> Result<CribfitSelfTest, RlError> {
    let model = QuadgramModel::english()?;

    // POSITIVE: the planted English-via-Comma symbol stream — a memoryless decode is
    // trivially crib-consistent, so it is gated through cribfit's own gate path and
    // must clear the matched null.
    let positive = positive_candidate(planted_positive_symbols());
    let positive_verdicts = gate_candidates(&[positive], &model, &positive_cfg(seed))?;
    let positive_survivor = positive_verdicts.first().is_some_and(|v| v.survivor);

    // DISCRIMINATION: a constructed carrier whose matching-modulus cumulative-sum is
    // consistent but whose MTF breaks occurrence-equality — the filter must accept
    // the former and reject the latter (so it is neither pass-all nor reject-all).
    let (control_m, control_anchor) = discrimination_carrier();
    let control_anchors = [control_anchor];
    let control_cumsum = cumsum_candidate(&control_m, 3, &control_anchors);
    let control_mtf = mtf_candidate(&control_m, Tokenization::Single, &control_anchors);
    let control_cumsum_consistent = control_cumsum.consistency.consistent;
    let control_mtf_consistent = control_mtf.consistency.consistent;

    // NEGATIVE + geometry: real `one`'s documented anchors give the verified
    // gcd(bit-gaps)=21 / gcd(run-gaps)=1, single-magnitude MTF is crib-inconsistent,
    // and the full filter finds no English survivor.
    let one = one_practice_digits()?;
    let derivation = derive_magnitudes(&one, BASE)?;
    let m = &derivation.magnitudes;
    let documented = [(26, 16, 69), (19, 19, 72), (19, 72, 116), (19, 19, 116)];
    let geometry = crib_geometry(m, &documented);

    let len26 = AnchorPair {
        length: 26,
        first: 16,
        second: 69,
        run_gap: 53,
        bit_gap: 105,
    };
    let mtf_single = mtf_candidate(m, Tokenization::Single, std::slice::from_ref(&len26));
    let mtf_anchor = mtf_single
        .consistency
        .anchors
        .first()
        .copied()
        .unwrap_or(AnchorConsistency {
            length: 26,
            compared: 0,
            agreements: 0,
            aligned: false,
        });

    let report = run_cribfit(&one, BASE, &negative_cfg(seed))?;

    Ok(CribfitSelfTest {
        gcd_bit_gaps: geometry.gcd_bit_gaps,
        gcd_run_gaps: geometry.gcd_run_gaps,
        bit_periods: geometry.bit_periods,
        mtf_single_len26_agreements: mtf_anchor.agreements,
        mtf_single_len26_compared: mtf_anchor.compared,
        mtf_single_consistent: mtf_single.consistency.consistent,
        control_cumsum_consistent,
        control_mtf_consistent,
        positive_survivor,
        negative_overall_survivor: report.overall_survivor,
    })
}

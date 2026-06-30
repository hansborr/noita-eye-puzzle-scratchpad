//! Tests for the crib-anchored consistency filter. These call the same library
//! functions the `cribfit` CLI handler calls, so the instrument and its regression
//! cannot drift.

use crate::attack::rlcodec::{derive_magnitudes, one_practice_digits};

use super::crib::crib_geometry;
use super::families::{Tokenization, bitperiodic_candidate, cumsum_candidate, mtf_candidate};
use super::{
    AnchorPair, BatteryCfg, CribGeometry, cribfit_self_test, derive_crib_geometry, run_cribfit,
};

/// The documented (verified) real-`one` crib pairs `(length, first, second)`.
const DOCUMENTED: [(usize, usize, usize); 4] =
    [(26, 16, 69), (19, 19, 72), (19, 72, 116), (19, 19, 116)];

/// A small, fast filter budget for the library tests (the honest negative is robust
/// to budget; this keeps `make verify` quick).
fn test_cfg(seed: u64) -> BatteryCfg {
    BatteryCfg {
        null_trials: 20,
        restarts: 5,
        iters: 1_500,
        top_k: 8,
        census_null_trials: 40,
        seed,
    }
}

fn one_magnitudes() -> Vec<usize> {
    let digits = one_practice_digits().expect("embedded one parses");
    derive_magnitudes(&digits, 5)
        .expect("one is a clean ±1 walk")
        .magnitudes
}

fn documented_geometry() -> CribGeometry {
    crib_geometry(&one_magnitudes(), &DOCUMENTED)
}

fn bitperiodic_divisibility_carrier() -> (Vec<usize>, AnchorPair) {
    let repeat = [1usize, 1, 1];
    let mut magnitudes = vec![2usize];
    let first = magnitudes.len();
    magnitudes.extend(repeat);
    magnitudes.push(1);
    let second = magnitudes.len();
    magnitudes.extend(repeat);
    let bit_gap = magnitudes.iter().skip(first).take(second - first).sum();
    let anchor = AnchorPair {
        length: repeat.len(),
        first,
        second,
        run_gap: second - first,
        bit_gap,
    };
    (magnitudes, anchor)
}

#[test]
fn documented_anchors_give_the_verified_lattice() {
    let geometry = documented_geometry();
    assert_eq!(geometry.gcd_bit_gaps, 21, "gcd(bit-gaps) must be 21");
    assert_eq!(geometry.gcd_run_gaps, 1, "gcd(run-gaps) must be 1");
    assert_eq!(geometry.bit_periods, vec![1, 3, 7, 21]);
    assert_eq!(geometry.run_periods, vec![1]);
    // Per-anchor gaps match the documented census geometry.
    let len26 = geometry
        .anchors
        .iter()
        .find(|a| a.length == 26)
        .expect("len-26 anchor present");
    assert_eq!((len26.run_gap, len26.bit_gap), (53, 105));
}

#[test]
fn derived_geometry_agrees_with_the_documented_lattice() {
    // The CLI's find_anchors-driven derivation must reproduce the documented gcds.
    let (geometry, census) =
        derive_crib_geometry(&one_magnitudes(), 8, 60, 0x0c41_b817_dead_0001).expect("census runs");
    assert_eq!(geometry.gcd_bit_gaps, 21);
    assert_eq!(geometry.gcd_run_gaps, 1);
    assert_eq!(geometry.bit_periods, vec![1, 3, 7, 21]);
    // The cribs are genuinely census-significant (a structural candidate).
    assert!(census.significant);
    assert_eq!(census.observed_max, 26);
}

#[test]
fn single_magnitude_mtf_is_applicable_and_excluded_on_one() {
    // Single-magnitude MTF is per-run aligned, so the filter APPLIES; the carrier
    // value is 22/26 agreements (NOT the spec's mistaken 0/26), but 22 < 26 means the
    // windows do NOT decode identically, so it is a genuine EXCLUSION (applicable +
    // inconsistent), not a set-aside.
    let geometry = documented_geometry();
    let candidate = mtf_candidate(&one_magnitudes(), Tokenization::Single, &geometry.anchors);
    assert!(candidate.consistency.applicable, "per-run MTF aligns to M");
    assert!(
        candidate.consistency.excluded(),
        "single-magnitude MTF must be applicable + inconsistent = excluded"
    );
    assert!(!candidate.consistency.consistent);
    assert!(!candidate.consistency.inapplicable());
    let len26 = candidate
        .consistency
        .anchors
        .iter()
        .find(|a| a.length == 26)
        .expect("len-26 anchor scored");
    assert_eq!(len26.compared, 26);
    assert_eq!(len26.agreements, 22, "verified agreement count");
    assert!(len26.aligned);
}

#[test]
fn variable_length_mtf_is_inapplicable_not_excluded_on_one() {
    // The pair/comma/term tokenizations' boundaries do not align across the cribs
    // (the odd run-gaps shift their phase; comma drops separator runs), so they are
    // INAPPLICABLE — set aside, never reported as a crib-inconsistency exclusion.
    let geometry = documented_geometry();
    let m = one_magnitudes();
    for tok in [
        Tokenization::Pair { phase: 0 },
        Tokenization::Comma { sep: 2 },
    ] {
        let candidate = mtf_candidate(&m, tok, &geometry.anchors);
        assert!(
            candidate.consistency.inapplicable(),
            "{tok:?} must be inapplicable (misaligned), not excluded"
        );
        assert!(!candidate.consistency.excluded());
        assert!(!candidate.consistency.consistent);
    }
}

#[test]
fn cumsum_mod_21_is_crib_consistent_english_viable() {
    let geometry = documented_geometry();
    let m = one_magnitudes();
    let candidate = cumsum_candidate(&m, 21, &geometry.anchors);
    assert!(
        candidate.consistency.consistent,
        "21 | every bit-gap, so cumsum mod 21 must be crib-consistent"
    );
    assert_eq!(candidate.alphabet, 21);
    assert!(candidate.english_viable);
    assert!(candidate.gateable());
}

#[test]
fn cumsum_mod_3_is_consistent_but_not_english_viable() {
    let geometry = documented_geometry();
    let candidate = cumsum_candidate(&one_magnitudes(), 3, &geometry.anchors);
    assert!(candidate.consistency.consistent, "3 | every bit-gap");
    assert!(
        !candidate.english_viable,
        "a 3-symbol alphabet is below MIN_LETTERS"
    );
    assert!(!candidate.gateable());
}

#[test]
fn bitperiodic_symbols_are_the_augmented_magnitude_coset_partition() {
    let magnitudes = vec![2usize, 1, 2, 3, 1, 2, 1];
    let p = 3usize;
    let candidate = bitperiodic_candidate(&magnitudes, p, &[]);
    let mut prefix = 0usize;
    let mut cosets = Vec::with_capacity(magnitudes.len());
    for &m in &magnitudes {
        cosets.push(prefix % p);
        prefix += m;
    }

    let augmented = magnitudes
        .iter()
        .copied()
        .zip(cosets)
        .zip(candidate.symbols.iter().copied())
        .map(|((m, coset), symbol)| (m, coset, symbol))
        .collect::<Vec<_>>();
    for (i, (m_i, coset_i, symbol_i)) in augmented.iter().copied().enumerate() {
        for (j, (m_j, coset_j, symbol_j)) in augmented.iter().copied().enumerate() {
            let same_augmented = m_i == m_j && coset_i == coset_j;
            assert_eq!(
                symbol_i == symbol_j,
                same_augmented,
                "symbol equality must exactly match (M, exclusive-prefix mod p) equality at {i}/{j}"
            );
        }
    }
}

#[test]
fn bitperiodic_consistency_follows_bit_gap_divisibility() {
    let (magnitudes, anchor) = bitperiodic_divisibility_carrier();
    assert_eq!(anchor.bit_gap, 4);
    let anchors = [anchor];

    let divisible = bitperiodic_candidate(&magnitudes, 2, &anchors);
    assert!(
        divisible.consistency.consistent,
        "2 | bit-gap, so the augmented cosets match across the repeat"
    );

    let non_divisible = bitperiodic_candidate(&magnitudes, 3, &anchors);
    assert!(
        non_divisible.consistency.excluded(),
        "p not dividing the bit-gap is per-run aligned but crib-inconsistent"
    );
    assert!(non_divisible.consistency.applicable);
    assert!(!non_divisible.consistency.consistent);
}

#[test]
fn bitperiodic_alphabet_sizes_regress_on_one() {
    let geometry = documented_geometry();
    let m = one_magnitudes();
    for (p, expected_alphabet) in [(1usize, 5usize), (3, 14), (7, 24), (21, 47)] {
        let candidate = bitperiodic_candidate(&m, p, &geometry.anchors);
        assert_eq!(
            candidate.alphabet, expected_alphabet,
            "real one BitPeriodicSubst(p={p}) alphabet size changed"
        );
        assert!(
            candidate.consistency.consistent,
            "p={p} divides every documented bit-gap and must be crib-consistent"
        );
    }
}

#[test]
fn bitperiodic_english_viability_flags_regress_on_one() {
    let geometry = documented_geometry();
    let m = one_magnitudes();
    for (p, english_viable) in [(1usize, false), (3, true), (7, true), (21, false)] {
        let candidate = bitperiodic_candidate(&m, p, &geometry.anchors);
        assert_eq!(
            candidate.english_viable, english_viable,
            "real one BitPeriodicSubst(p={p}) english-viable flag changed"
        );
    }
}

#[test]
fn real_one_yields_no_english_survivor() {
    let digits = one_practice_digits().expect("embedded one parses");
    let report = run_cribfit(&digits, 5, &test_cfg(0x0c41_b817_0000_0042)).expect("filter runs");
    assert!(
        !report.overall_survivor,
        "real one must be an honest negative: surviving candidates = {:?}",
        report
            .gated
            .iter()
            .filter(|v| v.survivor)
            .map(|v| (v.codec_name.clone(), v.z, v.p))
            .collect::<Vec<_>>()
    );
    assert!(report.has_cribs());
    // The English-viable crib-consistent candidates gated are cumsum mod 21 and
    // the bit-periodic keyed substitutions whose augmented alphabets fit in A..Z.
    assert!(
        report
            .gated
            .iter()
            .any(|v| v.codec_name == "CumulativeSumMod{n=21}"),
        "cumsum mod 21 must reach the gate: {:?}",
        report
            .gated
            .iter()
            .map(|v| &v.codec_name)
            .collect::<Vec<_>>()
    );
    assert!(
        report
            .gated
            .iter()
            .any(|v| v.codec_name == "BitPeriodicSubst{p=3}"),
        "bitperiodic p=3 must reach the gate"
    );
    assert!(
        report
            .gated
            .iter()
            .any(|v| v.codec_name == "BitPeriodicSubst{p=7}"),
        "bitperiodic p=7 must reach the gate"
    );
    assert!(
        !report
            .gated
            .iter()
            .any(|v| v.codec_name == "BitPeriodicSubst{p=21}"),
        "bitperiodic p=21 has alphabet 47 and must be reported in Section B, not gated"
    );
}

#[test]
fn self_test_passes() {
    let report = cribfit_self_test(0x0c41_b817_5e1f_0001).expect("self-test runs");
    assert!(report.passed(), "self-test must pass: {report:?}");
}

#[test]
fn discrimination_control_separates_memoryless_from_memoryful() {
    let report = cribfit_self_test(0x0c41_b817_d15c_0001).expect("self-test runs");
    assert!(
        report.control_cumsum_consistent,
        "matching-modulus cumsum must be crib-consistent (filter is not reject-all)"
    );
    assert!(
        !report.control_mtf_consistent,
        "memoryful MTF on the control must be crib-inconsistent (filter is not pass-all)"
    );
}

#[test]
fn positive_control_fires_through_the_gate() {
    let report = cribfit_self_test(0x0c41_b817_900d_0001).expect("self-test runs");
    assert!(
        report.positive_survivor,
        "the planted English positive control must clear the matched null inside cribfit"
    );
}

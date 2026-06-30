//! Tests for the key-difference discriminator. They exercise the same library
//! functions the `keydiff` CLI calls: the modular difference channels, the
//! `δ`-versus-gap regression, the verdict assembly, the orchestration error
//! paths, and the full self-test (planted controls + matched null).

use crate::analysis::translate_isomorph::RepeatAnchor;
use crate::nulls::null::{SplitMix64, random_index_below};

use super::{
    AutokeyFamily, DEFAULT_SEED, KeyDiffError, KeyDiffVerdict, RegressionFit, autokey_family,
    difference_channel, fit_regression, key_difference_scan, key_difference_self_test,
    verdict_from,
};

#[test]
fn difference_channel_is_the_modular_finite_difference() {
    let values = [0u16, 3, 7, 8];
    assert_eq!(difference_channel(&values, 12, 0), vec![0, 3, 7, 8]);
    // 1st difference mod 12: 3, 4, 1.
    assert_eq!(difference_channel(&values, 12, 1), vec![3, 4, 1]);
    // 2nd difference mod 12: 1, 9 (4-3=1, 1-4=-3≡9).
    assert_eq!(difference_channel(&values, 12, 2), vec![1, 9]);
}

#[test]
fn difference_channel_wraps_through_the_modulus() {
    // 2 - 10 = -8 ≡ 4 (mod 12); 0 - 2 = -2 ≡ 10 (mod 12).
    assert_eq!(difference_channel(&[10, 2, 0], 12, 1), vec![4, 10]);
}

#[test]
fn regression_reads_a_shared_slope_as_progressive() {
    // c[i] = (i + 5*i) over m = 12; the same single value, so δ = 5*gap.
    // Build anchors with gaps whose δ ≡ 5*gap (mod 12): construct a raw stream
    // c[i] = (5*i) mod 12 so c[second]-c[first] = 5*(second-first).
    let raw: Vec<u16> = (0..300u16)
        .map(|i| (5 * usize::from(i) % 12) as u16)
        .collect();
    let anchors = vec![
        RepeatAnchor {
            length: 10,
            first: 10,
            second: 121,
            gap: 111,
        },
        RepeatAnchor {
            length: 10,
            first: 10,
            second: 140,
            gap: 130,
        },
    ];
    let fit = fit_regression(&raw, 12, &anchors);
    assert_eq!(fit.pairs, 2);
    assert_eq!(fit.distinct_gaps, 2);
    assert_eq!(fit.best_slope, 5);
    assert_eq!(fit.consistent_pairs, 2);
    assert_eq!(
        autokey_family(&fit),
        AutokeyFamily::ProgressiveAlphabet { slope: 5 }
    );
}

#[test]
fn regression_with_one_gap_is_indeterminate() {
    let fit = RegressionFit {
        pairs: 1,
        distinct_gaps: 1,
        best_slope: 3,
        consistent_pairs: 1,
    };
    assert_eq!(autokey_family(&fit), AutokeyFamily::SingleGap);
}

#[test]
fn regression_without_a_shared_slope_is_classical_autokey() {
    let fit = RegressionFit {
        pairs: 3,
        distinct_gaps: 3,
        best_slope: 1,
        consistent_pairs: 1,
    };
    assert_eq!(autokey_family(&fit), AutokeyFamily::ClassicalAutokey);
}

#[test]
fn verdict_maps_each_firing_order() {
    assert_eq!(
        verdict_from(Some(0), None, true),
        KeyDiffVerdict::IdenticalKey
    );
    assert!(matches!(
        verdict_from(Some(1), None, true),
        KeyDiffVerdict::ConstantAdditive {
            family: AutokeyFamily::SingleGap
        }
    ));
    assert_eq!(
        verdict_from(Some(2), None, true),
        KeyDiffVerdict::LinearAdditive
    );
    assert_eq!(
        verdict_from(Some(4), None, true),
        KeyDiffVerdict::HigherOrderAdditive { order: 4 }
    );
    assert_eq!(verdict_from(None, None, true), KeyDiffVerdict::Irregular);
    assert_eq!(verdict_from(None, None, false), KeyDiffVerdict::NoSignal);
}

#[test]
fn scan_rejects_invalid_configuration() {
    assert_eq!(
        key_difference_scan(&[0, 1, 2, 3], 0, 2, 4, 8, 16, DEFAULT_SEED),
        Err(KeyDiffError::EmptyAlphabet)
    );
    assert_eq!(
        key_difference_scan(&[0], 12, 2, 4, 8, 16, DEFAULT_SEED),
        Err(KeyDiffError::StreamTooShort { length: 1 })
    );
}

#[test]
fn scan_rejects_zero_null_trials() {
    // With zero matched-null trials no order can be significant and the
    // gap-pattern certificate has no null to clear, so a significance-bearing
    // verdict (including `Irregular`) would be emitted with no null actually run.
    // The scan must reject the configuration rather than emit an uncalibrated
    // verdict.
    assert_eq!(
        key_difference_scan(&[0, 1, 2, 3, 0, 1, 2, 3], 12, 3, 4, 8, 0, DEFAULT_SEED),
        Err(KeyDiffError::NoNullTrials)
    );
}

#[test]
fn scan_classifies_a_constant_offset_repeat_as_order_one() {
    // A random base stream with a phrase planted twice, the second occurrence
    // shifted by a constant +4 (a constant Δ): the raw stream shows no repeat but
    // the 1st-difference channel does (the constant offset cancels under one
    // differencing).
    let m = 12usize;
    let mut rng = SplitMix64::new(0x0bad_f00d);
    let mut stream: Vec<u16> = Vec::with_capacity(400);
    for _ in 0..400 {
        stream.push(u16::try_from(random_index_below(m, &mut rng).expect("draw")).unwrap_or(0));
    }
    let mut phrase: Vec<u16> = Vec::with_capacity(40);
    for _ in 0..40 {
        phrase.push(u16::try_from(random_index_below(m, &mut rng).expect("draw")).unwrap_or(0));
    }
    if let Some(slot) = stream.get_mut(30..70) {
        slot.copy_from_slice(&phrase);
    }
    let modulus = u16::try_from(m).unwrap_or(1);
    let shifted: Vec<u16> = phrase.iter().map(|&v| (v + 4) % modulus).collect();
    if let Some(slot) = stream.get_mut(250..290) {
        slot.copy_from_slice(&shifted);
    }
    let report = key_difference_scan(&stream, m, 3, 8, 8, 64, DEFAULT_SEED).expect("scan runs");
    assert_eq!(report.fired_order, Some(1), "constant Δ fires at order 1");
    assert!(matches!(
        report.verdict,
        KeyDiffVerdict::ConstantAdditive { .. }
    ));
}

#[test]
fn structureless_stream_is_no_signal_not_irregular() {
    // A random stream has no additive firing AND no *significant* relabelled
    // repeat: its window-8 repeated-signature count does not clear the order-1
    // Markov null. The null-calibrated certificate must therefore stay absent, so
    // the verdict is the honest `NoSignal` — never `Irregular` sold on a
    // chance-level certificate (the failure mode the calibration removes).
    let m = 12usize;
    let mut rng = SplitMix64::new(0x5eed_1234);
    let mut stream: Vec<u16> = Vec::with_capacity(420);
    for _ in 0..420 {
        stream.push(u16::try_from(random_index_below(m, &mut rng).expect("draw")).unwrap_or(0));
    }
    let report = key_difference_scan(&stream, m, 3, 8, 8, 200, DEFAULT_SEED).expect("scan runs");
    assert_eq!(report.fired_order, None, "no additive order fires on noise");
    assert!(
        !report.gap_certificate.present,
        "the gap-pattern certificate must not clear its null on a structureless stream \
         (observed {} vs null ceiling {})",
        report.gap_certificate.observed_groups, report.gap_certificate.null_ceiling
    );
    assert_eq!(
        report.verdict,
        KeyDiffVerdict::NoSignal,
        "a chance-level certificate must yield NoSignal, not Irregular"
    );
}

#[test]
fn self_test_passes_on_all_planted_controls() {
    let result = key_difference_self_test(DEFAULT_SEED).expect("self-test runs");
    assert!(
        result.ctak_constant,
        "ciphertext-autokey classifies order 1"
    );
    assert!(result.vigenere_identical, "Vigenère classifies order 0");
    assert!(
        result.progressive_family,
        "progressive classifies progressive"
    );
    assert!(result.deck_irregular, "deck relabel classifies Irregular");
    assert!(result.null_agreement, "matched null agreement");
    assert!(result.passed);
}

#[test]
fn self_test_is_seed_robust() {
    for seed in [1u64, 0x1234_5678, DEFAULT_SEED, 0xdead_beef] {
        let result = key_difference_self_test(seed).expect("self-test runs");
        assert!(result.passed, "self-test failed for seed {seed:#x}");
    }
}

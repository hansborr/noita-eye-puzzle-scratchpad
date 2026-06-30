//! Tests for the run-length codec battery. These call the same library functions
//! the `rlcodec` CLI handler calls, so the instrument and its regression cannot
//! drift.

use crate::analysis::translate_isomorph::markov_resample;
use crate::core::glyph::Glyph;
use crate::nulls::null::SplitMix64;

use super::derive::synthesize_walk;
use super::{
    BatteryCfg, RlCodec, RlError, derive_magnitudes, magnitude_carrier, one_practice_digits,
    parse_base_digits, rlcodec_self_test, run_battery,
};

/// A deliberately small, fast battery budget for the library tests. The honest
/// negative is robust to budget (every real-`one` codec scores below its
/// symbol-stream Markov null regardless of search strength); this keeps
/// `make verify` quick.
fn test_cfg(seed: u64) -> BatteryCfg {
    BatteryCfg {
        null_trials: 20,
        restarts: 5,
        iters: 1_500,
        top_k: 6,
        census_null_trials: 40,
        seed,
    }
}

#[test]
fn derive_recovers_one_magnitude_carrier() {
    let digits = one_practice_digits().expect("embedded one parses");
    assert_eq!(digits.len(), 266);
    let derivation = derive_magnitudes(&digits, 5).expect("one is a clean ±1 walk");
    assert_eq!(derivation.n_bits, 265);
    assert_eq!(derivation.n_up, 125);
    assert_eq!(derivation.n_down, 140);
    assert_eq!(derivation.magnitudes.len(), 135);

    // Distribution {1:64, 2:34, 3:17, 4:18, 5:2}.
    let mut counts = std::collections::BTreeMap::new();
    for &magnitude in &derivation.magnitudes {
        *counts.entry(magnitude).or_insert(0usize) += 1;
    }
    assert_eq!(
        counts.into_iter().collect::<Vec<_>>(),
        vec![(1, 64), (2, 34), (3, 17), (4, 18), (5, 2)]
    );

    // The load-bearing bit-complemented 26-run repeat M[16..42] == M[69..95]
    // with opposite run-direction parity.
    let mag = &derivation.magnitudes;
    assert_eq!(mag.get(16..42), mag.get(69..95));
    let dir = &derivation.run_directions;
    assert_ne!(
        dir.get(16),
        dir.get(69),
        "the two occurrences must start on opposite run-direction parity"
    );

    // The 19-run message-end repeat M[116..135] == M[72..91] == M[19..38].
    assert_eq!(mag.get(116..135), mag.get(72..91));
    assert_eq!(mag.get(116..135), mag.get(19..38));
}

#[test]
fn non_unit_step_input_is_rejected() {
    // 0 -> 2 mod 5 is a +2 move, not ±1.
    let digits: Vec<Glyph> = [0u16, 2, 3].into_iter().map(Glyph).collect();
    assert!(matches!(
        derive_magnitudes(&digits, 5),
        Err(RlError::NonUnitStep { .. })
    ));
}

#[test]
fn parse_base_digits_matches_alphabet_parse() {
    let digits = parse_base_digits("0123 43210\n", 5).expect("digits parse");
    let expected: Vec<Glyph> = [0u16, 1, 2, 3, 4, 3, 2, 1, 0]
        .into_iter()
        .map(Glyph)
        .collect();
    assert_eq!(digits, expected);
    assert!(matches!(
        parse_base_digits("5", 5),
        Err(RlError::InvalidDigit { .. })
    ));
}

#[test]
fn positive_control_comma_codec_is_a_survivor_and_recovers_the_plant() {
    let report = rlcodec_self_test(0x0011_2233_4455_6677).expect("self-test runs");
    assert!(
        report.positive_survivor,
        "planted English-via-Comma must clear the matched null: {report:?}"
    );
    assert!(
        report.positive_partition_recovered,
        "the planted symbol partition must be recovered exactly: {report:?}"
    );
}

#[test]
fn real_one_yields_no_survivor() {
    let digits = one_practice_digits().expect("embedded one parses");
    let report = run_battery(&digits, 5, &test_cfg(0xA11C_0DEC_0000_0001)).expect("battery runs");
    assert!(
        !report.overall_survivor,
        "real one must be an honest negative: surviving codecs = {:?}",
        report
            .verdicts
            .iter()
            .filter(|verdict| verdict.survivor)
            .map(|verdict| (verdict.codec_name.clone(), verdict.z, verdict.p))
            .collect::<Vec<_>>()
    );
    // The census, by contrast, IS significant: the magnitude carrier genuinely
    // repeats (the direction-blind structure) — a structural candidate, not a
    // decode.
    assert!(report.census.significant);
    assert_eq!(report.census.observed_max, 26);
}

#[test]
fn self_test_passes() {
    let report = rlcodec_self_test(0x5e1f_7e57_0000_0001).expect("self-test runs");
    assert!(report.passed(), "self-test must pass: {report:?}");
}

#[test]
fn markov_resampled_carrier_yields_no_survivor() {
    // A pure order-1 Markov-resampled-M null has no chunk structure, so no codec
    // should survive — the gate does not manufacture a false positive.
    let digits = one_practice_digits().expect("embedded one parses");
    let derivation = derive_magnitudes(&digits, 5).expect("clean walk");
    let (stream, alphabet) = magnitude_carrier(&derivation.magnitudes);
    let mut rng = SplitMix64::new(0xBEEF_F00D_0000_0001);
    let resampled = markov_resample(&stream, alphabet, &mut rng).expect("resample");
    let resampled_mags: Vec<usize> = resampled.iter().map(|&value| value as usize + 1).collect();
    let null_digits = synthesize_walk(&resampled_mags, 5);
    let report =
        run_battery(&null_digits, 5, &test_cfg(0xBEEF_F00D_0000_0002)).expect("battery runs");
    assert!(
        !report.overall_survivor,
        "a Markov-resampled-M null must not survive: {:?}",
        report
            .verdicts
            .iter()
            .filter(|verdict| verdict.survivor)
            .map(|verdict| verdict.codec_name.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn comma_codec_decode_is_relabel_invariant() {
    // Two letters -> distinct tuples, comma-separated, decode to the partition.
    // Tuple A = [1], tuple B = [2,2]; plaintext "ABAB" -> [1,4,2,2,4,1,4,2,2].
    let magnitudes = vec![1usize, 4, 2, 2, 4, 1, 4, 2, 2];
    let decoded = RlCodec::Comma { sep: 4 }.decode(&magnitudes);
    assert_eq!(decoded, Some(vec![0usize, 1, 0, 1]));
}

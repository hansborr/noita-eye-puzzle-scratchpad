//! Tests for the bigram-order codec gate.

use crate::attack::rlcodec::{derive_magnitudes, one_practice_digits};

use super::{
    BIGRAM_PLANT_TEXT, BigramCfg, DEFAULT_SEED, HonestVerdict, READABLE_MIN, SURVIVOR_ALPHA,
    StreamKind, analyze_bigramcodec, bigramcodec_self_test, readable_coverage, tokenize,
};

fn test_cfg(seed: u64) -> BigramCfg {
    BigramCfg {
        null_trials: 20,
        restarts: 3,
        iters: 350,
        seed,
    }
}

#[test]
fn tokenization_shapes_match_practice_one() {
    let digits = one_practice_digits().expect("embedded one parses");
    let derivation = derive_magnitudes(&digits, 5).expect("one is a clean walk");

    let digit_pairs =
        tokenize(StreamKind::DigitPairs, &digits, &derivation.magnitudes, 5).expect("tokenize");
    assert_eq!(digit_pairs.tokens.len(), 133);
    assert_eq!(digit_pairs.distinct_count(), 10);
    assert_eq!(digit_pairs.dropped_tail, 0);

    let edges = tokenize(StreamKind::Edges, &digits, &derivation.magnitudes, 5).expect("tokenize");
    assert_eq!(edges.tokens.len(), 265);
    assert_eq!(edges.distinct_count(), 10);
    assert_eq!(edges.dropped_tail, 0);

    let mag_pairs =
        tokenize(StreamKind::MagPairs, &digits, &derivation.magnitudes, 5).expect("tokenize");
    assert_eq!(mag_pairs.tokens.len(), 67);
    assert_eq!(mag_pairs.distinct_count(), 14);
    assert_eq!(mag_pairs.dropped_tail, 1);
}

#[test]
fn readable_coverage_counts_distinct_crib_words() {
    assert_eq!(readable_coverage("rain rain wind road"), 3);
    assert!(readable_coverage(BIGRAM_PLANT_TEXT) >= READABLE_MIN);
    assert_eq!(readable_coverage("QZXJKVBNM"), 0);
}

#[test]
fn self_test_positive_fires_and_real_one_is_not_readable() {
    let report = bigramcodec_self_test(DEFAULT_SEED).expect("self-test runs");
    assert!(report.passed(), "self-test must pass: {report:?}");
    assert!(report.positive_readability_coverage >= READABLE_MIN);
    assert!(report.positive_beats_order0);
    assert!(
        !report.positive_beats_order1,
        "order-1 must stay documented as underpowered on the English plant: {report:?}"
    );
    assert!(report.positive_order1_p >= SURVIVOR_ALPHA);
    assert!(report.negative_max_readability_coverage < READABLE_MIN);
}

#[test]
fn real_one_is_not_readable_at_test_budget() {
    let digits = one_practice_digits().expect("embedded one parses");
    let report = analyze_bigramcodec(
        &digits,
        5,
        &[
            StreamKind::DigitPairs,
            StreamKind::Edges,
            StreamKind::MagPairs,
        ],
        &test_cfg(0x6269_6772_0000_1001),
    )
    .expect("analysis runs");

    let max_readability = report
        .streams
        .iter()
        .flat_map(|stream| stream.languages.iter())
        .map(|row| row.readability_coverage)
        .max()
        .unwrap_or(0);
    assert!(
        max_readability < READABLE_MIN,
        "real one must not clear readability coverage: {max_readability}"
    );
    assert!(
        !report.has_candidate(),
        "real one must not produce readable candidate rows: {:?}",
        candidate_rows(&report)
    );
}

#[test]
fn analysis_is_deterministic_for_fixed_seed() {
    let digits = one_practice_digits().expect("embedded one parses");
    let cfg = BigramCfg {
        null_trials: 4,
        restarts: 2,
        iters: 120,
        seed: 0x6269_6772_0000_2001,
    };
    let left = analyze_bigramcodec(&digits, 5, &[StreamKind::MagPairs], &cfg).expect("left run");
    let right = analyze_bigramcodec(&digits, 5, &[StreamKind::MagPairs], &cfg).expect("right run");
    assert_eq!(left, right);
}

fn candidate_rows(
    report: &super::BigramReport,
) -> Vec<(&'static str, &'static str, HonestVerdict)> {
    report
        .streams
        .iter()
        .flat_map(|stream| {
            stream.languages.iter().map(move |row| {
                (
                    stream.stream.kind.label(),
                    row.language.label(),
                    row.verdict,
                )
            })
        })
        .filter(|(_stream, _language, verdict)| *verdict == HonestVerdict::Candidate)
        .collect()
}

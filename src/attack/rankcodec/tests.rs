//! Tests for the predictive-rank codec instrument.

use crate::attack::rlcodec::{BatteryCfg, PLANT_PLAINTEXT, english_letters, one_practice_digits};
use crate::nulls::null::{SplitMix64, random_index_below};

use super::{
    DEFAULT_MAX_MAGNITUDE, DEFAULT_SEED, RankCfg, RankCribStatus, RankPredictor,
    analyze_magnitudes, analyze_rank_codec, crib_summary, rank_decode, rank_encode,
    rankcodec_self_test,
};

fn source() -> Vec<usize> {
    english_letters(PLANT_PLAINTEXT)
}

fn test_cfg(seed: u64) -> BatteryCfg {
    BatteryCfg {
        null_trials: 16,
        restarts: 4,
        iters: 800,
        top_k: 8,
        census_null_trials: 24,
        seed,
    }
}

fn rank_cfg(seed: u64) -> RankCfg {
    RankCfg {
        source_letters: source(),
        orders: vec![1, 2, 3],
        max_magnitude: DEFAULT_MAX_MAGNITUDE,
        gate: test_cfg(seed),
    }
}

#[test]
fn rank_codec_round_trips_multiple_sequences() {
    let pred = RankPredictor::train(&source(), 3);
    for letters in [
        source(),
        english_letters("THERAINTHERAINTHERAIN"),
        (0usize..26).collect::<Vec<_>>(),
    ] {
        let encoded = rank_encode(&pred, &letters);
        let decoded = rank_decode(&pred, &encoded);
        assert_eq!(decoded, letters);
    }
}

#[test]
fn predictor_rankings_are_total_and_deterministic() {
    let pred = RankPredictor::train(&source(), 2);
    for context in [Vec::new(), english_letters("TH"), english_letters("ZX")] {
        let ranked_a = pred.ranked(&context);
        let ranked_b = pred.ranked(&context);
        assert_eq!(ranked_a, ranked_b);

        let mut sorted = ranked_a.to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted, (0usize..26).collect::<Vec<_>>());
        for letter in 0usize..26 {
            let rank = pred.rank_of(&context, letter);
            assert_eq!(ranked_a.get(rank - 1).copied(), Some(letter));
        }
    }
}

#[test]
fn crib_consistency_detects_locking_and_non_locking_repeats() {
    let pred = RankPredictor::train(&source(), 3);
    let (_plant, locking, anchor) = super::selftest::build_positive_plant(&pred);
    let decoded = rank_decode(&pred, &locking);
    let consistent = crib_summary(&decoded, &[anchor], pred.order());
    assert_eq!(consistent.status, RankCribStatus::Consistent);

    let (non_locking, anchor) = super::selftest::build_inconsistent_carrier();
    let decoded = rank_decode(&pred, &non_locking);
    let inconsistent = crib_summary(&decoded, &[anchor], pred.order());
    assert_eq!(inconsistent.status, RankCribStatus::Excluded);
}

#[test]
fn feasibility_coverage_is_monotone_on_the_built_in_english() {
    let letters = source();
    let coverage = (1usize..=3)
        .map(|order| {
            let pred = RankPredictor::train(&letters, order);
            let ranks = rank_encode(&pred, &letters);
            let report = super::feasibility(&ranks, DEFAULT_MAX_MAGNITUDE);
            report.fraction_within_max
        })
        .collect::<Vec<_>>();
    assert!(coverage.windows(2).all(|pair| match pair {
        [previous, next] => next >= previous,
        _ => true,
    }));
}

#[test]
fn real_one_reports_every_swept_order() {
    let digits = one_practice_digits().expect("embedded one parses");
    let report =
        analyze_rank_codec(&digits, 5, &rank_cfg(0x7261_6e6b_0000_0001)).expect("analysis runs");
    assert_eq!(
        report.rows.iter().map(|row| row.order).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert!(report.rows.iter().all(|row| row.gate.evaluated));
}

#[test]
fn matched_null_plumbing_accepts_positive_and_keeps_random_control_low() {
    let pred = RankPredictor::train(&source(), 3);
    let (plant, magnitudes, anchor) = super::selftest::build_positive_plant(&pred);
    let recovered = rank_decode(&pred, &magnitudes);
    assert_eq!(recovered, plant);
    let gate = super::selftest::positive_gate(&pred, &magnitudes, &[anchor], 0x7261_6e6b_900d_0001)
        .expect("positive gate runs");
    assert!(gate.survivor, "positive should fire: {gate:?}");

    let mut rng = SplitMix64::new(0x7261_6e6b_5eed_0001);
    let random_m = (0..magnitudes.len())
        .map(|_index| random_index_below(DEFAULT_MAX_MAGNITUDE, &mut rng).map(|v| v + 1))
        .collect::<Result<Vec<_>, _>>()
        .expect("random draws");
    let random_decoded = rank_decode(&pred, &random_m);
    let cfg = test_cfg(0x7261_6e6b_5eed_0002);
    let report = analyze_magnitudes(
        random_m.len() + 1,
        5,
        random_m.iter().sum(),
        &random_m,
        &RankCfg {
            source_letters: source(),
            orders: vec![3],
            max_magnitude: DEFAULT_MAX_MAGNITUDE,
            gate: cfg,
        },
    )
    .expect("random control runs");
    assert!(report.rows.first().is_some_and(|row| !row.gate.survivor) || random_decoded.len() < 8);
}

#[test]
fn self_test_passes() {
    let report = rankcodec_self_test(DEFAULT_SEED).expect("self-test runs");
    assert!(report.passed(), "self-test must pass: {report:?}");
}

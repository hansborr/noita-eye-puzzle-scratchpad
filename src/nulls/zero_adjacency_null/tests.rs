use super::{
    ShuffleBandPosition, ZeroAdjacencyNullConfig, adjacency_summary, analyze_message_values,
    positive_controls, run_zero_adjacency_null,
};
use crate::core::trigram::TrigramValue;
use crate::nulls::null::{NullSampler, SplitMix64, WithinMessageShuffle};

const FLOAT_RELATIVE_EPSILON: f64 = 1.0e-12;

fn assert_relative_close(actual: f64, expected: f64, label: &str) {
    let tolerance = expected.abs() * FLOAT_RELATIVE_EPSILON;
    let difference = (actual - expected).abs();
    assert!(
        difference <= tolerance,
        "{label} changed: actual={actual:.17e} expected={expected:.17e} diff={difference:.17e} tolerance={tolerance:.17e}"
    );
}

#[test]
fn analytic_expected_count_matches_hand_calculation() {
    let keys = ["toy"];
    let messages = vec![values(&[1, 1, 1, 2, 2])];

    let summary = adjacency_summary(&keys, &messages).unwrap();

    assert_eq!(summary.adjacent_equal, 3);
    assert_eq!(summary.comparisons, 4);
    assert_relative_close(summary.analytic_expected, 1.6, "analytic expected");
    assert_relative_close(summary.rate, 0.75, "rate");
}

#[test]
fn shuffle_null_preserves_message_multisets_and_lengths() {
    let messages = vec![values(&[0, 0, 1, 1, 2, 2]), values(&[3, 3, 4])];
    let sampler = WithinMessageShuffle {
        messages: &messages,
    };
    let mut rng = SplitMix64::new(0x5151);

    let shuffled = sampler.sample(&mut rng).unwrap();

    assert_eq!(shuffled.len(), messages.len());
    for (original, shuffled_message) in messages.iter().zip(&shuffled) {
        let mut original_sorted = original.clone();
        let mut shuffled_sorted = shuffled_message.clone();
        original_sorted.sort_unstable();
        shuffled_sorted.sort_unstable();
        assert_eq!(shuffled_message.len(), original.len());
        assert_eq!(shuffled_sorted, original_sorted);
    }
}

#[test]
fn shuffle_null_is_reproducible_for_fixed_seed() {
    let config = ZeroAdjacencyNullConfig {
        seed: 0x5eed,
        trials_per_seed: 16,
        seed_count: 2,
    };
    let keys = ["toy"];
    let messages = vec![values(&[0, 0, 0, 1, 1, 1, 2, 2, 2])];

    let first = analyze_message_values(config, &keys, &messages).unwrap();
    let second = analyze_message_values(config, &keys, &messages).unwrap();

    assert_eq!(first, second);
    assert_eq!(first.null.trials, 32);
    assert!(first.null.mean > 0.0);
}

#[test]
fn positive_controls_separate_free_and_no_repeat_regimes() {
    let config = ZeroAdjacencyNullConfig {
        seed: 0x5150,
        trials_per_seed: 256,
        seed_count: 2,
    };

    let controls = positive_controls(config).unwrap();

    assert_eq!(
        controls.free_permutation.band_position,
        ShuffleBandPosition::Within
    );
    assert!(
        controls.free_permutation.observed.adjacent_equal > 0,
        "free control should contain ordinary adjacent equal pairs"
    );
    assert_eq!(
        controls.no_repeat_successor.band_position,
        ShuffleBandPosition::Below
    );
    assert_eq!(controls.no_repeat_successor.observed.adjacent_equal, 0);
    assert!(controls.no_repeat_successor.null.q025 > 0);
    assert!(
        controls.no_repeat_successor.empirical_p <= 0.01,
        "p={}",
        controls.no_repeat_successor.empirical_p
    );
}

#[test]
fn eye_zero_adjacency_headline_numbers_are_pinned() {
    let report = run_zero_adjacency_null(ZeroAdjacencyNullConfig::default()).unwrap();

    assert_eq!(report.order.name(), "standard36-u012-d012");
    assert_eq!(report.observed.adjacent_equal, 0);
    assert_eq!(report.observed.comparisons, 1_027);
    assert_relative_close(
        report.observed.analytic_expected,
        12.008_220_182_690_058,
        "eye analytic expected",
    );
    assert_eq!(report.empirical_p_count, 0);
    assert_relative_close(
        report.empirical_p,
        0.000_199_960_007_998_400_3,
        "eye empirical p",
    );
    assert_eq!(report.band_position, ShuffleBandPosition::Below);
    assert!(report.significant);
}

fn values(raw_values: &[u8]) -> Vec<TrigramValue> {
    raw_values
        .iter()
        .copied()
        .map(|raw| TrigramValue::new(raw).unwrap())
        .collect()
}

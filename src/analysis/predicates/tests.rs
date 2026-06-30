//! Tests for the Toboter predicate battery. They exercise the same library
//! functions the `predscan` CLI calls: the shared `missing_gap_sizes` gap
//! primitive, each predicate's statistic, both null samplers, the meta-analysis,
//! and the full planted self-test (positive controls + matched non-satisfying
//! nulls across both null shapes).

use crate::core::trigram::TrigramValue;
use crate::nulls::null::{NullSampler, SplitMix64};

use super::{
    GapProfile, MetaAnalysis, NullShape, Predicate, ValueResample, bonferroni_adjusted,
    first_two_non_coprime, has_two_digit_prime_factor, is_abab_decimal, message_sum,
    missing_gap_sizes, only_one_missing_run, predicate_self_test, run_battery, sidak_adjusted,
};

fn msg(values: &[u8]) -> Vec<TrigramValue> {
    values
        .iter()
        .map(|&value| TrigramValue::new(value).expect("planted values are in range"))
        .collect()
}

#[test]
fn abab_decimal_shape() {
    assert!(is_abab_decimal(4040));
    assert!(is_abab_decimal(5656));
    assert!(is_abab_decimal(4545));
    assert!(is_abab_decimal(7272));
    assert!(!is_abab_decimal(1234));
    assert!(!is_abab_decimal(4000)); // 4,0,0,0
    assert!(!is_abab_decimal(999)); // too short
    assert!(!is_abab_decimal(12345)); // too long
}

#[test]
fn two_digit_prime_factor_trial_division() {
    // The abab corpus sums are 101 * smooth -> no two-digit prime factor.
    assert!(!has_two_digit_prime_factor(4040)); // 2^3 * 5 * 101
    assert!(!has_two_digit_prime_factor(5656)); // 2^3 * 7 * 101
    assert!(!has_two_digit_prime_factor(0)); // treated as no factor
    assert!(!has_two_digit_prime_factor(49)); // 7^2, single-digit prime only
    assert!(has_two_digit_prime_factor(4042)); // 2 * 43 * 47
    assert!(has_two_digit_prime_factor(77)); // 7 * 11
    assert!(has_two_digit_prime_factor(121)); // 11^2
}

#[test]
fn first_two_coprimality() {
    assert!(first_two_non_coprime(&msg(&[6, 4]))); // gcd 2
    assert!(first_two_non_coprime(&msg(&[6, 9, 1]))); // gcd 3
    assert!(!first_two_non_coprime(&msg(&[3, 5]))); // gcd 1
    assert!(!first_two_non_coprime(&msg(&[7]))); // too short
}

#[test]
fn message_sum_is_base10_total() {
    assert_eq!(message_sum(&msg(&[10, 20, 12])), 42);
    assert_eq!(message_sum(&[]), 0);
}

#[test]
fn missing_gap_primitive_ties_to_profile() {
    // value 0 recurs at distance 2 (pos 0,2); value 6 at distance 2 (pos 3,5).
    // Realized = {2}, max realized 2, so the only missing size in 1..=2 is 1.
    let messages = vec![msg(&[0, 5, 0, 6, 7, 6])];
    let profile = GapProfile::of(&messages);
    assert_eq!(profile.max_realized, 2);
    assert!(profile.only_missing_one());
    // The shared primitive, called at the profile's d_max, agrees with the profile.
    assert_eq!(
        missing_gap_sizes(&messages, profile.max_realized),
        profile.missing
    );
    assert_eq!(profile.missing.into_iter().collect::<Vec<_>>(), vec![1]);
    // The early-stopping run statistic agrees with the profile field and reaches 2.
    assert_eq!(profile.only_one_missing_run, 2);
    assert_eq!(only_one_missing_run(&messages), 2);
    assert_eq!(Predicate::OnlyMissingGapOne.statistic(&messages), 2);
    assert!(Predicate::OnlyMissingGapOne.satisfied(&messages));
}

#[test]
fn only_one_missing_run_stops_at_first_hole_and_doubles_zero_it() {
    // Distances 2,3,4 realized, 1 absent, hole at 5 -> run length 4.
    // value a recurs at 2 (0,2), b at 3 (4,7), c at 4 (8,12); no distance-1 or -5.
    let messages = vec![msg(&[1, 9, 1, 9, 2, 8, 7, 2, 3, 8, 7, 6, 3])];
    assert_eq!(only_one_missing_run(&messages), 4);
    // A doubled trigram (distance 1) collapses the run to 0.
    let doubled = vec![msg(&[1, 1, 2, 5, 2])];
    assert_eq!(only_one_missing_run(&doubled), 0);
    assert!(!Predicate::OnlyMissingGapOne.satisfied(&doubled));
}

#[test]
fn missing_gap_primitive_extends_past_six() {
    // A repeat at distance 9 must be detected (the OrderStats array caps at 6).
    let mut values = vec![40u8];
    values.extend(std::iter::repeat_n(7u8, 8)); // 8 fillers
    values.push(40); // value 40 recurs at distance 9
    let messages = vec![msg(&values)];
    let profile = GapProfile::of(&messages);
    assert_eq!(profile.max_realized, 9);
    assert!(profile.realized.contains(&9));
    // Distances 1..=8 are all absent here.
    assert!(missing_gap_sizes(&messages, 9).contains(&8));
}

#[test]
fn gap_predicate_adjacency_breaks_it() {
    // Adding an adjacent-equal pair realizes distance 1, so it is no longer missing.
    let messages = vec![msg(&[0, 5, 0, 6, 7, 6, 9, 9])];
    let profile = GapProfile::of(&messages);
    assert!(profile.realized.contains(&1));
    assert!(!profile.only_missing_one());
    assert_eq!(Predicate::OnlyMissingGapOne.statistic(&messages), 0);
}

#[test]
fn value_resample_matches_lengths_and_pool() {
    let messages = vec![msg(&[1, 2, 3]), msg(&[40, 50])];
    let sampler = ValueResample::new(&messages);
    let mut rng = SplitMix64::new(0x1234);
    let draw = sampler.sample(&mut rng).expect("in-bounds draw");
    assert_eq!(draw.len(), 2);
    assert_eq!(draw.first().map(Vec::len), Some(3));
    assert_eq!(draw.get(1).map(Vec::len), Some(2));
    let pool: Vec<u8> = vec![1, 2, 3, 40, 50];
    for message in &draw {
        for value in message {
            assert!(pool.contains(&value.get()));
        }
    }
}

#[test]
fn predicate_statistics_count_satisfying_units() {
    let messages = vec![msg(&[50, 5, 5]), msg(&[10, 5, 5])];
    // Only the first message starts above 26.
    assert_eq!(Predicate::StartingTrigramAbove.statistic(&messages), 1);
    assert_eq!(Predicate::StartingTrigramAbove.unit_total(&messages), 2);
    assert!(!Predicate::StartingTrigramAbove.satisfied(&messages));
    // Null shapes are assigned per family.
    assert_eq!(
        Predicate::OnlyMissingGapOne.null_shape(),
        NullShape::WithinMessageShuffle
    );
    assert_eq!(
        Predicate::AbabDecimalSum.null_shape(),
        NullShape::ValueResample
    );
}

#[test]
fn meta_analysis_corrections_are_monotone() {
    // Bonferroni dominates Sidak, and a small p with K=5 still scales up.
    let k = 5;
    assert!(bonferroni_adjusted(0.001, k) >= sidak_adjusted(0.001, k));
    assert!((bonferroni_adjusted(0.001, k) - 0.005).abs() < 1e-9);
    assert!(bonferroni_adjusted(0.5, k) <= 1.0); // clamps at 1
}

#[test]
fn battery_runs_and_reports_five_predicates() {
    let messages = vec![
        msg(&[50, 4, 6, 8]),
        msg(&[40, 9, 3, 7]),
        msg(&[30, 5, 5, 5]),
    ];
    let report = run_battery(&messages, 83, 0xabc, 200, 400).expect("battery runs");
    assert_eq!(report.outcomes.len(), 5);
    assert_eq!(report.meta.k, 5);
    let summed: f64 = report.outcomes.iter().map(|outcome| outcome.p_value).sum();
    assert!((report.meta.expected_survivors - summed).abs() < 1e-9);
    assert!(report.meta.expected_survivors >= 0.0 && report.meta.expected_survivors <= 5.0);
    // Every p-value is a valid add-one estimator in (0, 1].
    for outcome in &report.outcomes {
        assert!(outcome.p_value > 0.0 && outcome.p_value <= 1.0);
    }
}

#[test]
fn meta_analysis_from_outcomes_matches_run() {
    let messages = vec![msg(&[50, 4, 6, 8]), msg(&[40, 9, 3, 7])];
    let report = run_battery(&messages, 83, 0xfeed, 150, 300).expect("battery runs");
    let recomputed = MetaAnalysis::of(&report.outcomes);
    assert_eq!(recomputed, report.meta);
}

#[test]
fn self_test_all_controls_pass() {
    let result = predicate_self_test(0x5eed);
    for check in &result.checks {
        assert!(check.passed, "control failed: {}", check.name);
    }
    assert!(result.passed);
    assert_eq!(result.checks.len(), 10);
}

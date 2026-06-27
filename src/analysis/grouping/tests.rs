use super::{
    CALIBRATION_STATES, GroupingAxis, calibrate_state_count, run_experiment8,
    synthetic_state_messages,
};
use crate::analysis::analysis;
use crate::nulls::null::SplitMix64;

fn grouping(report: &super::Experiment8Report, axis: GroupingAxis) -> &super::GroupingRow {
    report
        .groupings
        .iter()
        .find(|row| row.axis == axis)
        .unwrap()
}

#[test]
fn grouping_report_preserves_experiment_4_trigram_anchor() {
    let report = run_experiment8().unwrap();
    let trigram = grouping(&report, GroupingAxis::OrientationBase5 { width: 3 });
    assert_eq!(trigram.axis.nominal_base(), 125);
    assert_eq!(trigram.pooled.symbols, 1036);
    assert_eq!(trigram.pooled.used_alphabet, 83);
    assert_eq!(trigram.dropped_source_symbols, 0);
    assert!(
        (trigram.pooled.entropy_bits_per_symbol - 6.272_507_154_513_793).abs() < 1e-12,
        "trigram entropy changed: {}",
        trigram.pooled.entropy_bits_per_symbol
    );
    assert!(
        (trigram.pooled.ioc * 83.0 - 1.066_043_683_434_987_8).abs() < 1e-12,
        "trigram concatenated x83 IoC changed: {}",
        trigram.pooled.ioc * 83.0
    );
}

#[test]
fn grouping_numbers_are_deterministic_across_axes() {
    let report = run_experiment8().unwrap();
    let singles = grouping(&report, GroupingAxis::OrientationBase5 { width: 1 });
    let pairs = grouping(&report, GroupingAxis::OrientationBase5 { width: 2 });
    let tetragrams = grouping(&report, GroupingAxis::OrientationBase5 { width: 4 });
    let storage = grouping(&report, GroupingAxis::EngineStorageBase7);

    assert_eq!(singles.pooled.used_alphabet, 5);
    assert_eq!(singles.pooled.symbols, 3108);
    assert_eq!(pairs.pooled.used_alphabet, 25);
    assert_eq!(pairs.pooled.symbols, 1552);
    assert_eq!(pairs.dropped_source_symbols, 4);
    assert_eq!(tetragrams.pooled.used_alphabet, 375);
    assert_eq!(tetragrams.pooled.symbols, 774);
    assert_eq!(tetragrams.dropped_source_symbols, 12);
    assert_eq!(storage.pooled.used_alphabet, 6);
    assert_eq!(storage.pooled.symbols, 3194);
}

#[test]
fn compatibility_is_derived_from_language_references() {
    let report = run_experiment8().unwrap();
    assert_eq!(report.language_references.len(), 2);
    assert_eq!(
        report.compatibility.nearest_alphabet_grouping,
        "pairs N=2 base25"
    );
    let fully_compatible = report.compatibility.fully_compatible_groupings();
    assert!(fully_compatible.is_empty());
    let pair_row = report
        .compatibility
        .rows
        .iter()
        .find(|row| row.grouping_label == "pairs N=2 base25")
        .unwrap();
    assert!(pair_row.alphabet_compatible);
    assert!(!pair_row.entropy_compatible);
}

#[test]
fn state_count_estimate_is_collision_based_and_compares_to_83() {
    let report = run_experiment8().unwrap();
    let estimate = &report.state_estimate;
    assert!(estimate.range.includes_83);
    assert!(estimate.range.lower < 83);
    assert!(estimate.range.upper > 83);
    assert!(
        (estimate.collision.pooled_effective_states - 77.857_972_698_228_3).abs() < 1e-12,
        "pooled state estimate changed: {}",
        estimate.collision.pooled_effective_states
    );
    assert!(
        (estimate.collision.message_weighted_effective_states - 85.410_586_552_217_45).abs()
            < 1e-12,
        "message-weighted state estimate changed: {}",
        estimate.collision.message_weighted_effective_states
    );
    assert_eq!(estimate.longest_repeated_isomorph, Some(8));
}

#[test]
fn calibration_tracks_known_state_counts_without_using_used_count_as_estimate() {
    let message_lengths = [99, 103, 118, 102, 137, 124, 119, 120, 114];
    let calibration = calibrate_state_count(0x6578_7038_7374_6174, &message_lengths).unwrap();
    let true_states: Vec<usize> = calibration.rows.iter().map(|row| row.true_states).collect();
    assert_eq!(true_states, CALIBRATION_STATES);
    assert!(calibration.applied_relative_margin < 0.12);
    for row in &calibration.rows {
        assert!(
            row.relative_error < 0.12,
            "state {} estimate drifted too far: pooled {}, message {}",
            row.true_states,
            row.pooled_effective_states,
            row.message_weighted_effective_states
        );
        assert!(
            (row.pooled_effective_states - (1.0 / row.pooled_ioc)).abs() < 1e-12,
            "state {} estimate is not derived from measured IoC",
            row.true_states
        );
        assert!(
            (row.pooled_ioc - (1.0 / row.true_states as f64)).abs() > 1e-8,
            "state {} fixture looks degenerate: measured IoC equals construction floor",
            row.true_states
        );
    }
    for pair in calibration.rows.windows(2) {
        let [left, right] = pair else {
            continue;
        };
        assert!(left.pooled_effective_states < right.pooled_effective_states);
    }
}

#[test]
fn synthetic_fixture_estimator_is_measured_from_generated_symbols() {
    let lengths = [40, 41, 42];
    let mut rng = SplitMix64::new(0x5eed);
    let messages = synthetic_state_messages(&lengths, 25, &mut rng).unwrap();
    let pooled: Vec<_> = messages.iter().flatten().copied().collect();
    let ioc = analysis::index_of_coincidence(&pooled);
    assert!(ioc > 0.0);
    let measured = 1.0 / ioc;
    assert!(measured > 18.0);
    assert!(measured < 34.0);
    assert!((measured - 25.0).abs() > 0.01);
}

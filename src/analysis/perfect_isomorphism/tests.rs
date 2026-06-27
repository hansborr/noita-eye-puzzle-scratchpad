use std::collections::BTreeSet;

use super::regression::synthetic_internal_violation_fires;
use super::{
    ALPHABET_SIZE, BreakClass, PerfectIsomorphismConfig, WikiRegressionCheck,
    report_from_message_values, run_perfect_isomorphism,
};
use crate::analysis::orders;

#[test]
fn perfect_isomorphism_run_is_deterministic_for_fixed_seed() {
    let config = PerfectIsomorphismConfig {
        seed: 0x1234,
        trials: 32,
        ..PerfectIsomorphismConfig::default()
    };

    let first = run_perfect_isomorphism(config).unwrap();
    let second = run_perfect_isomorphism(config).unwrap();

    assert_eq!(first, second);
    assert_eq!(first.order.name(), "standard36-u012-d012");
}

#[test]
fn real_eye_stream_pins_lengths_and_alphabet() {
    let config = PerfectIsomorphismConfig {
        seed: 0x5678,
        trials: 32,
        ..PerfectIsomorphismConfig::default()
    };
    let report = run_perfect_isomorphism(config).unwrap();

    assert_eq!(report.total_length, 1_036);
    assert_eq!(
        report.message_lengths,
        vec![
            ("east1", 99),
            ("west1", 103),
            ("east2", 118),
            ("west2", 102),
            ("east3", 137),
            ("west3", 124),
            ("east4", 119),
            ("west4", 120),
            ("east5", 114),
        ]
    );

    let grids = orders::corpus_grids().unwrap();
    let messages =
        orders::read_corpus_message_values(&grids, orders::accepted_honeycomb_order()).unwrap();
    let distinct = messages
        .iter()
        .flatten()
        .map(|value| value.get())
        .collect::<BTreeSet<_>>();
    assert_eq!(distinct.len(), ALPHABET_SIZE);
}

#[test]
fn positive_control_and_regressions_fire() {
    let config = PerfectIsomorphismConfig {
        seed: 0x9999,
        trials: 32,
        ..PerfectIsomorphismConfig::default()
    };
    let report = run_perfect_isomorphism(config).unwrap();

    assert!(report.positive_control_fired);
    assert_eq!(report.robust_internal_violations, 0);
    assert_eq!(report.safe_extents.len(), 16);
    assert!(report.regression.iter().all(|result| result.reproduced));
    assert!(report.regression.iter().any(|result| {
        result.check == WikiRegressionCheck::CorruptionTheoryBound
            && result.hypothesis_label.contains("conditional")
    }));
}

#[test]
fn synthetic_internal_violation_control_is_detected() {
    assert!(synthetic_internal_violation_fires().unwrap());
}

#[test]
fn invalid_window_range_is_rejected() {
    let config = PerfectIsomorphismConfig {
        seed: 1,
        trials: 1,
        min_window: 10,
        max_window: 10,
    };

    assert!(run_perfect_isomorphism(config).is_err());
}

#[test]
fn hand_built_boundary_negative_stays_boundary() {
    let left = values(&[1, 2, 1, 3, 4, 5, 6]);
    let right = values(&[9, 8, 9, 7, 6, 5, 4]);
    let break_row = super::breaks::classify_break(super::breaks::PairSlice {
        left_key: "left",
        right_key: "right",
        left_values: &left,
        right_values: &right,
        left_start: 0,
        right_start: 0,
        prefix_len: 3,
    });

    assert_eq!(break_row.class, BreakClass::Boundary);
}

#[test]
fn report_from_message_values_accepts_small_trial_fixture() {
    let grids = orders::corpus_grids().unwrap();
    let keys = grids
        .iter()
        .map(crate::analysis::orders::GlyphGrid::message_key)
        .collect::<Vec<_>>();
    let order = orders::accepted_honeycomb_order();
    let message_values = orders::read_corpus_message_values(&grids, order).unwrap();
    let config = PerfectIsomorphismConfig {
        seed: 0x4242,
        trials: 32,
        ..PerfectIsomorphismConfig::default()
    };

    let report = report_from_message_values(config, order, &keys, &message_values).unwrap();

    assert_eq!(report.robust_internal_violations, 0);
}

fn values(raw: &[u8]) -> Vec<crate::core::trigram::TrigramValue> {
    raw.iter()
        .copied()
        .map(crate::core::trigram::TrigramValue::new)
        .map(Result::unwrap)
        .collect()
}

//! Tests for the closure-shadow hidden-state key-search instrument.

use std::collections::BTreeSet;

use super::{
    Anchor, NoBasisReason, ShadowSearchConfig, ShadowSearchOutcome, control, engine,
    run_shadow_search, run_shadow_search_first_anchor_only_for_test, shadow_search_self_test,
};

const ALPHABET: &str = "ABCDEFGHIJKL";

fn parse_two() -> Vec<u16> {
    const TWO: &str = include_str!("../../../research/data/practice-puzzles/two");
    TWO.chars()
        .filter_map(|ch| {
            if ch.is_whitespace() {
                None
            } else {
                ALPHABET
                    .chars()
                    .position(|candidate| candidate == ch)
                    .map(|index| u16::try_from(index).unwrap_or(0))
            }
        })
        .collect()
}

#[test]
fn self_test_controls_pass() {
    let report = shadow_search_self_test(0x7368_6164_6f77_0001).expect("self-test runs");
    assert!(report.positive_truth_survived, "{report:?}");
    assert!(report.positive_truth_in_pass1_survivors, "{report:?}");
    assert!(report.positive_pass1_filtered, "{report:?}");
    assert!(
        u128::from(report.positive_pass1_survivor_keys) < report.positive_key_space,
        "{report:?}"
    );
    assert!(report.positive_truth_at_max_soft, "{report:?}");
    assert_eq!(report.positive_closure_order, 6);
    assert!(report.untrimmed_anchor_killed_truth, "{report:?}");
    assert!(report.trimmed_anchor_retained_truth, "{report:?}");
    assert!(report.markov_null_no_basis, "{report:?}");
    assert_eq!(
        report.markov_null_reason,
        Some(NoBasisReason::NoSignificantIsomorphStructure)
    );
    assert!(report.passed, "{report:?}");
}

#[test]
fn real_two_reproduces_stage2_known_answer_counts() {
    let values = parse_two();
    let config = ShadowSearchConfig {
        class_report_limit: 4,
        ..ShadowSearchConfig::default()
    };
    let report = run_shadow_search(&values, 12, config).expect("search runs");
    // These assertions pin derived output surfaces recorded in the dossier.
    // They are not production inputs or hardcoded search seeds.
    assert_eq!(
        report.closure.as_ref().map(|closure| closure.order),
        Some(48)
    );
    assert_eq!(report.legal_readouts, vec![1, 2, 4, 5, 7, 8, 10, 11]);
    assert_eq!(
        report
            .fibers
            .iter()
            .map(|fiber| fiber.size)
            .collect::<Vec<_>>(),
        vec![4; 8]
    );
    assert_eq!(report.key_space, Some(3_145_728));
    assert_eq!(
        report
            .hard_anchors
            .iter()
            .map(|anchor| (anchor.first, anchor.second, anchor.length))
            .collect::<std::collections::BTreeSet<_>>(),
        [
            (25, 111, 29),
            (9, 559, 45),
            (234, 508, 38),
            (235, 355, 61),
            (355, 509, 37),
            (111, 575, 29),
            (330, 488, 13),
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(report.soft_anchors.len(), 17);
    let ShadowSearchOutcome::Searched { summary, .. } = report.outcome else {
        panic!("real two should search");
    };
    assert_eq!(summary.total_keys, 3_145_728);
    assert_eq!(summary.pass1_survivor_keys, 835_520);
    assert_eq!(summary.pass2_survivor_keys, 104_096);
    assert_eq!(summary.deduped_sequences, 104_096);
    assert_eq!(summary.max_soft_score, 12);
    assert_eq!(summary.soft_anchor_count, 17);
    assert_eq!(summary.max_soft_sequence_count, 96);
    assert_eq!(summary.max_soft_canonical_class_count, 24);
}

#[test]
fn first_hard_anchor_rejects_a_first_anchor_only_negative_in_pass1() {
    let (values, alphabet_size) = control::first_anchor_negative_fixture_for_test();
    let config = ShadowSearchConfig {
        class_report_limit: 0,
        top_k: 2,
        ..control::control_config_for_test(0x6669_7273_7400_0001)
    };
    let report = run_shadow_search_first_anchor_only_for_test(&values, alphabet_size, config)
        .expect("first-anchor-only search runs");
    assert_eq!(report.hard_anchors.len(), 2);
    let first_anchor = report
        .hard_anchors
        .first()
        .expect("fixture has a first hard anchor");
    let closure = report.closure.as_ref().expect("fixture derives a closure");
    let basis = engine::prepare_basis(&values, alphabet_size, closure).expect("basis prepares");
    let witness = engine::first_anchor_rejection_witness_for_test(&values, &basis, first_anchor)
        .expect("expected a full-stream-legal key rejected by the first hard anchor");
    assert!(!spans_equal(&witness, first_anchor));

    let ShadowSearchOutcome::Searched {
        summary,
        survivors: first_anchor_survivors,
    } = report.outcome
    else {
        panic!("first-anchor-only fixture search should run");
    };
    assert!(u128::from(summary.pass1_survivor_keys) < summary.total_keys);
    assert_eq!(summary.pass1_survivor_keys, summary.pass2_survivor_keys);
    let surviving_sequences: BTreeSet<Vec<u16>> = first_anchor_survivors
        .into_iter()
        .map(|survivor| survivor.q_sequence)
        .collect();
    assert!(!surviving_sequences.contains(&witness));
}

fn spans_equal(sequence: &[u16], anchor: &Anchor) -> bool {
    let left = sequence.get(anchor.first..anchor.first + anchor.length);
    let right = sequence.get(anchor.second..anchor.second + anchor.length);
    left.zip(right).is_some_and(|(left, right)| left == right)
}

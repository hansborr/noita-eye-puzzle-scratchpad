//! Tests for the closure-shadow hidden-state key-search instrument.

use super::{
    NoBasisReason, ShadowSearchConfig, ShadowSearchOutcome, run_shadow_search,
    shadow_search_self_test,
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
    assert_eq!(summary.pass2_survivor_keys, 104_096);
    assert_eq!(summary.deduped_sequences, 104_096);
    assert_eq!(summary.max_soft_score, 12);
    assert_eq!(summary.soft_anchor_count, 17);
    assert_eq!(summary.max_soft_sequence_count, 96);
    assert_eq!(summary.max_soft_canonical_class_count, 24);
}

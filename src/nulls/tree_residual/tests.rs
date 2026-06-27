use super::compute::{
    MessageSegments, cross_message_statistic, max_vec_capacity_for, report_from_message_values,
    residual_segment_messages, run_tree_residual, seed_batches,
};
use super::{CrossTailStatistic, TreeResidualConfig, TreeResidualError, TreeResidualScope};
use crate::analysis::orders;
use crate::core::trigram::TrigramValue;
use crate::nulls::null::SplitMix64;
use crate::nulls::perseus;

const FLOAT_RELATIVE_EPSILON: f64 = 1.0e-12;

fn assert_relative_close(actual: f64, expected: f64, label: &str) {
    let tolerance = expected.abs().max(1.0) * FLOAT_RELATIVE_EPSILON;
    let difference = (actual - expected).abs();
    assert!(
        difference <= tolerance,
        "{label} changed: actual={actual:.17e} expected={expected:.17e} diff={difference:.17e} tolerance={tolerance:.17e}"
    );
}

#[test]
fn kgram_intersection_counts_distinct_cross_message_overlap() {
    let messages = vec![
        message("a", &[&[1, 2, 3, 1, 2, 4]]),
        message("b", &[&[0, 1, 2, 3, 8]]),
        message("c", &[&[9, 1, 2, 4, 9]]),
    ];

    let statistic = cross_message_statistic(&messages, 3).unwrap();

    assert_eq!(
        statistic,
        CrossTailStatistic {
            total_distinct_ngrams: 8,
            shared_distinct_ngrams: 2,
            max_messages_per_ngram: 2,
        }
    );
}

#[test]
fn kgrams_do_not_cross_residual_segments() {
    let messages = vec![
        message("a", &[&[1, 2], &[3, 4]]),
        message("b", &[&[1, 2, 3]]),
    ];

    let statistic = cross_message_statistic(&messages, 3).unwrap();

    assert_eq!(statistic.shared_distinct_ngrams, 0);
    assert_eq!(statistic.total_distinct_ngrams, 1);
}

#[test]
fn residual_mask_reuses_perseus_shared_partition() {
    let keys = ["east1", "west1"];
    let messages = vec![
        values(&[80, 1, 2, 3, 10, 11, 12]),
        values(&[81, 1, 2, 3, 20, 21, 22]),
    ];
    let partition = perseus::build_shared_partition(&keys, &messages).unwrap();

    let residual = residual_segment_messages(&keys, &messages, &partition).unwrap();

    let segment_lengths = residual
        .iter()
        .map(|message| message.segments.iter().map(Vec::len).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    assert_eq!(segment_lengths, vec![vec![1, 3], vec![1, 3]]);
    let mut residual_iter = residual.iter();
    let first = residual_iter.next().unwrap();
    let second = residual_iter.next().unwrap();
    assert_eq!(first.segments, vec![values(&[80]), values(&[10, 11, 12])]);
    assert_eq!(second.segments, vec![values(&[81]), values(&[20, 21, 22])]);
}

#[test]
fn oversized_sample_count_returns_error_without_capacity_panic() {
    let too_many_samples = max_vec_capacity_for::<usize>() + 1;

    let result = report_from_message_values(
        TreeResidualConfig {
            seed: 0,
            trials: too_many_samples,
            seed_count: 1,
        },
        orders::accepted_honeycomb_order(),
        &[],
        &[],
    );

    assert_eq!(result.err(), Some(TreeResidualError::SampleCountTooLarge));
}

#[test]
fn oversized_seed_count_returns_error_without_capacity_panic() {
    let too_many_seeds = max_vec_capacity_for::<u64>() + 1;

    let result = seed_batches(0, too_many_seeds);

    assert_eq!(result.err(), Some(TreeResidualError::SampleCountTooLarge));
}

#[test]
fn planted_common_motif_positive_control_is_significant() {
    let keys = ["east1", "west1", "east2"];
    let messages = planted_motif_fixture();
    let report = report_from_message_values(
        TreeResidualConfig {
            seed: 0x5151,
            trials: 512,
            seed_count: 2,
        },
        orders::accepted_honeycomb_order(),
        &keys,
        &messages,
    )
    .unwrap();

    for row in report
        .rows
        .iter()
        .filter(|row| row.scope == TreeResidualScope::ResidualTails)
    {
        assert!(
            row.significant_excess,
            "planted motif should exceed its null for k={}: row={row:?}",
            row.k
        );
        assert!(
            row.observed.shared_distinct_ngrams >= 7usize.saturating_sub(row.k),
            "motif contribution disappeared for k={}: row={row:?}",
            row.k
        );
    }
}

#[test]
fn independent_tail_negative_control_matches_shuffle_null() {
    let keys = ["north", "south", "east1", "west1", "east2"];
    let messages = independent_tail_fixture(0x1234, keys.len(), 72, 97);
    let report = report_from_message_values(
        TreeResidualConfig {
            seed: 0x6161,
            trials: 512,
            seed_count: 2,
        },
        orders::accepted_honeycomb_order(),
        &keys,
        &messages,
    )
    .unwrap();

    for row in report
        .rows
        .iter()
        .filter(|row| row.scope == TreeResidualScope::ResidualTails)
    {
        assert!(
            !row.significant_excess,
            "independent tails produced an unexpected excess for k={}: row={row:?}",
            row.k
        );
        assert!(
            row.two_sided_p > 0.01,
            "independent tails landed in an extreme two-sided tail for k={}: row={row:?}",
            row.k
        );
    }
}

#[test]
fn eye_headline_counts_are_pinned() {
    let report = run_tree_residual(TreeResidualConfig {
        seed: 12_345,
        trials: 16,
        seed_count: 1,
    })
    .unwrap();

    assert_eq!(report.tail_total_length, 851);
    assert_row_observed(&report.rows, TreeResidualScope::ResidualTails, 3, 3, 2);
    assert_row_observed(&report.rows, TreeResidualScope::ResidualTails, 4, 0, 1);
    assert_row_observed(&report.rows, TreeResidualScope::FullMessages, 3, 56, 6);
    assert_row_observed(&report.rows, TreeResidualScope::FullMessages, 4, 49, 6);
}

#[test]
#[ignore = "canonical 1000-trial x 5-seed tree-residual regression; run with cargo test -- --ignored"]
fn eye_tree_residual_null_matches_headline_regression() {
    let report = run_tree_residual(TreeResidualConfig {
        seed: 12_345,
        trials: 1_000,
        seed_count: 5,
    })
    .unwrap();

    assert_eq!(report.tail_total_length, 851);
    assert_row_observed(&report.rows, TreeResidualScope::ResidualTails, 3, 3, 2);
    assert_row_observed(&report.rows, TreeResidualScope::ResidualTails, 4, 0, 1);
    assert_row_observed(&report.rows, TreeResidualScope::FullMessages, 3, 56, 6);
    assert_row_observed(&report.rows, TreeResidualScope::FullMessages, 4, 49, 6);
    let residual_k3 = find_row(&report.rows, TreeResidualScope::ResidualTails, 3);
    assert_eq!(residual_k3.null.samples, 5_000);
    assert_eq!(residual_k3.upper_tail_count, 92);
    assert_relative_close(
        residual_k3.upper_tail_p,
        0.018_596_280_743_851_23,
        "residual k=3 upper p",
    );
    assert!(residual_k3.significant_excess);

    let residual_k4 = find_row(&report.rows, TreeResidualScope::ResidualTails, 4);
    assert!(!residual_k4.significant_excess);

    let full_k3 = find_row(&report.rows, TreeResidualScope::FullMessages, 3);
    let full_k4 = find_row(&report.rows, TreeResidualScope::FullMessages, 4);
    assert_eq!(full_k3.upper_tail_count, 0);
    assert_eq!(full_k4.upper_tail_count, 0);
    assert!(full_k3.significant_excess);
    assert!(full_k4.significant_excess);
}

fn assert_row_observed(
    rows: &[super::TreeResidualRow],
    scope: TreeResidualScope,
    k: usize,
    expected_shared: usize,
    expected_max_messages: usize,
) {
    let row = find_row(rows, scope, k);
    assert_eq!(
        row.observed.shared_distinct_ngrams, expected_shared,
        "{scope:?} k={k} shared count changed"
    );
    assert_eq!(
        row.observed.max_messages_per_ngram, expected_max_messages,
        "{scope:?} k={k} max message count changed"
    );
}

fn find_row(
    rows: &[super::TreeResidualRow],
    scope: TreeResidualScope,
    k: usize,
) -> &super::TreeResidualRow {
    rows.iter()
        .find(|row| row.scope == scope && row.k == k)
        .unwrap()
}

fn planted_motif_fixture() -> Vec<Vec<TrigramValue>> {
    let trunk = values(&[118, 119, 120, 121]);
    let motif = [0, 1, 2, 3, 4, 5];
    let mut messages = Vec::new();
    for (start, position) in [(10, 4), (46, 15), (82, 26)] {
        let mut message = trunk.clone();
        let mut tail = sequential_tail(start, 36);
        plant_motif(&mut tail, position, &motif);
        message.extend(tail);
        messages.push(message);
    }
    messages
}

fn independent_tail_fixture(
    seed: u64,
    message_count: usize,
    len: usize,
    alphabet_size: u8,
) -> Vec<Vec<TrigramValue>> {
    let mut rng = SplitMix64::new(seed);
    let mut messages = Vec::new();
    for _message in 0..message_count {
        let mut values = Vec::new();
        for _position in 0..len {
            let raw = (rng.next_u64() % u64::from(alphabet_size)) as u8;
            values.push(value(raw));
        }
        messages.push(values);
    }
    messages
}

fn plant_motif(tail: &mut [TrigramValue], position: usize, motif: &[u8]) {
    for (offset, raw) in motif.iter().copied().enumerate() {
        let Some(slot) = tail.get_mut(position + offset) else {
            panic!("motif does not fit at position {position}");
        };
        *slot = value(raw);
    }
}

fn sequential_tail(start: u8, len: usize) -> Vec<TrigramValue> {
    (0..len)
        .map(|offset| value(start + u8::try_from(offset).unwrap()))
        .collect()
}

fn message(message_key: &'static str, segments: &[&[u8]]) -> MessageSegments {
    MessageSegments {
        message_key,
        segments: segments.iter().map(|segment| values(segment)).collect(),
    }
}

fn values(raw_values: &[u8]) -> Vec<TrigramValue> {
    raw_values.iter().copied().map(value).collect()
}

fn value(raw: u8) -> TrigramValue {
    TrigramValue::new(raw).unwrap()
}

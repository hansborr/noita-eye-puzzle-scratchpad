use super::{
    OrderStats, READING_LAYER_ALPHABET_SIZE, ReadingLayerFlatnessStats, ReadingOrder,
    TrigramPermutation, audit_order_stats, corpus_grids, reading_layer_flatness_stats,
    summarize_grids,
};

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
fn raw_order_matches_stage_a_anchor() {
    let grids = corpus_grids().unwrap();
    let stats = audit_order_stats(&grids)
        .unwrap()
        .into_iter()
        .find(|item| item.order == ReadingOrder::RawRows)
        .unwrap()
        .stats;
    assert_eq!(stats.total, 1036);
    assert_eq!(stats.distinct, 114);
    assert_eq!(stats.min, Some(0));
    assert_eq!(stats.max, Some(122));
    assert!(!stats.contiguous);
    assert_eq!(stats.values_above_82, 31);
    assert_eq!(stats.adjacent_equal, 17);
    assert_eq!(stats.recurrence_distance_1_to_6, [17, 12, 15, 10, 10, 9]);
}

#[test]
fn grids_expose_observed_row_widths() {
    let grids = corpus_grids().unwrap();
    let summary = summarize_grids(&grids);
    assert_eq!(summary.max_width, 39);
    assert!(summary.bottom_two_rows_differ_by_at_most_one);
    let widths: Vec<Vec<usize>> = summary
        .row_widths
        .into_iter()
        .map(|(_key, widths)| widths)
        .collect();
    assert_eq!(
        widths,
        vec![
            vec![39, 39, 39, 39, 39, 39, 32, 31],
            vec![39, 39, 39, 39, 39, 39, 38, 37],
            vec![39, 39, 39, 39, 39, 39, 39, 39, 21, 21],
            vec![39, 39, 39, 39, 39, 39, 36, 36],
            vec![39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 11, 10],
            vec![39, 39, 39, 39, 39, 39, 39, 39, 30, 30],
            vec![39, 39, 39, 39, 39, 39, 39, 39, 23, 22],
            vec![39, 39, 39, 39, 39, 39, 39, 39, 24, 24],
            vec![39, 39, 39, 39, 39, 39, 39, 39, 15, 15],
        ]
    );
}

#[test]
fn identity_honeycomb_reproduces_contiguous_anchor() {
    let grids = corpus_grids().unwrap();
    let order = ReadingOrder::HoneycombStandard {
        upper: TrigramPermutation::IDENTITY,
        lower: TrigramPermutation::IDENTITY,
    };
    let values = super::read_corpus_message_values(&grids, order).unwrap();
    let stats = OrderStats::from_message_values(&values);
    assert_eq!(stats.total, 1036);
    assert!(stats.is_contiguous_0_to_82());
    assert_eq!(stats.adjacent_equal, 0);
}

#[test]
fn accepted_honeycomb_message_lengths_are_distinct() {
    let grids = corpus_grids().unwrap();
    let values =
        super::read_corpus_message_values(&grids, super::accepted_honeycomb_order()).unwrap();
    let observed: Vec<(&str, usize)> = grids
        .iter()
        .zip(values.iter())
        .map(|(grid, values)| (grid.message_key(), values.len()))
        .collect();
    assert_eq!(
        observed,
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

    let mut lengths: Vec<usize> = observed
        .iter()
        .map(|(_message_key, length)| *length)
        .collect();
    let message_count = lengths.len();
    lengths.sort_unstable();
    lengths.dedup();
    assert_eq!(lengths.len(), message_count);
}

#[test]
fn audit_family_has_one_standard36_contiguous_zero_to_82_order() {
    let grids = corpus_grids().unwrap();
    let stats = audit_order_stats(&grids).unwrap();
    let winners: Vec<String> = stats
        .into_iter()
        .filter(|item| item.stats.is_contiguous_0_to_82())
        .map(|item| item.order.name())
        .collect();
    assert_eq!(winners, vec!["standard36-u012-d012"]);
}

#[test]
fn experiment_4_honeycomb_flatness_matches_frequency_and_ioc_anchors() {
    let grids = corpus_grids().unwrap();
    let order = ReadingOrder::HoneycombStandard {
        upper: TrigramPermutation::IDENTITY,
        lower: TrigramPermutation::IDENTITY,
    };
    let flatness = reading_layer_flatness_stats(&grids, order).unwrap();

    assert_eq!(flatness.total, 1036);
    assert_eq!(flatness.in_alphabet_total, 1036);
    assert_eq!(flatness.outside_alphabet_occurrences, 0);
    assert_eq!(flatness.frequencies.len(), READING_LAYER_ALPHABET_SIZE);
    assert_relative_close(
        flatness.mean_frequency,
        12.481_927_710_843_4,
        "mean frequency",
    );
    assert_eq!(flatness.min_frequency, 3);
    assert_eq!(flatness.max_frequency, 26);
    assert_eq!(flatness.zero_frequency_symbols, 0);
    assert_relative_close(
        flatness.normalized_ioc,
        flatness.ioc_probability * 83.0,
        "normalized IoC relation",
    );
    assert_relative_close(
        flatness.normalized_ioc,
        0.971_776_489_899_836,
        "per-message normalized IoC",
    );
    assert_relative_close(
        flatness.concatenated_normalized_ioc,
        flatness.concatenated_ioc_probability * 83.0,
        "concatenated normalized IoC relation",
    );
    assert_relative_close(
        flatness.concatenated_normalized_ioc,
        1.066_043_683_434_99,
        "concatenated normalized IoC",
    );
    assert_relative_close(
        flatness.chi_square_vs_uniform,
        150.355_212_355_212,
        "chi-square statistic",
    );
    assert_eq!(
        ReadingLayerFlatnessStats::CHI_SQUARE_VS_UNIFORM_DEGREES_OF_FREEDOM,
        82
    );
    let upper_tail_p = flatness.chi_square_vs_uniform_upper_tail_p_value.unwrap();
    assert_relative_close(
        upper_tail_p,
        6.310_017_333_267_23e-6,
        "chi-square upper-tail p-value",
    );
}

#[test]
fn experiment_4_raw_order_is_not_an_83_symbol_stream() {
    let grids = corpus_grids().unwrap();
    let flatness = reading_layer_flatness_stats(&grids, ReadingOrder::RawRows).unwrap();

    assert_eq!(flatness.total, 1036);
    assert!(flatness.outside_alphabet_occurrences > 0);
    assert!(flatness.chi_square_vs_uniform.is_infinite());
    assert_eq!(
        ReadingLayerFlatnessStats::CHI_SQUARE_VS_UNIFORM_DEGREES_OF_FREEDOM,
        82
    );
    assert_eq!(flatness.chi_square_vs_uniform_upper_tail_p_value, None);
}

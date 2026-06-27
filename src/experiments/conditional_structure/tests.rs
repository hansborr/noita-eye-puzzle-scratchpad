use super::nulls::{
    bias_calibration, comparison_from_samples, planted_controls, structured_plaintext_messages,
    trigram_from_index,
};
use super::transition::first_order_stats;
use super::{
    ConditionalStatistic, ConditionalStructureConfig, DEFAULT_ALPHABET_SIZE,
    report_from_message_values,
};
use crate::analysis::orders;
use crate::core::trigram::TrigramValue;

fn values(raw: &[usize]) -> Vec<TrigramValue> {
    raw.iter()
        .copied()
        .map(|value| trigram_from_index(value).unwrap())
        .collect()
}

#[test]
fn deterministic_alternation_has_full_first_order_information() {
    let messages = vec![values(&[0, 1, 0, 1, 0, 1, 0, 1])];
    let stats = first_order_stats(&["fixture"], &messages, 2).unwrap();

    assert_eq!(stats.matrix.symbols, 8);
    assert_eq!(stats.matrix.transitions, 7);
    assert_eq!(stats.graph.distinct_successor_edges, 2);
    assert_eq!(stats.graph.greedy_fsm_state_lower_bound, 2);
    assert!(stats.entropy.conditional_entropy_mle_bits.abs() < 1e-12);
    assert!(stats.entropy.mutual_information_mle_bits > 0.98);
    assert!(stats.entropy.mutual_information_corrected_bits > 0.25);
    assert!(
        stats.entropy.mutual_information_corrected_bits < stats.entropy.mutual_information_mle_bits
    );
}

#[test]
fn successor_graph_counts_edges_entropy_and_fsm_bound() {
    let messages = vec![values(&[0, 1, 2, 0, 2])];
    let stats = first_order_stats(&["fixture"], &messages, 3).unwrap();

    assert_eq!(stats.graph.observed_symbols, 3);
    assert_eq!(stats.graph.active_sources, 3);
    assert_eq!(stats.graph.active_targets, 3);
    assert_eq!(stats.graph.distinct_successor_edges, 4);
    assert_eq!(stats.graph.max_out_degree, 2);
    assert_eq!(stats.graph.greedy_fsm_state_lower_bound, 4);
    assert!(
        (stats.graph.successor_entropy_bits - (1.0 / 3.0)).abs() < 1e-12,
        "successor entropy was {}",
        stats.graph.successor_entropy_bits
    );
}

#[test]
fn two_sided_add_one_comparison_is_capped() {
    let comparison = comparison_from_samples(
        ConditionalStatistic::TransitionChiSquare,
        2.0,
        &[1.0, 2.0, 3.0],
    );

    assert_eq!(comparison.lower_tail_count, 2);
    assert_eq!(comparison.upper_tail_count, 2);
    assert!((comparison.two_sided_add_one_p - 1.0).abs() < f64::EPSILON);
}

#[test]
fn two_sided_add_one_applies_correction_before_doubling() {
    let comparison = comparison_from_samples(
        ConditionalStatistic::TransitionChiSquare,
        0.5,
        &[1.0, 2.0, 3.0],
    );

    assert_eq!(comparison.lower_tail_count, 0);
    assert_eq!(comparison.upper_tail_count, 3);
    assert!((comparison.two_sided_add_one_p - 0.5).abs() < f64::EPSILON);
}

#[test]
fn add_constant_calibration_reduces_flat_random_mi_bias() {
    let config = ConditionalStructureConfig {
        seed: 0x5150,
        seed_count: 2,
        trials_per_seed: 64,
        alphabet_size: DEFAULT_ALPHABET_SIZE,
    };
    let calibration = bias_calibration(config, &[99, 103, 118, 102]).unwrap();

    assert!(calibration.mle_mutual_information.mean > 0.0);
    assert!(
        calibration.corrected_mean_abs_mutual_information_bits
            < calibration.mle_mean_abs_mutual_information_bits,
        "MLE abs {} corrected abs {}",
        calibration.mle_mean_abs_mutual_information_bits,
        calibration.corrected_mean_abs_mutual_information_bits
    );
    assert!(
        calibration.corrected_mutual_information.mean.abs()
            < calibration.mle_mutual_information.mean
    );
}

#[test]
fn planted_controls_separate_static_from_deck_permuted_structure() {
    let config = ConditionalStructureConfig {
        seed: 0x7777,
        seed_count: 2,
        trials_per_seed: 64,
        alphabet_size: DEFAULT_ALPHABET_SIZE,
    };
    let plaintext = structured_plaintext_messages(&[160, 161, 162]).unwrap();
    let controls = planted_controls(config, &[160, 161, 162]).unwrap();
    assert_eq!(plaintext.len(), 3);

    let static_mi = controls
        .static_monoalphabetic
        .comparisons
        .iter()
        .find(|row| row.statistic == ConditionalStatistic::MutualInformationCorrected)
        .unwrap();
    let static_edges = controls
        .static_monoalphabetic
        .comparisons
        .iter()
        .find(|row| row.statistic == ConditionalStatistic::DistinctSuccessorEdges)
        .unwrap();
    let deck_mi = controls
        .deck_permuted
        .comparisons
        .iter()
        .find(|row| row.statistic == ConditionalStatistic::MutualInformationCorrected)
        .unwrap();
    let deck_edges = controls
        .deck_permuted
        .comparisons
        .iter()
        .find(|row| row.statistic == ConditionalStatistic::DistinctSuccessorEdges)
        .unwrap();

    assert!(static_mi.observed > static_mi.null.q975);
    assert!(static_edges.observed < static_edges.null.q025);
    assert!(!deck_mi.outside_pointwise_95, "deck MI row: {deck_mi:?}");
    assert!(
        !deck_edges.outside_pointwise_95,
        "deck edge row: {deck_edges:?}"
    );
}

#[test]
fn eye_headline_statistics_are_pinned() {
    let config = ConditionalStructureConfig {
        seed: 0x1234,
        seed_count: 1,
        trials_per_seed: 4,
        alphabet_size: DEFAULT_ALPHABET_SIZE,
    };
    let grids = orders::corpus_grids().unwrap();
    let keys = grids
        .iter()
        .map(crate::analysis::orders::GlyphGrid::message_key)
        .collect::<Vec<_>>();
    let order = orders::accepted_honeycomb_order();
    let messages = orders::read_corpus_message_values(&grids, order).unwrap();
    let report = report_from_message_values(config, order, &keys, &messages).unwrap();

    assert_eq!(report.observed.matrix.symbols, 1036);
    assert_eq!(report.observed.matrix.transitions, 1027);
    assert_eq!(report.observed.matrix.nonzero_cells, 850);
    assert_eq!(report.observed.chi_square.degrees_of_freedom, 6724);
    assert_eq!(report.observed.graph.distinct_successor_edges, 850);
    assert_eq!(report.observed.graph.greedy_fsm_state_lower_bound, 850);
    assert_eq!(report.observed.diagonal.self_transitions, 0);
    assert_eq!(report.observed.diagonal.self_transition_edges, 0);
    assert_eq!(report.observed.off_diagonal.matrix_cells, 6806);
    assert_eq!(report.observed.off_diagonal.distinct_successor_edges, 850);
    assert_eq!(report.observed.off_diagonal.expected_cells, 6806);
    assert_eq!(report.observed.off_diagonal.expected_lt_1_cells, 6806);
    assert_eq!(report.observed.off_diagonal.expected_lt_5_cells, 6806);
    assert!(
        (report
            .observed
            .diagonal
            .expected_self_transitions_independence
            - report.observed.diagonal.chi_square_contribution)
            .abs()
            < 1e-12
    );
    assert!(
        (report.observed.diagonal.chi_square_contribution
            + report.observed.off_diagonal.chi_square_statistic
            - report.observed.chi_square.statistic)
            .abs()
            < 1e-9
    );
    let no_repeat_self_transitions = report
        .no_repeat_null
        .comparisons
        .iter()
        .find(|row| row.statistic == ConditionalStatistic::SelfTransitions)
        .unwrap();
    assert!(no_repeat_self_transitions.observed.abs() < f64::EPSILON);
    assert!(no_repeat_self_transitions.null.min.abs() < f64::EPSILON);
    assert!(no_repeat_self_transitions.null.max.abs() < f64::EPSILON);
    assert!(
        (report.observed.entropy.mutual_information_corrected_bits - 0.000_726_184_362_833_670_6)
            .abs()
            < 1e-12,
        "MI changed: {}",
        report.observed.entropy.mutual_information_corrected_bits
    );
    assert!(
        (report.observed.graph.successor_entropy_bits - 3.186_263_722_367_619).abs() < 1e-12,
        "successor entropy changed: {}",
        report.observed.graph.successor_entropy_bits
    );
}

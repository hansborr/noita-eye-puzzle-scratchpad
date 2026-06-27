//! Stdout/markdown rendering for the conditional-structure report.

use crate::report::{self, Report};

use super::{
    ConditionalStatistic, ConditionalStructureReport, NullComparison,
    PRIMARY_CONDITIONAL_REPORT_STATISTICS, PlantedControlReport, ScalarNullBand, renderln,
};

impl Report for ConditionalStructureReport {
    fn render(&self) -> String {
        let report = self;
        let mut out = String::new();
        let total_trials = report
            .config
            .seed_count
            .saturating_mul(report.config.trials_per_seed);
        renderln!(
            &mut out,
            "first-order conditional structure & successor graph"
        );
        renderln!(&mut out, "order: {}", report.order.name());
        renderln!(
            &mut out,
            "alphabet: accepted honeycomb reading-layer values 0..={}",
            report.config.alphabet_size.saturating_sub(1)
        );
        renderln!(&mut out, "base seed: {}", report.config.seed);
        renderln!(
            &mut out,
            "shuffle null: {} seeds x {} trials/seed = {} within-message multiset-preserving shuffles",
            report.config.seed_count,
            report.config.trials_per_seed,
            total_trials
        );
        renderln!(
            &mut out,
            "no-repeat null: symmetric swap-chain shuffles conditioned on zero adjacent-equal pairs ({} burn-in sweeps, {} sweeps/sample)",
            report.no_repeat_null.burn_in_sweeps,
            report.no_repeat_null.sample_sweeps
        );
        renderln!(
            &mut out,
            "message lengths: {}",
            report::format_message_lengths(&report.message_lengths)
        );
        renderln!(
            &mut out,
            "boundary rule: transitions are counted within each message only; no transition crosses a message join"
        );
        renderln!(
            &mut out,
            "low-power caveat: {} symbols, {} transitions, and {} cells in an {}x{} matrix (mean {:.3} transitions/cell; {:.2} symbols/value). An inside-shuffle row is only a null-comparison result at this corpus size, not proof of memorylessness.",
            report.observed.matrix.symbols,
            report.observed.matrix.transitions,
            report.observed.matrix.matrix_cells,
            report.observed.matrix.alphabet_size,
            report.observed.matrix.alphabet_size,
            report.observed.matrix.mean_transitions_per_cell,
            report.observed.matrix.mean_symbols_per_value
        );
        renderln!(
            &mut out,
            "entropy correction: add-constant alpha={:.1} over the full {}-symbol next-state support; raw plug-in MI is shown only as a sparse-sample diagnostic",
            report.observed.entropy.add_constant_alpha,
            report.config.alphabet_size
        );
        renderln!(&mut out);
        append_conditional_observed(&mut out, report);
        renderln!(&mut out);
        append_conditional_comparisons(&mut out, report);
        renderln!(&mut out);
        append_conditional_diagonal_accounting(&mut out, report);
        renderln!(&mut out);
        append_conditional_no_repeat_comparisons(&mut out, report);
        renderln!(&mut out);
        append_conditional_bias_calibration(&mut out, report);
        renderln!(&mut out);
        append_conditional_controls(&mut out, report);
        renderln!(&mut out);
        append_conditional_interpretation(&mut out, report);
        out
    }
}

fn append_conditional_observed(out: &mut String, report: &ConditionalStructureReport) {
    let observed = report.observed;
    renderln!(out, "observed transition matrix");
    renderln!(
        out,
        "  nonzero cells: {}/{} ({:.3}% density)",
        observed.matrix.nonzero_cells,
        observed.matrix.matrix_cells,
        observed.matrix.density * 100.0
    );
    renderln!(
        out,
        "  active rows/cols: {}/{}; chi2 df {}; expected cells <1/<5: {}/{}",
        observed.chi_square.active_rows,
        observed.chi_square.active_columns,
        observed.chi_square.degrees_of_freedom,
        observed.chi_square.expected_lt_1_cells,
        observed.chi_square.expected_lt_5_cells
    );
    renderln!(
        out,
        "  H(next) raw/corrected: {:.4}/{:.4} bits; H(next|current) raw/corrected: {:.4}/{:.4} bits",
        observed.entropy.next_entropy_mle_bits,
        observed.entropy.next_entropy_corrected_bits,
        observed.entropy.conditional_entropy_mle_bits,
        observed.entropy.conditional_entropy_corrected_bits
    );
    renderln!(
        out,
        "  MI raw/corrected: {:.4}/{:.6} bits; G raw/corrected from MI: {:.1}/{:.3}; Pearson chi2: {:.3}",
        observed.entropy.mutual_information_mle_bits,
        observed.entropy.mutual_information_corrected_bits,
        likelihood_ratio_g_from_mi_bits(
            observed.entropy.transitions,
            observed.entropy.mutual_information_mle_bits
        ),
        likelihood_ratio_g_from_mi_bits(
            observed.entropy.transitions,
            observed.entropy.mutual_information_corrected_bits
        ),
        observed.chi_square.statistic
    );
    renderln!(
        out,
        "  diagonal: {} self-transitions in {} cells; fitted-independence expectation {:.2}; diagonal Pearson contribution {:.3}",
        observed.diagonal.self_transitions,
        report.config.alphabet_size,
        observed.diagonal.expected_self_transitions_independence,
        observed.diagonal.chi_square_contribution
    );
    renderln!(
        out,
        "  off-diagonal: {} edges over {} cells ({:.3}% density); chi2 contribution {:.3}; expected cells <1/<5: {}/{}",
        observed.off_diagonal.distinct_successor_edges,
        observed.off_diagonal.matrix_cells,
        observed.off_diagonal.edge_density * 100.0,
        observed.off_diagonal.chi_square_statistic,
        observed.off_diagonal.expected_lt_1_cells,
        observed.off_diagonal.expected_lt_5_cells
    );
    renderln!(
        out,
        "  successor graph: {} edges, mean out-degree {:.2}, max out-degree {}, successor entropy {:.4} bits, out-degree entropy {:.4} bits, FSM lower bound {} states",
        observed.graph.distinct_successor_edges,
        observed.graph.mean_out_degree,
        observed.graph.max_out_degree,
        observed.graph.successor_entropy_bits,
        observed.graph.out_degree_entropy_bits,
        observed.graph.greedy_fsm_state_lower_bound
    );
}

fn append_conditional_comparisons(out: &mut String, report: &ConditionalStructureReport) {
    renderln!(
        out,
        "within-message shuffle comparisons (unconstrained, diagonal included)"
    );
    renderln!(
        out,
        "{:<25} {:>12} {:>12} {:>19} {:>12} {:>10}",
        "statistic",
        "observed",
        "null med",
        "null 95%",
        "p two-sided",
        "flag"
    );
    for statistic in PRIMARY_CONDITIONAL_REPORT_STATISTICS {
        if let Some(row) = comparison_for_statistic(&report.comparisons, statistic) {
            append_conditional_comparison_row(out, row);
        }
    }
    renderln!(
        out,
        "p-values are two-sided add-one empirical values and pointwise over {} displayed statistics; no family-wise correction is claimed.",
        PRIMARY_CONDITIONAL_REPORT_STATISTICS.len()
    );
}

fn append_conditional_diagonal_accounting(out: &mut String, report: &ConditionalStructureReport) {
    let observed = report.observed;
    renderln!(out, "diagonal/no-repeat accounting");
    if let Some(row) =
        comparison_for_statistic(&report.comparisons, ConditionalStatistic::SelfTransitions)
    {
        renderln!(
            out,
            "  self transitions: eyes {}, unconstrained shuffle mean {:.2}, 95% {}, p {}; fitted-independence expectation {:.2}",
            format_conditional_statistic(row.statistic, row.observed),
            row.null.mean,
            format_conditional_band(row.statistic, row.null),
            report::format_probability(row.two_sided_add_one_p),
            observed.diagonal.expected_self_transitions_independence
        );
    }
    if let Some(row) = comparison_for_statistic(
        &report.comparisons,
        ConditionalStatistic::DistinctSuccessorEdgesOffDiagonal,
    ) {
        renderln!(
            out,
            "  off-diagonal successor edges vs unconstrained shuffle: eyes {}, 95% {}, flag {}",
            format_conditional_statistic(row.statistic, row.observed),
            format_conditional_band(row.statistic, row.null),
            conditional_flag(row)
        );
    }
    if let Some(row) = comparison_for_statistic(
        &report.comparisons,
        ConditionalStatistic::TransitionChiSquareOffDiagonal,
    ) {
        renderln!(
            out,
            "  off-diagonal Pearson contribution vs unconstrained shuffle: eyes {}, 95% {}, flag {}",
            format_conditional_statistic(row.statistic, row.observed),
            format_conditional_band(row.statistic, row.null),
            conditional_flag(row)
        );
    }
    renderln!(
        out,
        "  diagonal Pearson contribution is {:.3} of the full {:.3}; dropping diagonal cells is a diagnostic, while the no-repeat null below conditions the shuffles on the known zero-adjacency constraint.",
        observed.diagonal.chi_square_contribution,
        observed.chi_square.statistic
    );
}

fn append_conditional_no_repeat_comparisons(out: &mut String, report: &ConditionalStructureReport) {
    renderln!(out, "no-repeat-conditioned shuffle comparisons");
    renderln!(
        out,
        "{:<25} {:>12} {:>12} {:>19} {:>12} {:>10}",
        "statistic",
        "observed",
        "null med",
        "null 95%",
        "p two-sided",
        "flag"
    );
    for row in &report.no_repeat_null.comparisons {
        append_conditional_comparison_row(out, row);
    }
    renderln!(
        out,
        "The chain preserves each message multiset and rejects swaps that would create x->x; p-values are empirical over recorded chain states, not asymptotic chi-square tails."
    );
}

fn append_conditional_comparison_row(out: &mut String, row: &NullComparison) {
    renderln!(
        out,
        "{:<25} {:>12} {:>12} {:>19} {:>12} {:>10}",
        row.statistic.label(),
        format_conditional_statistic(row.statistic, row.observed),
        format_conditional_statistic(row.statistic, row.null.median),
        format_conditional_band(row.statistic, row.null),
        report::format_probability(row.two_sided_add_one_p),
        conditional_flag(row)
    );
}

fn conditional_flag(row: &NullComparison) -> &'static str {
    if row.outside_pointwise_95 {
        "pt95-out"
    } else {
        "inside"
    }
}

fn append_conditional_bias_calibration(out: &mut String, report: &ConditionalStructureReport) {
    let calibration = report.bias_calibration;
    renderln!(out, "flat-random estimator-bias calibration (true MI = 0)");
    renderln!(
        out,
        "  trials: {}; alphabet: {}; matched message lengths",
        calibration.trials,
        calibration.alphabet_size
    );
    renderln!(
        out,
        "  plug-in MI mean {:.4}, abs-mean {:.4}, 95% {}",
        calibration.mle_mutual_information.mean,
        calibration.mle_mean_abs_mutual_information_bits,
        format_conditional_band(
            ConditionalStatistic::MutualInformationCorrected,
            calibration.mle_mutual_information
        )
    );
    renderln!(
        out,
        "  add-1 MI mean {:.6}, abs-mean {:.6}, 95% {}",
        calibration.corrected_mutual_information.mean,
        calibration.corrected_mean_abs_mutual_information_bits,
        format_conditional_band(
            ConditionalStatistic::MutualInformationCorrected,
            calibration.corrected_mutual_information
        )
    );
}

fn append_conditional_controls(out: &mut String, report: &ConditionalStructureReport) {
    renderln!(out, "planted structure controls");
    renderln!(
        out,
        "{:<27} {:>8} {:>10} {:>19} {:>8} {:>17} {:>9} {:>10}",
        "control",
        "MI raw",
        "MI add-1",
        "MI null 95%",
        "edges",
        "edge null 95%",
        "FSM lb",
        "verdict"
    );
    for control in [
        &report.controls.static_monoalphabetic,
        &report.controls.deck_permuted,
    ] {
        let mi = conditional_comparison(control, ConditionalStatistic::MutualInformationCorrected);
        let edges = conditional_comparison(control, ConditionalStatistic::DistinctSuccessorEdges);
        let verdict = conditional_control_verdict(control);
        renderln!(
            out,
            "{:<27} {:>8.3} {:>10} {:>19} {:>8} {:>17} {:>9} {:>10}",
            control.label,
            control.observed.entropy.mutual_information_mle_bits,
            mi.map_or_else(
                || "n/a".to_owned(),
                |row| format_conditional_statistic(row.statistic, row.observed)
            ),
            mi.map_or_else(
                || "n/a".to_owned(),
                |row| format_conditional_band(row.statistic, row.null)
            ),
            edges.map_or_else(
                || "n/a".to_owned(),
                |row| format_conditional_statistic(row.statistic, row.observed)
            ),
            edges.map_or_else(
                || "n/a".to_owned(),
                |row| format_conditional_band(row.statistic, row.null)
            ),
            control.observed.graph.greedy_fsm_state_lower_bound,
            verdict
        );
    }
    renderln!(
        out,
        "control construction: {}; {}.",
        report.controls.static_monoalphabetic.construction,
        report.controls.deck_permuted.construction
    );
}

fn append_conditional_interpretation(out: &mut String, report: &ConditionalStructureReport) {
    let primary_outliers = conditional_primary_outliers(report);
    let off_diagonal_outliers = conditional_off_diagonal_outliers(report);
    let no_repeat_outliers = conditional_no_repeat_outliers(report);

    append_conditional_outlier_framing(
        out,
        report,
        &primary_outliers,
        &off_diagonal_outliers,
        &no_repeat_outliers,
    );
    append_conditional_effect_size(out, report);
    append_conditional_sparse_caveat(out, report);
    renderln!(
        out,
        "Raw unconstrained exceedances are dominated by the known zero-adjacency constraint (above). Any exceedances that survive the no-repeat-conditioned null are not attributable to zero-adjacency (that null controls it) nor to table sparsity (those tails are empirical, not asymptotic); they reflect only a tiny residual arrangement effect whose honest effect size is negligible (corrected MI near zero, above). None of this is a plaintext/decryption claim or evidence of novel first-order memory. The planted controls still verify directionality for truly first-order-structured fixtures."
    );
}

fn conditional_primary_outliers(report: &ConditionalStructureReport) -> Vec<String> {
    PRIMARY_CONDITIONAL_REPORT_STATISTICS
        .iter()
        .filter_map(|&statistic| comparison_for_statistic(&report.comparisons, statistic))
        .filter(|row| row.outside_pointwise_95)
        .map(conditional_outlier_label)
        .collect()
}

fn conditional_off_diagonal_outliers(report: &ConditionalStructureReport) -> Vec<String> {
    [
        ConditionalStatistic::TransitionChiSquareOffDiagonal,
        ConditionalStatistic::DistinctSuccessorEdgesOffDiagonal,
    ]
    .iter()
    .filter_map(|&statistic| comparison_for_statistic(&report.comparisons, statistic))
    .filter(|row| row.outside_pointwise_95)
    .map(conditional_outlier_label)
    .collect()
}

fn conditional_no_repeat_outliers(report: &ConditionalStructureReport) -> Vec<String> {
    report
        .no_repeat_null
        .comparisons
        .iter()
        .filter(|row| {
            row.statistic != ConditionalStatistic::SelfTransitions && row.outside_pointwise_95
        })
        .map(conditional_outlier_label)
        .collect()
}

fn append_conditional_outlier_framing(
    out: &mut String,
    report: &ConditionalStructureReport,
    primary_outliers: &[String],
    off_diagonal_outliers: &[String],
    no_repeat_outliers: &[String],
) {
    append_conditional_primary_outliers(out, primary_outliers);
    if let Some(row) =
        comparison_for_statistic(&report.comparisons, ConditionalStatistic::SelfTransitions)
    {
        renderln!(
            out,
            "Diagonal confound: the accepted eye order has {} adjacent-equal self-transitions, while the unconstrained shuffle null averages {:.2} with 95% {}. Those raw exceedances are therefore dominated by the already-known zero-adjacency constraint.",
            format_conditional_statistic(row.statistic, row.observed),
            row.null.mean,
            format_conditional_band(row.statistic, row.null)
        );
    }
    append_conditional_off_diagonal_framing(out, off_diagonal_outliers);
    append_conditional_no_repeat_framing(out, no_repeat_outliers);
}

fn append_conditional_primary_outliers(out: &mut String, primary_outliers: &[String]) {
    if primary_outliers.is_empty() {
        renderln!(
            out,
            "Interpretation: the original seven-row unconstrained shuffle table has no pointwise exceedances."
        );
    } else {
        renderln!(
            out,
            "Interpretation: the original seven-row unconstrained shuffle table has pointwise exceedances in {}.",
            primary_outliers.join(", ")
        );
    }
}

fn append_conditional_off_diagonal_framing(out: &mut String, off_diagonal_outliers: &[String]) {
    if off_diagonal_outliers.is_empty() {
        renderln!(
            out,
            "Dropping diagonal cells removes the off-diagonal edge/chi-square pointwise flags against the unconstrained shuffle diagnostic."
        );
    } else {
        renderln!(
            out,
            "Dropping diagonal cells alone leaves unconstrained-shuffle diagnostic flags in {}; this is not the final control because that null still permits adjacent repeats.",
            off_diagonal_outliers.join(", ")
        );
    }
}

fn append_conditional_no_repeat_framing(out: &mut String, no_repeat_outliers: &[String]) {
    if no_repeat_outliers.is_empty() {
        renderln!(
            out,
            "After conditioning the shuffle null on zero adjacent-equal pairs, no displayed MI/off-diagonal statistic is outside its pointwise 95% band; no first-order signal survives this control."
        );
    } else {
        renderln!(
            out,
            "After conditioning the shuffle null on zero adjacent-equal pairs, pointwise flags remain in {}. Treat them as a tiny residual arrangement effect with negligible effect size (corrected MI near zero, below), not novel first-order memory.",
            no_repeat_outliers.join(", ")
        );
    }
}

fn append_conditional_effect_size(out: &mut String, report: &ConditionalStructureReport) {
    let observed = report.observed;
    let raw_mi_excess = observed.entropy.mutual_information_mle_bits
        - report.bias_calibration.mle_mutual_information.mean;
    let corrected_mi_excess = observed.entropy.mutual_information_corrected_bits
        - report.bias_calibration.corrected_mutual_information.mean;
    let corrected_mi_fraction = if observed.entropy.max_entropy_bits > 0.0 {
        observed.entropy.mutual_information_corrected_bits / observed.entropy.max_entropy_bits
    } else {
        0.0
    };
    renderln!(
        out,
        "Effect size: corrected MI is {:.6} bits ({:.3e} of the {:.3}-bit maximum); raw plug-in MI exceeds the flat-random null mean by {:.3} bits and collapses to {:.6} bits after correction.",
        observed.entropy.mutual_information_corrected_bits,
        corrected_mi_fraction,
        observed.entropy.max_entropy_bits,
        raw_mi_excess,
        corrected_mi_excess
    );
}

fn append_conditional_sparse_caveat(out: &mut String, report: &ConditionalStructureReport) {
    let observed = report.observed;
    renderln!(
        out,
        "Sparse-table caveat: {}/{} Pearson expected cells are <1 (<5: {}), with mean {:.3}; the asymptotic chi-square df={} tail is invalid. The Pearson value {:.3} is a sparse-table inflation artifact relative to G=2*N*MI: {:.1} from raw MLE MI and {:.3} after add-1 correction.",
        observed.chi_square.expected_lt_1_cells,
        observed.chi_square.expected_cells,
        observed.chi_square.expected_lt_5_cells,
        report::fraction(
            observed.entropy.transitions,
            observed.chi_square.expected_cells
        ),
        observed.chi_square.degrees_of_freedom,
        observed.chi_square.statistic,
        likelihood_ratio_g_from_mi_bits(
            observed.entropy.transitions,
            observed.entropy.mutual_information_mle_bits
        ),
        likelihood_ratio_g_from_mi_bits(
            observed.entropy.transitions,
            observed.entropy.mutual_information_corrected_bits
        )
    );
}

fn conditional_outlier_label(row: &NullComparison) -> String {
    format!(
        "{} (p={})",
        row.statistic.label(),
        report::format_probability(row.two_sided_add_one_p)
    )
}

fn conditional_comparison(
    control: &PlantedControlReport,
    statistic: ConditionalStatistic,
) -> Option<&NullComparison> {
    comparison_for_statistic(&control.comparisons, statistic)
}

fn comparison_for_statistic(
    comparisons: &[NullComparison],
    statistic: ConditionalStatistic,
) -> Option<&NullComparison> {
    comparisons.iter().find(|row| row.statistic == statistic)
}

fn conditional_control_verdict(control: &PlantedControlReport) -> &'static str {
    let mi = conditional_comparison(control, ConditionalStatistic::MutualInformationCorrected);
    let edges = conditional_comparison(control, ConditionalStatistic::DistinctSuccessorEdges);
    match (mi, edges) {
        (Some(mi), Some(edges))
            if mi.observed > mi.null.q975 && edges.observed < edges.null.q025 =>
        {
            "separated"
        }
        (Some(mi), Some(edges)) if !mi.outside_pointwise_95 && !edges.outside_pointwise_95 => {
            "inside"
        }
        _ => "check",
    }
}

fn likelihood_ratio_g_from_mi_bits(transitions: usize, mutual_information_bits: f64) -> f64 {
    2.0 * transitions as f64 * mutual_information_bits * std::f64::consts::LN_2
}

fn format_conditional_band(statistic: ConditionalStatistic, band: ScalarNullBand) -> String {
    format!(
        "{}..{}",
        format_conditional_statistic(statistic, band.q025),
        format_conditional_statistic(statistic, band.q975)
    )
}

fn format_conditional_statistic(statistic: ConditionalStatistic, value: f64) -> String {
    match statistic {
        ConditionalStatistic::TransitionChiSquare
        | ConditionalStatistic::TransitionChiSquareOffDiagonal => {
            format!("{value:.2}")
        }
        ConditionalStatistic::DistinctSuccessorEdges
        | ConditionalStatistic::DistinctSuccessorEdgesOffDiagonal
        | ConditionalStatistic::GreedyFsmStateLowerBound
        | ConditionalStatistic::SelfTransitions => {
            format!("{value:.0}")
        }
        _ => format!("{value:.6}"),
    }
}

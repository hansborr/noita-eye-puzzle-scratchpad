//! Report rendering for the Noita eye-puzzle command-line tools.
//!
//! The functions in this module intentionally keep presentation separate from
//! the experiment engines. They render already-computed domain reports and
//! convert domain errors into user-facing CLI text.

use crate::glyph::Sequence;
use crate::{
    analysis, conditional_structure, gak_attack, grouping, orders, orientation_homogeneity,
};

/// A domain report that can render itself to user-facing CLI text.
pub trait Report {
    /// Renders this report as a complete, newline-terminated block of text.
    fn render(&self) -> String;
}

/// Appends formatted arguments followed by a newline to a rendered report.
pub(crate) fn append_line(out: &mut String, args: std::fmt::Arguments<'_>) {
    use std::fmt::Write as _;

    let _write_result = out.write_fmt(args);
    out.push('\n');
}

/// Appends a blank newline to a rendered report.
pub(crate) fn append_blank_line(out: &mut String) {
    out.push('\n');
}

macro_rules! appendln {
    ($out:expr) => {
        $crate::report::append_blank_line($out)
    };
    ($out:expr, $($arg:tt)*) => {
        $crate::report::append_line($out, format_args!($($arg)*))
    };
}

pub(crate) use appendln;

/// Formats a Thread 4 synthetic GAK-attack (GCTAK gate) error for CLI output.
#[must_use]
pub fn format_gak_attack_error(error: &gak_attack::GakAttackError) -> String {
    match error {
        gak_attack::GakAttackError::Cipher(cipher_error) => {
            format!("GAK-attack cipher error: {cipher_error}")
        }
        gak_attack::GakAttackError::RandomBoundTooLarge { bound } => {
            format!("random draw bound {bound} is too large for the in-crate sampler")
        }
        gak_attack::GakAttackError::ZeroSeeds => {
            "at least one seed per group kind is required for the gate matrix".to_owned()
        }
        gak_attack::GakAttackError::DihedralHalfOrderTooSmall { half_order } => {
            format!("dihedral half-order {half_order} is below 3 (would not be non-commutative)")
        }
        gak_attack::GakAttackError::CyclicOrderTooSmall { order } => {
            format!("cyclic order {order} is below 2")
        }
        gak_attack::GakAttackError::DeckStateSizeTooSmall { state_size } => format!(
            "deck size n={state_size} is below 3: the non-trivial-H deck attack requires n>=3 (n=2 is trivial-H GCTAK and collapses the merge threshold to 1)"
        ),
        gak_attack::GakAttackError::TooManyLetters {
            requested,
            available,
        } => format!(
            "requested {requested} plaintext letters but the group has only {available} non-identity generators"
        ),
        gak_attack::GakAttackError::TooFewLetters { requested } => format!(
            "requested {requested} plaintext letters but at least 2 are required (the dihedral non-commutative witness and a non-degenerate repeated-phrase partition both need >=2)"
        ),
        gak_attack::GakAttackError::SmallSupportRadiusUnsupported { requested } => format!(
            "small-support radius {requested} is rejected for the GCTAK gate, which runs unconstrained (radius 0); the small-support prior is exercised only by the deck/marginalization validation sweeps"
        ),
        gak_attack::GakAttackError::SymbolOutOfRange { value } => {
            format!("generated symbol {value} cannot be represented as a reading-layer value")
        }
        gak_attack::GakAttackError::EmptyTemplate => {
            "the generated plaintext template was empty".to_owned()
        }
        gak_attack::GakAttackError::PositiveControlFailed {
            group,
            seed,
            real_recovered,
            null_recovered,
        } => format!(
            "positive control failed for {group} seed {seed}: real_recovered={real_recovered}, null_recovered={null_recovered} (methodology bug, never a data finding)"
        ),
        gak_attack::GakAttackError::Grid(grid_error) => {
            format!("eye corpus grid/order error: {grid_error:?}")
        }
        gak_attack::GakAttackError::PerfectIsomorphism(error) => {
            format!("Thread-3 perfect-isomorphism consistency scan failed: {error}")
        }
        gak_attack::GakAttackError::HeldOutPositiveControlFailed {
            real_score,
            null_score,
        } => format!(
            "held-out positive control did not fire on the synthetic isomorph-rich fixture (real score={real_score} <= worst-case null score={null_score}); the held-out gate is not trustworthy (methodology bug, never an eye finding)"
        ),
        gak_attack::GakAttackError::Language(error) => {
            format!("language model for the SPECULATIVE cleartext gate could not be built: {error}")
        }
        gak_attack::GakAttackError::CandidateRecordWrite { path } => {
            format!("could not write the mandatory candidate record to {path}")
        }
        gak_attack::GakAttackError::EyesZeroTrials => {
            "the eyes Step-3 held-out gate needs at least one matched-null trial (zero trials would define the p-value over an empty sample)".to_owned()
        }
    }
}

/// Formats an Experiment 8 grouping error for CLI output.
#[must_use]
pub fn format_grouping_error(error: grouping::GroupingError) -> String {
    match error {
        grouping::GroupingError::Grid(grid_error) => format!("grid/order error: {grid_error:?}"),
        grouping::GroupingError::Language(language_error) => {
            format!("language model error: {language_error}")
        }
        grouping::GroupingError::Isomorph(isomorph_error) => {
            format!("isomorph detector error: {isomorph_error:?}")
        }
        grouping::GroupingError::InvalidStorageSymbol {
            message_index,
            symbol,
        } => format!("storage message {message_index} decoded invalid symbol {symbol}"),
        grouping::GroupingError::ZeroStateCount => {
            "synthetic calibration state count must be at least 1".to_owned()
        }
        grouping::GroupingError::StateCountTooLarge { state_count } => {
            format!("synthetic calibration state count {state_count} is too large")
        }
        grouping::GroupingError::RandomBoundTooLarge { bound } => {
            format!("synthetic calibration random bound {bound} is too large")
        }
    }
}

/// Formats an orientation homogeneity error for CLI output.
#[must_use]
pub fn format_orientation_homogeneity_error(
    error: orientation_homogeneity::OrientationHomogeneityError,
) -> String {
    match error {
        orientation_homogeneity::OrientationHomogeneityError::ZeroTrials => {
            "at least one repartition trial per seed is required".to_owned()
        }
        orientation_homogeneity::OrientationHomogeneityError::ZeroSeedCount => {
            "at least one deterministic seed stream is required".to_owned()
        }
        orientation_homogeneity::OrientationHomogeneityError::TrialCountTooLarge => {
            "trial count is too large for add-one p-value calibration".to_owned()
        }
        orientation_homogeneity::OrientationHomogeneityError::MessageCountMismatch {
            expected,
            observed,
        } => format!("expected {expected} verified messages, observed {observed}"),
        orientation_homogeneity::OrientationHomogeneityError::InvalidStorageSymbol {
            message_index,
            symbol,
        } => format!("storage message {message_index} decoded invalid symbol {symbol}"),
        orientation_homogeneity::OrientationHomogeneityError::EyeCountMismatch {
            message_key,
            expected,
            observed,
        } => format!(
            "{message_key} engine-derived orientation count {observed} did not match verified eye count {expected}"
        ),
        orientation_homogeneity::OrientationHomogeneityError::LengthTotalMismatch {
            lengths_total,
            pooled_total,
        } => format!(
            "per-message lengths sum to {lengths_total}, but pooled orientation count is {pooled_total}"
        ),
        orientation_homogeneity::OrientationHomogeneityError::RandomBoundTooLarge { bound } => {
            format!("random draw bound {bound} is too large")
        }
    }
}

/// Formats a first-order conditional-structure error for CLI output.
#[must_use]
pub fn format_conditional_structure_error(
    error: conditional_structure::ConditionalStructureError,
) -> String {
    match error {
        conditional_structure::ConditionalStructureError::Grid(grid_error) => {
            format!("grid/order error: {grid_error:?}")
        }
        conditional_structure::ConditionalStructureError::ZeroSeeds => {
            "at least one seed stream is required".to_owned()
        }
        conditional_structure::ConditionalStructureError::ZeroTrials => {
            "at least one shuffle trial per seed is required".to_owned()
        }
        conditional_structure::ConditionalStructureError::InvalidAlphabetSize { alphabet_size } => {
            format!("invalid alphabet size {alphabet_size}; expected 1..=125")
        }
        conditional_structure::ConditionalStructureError::TrialCountTooLarge => {
            "Monte-Carlo trial count is too large".to_owned()
        }
        conditional_structure::ConditionalStructureError::MatrixTooLarge { alphabet_size } => {
            format!("transition matrix for alphabet size {alphabet_size} is too large")
        }
        conditional_structure::ConditionalStructureError::ValueOutsideAlphabet {
            message_key,
            value,
            alphabet_size,
        } => format!(
            "{message_key}: reading-layer value {value} is outside alphabet size {alphabet_size}"
        ),
        conditional_structure::ConditionalStructureError::RandomBoundTooLarge { bound } => {
            format!("random draw bound {bound} is too large")
        }
        conditional_structure::ConditionalStructureError::NoRepeatNullRequiresNoAdjacentEqual {
            message_key,
        } => format!(
            "{message_key}: no-repeat conditioned null requires an input with no adjacent-equal transitions"
        ),
    }
}

/// Returns the singular or plural form for a report count.
pub(crate) fn counted_form(
    count: usize,
    singular: &'static str,
    plural: &'static str,
) -> &'static str {
    if count == 1 { singular } else { plural }
}

/// Formats keyed message lengths for report output.
pub(crate) fn format_message_lengths(lengths: &[(&'static str, usize)]) -> String {
    lengths
        .iter()
        .map(|(key, length)| format!("{key}:{length}"))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn format_null_flag(pointwise: bool, envelope: bool) -> &'static str {
    if envelope {
        "OUT"
    } else if pointwise {
        "pt95"
    } else {
        "inside"
    }
}

pub(crate) fn format_match_count(matches: usize, comparisons: usize) -> String {
    format!("{matches}/{comparisons}")
}

const PRIMARY_CONDITIONAL_REPORT_STATISTICS: [conditional_structure::ConditionalStatistic; 7] = [
    conditional_structure::ConditionalStatistic::NextEntropyCorrected,
    conditional_structure::ConditionalStatistic::ConditionalEntropyCorrected,
    conditional_structure::ConditionalStatistic::MutualInformationCorrected,
    conditional_structure::ConditionalStatistic::TransitionChiSquare,
    conditional_structure::ConditionalStatistic::DistinctSuccessorEdges,
    conditional_structure::ConditionalStatistic::SuccessorEntropy,
    conditional_structure::ConditionalStatistic::GreedyFsmStateLowerBound,
];

/// Prints the first-order conditional-structure and successor-graph report.
pub fn print_conditional_structure_report(
    report: &conditional_structure::ConditionalStructureReport,
) {
    let total_trials = report
        .config
        .seed_count
        .saturating_mul(report.config.trials_per_seed);
    println!("first-order conditional structure & successor graph");
    println!("order: {}", report.order.name());
    println!(
        "alphabet: accepted honeycomb reading-layer values 0..={}",
        report.config.alphabet_size.saturating_sub(1)
    );
    println!("base seed: {}", report.config.seed);
    println!(
        "shuffle null: {} seeds x {} trials/seed = {} within-message multiset-preserving shuffles",
        report.config.seed_count, report.config.trials_per_seed, total_trials
    );
    println!(
        "no-repeat null: symmetric swap-chain shuffles conditioned on zero adjacent-equal pairs ({} burn-in sweeps, {} sweeps/sample)",
        report.no_repeat_null.burn_in_sweeps, report.no_repeat_null.sample_sweeps
    );
    println!(
        "message lengths: {}",
        format_message_lengths(&report.message_lengths)
    );
    println!(
        "boundary rule: transitions are counted within each message only; no transition crosses a message join"
    );
    println!(
        "low-power caveat: {} symbols, {} transitions, and {} cells in an {}x{} matrix (mean {:.3} transitions/cell; {:.2} symbols/value). An inside-shuffle row is only a null-comparison result at this corpus size, not proof of memorylessness.",
        report.observed.matrix.symbols,
        report.observed.matrix.transitions,
        report.observed.matrix.matrix_cells,
        report.observed.matrix.alphabet_size,
        report.observed.matrix.alphabet_size,
        report.observed.matrix.mean_transitions_per_cell,
        report.observed.matrix.mean_symbols_per_value
    );
    println!(
        "entropy correction: add-constant alpha={:.1} over the full {}-symbol next-state support; raw plug-in MI is shown only as a sparse-sample diagnostic",
        report.observed.entropy.add_constant_alpha, report.config.alphabet_size
    );
    println!();
    print_conditional_observed(report);
    println!();
    print_conditional_comparisons(report);
    println!();
    print_conditional_diagonal_accounting(report);
    println!();
    print_conditional_no_repeat_comparisons(report);
    println!();
    print_conditional_bias_calibration(report);
    println!();
    print_conditional_controls(report);
    println!();
    print_conditional_interpretation(report);
}

fn print_conditional_observed(report: &conditional_structure::ConditionalStructureReport) {
    let observed = report.observed;
    println!("observed transition matrix");
    println!(
        "  nonzero cells: {}/{} ({:.3}% density)",
        observed.matrix.nonzero_cells,
        observed.matrix.matrix_cells,
        observed.matrix.density * 100.0
    );
    println!(
        "  active rows/cols: {}/{}; chi2 df {}; expected cells <1/<5: {}/{}",
        observed.chi_square.active_rows,
        observed.chi_square.active_columns,
        observed.chi_square.degrees_of_freedom,
        observed.chi_square.expected_lt_1_cells,
        observed.chi_square.expected_lt_5_cells
    );
    println!(
        "  H(next) raw/corrected: {:.4}/{:.4} bits; H(next|current) raw/corrected: {:.4}/{:.4} bits",
        observed.entropy.next_entropy_mle_bits,
        observed.entropy.next_entropy_corrected_bits,
        observed.entropy.conditional_entropy_mle_bits,
        observed.entropy.conditional_entropy_corrected_bits
    );
    println!(
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
    println!(
        "  diagonal: {} self-transitions in {} cells; fitted-independence expectation {:.2}; diagonal Pearson contribution {:.3}",
        observed.diagonal.self_transitions,
        report.config.alphabet_size,
        observed.diagonal.expected_self_transitions_independence,
        observed.diagonal.chi_square_contribution
    );
    println!(
        "  off-diagonal: {} edges over {} cells ({:.3}% density); chi2 contribution {:.3}; expected cells <1/<5: {}/{}",
        observed.off_diagonal.distinct_successor_edges,
        observed.off_diagonal.matrix_cells,
        observed.off_diagonal.edge_density * 100.0,
        observed.off_diagonal.chi_square_statistic,
        observed.off_diagonal.expected_lt_1_cells,
        observed.off_diagonal.expected_lt_5_cells
    );
    println!(
        "  successor graph: {} edges, mean out-degree {:.2}, max out-degree {}, successor entropy {:.4} bits, out-degree entropy {:.4} bits, FSM lower bound {} states",
        observed.graph.distinct_successor_edges,
        observed.graph.mean_out_degree,
        observed.graph.max_out_degree,
        observed.graph.successor_entropy_bits,
        observed.graph.out_degree_entropy_bits,
        observed.graph.greedy_fsm_state_lower_bound
    );
}

fn print_conditional_comparisons(report: &conditional_structure::ConditionalStructureReport) {
    println!("within-message shuffle comparisons (unconstrained, diagonal included)");
    println!(
        "{:<25} {:>12} {:>12} {:>19} {:>12} {:>10}",
        "statistic", "observed", "null med", "null 95%", "p two-sided", "flag"
    );
    for statistic in PRIMARY_CONDITIONAL_REPORT_STATISTICS {
        if let Some(row) = comparison_for_statistic(&report.comparisons, statistic) {
            print_conditional_comparison_row(row);
        }
    }
    println!(
        "p-values are two-sided add-one empirical values and pointwise over {} displayed statistics; no family-wise correction is claimed.",
        PRIMARY_CONDITIONAL_REPORT_STATISTICS.len()
    );
}

fn print_conditional_diagonal_accounting(
    report: &conditional_structure::ConditionalStructureReport,
) {
    let observed = report.observed;
    println!("diagonal/no-repeat accounting");
    if let Some(row) = comparison_for_statistic(
        &report.comparisons,
        conditional_structure::ConditionalStatistic::SelfTransitions,
    ) {
        println!(
            "  self transitions: eyes {}, unconstrained shuffle mean {:.2}, 95% {}, p {}; fitted-independence expectation {:.2}",
            format_conditional_statistic(row.statistic, row.observed),
            row.null.mean,
            format_conditional_band(row.statistic, row.null),
            format_probability(row.two_sided_add_one_p),
            observed.diagonal.expected_self_transitions_independence
        );
    }
    if let Some(row) = comparison_for_statistic(
        &report.comparisons,
        conditional_structure::ConditionalStatistic::DistinctSuccessorEdgesOffDiagonal,
    ) {
        println!(
            "  off-diagonal successor edges vs unconstrained shuffle: eyes {}, 95% {}, flag {}",
            format_conditional_statistic(row.statistic, row.observed),
            format_conditional_band(row.statistic, row.null),
            conditional_flag(row)
        );
    }
    if let Some(row) = comparison_for_statistic(
        &report.comparisons,
        conditional_structure::ConditionalStatistic::TransitionChiSquareOffDiagonal,
    ) {
        println!(
            "  off-diagonal Pearson contribution vs unconstrained shuffle: eyes {}, 95% {}, flag {}",
            format_conditional_statistic(row.statistic, row.observed),
            format_conditional_band(row.statistic, row.null),
            conditional_flag(row)
        );
    }
    println!(
        "  diagonal Pearson contribution is {:.3} of the full {:.3}; dropping diagonal cells is a diagnostic, while the no-repeat null below conditions the shuffles on the known zero-adjacency constraint.",
        observed.diagonal.chi_square_contribution, observed.chi_square.statistic
    );
}

fn print_conditional_no_repeat_comparisons(
    report: &conditional_structure::ConditionalStructureReport,
) {
    println!("no-repeat-conditioned shuffle comparisons");
    println!(
        "{:<25} {:>12} {:>12} {:>19} {:>12} {:>10}",
        "statistic", "observed", "null med", "null 95%", "p two-sided", "flag"
    );
    for row in &report.no_repeat_null.comparisons {
        print_conditional_comparison_row(row);
    }
    println!(
        "The chain preserves each message multiset and rejects swaps that would create x->x; p-values are empirical over recorded chain states, not asymptotic chi-square tails."
    );
}

fn print_conditional_comparison_row(row: &conditional_structure::NullComparison) {
    println!(
        "{:<25} {:>12} {:>12} {:>19} {:>12} {:>10}",
        row.statistic.label(),
        format_conditional_statistic(row.statistic, row.observed),
        format_conditional_statistic(row.statistic, row.null.median),
        format_conditional_band(row.statistic, row.null),
        format_probability(row.two_sided_add_one_p),
        conditional_flag(row)
    );
}

fn conditional_flag(row: &conditional_structure::NullComparison) -> &'static str {
    if row.outside_pointwise_95 {
        "pt95-out"
    } else {
        "inside"
    }
}

fn print_conditional_bias_calibration(report: &conditional_structure::ConditionalStructureReport) {
    let calibration = report.bias_calibration;
    println!("flat-random estimator-bias calibration (true MI = 0)");
    println!(
        "  trials: {}; alphabet: {}; matched message lengths",
        calibration.trials, calibration.alphabet_size
    );
    println!(
        "  plug-in MI mean {:.4}, abs-mean {:.4}, 95% {}",
        calibration.mle_mutual_information.mean,
        calibration.mle_mean_abs_mutual_information_bits,
        format_conditional_band(
            conditional_structure::ConditionalStatistic::MutualInformationCorrected,
            calibration.mle_mutual_information
        )
    );
    println!(
        "  add-1 MI mean {:.6}, abs-mean {:.6}, 95% {}",
        calibration.corrected_mutual_information.mean,
        calibration.corrected_mean_abs_mutual_information_bits,
        format_conditional_band(
            conditional_structure::ConditionalStatistic::MutualInformationCorrected,
            calibration.corrected_mutual_information
        )
    );
}

fn print_conditional_controls(report: &conditional_structure::ConditionalStructureReport) {
    println!("planted structure controls");
    println!(
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
        let mi = conditional_comparison(
            control,
            conditional_structure::ConditionalStatistic::MutualInformationCorrected,
        );
        let edges = conditional_comparison(
            control,
            conditional_structure::ConditionalStatistic::DistinctSuccessorEdges,
        );
        let verdict = conditional_control_verdict(control);
        println!(
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
    println!(
        "control construction: {}; {}.",
        report.controls.static_monoalphabetic.construction,
        report.controls.deck_permuted.construction
    );
}

fn print_conditional_interpretation(report: &conditional_structure::ConditionalStructureReport) {
    let primary_outliers = conditional_primary_outliers(report);
    let off_diagonal_outliers = conditional_off_diagonal_outliers(report);
    let no_repeat_outliers = conditional_no_repeat_outliers(report);

    print_conditional_outlier_framing(
        report,
        &primary_outliers,
        &off_diagonal_outliers,
        &no_repeat_outliers,
    );
    print_conditional_effect_size(report);
    print_conditional_sparse_caveat(report);
    println!(
        "Raw unconstrained exceedances are dominated by the known zero-adjacency constraint (above). Any exceedances that survive the no-repeat-conditioned null are not attributable to zero-adjacency (that null controls it) nor to table sparsity (those tails are empirical, not asymptotic); they reflect only a tiny residual arrangement effect whose honest effect size is negligible (corrected MI near zero, above). None of this is a plaintext/decryption claim or evidence of novel first-order memory. The planted controls still verify directionality for truly first-order-structured fixtures."
    );
}

fn conditional_primary_outliers(
    report: &conditional_structure::ConditionalStructureReport,
) -> Vec<String> {
    PRIMARY_CONDITIONAL_REPORT_STATISTICS
        .iter()
        .filter_map(|&statistic| comparison_for_statistic(&report.comparisons, statistic))
        .filter(|row| row.outside_pointwise_95)
        .map(conditional_outlier_label)
        .collect()
}

fn conditional_off_diagonal_outliers(
    report: &conditional_structure::ConditionalStructureReport,
) -> Vec<String> {
    [
        conditional_structure::ConditionalStatistic::TransitionChiSquareOffDiagonal,
        conditional_structure::ConditionalStatistic::DistinctSuccessorEdgesOffDiagonal,
    ]
    .iter()
    .filter_map(|&statistic| comparison_for_statistic(&report.comparisons, statistic))
    .filter(|row| row.outside_pointwise_95)
    .map(conditional_outlier_label)
    .collect()
}

fn conditional_no_repeat_outliers(
    report: &conditional_structure::ConditionalStructureReport,
) -> Vec<String> {
    report
        .no_repeat_null
        .comparisons
        .iter()
        .filter(|row| {
            row.statistic != conditional_structure::ConditionalStatistic::SelfTransitions
                && row.outside_pointwise_95
        })
        .map(conditional_outlier_label)
        .collect()
}

fn print_conditional_outlier_framing(
    report: &conditional_structure::ConditionalStructureReport,
    primary_outliers: &[String],
    off_diagonal_outliers: &[String],
    no_repeat_outliers: &[String],
) {
    print_conditional_primary_outliers(primary_outliers);
    if let Some(row) = comparison_for_statistic(
        &report.comparisons,
        conditional_structure::ConditionalStatistic::SelfTransitions,
    ) {
        println!(
            "Diagonal confound: the accepted eye order has {} adjacent-equal self-transitions, while the unconstrained shuffle null averages {:.2} with 95% {}. Those raw exceedances are therefore dominated by the already-known zero-adjacency constraint.",
            format_conditional_statistic(row.statistic, row.observed),
            row.null.mean,
            format_conditional_band(row.statistic, row.null)
        );
    }
    print_conditional_off_diagonal_framing(off_diagonal_outliers);
    print_conditional_no_repeat_framing(no_repeat_outliers);
}

fn print_conditional_primary_outliers(primary_outliers: &[String]) {
    if primary_outliers.is_empty() {
        println!(
            "Interpretation: the original seven-row unconstrained shuffle table has no pointwise exceedances."
        );
    } else {
        println!(
            "Interpretation: the original seven-row unconstrained shuffle table has pointwise exceedances in {}.",
            primary_outliers.join(", ")
        );
    }
}

fn print_conditional_off_diagonal_framing(off_diagonal_outliers: &[String]) {
    if off_diagonal_outliers.is_empty() {
        println!(
            "Dropping diagonal cells removes the off-diagonal edge/chi-square pointwise flags against the unconstrained shuffle diagnostic."
        );
    } else {
        println!(
            "Dropping diagonal cells alone leaves unconstrained-shuffle diagnostic flags in {}; this is not the final control because that null still permits adjacent repeats.",
            off_diagonal_outliers.join(", ")
        );
    }
}

fn print_conditional_no_repeat_framing(no_repeat_outliers: &[String]) {
    if no_repeat_outliers.is_empty() {
        println!(
            "After conditioning the shuffle null on zero adjacent-equal pairs, no displayed MI/off-diagonal statistic is outside its pointwise 95% band; no first-order signal survives this control."
        );
    } else {
        println!(
            "After conditioning the shuffle null on zero adjacent-equal pairs, pointwise flags remain in {}. Treat them as a tiny residual arrangement effect with negligible effect size (corrected MI near zero, below), not novel first-order memory.",
            no_repeat_outliers.join(", ")
        );
    }
}

fn print_conditional_effect_size(report: &conditional_structure::ConditionalStructureReport) {
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
    println!(
        "Effect size: corrected MI is {:.6} bits ({:.3e} of the {:.3}-bit maximum); raw plug-in MI exceeds the flat-random null mean by {:.3} bits and collapses to {:.6} bits after correction.",
        observed.entropy.mutual_information_corrected_bits,
        corrected_mi_fraction,
        observed.entropy.max_entropy_bits,
        raw_mi_excess,
        corrected_mi_excess
    );
}

fn print_conditional_sparse_caveat(report: &conditional_structure::ConditionalStructureReport) {
    let observed = report.observed;
    println!(
        "Sparse-table caveat: {}/{} Pearson expected cells are <1 (<5: {}), with mean {:.3}; the asymptotic chi-square df={} tail is invalid. The Pearson value {:.3} is a sparse-table inflation artifact relative to G=2*N*MI: {:.1} from raw MLE MI and {:.3} after add-1 correction.",
        observed.chi_square.expected_lt_1_cells,
        observed.chi_square.expected_cells,
        observed.chi_square.expected_lt_5_cells,
        fraction(
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

fn conditional_outlier_label(row: &conditional_structure::NullComparison) -> String {
    format!(
        "{} (p={})",
        row.statistic.label(),
        format_probability(row.two_sided_add_one_p)
    )
}

fn conditional_comparison(
    control: &conditional_structure::PlantedControlReport,
    statistic: conditional_structure::ConditionalStatistic,
) -> Option<&conditional_structure::NullComparison> {
    comparison_for_statistic(&control.comparisons, statistic)
}

fn comparison_for_statistic(
    comparisons: &[conditional_structure::NullComparison],
    statistic: conditional_structure::ConditionalStatistic,
) -> Option<&conditional_structure::NullComparison> {
    comparisons.iter().find(|row| row.statistic == statistic)
}

fn conditional_control_verdict(
    control: &conditional_structure::PlantedControlReport,
) -> &'static str {
    let mi = conditional_comparison(
        control,
        conditional_structure::ConditionalStatistic::MutualInformationCorrected,
    );
    let edges = conditional_comparison(
        control,
        conditional_structure::ConditionalStatistic::DistinctSuccessorEdges,
    );
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

fn format_conditional_band(
    statistic: conditional_structure::ConditionalStatistic,
    band: conditional_structure::ScalarNullBand,
) -> String {
    format!(
        "{}..{}",
        format_conditional_statistic(statistic, band.q025),
        format_conditional_statistic(statistic, band.q975)
    )
}

fn format_conditional_statistic(
    statistic: conditional_structure::ConditionalStatistic,
    value: f64,
) -> String {
    match statistic {
        conditional_structure::ConditionalStatistic::TransitionChiSquare
        | conditional_structure::ConditionalStatistic::TransitionChiSquareOffDiagonal => {
            format!("{value:.2}")
        }
        conditional_structure::ConditionalStatistic::DistinctSuccessorEdges
        | conditional_structure::ConditionalStatistic::DistinctSuccessorEdgesOffDiagonal
        | conditional_structure::ConditionalStatistic::GreedyFsmStateLowerBound
        | conditional_structure::ConditionalStatistic::SelfTransitions => {
            format!("{value:.0}")
        }
        _ => format!("{value:.6}"),
    }
}

/// Returns `numerator / denominator`, with zero for an empty denominator.
pub(crate) fn fraction(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

/// Formats a fraction as a one-decimal percentage.
pub(crate) fn format_percent(fraction: f64) -> String {
    format!("{:.1}%", fraction * 100.0)
}

/// Formats a probability for report output.
pub(crate) fn format_probability(value: f64) -> String {
    if value < 0.001 {
        format!("{value:.3e}")
    } else {
        format!("{value:.6}")
    }
}

/// Prints the Thread 4 synthetic GAK-attack / GCTAK decisive-gate report.
pub fn print_gak_attack_report(report: &gak_attack::GakAttackReport) {
    println!("Thread 4 synthetic GAK-attack (GCTAK decisive gate)");
    println!("hidden subgroup: {}", report.hidden_subgroup.label());
    println!("seed: {}", report.config.seed);
    println!("seeds per group kind: {}", report.config.seeds_per_kind);
    println!(
        "cyclic order: {}; dihedral D_2k half-order k: {}",
        report.config.cyclic_order, report.config.dihedral_half_order
    );
    println!(
        "plaintext letters: {}; phrase repeats: {}; phrase length: {}",
        report.config.num_pt_letters, report.config.phrase_repeats, report.config.phrase_len
    );
    println!(
        "TENTATIVE small-support radius (<=k transpositions): {} (0 = unconstrained gate regime)",
        report.config.small_support_radius
    );
    println!(
        "wiki pages this unit encodes: Group-Autokey-(GAK).md; Group-Ciphertext-Autokey-(GCTAK).md; Alphabet-Chaining.md / Graph-Chaining.md"
    );
    println!();
    print_gak_attack_rates(report);
    println!();
    print_gak_attack_outcomes(report);
    println!();
    print_gak_attack_exemplars(report);
    println!();
    print_gak_attack_deck(report);
    println!();
    print_gak_attack_marginalization(report);
    println!();
    print_gak_attack_interpretation(report);
}

fn print_gak_attack_marginalization(report: &gak_attack::GakAttackReport) {
    let marg = &report.marginalization;
    println!(
        "UNIT 2b hidden-state marginalization (idea 3) + TENTATIVE small-support prior (idea 2)"
    );
    println!(
        "  idea 3 overcomes the unit-2a obstruction: instead of collapsing each phrase column to its single-valued core (the 2a baseline), a BOUNDED BEAM / belief-propagation over the hidden-state branches admits the multi-valued branches that GENERALIZE to a HELD-OUT chain-link fold (a TRAIN/HELD-OUT split of the same column's occurrences). The recovered object is the per-letter visible-coset edge MARGINAL over hidden states (multi-valued from allowed) -- a PARTIAL visible-coset action recovery, NOT a recovered key, NOT the plaintext->group-element mapping. SYNTHETIC-ONLY."
    );
    println!(
        "  beam width bound: {} (DISCLOSED, no silent truncation; dropped beams are reported per n)",
        marg.beam_width
    );
    println!(
        "  small-support prior (idea 2) for the headline sweep: {}",
        marg.prior.label()
    );
    println!(
        "  decimals tagged (mean) are PER-SEED MEAN fractions; the recov/edges columns are AGGREGATE totals over all seeds (the aggregate ratio differs slightly from the per-seed mean)."
    );
    println!(
        "  {:<4} {:>12} {:>7} {:>13} {:>11} {:>9} {:>11} {:>9} {:>11} {:>8} {:>8} {:>7} {:>8}",
        "n",
        "|H|=(n-1)!",
        "seeds",
        "i3 recov/edges",
        "i3 (mean)",
        "core recov",
        "core (mean)",
        "null recov",
        "null (mean)",
        "i3>core",
        "i3>null",
        "p",
        "dropped"
    );
    for point in &marg.points {
        println!(
            "  {:<4} {:>12} {:>7} {:>13} {:>11} {:>9} {:>11} {:>9} {:>11} {:>8} {:>8} {:>7} {:>8}",
            point.state_size,
            point.hidden_subgroup_order,
            point.seeds,
            format!("{}/{}", point.idea3_true_total, point.truth_edges_total),
            format!("{:.3}", point.idea3_mean_fraction),
            point.baseline_true_total,
            format!("{:.3}", point.baseline_mean_fraction),
            point.null_true_total,
            format!("{:.3}", point.null_mean_fraction),
            yes_no(point.idea3_beats_baseline),
            yes_no(point.idea3_beats_null),
            format!("{:.3}", point.matched_null_p_value),
            point.beams_dropped
        );
    }
    println!(
        "  MEASURED result: idea-3 marginalization recovers SEVERAL-FOLD more true per-letter coset edges than the 2a single-valued core at every n (the multi-valued branches the core discards are most of the action), and beats the matched null. It is STRONGEST at the smallest n and BREAKS as the hidden-state count |H| = (n-1)! grows (the train fold samples a shrinking share of the hidden states), degrading toward -- never below -- the 2a baseline. \"Helps on small n, breaks as n grows\" is the expected, reportable outcome, not a thread failure. (This wording holds on the default-seed sweep; non-default --seed runs are not gate-guaranteed -- see the table above.)"
    );
    print_gak_attack_small_support(&marg.small_support_validation);
}

fn print_gak_attack_small_support(v: &gak_attack::SmallSupportValidation) {
    println!(
        "  TENTATIVE small-support prior validation (idea 2; the prior is a heuristic to validate, NOT a hard constraint, labelled everywhere)"
    );
    println!(
        "    method: generate fixtures WITH small-support truth and WITHOUT (unconstrained S_n), run idea-3 with the prior OFF and ON in each (n={}, {} seeds), and measure edge-recall + edge-precision.",
        v.state_size, v.seeds
    );
    println!(
        "    small-support truth: recall on/off = {}/{} of {}; precision on/off = {:.3}/{:.3}",
        v.small_truth_prior_on,
        v.small_truth_prior_off,
        v.small_truth_total,
        v.small_precision(true),
        v.small_precision(false)
    );
    println!(
        "    unconstrained truth: recall on/off = {}/{} of {}; precision on/off = {:.3}/{:.3}",
        v.broad_truth_prior_on,
        v.broad_truth_prior_off,
        v.broad_truth_total,
        v.broad_precision(true),
        v.broad_precision(false)
    );
    println!(
        "    prior FAILS GRACEFULLY (the robust, structural guarantee): {} -- its confidence floor only ever DROPS genuine low-support edges (recall ON <= OFF in both conditions) and never invents any, so precision is held or improved and a WRONG small-support assumption is never rewarded.",
        yes_no(v.prior_fails_gracefully())
    );
    println!(
        "    prior is SELECTIVELY discriminative (weak, TENTATIVE signal): {} -- in the deck realization the near-identity structure of the per-letter permutations only WEAKLY survives into the visible-coset marginal (hidden-state cycling spreads the marked card), so the prior helps small-support truth only marginally more than unconstrained truth. This thin margin is reported as TENTATIVE; the graceful-failure property is the load-bearing result.",
        yes_no(v.prior_is_discriminative())
    );
}

fn print_gak_attack_deck(report: &gak_attack::GakAttackReport) {
    let deck = &report.deck;
    println!(
        "REAL-GAK deck attack (non-trivial hidden subgroup H = Stab(top) = S_(n-1), |H| = (n-1)! > 1)"
    );
    println!(
        "  this is the community's stated open problem. What this unit recovers is PARTIAL visible-coset action recovery (a fraction of per-letter visible-coset transitions; NOT a recovered key, NOT the plaintext->group-element mapping), plus a MEASURED bound on how far that gets. SYNTHETIC-ONLY (we hold ground truth)."
    );
    println!("  per-letter draw regime: {}", deck.regime.label());
    println!(
        "  measured obstruction: under non-trivial H the visible transition depends on the FULL hidden state, so most of a letter's visible-coset action is multi-valued across hidden states. The recoverable part (single-valued core) is bounded by this multi-valuedness -- which MOTIVATES idea 3 (hidden-state marginalization)."
    );
    println!(
        "  {:<4} {:>12} {:>7} {:>20} {:>20} {:>12} {:>14} {:>9} {:>6}",
        "n",
        "|H|=(n-1)!",
        "seeds",
        "real (recov/letters)",
        "null (recov/letters)",
        "real>null",
        "multivalued-frac",
        "aborts",
        "p"
    );
    for tp in &deck.tractability {
        println!(
            "  {:<4} {:>12} {:>7} {:>11} {:>8} {:>11} {:>8} {:>12} {:>14} {:>9} {:>6}",
            tp.state_size,
            tp.hidden_subgroup_order,
            tp.seeds,
            format!("{}/{}", tp.real_recovered_total, tp.letters_total),
            format!("{:.3}", tp.real_mean_fraction),
            format!("{}/{}", tp.null_recovered_total, tp.letters_total),
            format!("{:.3}", tp.null_mean_fraction),
            yes_no(tp.real_beats_null),
            format!("{:.3}", tp.multi_valued_fraction),
            tp.true_conflict_aborts,
            format!("{:.3}", tp.matched_null_p_value)
        );
    }
    println!(
        "  multivalued-frac: the MEASURED hidden-state obstruction (fraction of visible cosets that map multi-valued under a fixed letter). Larger => less recoverable here; this is the headline honest result of the unit and the motivation for idea 3."
    );
    println!(
        "  fixed-context TRUE-conflict aborts (a FEATURE, not a bug): occurrence-pair alignments where two arrows out of / into one symbol under ONE fixed alignment proved a bad isomorph alignment and were dropped, protecting honesty. (Cross-hidden-state multi-valuedness is NOT a conflict -- it is the measured obstruction above.)"
    );
    println!(
        "  beats matched null on the easiest fixture (n={}): {}",
        deck.easiest_state_size,
        yes_no(deck.beats_null_on_easiest)
    );
    println!(
        "  measured negative is the deliverable: partial visible-coset action recovery stays SMALL and roughly FLAT across n (it does NOT climb with n), bounded by the hidden-state obstruction; this is the expected, reportable outcome, not a thread failure. The matched null is destroyed at small n and only begins to match real at larger n / some seeds. (This wording holds on the default-seed sweep; non-default --seed runs are not gate-guaranteed -- see the table above.)"
    );
    println!(
        "  the per-seed p-value is conservative (high per-fixture variance) and is non-significant on its own -- say so; the aggregate contrast is the AGGREGATE recovered-letter count real vs null."
    );
    println!(
        "  TENTATIVE small-support prior + hidden-state marginalization are the NEXT unit: this unit only generates both regimes and leaves documented hooks (the overlap-threshold merge and the single-valued-core light merge), it does NOT apply those priors."
    );
}

fn print_gak_attack_rates(report: &gak_attack::GakAttackReport) {
    println!("rate-beats-null gate (the gate is the RATE vs null, NOT a single seed)");
    println!(
        "  required minimum real recovery rate per group kind: {:.3}",
        report.min_real_recovery_rate
    );
    println!(
        "  {:<10} {:<7} {:>6} {:>18} {:>18}",
        "group", "noncomm", "seeds", "real-rate (real/n)", "null-rate (null/n)"
    );
    for rate in &report.rates {
        println!(
            "  {:<10} {:<7} {:>6} {:>10} {:>7} {:>10} {:>7}",
            rate.group,
            yes_no(rate.non_commutative),
            rate.seeds,
            format!("{:.3}", rate.real_fraction()),
            format!("{}/{}", rate.real_recovered, rate.seeds),
            format!("{:.3}", rate.null_fraction()),
            format!("{}/{}", rate.null_recovered, rate.seeds)
        );
    }
    println!(
        "  rate-vs-null gate passed (real rate clears floor AND strictly exceeds matched-null rate): {}",
        yes_no(report.rate_gate_passed)
    );
    println!(
        "  matched shuffle null failed to recover on every independent seed (required contrast): {}",
        yes_no(report.all_null_failed)
    );
}

fn print_gak_attack_outcomes(report: &gak_attack::GakAttackReport) {
    println!("per-seed outcomes and per-letter permutation-recovery fractions (real vs null)");
    println!(
        "  {:<10} {:>10} {:>6} {:>20} {:>20} {:>16}",
        "group", "|G|/real", "ct-len", "real perm-recovery", "null perm-recovery", "chain-links ok"
    );
    for outcome in &report.outcomes {
        println!(
            "  {:<10} {:>5}/{:<4} {:>6} {:>13} {:>6} {:>13} {:>6} {:>8}/{:<7}",
            outcome.group,
            outcome.group_order,
            outcome.realized_order,
            outcome.ciphertext_len,
            format!(
                "{}/{}",
                outcome.real_permutations_recovered, outcome.permutations_total
            ),
            format!(
                "{:.3}",
                fraction(
                    outcome.real_permutations_recovered,
                    outcome.permutations_total
                )
            ),
            format!(
                "{}/{}",
                outcome.null_permutations_recovered, outcome.permutations_total
            ),
            format!(
                "{:.3}",
                fraction(
                    outcome.null_permutations_recovered,
                    outcome.permutations_total
                )
            ),
            outcome.chain_link_consistent,
            outcome.chain_link_checks
        );
    }
}

fn print_gak_attack_exemplars(report: &gak_attack::GakAttackReport) {
    println!(
        "retry-selected exemplars (ILLUSTRATIONS ONLY, NOT pass evidence; the gate passes on the RATE above)"
    );
    for exemplar in &report.exemplars {
        let outcome = exemplar.outcome;
        println!(
            "  {} exemplar: seed {} found after {} attempt(s); real per-letter permutation recovery {}/{}; chain-links {}/{} satisfied",
            outcome.group,
            outcome.seed,
            exemplar.attempts_used,
            outcome.real_permutations_recovered,
            outcome.permutations_total,
            outcome.chain_link_consistent,
            outcome.chain_link_checks
        );
    }
    println!(
        "  note: an exemplar is an illustration of one worked seed, not evidence every seed recovers."
    );
}

fn print_gak_attack_interpretation(report: &gak_attack::GakAttackReport) {
    if report.rate_gate_passed {
        println!(
            "Interpretation: on these SYNTHETIC-ONLY GCTAK fixtures (we hold the ground-truth key), the extended-chaining solver recovers per-letter permutations at a real rate that clears the documented floor and strictly beats its matched within-message shuffle null. This validates the methodology as a positive control; it is NOT a decode."
        );
    } else {
        println!(
            "Interpretation: the rate-beats-null gate did not pass for every group kind on these SYNTHETIC-ONLY fixtures. A negative or partial result is the expected, reportable outcome of the broader GAK thread, not a failure of it."
        );
    }
    println!(
        "REAL-GAK deck interpretation: on the non-trivial-H deck stabilizer (real GAK, |H|>1) the attack achieves PARTIAL visible-coset action recovery (a fraction of per-letter visible-coset transitions; NOT a recovered key, NOT the plaintext->group-element mapping). That fraction stays SMALL and roughly FLAT across n -- bounded by the MEASURED hidden-state obstruction (the multi-valuedness of the visible-coset action across hidden states), which is the part not recoverable without idea 3. The matched null is destroyed at small n and only begins to match real at larger n / some seeds. This measured obstruction is the contribution the wiki asks for and motivates idea 3; it is computed on SYNTHETIC ground truth and says nothing about the eyes. (The FLAT/destroyed-null wording holds on the default-seed sweep; non-default --seed runs are not gate-guaranteed -- see the table above.)"
    );
    println!(
        "UNIT 2b idea-3 interpretation: hidden-state marginalization (a bounded beam over hidden-state branches, scored by held-out chain links) recovers MARKEDLY more of the per-letter visible-coset action than the 2a single-valued-core baseline on SYNTHETIC small-n deck GAK -- but only PARTIAL visible-coset action recovery (an edge marginal over hidden states), NEVER a recovered key and NEVER the plaintext->group-element mapping. It breaks as |H| = (n-1)! grows; a marginal/negative result at larger n is the expected outcome. The TENTATIVE small-support prior is validated (fails gracefully; only weakly discriminative in this realization) and is OFF in the headline sweep so no result silently depends on it. The beam width and dropped-beam counts are disclosed (no silent truncation). (The MARKEDLY-more wording holds on the default-seed sweep; non-default --seed runs are not gate-guaranteed -- see the table above.)"
    );
    println!(
        "Synthetic-only disclaimer: this unit NEVER touches the eye corpus; it generates and solves its own GCTAK ciphertexts whose key it holds. No claim here transfers to the eyes."
    );
    println!(
        "Claim ceiling: the eyes remain deterministic, engine-generated, strikingly structured data of unknown meaning; unsolved; no primary developer source confirms recoverable plaintext. This run says nothing about recoverable eye plaintext."
    );
    println!(
        "TENTATIVE small-support prior: the <=k-swaps / small-support search heuristic is a TENTATIVE prior to validate, not a hard constraint; the GCTAK gate runs unconstrained (radius 0) and does not depend on it."
    );
    println!(
        "Reportable-negative framing: a negative or partial recovery result in later GAK steps is the expected, reportable outcome, not a thread failure."
    );
}

/// Prints the Thread 4 EYES Step-3 report: the ONLY unit touching the real eyes.
///
/// This is the highest honesty-risk surface in the project. Every line preserves
/// the claim ceiling, states the expected outcome is NO surviving candidate, reports
/// the held-out + Thread-3 verdicts, labels everything HYPOTHESIS-not-decode, and
/// NEVER implies a decode.
pub fn print_gak_attack_eyes_report(report: &gak_attack::EyesAttackReport) {
    println!("Thread 4 EYES Step 3 (the ONLY unit that touches the real eye corpus)");
    println!(
        "Claim ceiling: the eyes are deterministic, engine-generated, strikingly structured data of unknown meaning; unsolved; no primary developer source confirms recoverable plaintext. Nothing here is stronger."
    );
    println!(
        "Expected outcome: NO surviving candidate. The standing conclusion is the eye decode remains BLOCKED on the unknown symbol->meaning mapping; a clean honest negative is a SUCCESS, not a failure."
    );
    println!(
        "What is recovered: STRUCTURE (visible-coset / chain-link constraints), NOT cleartext. A full structural recovery still yields abstract plaintext-letter INDICES, not readable text, because symbol->letter mapping needs an external ANCHOR (the standing blocker). Any candidate is a HYPOTHESIS, never a decode."
    );
    println!(
        "entry path (exact): orders::corpus_grids() -> accepted_honeycomb_order() -> read_corpus_message_values (per-message, boundaries kept, never concatenated, never re-ordered)"
    );
    println!(
        "  reading order `{}`; {} reading-layer symbols; {} distinct (the 83-symbol reading layer); {} messages",
        report.order_name,
        report.total_symbols,
        report.distinct_symbols,
        report.per_message.len()
    );
    println!();
    print_eyes_gate1(report);
    println!();
    print_eyes_gates_2_3_verdict(report);
}

/// Prints the EYES Step-3 Gate-1 (held-out isomorphs) section.
fn print_eyes_gate1(report: &gak_attack::EyesAttackReport) {
    // GATE 1: held-out isomorphs (embargoed-consensus coverage-weighted score).
    println!("GATE 1 -- held-out isomorphs vs matched within-message shuffle null");
    println!(
        "  statistic: EMBARGOED-CONSENSUS coverage-weighted excess correctness. The recovered model is a LIBRARY of context-colored partial permutations (one per TRAIN isomorph occurrence pair), NOT a collapsed global symbol map. A held-out edge scores only when >=2 train contexts from DISTINCT signature groups -- with NO physical span overlap/adjacency with the held-out context -- AGREE on it; that embargo kills the nested/overlapping-window leak a within-message shuffle mimics, so only genuinely TRANSFERABLE structure scores. score = (A-1)*hits - A*misses (ambiguous unpenalized), A=83, with a per-message COVERAGE CLAMP that zeroes any message with < 4 confident decisions (an explicit part of the statistic, applied identically to real and null). Gate-1 chaining is ENFORCED to stay within the Thread-3 safe isomorph extents (F2). A shuffle has no transferable structure detected by this gate, so it scores ~0."
    );
    println!(
        "  held-out POSITIVE CONTROL on a synthetic isomorph-rich eye-shaped fixture: real score {} vs worst-case null score {} (on {} scoreable edges) -> fired={} (the predictor must fire on KNOWN signal AND clear its OWN population's material-effect bar, or the gate is not trusted)",
        report.held_out_positive_control.real_score,
        report.held_out_positive_control.null_score,
        report.held_out_positive_control.scoreable_edges,
        yes_no(report.held_out_positive_control.fired)
    );
    println!(
        "  real eyes aggregate held-out: hits={} misses={} ambiguous={}; coverage-weighted score = {}",
        report.real_held_out_hits_total,
        report.real_held_out_misses_total,
        report.real_held_out_ambiguous_total,
        report.real_score
    );
    println!(
        "  matched within-message shuffle null: {} trials, {} >= real; null mean score {:.2}; add-one p = {:.4}",
        report.trials,
        report.null_at_least_real,
        report.null_mean_score,
        report.matched_null_p_value
    );
    println!(
        "  material-effect bar (p-value is NECESSARY, NOT sufficient), POPULATION-RELATIVE and FAIR to the eyes: the real-vs-null excess must reach {:.0}% of the eyes' OWN max achievable score = scoreable_edges*(A-1) = {}*{} = {:.0}, so threshold = {:.1} (BELOW the eyes' max, so genuine signal COULD clear it); met={} (the detector is validated: the positive control clears its own population's bar by the identical rule)",
        gak_attack::EYES_MATERIAL_EFFECT_FRACTION * 100.0,
        report.scoreable_edges,
        gak_attack::EYE_READING_ALPHABET_SIZE - 1,
        report.max_achievable_score,
        report.material_effect_threshold,
        yes_no(report.material_effect_met)
    );
    println!(
        "  GATE 1 VERDICT (held-out beats matched null AND clears the calibrated material-effect bar): {}",
        yes_no(report.held_out_beats_null)
    );
    println!("  per-message (boundaries kept; never concatenated):");
    println!(
        "    {:<6} {:>4} {:>10} {:>6} {:>8} {:>7} {:>5} {:>5} {:>5} {:>7}",
        "msg", "len", "iso-groups", "pairs", "touched", "aborts", "hits", "miss", "amb", "score"
    );
    for m in &report.per_message {
        println!(
            "    {:<6} {:>4} {:>10} {:>6} {:>8} {:>7} {:>5} {:>5} {:>5} {:>7}",
            m.message_key,
            m.length,
            m.isomorph_groups,
            m.aligned_pairs,
            m.symbols_touched,
            m.true_conflict_aborts,
            m.real_held_out_hits,
            m.real_held_out_misses,
            m.real_held_out_ambiguous,
            m.real_score
        );
    }
}

/// Prints the EYES Step-3 Gate-2 / Gate-3 sections, the verdict, and the
/// candidate-logging protocol (the honesty-lock tail).
fn print_eyes_gates_2_3_verdict(report: &gak_attack::EyesAttackReport) {
    // GATE 2: Thread-3 consistency.
    println!(
        "GATE 2 -- Thread-3 perfect-isomorphism consistency (Thread-3 API REUSED, never re-derived)"
    );
    println!(
        "  robust internal violations: {} (must be 0 -- a non-zero count is a manufactured TRUE conflict that would disqualify the model)",
        report.three_consistency.robust_internal_violations
    );
    println!(
        "  safe isomorph extents exported: {} (Gate-1 chaining is ENFORCED to stay within these per-message safe spans (F2): an occurrence window is admitted only inside a Thread-3 safe span, so chaining never over-extends past them)",
        report.three_consistency.safe_extents
    );
    println!(
        "  Thread-3 positive control fired: {}",
        yes_no(report.three_consistency.positive_control_fired)
    );
    println!(
        "  GATE 2 VERDICT (model consistent with Thread 3): {}",
        yes_no(report.three_consistency.consistent)
    );
    println!();

    // GATE 3: speculative cleartext.
    println!(
        "GATE 3 -- SPECULATIVE cleartext plausibility (LAST, Finnish-weighted, NEVER primary)"
    );
    match &report.speculative_cleartext {
        None => {
            println!(
                "  NOT RUN. Gate 1 and/or Gate 2 did not pass (the expected case), so the SPECULATIVE cleartext path is correctly NOT executed and NO candidate cleartext is reported."
            );
        }
        Some(s) => {
            println!(
                "  RAN (both structural gates passed). The symbol->letter mapping is a HYPOTHESIS, never recovered; this is NEVER primary evidence. Implied plaintext logged VERBATIM to the candidate record for human review (Finnish weighted highly -- Noita is Finnish)."
            );
            println!(
                "  Finnish bigram {:.4} vs matched-mapping null {:.4} -> beats={}; English bigram {:.4} vs null {:.4} -> beats={}",
                s.finnish_score,
                s.finnish_null_mean,
                yes_no(s.beats_finnish_null),
                s.english_score,
                s.english_null_mean,
                yes_no(s.beats_english_null)
            );
        }
    }
    println!();

    // The verdict + interpretation (honesty lock).
    println!(
        "THE VERDICT: candidate survived BOTH structural gates: {}",
        yes_no(report.candidate_survived)
    );
    if report.candidate_survived {
        println!(
            "Interpretation: a candidate survived the held-out + Thread-3 checks. It is logged as a HYPOTHESIS for human review, NOT a decode. The claim ceiling still binds: this is NOT a recovered eye plaintext. FLAGGED LOUDLY for human review."
        );
    } else {
        println!(
            "Interpretation: no candidate surfaced. This is the EXPECTED, reportable outcome -- with a near-S_83 group and very little eye text, recovered structure does not predict held-out isomorphs above the matched null (no transferable structure DETECTED BY THIS GATE). The eye decode REMAINS BLOCKED on the unknown symbol->meaning mapping. This is a HYPOTHESIS-free honest negative, NOT a decode."
        );
    }
    println!(
        "Candidate-logging protocol: every eyes run writes a dated, clock-free record under research/gak-threads/candidates/ capturing the attempt, the recovered-structure amount, the held-out verdict + matched-null p-value, the Thread-3 verdict, and the explicit HYPOTHESIS-not-decode label; any candidate cleartext (English OR Finnish) is logged VERBATIM for human review. This run's record: {}",
        report.record_path.display()
    );
}

/// Formats unsigned integer values as a comma-separated report list.
pub(crate) fn format_usize_values(values: &[usize]) -> String {
    if values.is_empty() {
        return "none".to_owned();
    }
    values
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

/// Returns a report-safe preview of `text`, truncating at a character boundary.
pub(crate) fn preview_text(text: &str, max_chars: usize) -> String {
    let mut preview = String::new();
    let mut omitted = false;
    for (index, symbol) in text.chars().enumerate() {
        if index >= max_chars {
            omitted = true;
            break;
        }
        preview.push(symbol);
    }
    if omitted {
        preview.push_str("...");
    }
    preview
}

pub(crate) fn format_positions(positions: &[usize]) -> String {
    let mut rendered = positions
        .iter()
        .take(12)
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",");
    if positions.len() > 12 {
        rendered.push_str(",...");
    }
    rendered
}

fn format_optional_f64(value: Option<f64>) -> String {
    value.map_or_else(|| "n/a".to_owned(), |number| format!("{number:.2}"))
}

fn format_optional_usize(value: Option<usize>) -> String {
    value.map_or_else(|| "none".to_owned(), |number| number.to_string())
}

/// Prints the cross-message orientation-frequency homogeneity report.
pub fn print_orientation_homogeneity_report(
    report: &orientation_homogeneity::OrientationHomogeneityReport,
) {
    println!("cross-message orientation-frequency homogeneity");
    println!("layer: engine-fixed single orientations 0..=4; delimiter 5 stripped");
    println!(
        "order independence: no honeycomb traversal, no trigram reading layer, no symbol-to-meaning guess"
    );
    println!("seed: {}", report.config.seed);
    println!("seed streams: {}", report.config.seed_count);
    println!("trials per seed: {}", report.config.trials_per_seed);
    println!(
        "total repartitions: {}",
        report
            .config
            .trials_per_seed
            .saturating_mul(report.config.seed_count)
    );
    println!(
        "message lengths: {}",
        format_orientation_profile_lengths(&report.profiles)
    );
    println!(
        "total orientations: {} (verified eye-count sum {})",
        report.total_orientations, report.total_eye_count
    );
    println!(
        "null: shuffle the pooled orientation multiset and repartition into the true message lengths"
    );
    println!();
    print_orientation_profiles(report);
    println!();
    print_orientation_uniform_context(report);
    println!();
    print_orientation_homogeneity_statistics(report);
    println!();
    print_orientation_repartition_null(report);
    println!();
    print_orientation_positive_control(report);
    println!();
    print_orientation_homogeneity_interpretation(report);
}

fn print_orientation_profiles(report: &orientation_homogeneity::OrientationHomogeneityReport) {
    println!("per-message orientation profiles");
    println!(
        "{:<6} {:>5} {:>5} {:>5} {:>5} {:>5} {:>5} {:>8} {:>8} {:>8} {:>8} {:>8}",
        "msg", "len", "c0", "c1", "c2", "c3", "c4", "f0", "f1", "f2", "f3", "f4"
    );
    for profile in &report.profiles {
        let [c0, c1, c2, c3, c4] = profile.counts;
        let [f0, f1, f2, f3, f4] = profile.frequencies;
        println!(
            "{:<6} {:>5} {:>5} {:>5} {:>5} {:>5} {:>5} {:>8.4} {:>8.4} {:>8.4} {:>8.4} {:>8.4}",
            profile.message_key, profile.length, c0, c1, c2, c3, c4, f0, f1, f2, f3, f4
        );
    }
}

fn print_orientation_uniform_context(
    report: &orientation_homogeneity::OrientationHomogeneityReport,
) {
    let uniform = report.pooled_uniform;
    println!("pooled orientation-frequency context");
    println!(
        "pooled counts: {}",
        format_orientation_counts(&uniform.counts)
    );
    println!(
        "pooled chi-square vs uniform: {} df {} p>=chi2 {}",
        format_chi_square(uniform.chi_square_vs_uniform),
        uniform.degrees_of_freedom,
        format_chi_square_p_value(uniform.asymptotic_upper_tail_p)
    );
}

fn print_orientation_homogeneity_statistics(
    report: &orientation_homogeneity::OrientationHomogeneityReport,
) {
    let homogeneity = report.homogeneity;
    println!("observed cross-message homogeneity statistics");
    println!(
        "Pearson X^2: {} df {} asymptotic p>=X^2 {}",
        format_chi_square(homogeneity.pearson_chi_square),
        homogeneity.degrees_of_freedom,
        format_chi_square_p_value(homogeneity.pearson_asymptotic_upper_tail_p)
    );
    println!(
        "G-test: {} df {} asymptotic p>=G {}",
        format_chi_square(homogeneity.g_test),
        homogeneity.degrees_of_freedom,
        format_chi_square_p_value(homogeneity.g_test_asymptotic_upper_tail_p)
    );
}

fn print_orientation_repartition_null(
    report: &orientation_homogeneity::OrientationHomogeneityReport,
) {
    println!("length-matched repartition null");
    println!(
        "{:<12} {:>10} {:>10} {:>19} {:>20} {:>10} {:>10} {:>10}",
        "stat", "observed", "mean", "null 95%", "null min/med/max", "p<=obs", "p>=obs", "p2"
    );
    print_homogeneity_null_row("Pearson X^2", report.pearson_null);
    print_homogeneity_null_row("G-test", report.g_test_null);
}

fn print_homogeneity_null_row(
    label: &str,
    comparison: orientation_homogeneity::HomogeneityNullComparison,
) {
    println!(
        "{:<12} {:>10} {:>10.3} {:>19} {:>20} {:>10} {:>10} {:>10}",
        label,
        format_chi_square(comparison.observed),
        comparison.null.mean,
        format_null_band_f64(comparison.null.q025, comparison.null.q975),
        format_null_min_median_max(comparison.null),
        format_probability(comparison.lower_tail_add_one_p),
        format_probability(comparison.upper_tail_add_one_p),
        format_probability(comparison.two_sided_add_one_p)
    );
}

fn print_orientation_positive_control(
    report: &orientation_homogeneity::OrientationHomogeneityReport,
) {
    println!("heterogeneous positive control");
    println!(
        "fixture: same nine lengths, but each synthetic message has a deliberately different dominant orientation"
    );
    println!(
        "{:<12} {:>10} {:>19} {:>10} {:>10}",
        "stat", "observed", "null 95%", "p>=obs", "verdict"
    );
    print_positive_homogeneity_row("Pearson X^2", report.positive_control.pearson);
    print_positive_homogeneity_row("G-test", report.positive_control.g_test);
}

fn print_positive_homogeneity_row(
    label: &str,
    comparison: orientation_homogeneity::HomogeneityNullComparison,
) {
    let verdict = if comparison.observed > comparison.null.q975 {
        "upper-tail"
    } else {
        "inside"
    };
    println!(
        "{:<12} {:>10} {:>19} {:>10} {:>10}",
        label,
        format_chi_square(comparison.observed),
        format_null_band_f64(comparison.null.q025, comparison.null.q975),
        format_probability(comparison.upper_tail_add_one_p),
        verdict
    );
}

fn print_orientation_homogeneity_interpretation(
    report: &orientation_homogeneity::OrientationHomogeneityReport,
) {
    let pearson = report.pearson_null;
    let g_test = report.g_test_null;
    if pearson.observed < pearson.null.median && pearson.lower_tail_add_one_p <= 0.05 {
        println!(
            "Interpretation: the Pearson statistic is in the lower tail of the length-matched repartition null, so the nine messages are more homogeneous in orientation frequencies than random repartitions of the same pooled symbols. The G-test lower-tail p is {}.",
            format_probability(g_test.lower_tail_add_one_p)
        );
        println!(
            "That is an order-independent shared-source distribution signature. It constrains source homogeneity only; it does not imply meaning, and a single deterministic generator emitting structured-but-meaningless data remains an equally valid explanation."
        );
    } else if pearson.observed > pearson.null.median && pearson.upper_tail_add_one_p <= 0.05 {
        println!(
            "Interpretation: the Pearson statistic is in the upper tail of the length-matched repartition null, so the messages are more heterogeneous in orientation frequencies than a shared pooled distribution would predict. The G-test upper-tail p is {}.",
            format_probability(g_test.upper_tail_add_one_p)
        );
        println!(
            "This would argue against unusually tight cross-message homogeneity, but it still says nothing about plaintext or symbol meaning."
        );
    } else {
        println!(
            "Interpretation: the observed homogeneity statistic lands in the bulk of the length-matched repartition null. Similar-looking per-message profiles are therefore unremarkable at this sampling depth."
        );
    }
    println!(
        "Decode potential: none directly. This is structural evidence at the orientation-frequency layer, not a language or cipher attack."
    );
}

fn format_orientation_profile_lengths(
    profiles: &[orientation_homogeneity::OrientationProfile],
) -> String {
    profiles
        .iter()
        .map(|profile| format!("{}:{}", profile.message_key, profile.length))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_orientation_counts(
    counts: &[usize; orientation_homogeneity::ORIENTATION_BUCKETS],
) -> String {
    counts
        .iter()
        .enumerate()
        .map(|(digit, count)| format!("{digit}:{count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_null_band_f64(q025: f64, q975: f64) -> String {
    format!("{q025:.3}..{q975:.3}")
}

fn format_null_min_median_max(band: orientation_homogeneity::ScalarNullBand) -> String {
    format!("{:.3}/{:.3}/{:.3}", band.min, band.median, band.max)
}

/// Prints the Experiment 8 grouping and state-count report.
pub fn print_grouping_report(report: &grouping::Experiment8Report) {
    println!("Experiment 8 base-N grouping reinterpretation");
    println!("order: {}", report.state_estimate.order.name());
    println!(
        "message lengths: {}",
        format_message_lengths(&report.state_estimate.message_lengths)
    );
    println!(
        "boundary rule: rendered groups are non-overlapping within each message; incomplete tails are dropped and no group crosses a message join"
    );
    println!(
        "storage axis: engine base-7 decoded symbols 0..=5, including delimiter 5, reported separately from rendered orientations"
    );
    println!();
    print_grouping_summary(report);
    println!();
    print_grouping_message_detail(report);
    println!();
    print_language_reference_rows(report);
    println!();
    print_grouping_compatibility(report);
    println!();
    print_state_count_estimate(report);
    println!();
    print_state_count_calibration(report);
    println!();
    print_grouping_interpretation(report);
}

fn print_grouping_summary(report: &grouping::Experiment8Report) {
    println!("grouping summary");
    println!(
        "{:<24} {:>5} {:>7} {:>6} {:>5} {:>9} {:>8} {:>10} {:>9} {:>10}",
        "grouping",
        "base",
        "symbols",
        "drop",
        "used",
        "H bits",
        "H/log2k",
        "IoC pool",
        "H msg",
        "IoC msg"
    );
    for row in &report.groupings {
        println!(
            "{:<24} {:>5} {:>7} {:>6} {:>5} {:>9.4} {:>8.4} {:>10.6} {:>9.4} {:>10.6}",
            row.axis.label(),
            row.axis.nominal_base(),
            row.pooled.symbols,
            row.dropped_source_symbols,
            row.pooled.used_alphabet,
            row.pooled.entropy_bits_per_symbol,
            row.pooled.normalized_entropy,
            row.pooled.ioc,
            row.message_weighted_entropy_bits_per_symbol,
            row.message_weighted_ioc
        );
    }
}

fn print_grouping_message_detail(report: &grouping::Experiment8Report) {
    println!("per-message grouping detail");
    println!(
        "{:<24} {:<6} {:>6} {:>4} {:>5} {:>9} {:>8} {:>10}",
        "grouping", "msg", "symbols", "drop", "used", "H bits", "H/log2k", "IoC"
    );
    for row in &report.groupings {
        for message in &row.messages {
            println!(
                "{:<24} {:<6} {:>6} {:>4} {:>5} {:>9.4} {:>8.4} {:>10.6}",
                row.axis.label(),
                message.message_key,
                message.stats.symbols,
                message.dropped_source_symbols,
                message.stats.used_alphabet,
                message.stats.entropy_bits_per_symbol,
                message.stats.normalized_entropy,
                message.stats.ioc
            );
        }
    }
}

fn print_language_reference_rows(report: &grouping::Experiment8Report) {
    println!("natural-language unigram references from bundled language models");
    println!(
        "{:<8} {:>7} {:>8} {:>7} {:>9} {:>8} {:>10} {:>9}",
        "lang", "nom k", "obs k", "letters", "H bits", "H/log2k", "IoC", "1/IoC"
    );
    for reference in &report.language_references {
        println!(
            "{:<8} {:>7} {:>8} {:>7} {:>9.4} {:>8.4} {:>10.6} {:>9.2}",
            reference.language,
            reference.nominal_alphabet,
            reference.observed_used_alphabet,
            reference.symbols,
            reference.entropy_bits_per_symbol,
            reference.normalized_entropy,
            reference.ioc,
            reference.collision_effective_alphabet
        );
    }
}

fn print_grouping_compatibility(report: &grouping::Experiment8Report) {
    println!("language-compatibility flags");
    println!(
        "derived bands: alphabet {}..={}, entropy {:.4}..{:.4} bits",
        report.compatibility.alphabet_min,
        report.compatibility.alphabet_max,
        report.compatibility.entropy_min,
        report.compatibility.entropy_max
    );
    println!(
        "{:<24} {:>10} {:>10} {:>10}",
        "grouping", "alphabet", "entropy", "both"
    );
    for row in &report.compatibility.rows {
        let both = row.alphabet_compatible && row.entropy_compatible;
        println!(
            "{:<24} {:>10} {:>10} {:>10}",
            row.grouping_label,
            yes_no(row.alphabet_compatible),
            yes_no(row.entropy_compatible),
            yes_no(both)
        );
    }
    let compatible = report.compatibility.fully_compatible_groupings();
    if compatible.is_empty() {
        println!("fully compatible groupings: none");
    } else {
        println!("fully compatible groupings: {}", compatible.join(", "));
    }
    println!(
        "nearest alphabet-size match: {}",
        report.compatibility.nearest_alphabet_grouping
    );
}

fn print_state_count_estimate(report: &grouping::Experiment8Report) {
    let estimate = &report.state_estimate;
    let collision = estimate.collision;
    println!("independent collision state-count estimate");
    println!(
        "pooled IoC: {:.6}; 1/IoC: {:.2}; collision entropy: {:.4} bits",
        collision.pooled_ioc, collision.pooled_effective_states, collision.collision_entropy_bits
    );
    println!(
        "message-weighted IoC: {:.6}; 1/IoC: {:.2}; pooled Shannon entropy: {:.4} bits",
        collision.message_weighted_ioc,
        collision.message_weighted_effective_states,
        collision.pooled_entropy_bits_per_symbol
    );
    println!(
        "calibrated range: {}..{} states; contains established reading-layer size {}: {}",
        estimate.range.lower,
        estimate.range.upper,
        orders::READING_LAYER_ALPHABET_SIZE,
        yes_no(estimate.range.includes_83)
    );
    println!(
        "calibration margin applied: {:.1}%",
        estimate.calibration_relative_margin * 100.0
    );
    println!(
        "longest repeated isomorph in scanned k={}..={}: {}",
        grouping_state_min_window(report),
        grouping_state_max_window(report),
        estimate
            .longest_repeated_isomorph
            .map_or_else(|| "none".to_owned(), |window| window.to_string())
    );
    println!();
    println!("isomorph/window diagnostics");
    println!(
        "{:>2} {:>8} {:>8} {:>10} {:>8} {:>12}",
        "k", "windows", "inform", "rep kinds", "max rep", "birthday N"
    );
    for row in &estimate.isomorph_rows {
        println!(
            "{:>2} {:>8} {:>8} {:>10} {:>8} {:>12}",
            row.window,
            row.windows,
            row.informative_windows,
            row.repeated_signature_kinds,
            row.max_repeat_count,
            format_optional_f64(row.birthday_effective_states)
        );
    }
}

fn print_state_count_calibration(report: &grouping::Experiment8Report) {
    println!("synthetic N-state positive-control calibration");
    println!("seed: {}", report.calibration.seed);
    println!(
        "model: real message lengths, uniform N-symbol plaintext through N deterministic rotational alphabets"
    );
    println!(
        "{:>6} {:>5} {:>10} {:>10} {:>10} {:>8} {:>10}",
        "true N", "used", "IoC pool", "N pool", "N msg", "rel err", "max iso"
    );
    for row in &report.calibration.rows {
        println!(
            "{:>6} {:>5} {:>10.6} {:>10.2} {:>10.2} {:>8.2}% {:>10}",
            row.true_states,
            row.used_alphabet,
            row.pooled_ioc,
            row.pooled_effective_states,
            row.message_weighted_effective_states,
            row.relative_error * 100.0,
            format_optional_usize(row.longest_repeated_isomorph)
        );
    }
    println!(
        "max sampled relative error: {:.2}%; applied margin: {:.2}%",
        report.calibration.max_relative_error * 100.0,
        report.calibration.applied_relative_margin * 100.0
    );
}

fn print_grouping_interpretation(report: &grouping::Experiment8Report) {
    let compatible = report.compatibility.fully_compatible_groupings();
    if compatible.is_empty() {
        println!(
            "Interpretation: no tested grouping matches both the bundled natural-language alphabet-size band and entropy band as raw plaintext. The nearest alphabet-size match is {}, but its entropy is measured separately above.",
            report.compatibility.nearest_alphabet_grouping
        );
    } else {
        println!(
            "Interpretation: grouping(s) matching both measured language alphabet size and entropy: {}.",
            compatible.join(", ")
        );
    }

    let range = report.state_estimate.range;
    let relation = if range.includes_83 {
        "overlaps"
    } else if range.upper < orders::READING_LAYER_ALPHABET_SIZE {
        "falls below"
    } else {
        "sits above"
    };
    println!(
        "The independent collision estimate gives an approximate {}..{} state range, which {relation} the established 83-symbol reading layer. This agreement check does not assume 83, and it does not decode meaning.",
        range.lower, range.upper
    );
    println!(
        "Near-uniform high entropy remains consistent with a permutation or other structured transformation of data, as in Experiment 4; these numbers constrain plausible encodings only."
    );
}

fn grouping_state_min_window(report: &grouping::Experiment8Report) -> usize {
    report
        .state_estimate
        .isomorph_rows
        .iter()
        .map(|row| row.window)
        .min()
        .unwrap_or_default()
}

fn grouping_state_max_window(report: &grouping::Experiment8Report) -> usize {
    report
        .state_estimate
        .isomorph_rows
        .iter()
        .map(|row| row.window)
        .max()
        .unwrap_or_default()
}

/// Prints the reading-order audit and Experiment 4 flatness report.
pub fn print_orders_report(
    summary: &orders::GridSummary,
    stats: &[orders::NamedOrderStats],
    flatness: &[orders::NamedReadingLayerFlatnessStats],
) {
    println!("grid row widths:");
    for (key, widths) in &summary.row_widths {
        println!("  {key}: {}", format_widths(widths));
    }
    println!("max row width: {}", summary.max_width);
    println!(
        "bottom two rows differ by <=1: {}",
        summary.bottom_two_rows_differ_by_at_most_one
    );
    println!();
    println!(
        "{:<24} {:>5} {:>8} {:>11} {:>9} {:>5} {:>8} {:>23}",
        "order", "total", "distinct", "contiguous", "span", ">82", "adj-eq", "recurrence d1..d6"
    );

    let mut winners = Vec::new();
    for item in stats {
        if item.stats.is_contiguous_0_to_82() {
            winners.push(item.order.name());
        }
        println!(
            "{:<24} {:>5} {:>8} {:>11} {:>9} {:>5} {:>8} {:>23}",
            item.order.name(),
            item.stats.total,
            item.stats.distinct,
            item.stats.contiguous,
            format_span(item.stats.min, item.stats.max),
            item.stats.values_above_82,
            item.stats.adjacent_equal,
            format_recurrence(&item.stats.recurrence_distance_1_to_6)
        );
    }
    println!();
    if winners.is_empty() {
        println!("contiguous 0..=82 orders: none");
    } else {
        println!("contiguous 0..=82 orders: {}", winners.join(", "));
    }

    print_experiment_4_flatness_report(flatness);
}

/// Renders frequency, entropy, and `IoC` statistics for one rendered sequence.
#[must_use]
pub fn render_sequence_report(label: &str, seq: &Sequence) -> String {
    let mut out = String::new();
    appendln!(&mut out, "{label}: {} glyphs", seq.len());
    appendln!(
        &mut out,
        "  entropy:               {:.4} bits/glyph",
        analysis::shannon_entropy(&seq.glyphs)
    );
    appendln!(
        &mut out,
        "  index of coincidence:  {:.4}",
        analysis::index_of_coincidence(&seq.glyphs)
    );
    appendln!(&mut out, "  frequencies:");
    for (glyph, count) in analysis::frequencies(&seq.glyphs) {
        appendln!(&mut out, "    {glyph}: {count}");
    }
    out
}

/// Formats row widths as a comma-separated report list.
pub(crate) fn format_widths(widths: &[usize]) -> String {
    widths
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn format_span(min: Option<u8>, max: Option<u8>) -> String {
    match min.zip(max) {
        Some((low, high)) => format!("{low}..{high}"),
        None => "empty".to_owned(),
    }
}

fn format_recurrence(recurrence: &[usize; 6]) -> String {
    let [d1, d2, d3, d4, d5, d6] = *recurrence;
    format!("{d1},{d2},{d3},{d4},{d5},{d6}")
}

fn print_experiment_4_flatness_report(flatness: &[orders::NamedReadingLayerFlatnessStats]) {
    println!();
    println!("Experiment 4 reading-layer flatness");
    println!("alphabet: 83 reading-layer symbols, values 0..=82");
    println!(
        "frequency counts are pooled across the nine messages; entropy and IoC p/msg are message-weighted"
    );
    println!(
        "IoC convention: probability form from analysis::index_of_coincidence; x83/all is the concatenated community-reference cross-check"
    );
    println!(
        "{:<24} {:>5} {:>5} {:>7} {:>7} {:>13} {:>17} {:>10} {:>10} {:>10} {:>12} {:>7} {:>12}",
        "order",
        "total",
        "in83",
        "outside",
        "mean",
        "freq min..max",
        "entropy/max",
        "IoC p/msg",
        "x83/msg",
        "x83/all",
        "chi2 83",
        "df",
        "p>=chi2"
    );
    for item in flatness
        .iter()
        .filter(|item| is_experiment_4_order(item.order))
    {
        println!(
            "{:<24} {:>5} {:>5} {:>7} {:>7.2} {:>13} {:>17} {:>10.6} {:>10.3} {:>10.3} {:>12} {:>7} {:>12}",
            item.order.name(),
            item.flatness.total,
            item.flatness.in_alphabet_total,
            item.flatness.outside_alphabet_occurrences,
            item.flatness.mean_frequency,
            format_frequency_range(&item.flatness),
            format_entropy_ratio(&item.flatness),
            item.flatness.ioc_probability,
            item.flatness.normalized_ioc,
            item.flatness.concatenated_normalized_ioc,
            format_chi_square(item.flatness.chi_square_vs_uniform),
            orders::ReadingLayerFlatnessStats::CHI_SQUARE_VS_UNIFORM_DEGREES_OF_FREEDOM,
            format_chi_square_p_value(item.flatness.chi_square_vs_uniform_upper_tail_p_value)
        );
    }
    println!();
    println!(
        "Interpretation: the df-aware chi-square tail tests exact iid uniformity over the 83 buckets, not whether the stream is meaningful. Flat-ish per-symbol frequency still RULES MONOALPHABETIC OUT; it does NOT rule a real message IN, and structured-but-meaningless data can also be near-uniform. Do not present flatness as evidence of encoding."
    );
}

fn is_experiment_4_order(order: orders::ReadingOrder) -> bool {
    matches!(
        order,
        orders::ReadingOrder::RawRows | orders::ReadingOrder::HoneycombStandard { .. }
    )
}

fn format_frequency_range(flatness: &orders::ReadingLayerFlatnessStats) -> String {
    format!(
        "{}..{} z{}",
        flatness.min_frequency, flatness.max_frequency, flatness.zero_frequency_symbols
    )
}

fn format_entropy_ratio(flatness: &orders::ReadingLayerFlatnessStats) -> String {
    format!(
        "{:.4}/{:.4}",
        flatness.entropy_bits_per_symbol, flatness.max_entropy_bits_per_symbol
    )
}

fn format_chi_square(value: f64) -> String {
    if value.is_infinite() {
        "inf(outside)".to_owned()
    } else {
        format!("{value:.3}")
    }
}

fn format_chi_square_p_value(value: Option<f64>) -> String {
    value.map_or_else(|| "n/a".to_owned(), |p_value| format!("{p_value:.6e}"))
}

pub(crate) fn format_histogram<T: std::fmt::Display>(histogram: &[(T, usize)]) -> String {
    histogram
        .iter()
        .map(|(value, count)| format!("{value}:{count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::{
        format_chi_square, format_chi_square_p_value, format_histogram, format_match_count,
        format_null_flag, format_probability, format_span,
    };

    #[test]
    fn representative_scalar_formatters_are_stable() {
        assert_eq!(format_probability(0.25), "0.250000");
        assert_eq!(format_probability(0.000_25), "2.500e-4");
        assert_eq!(format_chi_square(12.345_6), "12.346");
        assert_eq!(format_chi_square(f64::INFINITY), "inf(outside)");
        assert_eq!(format_chi_square_p_value(Some(0.125)), "1.250000e-1");
        assert_eq!(format_chi_square_p_value(None), "n/a");
    }

    #[test]
    fn representative_table_formatters_are_stable() {
        assert_eq!(format_span(Some(0), Some(82)), "0..82");
        assert_eq!(format_span(None, Some(82)), "empty");
        assert_eq!(format_match_count(3, 99), "3/99");
        assert_eq!(format_null_flag(false, false), "inside");
        assert_eq!(format_null_flag(true, false), "pt95");
        assert_eq!(format_null_flag(true, true), "OUT");
    }

    #[test]
    fn representative_histogram_formatters_are_stable() {
        assert_eq!(
            format_histogram(&[(82_usize, 1), (83_usize, 2)]),
            "82:1, 83:2"
        );
        assert_eq!(format_histogram(&[(0_u8, 5), (4_u8, 7)]), "0:5, 4:7");
    }
}

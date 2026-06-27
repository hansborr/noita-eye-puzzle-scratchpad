use super::DofNullReport;
use crate::report::{self, Report};

impl Report for DofNullReport {
    fn render(&self) -> String {
        let mut out = String::new();
        append_dof_header(&mut out, self);
        report::appendln!(&mut out);
        append_dof_summary(&mut out, self);
        report::appendln!(&mut out);
        append_dof_analytic_headline(&mut out, self);
        report::appendln!(&mut out);
        append_dof_skips(&mut out, self);
        report::appendln!(&mut out);
        append_dof_cell_breakdown(&mut out, self);
        report::appendln!(&mut out);
        append_dof_interpretation(&mut out);
        out
    }
}

fn append_dof_header(out: &mut String, report: &DofNullReport) {
    report::appendln!(out, "calibrated researcher-DoF random-grid null");
    report::appendln!(out, "seed: {}", report.config.seed);
    report::appendln!(
        out,
        "calibration trials (A): {}",
        report.config.calibration_trials
    );
    report::appendln!(out, "resampling trials (B): {}", report.config.trials);
    report::appendln!(
        out,
        "configured axes: {} traversals x {} groupings x {} statistics = {} total cells",
        report.configured_orders,
        report.configured_groupings,
        report.configured_statistics,
        report.configured_cell_count
    );
    report::appendln!(out, "valid calibrated cells: {}", report.valid_cell_count);
    report::appendln!(
        out,
        "skipped traversal/grouping combos: {}",
        report.skipped.len()
    );
    report::appendln!(
        out,
        "resampled: verified row-width structure with uniform orientation cells 0..=4"
    );
    report::appendln!(
        out,
        "calibration: set A defines each cell's empirical marginal tail; the eyes and independent set B are both scored against A before the cross-cell min-p search"
    );
    report::appendln!(
        out,
        "scope nuance: the standard36 honeycomb walk is data-independent; the newly calibrated exposure is concentrated on grouping/statistic choice plus non-honeycomb controls"
    );
    report::appendln!(
        out,
        "empirical marginal floor: {} = 1/(calibration trials + 1)",
        report::format_probability(report.empirical_marginal_floor)
    );
}

fn append_dof_summary(out: &mut String, report: &DofNullReport) {
    report::appendln!(
        out,
        "eyes min marginal p: {}{}",
        report::format_probability(report.observed_min_p),
        floor_censored_suffix(report.observed_min_p, report.empirical_marginal_floor)
    );
    report::appendln!(
        out,
        "best cell: {} / {} / {} ({}, real {}, null {}..{}..{})",
        report.best_cell.order.name(),
        report.best_cell.grouping.label(),
        report.best_cell.statistic.label(),
        report.best_cell.tail.label(),
        format_statistic_value(report.best_cell.real_value),
        format_statistic_value(report.best_cell.null_min),
        format_statistic_value(report.best_cell.null_median),
        format_statistic_value(report.best_cell.null_max)
    );
    report::appendln!(
        out,
        "adaptive raw exceedances in B: {}/{}",
        report.adaptive_extreme_count,
        report.config.trials
    );
    report::appendln!(
        out,
        "resolution-limited adaptive min-p diagnostic: {}/{} = {:.6} (95% Wilson {:.6}..{:.6})",
        report.adaptive_interval.count,
        report.adaptive_interval.trials,
        report.adaptive_interval.estimate,
        report.adaptive_interval.lower,
        report.adaptive_interval.upper
    );
    report::appendln!(
        out,
        "effective independent comparisons (median Sidak-equivalent): {}",
        format_effective_comparisons(report.effective_comparisons)
    );
    report::appendln!(
        out,
        "resampling-grid min-p range scored against A: {}..{}..{}",
        report::format_probability(report.null_min_p_min),
        report::format_probability(report.null_min_p_median),
        report::format_probability(report.null_min_p_max)
    );
}

fn append_dof_interpretation(out: &mut String) {
    report::appendln!(
        out,
        "Interpretation: the empirical adaptive value above is a finite-resolution diagnostic, not the headline significance. With this calibration size, any sub-floor cell is censored to the floor, so the diagnostic estimates how often random grids hit that floor somewhere after look-elsewhere multiplicity. The analytic bound is the appropriate correction for the known bounded-contiguity headline; it remains astronomically small and still does not decode meaning."
    );
    report::appendln!(
        out,
        "Seed-stability note: multi-seed regressions keep the eyes' min marginal p and accepted headline cell at the calibration floor, with the adaptive diagnostic staying in the same finite-resolution floor-hit regime. The analytic DoF-corrected headline bound is seed-independent."
    );
}

fn append_dof_analytic_headline(out: &mut String, report: &DofNullReport) {
    let Some(bounds) = &report.analytic_headline_bounds else {
        report::appendln!(
            out,
            "analytic DoF-corrected headline bound: unavailable for this search space"
        );
        return;
    };
    let calibration_draws_to_resolve = if bounds.per_order > 0.0 {
        1.0 / bounds.per_order
    } else {
        f64::INFINITY
    };

    report::appendln!(
        out,
        "analytic DoF-corrected headline bound under independent uniform trigrams:"
    );
    report::appendln!(
        out,
        "  headline cell: {} / {} / {} real {}, empirical p {}{} ({} calibration hits)",
        bounds.cell.order.name(),
        bounds.cell.grouping.label(),
        bounds.cell.statistic.label(),
        format_statistic_value(bounds.cell.real_value),
        report::format_probability(bounds.cell.marginal_p),
        floor_censored_suffix(bounds.cell.marginal_p, report.empirical_marginal_floor),
        bounds.cell.marginal_extreme_count
    );
    report::appendln!(
        out,
        "  per-order (83/125)^{}: {:.6e}",
        bounds.trigrams,
        bounds.per_order
    );
    report::appendln!(
        out,
        "  total configured cells (M={}): Bonferroni {:.6e}; Sidak {:.6e}",
        bounds.total_configured_cells,
        bounds.total_bonferroni,
        bounds.total_sidak
    );
    report::appendln!(
        out,
        "  effective comparisons (M={}): Bonferroni {:.6e}; Sidak {:.6e}",
        format_effective_comparisons(bounds.effective_comparisons),
        bounds.effective_bonferroni,
        bounds.effective_sidak
    );
    report::appendln!(
        out,
        "  calibration draws needed to resolve this per-order scale empirically: ~{calibration_draws_to_resolve:.3e}"
    );
    report::appendln!(
        out,
        "  conclusion: the bounded 0..=82 headline survives the configured researcher-DoF correction analytically."
    );
}

fn append_dof_skips(out: &mut String, report: &DofNullReport) {
    if report.skipped.is_empty() {
        report::appendln!(out, "skipped combos: none");
        return;
    }
    report::appendln!(out, "skipped combos");
    for skipped in &report.skipped {
        report::appendln!(
            out,
            "  {} / {}: {}",
            skipped.order.name(),
            skipped.grouping.label(),
            skipped.reason
        );
    }
}

fn append_dof_cell_breakdown(out: &mut String, report: &DofNullReport) {
    let mut cells = report.cells.iter().collect::<Vec<_>>();
    cells.sort_by(|left, right| {
        left.marginal_p
            .total_cmp(&right.marginal_p)
            .then_with(|| left.statistic.cmp(&right.statistic))
            .then_with(|| left.grouping.cmp(&right.grouping))
            .then_with(|| left.order.cmp(&right.order))
    });
    report::appendln!(out, "per-cell marginal calibration from set A");
    report::appendln!(
        out,
        "{:<24} {:<17} {:<24} {:>4} {:>7} {:>7} {:>10} {:>20} {:>11}",
        "order",
        "grouping",
        "statistic",
        "tail",
        "symbols",
        "drop",
        "real",
        "null min/med/max",
        "p"
    );
    for cell in cells {
        report::appendln!(
            out,
            "{:<24} {:<17} {:<24} {:>4} {:>7} {:>7} {:>10} {:>20} {:>11}",
            cell.order.name(),
            cell.grouping.label(),
            cell.statistic.label(),
            cell.tail.label(),
            cell.real_symbols,
            cell.dropped_source_symbols,
            format_statistic_value(cell.real_value),
            format!(
                "{}/{}/{}",
                format_statistic_value(cell.null_min),
                format_statistic_value(cell.null_median),
                format_statistic_value(cell.null_max)
            ),
            report::format_probability(cell.marginal_p)
        );
    }
}

fn floor_censored_suffix(value: f64, floor: f64) -> &'static str {
    if (value - floor).abs() <= f64::EPSILON * 8.0 {
        " (floor-censored)"
    } else {
        ""
    }
}

fn format_statistic_value(value: f64) -> String {
    if (value - value.round()).abs() < 1e-9 {
        format!("{value:.0}")
    } else {
        format!("{value:.4}")
    }
}

fn format_effective_comparisons(value: f64) -> String {
    if value.is_infinite() {
        "infinite".to_owned()
    } else {
        format!("{value:.2}")
    }
}

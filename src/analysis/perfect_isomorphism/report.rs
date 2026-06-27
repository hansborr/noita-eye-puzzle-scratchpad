//! Human-readable render for the perfect-isomorphism scan report.

use crate::report::{self, Report};

use super::{
    BenignDesyncRegion, BreakClass, BreakLocalization, IsomorphCatalogEntry,
    PerfectIsomorphismReport, SIGNIFICANCE_ALPHA, SafeSpan, WikiRegressionCheck,
};

impl Report for PerfectIsomorphismReport {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(
            &mut out,
            "Thread 3 perfect-isomorphism / allomorph-consistency scan"
        );
        report::appendln!(&mut out, "order: {}", self.order.name());
        report::appendln!(&mut out, "seed: {}", self.config.seed);
        report::appendln!(&mut out, "trials: {}", self.config.trials);
        report::appendln!(
            &mut out,
            "message lengths: {}",
            report::format_message_lengths(&self.message_lengths)
        );
        report::appendln!(&mut out, "pooled length: {}", self.total_length);
        report::appendln!(
            &mut out,
            "catalog windows: vetted discrete set {{8, 9, 11}} filtered by configured range {}..={}",
            self.config.min_window,
            self.config.max_window
        );
        report::appendln!(
            &mut out,
            "null: within each message, preserve the exact symbol multiset and length, shuffle order, recompute the internal-candidate count"
        );
        report::appendln!(
            &mut out,
            "mapping-independent scope: ciphertext symbol equality and gap structure only; no symbol-to-meaning mapping or language scoring"
        );
        report::appendln!(&mut out);
        append_perfect_catalog(&mut out, self);
        report::appendln!(&mut out);
        append_perfect_breaks(&mut out, self);
        report::appendln!(&mut out);
        append_perfect_headline(&mut out, self);
        report::appendln!(&mut out);
        append_perfect_safe_extents(&mut out, self);
        report::appendln!(&mut out);
        append_perfect_regressions(&mut out, self);
        report::appendln!(&mut out);
        append_perfect_interpretation(&mut out, self);
        out
    }
}

fn append_perfect_catalog(out: &mut String, report: &PerfectIsomorphismReport) {
    report::appendln!(out, "cross-message gap-pattern catalog");
    report::appendln!(
        out,
        "  {:<13} {:>3} {:>7} {:>4} {:>8} {:>10} {:>10}",
        "signature",
        "win",
        "repeats",
        "occ",
        "nullmax",
        "p",
        "tier"
    );
    for (entry, row) in report.catalog.iter().zip(&report.significance) {
        let tier = if row.strong {
            "strong"
        } else {
            "coincidental-class"
        };
        report::appendln!(
            out,
            "  {:<13} {:>3} {:>7} {:>4} {:>8} {:>10} {:>10}",
            entry.signature,
            entry.window,
            entry.repeat_count,
            entry.occurrences.len(),
            row.null_max_occurrences,
            report::format_probability(row.empirical_p),
            tier
        );
        report::appendln!(
            out,
            "    occurrences: {}",
            format_catalog_occurrences(entry)
        );
    }
}

fn append_perfect_breaks(out: &mut String, report: &PerfectIsomorphismReport) {
    report::appendln!(out, "maximal-extension break localization");
    if report.breaks.is_empty() {
        report::appendln!(out, "  no bounded breaks in strong extents");
        return;
    }
    report::appendln!(
        out,
        "  {:<13} {:>9} {:>9} {:>5} {:>6} {:>6} {:>7} {:<18}",
        "pair",
        "left",
        "right",
        "idx",
        "island",
        "far",
        "flank",
        "class"
    );
    for break_row in &report.breaks {
        report::appendln!(
            out,
            "  {:<13} {:>9} {:>9} {:>5} {:>6} {:>6} {:>7} {:<18}",
            format!("{}/{}", break_row.pair.0, break_row.pair.1),
            break_row.anchor.0,
            break_row.anchor.1,
            break_row.break_index,
            break_row.island_cols,
            break_row.far_run,
            break_row.left_flank,
            format_perfect_break_class(break_row.class)
        );
    }
}

fn append_perfect_headline(out: &mut String, report: &PerfectIsomorphismReport) {
    report::appendln!(out, "headline internal-violation null");
    report::appendln!(
        out,
        "  robust strong-bar internal violations: {}",
        report.robust_internal_violations
    );
    report::appendln!(
        out,
        "  matched null count: mean {:.3}, median {:.1}, q97.5 {}, max {}",
        report.internal_violation_null.count_mean,
        report.internal_violation_null.count_median,
        report.internal_violation_null.count_q975,
        report.internal_violation_null.count_max
    );
    report::appendln!(
        out,
        "  upper-tail add-one p: ({extreme}+1)/({trials}+1) = {p}",
        extreme = report.empirical_p_count,
        trials = report.internal_violation_null.trials,
        p = report::format_probability(report.empirical_p)
    );
    report::appendln!(
        out,
        "  loose-bar note: the vetted empirical loose candidate is east4@65/west4@67 in the Stutter Section; it is benign and within the chance-collision null, so it is not promoted to the strong headline"
    );
    report::appendln!(out, "  result: {}", perfect_headline_result(report));
}

fn perfect_headline_result(report: &PerfectIsomorphismReport) -> String {
    if report.robust_internal_violations == 0 {
        return "0 robust internal violations -> SUPPORTS (does not prove) perfect isomorphism"
            .to_owned();
    }
    if report.empirical_p <= SIGNIFICANCE_ALPHA {
        format!(
            "{} robust internal violations exceed the matched null (p = {}) -> DISFAVOURS the proven-perfect-isomorphism family",
            report.robust_internal_violations,
            report::format_probability(report.empirical_p)
        )
    } else {
        format!(
            "{} robust internal violations are within the matched null (p = {}) -> not promoted to a family-falsifying violation",
            report.robust_internal_violations,
            report::format_probability(report.empirical_p)
        )
    }
}

fn append_perfect_safe_extents(out: &mut String, report: &PerfectIsomorphismReport) {
    report::appendln!(out, "safe-isomorph extent export");
    report::appendln!(out, "  count: {}", report.safe_extents.len());
    report::appendln!(
        out,
        "  {:<13} {:>12} {:>12} {:<18}",
        "pair",
        "left",
        "right",
        "bound"
    );
    for extent in &report.safe_extents {
        report::appendln!(
            out,
            "  {:<13} {:>12} {:>12} {:<18}",
            format!("{}/{}", extent.pair.0, extent.pair.1),
            format_safe_span(extent.left_span),
            format_safe_span(extent.right_span),
            format_optional_break(extent.bounding_break.as_ref())
        );
    }
}

fn append_perfect_regressions(out: &mut String, report: &PerfectIsomorphismReport) {
    report::appendln!(out, "wiki regression checks");
    for result in &report.regression {
        let status = if result.reproduced { "PASS" } else { "FAIL" };
        report::appendln!(
            out,
            "  {:<30} {:<4} produced [{}]",
            format_perfect_regression_check(result.check),
            status,
            result.produced.join(" | ")
        );
        if !result.hypothesis_label.is_empty() {
            report::appendln!(out, "    hypothesis: {}", result.hypothesis_label);
        }
    }
    report::appendln!(
        out,
        "  positive control: {}",
        if report.positive_control_fired {
            "fired"
        } else {
            "failed"
        }
    );
}

fn append_perfect_interpretation(out: &mut String, report: &PerfectIsomorphismReport) {
    report::appendln!(
        out,
        "Multiplicity note: multiple isomorph signatures, occurrence pairs, and vetted windows are tested; pointwise rows are labels for structural triage, while the matched null calibrates the internal-violation count."
    );
    report::appendln!(out, "{}", perfect_interpretation(report));
    report::appendln!(
        out,
        "Claim ceiling: the eyes remain deterministic, engine-generated, strikingly structured data of unknown meaning; unsolved; no primary developer source confirms recoverable plaintext."
    );
}

fn perfect_interpretation(report: &PerfectIsomorphismReport) -> String {
    if report.robust_internal_violations == 0 {
        return "Interpretation: Perfect-Isomorphism.md and Allomorphs.md make this a family-selection check, not a decode. The observed 0 robust strong-bar internal violations SUPPORTS (does not prove) perfect isomorphism and keeps the GAK family viable; it does not imply \"the eyes are GAK.\" A clean internal violation would disfavor the proven CTAK..XGAK family, but XGAK's upper edge is <=, not equality."
            .to_owned();
    }
    if report.empirical_p <= SIGNIFICANCE_ALPHA {
        format!(
            "Interpretation: Perfect-Isomorphism.md and Allomorphs.md make this a family-selection check, not a decode. The observed {} robust strong-bar internal violations are in the matched upper tail (add-one p = {}), so they DISFAVOUR the proven CTAK..XGAK perfectly-isomorphic family unless individually explained by new benign evidence; this still does not prove the eyes are imperfectly isomorphic, because XGAK's upper edge is <=, not equality.",
            report.robust_internal_violations,
            report::format_probability(report.empirical_p)
        )
    } else {
        format!(
            "Interpretation: Perfect-Isomorphism.md and Allomorphs.md make this a family-selection check, not a decode. The observed {} robust strong-bar internal violations do not exceed the matched chance-collision null (add-one p = {}), so they are not promoted to a family-falsifying result and the GAK family remains viable; this does not imply \"the eyes are GAK.\"",
            report.robust_internal_violations,
            report::format_probability(report.empirical_p)
        )
    }
}

fn format_catalog_occurrences(entry: &IsomorphCatalogEntry) -> String {
    entry
        .occurrences
        .iter()
        .map(|(key, start)| format!("{key}@{start}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_perfect_break_class(class: BreakClass) -> String {
    match class {
        BreakClass::Boundary => "Boundary".to_owned(),
        BreakClass::InternalCandidate => "InternalCandidate".to_owned(),
        BreakClass::BenignDesync { region } => {
            format!("BenignDesync/{}", format_benign_region(region))
        }
    }
}

fn format_benign_region(region: BenignDesyncRegion) -> &'static str {
    match region {
        BenignDesyncRegion::FunnyLookingObstacle => "FunnyObstacle",
        BenignDesyncRegion::Caboose => "Caboose",
        BenignDesyncRegion::StutterSection => "Stutter",
    }
}

fn format_safe_span(span: SafeSpan) -> String {
    format!("{}..{}", span.start, span.end())
}

fn format_optional_break(break_row: Option<&BreakLocalization>) -> String {
    break_row.map_or_else(
        || "message-end".to_owned(),
        |row| {
            format!(
                "{}@{}",
                format_perfect_break_class(row.class),
                row.break_index
            )
        },
    )
}

fn format_perfect_regression_check(check: WikiRegressionCheck) -> &'static str {
    match check {
        WikiRegressionCheck::Messages12SharedAllomorph => "3A messages 1/2",
        WikiRegressionCheck::Messages789ExtraRepeat => "3B messages 7/8/9",
        WikiRegressionCheck::CorruptionTheoryBound => "3C bound hypothesis (fixed annotation)",
        WikiRegressionCheck::MainIsomorphPositiveControl => "main isomorph control",
    }
}

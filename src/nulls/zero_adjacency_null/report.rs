//! stdout rendering for the Experiment 7D zero-adjacency forbidden-successor
//! null report.

use crate::report::{self, Report};

use super::{
    AdjacencyNullBand, ShuffleBandPosition, ZeroAdjacencyNullReport, ZeroAdjacencyPositiveControls,
};

impl Report for ZeroAdjacencyNullReport {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(
            &mut out,
            "Experiment 7D zero-adjacency forbidden-successor null"
        );
        report::appendln!(&mut out, "order: {}", self.order.name());
        report::appendln!(&mut out, "base seed: {}", self.config.seed);
        report::appendln!(&mut out, "seed streams: {}", self.config.seed_count);
        report::appendln!(&mut out, "trials per seed: {}", self.config.trials_per_seed);
        report::appendln!(&mut out, "total shuffles: {}", self.null.trials);
        report::appendln!(
            &mut out,
            "message lengths: {}",
            report::format_message_lengths(&self.message_lengths)
        );
        report::appendln!(&mut out, "pooled length: {}", self.total_length);
        report::appendln!(
            &mut out,
            "boundary rule: adjacent pairs are counted within each message only; no pair crosses a message join"
        );
        report::appendln!(
            &mut out,
            "null: Fisher-Yates shuffle within each message, preserving that message's exact value multiset and length"
        );
        report::appendln!(
            &mut out,
            "statistic: pooled adjacent-equal reading-layer value pairs under the fixed accepted honeycomb order"
        );
        report::appendln!(&mut out);
        append_zero_adjacency_observed(&mut out, self);
        report::appendln!(&mut out);
        append_zero_adjacency_null(&mut out, self);
        report::appendln!(&mut out);
        append_zero_adjacency_controls(&mut out, &self.controls);
        report::appendln!(&mut out);
        append_zero_adjacency_interpretation(&mut out, self);
        out
    }
}

fn append_zero_adjacency_observed(out: &mut String, report: &ZeroAdjacencyNullReport) {
    report::appendln!(out, "observed eye statistic");
    report::appendln!(
        out,
        "  observed adjacent equal: {}/{} = {:.6}",
        report.observed.adjacent_equal,
        report.observed.comparisons,
        report.observed.rate
    );
    report::appendln!(
        out,
        "  analytic E from per-message multisets: {:.6}",
        report.observed.analytic_expected
    );
    report::appendln!(
        out,
        "  position vs shuffle band: {}",
        report.band_position.label()
    );
    report::appendln!(
        out,
        "  {:<6} {:>6} {:>8} {:>8} {:>10}",
        "msg",
        "len",
        "pairs",
        "adj",
        "E"
    );
    for row in &report.observed.messages {
        report::appendln!(
            out,
            "  {:<6} {:>6} {:>8} {:>8} {:>10.3}",
            row.message_key,
            row.len,
            row.comparisons,
            row.adjacent_equal,
            row.analytic_expected
        );
    }
}

fn append_zero_adjacency_null(out: &mut String, report: &ZeroAdjacencyNullReport) {
    report::appendln!(out, "within-message shuffle null");
    report::appendln!(
        out,
        "  adjacent-equal count: mean {:.2}, 95% {}, median {:.1}, min {}, max {}",
        report.null.mean,
        format_adjacency_band(report.null),
        report.null.median,
        report.null.min,
        report.null.max
    );
    report::appendln!(
        out,
        "  lower-tail add-one p: ({extreme}+1)/({trials}+1) = {p}",
        extreme = report.empirical_p_count,
        trials = report.null.trials,
        p = report::format_probability(report.empirical_p)
    );
}

fn append_zero_adjacency_controls(out: &mut String, controls: &ZeroAdjacencyPositiveControls) {
    report::appendln!(out, "positive controls");
    report::appendln!(
        out,
        "  {:<20} {:>8} {:>10} {:>10} {:>11} {:>8}",
        "control",
        "adj",
        "E",
        "null95",
        "p<=obs",
        "band"
    );
    for control in [&controls.free_permutation, &controls.no_repeat_successor] {
        report::appendln!(
            out,
            "  {:<20} {:>8} {:>10.3} {:>10} {:>11} {:>8}",
            control.label,
            control.observed.adjacent_equal,
            control.observed.analytic_expected,
            format_adjacency_band(control.null),
            report::format_probability(control.empirical_p),
            control.band_position.label()
        );
        report::appendln!(out, "    {}", control.description);
    }
}

fn append_zero_adjacency_interpretation(out: &mut String, report: &ZeroAdjacencyNullReport) {
    if report.significant && report.observed.adjacent_equal == 0 {
        report::appendln!(
            out,
            "Interpretation: observed zero adjacent equal pairs sits below the within-message multiset shuffle band while analytic E={:.6}. That is structural evidence for a no-fixed-successor / forbidden-successor mechanism beyond frequency flatness, but it decodes nothing and does not identify a cipher.",
            report.observed.analytic_expected
        );
    } else if report.band_position == ShuffleBandPosition::Within {
        report::appendln!(
            out,
            "Interpretation: observed adjacency sits within the within-message multiset shuffle band. In this run, the no-doubled-trigram property is explained by the eye messages' own frequencies rather than by a separate forbidden-successor constraint."
        );
    } else {
        report::appendln!(
            out,
            "Interpretation: observed adjacency does not match the lower-tail forbidden-successor prediction under this null. Treat any out-of-band direction as an arrangement diagnostic only; it decodes nothing."
        );
    }
    report::appendln!(
        out,
        "The result is conditional on the Experiment-0-verified transcription and the fixed accepted honeycomb order; the null randomizes arrangement within each message, not reading order or symbol meaning."
    );
}

fn format_adjacency_band(band: AdjacencyNullBand) -> String {
    format!("{}..{}", band.q025, band.q975)
}

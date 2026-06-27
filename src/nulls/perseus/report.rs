use super::{PerseusReport, SharedSpan};
use crate::report::{self, Report};

impl Report for PerseusReport {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(&mut out, "Experiment 7C Perseus recurrence null");
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
            "operational definition: same-offset common runs of length >= {} are shared if they are in the earliest leading-family alignment or in an East/West counterpart pair; all other positions are non-shared",
            self.partition.min_shared_run_len
        );
        report::appendln!(
            &mut out,
            "recurrence statistic: while scanning each message left to right, count a shared-position symbol as recurrent if it appeared earlier in a non-shared position in that same message"
        );
        report::appendln!(
            &mut out,
            "null: keep the reconstructed position mask fixed and Fisher-Yates shuffle values within each message, preserving its exact multiset and length"
        );
        report::appendln!(
            &mut out,
            "documented reference only: community quote p~{} for strict no-recurrence if random; this run computes its own shuffle p-value",
            report::format_probability(self.documented_reference_chance)
        );
        report::appendln!(&mut out);
        append_perseus_partition(&mut out, self);
        report::appendln!(&mut out);
        append_perseus_observed(&mut out, self);
        report::appendln!(&mut out);
        append_perseus_null(&mut out, self);
        report::appendln!(&mut out);
        append_perseus_interpretation(&mut out, self);
        out
    }
}

fn append_perseus_partition(out: &mut String, report: &PerseusReport) {
    report::appendln!(out, "partition summary");
    report::appendln!(
        out,
        "  leading shared start: {}",
        report
            .partition
            .leading_start
            .map_or_else(|| "none".to_owned(), |start| start.to_string())
    );
    match &report.partition.global_prefix {
        Some(prefix) => report::appendln!(
            out,
            "  all-message prefix: start {} len {} values {}",
            prefix.start,
            prefix.len,
            format_u8_values(&prefix.values)
        ),
        None => report::appendln!(out, "  all-message prefix: none"),
    }
    report::appendln!(
        out,
        "  selected pair runs: {}",
        report.partition.selected_pair_runs.len()
    );
    report::appendln!(out, "  counterpart longest runs:");
    for run in &report.partition.counterpart_runs {
        report::appendln!(
            out,
            "    {}/{} start {} len {}",
            run.east_key,
            run.west_key,
            run.start,
            run.len
        );
    }
    report::appendln!(out, "  per-message spans:");
    for message in &report.partition.messages {
        report::appendln!(
            out,
            "    {:<6} shared {:>3}/{:<3} spans {}",
            message.message_key,
            message.shared_symbols,
            message.len,
            format_shared_spans(&message.shared_spans)
        );
    }
}

fn append_perseus_observed(out: &mut String, report: &PerseusReport) {
    report::appendln!(out, "observed recurrence statistic");
    report::appendln!(
        out,
        "  pooled: {}/{} = {:.6}",
        report.observed.recurrent_occurrences,
        report.observed.tested_shared_occurrences,
        report.observed.rate
    );
    report::appendln!(
        out,
        "  non-shared positions scanned: {}",
        report.observed.non_shared_occurrences
    );
    report::appendln!(
        out,
        "  recurrent symbol values: {}",
        format_u8_values(&report.observed.recurrent_symbols)
    );
    report::appendln!(
        out,
        "  {:<6} {:>10} {:>10} {:>10} {:>10} {:<16}",
        "msg",
        "nonshared",
        "tested",
        "recur",
        "rate",
        "symbols"
    );
    for row in &report.observed.messages {
        report::appendln!(
            out,
            "  {:<6} {:>10} {:>10} {:>10} {:>10.6} {:<16}",
            row.message_key,
            row.non_shared_occurrences,
            row.tested_shared_occurrences,
            row.recurrent_occurrences,
            row.rate,
            format_u8_values(&row.recurrent_symbols)
        );
    }
}

fn append_perseus_null(out: &mut String, report: &PerseusReport) {
    report::appendln!(out, "within-message shuffle null");
    report::appendln!(
        out,
        "  recurrence count: mean {:.2}, 95% {}..{}, median {:.1}, min {}, max {}",
        report.null.count_mean,
        report.null.count_q025,
        report.null.count_q975,
        report.null.count_median,
        report.null.count_min,
        report.null.count_max
    );
    report::appendln!(
        out,
        "  recurrence rate: mean {:.6}, 95% {:.6}..{:.6}, median {:.6}",
        report.null.rate_mean,
        report.null.rate_q025,
        report.null.rate_q975,
        report.null.rate_median
    );
    report::appendln!(
        out,
        "  lower-tail empirical p: ({extreme}+1)/({trials}+1) = {p}",
        extreme = report.empirical_p_count,
        trials = report.config.trials,
        p = report::format_probability(report.empirical_p)
    );
}

fn append_perseus_interpretation(out: &mut String, report: &PerseusReport) {
    if report.significant && report.observed.recurrent_occurrences == 0 {
        report::appendln!(
            out,
            "Interpretation: under this pinned partition, the strict Perseus no-recurrence constraint is present beyond the within-message shuffle null. This corroborates the non-commutative / plaintext-driven permutation direction, but it decodes nothing and does not identify a cipher."
        );
    } else if report.significant {
        report::appendln!(
            out,
            "Interpretation: recurrence is lower than the within-message shuffle null, but the strict 'never reappears' wording is not exact under this partition. Treat this as a structural corroboration only; it decodes nothing."
        );
    } else {
        report::appendln!(
            out,
            "Interpretation: this run does not show the Perseus recurrence constraint beyond the within-message shuffle null. That weakly retires this community claim under the pinned definition, and still decodes nothing."
        );
    }
    report::appendln!(
        out,
        "Seed-stability note: 1000-shuffle multi-seed regressions over seeds 12345, 67890, 13579, 24680, and 424242 keep the observed statistic at 0/185 and the lower-tail p below 0.01."
    );
    report::appendln!(
        out,
        "The result is conditional on the accepted honeycomb reading order and on the documented shared-region operationalization printed above."
    );
}

fn format_u8_values(values: &[u8]) -> String {
    if values.is_empty() {
        return "none".to_owned();
    }
    values
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn format_shared_spans(spans: &[SharedSpan]) -> String {
    if spans.is_empty() {
        return "none".to_owned();
    }
    spans
        .iter()
        .map(|span| format!("{}..{}", span.start, span.end()))
        .collect::<Vec<_>>()
        .join(",")
}

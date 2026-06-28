//! Thread 5 chaining-graph report rendering for [`ChainingGraphReport`].
//!
//! Holds the `Report` implementation and its `append_*` helpers, split out of
//! the chaining-graph battery body so the compute lives separately.

use crate::report::{self, Report};

use super::{ChainingGraphReport, NullStatistic};

impl Report for ChainingGraphReport {
    fn render(&self) -> String {
        let mut out = String::new();
        append_chaining_graph_header(&mut out, self);
        report::appendln!(&mut out);
        append_chaining_graph_catalogue(&mut out, self);
        report::appendln!(&mut out);
        append_chaining_graph_coverage(&mut out, self);
        report::appendln!(&mut out);
        append_chaining_graph_null(&mut out, self);
        report::appendln!(&mut out);
        append_chaining_graph_positive_control(&mut out, self);
        report::appendln!(&mut out);
        append_chaining_graph_interpretation(&mut out);
        out
    }
}

fn append_chaining_graph_header(out: &mut String, report: &ChainingGraphReport) {
    report::appendln!(out, "Thread 5 graph-chaining audit");
    report::appendln!(out, "order: {}", report.order.name());
    report::appendln!(out, "seed: {}", report.config.seed);
    report::appendln!(out, "shuffle trials: {}", report.config.trials);
    report::appendln!(
        out,
        "window/core: {}/{}",
        report.config.window_len,
        report.config.core_len
    );
    report::appendln!(
        out,
        "message lengths: {}",
        report::format_message_lengths(&report.message_lengths)
    );
    report::appendln!(
        out,
        "wiki pages under test: Graph-Chaining.md, Alphabet-Chaining.md, Chaining-Conflicts.md, Chaining-Conflict-Rates.md"
    );
    report::appendln!(
        out,
        "scope: ciphertext symbol equality plus observed context actions only"
    );
    report::appendln!(
        out,
        "scope caveat: broad window-11/shared-pivot gap-isomorph audit; same-plaintext support is not established by the broad graph."
    );
    report::appendln!(
        out,
        "canonical-orientation caveat: each unordered occurrence pair contributes one sorted-order directed context; reverse orientations are not expanded."
    );
}

fn append_chaining_graph_catalogue(out: &mut String, report: &ChainingGraphReport) {
    report::appendln!(
        out,
        "broad window-11/shared-pivot gap-isomorph conflict catalogue"
    );
    report::appendln!(out, "  total: {}", report.catalogue.total);
    report::appendln!(
        out,
        "  distinct-column conflict paths: {}",
        report.catalogue.independent
    );
    report::appendln!(
        out,
        "  fragile over-extension: {}",
        report.catalogue.fragile
    );
    report::appendln!(
        out,
        "  label note: distinct-column paths are provenance separation, not independent same-plaintext witnesses."
    );
}

fn append_chaining_graph_coverage(out: &mut String, report: &ChainingGraphReport) {
    report::appendln!(out, "broad window-11/shared-pivot gap-isomorph coverage");
    report::appendln!(
        out,
        "  symbols touched: {}/{}",
        report.coverage.symbols_touched,
        report.coverage.alphabet_size
    );
    report::appendln!(
        out,
        "  largest component: {}",
        report.coverage.largest_component
    );
    report::appendln!(
        out,
        "  components among touched symbols: {}",
        report.coverage.component_count
    );
    report::appendln!(out, "core-supported repeated-core coverage");
    report::appendln!(
        out,
        "  symbols touched: {}/{}",
        report.coverage.core_supported_symbols,
        report.coverage.alphabet_size
    );
    report::appendln!(
        out,
        "  largest component: {}",
        report.coverage.core_largest_component
    );
    report::appendln!(
        out,
        "  components among touched symbols: {}",
        report.coverage.core_supported_components
    );
    report::appendln!(
        out,
        "  label note: repeated-core support is a provenance filter inside this Rust audit, not wave-1's same-plaintext genuine tier."
    );
}

fn append_chaining_graph_null(out: &mut String, report: &ChainingGraphReport) {
    report::appendln!(out, "matched within-message multiset-shuffle null");
    append_null_stat(
        out,
        "total conflicts (upper tail)",
        report.null.total_conflicts,
    );
    append_null_stat(
        out,
        "distinct-column conflict paths (upper tail)",
        report.null.independent_conflicts,
    );
    append_null_stat(
        out,
        "symbols touched (upper tail)",
        report.null.symbols_touched,
    );
    append_null_stat(
        out,
        "largest component (upper tail)",
        report.null.largest_component,
    );
    append_null_stat(
        out,
        "component count (lower tail)",
        report.null.component_count,
    );
}

fn append_null_stat(out: &mut String, label: &str, statistic: NullStatistic) {
    report::appendln!(
        out,
        "  {label}: real {} null mean {:.2} q025 {} median {:.2} q975 {} max {} p {} ({}/{})",
        statistic.real,
        statistic.band.mean,
        statistic.band.q025,
        statistic.band.median,
        statistic.band.q975,
        statistic.band.max,
        report::format_probability(statistic.empirical_p),
        statistic.empirical_p_count,
        statistic.band.trials
    );
}

fn append_chaining_graph_positive_control(out: &mut String, report: &ChainingGraphReport) {
    report::appendln!(out, "positive control");
    report::appendln!(
        out,
        "  synthetic non-commutative GAK stream fixture: passed={} conflicts={} null_max_conflicts={} conflict_margin={} required_margin={} planted_symbols={} observed_symbols={}",
        report.positive_control.passed,
        report.positive_control.conflicts,
        report.positive_control.null_max_conflicts,
        report.positive_control.conflict_margin,
        report.positive_control.required_margin,
        report.positive_control.planted_symbols,
        report.positive_control.observed_symbols
    );
}

fn append_chaining_graph_interpretation(out: &mut String) {
    report::appendln!(
        out,
        "Interpretation: broad conflict counts quantify window-11/shared-pivot gap-isomorph non-commutativity, including coincidental collisions; they are not same-plaintext evidence. Core-supported coverage is printed as a repeated-core guardrail, while same-plaintext support is not established by the broad graph. Coverage is evidence, not proof, for the transitivity premise."
    );
    report::appendln!(
        out,
        "Wave-1 comparability note: this Rust audit is window-11 + shared-pivot only and is not directly comparable to wave-1's L=10..15 broad survey (17,124 conflicts, 79/83 coverage) nor its genuine tier (~1 conflict witness, ~28/83 coverage); the figures measure different search spaces."
    );
    report::appendln!(
        out,
        "Multiplicity note: the report shows several descriptive tails from the same matched null; read them as an audit panel, not independent discoveries."
    );
}

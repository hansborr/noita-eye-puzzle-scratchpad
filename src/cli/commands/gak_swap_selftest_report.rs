//! Self-test report rendering for the `gak-swap-recover` command.

use noita_eye_puzzle::attack::gak_attack::lymm_deck::{
    GakSwapSelfTestReport, NullControlReport, PositiveControlReport,
};

use crate::cli::args_gak_swap::GakSwapOutput;

pub(crate) fn print_self_test(report: &GakSwapSelfTestReport, output: GakSwapOutput) {
    if output == GakSwapOutput::Json {
        println!("{}", self_test_json(report));
        return;
    }
    println!(
        "gak swap self-test (seed=0x{:016x}, max-nodes={}):",
        report.config.seed,
        report
            .config
            .max_nodes
            .map_or_else(|| "none".to_owned(), |nodes| nodes.to_string())
    );
    print_positive("positive ns=1", &report.positive_ns1);
    print_positive("positive ns=2", &report.positive_ns2);
    print_positive("positive ns=3 local-search", &report.positive_ns3_local);
    print_null(&report.full_permutation_null);
    print_null(&report.over_budget_null);
    println!(
        "  over-budget recovery at supported bound: {}",
        pass_fail(report.over_budget_recovery_exact)
    );
    print_null(&report.label_shuffle_null);
    print_null(&report.local_search_matched_null);
    println!("  SELF-TEST: {}", pass_fail(report.passed()));
}

pub(crate) fn self_test_json(report: &GakSwapSelfTestReport) -> String {
    format!(
        "{{\"seed\":\"0x{:016x}\",\"passed\":{},\"positive_ns1\":{},\"positive_ns2\":{},\"positive_ns3_local\":{},\"full_permutation_null\":{},\"over_budget_null\":{},\"over_budget_recovery_exact\":{},\"label_shuffle_null\":{},\"local_search_matched_null\":{}}}",
        report.config.seed,
        report.passed(),
        positive_json(&report.positive_ns1),
        positive_json(&report.positive_ns2),
        positive_json(&report.positive_ns3_local),
        null_json(&report.full_permutation_null),
        null_json(&report.over_budget_null),
        report.over_budget_recovery_exact,
        null_json(&report.label_shuffle_null),
        null_json(&report.local_search_matched_null)
    )
}

fn print_positive(label: &str, report: &PositiveControlReport) {
    println!(
        "  {label}: {} matched-unique={} ambiguous-present={} ambiguous-missing={} mismatched-unique={} observed={} nodes={} sat-decisions={} sat-conflicts={}",
        pass_fail(report.exact),
        report.matched_observed_letters,
        report.ambiguous_observed_letters,
        report.ambiguous_missing_planted_letters,
        report.mismatched_unique_letters,
        report.observed_letters,
        report.nodes,
        report.sat_decisions,
        report.sat_conflicts
    );
}

fn print_null(report: &NullControlReport) {
    println!(
        "  null {}: {} outcome={} nodes={}",
        report.label,
        pass_fail(report.failed),
        report.outcome.as_str(),
        option_json(report.nodes)
    );
}

fn positive_json(report: &PositiveControlReport) -> String {
    format!(
        "{{\"num_swaps\":{},\"exact\":{},\"matched_observed_letters\":{},\"ambiguous_observed_letters\":{},\"ambiguous_missing_planted_letters\":{},\"mismatched_unique_letters\":{},\"observed_letters\":{},\"nodes\":{},\"sat_decisions\":{},\"sat_conflicts\":{}}}",
        report.num_swaps,
        report.exact,
        report.matched_observed_letters,
        report.ambiguous_observed_letters,
        report.ambiguous_missing_planted_letters,
        report.mismatched_unique_letters,
        report.observed_letters,
        report.nodes,
        report.sat_decisions,
        report.sat_conflicts
    )
}

fn null_json(report: &NullControlReport) -> String {
    format!(
        "{{\"label\":\"{}\",\"failed\":{},\"outcome\":\"{}\",\"nodes\":{}}}",
        json_escape(report.label),
        report.failed,
        report.outcome.as_str(),
        option_json(report.nodes)
    )
}

fn pass_fail(ok: bool) -> &'static str {
    if ok { "PASS" } else { "FAIL" }
}

fn option_json(value: Option<usize>) -> String {
    value.map_or_else(|| "null".to_owned(), |found| found.to_string())
}

fn json_escape(raw: &str) -> String {
    let mut escaped = String::new();
    for ch in raw.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            other => escaped.push(other),
        }
    }
    escaped
}

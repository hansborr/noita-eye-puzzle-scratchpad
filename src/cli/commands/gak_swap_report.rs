//! Report rendering for the `gak-swap-recover` command.

use std::fmt::Write as _;

use noita_eye_puzzle::attack::gak_attack::lymm_deck::{
    GakSwapSelfTestReport, NullControlReport, PositiveControlReport, RecoveryReport,
    SWAP_RECOVERY_FRONTIER_MESSAGE, SwapInferenceReport, python_pt_mapping_literal,
};

use crate::cli::args_gak_swap::GakSwapOutput;

pub(crate) fn print_recovery_report(
    report: &RecoveryReport,
    controls: Option<&GakSwapSelfTestReport>,
    controls_skipped: bool,
    pair_count: usize,
    output: GakSwapOutput,
) {
    match output {
        GakSwapOutput::Text => {
            print_text_report(report, controls, controls_skipped, pair_count);
        }
        GakSwapOutput::Json => {
            print_json_report(report, controls, controls_skipped, pair_count);
        }
    }
}

pub(crate) fn print_inference_report(
    report: &SwapInferenceReport,
    controls: Option<&GakSwapSelfTestReport>,
    controls_skipped: bool,
    pair_count: usize,
    deck_size: usize,
    output: GakSwapOutput,
) {
    match output {
        GakSwapOutput::Text => {
            print_inference_text(report, controls, controls_skipped, pair_count, deck_size);
        }
        GakSwapOutput::Json => {
            print_inference_json(report, controls, controls_skipped, pair_count, deck_size);
        }
    }
}

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
    print_null(&report.full_permutation_null);
    print_null(&report.over_budget_null);
    println!(
        "  over-budget recovery at supported bound: {}",
        pass_fail(report.over_budget_recovery_exact)
    );
    print_null(&report.label_shuffle_null);
    println!("  SELF-TEST: {}", pass_fail(report.passed()));
}

fn print_text_report(
    report: &RecoveryReport,
    controls: Option<&GakSwapSelfTestReport>,
    controls_skipped: bool,
    pair_count: usize,
) {
    print_controls(controls, controls_skipped);
    print_recovery_details(report, pair_count);
}

fn print_inference_text(
    report: &SwapInferenceReport,
    controls: Option<&GakSwapSelfTestReport>,
    controls_skipped: bool,
    pair_count: usize,
    deck_size: usize,
) {
    print_controls(controls, controls_skipped);
    println!(
        "gak-swap-recover infer-swaps: {pair_count} known-plaintext pairs, n={}, requested={}..{}, attempted={}..{}",
        deck_size,
        report.requested.start,
        report.requested.end,
        report.attempted.start,
        report.attempted.end
    );
    if report.frontier_capped {
        println!(
            "  frontier: capped at ns={}; {SWAP_RECOVERY_FRONTIER_MESSAGE}",
            report.attempted.end
        );
    }
    if let Some(selected) = &report.selected {
        println!("  inferred max-swaps: {}", selected.config.max_swaps);
        println!(
            "  support-size: {} (max final-perm support over observed letters)",
            report.inferred_support_size().unwrap_or(0)
        );
        println!(
            "  round-trip: {}/{} ciphertext symbols matched",
            selected.round_trip.matched, selected.round_trip.total
        );
    } else {
        println!("  inferred max-swaps: none");
        println!("  support-size: none");
    }
    println!("  attempts:");
    for attempt in &report.attempts {
        let round_trip = attempt.round_trip.as_ref().map_or_else(
            || "-".to_owned(),
            |round_trip| format!("{}/{}", round_trip.matched, round_trip.total),
        );
        let nodes = attempt
            .stats
            .as_ref()
            .map_or_else(|| "-".to_owned(), |stats| stats.nodes.to_string());
        let error = attempt
            .error
            .as_ref()
            .map_or_else(String::new, |error| format!(" error={error:?}"));
        println!(
            "    s={} outcome={} support-size={} round-trip={} nodes={}{}",
            attempt.max_swaps,
            attempt.outcome.as_str(),
            option_json(attempt.support_size),
            round_trip,
            nodes,
            error
        );
    }
    if let Some(selected) = &report.selected {
        print_recovery_details(selected, pair_count);
    }
}

fn print_controls(controls: Option<&GakSwapSelfTestReport>, controls_skipped: bool) {
    if let Some(self_test) = controls {
        print_self_test(self_test, GakSwapOutput::Text);
    } else if controls_skipped {
        println!(
            "gak swap controls: SKIPPED by --skip-controls; real-file output is not control-gated"
        );
    } else {
        println!("gak swap controls: not run");
    }
}

fn print_recovery_details(report: &RecoveryReport, pair_count: usize) {
    println!(
        "gak-swap-recover: {pair_count} known-plaintext pairs, n={}, max-swaps={}",
        report.pt_mapping.values().next().map_or(0, Vec::len),
        report.config.max_swaps
    );
    let exact = report.round_trip.exact();
    println!(
        "  verdict: {}",
        if exact {
            "VERIFIED RECOVERY (exact re-encryption)"
        } else {
            "CANDIDATE (not exact)"
        }
    );
    println!(
        "  round-trip: {}/{} ciphertext symbols matched",
        report.round_trip.matched, report.round_trip.total
    );
    if let Some((label, index, expected, actual)) = &report.round_trip.first_divergence {
        println!(
            "  first divergence: message {label} at ct index {index}: expected {expected:?}, got {actual:?}"
        );
    }
    println!(
        "  stats: candidates={} pruned={} deductions={} nodes={} sat-decisions={} sat-conflicts={} beam-drops={} target-rejections={} target-clauses={} target-replay-checks={} target-replay-literals={} candidate-clauses={} truth-checks={}",
        report.stats.enumerated_candidates,
        report.stats.domains_pruned,
        report.stats.deductions,
        report.stats.nodes,
        report.stats.sat_decisions,
        report.stats.sat_conflicts,
        report.stats.beam_drops,
        report.stats.target_rejections,
        report.stats.target_clauses_learned,
        report.stats.target_replay_checks,
        report.stats.target_replay_literals,
        report.stats.candidate_clauses_learned,
        report.stats.truth_preservation_checks
    );
    if !report.stats.measured_target_domain_entries.is_empty() {
        println!(
            "  measured target-slice residual: total={} max-domain={} per-letter={}",
            report.stats.measured_target_total_entries,
            report.stats.measured_target_max_domain,
            format_char_usize_pairs(&report.stats.measured_target_domain_entries)
        );
    }
    println!("  per-message:");
    for (label, matched, total) in &report.round_trip.per_message {
        println!("    {label}: {matched}/{total}");
    }
    println!("  per-letter:");
    for letter in &report.letters {
        println!(
            "    {} occ={} target={} support={} swaps={} equiv={} no-doubles={} verdict={:?}",
            letter.letter,
            letter.occurrences,
            format_option_usize(letter.target),
            format_usize_slice(&letter.support),
            format_usize_slice(&letter.canonical_swaps),
            letter.equivalent_count,
            letter.no_doubles,
            letter.verdict
        );
    }
    println!("  python pt_mapping (copy into noita_test_cipher.py after numpy import):");
    print!("{}", python_pt_mapping_literal(&report.pt_mapping));
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

fn print_json_report(
    report: &RecoveryReport,
    controls: Option<&GakSwapSelfTestReport>,
    controls_skipped: bool,
    pair_count: usize,
) {
    let mut out = recovery_json_prefix(controls, controls_skipped, pair_count);
    writeln!(&mut out, "  \"max_swaps\": {},", report.config.max_swaps).expect("write to String");
    append_recovery_json_body(&mut out, report, "  ");
    writeln!(&mut out, "}}").expect("write to String");
    print!("{out}");
}

fn print_inference_json(
    report: &SwapInferenceReport,
    controls: Option<&GakSwapSelfTestReport>,
    controls_skipped: bool,
    pair_count: usize,
    deck_size: usize,
) {
    let mut out = recovery_json_prefix(controls, controls_skipped, pair_count);
    writeln!(&mut out, "  \"mode\": \"infer-swaps\",").expect("write to String");
    writeln!(&mut out, "  \"n\": {deck_size},").expect("write to String");
    writeln!(
        &mut out,
        "  \"requested_range\": {{\"start\": {}, \"end\": {}}},",
        report.requested.start, report.requested.end
    )
    .expect("write to String");
    writeln!(
        &mut out,
        "  \"attempted_range\": {{\"start\": {}, \"end\": {}}},",
        report.attempted.start, report.attempted.end
    )
    .expect("write to String");
    writeln!(
        &mut out,
        "  \"frontier_capped\": {},",
        report.frontier_capped
    )
    .expect("write to String");
    writeln!(
        &mut out,
        "  \"inferred_max_swaps\": {},",
        option_json(report.inferred_max_swaps())
    )
    .expect("write to String");
    writeln!(
        &mut out,
        "  \"inferred_support_size\": {},",
        option_json(report.inferred_support_size())
    )
    .expect("write to String");
    writeln!(&mut out, "  \"attempts\": [").expect("write to String");
    for (index, attempt) in report.attempts.iter().enumerate() {
        let comma = if index + 1 == report.attempts.len() {
            ""
        } else {
            ","
        };
        let round_trip = attempt.round_trip.as_ref().map_or_else(
            || "null".to_owned(),
            |round_trip| {
                format!(
                    "{{\"matched\": {}, \"total\": {}}}",
                    round_trip.matched, round_trip.total
                )
            },
        );
        let nodes = attempt
            .stats
            .as_ref()
            .map_or_else(|| "null".to_owned(), |stats| stats.nodes.to_string());
        let error = attempt.error.as_ref().map_or_else(
            || "null".to_owned(),
            |error| format!("\"{}\"", json_escape(error)),
        );
        writeln!(
            &mut out,
            "    {{\"max_swaps\": {}, \"outcome\": \"{}\", \"support_size\": {}, \"round_trip\": {}, \"nodes\": {}, \"error\": {}}}{}",
            attempt.max_swaps,
            attempt.outcome.as_str(),
            option_json(attempt.support_size),
            round_trip,
            nodes,
            error,
            comma
        )
        .expect("write to String");
    }
    writeln!(&mut out, "  ],").expect("write to String");
    if let Some(selected) = &report.selected {
        writeln!(&mut out, "  \"selected\": {{").expect("write to String");
        append_recovery_json_body(&mut out, selected, "    ");
        writeln!(&mut out, "  }}").expect("write to String");
    } else {
        writeln!(&mut out, "  \"selected\": null").expect("write to String");
    }
    writeln!(&mut out, "}}").expect("write to String");
    print!("{out}");
}

fn recovery_json_prefix(
    controls: Option<&GakSwapSelfTestReport>,
    controls_skipped: bool,
    pair_count: usize,
) -> String {
    let mut out = String::new();
    writeln!(&mut out, "{{").expect("write to String");
    writeln!(&mut out, "  \"tool\": \"gak-swap-recover\",").expect("write to String");
    writeln!(&mut out, "  \"pair_count\": {pair_count},").expect("write to String");
    match controls {
        Some(self_test) => {
            writeln!(&mut out, "  \"controls\": {},", self_test_json(self_test))
                .expect("write to String");
        }
        None if controls_skipped => {
            writeln!(&mut out, "  \"controls\": \"skipped\",").expect("write to String");
        }
        None => {
            writeln!(&mut out, "  \"controls\": null,").expect("write to String");
        }
    }
    out
}

fn append_recovery_json_body(out: &mut String, report: &RecoveryReport, indent: &str) {
    writeln!(out, "{indent}\"exact\": {},", report.round_trip.exact()).expect("write to String");
    writeln!(out, "{indent}\"verdict\": \"{:?}\",", report.verdict).expect("write to String");
    writeln!(out, "{indent}\"round_trip\": {},", round_trip_json(report)).expect("write to String");
    writeln!(out, "{indent}\"pt_mapping\": {},", pt_mapping_json(report)).expect("write to String");
    writeln!(
        out,
        "{indent}\"python_pt_mapping\": \"{}\",",
        json_escape(&python_pt_mapping_literal(&report.pt_mapping))
    )
    .expect("write to String");
    writeln!(
        out,
        "{indent}\"stats\": {{\"candidates\": {}, \"domains_pruned\": {}, \"deductions\": {}, \"nodes\": {}, \"sat_decisions\": {}, \"sat_conflicts\": {}, \"beam_drops\": {}, \"target_rejections\": {}, \"target_clauses_learned\": {}, \"target_replay_checks\": {}, \"target_replay_literals\": {}, \"candidate_clauses_learned\": {}, \"truth_preservation_checks\": {}, \"measured_target_total_entries\": {}, \"measured_target_max_domain\": {}, \"measured_target_domain_entries\": {}}},",
        report.stats.enumerated_candidates,
        report.stats.domains_pruned,
        report.stats.deductions,
        report.stats.nodes,
        report.stats.sat_decisions,
        report.stats.sat_conflicts,
        report.stats.beam_drops,
        report.stats.target_rejections,
        report.stats.target_clauses_learned,
        report.stats.target_replay_checks,
        report.stats.target_replay_literals,
        report.stats.candidate_clauses_learned,
        report.stats.truth_preservation_checks,
        report.stats.measured_target_total_entries,
        report.stats.measured_target_max_domain,
        char_usize_pairs_json(&report.stats.measured_target_domain_entries)
    )
    .expect("write to String");
    writeln!(out, "{indent}\"letters\": [").expect("write to String");
    for (index, letter) in report.letters.iter().enumerate() {
        let comma = if index + 1 == report.letters.len() {
            ""
        } else {
            ","
        };
        writeln!(
            out,
            "{indent}  {{\"letter\": \"{}\", \"occurrences\": {}, \"target\": {}, \"support\": {}, \"support_size\": {}, \"swap_word\": {}, \"swaps\": {}, \"permutation\": {}, \"equivalent_count\": {}, \"no_doubles\": {}, \"verdict\": \"{:?}\"}}{}",
            json_escape(&letter.letter.to_string()),
            letter.occurrences,
            option_json(letter.target),
            usize_slice_json(&letter.support),
            letter.support.len(),
            usize_slice_json(&letter.canonical_swaps),
            usize_slice_json(&letter.canonical_swaps),
            optional_usize_slice_json(letter.permutation.as_deref()),
            letter.equivalent_count,
            letter.no_doubles,
            letter.verdict,
            comma
        )
        .expect("write to String");
    }
    writeln!(out, "{indent}]").expect("write to String");
}

fn round_trip_json(report: &RecoveryReport) -> String {
    format!(
        "{{\"matched\": {}, \"total\": {}, \"exact\": {}, \"per_message\": {}, \"first_divergence\": {}}}",
        report.round_trip.matched,
        report.round_trip.total,
        report.round_trip.exact(),
        per_message_json(report),
        first_divergence_json(report)
    )
}

fn per_message_json(report: &RecoveryReport) -> String {
    let rows = report
        .round_trip
        .per_message
        .iter()
        .map(|(label, matched, total)| {
            format!(
                "{{\"label\": \"{}\", \"matched\": {}, \"total\": {}}}",
                json_escape(label),
                matched,
                total
            )
        })
        .collect::<Vec<_>>();
    format!("[{}]", rows.join(", "))
}

fn first_divergence_json(report: &RecoveryReport) -> String {
    report.round_trip.first_divergence.as_ref().map_or_else(
        || "null".to_owned(),
        |(label, index, expected, actual)| {
            format!(
                "{{\"label\": \"{}\", \"index\": {}, \"expected\": \"{}\", \"actual\": \"{}\"}}",
                json_escape(label),
                index,
                json_escape(&expected.to_string()),
                json_escape(&actual.to_string())
            )
        },
    )
}

fn pt_mapping_json(report: &RecoveryReport) -> String {
    let rows = report
        .pt_mapping
        .iter()
        .map(|(letter, permutation)| {
            format!(
                "\"{}\": {}",
                json_escape(&letter.to_string()),
                usize_slice_json(permutation)
            )
        })
        .collect::<Vec<_>>();
    format!("{{{}}}", rows.join(", "))
}

fn self_test_json(report: &GakSwapSelfTestReport) -> String {
    format!(
        "{{\"seed\":\"0x{:016x}\",\"passed\":{},\"positive_ns1\":{},\"positive_ns2\":{},\"full_permutation_null\":{},\"over_budget_null\":{},\"over_budget_recovery_exact\":{},\"label_shuffle_null\":{}}}",
        report.config.seed,
        report.passed(),
        positive_json(&report.positive_ns1),
        positive_json(&report.positive_ns2),
        null_json(&report.full_permutation_null),
        null_json(&report.over_budget_null),
        report.over_budget_recovery_exact,
        null_json(&report.label_shuffle_null)
    )
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

fn format_option_usize(value: Option<usize>) -> String {
    value.map_or_else(|| "-".to_owned(), |found| found.to_string())
}

fn format_usize_slice(values: &[usize]) -> String {
    values
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn format_char_usize_pairs(values: &[(char, usize)]) -> String {
    values
        .iter()
        .map(|(letter, count)| format!("{letter}:{count}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn option_json(value: Option<usize>) -> String {
    value.map_or_else(|| "null".to_owned(), |found| found.to_string())
}

fn usize_slice_json(values: &[usize]) -> String {
    format!("[{}]", format_usize_slice(values))
}

fn optional_usize_slice_json(values: Option<&[usize]>) -> String {
    values.map_or_else(|| "null".to_owned(), usize_slice_json)
}

fn char_usize_pairs_json(values: &[(char, usize)]) -> String {
    let entries = values
        .iter()
        .map(|(letter, count)| format!("[\"{}\",{}]", json_escape(&letter.to_string()), count))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{entries}]")
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

//! Handler for `shadowsearch`: closure-shadow hidden-state key search.

use std::fmt::Write as _;
use std::process::ExitCode;

use noita_eye_puzzle::analysis::shadow_search::{
    self, Anchor, CanonicalClass, FiberReport, RepresentativeKey, ShadowSearchOutcome,
    ShadowSearchReport, ShadowSearchSelfTest,
};

use crate::cli::args_shadowsearch::ShadowsearchArgs;
use crate::cli::shared::{parse_cli_sequence, resolve_input_text};

const ORIENTATION_ALPHABET: usize = 5;
const CAVEAT: &str = "closure is a lower-bound shadow group; a 48-shadow survivor is a quotient candidate and does not certify a key in the reported order-96 true group";

/// Dispatches the `shadowsearch` subcommand.
pub(crate) fn run_shadowsearch(args: &ShadowsearchArgs) -> ExitCode {
    if args.self_test {
        return run_self_test(args.seed);
    }
    run_scan(args)
}

fn run_self_test(seed: u64) -> ExitCode {
    let report = match shadow_search::shadow_search_self_test(seed) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("shadowsearch self-test error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print_self_test(seed, &report);
    if report.passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn run_scan(args: &ShadowsearchArgs) -> ExitCode {
    let controls = if args.output.is_some() {
        match shadow_search::shadow_search_self_test(args.seed) {
            Ok(report) if report.passed => Some(report),
            Ok(report) => {
                print_self_test(args.seed, &report);
                eprintln!("shadowsearch refused --output because self-test failed");
                return ExitCode::FAILURE;
            }
            Err(error) => {
                eprintln!("shadowsearch self-test error: {error}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };

    let text = match resolve_input_text(
        args.sequence.as_deref(),
        args.input_file.as_ref(),
        args.stdin,
    ) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("failed to read input: {error}");
            return ExitCode::FAILURE;
        }
    };
    let parsed = match parse_cli_sequence(&text, args.alphabet.as_deref(), false) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let values: Vec<u16> = parsed.glyphs.iter().map(|glyph| glyph.0).collect();
    let alphabet_size = args
        .alphabet
        .as_deref()
        .map_or(ORIENTATION_ALPHABET, |spec| spec.chars().count());
    let labels = symbol_labels(args.alphabet.as_deref(), alphabet_size);
    let report = match shadow_search::run_shadow_search(&values, alphabet_size, args.into()) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("shadowsearch error: {error}");
            return ExitCode::FAILURE;
        }
    };

    if let Some(control_report) = controls.as_ref() {
        print_self_test(args.seed, control_report);
    }
    print_report(&report, &labels);
    if let Some(path) = args.output.as_ref() {
        let artifact = report_json(&report);
        if let Err(error) = std::fs::write(path, artifact) {
            eprintln!("failed to write shadowsearch artifact: {error}");
            return ExitCode::FAILURE;
        }
        println!("  artifact: wrote {}", path.display());
    }
    ExitCode::SUCCESS
}

fn print_self_test(seed: u64, report: &ShadowSearchSelfTest) {
    println!("shadowsearch self-test (seed=0x{seed:016x}):");
    println!(
        "  hidden-state positive:   {} (closure order {}, pass1 {}/{}, truth soft {}/{})",
        pass_fail(
            report.positive_truth_survived
                && report.positive_truth_in_pass1_survivors
                && report.positive_pass1_filtered
                && report.positive_truth_at_max_soft
        ),
        report.positive_closure_order,
        report.positive_pass1_survivor_keys,
        report.positive_key_space,
        report.positive_truth_soft_score,
        report.positive_max_soft_score
    );
    println!(
        "  untrimmed-anchor control: {}",
        pass_fail(report.untrimmed_anchor_killed_truth)
    );
    println!(
        "  trimmed-anchor control:   {}",
        pass_fail(report.trimmed_anchor_retained_truth)
    );
    println!(
        "  matched Markov null:      {} ({})",
        pass_fail(report.markov_null_no_basis),
        report
            .markov_null_reason
            .map_or("searched".to_owned(), |reason| reason.label().to_owned())
    );
    println!("  SELF-TEST: {}", pass_fail(report.passed));
}

fn print_report(report: &ShadowSearchReport, labels: &[String]) {
    println!(
        "shadowsearch: {} symbols over a {}-symbol alphabet",
        report.input_len, report.alphabet_size
    );
    println!("  output: quotient candidates under the closure (shadow) group, never decodes");
    println!("  caveat: {CAVEAT}");
    println!(
        "  basis: longest pattern-isomorph {}, null ceiling {}, p-value {:.4}, full maps {}",
        report.isomap.observed_max,
        report.isomap.null.ceiling,
        report.isomap.null.p_value,
        report.isomap.full_map_count
    );
    match &report.outcome {
        ShadowSearchOutcome::NoBasis { reason } => {
            println!("  verdict: NO BASIS ({}) -- search refused", reason.label());
        }
        ShadowSearchOutcome::Searched { summary, .. } => {
            print_basis(report, labels);
            print_anchors("hard anchors", &report.hard_anchors);
            print_anchors("soft anchors", &report.soft_anchors);
            println!("  search:");
            println!("    key space: {}", summary.total_keys);
            println!("    pass 1 survivor keys: {}", summary.pass1_survivor_keys);
            println!("    pass 2 survivor keys: {}", summary.pass2_survivor_keys);
            println!("    deduped q sequences: {}", summary.deduped_sequences);
            println!(
                "    max soft score: {}/{} over {} sequence(s)",
                summary.max_soft_score, summary.soft_anchor_count, summary.max_soft_sequence_count
            );
            println!(
                "    canonical classes at max: {} (retained {})",
                summary.max_soft_canonical_class_count,
                summary.top_canonical_classes.len()
            );
            for (index, class) in summary.top_canonical_classes.iter().enumerate() {
                println!(
                    "      class {}: score {} seqs {} nkeys {} key {} pattern {}",
                    index + 1,
                    class.soft_score,
                    class.sequence_count,
                    class.key_multiplicity,
                    format_key(&class.representative_key),
                    pattern_prefix(&class.canonical_pattern, 80)
                );
            }
        }
    }
}

fn print_basis(report: &ShadowSearchReport, labels: &[String]) {
    if let Some(closure) = &report.closure {
        println!("  closure lower bound:");
        println!("    group order: {}", closure.order);
        println!(
            "    legal readouts: {}",
            format_readouts(&report.legal_readouts, labels)
        );
        println!("    fibers: {}", format_fibers(&report.fibers, labels));
        if let Some(key_space) = report.key_space {
            println!("    key space formula: |G| * prod(|F_q|) = {key_space}");
        }
    }
}

fn print_anchors(label: &str, anchors: &[Anchor]) {
    println!("  {label}: {}", anchors.len());
    for anchor in anchors {
        println!(
            "    ({},{},{}) raw=({},{},{}) trim={}",
            anchor.first,
            anchor.second,
            anchor.length,
            anchor.raw_first,
            anchor.raw_second,
            anchor.raw_length,
            anchor.trim
        );
    }
}

fn report_json(report: &ShadowSearchReport) -> String {
    let mut out = String::new();
    writeln!(&mut out, "{{").expect("write to String");
    writeln!(&mut out, "  \"tool\": \"shadowsearch\",").expect("write to String");
    writeln!(&mut out, "  \"caveat\": \"{}\",", json_escape(CAVEAT)).expect("write to String");
    writeln!(&mut out, "  \"input_len\": {},", report.input_len).expect("write to String");
    writeln!(&mut out, "  \"alphabet_size\": {},", report.alphabet_size).expect("write to String");
    write_basis_json(&mut out, report);
    writeln!(
        &mut out,
        "  \"hard_anchors\": {},",
        anchors_json(&report.hard_anchors)
    )
    .expect("write to String");
    writeln!(
        &mut out,
        "  \"soft_anchors\": {},",
        anchors_json(&report.soft_anchors)
    )
    .expect("write to String");
    match &report.outcome {
        ShadowSearchOutcome::NoBasis { reason } => {
            writeln!(
                &mut out,
                "  \"outcome\": {{\"verdict\": \"no-basis\", \"reason\": \"{}\"}}",
                reason.label()
            )
            .expect("write to String");
        }
        ShadowSearchOutcome::Searched { summary, .. } => {
            writeln!(&mut out, "  \"outcome\": {{").expect("write to String");
            writeln!(&mut out, "    \"verdict\": \"searched\",").expect("write to String");
            writeln!(
                &mut out,
                "    \"total_keys\": {}, \"pass1_survivor_keys\": {}, \"pass2_survivor_keys\": {},",
                summary.total_keys, summary.pass1_survivor_keys, summary.pass2_survivor_keys
            )
            .expect("write to String");
            writeln!(
                &mut out,
                "    \"deduped_sequences\": {}, \"soft_anchor_count\": {}, \"max_soft_score\": {},",
                summary.deduped_sequences, summary.soft_anchor_count, summary.max_soft_score
            )
            .expect("write to String");
            writeln!(
                &mut out,
                "    \"max_soft_sequence_count\": {}, \"max_soft_canonical_class_count\": {},",
                summary.max_soft_sequence_count, summary.max_soft_canonical_class_count
            )
            .expect("write to String");
            writeln!(
                &mut out,
                "    \"score_histogram\": {},",
                histogram_json(&summary.score_histogram)
            )
            .expect("write to String");
            writeln!(
                &mut out,
                "    \"top_canonical_classes\": {}",
                classes_json(&summary.top_canonical_classes)
            )
            .expect("write to String");
            writeln!(&mut out, "  }}").expect("write to String");
        }
    }
    writeln!(&mut out, "}}").expect("write to String");
    out
}

fn write_basis_json(out: &mut String, report: &ShadowSearchReport) {
    let closure_order = report
        .closure
        .as_ref()
        .map_or_else(|| "null".to_owned(), |closure| closure.order.to_string());
    writeln!(
        out,
        "  \"basis\": {{\"significant\": {}, \"observed_max\": {}, \"null_ceiling\": {}, \"null_p_value\": {:.6}, \"full_map_count\": {}, \"closure_order\": {}, \"legal_readouts\": {}, \"fibers\": {}, \"key_space\": {}}},",
        report.isomap.significant,
        report.isomap.observed_max,
        report.isomap.null.ceiling,
        report.isomap.null.p_value,
        report.isomap.full_map_count,
        closure_order,
        usize_json(&report.legal_readouts),
        fibers_json(&report.fibers),
        report.key_space.map_or_else(|| "null".to_owned(), |key_space| key_space.to_string())
    )
    .expect("write to String");
}

fn classes_json(classes: &[CanonicalClass]) -> String {
    let rows = classes
        .iter()
        .map(|class| {
            format!(
                "{{\"soft_score\":{},\"sequence_count\":{},\"key_multiplicity\":{},\"canonical_pattern\":{},\"representative_key\":{}}}",
                class.soft_score,
                class.sequence_count,
                class.key_multiplicity,
                u16_json(&class.canonical_pattern),
                key_json(&class.representative_key)
            )
        })
        .collect::<Vec<_>>();
    format!("[{}]", rows.join(","))
}

fn key_json(key: &RepresentativeKey) -> String {
    let choices = key
        .choices
        .iter()
        .map(|choice| {
            format!(
                "{{\"readout\":{},\"fiber_choice\":{},\"element_index\":{},\"element\":{}}}",
                choice.readout,
                choice.fiber_choice,
                choice.element_index,
                usize_json(&choice.element)
            )
        })
        .collect::<Vec<_>>();
    format!(
        "{{\"initial_state_index\":{},\"initial_state\":{},\"choices\":[{}]}}",
        key.initial_state_index,
        usize_json(&key.initial_state),
        choices.join(",")
    )
}

fn anchors_json(anchors: &[Anchor]) -> String {
    let rows = anchors
        .iter()
        .map(|anchor| {
            format!(
                "{{\"first\":{},\"second\":{},\"length\":{},\"raw_first\":{},\"raw_second\":{},\"raw_length\":{},\"trim\":{}}}",
                anchor.first,
                anchor.second,
                anchor.length,
                anchor.raw_first,
                anchor.raw_second,
                anchor.raw_length,
                anchor.trim
            )
        })
        .collect::<Vec<_>>();
    format!("[{}]", rows.join(","))
}

fn fibers_json(fibers: &[FiberReport]) -> String {
    let rows = fibers
        .iter()
        .map(|fiber| {
            format!(
                "{{\"readout\":{},\"size\":{},\"element_indices\":{}}}",
                fiber.readout,
                fiber.size,
                usize_json(&fiber.element_indices)
            )
        })
        .collect::<Vec<_>>();
    format!("[{}]", rows.join(","))
}

fn histogram_json(histogram: &std::collections::BTreeMap<usize, usize>) -> String {
    let rows = histogram
        .iter()
        .map(|(score, count)| format!("\"{score}\":{count}"))
        .collect::<Vec<_>>();
    format!("{{{}}}", rows.join(","))
}

fn format_readouts(readouts: &[usize], labels: &[String]) -> String {
    readouts
        .iter()
        .map(|&readout| label_of(readout, labels))
        .collect::<Vec<_>>()
        .join(",")
}

fn format_fibers(fibers: &[FiberReport], labels: &[String]) -> String {
    fibers
        .iter()
        .map(|fiber| format!("{}:{}", label_of(fiber.readout, labels), fiber.size))
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_key(key: &RepresentativeKey) -> String {
    let choices = key
        .choices
        .iter()
        .map(|choice| format!("{}#{}", choice.readout, choice.fiber_choice))
        .collect::<Vec<_>>()
        .join(",");
    format!("u{} [{}]", key.initial_state_index, choices)
}

fn pattern_prefix(pattern: &[u16], max_len: usize) -> String {
    let mut text = String::new();
    for value in pattern.iter().take(max_len) {
        text.push_str(&value.to_string());
    }
    if pattern.len() > max_len {
        text.push_str("...");
    }
    text
}

fn symbol_labels(alphabet: Option<&str>, alphabet_size: usize) -> Vec<String> {
    match alphabet {
        Some(spec) => spec.chars().map(|ch| ch.to_string()).collect(),
        None => (0..alphabet_size)
            .map(|symbol| symbol.to_string())
            .collect(),
    }
}

fn label_of(symbol: usize, labels: &[String]) -> String {
    labels
        .get(symbol)
        .cloned()
        .unwrap_or_else(|| symbol.to_string())
}

fn usize_json(values: &[usize]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn u16_json(values: &[u16]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
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

fn pass_fail(passed: bool) -> &'static str {
    if passed { "PASS" } else { "FAIL" }
}

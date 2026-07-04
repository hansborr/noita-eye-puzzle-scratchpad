//! Handler for the `isomap` subcommand: equality-pattern isomorph column-map
//! extraction plus group closure over the full maps.

use std::process::ExitCode;

use noita_eye_puzzle::analysis::isomorph_map::{
    self, BlockSystem, ChainValidation, ColumnMap, GroupClosure, MapKind,
};

use crate::cli::args_isomap::IsomapArgs;
use crate::cli::shared::{parse_cli_sequence, resolve_input_text};

const ORIENTATION_ALPHABET: usize = 5;
const MAX_BLOCK_SYSTEMS_PRINTED: usize = 8;

/// Dispatches the `isomap` subcommand.
pub(crate) fn run_isomap(args: &IsomapArgs) -> ExitCode {
    if args.self_test {
        return run_self_test(args.seed);
    }
    run_scan(args)
}

fn run_self_test(seed: u64) -> ExitCode {
    let report = match isomorph_map::isomorph_map_self_test(seed) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("isomap self-test error: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!("isomap self-test (seed=0x{seed:016x}):");
    println!(
        "  GAK positive control:     {} (closure order {})",
        pass_fail(report.gak_positive_passed),
        report.positive_group_order
    );
    println!(
        "  matched Markov null:      {} (closure order {})",
        pass_fail(report.null_rejected),
        report.null_group_order
    );
    println!(
        "  dirty-boundary control:   {}",
        pass_fail(report.dirty_boundary_passed)
    );
    println!(
        "  SELF-TEST: {}",
        if report.passed { "PASS" } else { "FAIL" }
    );
    if report.passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn run_scan(args: &IsomapArgs) -> ExitCode {
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

    let report = match isomorph_map::isomorph_map_scan(
        &values,
        alphabet_size,
        args.min_span_len,
        args.trim,
        args.top_k,
        args.null_trials,
        args.seed,
    ) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("isomap error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let chains = isomorph_map::validate_chains(&report.maps);
    let full_maps: Vec<Vec<usize>> = report
        .maps
        .iter()
        .filter_map(|map| map.permutation.clone())
        .collect();
    let closure = match isomorph_map::close_full_maps(&full_maps, alphabet_size, args.closure_cap) {
        Ok(closure) => closure,
        Err(error) => {
            eprintln!("isomap closure error: {error}");
            return ExitCode::FAILURE;
        }
    };

    print_report(&report, &chains, &closure, &labels);
    ExitCode::SUCCESS
}

fn print_report(
    report: &isomorph_map::IsoMapReport,
    chains: &ChainValidation,
    closure: &GroupClosure,
    labels: &[String],
) {
    println!(
        "isomap: {} symbols over a {}-symbol alphabet",
        report.input_len, report.alphabet_size
    );
    println!(
        "  detector: raw equality-pattern isomorphs; boundary trim {} per side",
        report.trim
    );
    println!(
        "  longest equality-pattern span: {} symbols",
        report.observed_max
    );
    println!(
        "  matched null (order-1 Markov, {} trials): mean longest {:.1}, ceiling {}, p-value {:.4}",
        report.null.trials, report.null.mean_longest, report.null.ceiling, report.null.p_value
    );
    if report.significant {
        println!(
            "  verdict: STRUCTURAL CANDIDATE -- pattern span clears the transition-preserving null; this is not a decode."
        );
    } else {
        println!("  verdict: NO MAP BEYOND NULL -- no column maps are trusted from this input.");
    }
    println!(
        "  maps: {} surviving span pairs; {} full bijections, {} partial injections",
        report.maps.len(),
        report.full_map_count,
        report.partial_map_count
    );
    for map in &report.maps {
        print_map(map, labels);
    }
    print_chains(chains, labels);
    print_closure(closure, labels);
    println!(
        "  note: closure is a reconstructed state-group LOWER BOUND from observed full maps; a small-index supergroup probe is left for stage 1b."
    );
}

fn print_map(map: &ColumnMap, labels: &[String]) {
    let kind = match map.kind {
        MapKind::Full => "full",
        MapKind::Partial => "partial",
    };
    println!(
        "    len {:>4} at {} and {} (gap {}, core {}, dropped {})  {}  {}",
        map.span.length,
        map.span.first,
        map.span.second,
        map.span.gap,
        map.core_len,
        map.boundary_positions_dropped,
        kind,
        format_mapping(&map.mapping, labels)
    );
}

fn print_chains(chains: &ChainValidation, labels: &[String]) {
    println!(
        "  chaining: {} direct triples checked, {} violation(s)",
        chains.checked,
        chains.violations.len()
    );
    for violation in &chains.violations {
        println!(
            "    violation A={} B={} C={} on {}: composed {} vs direct {}",
            violation.first,
            violation.middle,
            violation.third,
            label_of(violation.symbol, labels),
            label_of(violation.composed, labels),
            label_of(violation.direct, labels)
        );
    }
}

fn print_closure(closure: &GroupClosure, labels: &[String]) {
    println!("  closure lower bound:");
    println!("    group order: {}", closure.order);
    println!(
        "    element-order histogram: {}",
        format_histogram(&closure.element_order_histogram)
    );
    println!(
        "    transitive: {}; orbits: {}",
        yes_no(closure.transitive),
        format_blocks(&closure.orbits, labels)
    );
    if closure.block_search_skipped {
        println!("    preserved block systems: skipped for this alphabet size");
    } else if closure.block_systems.is_empty() {
        println!("    preserved block systems: none found");
    } else {
        println!("    preserved block systems:");
        for system in closure.block_systems.iter().take(MAX_BLOCK_SYSTEMS_PRINTED) {
            println!("      {}", format_block_system(system, labels));
        }
        if closure.block_systems.len() > MAX_BLOCK_SYSTEMS_PRINTED {
            println!(
                "      ... {} more",
                closure.block_systems.len() - MAX_BLOCK_SYSTEMS_PRINTED
            );
        }
    }
    println!(
        "    point stabilizer at {}: {}",
        label_of(0, labels),
        closure.point_stabilizer_order
    );
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

fn format_mapping(mapping: &[Option<usize>], labels: &[String]) -> String {
    mapping
        .iter()
        .enumerate()
        .filter_map(|(source, target)| {
            target
                .map(|target| format!("{}->{}", label_of(source, labels), label_of(target, labels)))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_histogram(histogram: &std::collections::BTreeMap<usize, usize>) -> String {
    let body = histogram
        .iter()
        .map(|(order, count)| format!("{order}:{count}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{{{body}}}")
}

fn format_block_system(system: &BlockSystem, labels: &[String]) -> String {
    format_blocks(&system.blocks, labels)
}

fn format_blocks(blocks: &[Vec<usize>], labels: &[String]) -> String {
    blocks
        .iter()
        .map(|block| {
            let mut body = String::new();
            for &symbol in block {
                body.push_str(&label_of(symbol, labels));
            }
            format!("{{{body}}}")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn pass_fail(passed: bool) -> &'static str {
    if passed { "PASS" } else { "FAIL" }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

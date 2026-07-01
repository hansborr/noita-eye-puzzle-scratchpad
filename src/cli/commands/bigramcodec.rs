//! Handler for the `bigramcodec` subcommand.

use std::process::ExitCode;

use noita_eye_puzzle::attack::bigramcodec::{
    self, BigramCfg, BigramReport, BigramSelfTestReport, HonestVerdict, LanguageRow, NullStats,
    READABLE_MIN, StreamKind, StreamReport,
};

use crate::cli::args_bigramcodec::{BigramStreamArg, BigramcodecArgs};
use crate::cli::shared::{parse_cli_sequence, resolve_input_text};

const DEFAULT_BASE: usize = 5;

/// Dispatches the `bigramcodec` subcommand.
pub(crate) fn run_bigramcodec(args: &BigramcodecArgs) -> ExitCode {
    if args.self_test {
        return run_self_test(args.seed);
    }
    run_scan(args)
}

fn cfg_from(args: &BigramcodecArgs) -> BigramCfg {
    BigramCfg {
        null_trials: args.null_trials,
        restarts: args.restarts,
        iters: args.iters,
        seed: args.seed,
    }
}

fn selected_streams(args: &BigramcodecArgs) -> Vec<StreamKind> {
    if args.streams.is_empty() {
        return bigramcodec::all_streams().to_vec();
    }
    args.streams
        .iter()
        .copied()
        .flat_map(BigramStreamArg::to_streams)
        .collect()
}

fn run_scan(args: &BigramcodecArgs) -> ExitCode {
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
    let base = args
        .alphabet
        .as_deref()
        .map_or(DEFAULT_BASE, |spec| spec.chars().count());
    let cfg = cfg_from(args);
    let streams = selected_streams(args);
    let report = match bigramcodec::analyze_bigramcodec(&parsed.glyphs, base, &streams, &cfg) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("bigramcodec error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print_report(&report, &cfg);
    ExitCode::SUCCESS
}

fn print_report(report: &BigramReport, cfg: &BigramCfg) {
    print_header(report, cfg);
    for stream in &report.streams {
        print_stream(stream);
    }
    println!();
    if report.has_candidate() {
        println!(
            "OVERALL VERDICT: readable candidate hypothesis present. This is not a decode; inspect the text and crib hits by eye. The statistical gate cannot confirm a bigram-carried signal at this budget."
        );
    } else {
        println!(
            "OVERALL VERDICT: no readable candidate. Order-0-only rows are token-bigram artifacts; order-1 is a near-powerless diagnostic for this bigram objective, not a language discriminator."
        );
    }
}

fn print_header(report: &BigramReport, cfg: &BigramCfg) {
    let carrier = &report.carrier;
    let distribution = carrier
        .distribution
        .iter()
        .map(|(value, count)| format!("{value}:{count}"))
        .collect::<Vec<_>>()
        .join(", ");
    println!(
        "bigramcodec: {} digits over base {} (clean +/-1 walk)",
        carrier.n_digits, carrier.base
    );
    println!(
        "  moves: {} bits ({} up / {} down); magnitudes |M| = {} distribution {{{}}}",
        carrier.n_bits, carrier.n_up, carrier.n_down, carrier.n_magnitudes, distribution
    );
    println!(
        "  search budget: null_trials={} restarts={} iters={} seed=0x{:016x}",
        cfg.null_trials, cfg.restarts, cfg.iters, cfg.seed
    );
    println!(
        "  verdict rule: candidate = readability coverage >= {READABLE_MIN}; artifact = not readable but beats order-0; negative = not readable and does not beat order-0."
    );
    println!(
        "  nulls: order-0 = unigram-preserving shuffle; order-1 = Markov transition-preserving confound control retained as a diagnostic."
    );
    println!(
        "  order-1 honesty note: a perfectly recovered English plant scores only about z=+0.6, p=0.33, so genuine English can fail it too."
    );
}

fn print_stream(stream: &StreamReport) {
    let summary = &stream.stream;
    println!();
    println!(
        "Stream {}: {} tokens from {} source units; distinct symbols = {}",
        summary.kind.label(),
        summary.tokens.len(),
        summary.source_units,
        summary.distinct_count()
    );
    if summary.dropped_tail > 0 {
        println!(
            "  tail: {} trailing source unit(s) were left unpaired and not scored.",
            summary.dropped_tail
        );
    }
    if summary.distinct_count() < bigramcodec::GENERAL_ENGLISH_DISTINCT_FLOOR {
        println!(
            "  alphabet cap: fewer than about 20 distinct symbols cannot carry general 26-letter English; this stream is alphabet-capped."
        );
    }
    println!(
        "  {:<8} {:>9} {:>9} {:>9} {:>7} {:>7} {:>9} {:>9} {:>7} {:>7} {:>4}  verdict",
        "lang",
        "observed",
        "o0_mean",
        "o0_max",
        "o0_z",
        "o0_p",
        "o1_mean",
        "o1_max",
        "o1_z",
        "o1_p",
        "read"
    );
    for row in &stream.languages {
        print_row(row);
    }
    println!("  best decode text (best substitution; hypothesis text, not a decode claim):");
    for row in &stream.languages {
        println!("    {:<8} {}", row.language.label(), row.real.text);
    }
}

fn print_row(row: &LanguageRow) {
    let Some(order0) = row.order0.as_ref() else {
        println!(
            "  {:<8} {:>9} {:>9} {:>9} {:>7} {:>7} {:>9} {:>9} {:>7} {:>7} {:>4}  skipped",
            row.language.label(),
            "-",
            "-",
            "-",
            "-",
            "-",
            "-",
            "-",
            "-",
            "-",
            "-"
        );
        return;
    };
    let Some(order1) = row.order1.as_ref() else {
        return;
    };
    println!(
        "  {:<8} {:>9.3} {:>9.3} {:>9.3} {:>+7.2} {:>7.4} {:>9.3} {:>9.3} {:>+7.2} {:>7.4} {:>4}  {}",
        row.language.label(),
        row.real.best_mean,
        order0.mean,
        order0.ceiling,
        finite_z(order0),
        order0.p,
        order1.mean,
        order1.ceiling,
        finite_z(order1),
        order1.p,
        row.readability_coverage,
        verdict_label(row.verdict)
    );
}

fn finite_z(stats: &NullStats) -> f64 {
    if stats.z.is_finite() { stats.z } else { 999.0 }
}

fn verdict_label(verdict: HonestVerdict) -> &'static str {
    match verdict {
        HonestVerdict::Candidate => "CANDIDATE",
        HonestVerdict::Artifact => "artifact",
        HonestVerdict::Negative => "negative",
        HonestVerdict::Skipped => "skipped",
    }
}

fn run_self_test(seed: u64) -> ExitCode {
    let report = match bigramcodec::bigramcodec_self_test(seed) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("bigramcodec self-test error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print_self_test(seed, &report);
    if report.passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn print_self_test(seed: u64, report: &BigramSelfTestReport) {
    println!("bigramcodec self-test (seed=0x{seed:016x}):");
    println!(
        "  POSITIVE (mag-pairs English plant): readability coverage = {} (min {}), beats order-0 = {}",
        report.positive_readability_coverage, READABLE_MIN, report.positive_beats_order0
    );
    println!(
        "  ORDER-1 CONTROL (same English plant): z = {:+.2}, p = {:.4}, clears gate = {} (must be false)",
        finite_self_test_z(report.positive_order1_z),
        finite_self_test_p(report.positive_order1_p),
        report.positive_beats_order1
    );
    println!(
        "  NEGATIVE (real one): max readability coverage = {} (must be < {})",
        report.negative_max_readability_coverage, READABLE_MIN
    );
    println!(
        "  SELF-TEST: {}",
        if report.passed() { "PASS" } else { "FAIL" }
    );
}

fn finite_self_test_z(z: f64) -> f64 {
    if z.is_finite() { z } else { 999.0 }
}

fn finite_self_test_p(p: f64) -> f64 {
    if p.is_finite() { p } else { 1.0 }
}

//! Handler for the `rlcodec` subcommand: the run-length codec battery for
//! `±1`-walk puzzles.
//!
//! It calls the same library functions the module's tests exercise
//! ([`rlcodec::run_battery`] / [`rlcodec::rlcodec_self_test`]). A high n-gram
//! score is **not** a decode (AGENTS.md honesty discipline): a codec is only a
//! survivor if it beats its matched null — an order-1 Markov resample of that
//! codec's *decoded symbol stream* — and the expected verdict on real `one` is an
//! honest negative.

use std::process::ExitCode;

use noita_eye_puzzle::attack::rlcodec::{self, BatteryCfg, BatteryReport, CodecVerdict};

use crate::cli::args_rlcodec::RlcodecArgs;
use crate::cli::shared::{display_prefix, parse_cli_sequence, resolve_input_text};

/// Walk base used when no `--alphabet` is supplied (the five orientation digits).
const DEFAULT_BASE: usize = 5;
/// Characters of rendered plaintext shown per codec.
const TEXT_PREVIEW: usize = 60;

/// Dispatches the `rlcodec` subcommand (battery, or `--self-test`).
pub(crate) fn run_rlcodec(args: &RlcodecArgs) -> ExitCode {
    if args.self_test {
        return run_self_test(args.seed);
    }
    run_scan(args)
}

/// Builds the battery configuration from the CLI arguments.
fn cfg_from(args: &RlcodecArgs) -> BatteryCfg {
    BatteryCfg {
        null_trials: args.null_trials,
        restarts: args.restarts,
        iters: args.iters,
        top_k: args.top_k,
        census_null_trials: rlcodec::DEFAULT_CENSUS_NULL_TRIALS,
        seed: args.seed,
    }
}

/// Runs the battery on the resolved input and prints the report.
fn run_scan(args: &RlcodecArgs) -> ExitCode {
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
    let report = match rlcodec::run_battery(&parsed.glyphs, base, &cfg) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("rlcodec error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print_report(&report, &cfg);
    ExitCode::SUCCESS
}

/// Prints the full battery report (header, census, codec table, overall verdict).
fn print_report(report: &BatteryReport, cfg: &BatteryCfg) {
    print_header(report);
    print_census(report, cfg.census_null_trials);
    print_battery(report);
    println!();
    if report.overall_survivor {
        println!(
            "OVERALL VERDICT: SURVIVOR present — a codec beat its matched null (verify as a candidate, never a decode)."
        );
    } else {
        println!(
            "OVERALL VERDICT: no survivor (honest negative). Near-English codec scores that do not beat the matched null are substitution-freedom artifacts, not a decode."
        );
        println!(
            "  scope: the matched null preserves each decoded stream's first-order (bigram) symbol structure, so this reads as 'no detectable ABOVE-bigram English signal', NOT 'not English'. At the short comma/term decode lengths (n ~ 18-35) the test has limited power — it excludes a strong/searchable codec signal, not a short genuine message."
        );
    }
}

/// Prints the derivation header.
fn print_header(report: &BatteryReport) {
    let derivation = &report.derivation;
    let distribution = derivation
        .distribution
        .iter()
        .map(|(value, count)| format!("{value}:{count}"))
        .collect::<Vec<_>>()
        .join(", ");
    println!(
        "rlcodec: {} digits over base {} (clean ±1 walk)",
        derivation.n_digits, derivation.base
    );
    println!(
        "  moves: {} bits ({} up / {} down)",
        derivation.n_bits, derivation.n_up, derivation.n_down
    );
    println!(
        "  carrier: direction-blind magnitudes |M| = {}  distribution {{{}}}",
        derivation.n_magnitudes, distribution
    );
}

/// Prints Section A: the magnitude census.
fn print_census(report: &BatteryReport, census_null_trials: usize) {
    let census = &report.census;
    println!();
    println!("Section A — magnitude census (carrier exact-repeat structure):");
    println!(
        "  observed longest repeat: {} magnitudes",
        census.observed_max
    );
    println!(
        "  matched null (order-1 Markov, {} trials): mean longest {:.2}, ceiling {}, p {:.4}",
        census_null_trials, census.null_max_mean, census.null_ceiling, census.p_value
    );
    if census.significant {
        println!(
            "  verdict: SIGNIFICANT — the carrier repeats beyond the transition-preserving null (a structural candidate, NOT a decode)."
        );
    } else {
        println!("  verdict: not significant (no repeat beyond the matched null).");
    }
    if census.anchors.is_empty() {
        println!("  (no anchors above the reporting floor)");
    } else {
        println!("  anchors (run positions; longest first):");
        for anchor in &census.anchors {
            let flag = if anchor.complemented {
                "  COMPLEMENTED (opposite run-direction parity)"
            } else {
                ""
            };
            println!(
                "    len {:>3}  at {} and {}  (gap {}){}",
                anchor.length, anchor.first, anchor.second, anchor.gap, flag
            );
        }
    }
}

/// Prints Section B: the per-codec battery table and rendered-text previews.
fn print_battery(report: &BatteryReport) {
    println!();
    println!("Section B — codec battery (real vs matched symbol-stream order-1 Markov null):");
    println!(
        "  {:<20} {:>4} {:>4} {:>9} {:>9} {:>9} {:>7} {:>7}  verdict",
        "codec", "#let", "|S|", "real", "null_mu", "null_max", "z", "p"
    );
    for verdict in &report.verdicts {
        print_verdict_row(verdict);
    }
    println!();
    println!("  rendered text (best substitution; first {TEXT_PREVIEW} chars):");
    for verdict in &report.verdicts {
        if verdict.evaluated {
            println!(
                "    {:<20} {}",
                verdict.codec_name,
                display_prefix(&verdict.text, TEXT_PREVIEW)
            );
        } else {
            println!("    {:<20} {}", verdict.codec_name, verdict.text);
        }
    }
}

/// Prints one codec's numeric row (or a degenerate marker).
fn print_verdict_row(verdict: &CodecVerdict) {
    if !verdict.evaluated {
        println!(
            "  {:<20} {:>4} {:>4} {:>9} {:>9} {:>9} {:>7} {:>7}  n/a (degenerate/skipped)",
            verdict.codec_name, verdict.n_letters, verdict.alphabet, "-", "-", "-", "-", "-"
        );
        return;
    }
    let label = if verdict.survivor {
        "SURVIVOR"
    } else {
        "below-null"
    };
    println!(
        "  {:<20} {:>4} {:>4} {:>9.3} {:>9.3} {:>9.3} {:>+7.2} {:>7.4}  {}",
        verdict.codec_name,
        verdict.n_letters,
        verdict.alphabet,
        verdict.real_mean,
        verdict.null_mean,
        verdict.null_max,
        verdict.z,
        verdict.p,
        label
    );
}

/// `rlcodec --self-test`: planted positive control + real-`one` negative.
fn run_self_test(seed: u64) -> ExitCode {
    let report = match rlcodec::rlcodec_self_test(seed) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("rlcodec self-test error: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!("rlcodec self-test (seed=0x{seed:016x}):");
    println!(
        "  POSITIVE ({}): survivor = {}, planted partition recovered = {}",
        report.positive_codec, report.positive_survivor, report.positive_partition_recovered
    );
    println!(
        "  NEGATIVE (real one): overall survivor = {} (must be false)",
        report.negative_overall_survivor
    );
    println!(
        "  SELF-TEST: {}",
        if report.passed() { "PASS" } else { "FAIL" }
    );
    if report.passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

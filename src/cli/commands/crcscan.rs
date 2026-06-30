//! Handler for the `crcscan` subcommand.
//!
//! The command is deliberately file-driven and candidate-framed: a match is a
//! stored-word mapping anchor to corroborate, never recovered plaintext.

use std::io::Read;
use std::process::ExitCode;

use noita_eye_puzzle::analysis::crc_scan::{
    self, CandidateMatch, DEFAULT_WORDLIST_TEXT, ScanReport, TargetCatalog, parse_target_text,
};

use crate::cli::args_analysis::CrcscanArgs;

/// Dispatches the `crcscan` subcommand.
pub(crate) fn run_crcscan(args: &CrcscanArgs) -> ExitCode {
    if args.self_test {
        return run_self_test(args);
    }
    run_scan(args)
}

fn run_scan(args: &CrcscanArgs) -> ExitCode {
    let words = match load_wordlist(args) {
        Ok(words) => words,
        Err(error) => {
            eprintln!("crcscan wordlist error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let targets = match load_targets(args) {
        Ok(targets) => targets,
        Err(error) => {
            eprintln!("crcscan target error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let report = match crc_scan::run_scan(&words, &targets, args.null_trials, args.seed) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("crcscan error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print_report(
        &report,
        args.wordlist.is_some(),
        args.input_file.is_some() || args.stdin,
    );
    ExitCode::SUCCESS
}

fn run_self_test(args: &CrcscanArgs) -> ExitCode {
    let report = match crc_scan::run_self_test(args.null_trials, args.seed) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("crcscan self-test error: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!("crcscan self-test (seed=0x{:016x}):", args.seed);
    println!(
        "  CRC-32/BZIP2(\"lumikki\") raw:        0x{:08x}",
        report.bzip2_raw
    );
    println!(
        "  byte-reversed positive control:      0x{:08x}",
        report.bzip2_byte_reversed
    );
    println!(
        "  lumikki -> 0xacf68674 control:       {}",
        pass_fail(report.crc_math_passed)
    );
    println!(
        "  planted scanner recovery:            {}",
        pass_fail(report.planted_recovery_passed)
    );
    println!(
        "  SplitMix64 null mean vs lambda:      {:.6e} vs {:.6e} ({})",
        report.null_mean,
        report.null_lambda,
        pass_fail(report.null_agrees)
    );
    println!("  SELF-TEST: {}", pass_fail(report.passed()));
    if report.passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn load_wordlist(args: &CrcscanArgs) -> Result<Vec<String>, String> {
    let text = match &args.wordlist {
        Some(path) => std::fs::read_to_string(path)
            .map_err(|error| format!("failed to read wordlist: {error}"))?,
        None => DEFAULT_WORDLIST_TEXT.to_owned(),
    };
    crc_scan::parse_wordlist(&text).map_err(|error| error.to_string())
}

fn load_targets(args: &CrcscanArgs) -> Result<TargetCatalog, String> {
    if let Some(path) = &args.input_file {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("failed to read input: {error}"))?;
        return parse_target_text(&text).map_err(|error| error.to_string());
    }
    if args.stdin {
        let mut text = String::new();
        let _bytes_read = std::io::stdin()
            .read_to_string(&mut text)
            .map_err(|error| format!("failed to read stdin: {error}"))?;
        return parse_target_text(&text).map_err(|error| error.to_string());
    }
    Ok(TargetCatalog::from_engine_messages())
}

fn print_report(report: &ScanReport, external_wordlist: bool, external_targets: bool) {
    println!("crcscan: stored-u32 CRC/hash word scan");
    println!(
        "  wordlist: {} entries ({})",
        report.dictionary_size,
        if external_wordlist {
            "external"
        } else {
            crc_scan::DEFAULT_WORDLIST_PATH
        }
    );
    println!(
        "  targets: {} stored u32s in {} pairs, {} unique nonzero u32s ({})",
        report.stored_u32_count,
        report.pair_count,
        report.unique_nonzero_u32_count,
        if external_targets {
            "external"
        } else {
            "verified ENGINE_MESSAGES"
        }
    );
    println!(
        "  configs: {} variants x 2 output byte orders = {} tests per word",
        report.variant_count, report.config_count
    );
    println!(
        "  note: byte-reversed output tests the equivalent target byte order without double-counting mirror comparisons."
    );
    print_matches(report);
    println!(
        "  analytic false-alarm: lambda={:.6e}, k={}, Poisson p(>=k)={:.6e}",
        report.analytic.lambda, report.statistical_hit_count, report.analytic.p_at_least_observed
    );
    println!(
        "  SplitMix64 null ({} trials, seed=0x{:016x}): mean {:.6e}, median {:.2}, min {}, max {}, empirical p(>=k) {:.6e}",
        report.empirical.trials,
        report.empirical.seed,
        report.empirical.mean,
        report.empirical.median,
        report.empirical.min,
        report.empirical.max,
        report.empirical.p_at_least_observed
    );
    println!(
        "  dictionary-size caution: the same hit is strong when lambda is tiny, but only suggestive for broad wordlists; with 100000 words here lambda would be {:.6e}.",
        lambda_for_words(report, 100_000)
    );
    println!("  verdict: candidates only; no hit is a decode without independent corroboration.");
}

fn print_matches(report: &ScanReport) {
    if report.matches.is_empty() {
        println!("  candidates: none");
        return;
    }
    println!("  candidates:");
    for hit in &report.matches {
        print_match(hit);
    }
}

fn print_match(hit: &CandidateMatch) {
    println!(
        "    word {:?} via {} ({}) -> 0x{:08x}; stored 0x{:08x} at m{} p{} {}",
        hit.word,
        hit.variant,
        hit.output_order,
        hit.digest_value,
        hit.stored_value,
        hit.location.message_index,
        hit.location.position,
        hit.location.half
    );
}

fn lambda_for_words(report: &ScanReport, words: usize) -> f64 {
    report.unique_nonzero_u32_count as f64 * report.config_count as f64 * words as f64
        / 4_294_967_296.0
}

fn pass_fail(ok: bool) -> &'static str {
    if ok { "PASS" } else { "FAIL" }
}

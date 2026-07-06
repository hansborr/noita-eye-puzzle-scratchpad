//! Handler for `substfinish`: monoalphabetic finishing of segmented candidates.

use std::process::ExitCode;

use noita_eye_puzzle::attack::substitution::{self, SubstitutionReport, SubstitutionSelfTest};

use crate::cli::args_substfinish::SubstfinishArgs;
use crate::cli::shared::{display_prefix, resolve_input_text};

const PREVIEW_CHARS: usize = 180;

/// Dispatches the `substfinish` subcommand.
pub(crate) fn run_substfinish(args: &SubstfinishArgs) -> ExitCode {
    let config = args.into();
    if args.self_test {
        return run_self_test(config);
    }
    run_real(args, config)
}

fn run_self_test(config: substitution::SubstitutionConfig) -> ExitCode {
    match substitution::substitution_self_test(config) {
        Ok(report) => {
            print_self_test(&report);
            if report.passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("substfinish self-test error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_real(args: &SubstfinishArgs, config: substitution::SubstitutionConfig) -> ExitCode {
    let controls = match substitution::substitution_self_test(config) {
        Ok(report) if report.passed => report,
        Ok(report) => {
            print_self_test(&report);
            eprintln!("substfinish refused real input because self-test failed");
            return ExitCode::FAILURE;
        }
        Err(error) => {
            eprintln!("substfinish self-test error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let text = match resolve_input_text(
        args.sequence.as_deref(),
        args.input_file.as_ref(),
        args.stdin,
    ) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("failed to read substitution input: {error}");
            return ExitCode::FAILURE;
        }
    };
    let Some(alphabet) = args.alphabet.as_deref() else {
        eprintln!("substfinish needs --alphabet <symbols> for real input");
        return ExitCode::FAILURE;
    };
    let input = match substitution::parse_substitution_input(&text, alphabet) {
        Ok(input) => input,
        Err(error) => {
            eprintln!("substfinish parse error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let report = match substitution::run_substitution_finish(&input, &config) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("substfinish error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print_self_test(&controls);
    print_report(&report, &config);
    ExitCode::SUCCESS
}

fn print_self_test(report: &SubstitutionSelfTest) {
    println!("substfinish self-test:");
    println!(
        "  planted positive: {} (candidate {}, exact {}, beats null {})",
        pass_fail(report.positive_candidate && report.positive_exact && report.positive_beats_null),
        pass_fail(report.positive_candidate),
        pass_fail(report.positive_exact),
        pass_fail(report.positive_beats_null)
    );
    println!(
        "  flat matched control: {}",
        pass_fail(report.flat_no_candidate)
    );
    println!("  SELF-TEST: {}", pass_fail(report.passed));
}

fn print_report(report: &SubstitutionReport, config: &substitution::SubstitutionConfig) {
    println!("substfinish:");
    println!(
        "  scope: monoalphabetic substitution over visible symbols with whitespace preserved; candidate only, not a verified decode"
    );
    println!(
        "  input: {} symbols, {} alphabet entries, {} separators",
        report.symbols, report.alphabet_size, report.separators
    );
    println!(
        "  search: restarts {}, iterations {}, seed 0x{:016x}",
        config.restarts, config.iters, config.seed
    );
    println!(
        "  matched null: space-position-preserving symbol shuffles; trials {}, observed {:.4}, null_ge {}, p_emp {:.4}, margin vs null max {:.4}",
        config.null_trials,
        report.observed_score,
        report.null_ge,
        report.p_emp,
        report.margin_vs_null_max
    );
    println!("  VERDICT: {}", report.verdict.label());
    println!(
        "  candidate preview: {}",
        display_prefix(&report.plaintext, PREVIEW_CHARS)
    );
    println!("  mapping:");
    for row in &report.mapping {
        println!("    {:?} -> {}", row.symbol, row.letter);
    }
}

fn pass_fail(passed: bool) -> &'static str {
    if passed { "PASS" } else { "FAIL" }
}

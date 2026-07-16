//! `polyshift` command handler.

use std::process::ExitCode;

use noita_eye_puzzle::attack::{polyshift, quadgram};

use crate::cli::args_polyshift::PolyshiftArgs;
use crate::cli::shared::{display_prefix, parse_cli_sequence, resolve_input_text};

pub(crate) fn run_polyshift(args: &PolyshiftArgs) -> ExitCode {
    let model = match quadgram::QuadgramModel::english() {
        Ok(model) => model,
        Err(error) => {
            eprintln!("polyshift language-model error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let control = match polyshift::planted_control(args.null_trials, args.seed, &model) {
        Ok(control) => control,
        Err(error) => {
            eprintln!("polyshift control error: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "polyshift planted control: {} (accuracy {:.3}, z {:.2}, margin {:.3}, round-trip {})",
        if control.passes { "PASS" } else { "FAIL" },
        control.accuracy,
        control.report.z,
        control.report.margin,
        control.report.candidate.round_trip_ok,
    );
    if !control.passes {
        eprintln!("polyshift stopped: planted positive control did not clear the full gate");
        return ExitCode::FAILURE;
    }

    let raw = match resolve_input_text(
        args.sequence.as_deref(),
        args.input_file.as_ref(),
        args.stdin,
    ) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("polyshift input error: {error}");
            return ExitCode::FAILURE;
        }
    };
    if args.alphabet.chars().count() != 26 {
        eprintln!("polyshift input error: --alphabet must contain exactly 26 symbols");
        return ExitCode::FAILURE;
    }
    let parsed = match parse_cli_sequence(&raw, Some(&args.alphabet), false) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("polyshift input error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let ciphertext: Vec<u8> = parsed.glyphs.iter().map(|glyph| glyph.0 as u8).collect();
    let report = match polyshift::analyze(
        &ciphertext,
        args.degree,
        args.null_trials,
        args.seed,
        &model,
    ) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("polyshift analysis error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print_report(&report);
    ExitCode::SUCCESS
}

fn print_report(report: &polyshift::PolyshiftReport) {
    let candidate = &report.candidate;
    println!(
        "polyshift exhaustive sweep: degree <= {}, cells {}, matched nulls {}",
        report.degree, report.searched_cells, report.null_trials
    );
    println!(
        "best candidate (hypothesis, never a decode): convention={} a={} b={} c={} score={:.6}",
        candidate.convention.name(),
        candidate.quadratic,
        candidate.linear,
        candidate.constant,
        candidate.score,
    );
    println!(
        "gate: round-trip={} null-mean={:.6} null-std={:.6} margin={:.6} z={:.3} survives={}",
        candidate.round_trip_ok,
        report.null_mean,
        report.null_std,
        report.margin,
        report.z,
        report.survives,
    );
    println!(
        "candidate prefix: {}",
        display_prefix(&candidate.render_plaintext(), 160)
    );
    if report.survives {
        println!(
            "VERDICT: Candidate — the bounded family produced a null-clearing, exact-replaying hypothesis; external confirmation is still required."
        );
    } else {
        println!(
            "VERDICT: HonestNegative — no candidate in the enumerated degree-{} position-polynomial family cleared z >= {:.0} and margin >= {:.0}; this excludes only that family.",
            report.degree,
            polyshift::Z_THRESHOLD,
            polyshift::MIN_SCORE_MARGIN,
        );
    }
}

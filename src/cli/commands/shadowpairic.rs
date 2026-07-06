//! Handler for `shadowpairic`: phase-0 pair-IC class ranking.

use std::process::ExitCode;

use noita_eye_puzzle::analysis::shadow_finish::{self, PairIcReport, PairIcSelfTest, PairIcShape};

use crate::cli::args_shadowpairic::ShadowpairicArgs;

/// Dispatches the `shadowpairic` subcommand.
pub(crate) fn run_shadowpairic(args: &ShadowpairicArgs) -> ExitCode {
    if args.self_test {
        return run_self_test(args.seed);
    }
    run_real(args)
}

fn run_self_test(seed: u64) -> ExitCode {
    match shadow_finish::pair_ic_self_test(seed) {
        Ok(report) => {
            print_self_test(seed, &report);
            if report.passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("shadowpairic self-test error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_real(args: &ShadowpairicArgs) -> ExitCode {
    let controls = match shadow_finish::pair_ic_self_test(args.seed) {
        Ok(report) if report.passed => report,
        Ok(report) => {
            print_self_test(args.seed, &report);
            eprintln!("shadowpairic refused real artifact output because self-test failed");
            return ExitCode::FAILURE;
        }
        Err(error) => {
            eprintln!("shadowpairic self-test error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let Some(artifact_path) = args.artifact.as_ref() else {
        eprintln!("shadowpairic needs --artifact <shadowsearch-output.json>");
        return ExitCode::FAILURE;
    };
    let artifact_text = match std::fs::read_to_string(artifact_path) {
        Ok(text) => text,
        Err(error) => {
            eprintln!(
                "failed to read artifact {}: {error}",
                artifact_path.display()
            );
            return ExitCode::FAILURE;
        }
    };
    let report = match shadow_finish::run_pair_ic_ranking(&artifact_text, args.target_ic) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("shadowpairic error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print_self_test(args.seed, &controls);
    print_report(&report, artifact_path);
    ExitCode::SUCCESS
}

fn print_self_test(seed: u64, report: &PairIcSelfTest) {
    println!("shadowpairic self-test (seed=0x{seed:016x}):");
    println!(
        "  invariance: {} (plain IC {:.6}, transformed IC {:.6}, delta {:.3e}, decode roundtrip {})",
        pass_fail(report.invariance_passed && report.decoded_roundtrip),
        report.plaintext_ic,
        report.transformed_ic,
        report.invariance_delta,
        pass_fail(report.decoded_roundtrip)
    );
    println!(
        "  matched flat null: {} (flat IC {:.6}, distance from English {:.6})",
        pass_fail(report.flat_null_away),
        report.flat_null_ic,
        report.flat_null_distance
    );
    println!("  SELF-TEST: {}", pass_fail(report.passed));
}

fn print_report(report: &PairIcReport, artifact_path: &std::path::Path) {
    println!("shadowpairic: {}", artifact_path.display());
    println!(
        "  scope: phase-0 pair-value IC over canonical q-pattern classes; ranker only, not a decode or acceptance verdict"
    );
    println!(
        "  target: English monogram IC {:.6}; phase {}; classes {}; dropped q-symbols {}",
        report.target_ic,
        report.phase.label(),
        report.classes,
        report.dropped_q_symbols
    );
    println!(
        "  shape: {} (English-like rows within +/-{:.4}: {}; best-vs-second distance gap {:.6})",
        shape_label(report.shape),
        report.english_like_window,
        report.english_like_classes,
        report.best_second_distance_gap
    );
    println!(
        "  caution: at N around 349, a junk class can land near English IC by chance; use this only to order later finish work"
    );
    println!(
        "  {:>4} {:>5} {:>5} {:>10} {:>10} {:>6} {:>7} {:>10}",
        "rank", "class", "pairs", "pair_ic", "distance", "soft", "seqs", "nkeys"
    );
    for row in &report.rankings {
        println!(
            "  {:>4} {:>5} {:>5} {:>10.6} {:>10.6} {:>6} {:>7} {:>10}",
            row.rank,
            row.class_index,
            row.pairs,
            row.pair_ic,
            row.distance,
            row.soft_score,
            row.sequence_count,
            row.key_multiplicity
        );
    }
}

fn shape_label(shape: PairIcShape) -> &'static str {
    match shape {
        PairIcShape::SharplyPeaked => "sharply peaked",
        PairIcShape::Flat => "flat/diffuse",
    }
}

fn pass_fail(passed: bool) -> &'static str {
    if passed { "PASS" } else { "FAIL" }
}

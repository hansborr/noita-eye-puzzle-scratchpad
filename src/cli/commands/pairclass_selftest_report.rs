//! Self-test reporting for the `pairclass` command.

use std::process::ExitCode;

use noita_eye_puzzle::attack::pairclass::pairclass_self_test;

pub(crate) fn run_self_test(seed: u64) -> ExitCode {
    let report = match pairclass_self_test(seed) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("pairclass self-test error: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!("pairclass self-test (seed=0x{seed:016x}):");
    println!(
        "  planted positive (recovery {:.3}): {}",
        report.plant.recovery,
        pass_fail(report.plant.passed())
    );
    println!("  matched Markov null: {}", pass_fail(report.null.passed()));
    println!(
        "  forced-prune instrumentation: {}",
        pass_fail(report.prune.passed())
    );
    println!(
        "  anchor-seed mechanism (oracle {:.3}, beam midword {}, enum leading {}, enum rejects-bad {}, harvest {}, occupancy {} {}): {}",
        report.anchor.oracle_recovery,
        report
            .anchor
            .harvested_truth_rank
            .map_or_else(|| "not-harvested".to_owned(), |rank| format!("#{rank}")),
        report
            .anchor
            .enumerated_truth_rank
            .map_or_else(|| "not-retained".to_owned(), |rank| format!("#{rank}")),
        pass_fail(report.anchor.enumerated_rejects_bad_coloring),
        report.anchor.harvested,
        report.anchor.max_occupancy,
        if report.anchor.saturated {
            "SATURATED"
        } else {
            "open"
        },
        pass_fail(report.anchor.passed())
    );
    println!(
        "  structured coloring (positive {:.3}, random-neg fired {}, null-floor hits {}): {}",
        report.structured.positive.mean_recovery,
        report.structured.negative.fired,
        report.structured.null.null_ge_floor,
        pass_fail(report.structured.passed())
    );
    println!("  walk gate control: {}", pass_fail(report.walk_gate));
    println!(
        "  embedded two regression (348 tokens, marginals {:?}): {}",
        report.two.marginals,
        pass_fail(report.two.passed())
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

fn pass_fail(value: bool) -> &'static str {
    if value { "PASS" } else { "FAIL" }
}

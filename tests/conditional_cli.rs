//! CLI characterization tests for first-order conditional-structure reports.

mod common;

use common::{assert_contains, run_noita_eye};

#[test]
fn conditional_subcommand_reports_first_order_panel() {
    let stdout = run_noita_eye(&[
        "conditional",
        "--trials-per-seed",
        "2",
        "--seeds",
        "2",
        "--seed",
        "123",
    ]);

    assert_contains(
        &stdout,
        "first-order conditional structure & successor graph",
    );
    assert_contains(&stdout, "low-power caveat:");
    assert_contains(&stdout, "within-message shuffle comparisons");
    assert_contains(&stdout, "diagonal/no-repeat accounting");
    assert_contains(&stdout, "no-repeat-conditioned shuffle comparisons");
    assert_contains(&stdout, "Sparse-table caveat:");
    assert_contains(&stdout, "flat-random estimator-bias calibration");
    assert_contains(&stdout, "planted structure controls");
    assert_contains(&stdout, "MI raw/corrected:");
}

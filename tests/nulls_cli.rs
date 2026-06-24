//! CLI characterization tests for null-model report subcommands.

mod common;

use common::{assert_contains, run_noita_eye};

#[test]
fn nulltest_subcommand_reports_standard36_null() {
    let stdout = run_noita_eye(&["nulltest", "--trials", "5", "--seed", "123"]);

    assert_contains(&stdout, "standard36 random-grid null");
    assert_contains(&stdout, "orders searched per trial:");
    assert_contains(&stdout, "analytic fixed-order headline bounds");
    assert_contains(
        &stdout,
        "Interpretation: this corrects grid-content randomness",
    );
}

#[test]
fn dofnull_subcommand_reports_researcher_dof_null() {
    let stdout = run_noita_eye(&[
        "dofnull",
        "--trials",
        "5",
        "--calib-trials",
        "5",
        "--seed",
        "123",
    ]);

    assert_contains(&stdout, "calibrated researcher-DoF random-grid null");
    assert_contains(&stdout, "configured axes:");
    assert_contains(&stdout, "analytic DoF-corrected headline bound");
    assert_contains(&stdout, "per-cell marginal calibration from set A");
}

#[test]
fn dofnull_calibration_trials_default_to_trials() {
    let stdout = run_noita_eye(&["dofnull", "--trials", "1", "--seed", "123"]);

    assert_contains(&stdout, "calibration trials (A): 1");
    assert_contains(&stdout, "resampling trials (B): 1");
}

#[test]
fn pipelinenull_subcommand_reports_pipeline_and_input_controls() {
    let stdout = run_noita_eye(&["pipelinenull", "--trials", "5", "--seed", "123"]);

    assert_contains(&stdout, "base-7 generation-pipeline null");
    assert_contains(&stdout, "resampled: matched engine pair lengths");
    assert_contains(&stdout, "engine-input randomness negative control");
    assert_contains(
        &stdout,
        "Interpretation: the base-7 pipeline does not manufacture",
    );
}

#[test]
fn isomorphnull_subcommand_reports_shuffle_null() {
    let stdout = run_noita_eye(&["isomorphnull", "--trials", "5", "--seed", "123"]);

    assert_contains(&stdout, "Experiment 7A isomorph shuffle null");
    assert_contains(
        &stdout,
        "boundary rule: detector runs within each message only",
    );
    assert_contains(&stdout, "longest repeated real isomorph");
    assert_contains(&stdout, "Any striking excess should be rechecked");
}

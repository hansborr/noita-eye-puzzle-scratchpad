//! CLI characterization tests for grouping reports.

mod common;

use common::{assert_contains, run_noita_eye};

#[test]
fn grouping_subcommand_reports_grouping_and_state_estimates() {
    let stdout = run_noita_eye(&["grouping"]);

    assert_contains(&stdout, "Experiment 8 base-N grouping reinterpretation");
    assert_contains(&stdout, "grouping summary");
    assert_contains(&stdout, "language-compatibility flags");
    assert_contains(&stdout, "independent collision state-count estimate");
    assert_contains(&stdout, "synthetic N-state positive-control calibration");
}

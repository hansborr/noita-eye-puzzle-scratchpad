//! CLI characterization tests for Pyry's Conditions falsification reports.

mod common;

use common::{assert_contains, run_noita_eye};

#[test]
fn pyry_subcommand_reports_falsification_matrix() {
    let stdout = run_noita_eye(&["pyry", "--seed", "123", "--draws", "4"]);

    assert_contains(&stdout, "Pyry's Conditions falsification harness");
    assert_contains(
        &stdout,
        "fixed alphabet: accepted honeycomb reading-layer values 0..=82",
    );
    assert_contains(&stdout, "C1 threshold: pooled IoC x83 <= 1.120");
    assert_contains(
        &stdout,
        "eyes                         yes     yes     yes     yes     yes     yes     yes     yes     yes      9/9     sanity",
    );
    assert_contains(
        &stdout,
        "autokey/Alberti              3/4     4/4     4/4     4/4     4/4     4/4     4/4     4/4     4/4      3/4 consistent",
    );
    assert_contains(
        &stdout,
        "Self-modifying direction: autokey/Alberti-style fixtures passed all nine in 3/4 draws.",
    );
    assert_contains(
        &stdout,
        "no language scoring, no symbol-to-meaning mapping, no reading-order re-selection",
    );
}

//! CLI regression tests for the Thread 3 perfect-isomorphism scan.

mod common;

use common::{assert_contains, run_noita_eye};

#[test]
fn perfectiso_subcommand_reports_headline_and_regressions() {
    let stdout = run_noita_eye(&["perfectiso", "--trials", "32", "--seed", "123"]);

    assert_contains(
        &stdout,
        "Thread 3 perfect-isomorphism / allomorph-consistency scan",
    );
    assert_contains(&stdout, "catalog windows: vetted discrete set {8, 9, 11}");
    assert_contains(&stdout, "robust strong-bar internal violations: 0");
    assert_contains(
        &stdout,
        "0 robust internal violations -> SUPPORTS (does not prove) perfect isomorphism",
    );
    assert_contains(&stdout, "safe-isomorph extent export");
    assert_contains(&stdout, "count: 16");
    assert_contains(&stdout, "3A messages 1/2");
    assert_contains(&stdout, "3B messages 7/8/9");
    assert_contains(&stdout, "3C bound hypothesis");
    assert_contains(&stdout, "positive control: fired");
    assert_contains(&stdout, "unknown meaning; unsolved");
}

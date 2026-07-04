//! CLI characterization tests for the closure-shadow key-search instrument.

mod common;

use common::{assert_contains, run_noita_eye};

#[test]
fn shadowsearch_self_test_reports_all_controls() {
    let stdout = run_noita_eye(&["shadowsearch", "--self-test", "--seed", "123"]);

    assert_contains(&stdout, "shadowsearch self-test");
    assert_contains(&stdout, "hidden-state positive:   PASS");
    assert_contains(&stdout, "untrimmed-anchor control: PASS");
    assert_contains(&stdout, "trimmed-anchor control:   PASS");
    assert_contains(&stdout, "matched Markov null:      PASS");
    assert_contains(&stdout, "SELF-TEST: PASS");
}

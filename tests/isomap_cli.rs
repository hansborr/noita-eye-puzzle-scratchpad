//! CLI characterization tests for the `isomap` column-map instrument.

mod common;

use common::{assert_contains, run_noita_eye};

#[test]
fn isomap_self_test_reports_all_controls() {
    let stdout = run_noita_eye(&["isomap", "--self-test", "--seed", "123"]);

    assert_contains(&stdout, "isomap self-test");
    assert_contains(&stdout, "GAK positive control:     PASS");
    assert_contains(&stdout, "matched Markov null:      PASS");
    assert_contains(&stdout, "dirty-boundary control:   PASS");
    assert_contains(&stdout, "SELF-TEST: PASS");
}

#[test]
fn isomap_two_reports_recorded_lower_bound() {
    let stdout = run_noita_eye(&[
        "isomap",
        "--input-file",
        "research/data/practice-puzzles/two",
        "--alphabet",
        "ABCDEFGHIJKL",
        "--null-trials",
        "16",
        "--seed",
        "123",
    ]);

    assert_contains(&stdout, "isomap: 698 symbols over a 12-symbol alphabet");
    assert_contains(&stdout, "verdict: STRUCTURAL CANDIDATE");
    assert_contains(&stdout, "maps:");
    assert_contains(&stdout, "chaining:");
    assert_contains(&stdout, "group order: 48");
    assert_contains(&stdout, "element-order histogram: {1:1, 2:15, 3:32}");
    assert_contains(&stdout, "{ADGJ} {BEHK} {CFIL}");
    assert_contains(&stdout, "point stabilizer at A: 4");
    assert_contains(&stdout, "LOWER BOUND");
}

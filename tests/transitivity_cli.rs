//! CLI regression tests for the transitivity / D166 report.

mod common;

use common::{assert_contains, run_noita_eye};

#[test]
fn transitivity_subcommand_reports_conditional_dihedral_caveats() {
    let stdout = run_noita_eye(&["transitivity", "--trials", "1", "--seed", "123"]);

    assert_contains(&stdout, "Thread 1B transitivity / D166 audit");
    assert_contains(&stdout, "verdict: D166 excluded conditionally");
    assert_contains(&stdout, "confidence: MEDIUM / conditional");
    assert_contains(&stdout, "core-only witnesses: 0");
    assert_contains(&stdout, "canonical-orientation caveat");
    assert_contains(&stdout, "broad window-11/non-genuine catalogue");
    assert_contains(&stdout, "distinct-column");
    assert_contains(&stdout, "D166 catalogue caveat");
    assert_contains(&stdout, "broad gap-isomorph evidence");
    assert_contains(
        &stdout,
        "not additional genuine/core-supported D166 witness support",
    );
    assert_contains(&stdout, "Wave-1 comparability note");
    assert_contains(
        &stdout,
        "from 19 ('3'): 9 (')') vs 63 ('_') core_only=false",
    );
    assert_contains(&stdout, "Assumptions A1-A5");
    assert_contains(&stdout, "HOLE 1");
    assert_contains(&stdout, "HOLE 2");
}

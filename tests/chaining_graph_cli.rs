//! CLI regression tests for graph-chaining reports.

mod common;

use common::{assert_contains, run_noita_eye};

#[test]
fn chaining_graph_subcommand_reports_conflicts_coverage_and_control() {
    let stdout = run_noita_eye(&["chaining-graph", "--trials", "1", "--seed", "123"]);

    assert_contains(&stdout, "Thread 5 graph-chaining audit");
    assert_contains(
        &stdout,
        "broad window-11/shared-pivot gap-isomorph conflict catalogue",
    );
    assert_contains(&stdout, "distinct-column conflict paths");
    assert_contains(
        &stdout,
        "broad window-11/shared-pivot gap-isomorph coverage",
    );
    assert_contains(&stdout, "core-supported repeated-core coverage");
    assert_contains(&stdout, "not wave-1's same-plaintext genuine tier");
    assert_contains(
        &stdout,
        "same-plaintext support is not established by the broad graph",
    );
    assert_contains(&stdout, "canonical-orientation caveat");
    assert_contains(&stdout, "Wave-1 comparability note");
    assert_contains(&stdout, "matched within-message multiset-shuffle null");
    assert_contains(&stdout, "synthetic non-commutative GAK stream fixture");
}

//! CLI regression tests for the tree-residual cross-tail n-gram null.

mod common;

use common::{assert_contains, run_noita_eye};

#[test]
fn treeresidual_subcommand_reports_cross_tail_null() {
    let stdout = run_noita_eye(&[
        "treeresidual",
        "--trials",
        "5",
        "--seed-count",
        "1",
        "--seed",
        "123",
    ]);

    assert_contains(&stdout, "tree-residual cross-tail n-gram null");
    assert_contains(&stdout, "mask reused: Experiment 7C Perseus");
    assert_contains(
        &stdout,
        "boundary rule: k-grams are built within one message residual segment",
    );
    assert_contains(&stdout, "residual-tails");
    assert_contains(&stdout, "full-message sanity");
    assert_contains(&stdout, "symbol-meaning guesses");
}

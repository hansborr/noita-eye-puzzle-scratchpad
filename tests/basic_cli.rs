//! CLI characterization tests for basic report subcommands.

mod common;

use common::{assert_contains, run_noita_eye};

#[test]
fn demo_subcommand_reports_verified_corpus_statistics() {
    let stdout = run_noita_eye(&["demo"]);

    assert_contains(&stdout, "verified eye corpus");
    assert_contains(&stdout, "entropy:");
    assert_contains(&stdout, "index of coincidence:");
    assert_contains(&stdout, "frequencies:");
}

#[test]
fn stats_subcommand_reports_input_sequence_statistics() {
    let stdout = run_noita_eye(&["stats", "012340123455"]);

    assert_contains(&stdout, "input:");
    assert_contains(&stdout, "entropy:");
    assert_contains(&stdout, "index of coincidence:");
    assert_contains(&stdout, "frequencies:");
}

#[test]
fn orders_subcommand_reports_order_audit_and_flatness() {
    let stdout = run_noita_eye(&["orders"]);

    assert_contains(&stdout, "grid row widths:");
    assert_contains(&stdout, "contiguous 0..=82 orders:");
    assert_contains(&stdout, "Experiment 4 reading-layer flatness");
    assert_contains(
        &stdout,
        "Interpretation: the df-aware chi-square tail tests",
    );
}

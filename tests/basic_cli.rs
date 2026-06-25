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
    // The entropy and IoC of the frozen nine-message corpus are content-derived
    // (no RNG), so these literals pin the verified corpus byte-content.
    assert_contains(&stdout, "2.2801 bits/glyph");
    assert_contains(&stdout, "0.2108");
}

#[test]
fn stats_subcommand_reports_input_sequence_statistics() {
    // "012340123455": the trailing two `5`s are row delimiters, leaving ten
    // glyphs uniform over digits 0-4, so entropy is exactly log2(5) (~2.3219)
    // and the index of coincidence is 1/9 (~0.1111), independent of any seed.
    let stdout = run_noita_eye(&["stats", "012340123455"]);

    assert_contains(&stdout, "input: 10 glyphs");
    assert_contains(&stdout, "entropy:");
    assert_contains(&stdout, "2.3219 bits/glyph");
    assert_contains(&stdout, "index of coincidence:");
    assert_contains(&stdout, "0.1111");
    assert_contains(&stdout, "frequencies:");
    assert_contains(&stdout, "g0: 2");
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

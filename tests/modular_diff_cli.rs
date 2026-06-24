//! CLI characterization tests for modular-difference reporting.

mod common;

use common::{assert_contains, run_noita_eye};

#[test]
fn moddiff_subcommand_reports_structureless_headline_band() {
    let stdout = run_noita_eye(&[
        "moddiff",
        "--trials",
        "8",
        "--seed",
        "123",
        "--max-period",
        "8",
        "--max-lag",
        "8",
    ]);

    assert_contains(
        &stdout,
        "Experiment 13 modular-difference family fingerprint",
    );
    assert_contains(
        &stdout,
        "boundary rule: every modular difference resets at message starts",
    );
    assert_contains(&stdout, "primary mod-83 differenced streams");
    assert_contains(&stdout, "secondary mod-125 differenced streams");
    assert_contains(
        &stdout,
        "Headline k=1 mod-83: top difference 7 occurs 25/1027 (0.0243); delta-IoC +0.000444; placement structureless.",
    );
    assert_contains(
        &stdout,
        "disfavors the simple incrementing-wheel fingerprint specifically",
    );
}

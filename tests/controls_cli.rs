//! CLI characterization tests for positive-control reports.

mod common;

use common::{assert_contains, run_noita_eye};

#[test]
fn controls_monoalphabetic_reports_positive_control() {
    let stdout = run_noita_eye(&["controls", "monoalphabetic", "--seed", "123"]);

    assert_contains(&stdout, "Experiment 11 monoalphabetic positive control");
    assert_contains(&stdout, "generated key:");
    assert_contains(&stdout, "known-key recovery: yes");
    assert_contains(&stdout, "documented Common Glyphs plaintext vectors");
}

#[test]
fn controls_isomorph_reports_polyalphabetic_positive_control() {
    let stdout = run_noita_eye(&["controls", "isomorph", "--seed", "123"]);

    assert_contains(
        &stdout,
        "Experiment 11 isomorph/polyalphabetic positive control",
    );
    assert_contains(&stdout, "known-present Vigenere repeating-key fixture");
    assert_contains(&stdout, "known-absent autokey short-seed fixture");
    assert_contains(&stdout, "known-absent full-length running-key fixture");
}

#[test]
fn controls_polyalphabetic_alias_reports_isomorph_control() {
    let stdout = run_noita_eye(&["controls", "polyalphabetic", "--seed", "123"]);

    assert_contains(
        &stdout,
        "Experiment 11 isomorph/polyalphabetic positive control",
    );
    assert_contains(&stdout, "known-present Vigenere repeating-key fixture");
}

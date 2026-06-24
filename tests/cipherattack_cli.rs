//! CLI characterization tests for candidate-cipher attack reports.

mod common;

use common::{assert_contains, run_noita_eye};

#[test]
fn cipherattack_subcommand_reports_candidate_cipher_harness() {
    let stdout = run_noita_eye(&[
        "cipherattack",
        "--samples",
        "1",
        "--null-trials",
        "1",
        "--max-vigenere-period",
        "1",
        "--seed",
        "123",
    ]);

    assert_contains(
        &stdout,
        "Experiment 12 candidate-cipher language-scoring/null harness",
    );
    assert_contains(&stdout, "fundamental limitation:");
    assert_contains(&stdout, "search methods");
    assert_contains(&stdout, "mapping caveats");
    assert_contains(&stdout, "positive control");
    assert_contains(&stdout, "Overall conclusion: clean negative");
}

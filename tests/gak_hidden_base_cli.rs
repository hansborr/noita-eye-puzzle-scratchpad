//! CLI tests for the hidden-base GAK/deck identifiability audit.

mod common;

use common::{assert_contains, run_noita_eye};

#[test]
fn gak_hidden_base_audit_cli_runs_controls_and_reports_surface() {
    let stdout = run_noita_eye(&[
        "gak-hidden-base-audit",
        "--n",
        "7",
        "--num-swaps",
        "1",
        "--messages",
        "4",
        "--message-len",
        "16",
        "--trials",
        "2",
    ]);

    assert_contains(&stdout, "gak-hidden-base-audit: trials=2 n=7 max-swaps=1");
    assert_contains(&stdout, "cipher convention:");
    assert_contains(&stdout, "hidden-base controls: PASS");
    assert_contains(&stdout, "planted-positive: PASS");
    assert_contains(&stdout, "random-full-permutation-key-null: PASS");
    assert_contains(&stdout, "ciphertext-label-shuffle-null: PASS");
    assert_contains(&stdout, "identifiability:");
    assert_contains(&stdout, "trial-0 decomposition:");
}

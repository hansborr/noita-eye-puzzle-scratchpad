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

#[test]
fn gak_hidden_base_s1_recover_cli_reports_solver_surface() {
    let stdout = run_noita_eye(&[
        "gak-hidden-base-s1-recover",
        "--n",
        "7",
        "--messages",
        "4",
        "--message-len",
        "16",
        "--trials",
        "2",
    ]);

    assert_contains(&stdout, "gak-hidden-base-s1-recover: trials=2 n=7 s=1");
    assert_contains(&stdout, "hidden-base s1 controls: PASS");
    assert_contains(&stdout, "planted-positive: PASS");
    assert_contains(&stdout, "ciphertext-label-shuffle-null: PASS");
    assert_contains(&stdout, "over-budget-key-null: PASS");
    assert_contains(&stdout, "base candidates tested per trial:");
    assert_contains(&stdout, "brute-force n!=5040");
    assert_contains(&stdout, "trial-0 recovery:");
    assert_contains(&stdout, "trial-0 audit:");
}

#[test]
fn gak_hidden_base_local_recover_cli_reports_bounded_surface() {
    let stdout = run_noita_eye(&[
        "gak-hidden-base-local-recover",
        "--n",
        "5",
        "--num-swaps",
        "3",
        "--messages",
        "6",
        "--message-len",
        "24",
        "--trials",
        "1",
        "--attempts",
        "96",
        "--max-rounds",
        "18",
    ]);

    assert_contains(&stdout, "gak-hidden-base-local-recover: trials=1 n=5 s=3");
    assert_contains(&stdout, "third-symbol-rank=true");
    assert_contains(&stdout, "fair-joint-order=true");
    assert_contains(&stdout, "joint-total-cap=393216");
    assert_contains(&stdout, "hidden-base local controls: PASS");
    assert_contains(&stdout, "planted-s2-positive: PASS");
    assert_contains(&stdout, "planted-s3-positive: PASS");
    assert_contains(&stdout, "scope note: a search-cap miss is not a proof");
    assert_contains(&stdout, "search surface: sigma-domain=");
    assert_contains(&stdout, "joint-replay-events min/max=");
    assert_contains(&stdout, "joint-pairs evaluated/eligible min/max=");
    assert_contains(&stdout, "total-budget-exhausted=");
    assert_contains(&stdout, "top-source stage: retained min/max=");
    assert_contains(&stdout, "third-symbol-evaluations min/max=");
    assert_contains(&stdout, "top-source planted audit: retained=");
    assert_contains(&stdout, "trial-0 recovery:");
    assert_contains(&stdout, "trial-0 signal:");
}

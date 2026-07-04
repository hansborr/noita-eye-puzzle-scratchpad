//! CLI tests for the Lymm known-plaintext swap-recovery command.

mod common;

use common::{assert_contains, run_noita_eye, run_noita_eye_failure};

const PLAINTEXTS: &str = "research/data/practice-puzzles/deck-swap/plaintexts.txt";
const NS1_CIPHERTEXTS: &str = "research/data/practice-puzzles/deck-swap/1_swap_ct.txt";
const NS2_CIPHERTEXTS: &str = "research/data/practice-puzzles/deck-swap/2_swap_ct.txt";
const NS3_CIPHERTEXTS: &str = "research/data/practice-puzzles/deck-swap/3_swap_ct.txt";

#[test]
fn gak_swap_recover_cli_recovers_ns1_exactly() {
    let stdout = run_noita_eye(&[
        "gak-swap-recover",
        "--plaintext-file",
        PLAINTEXTS,
        "--ciphertext-file",
        NS1_CIPHERTEXTS,
        "--num-swaps",
        "1",
        "--skip-controls",
    ]);

    assert_contains(&stdout, "gak swap controls: SKIPPED by --skip-controls");
    assert_contains(&stdout, "gak-swap-recover: 8 known-plaintext pairs");
    assert_contains(&stdout, "VERIFIED RECOVERY (exact re-encryption)");
    assert_contains(&stdout, "round-trip: 2439/2439 ciphertext symbols matched");
    assert_contains(&stdout, "stats: candidates=83");
    assert_contains(&stdout, "python pt_mapping (copy into noita_test_cipher.py");
    assert_contains(&stdout, "pt_mapping = {");
    assert_contains(&stdout, "\"A\": np.array([");
}

#[test]
fn gak_swap_recover_cli_reports_ns3_frontier_not_recovery() {
    let stderr = run_noita_eye_failure(&[
        "gak-swap-recover",
        "--plaintext-file",
        PLAINTEXTS,
        "--ciphertext-file",
        NS3_CIPHERTEXTS,
        "--num-swaps",
        "3",
        "--skip-controls",
    ]);

    assert_contains(&stderr, "unsupported top-swap budget 3");
    assert_contains(&stderr, "ns=3 remains a recorded wall");
}

#[test]
fn gak_swap_recover_cli_infers_ns2_with_frontier_cap() {
    let stdout = run_noita_eye(&[
        "gak-swap-recover",
        "--plaintext-file",
        PLAINTEXTS,
        "--ciphertext-file",
        NS2_CIPHERTEXTS,
        "--infer-swaps",
        "1..3",
        "--max-nodes",
        "50000",
        "--skip-controls",
    ]);

    assert_contains(&stdout, "gak-swap-recover infer-swaps");
    assert_contains(&stdout, "requested=1..3, attempted=1..2");
    assert_contains(&stdout, "frontier: capped at ns=2");
    assert_contains(&stdout, "ns=3 remains a recorded wall");
    assert_contains(&stdout, "inferred max-swaps: 2");
    assert_contains(&stdout, "support-size: 3 (max final-perm support");
    assert_contains(&stdout, "s=1 outcome=");
    assert_contains(&stdout, "s=2 outcome=exact-round-trip");
}

#[test]
fn gak_swap_recover_cli_rejects_infer_range_past_frontier() {
    let stderr = run_noita_eye_failure(&[
        "gak-swap-recover",
        "--plaintext-file",
        PLAINTEXTS,
        "--ciphertext-file",
        NS3_CIPHERTEXTS,
        "--infer-swaps",
        "3..4",
        "--skip-controls",
    ]);

    assert_contains(&stderr, "unsupported top-swap budget 3");
    assert_contains(&stderr, "ns=3 remains a recorded wall");
}

#[test]
fn gak_swap_recover_cli_json_includes_shareable_mapping_surface() {
    let stdout = run_noita_eye(&[
        "gak-swap-recover",
        "--plaintext-file",
        PLAINTEXTS,
        "--ciphertext-file",
        NS1_CIPHERTEXTS,
        "--num-swaps",
        "1",
        "--output",
        "json",
        "--skip-controls",
    ]);

    assert_contains(&stdout, "\"verdict\": \"RecoveredUnique\"");
    assert_contains(
        &stdout,
        "\"round_trip\": {\"matched\": 2439, \"total\": 2439, \"exact\": true",
    );
    assert_contains(&stdout, "\"pt_mapping\": {");
    assert_contains(&stdout, "\"A\": [");
    assert_contains(&stdout, "\"python_pt_mapping\": \"pt_mapping = {\\n");
    assert_contains(&stdout, "\"support_size\": 2");
    assert_contains(&stdout, "\"swap_word\": [");
    assert_contains(&stdout, "\"permutation\": [");
}

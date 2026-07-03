//! CLI tests for the Lymm known-plaintext swap-recovery command.

mod common;

use common::{assert_contains, run_noita_eye, run_noita_eye_failure};

const PLAINTEXTS: &str = "research/data/practice-puzzles/deck-swap/plaintexts.txt";
const NS1_CIPHERTEXTS: &str = "research/data/practice-puzzles/deck-swap/1_swap_ct.txt";
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
    ]);

    assert_contains(&stdout, "gak-swap-recover: 8 known-plaintext pairs");
    assert_contains(&stdout, "VERIFIED RECOVERY (exact re-encryption)");
    assert_contains(&stdout, "round-trip: 2439/2439 ciphertext symbols matched");
    assert_contains(&stdout, "stats: candidates=83");
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
    ]);

    assert_contains(&stderr, "unsupported top-swap budget 3");
    assert_contains(&stderr, "ns=3 remains a recorded wall");
}

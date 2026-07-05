//! CLI tests for the Lymm known-plaintext swap-recovery command.

mod common;

use std::collections::BTreeMap;
use std::fs;

use common::{assert_contains, run_noita_eye, run_noita_eye_failure};
use noita_eye_puzzle::attack::gak_attack::lymm_deck::{
    LymmComposeDirection, LymmDeckSpec, encrypt_lymm_deck, lymm_default_ct_alphabet,
};

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
fn gak_swap_arc_phase0_cli_runs_instrument_controls() {
    let stdout = run_noita_eye(&[
        "gak-swap-arc-phase0",
        "--run-controls",
        "--max-rejections",
        "1",
        "--replay-cap",
        "32",
    ]);

    assert_contains(&stdout, "gak swap arc Phase-0 controls:");
    assert_contains(&stdout, "planted-positive: PASS");
    assert_contains(&stdout, "matched-null: PASS");
    assert_contains(&stdout, "SELF-TEST: PASS");
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

#[test]
fn gak_swap_recover_cli_accepts_explicit_generator_file() {
    let spec = LymmDeckSpec::from_base(7, "AB", &lymm_default_ct_alphabet(7), (0..7).collect())
        .expect("spec");
    let mapping = BTreeMap::from([('A', rotation(7, 1)), ('B', rotation(7, 2))]);
    let plaintexts = ["ABBAAB", "BABAAB"];
    let ciphertexts = plaintexts
        .iter()
        .map(|plaintext| encrypt_lymm_deck(&spec, &mapping, plaintext).expect("encrypt"))
        .collect::<Vec<_>>();

    let plaintext_path = write_temp_file("pt", &plaintexts.join("\n\n"));
    let ciphertext_path = write_temp_file("ct", &ciphertexts.join("\n\n"));
    let base_path = write_temp_file("base", "0 1 2 3 4 5 6\n");
    let generator_path = write_temp_file(
        "generators",
        "\
rot1: 1 2 3 4 5 6 0
rot2: 2 3 4 5 6 0 1
",
    );

    let plaintext_path_str = plaintext_path.display().to_string();
    let ciphertext_path_str = ciphertext_path.display().to_string();
    let base_path_str = base_path.display().to_string();
    let generator_path_str = generator_path.display().to_string();
    let stdout = run_noita_eye(&[
        "gak-swap-recover",
        "--plaintext-file",
        &plaintext_path_str,
        "--ciphertext-file",
        &ciphertext_path_str,
        "--pair-format",
        "blank-lines",
        "--pt-alphabet",
        "AB",
        "--n",
        "7",
        "--base-file",
        &base_path_str,
        "--generator-file",
        &generator_path_str,
        "--max-swaps",
        "1",
        "--skip-controls",
    ]);

    assert_contains(&stdout, "VERIFIED RECOVERY (exact re-encryption)");
    assert_contains(&stdout, "gak-swap-recover: 2 known-plaintext pairs, n=7");
    assert_contains(&stdout, "stats: candidates=2");

    for path in [plaintext_path, ciphertext_path, base_path, generator_path] {
        let _ignored = fs::remove_file(path);
    }
}

#[test]
fn gak_swap_recover_cli_accepts_compose_direction_and_emit_index() {
    let spec = LymmDeckSpec::from_base(7, "AB", &lymm_default_ct_alphabet(7), (0..7).collect())
        .expect("spec")
        .with_compose_dir(LymmComposeDirection::Right)
        .with_emit_index(1)
        .expect("emit index");
    let mapping = BTreeMap::from([('A', rotation(7, 1)), ('B', rotation(7, 2))]);
    let plaintexts = ["ABBAAB", "BABAAB"];
    let ciphertexts = plaintexts
        .iter()
        .map(|plaintext| encrypt_lymm_deck(&spec, &mapping, plaintext).expect("encrypt"))
        .collect::<Vec<_>>();

    let plaintext_path = write_temp_file("right-pt", &plaintexts.join("\n\n"));
    let ciphertext_path = write_temp_file("right-ct", &ciphertexts.join("\n\n"));
    let base_path = write_temp_file("right-base", "0 1 2 3 4 5 6\n");
    let generator_path = write_temp_file(
        "right-generators",
        "\
rot1: 1 2 3 4 5 6 0
rot2: 2 3 4 5 6 0 1
",
    );

    let plaintext_path_str = plaintext_path.display().to_string();
    let ciphertext_path_str = ciphertext_path.display().to_string();
    let base_path_str = base_path.display().to_string();
    let generator_path_str = generator_path.display().to_string();
    let stdout = run_noita_eye(&[
        "gak-swap-recover",
        "--plaintext-file",
        &plaintext_path_str,
        "--ciphertext-file",
        &ciphertext_path_str,
        "--pair-format",
        "blank-lines",
        "--pt-alphabet",
        "AB",
        "--n",
        "7",
        "--base-file",
        &base_path_str,
        "--generator-file",
        &generator_path_str,
        "--max-swaps",
        "1",
        "--compose-direction",
        "right",
        "--emit-index",
        "1",
        "--skip-controls",
    ]);

    assert_contains(&stdout, "VERIFIED RECOVERY (exact re-encryption)");
    assert_contains(&stdout, "gak-swap-recover: 2 known-plaintext pairs, n=7");
    assert_contains(&stdout, "stats: candidates=2");

    for path in [plaintext_path, ciphertext_path, base_path, generator_path] {
        let _ignored = fs::remove_file(path);
    }
}

fn write_temp_file(label: &str, contents: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "noita-eye-gak-swap-{label}-{}-{}.txt",
        std::process::id(),
        unique_suffix()
    ));
    fs::write(&path, contents).expect("write temp file");
    path
}

fn unique_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos()
}

fn rotation(n: usize, shift: usize) -> Vec<usize> {
    (0..n).map(|index| (index + shift) % n).collect()
}

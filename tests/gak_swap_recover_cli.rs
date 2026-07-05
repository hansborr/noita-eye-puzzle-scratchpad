//! CLI tests for the Lymm known-plaintext swap-recovery command.

mod common;

use std::collections::BTreeMap;
use std::fs;

use common::{assert_contains, run_noita_eye, run_noita_eye_failure};
use noita_eye_puzzle::attack::gak_attack::lymm_deck::{
    LymmComposeDirection, LymmDeckSpec, encrypt_lymm_deck, generate_random_pt_mapping,
    lymm_default_ct_alphabet,
};

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
fn gak_swap_recover_cli_recovers_synthetic_ns3_with_local_search() {
    let (plaintext_path, ciphertext_path) = write_synthetic_swap_fixture("direct", 3);
    let plaintext_path_str = plaintext_path.display().to_string();
    let ciphertext_path_str = ciphertext_path.display().to_string();
    let stdout = run_noita_eye(&[
        "gak-swap-recover",
        "--plaintext-file",
        &plaintext_path_str,
        "--ciphertext-file",
        &ciphertext_path_str,
        "--pair-format",
        "blank-lines",
        "--pt-alphabet",
        "ABCD",
        "--n",
        "11",
        "--base-permutation",
        "affine:shift=4,decimation=3",
        "--num-swaps",
        "3",
        "--strategy",
        "local-search",
        "--skip-controls",
    ]);

    assert_contains(&stdout, "VERIFIED RECOVERY (exact re-encryption)");
    assert_contains(&stdout, "gak-swap-recover: 4 known-plaintext pairs, n=11");
    assert_contains(&stdout, "max-swaps=3");

    for path in [plaintext_path, ciphertext_path] {
        let _ignored = fs::remove_file(path);
    }
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
fn gak_swap_arc_phase0_cli_rejects_zero_replay_cap() {
    let stderr =
        run_noita_eye_failure(&["gak-swap-arc-phase0", "--run-controls", "--replay-cap", "0"]);

    assert_contains(&stderr, "must be at least 1");
}

#[test]
fn gak_swap_recover_cli_infers_ns2_with_frontier_cap() {
    let (plaintext_path, ciphertext_path) = write_synthetic_swap_fixture("cap", 2);
    let plaintext_path_str = plaintext_path.display().to_string();
    let ciphertext_path_str = ciphertext_path.display().to_string();
    let stdout = run_noita_eye(&[
        "gak-swap-recover",
        "--plaintext-file",
        &plaintext_path_str,
        "--ciphertext-file",
        &ciphertext_path_str,
        "--pair-format",
        "blank-lines",
        "--pt-alphabet",
        "ABCD",
        "--n",
        "11",
        "--base-permutation",
        "affine:shift=4,decimation=3",
        "--infer-swaps",
        "1..4",
        "--max-nodes",
        "50000",
        "--skip-controls",
    ]);

    assert_contains(&stdout, "gak-swap-recover infer-swaps");
    assert_contains(&stdout, "requested=1..4, attempted=1..3");
    assert_contains(&stdout, "frontier: capped at ns=3");
    assert_contains(&stdout, "inferred max-swaps: 2");
    assert_contains(&stdout, "support-size:");
    assert_contains(&stdout, "s=1 outcome=");
    assert_contains(&stdout, "s=2 outcome=exact-round-trip");

    for path in [plaintext_path, ciphertext_path] {
        let _ignored = fs::remove_file(path);
    }
}

#[test]
fn gak_swap_recover_cli_infers_synthetic_ns3_with_auto_strategy() {
    let (plaintext_path, ciphertext_path) = write_synthetic_swap_fixture("infer", 3);
    let plaintext_path_str = plaintext_path.display().to_string();
    let ciphertext_path_str = ciphertext_path.display().to_string();
    let stdout = run_noita_eye(&[
        "gak-swap-recover",
        "--plaintext-file",
        &plaintext_path_str,
        "--ciphertext-file",
        &ciphertext_path_str,
        "--pair-format",
        "blank-lines",
        "--pt-alphabet",
        "ABCD",
        "--n",
        "11",
        "--base-permutation",
        "affine:shift=4,decimation=3",
        "--infer-swaps",
        "1..3",
        "--skip-controls",
    ]);

    assert_contains(&stdout, "requested=1..3, attempted=1..3");
    assert_contains(&stdout, "inferred max-swaps: 3");
    assert_contains(&stdout, "s=3 outcome=exact-round-trip");

    for path in [plaintext_path, ciphertext_path] {
        let _ignored = fs::remove_file(path);
    }
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
        "4..5",
        "--skip-controls",
    ]);

    assert_contains(&stderr, "unsupported top-swap budget 4");
    assert_contains(&stderr, "ns<=3");
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

fn write_synthetic_swap_fixture(
    label: &str,
    num_swaps: usize,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let spec = LymmDeckSpec::from_shift_decimation(11, "ABCD", &lymm_default_ct_alphabet(11), 4, 3)
        .expect("spec");
    let planted = generate_random_pt_mapping(
        &spec,
        num_swaps,
        0x51a7_0300_0000_0000 ^ u64::try_from(num_swaps).expect("small swap count"),
    )
    .expect("planted mapping");
    let plaintexts = synthetic_ns3_plaintexts();
    let ciphertexts = plaintexts
        .iter()
        .map(|plaintext| encrypt_lymm_deck(&spec, &planted.pt_mapping, plaintext).expect("encrypt"))
        .collect::<Vec<_>>();
    let plaintext_label = format!("{label}-ns{num_swaps}-pt");
    let ciphertext_label = format!("{label}-ns{num_swaps}-ct");
    (
        write_temp_file(&plaintext_label, &plaintexts.join("\n\n")),
        write_temp_file(&ciphertext_label, &ciphertexts.join("\n\n")),
    )
}

fn synthetic_ns3_plaintexts() -> Vec<String> {
    ['A', 'B', 'C', 'D']
        .into_iter()
        .map(|letter| letter.to_string().repeat(96))
        .collect()
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

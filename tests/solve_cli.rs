//! CLI characterization tests for the solve pipeline.

mod common;

use common::{assert_contains, run_noita_eye, run_noita_eye_raw};

/// A per-process, per-test temp candidates dir so the solve auto-log never writes
/// into the tracked `research/gak-threads/candidates/` during `cargo test`. The
/// dir path is the one machine-coupled token in solve stdout, so the golden test
/// redacts it to the stable `<CANDIDATES_DIR>` placeholder (mirroring the
/// `gak_attack_eyes` pattern in `tests/golden_master.rs`).
fn temp_candidates_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("noita-solve-cli-{}-{tag}", std::process::id()));
    let _removed = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn solve_subcommand_reports_labelled_hypothesis_for_caesar_plant() {
    let dir = temp_candidates_dir("caesar-hypothesis");
    let dir_str = dir.to_str().expect("temp dir path is valid UTF-8");
    let stdout = run_noita_eye(&[
        "solve",
        "--seed",
        "123",
        "--null-trials",
        "4",
        "--candidates-dir",
        dir_str,
        "AOLXBPJRIYVDUMVEQBTWZVCLYAOLSHGFKVN",
    ]);

    assert_contains(&stdout, "Solve candidates: HYPOTHESIS, not decode");
    assert_contains(&stdout, "cipher: Caesar");
    assert_contains(&stdout, "beats_null: true");
    assert_contains(
        &stdout,
        "rendered_text: THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG",
    );
    assert_contains(&stdout, "record: ");

    // The record was actually persisted under the temp dir.
    let record_written = std::fs::read_dir(&dir)
        .expect("read temp candidates dir")
        .any(|entry| {
            entry
                .expect("read entry")
                .file_name()
                .to_string_lossy()
                .starts_with("solve-")
        });
    assert!(
        record_written,
        "solve must write a solve-* record under {dir:?}"
    );
    let _cleanup = std::fs::remove_dir_all(&dir);
}

#[test]
fn solve_subcommand_stdout_matches_golden_fixture() {
    // The candidates-dir path is redacted to <CANDIDATES_DIR> before the
    // byte-exact comparison; the seed-stable record filename stays pinned.
    let dir = temp_candidates_dir("golden");
    let dir_str = dir.to_str().expect("temp dir path is valid UTF-8");
    let run = run_noita_eye_raw(&[
        "solve",
        "--seed",
        "123",
        "--null-trials",
        "4",
        "--candidates-dir",
        dir_str,
        "AOLXBPJRIYVDUMVEQBTWZVCLYAOLSHGFKVN",
    ]);

    assert!(run.success, "stderr:\n{}", run.stderr);
    assert_eq!(run.stderr, "");
    let normalized = run.stdout.replace(dir_str, "<CANDIDATES_DIR>");
    assert_eq!(
        normalized,
        include_str!("golden/solve_caesar_s123_nt4.stdout")
    );
    let _cleanup = std::fs::remove_dir_all(&dir);
}

#[test]
fn solve_subcommand_mapping_search_runs_and_logs() {
    // Phase-2 mapping search over the CLI (deterministic: fixed seed, SplitMix64).
    // A smoke check (not byte-exact) keeps it robust to float formatting while
    // proving the searched path runs end-to-end and auto-logs a HYPOTHESIS.
    let dir = temp_candidates_dir("search");
    let dir_str = dir.to_str().expect("temp dir path is valid UTF-8");
    let run = run_noita_eye_raw(&[
        "solve",
        "--mapping-search",
        "--family",
        "identity",
        "--restarts",
        "2",
        "--iterations",
        "600",
        "--seed",
        "123",
        "--null-trials",
        "2",
        "--label",
        "cli-search-smoke",
        "--candidates-dir",
        dir_str,
        "AOLXBPJRIYVDUMVEQBTWZVCLYAOLSHGFKVN",
    ]);

    assert!(run.success, "stderr:\n{}", run.stderr);
    assert_eq!(run.stderr, "");
    assert_contains(&run.stdout, "Solve candidates: HYPOTHESIS, not decode");
    assert_contains(&run.stdout, "record: ");
    assert_contains(&run.stdout, "solve-cli-search-smoke-seed-");

    let record_written = std::fs::read_dir(&dir)
        .expect("read temp candidates dir")
        .any(|entry| {
            entry
                .expect("read entry")
                .file_name()
                .to_string_lossy()
                .starts_with("solve-cli-search-smoke-seed-")
        });
    assert!(
        record_written,
        "mapping search must write a record under {dir:?}"
    );
    let _cleanup = std::fs::remove_dir_all(&dir);
}

//! CLI characterization tests for pairclass-specific guardrails.

mod common;

use common::{assert_contains, run_noita_eye_raw};

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("noita-pairclass-cli-{}-{tag}", std::process::id()));
    let _removed = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn structured_mode_rejects_zero_plants_before_real_scoring() {
    let dir = temp_dir("zero-plants");
    let wordlist = dir.join("words.txt");
    let plant_text = dir.join("plant.txt");
    std::fs::write(&wordlist, "cat 100\ndog 90\nact 3\n").expect("write wordlist");
    std::fs::write(&plant_text, "cat dog cat dog").expect("write plant text");
    let wordlist = wordlist.to_str().expect("wordlist path is UTF-8");
    let plant_text = plant_text.to_str().expect("plant path is UTF-8");

    let run = run_noita_eye_raw(&[
        "pairclass",
        "--wordlist",
        wordlist,
        "--coloring-family",
        "toy",
        "--structured-max-decodes",
        "1",
        "--plant-text-file",
        plant_text,
        "--plants",
        "0",
        "--plant-bar",
        "0",
        "--null-trials",
        "1",
    ]);

    assert!(
        !run.success,
        "stdout:\n{}\nstderr:\n{}",
        run.stdout, run.stderr
    );
    assert_contains(
        &run.stderr,
        "--coloring-family requires --plants >= 1 for non-vacuous controls",
    );
    assert!(
        !run.stdout.contains("Structured oracle candidates"),
        "real scoring should not run:\n{}",
        run.stdout
    );
    let _cleanup = std::fs::remove_dir_all(&dir);
}

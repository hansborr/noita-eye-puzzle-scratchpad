//! CLI characterization tests for the solve pipeline.

mod common;

use common::{assert_contains, run_noita_eye, run_noita_eye_raw};

#[test]
fn solve_subcommand_reports_labelled_hypothesis_for_caesar_plant() {
    let output = run_noita_eye(&[
        "solve",
        "--seed",
        "123",
        "--null-trials",
        "4",
        "AOLXBPJRIYVDUMVEQBTWZVCLYAOLSHGFKVN",
    ]);

    assert_contains(&output, "Solve candidates: HYPOTHESIS, not decode");
    assert_contains(&output, "cipher: Caesar");
    assert_contains(&output, "beats_null: true");
    assert_contains(
        &output,
        "rendered_text: THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG",
    );
}

#[test]
fn solve_subcommand_stdout_matches_golden_fixture() {
    let run = run_noita_eye_raw(&[
        "solve",
        "--seed",
        "123",
        "--null-trials",
        "4",
        "AOLXBPJRIYVDUMVEQBTWZVCLYAOLSHGFKVN",
    ]);

    assert!(run.success, "stderr:\n{}", run.stderr);
    assert_eq!(run.stderr, "");
    assert_eq!(
        run.stdout,
        include_str!("golden/solve_caesar_s123_nt4.stdout")
    );
}

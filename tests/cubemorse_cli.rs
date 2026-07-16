//! CLI smoke tests for the cube/Morse practice-puzzle instrument.

mod common;

use common::{assert_contains, run_noita_eye};

#[test]
fn cubemorse_recovers_both_exact_first_letter_completions() {
    let stdout = run_noita_eye(&[
        "cubemorse",
        "--null-trials",
        "8",
        "--top",
        "3",
        "--seed",
        "0x637562656d6f7273",
    ]);

    assert_contains(&stdout, "SELF-TEST: PASS");
    assert_contains(&stdout, "CUBE IS A GREAT TOY MODEL OF NON-COMMUTATIVITY.");
    assert_contains(&stdout, "FUBE IS A GREAT TOY MODEL OF NON-COMMUTATIVITY.");
    assert_contains(&stdout, "exact RoundTrip 139/139");
    assert_contains(&stdout, "matched null: 0/8 produced valid Morse");
    assert_contains(&stdout, "VERDICT: ExactCandidate");
}

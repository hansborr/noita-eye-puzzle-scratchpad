//! CLI smoke test for the position-polynomial shift instrument.

mod common;

use common::{assert_contains, run_noita_eye};

#[test]
fn polyshift_runs_control_and_matched_null() {
    let stdout = run_noita_eye(&[
        "polyshift",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "--degree",
        "1",
        "--null-trials",
        "2",
        "--seed",
        "0x706f6c7973686966",
    ]);

    assert_contains(&stdout, "polyshift planted control: PASS");
    assert_contains(&stdout, "polyshift exhaustive sweep: degree <= 1");
    assert_contains(&stdout, "round-trip=true");
    assert_contains(&stdout, "best candidate (hypothesis, never a decode)");
}

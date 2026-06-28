//! CLI regression tests for the Thread 2 AGL(1,83)-GAK exclusion.

mod common;

use common::{assert_contains, run_noita_eye};

#[test]
fn agl_gak_subcommand_reports_exclusion_and_honesty_caveats() {
    // The exclusion rests on the exhaustive fixed-point enumeration and the
    // algebraically-zero varying-shared-run count, so a small forward-sim trial
    // count still yields the Excluded verdict.
    let stdout = run_noita_eye(&["agl-gak", "--null-trials", "32", "--seed", "123"]);

    assert_contains(&stdout, "Thread 2 AGL(1,83)-GAK stress test");
    assert_contains(&stdout, "subgroups: C83:C82 and C83:C41");
    // The exhaustive universe denominator is explicitly labelled.
    assert_contains(&stdout, "fixed>=2/universe");
    assert_contains(
        &stdout,
        "AGL(1,83)-GAK is rigorously excluded for both C83:C82 and C83:C41",
    );
    // Honesty: the wiki over-conceded; the varying-shared-run mechanism is the rigorous kill.
    assert_contains(
        &stdout,
        "over-conceded / weaker than needed: the rigorous kill is the varying-shared-run mechanism",
    );
    // Scope caveat.
    assert_contains(
        &stdout,
        "narrows the transitive GAK candidate set toward {A83, S83}",
    );
    assert_contains(
        &stdout,
        "Scope: this excludes the point-stabilizer AGL-GAK family",
    );
}

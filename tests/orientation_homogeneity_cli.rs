//! CLI characterization tests for orientation homogeneity reports.

mod common;

use common::{assert_contains, run_noita_eye};

#[test]
fn homogeneity_subcommand_reports_orientation_frequency_null() {
    let stdout = run_noita_eye(&["homogeneity", "--trials", "8", "--seeds", "2"]);

    assert_contains(&stdout, "cross-message orientation-frequency homogeneity");
    assert_contains(&stdout, "engine-fixed single orientations 0..=4");
    assert_contains(&stdout, "order independence: no honeycomb traversal");
    assert_contains(
        &stdout,
        "total orientations: 3108 (verified eye-count sum 3108)",
    );
    assert_contains(&stdout, "pooled counts: 0:774, 1:739, 2:699, 3:490, 4:406");
    assert_contains(&stdout, "Pearson X^2: 21.917 df 32");
    assert_contains(&stdout, "G-test: 21.999 df 32");
    assert_contains(&stdout, "length-matched repartition null");
    assert_contains(&stdout, "heterogeneous positive control");
    assert_contains(&stdout, "Decode potential: none directly.");
}

//! CLI characterization tests for the honeycomb lattice report.

mod common;

use common::{assert_contains, run_noita_eye};

#[test]
fn honeycomb_subcommand_reports_fixed_order_lattice_null() {
    let stdout = run_noita_eye(&["honeycomb", "--trials", "5", "--seed", "123"]);

    assert_contains(&stdout, "Experiment 20 honeycomb 2D lattice structure");
    assert_contains(
        &stdout,
        "held fixed: accepted honeycomb traversal and trigram digit order",
    );
    assert_contains(&stdout, "vertical same pos: 13/802 = 0.016209");
    assert_contains(&stdout, "same-distance 1D control");
    assert_contains(&stdout, "chi-square: 260.202; df: 150");
    assert_contains(
        &stdout,
        "upper/lower trigrams: 520/516; chi-square: 113.162",
    );
    assert_contains(
        &stdout,
        "avoids order circularity by not searching or reselecting an order",
    );
}

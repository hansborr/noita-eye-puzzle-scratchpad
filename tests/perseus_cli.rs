//! CLI regression tests for the Perseus recurrence null.

use std::process::Command;

#[test]
fn perseus_subcommand_reports_recurrence_null() {
    let output = Command::new(env!("CARGO_BIN_EXE_noita-eye"))
        .args(["perseus", "--trials", "8", "--seed", "123"])
        .output()
        .expect("perseus command should run");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr:\n{stderr}");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Experiment 7C Perseus recurrence null"),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("observed recurrence statistic"),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("lower-tail empirical p"),
        "stdout:\n{stdout}"
    );
    assert!(stdout.contains("decodes nothing"), "stdout:\n{stdout}");
}

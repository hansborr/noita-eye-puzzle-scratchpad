//! CLI regression tests for alphabet-chaining reporting.

use std::process::Command;

#[test]
fn chaining_subcommand_reports_calibrated_fail_signature() {
    let output = Command::new(env!("CARGO_BIN_EXE_noita-eye"))
        .args([
            "chaining",
            "--trials",
            "8",
            "--seed",
            "123",
            "--min-period",
            "2",
            "--max-period",
            "3",
        ])
        .output()
        .expect("chaining command should run");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr:\n{stderr}");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Experiment 7B alphabet-chaining structural control"),
        "stdout:\n{stdout}"
    );
    assert!(stdout.contains("known-fail"), "stdout:\n{stdout}");
    assert!(
        stdout.contains("This is a structural null result only"),
        "stdout:\n{stdout}"
    );
}

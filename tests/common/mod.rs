//! Shared helpers for CLI integration tests.

use std::process::Command;

/// Runs the compiled `noita-eye` binary and returns standard output.
pub fn run_noita_eye(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_noita-eye"))
        .args(args)
        .output()
        .expect("noita-eye command should run");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "args: {args:?}\nstderr:\n{stderr}");

    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Asserts that CLI output contains a stable report label.
pub fn assert_contains(output: &str, needle: &str) {
    assert!(
        output.contains(needle),
        "missing {needle:?}\noutput:\n{output}"
    );
}

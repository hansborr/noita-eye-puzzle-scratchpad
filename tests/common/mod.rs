//! Shared helpers for CLI integration tests.

use std::process::Command;

/// Full captured CLI run, including both streams and exit status.
#[allow(
    dead_code,
    reason = "shared integration-test helper is only used by the golden-master suite"
)]
pub struct CliRun {
    /// Standard output decoded as UTF-8 lossily, matching the existing helpers.
    pub stdout: String,
    /// Standard error decoded as UTF-8 lossily, matching the existing helpers.
    pub stderr: String,
    /// Exact process exit code when the process exits normally.
    pub status_code: Option<i32>,
    /// Whether the command exited successfully.
    pub success: bool,
}

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

/// Runs the compiled `noita-eye` binary and returns standard error from a failed run.
#[allow(
    dead_code,
    reason = "shared integration-test helper is only used by negative CLI test suites"
)]
pub fn run_noita_eye_failure(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_noita-eye"))
        .args(args)
        .output()
        .expect("noita-eye command should run");

    assert!(
        !output.status.success(),
        "args: {args:?}\nstdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );

    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Runs the compiled `noita-eye` binary and returns both streams plus status.
#[allow(
    dead_code,
    reason = "shared integration-test helper is only used by the golden-master suite"
)]
pub fn run_noita_eye_raw(args: &[&str]) -> CliRun {
    let output = Command::new(env!("CARGO_BIN_EXE_noita-eye"))
        .args(args)
        .output()
        .expect("noita-eye command should run");

    CliRun {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        status_code: output.status.code(),
        success: output.status.success(),
    }
}

/// Asserts that CLI output contains a stable report label.
pub fn assert_contains(output: &str, needle: &str) {
    assert!(
        output.contains(needle),
        "missing {needle:?}\noutput:\n{output}"
    );
}

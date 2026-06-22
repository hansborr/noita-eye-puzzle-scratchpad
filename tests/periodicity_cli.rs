//! CLI regression tests for periodicity reporting.

use std::process::Command;

#[test]
fn out_rows_do_not_print_no_exceedance_verdict() {
    let output = Command::new(env!("CARGO_BIN_EXE_noita-eye"))
        .args([
            "periodicity",
            "--trials",
            "1",
            "--seed",
            "0",
            "--max-lag",
            "4",
            "--max-period",
            "1",
        ])
        .output()
        .expect("periodicity command should run");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr:\n{stderr}");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("OUT"), "stdout:\n{stdout}");
    assert!(
        stdout.contains("pooled/per-message period/lag rows exceed"),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("report-wide null envelope is undersampled"),
        "stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("no pooled or per-message period/lag row exceeds"),
        "stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("That rules out a simple fixed-period polyalphabetic cipher"),
        "stdout:\n{stdout}"
    );
}

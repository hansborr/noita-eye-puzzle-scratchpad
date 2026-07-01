//! Handler for the `codecpower` subcommand.

use std::io::{self, Read};
use std::process::ExitCode;

use noita_eye_puzzle::attack::codecpower::{
    self, CodecpowerSelfTest, PowerCfg, PowerReport, PowerRow, SELFTEST_LONG_LENGTH,
    SELFTEST_SHORT_LENGTH,
};
use noita_eye_puzzle::attack::rlcodec::{self, BatteryCfg, PLANT_PLAINTEXT, english_letters};
use noita_eye_puzzle::core::glyph::Alphabet;

use crate::cli::args_codecpower::CodecpowerArgs;

/// Dispatches the `codecpower` subcommand.
pub(crate) fn run_codecpower(args: &CodecpowerArgs) -> ExitCode {
    if args.self_test {
        return run_self_test(args.seed);
    }
    run_scan(args)
}

fn gate_cfg_from(args: &CodecpowerArgs) -> BatteryCfg {
    BatteryCfg {
        null_trials: args.null_trials,
        restarts: args.restarts,
        iters: args.iters,
        top_k: 0,
        census_null_trials: 0,
        seed: args.seed,
    }
}

fn run_scan(args: &CodecpowerArgs) -> ExitCode {
    let base = match base_from_alphabet(args.alphabet.as_deref()) {
        Ok(base) => base,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let (source_letters, source_label) = match resolve_source(args) {
        Ok(resolved) => resolved,
        Err(error) => {
            eprintln!("failed to read English source: {error}");
            return ExitCode::FAILURE;
        }
    };
    if source_letters.is_empty() {
        eprintln!("English source {source_label} contains no letters after filtering");
        return ExitCode::FAILURE;
    }
    let cfg = PowerCfg {
        source_letters,
        lengths: args.lengths.clone(),
        trials: args.trials,
        sep: args.sep,
        base,
        power_threshold: args.power_threshold,
        gate: gate_cfg_from(args),
    };
    let report = match codecpower::measure_power(&cfg) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("codecpower error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print_report(&report, &source_label, &cfg);
    ExitCode::SUCCESS
}

fn base_from_alphabet(alphabet_spec: Option<&str>) -> Result<usize, String> {
    let Some(spec) = alphabet_spec else {
        return Ok(rlcodec::DEFAULT_PLANT_BASE);
    };
    let alphabet = Alphabet::from_chars(spec).map_err(|character| {
        format!("invalid --alphabet: repeated or unrepresentable character {character:?}")
    })?;
    let base = alphabet.len();
    if base < 2 {
        Err(format!(
            "invalid --alphabet: base {base} cannot host a ±1 walk"
        ))
    } else {
        Ok(base)
    }
}

fn resolve_source(args: &CodecpowerArgs) -> Result<(Vec<usize>, String), io::Error> {
    if let Some(path) = &args.input_file {
        let text = std::fs::read_to_string(path)?;
        return Ok((english_letters(&text), path.display().to_string()));
    }
    if args.stdin {
        let mut text = String::new();
        let _bytes_read = io::stdin().read_to_string(&mut text)?;
        return Ok((english_letters(&text), "stdin".to_owned()));
    }
    Ok((
        english_letters(PLANT_PLAINTEXT),
        "built-in planted-control passage".to_owned(),
    ))
}

fn print_report(report: &PowerReport, source_label: &str, cfg: &PowerCfg) {
    println!(
        "codecpower: {} detection-power calibration for practice puzzle one",
        report.codec_name
    );
    println!(
        "  target budget: |M| = {} magnitudes (one operating point)",
        report.one_carrier_budget
    );
    println!(
        "  source: {} ({} letters after filtering)",
        source_label,
        cfg.source_letters.len()
    );
    println!(
        "  gate: null_trials={} restarts={} iters={} seed=0x{:016x}",
        cfg.gate.null_trials, cfg.gate.restarts, cfg.gate.iters, cfg.gate.seed
    );
    println!(
        "  caveat: English power is calibrated against the same quadgram model the gate scores; this characterizes the gate's own notion of English, not held-out generalization."
    );
    println!();
    println!(
        "  {:>5} {:>9} {:>12} {:>9} {:>9} {:>9} {:>11}",
        "L", "mean|M|", "power", "mean_z", "mean_p", "det", "fp_ctrl"
    );
    for row in &report.rows {
        print_row(row);
    }
    println!();
    println!(
        "size control: non-English false-positive rate = {:.3} ({}/{})",
        report.false_positive_rate, report.false_positive_detections, report.false_positive_trials
    );
    print_operating_point(report);
    print_floor(report);
    print_verdict(report);
}

fn print_row(row: &PowerRow) {
    println!(
        "  {:>5} {:>9.1} {:>7.3} ({:>2}/{:<2}) {:>+9.2} {:>9.4} {:>3}/{:<3} {:>7.3}",
        row.length,
        row.mean_carrier,
        row.power,
        row.detections,
        row.trials,
        row.mean_z,
        row.mean_p,
        row.control_detections,
        row.trials,
        row.control_rate
    );
}

fn print_operating_point(report: &PowerReport) {
    if let Some(point) = &report.operating_point {
        println!(
            "operating point: carrier≈{} at L≈{} (mean|M| {:.1}) has power {:.3}",
            report.one_carrier_budget, point.length, point.mean_carrier, point.power
        );
    } else {
        println!(
            "operating point: no swept lengths available for carrier≈{}",
            report.one_carrier_budget
        );
    }
}

fn print_floor(report: &PowerReport) {
    match &report.detectable_floor {
        Some(point) => println!(
            "detectable-length floor: L={} reaches power {:.3} at mean|M| {:.1} (threshold {:.2})",
            point.length, point.power, point.mean_carrier, report.power_threshold
        ),
        None => println!(
            "detectable-length floor: no swept length reaches threshold {:.2}",
            report.power_threshold
        ),
    }
}

fn print_verdict(report: &PowerReport) {
    let Some(point) = &report.operating_point else {
        println!("VERDICT: no plaintext claim; no operating point was measured for this sweep.");
        return;
    };
    let interpretation = if point.power >= report.power_threshold {
        "the actual matched-null gate is powered at this budget for this comma-coded English source"
    } else {
        "the actual matched-null gate is underpowered at this budget; a negative cannot separate wrong codec from too-short genuine message"
    };
    println!(
        "VERDICT: at carrier≈{} (L≈{}) the gate has power {:.3}; {interpretation}. No claim is made about one's plaintext.",
        report.one_carrier_budget, point.length, point.power
    );
}

fn run_self_test(seed: u64) -> ExitCode {
    let report = match codecpower::codecpower_self_test(seed) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("codecpower self-test error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print_self_test(seed, &report);
    if report.passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn print_self_test(seed: u64, report: &CodecpowerSelfTest) {
    println!("codecpower self-test (seed=0x{seed:016x}):");
    println!(
        "  directional power: short L={} power {:.3}, long L={} power {:.3}",
        SELFTEST_SHORT_LENGTH, report.short_power, SELFTEST_LONG_LENGTH, report.long_power
    );
    println!(
        "  size control: false-positive rate {:.3} (must be <= {:.3})",
        report.false_positive_rate,
        2.0 * rlcodec::SURVIVOR_ALPHA
    );
    println!(
        "  SELF-TEST: {}",
        if report.passed() { "PASS" } else { "FAIL" }
    );
}

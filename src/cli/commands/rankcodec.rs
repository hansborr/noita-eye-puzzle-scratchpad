//! Handler for the `rankcodec` subcommand.

use std::io::{self, Read};
use std::process::ExitCode;

use noita_eye_puzzle::attack::rankcodec::{
    self, CribLock, FeasibilitySummary, RankCfg, RankOrderRow, RankReport, RankSelfTest,
};
use noita_eye_puzzle::attack::rlcodec::{self, BatteryCfg, PLANT_PLAINTEXT, english_letters};

use crate::cli::args_rankcodec::RankcodecArgs;
use crate::cli::shared::{parse_cli_sequence, resolve_input_text};

/// Walk base used when no `--alphabet` is supplied.
const DEFAULT_BASE: usize = 5;

/// Dispatches the `rankcodec` subcommand.
pub(crate) fn run_rankcodec(args: &RankcodecArgs) -> ExitCode {
    if args.self_test {
        return run_self_test(args.seed);
    }
    run_scan(args)
}

fn gate_cfg_from(args: &RankcodecArgs) -> BatteryCfg {
    BatteryCfg {
        null_trials: args.null_trials,
        restarts: args.restarts,
        iters: args.iters,
        top_k: args.top_k,
        census_null_trials: rlcodec::DEFAULT_CENSUS_NULL_TRIALS,
        seed: args.seed,
    }
}

fn run_scan(args: &RankcodecArgs) -> ExitCode {
    let (source_letters, source_label) = match resolve_source(args) {
        Ok(resolved) => resolved,
        Err(error) => {
            eprintln!("failed to read predictor source: {error}");
            return ExitCode::FAILURE;
        }
    };
    if source_letters.is_empty() {
        eprintln!("predictor source {source_label} contains no letters after filtering");
        return ExitCode::FAILURE;
    }

    let cfg = RankCfg {
        source_letters,
        orders: args.orders.clone(),
        max_magnitude: args.max_magnitude,
        gate: gate_cfg_from(args),
    };

    let report = match resolve_target_and_run(args, &cfg) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("rankcodec error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print_report(&report, &source_label, &cfg);
    ExitCode::SUCCESS
}

fn resolve_source(args: &RankcodecArgs) -> Result<(Vec<usize>, String), io::Error> {
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

fn resolve_target_and_run(args: &RankcodecArgs, cfg: &RankCfg) -> Result<RankReport, String> {
    if args.target_file.is_none() && !args.target_stdin {
        return rankcodec::analyze_embedded_one(cfg).map_err(|error| error.to_string());
    }

    let text = resolve_input_text(None, args.target_file.as_ref(), args.target_stdin)
        .map_err(|error| format!("failed to read target input: {error}"))?;
    let parsed = parse_cli_sequence(&text, args.alphabet.as_deref(), false)
        .map_err(|error| error.to_string())?;
    let base = args
        .alphabet
        .as_deref()
        .map_or(DEFAULT_BASE, |spec| spec.chars().count());
    rankcodec::analyze_rank_codec(&parsed.glyphs, base, cfg).map_err(|error| error.to_string())
}

fn print_report(report: &RankReport, source_label: &str, cfg: &RankCfg) {
    print_header(report, source_label, cfg);
    print_cribs(report);
    print_rows(report);
    print_verdict(report);
}

fn print_header(report: &RankReport, source_label: &str, cfg: &RankCfg) {
    let carrier = &report.carrier;
    let distribution = carrier
        .distribution
        .iter()
        .map(|(value, count)| format!("{value}:{count}"))
        .collect::<Vec<_>>()
        .join(", ");
    println!("rankcodec: bounded-order predictive-rank codec for practice puzzle one");
    println!(
        "  target carrier: {} digits over base {}, {} bits, |M| = {}, distribution {{{}}}",
        carrier.n_digits, carrier.base, carrier.n_bits, carrier.n_magnitudes, distribution
    );
    println!(
        "  predictor source: {} ({} letters after filtering)",
        source_label, report.source_len
    );
    println!(
        "  orders: {:?}; predictor order is strictly below quadgram scorer order {}",
        cfg.orders,
        rankcodec::QUADGRAM_SCORER_ORDER
    );
    println!(
        "  matched null: order-1 Markov resample of M with crib windows pinned, then the identical order-k decode"
    );
    println!("  gate caveat: TERTIARY only and underpowered at 135 magnitudes (see codecpower)");
    println!(
        "  gate budget: null_trials={} restarts={} iters={} seed=0x{:016x}",
        cfg.gate.null_trials, cfg.gate.restarts, cfg.gate.iters, cfg.gate.seed
    );
}

fn print_cribs(report: &RankReport) {
    println!();
    println!("Cribs reused from cribfit (census-derived, not recomputed locally):");
    println!(
        "  longest repeat {} vs null ceiling {} (p {:.4}); significant={}",
        report.census.observed_max,
        report.census.null_ceiling,
        report.census.p_value,
        report.census.significant
    );
    for anchor in &report.geometry.anchors {
        println!(
            "  len {:>2}  M[{}..{}] == M[{}..{}]  run-gap {}  bit-gap {}",
            anchor.length,
            anchor.first,
            anchor.first + anchor.length,
            anchor.second,
            anchor.second + anchor.length,
            anchor.run_gap,
            anchor.bit_gap
        );
    }
}

fn print_rows(report: &RankReport) {
    println!();
    println!("Per-order results (feasibility + crib are PRIMARY; gate is TERTIARY):");
    for row in &report.rows {
        print_row(row, report.max_magnitude);
    }
}

fn print_row(row: &RankOrderRow, max_magnitude: usize) {
    println!("  k = {}", row.order);
    print_feasibility(&row.feasibility, max_magnitude);
    println!(
        "    crib: {}  locked tails {}",
        row.crib.status.label(),
        lock_summary(&row.crib.locks)
    );
    if row.gate.evaluated {
        println!(
            "    gate (TERTIARY, underpowered at 135 magnitudes; see codecpower): z {:+.2}, p {:.4}, survivor {}",
            row.gate.z,
            row.gate.p,
            yes_no(row.gate.survivor)
        );
    } else {
        println!(
            "    gate (TERTIARY, underpowered at 135 magnitudes; see codecpower): n/a {}",
            row.gate.text
        );
    }
}

fn print_feasibility(feasibility: &FeasibilitySummary, max_magnitude: usize) {
    println!(
        "    feasibility: {:.1}% ({}/{}) of English-source ranks <= {}  all-representable {}",
        100.0 * feasibility.fraction_within_max,
        feasibility.within_max,
        feasibility.total,
        max_magnitude,
        yes_no(feasibility.all_within_max)
    );
    println!(
        "    expected rank-hit distribution on English: {}",
        rank_distribution(feasibility)
    );
}

fn rank_distribution(feasibility: &FeasibilitySummary) -> String {
    let mut parts = feasibility
        .within_distribution
        .iter()
        .map(|(rank, count)| format!("{rank}:{count}"))
        .collect::<Vec<_>>();
    parts.push(format!(
        ">{}:{}",
        feasibility.within_distribution.len(),
        feasibility.overflow
    ));
    parts.join(", ")
}

fn lock_summary(locks: &[CribLock]) -> String {
    if locks.is_empty() {
        return "(none)".to_owned();
    }
    locks
        .iter()
        .map(|lock| {
            format!(
                "len{}@{}/{} {}/{}",
                lock.length, lock.first, lock.second, lock.locked_tail, lock.required_tail
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn print_verdict(report: &RankReport) {
    println!();
    let admissible = report.crib_admissible_orders();
    let best_feasibility = report
        .rows
        .iter()
        .map(|row| row.feasibility.fraction_within_max)
        .fold(0.0_f64, f64::max);
    println!(
        "English representable in ranks <= {} under any swept bounded-order predictor: {} (best coverage {:.1}%).",
        report.max_magnitude,
        yes_no(report.english_representable_in_range()),
        100.0 * best_feasibility
    );
    if admissible.is_empty() {
        println!(
            "VERDICT: no swept order is crib-admissible; rankcodec is excluded for orders {:?}. The statistical gate remains underpowered at 135 magnitudes and makes no plaintext claim.",
            report.rows.iter().map(|row| row.order).collect::<Vec<_>>()
        );
    } else {
        println!(
            "VERDICT: crib-admissible at order(s) {admissible:?}; statistical gate underpowered at 135 magnitudes — candidate only, no decode claim."
        );
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn run_self_test(seed: u64) -> ExitCode {
    let report = match rankcodec::rankcodec_self_test(seed) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("rankcodec self-test error: {error}");
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

fn print_self_test(seed: u64, report: &RankSelfTest) {
    println!("rankcodec self-test (seed=0x{seed:016x}):");
    println!("  round-trip: {}", pass_fail(report.round_trip));
    println!(
        "  planted positive: recovered {}, crib-lock {}, gate {}",
        pass_fail(report.positive.recovered),
        pass_fail(report.positive.crib_consistent),
        pass_fail(report.positive.survivor)
    );
    println!(
        "  crib discrimination: {}",
        pass_fail(report.inconsistent_excluded)
    );
    println!(
        "  SELF-TEST: {}",
        if report.passed() { "PASS" } else { "FAIL" }
    );
}

fn pass_fail(value: bool) -> &'static str {
    if value { "PASS" } else { "FAIL" }
}

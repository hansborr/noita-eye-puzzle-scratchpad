//! Handler for the `mdlcodec` subcommand.

use std::io::{self, Read};
use std::process::ExitCode;

use noita_eye_puzzle::attack::mdlcodec::{self, MdlCellReport, MdlCfg, MdlReport, MdlSelfTest};
use noita_eye_puzzle::attack::quadgram::{DEFAULT_SMOOTHING, QuadgramModel};
use noita_eye_puzzle::attack::rlcodec::one_practice_digits;

use crate::cli::args_mdlcodec::MdlcodecArgs;
use crate::cli::shared::{parse_cli_sequence, resolve_input_text};

const DEFAULT_BASE: usize = 5;

/// Dispatches the `mdlcodec` subcommand.
pub(crate) fn run_mdlcodec(args: &MdlcodecArgs) -> ExitCode {
    if args.self_test {
        return run_self_test(args.seed);
    }
    run_scan(args)
}

fn cfg_from(args: &MdlcodecArgs) -> Result<MdlCfg, String> {
    Ok(MdlCfg {
        ring_sizes: parse_ring_sizes(&args.ring_sizes)?,
        coeff_max: args.coeff_max,
        epsilon_bits: args.epsilon_bits,
        top: args.top,
        null_trials: args.null_trials,
        restarts: args.restarts,
        iters: args.iters,
        top_k: args.top_k,
        census_null_trials: args.census_null_trials,
        seed: args.seed,
        min_effective_alphabet: args.min_effective_alphabet,
    })
}

fn run_scan(args: &MdlcodecArgs) -> ExitCode {
    let cfg = match cfg_from(args) {
        Ok(cfg) => cfg,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let (model, source_label) = match resolve_model(args) {
        Ok(resolved) => resolved,
        Err(error) => {
            eprintln!("failed to build English model: {error}");
            return ExitCode::FAILURE;
        }
    };
    let (digits, base, target_label) = match resolve_target(args) {
        Ok(resolved) => resolved,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let report = match mdlcodec::analyze_mdl_with_model(&digits, base, &cfg, &model) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("mdlcodec error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print_report(&report, &cfg, &source_label, &target_label);
    ExitCode::SUCCESS
}

fn resolve_model(args: &MdlcodecArgs) -> Result<(QuadgramModel, String), String> {
    if let Some(path) = &args.input_file {
        let text = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
        let model = QuadgramModel::from_sample(&text, DEFAULT_SMOOTHING)
            .map_err(|error| error.to_string())?;
        return Ok((model, path.display().to_string()));
    }
    if args.stdin {
        let mut text = String::new();
        let _bytes_read = io::stdin()
            .read_to_string(&mut text)
            .map_err(|error| error.to_string())?;
        let model = QuadgramModel::from_sample(&text, DEFAULT_SMOOTHING)
            .map_err(|error| error.to_string())?;
        return Ok((model, "stdin".to_owned()));
    }
    let model = QuadgramModel::english().map_err(|error| error.to_string())?;
    Ok((model, "built-in English quadgram corpus".to_owned()))
}

fn resolve_target(
    args: &MdlcodecArgs,
) -> Result<(Vec<noita_eye_puzzle::core::glyph::Glyph>, usize, String), String> {
    if args.target_file.is_none() && !args.target_stdin {
        let digits = one_practice_digits().map_err(|error| error.to_string())?;
        return Ok((
            digits,
            DEFAULT_BASE,
            "embedded practice puzzle one".to_owned(),
        ));
    }
    let text = resolve_input_text(None, args.target_file.as_ref(), args.target_stdin)
        .map_err(|error| format!("failed to read target input: {error}"))?;
    let parsed = parse_cli_sequence(&text, args.alphabet.as_deref(), false)
        .map_err(|error| error.to_string())?;
    let base = args
        .alphabet
        .as_deref()
        .map_or(DEFAULT_BASE, |spec| spec.chars().count());
    let label = args.target_file.as_ref().map_or_else(
        || "target stdin".to_owned(),
        |path| path.display().to_string(),
    );
    Ok((parsed.glyphs, base, label))
}

fn print_report(report: &MdlReport, cfg: &MdlCfg, source_label: &str, target_label: &str) {
    print_header(report, cfg, source_label, target_label);
    print_cribs(report);
    print_coverage(report);
    print_top_table(report);
    print_winner_and_verdict(report, cfg);
}

fn print_header(report: &MdlReport, cfg: &MdlCfg, source_label: &str, target_label: &str) {
    let carrier = &report.carrier;
    let distribution = carrier
        .distribution
        .iter()
        .map(|(value, count)| format!("{value}:{count}"))
        .collect::<Vec<_>>()
        .join(", ");
    println!("mdlcodec: crib-synchronous MDL-like affine running-key search");
    println!(
        "  caveat: at ~33 bytes this problem is likely under-determined; output is a CANDIDATE, never a decode."
    );
    println!(
        "  target: {target_label}; {} digits over base {}, {} bits, |M| = {}, sum {}, distribution {{{}}}",
        carrier.n_digits,
        carrier.base,
        carrier.n_bits,
        carrier.n_magnitudes,
        carrier.sum,
        distribution
    );
    println!("  English model: {source_label}");
    println!(
        "  family: idx[i]=(a*S_i+b*i) mod R, o_0 fixed at 0; emitted-symbol-history codecs are OUT OF SCOPE for this instrument."
    );
    println!(
        "  cost: L_text=-best_sum/ln(2); L_codec uses effective alphabet k plus log2(canonical searched grid)."
    );
    println!(
        "  budget: rings={:?} coeff_max={} null_trials={} restarts={} iters={} seed=0x{:016x}",
        cfg.ring_sizes, cfg.coeff_max, cfg.null_trials, cfg.restarts, cfg.iters, cfg.seed
    );
}

fn print_cribs(report: &MdlReport) {
    println!();
    println!(
        "Cribs: longest repeat {} vs null ceiling {} (p {:.4}); significant={}",
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

fn print_coverage(report: &MdlReport) {
    let coverage = report.coverage;
    println!();
    println!(
        "Cell coverage: searched={} eligible={} feasible={} deduped={}",
        coverage.searched, coverage.eligible, coverage.feasible, coverage.deduped
    );
    println!(
        "Post-selection null best-MDL: evaluated {}/{} draws, mean {:.2}, p05 {:.2}, range {:.2}..{:.2}; survivor rule is real MDL <= null p05.",
        report.null.trials_evaluated,
        report.null.trials_requested,
        report.null.mean_mdl_bits,
        report.null.p05_mdl_bits,
        report.null.min_mdl_bits,
        report.null.max_mdl_bits
    );
}

fn print_top_table(report: &MdlReport) {
    println!();
    println!("Top MDL-like affine cells (Delta = real MDL - mean null-best MDL; lower is better):");
    println!(
        "  {:>3} {:>3} {:>3} {:>3} {:>3} {:>9} {:>9} {:>9} {:>9} {:>7} {:>8}",
        "#", "R", "a", "b", "k", "L_codec", "L_text", "MDL", "Delta", "z", "survivor"
    );
    for (index, row) in report.top_cells.iter().enumerate() {
        print_row(index + 1, row);
    }
}

fn print_row(index: usize, row: &MdlCellReport) {
    println!(
        "  {:>3} {:>3} {:>3} {:>3} {:>3} {:>9.2} {:>9.2} {:>9.2} {:>9.2} {:>+7.2} {:>8}",
        index,
        row.cell.ring,
        row.cell.a,
        row.cell.b,
        row.effective_alphabet,
        row.l_codec_bits,
        row.l_text_bits,
        row.mdl_bits,
        row.delta_mdl_bits,
        row.z,
        yes_no(row.survivor)
    );
}

fn print_winner_and_verdict(report: &MdlReport, cfg: &MdlCfg) {
    let winner = &report.winner;
    println!();
    println!(
        "Global winner: R={} a={} b={} k={}  L_codec={:.2} L_text={:.2} MDL={:.2} Delta={:.2} z={:+.2} survivor={}",
        winner.cell.ring,
        winner.cell.a,
        winner.cell.b,
        winner.effective_alphabet,
        winner.l_codec_bits,
        winner.l_text_bits,
        winner.mdl_bits,
        winner.delta_mdl_bits,
        winner.z,
        yes_no(winner.survivor)
    );
    println!(
        "Under-determination: {} cell(s) within {:.2} bits of the winner; spread {:.2} bits.",
        report.underdetermination_count, cfg.epsilon_bits, report.underdetermination_spread_bits
    );
    println!("{}", report.verdict.sentence());
    println!();
    println!(
        "CANDIDATE (MDL-selected affine codec R={},a={},b={}), NOT a recovered plaintext:",
        winner.cell.ring, winner.cell.a, winner.cell.b
    );
    println!("{}", winner.candidate);
}

fn run_self_test(seed: u64) -> ExitCode {
    let report = match mdlcodec::mdlcodec_self_test(seed) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("mdlcodec self-test error: {error}");
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

fn print_self_test(seed: u64, report: &MdlSelfTest) {
    println!("mdlcodec self-test (seed=0x{seed:016x}):");
    println!(
        "  planted positive: crib {}, recovered {}, survivor {}, near-winner {}",
        pass_fail(report.planted_cell_crib_consistent),
        pass_fail(report.planted_recovered),
        pass_fail(report.planted_survivor),
        pass_fail(report.planted_near_winner)
    );
    println!(
        "    planted null margin: Delta={:.2} bits, null p05={:.2}",
        report.planted_delta_mdl_bits, report.planted_null_p05_bits
    );
    println!(
        "  null control: non-survivor {}, under-determined {} (near ties {})",
        pass_fail(report.null_non_survivor),
        pass_fail(report.null_underdetermined),
        report.null_underdetermination_count
    );
    println!(
        "  cribfit cross-check (a=1,b=0 includes R=21 and matches admissible set): {}",
        pass_fail(report.cribfit_r21_crosscheck)
    );
    println!(
        "  SELF-TEST: {}",
        if report.passed() { "PASS" } else { "FAIL" }
    );
}

fn parse_ring_sizes(raw: &str) -> Result<Vec<usize>, String> {
    let mut values = Vec::new();
    for part in raw
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        if let Some((start, end)) = part.split_once("..=") {
            push_range(start, end, &mut values)?;
        } else if let Some((start, end)) = part.split_once("..") {
            push_range(start, end, &mut values)?;
        } else {
            values.push(
                part.parse::<usize>()
                    .map_err(|error| format!("invalid --ring-sizes value {part:?}: {error}"))?,
            );
        }
    }
    values.sort_unstable();
    values.dedup();
    if values.is_empty() {
        Err("invalid --ring-sizes: no rings supplied".to_owned())
    } else {
        Ok(values)
    }
}

fn push_range(start: &str, end: &str, values: &mut Vec<usize>) -> Result<(), String> {
    let start = start
        .trim()
        .parse::<usize>()
        .map_err(|error| format!("invalid --ring-sizes range start: {error}"))?;
    let end = end
        .trim()
        .parse::<usize>()
        .map_err(|error| format!("invalid --ring-sizes range end: {error}"))?;
    if start > end {
        return Err(format!(
            "invalid --ring-sizes range {start}..={end}: start exceeds end"
        ));
    }
    values.extend(start..=end);
    Ok(())
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn pass_fail(value: bool) -> &'static str {
    if value { "PASS" } else { "FAIL" }
}

//! Handler for the `maskdecode` subcommand.

use std::process::ExitCode;

use noita_eye_puzzle::attack::maskdecode::{
    self, CandidateCell, MaskAnalysis, MaskCfg, MaskReport, MaskSelfTest, MaskVerdict,
    NotAWalkDetail,
};

use crate::cli::args_maskdecode::MaskdecodeArgs;
use crate::cli::shared::{parse_cli_sequence, resolve_input_text};

/// Walk base used when no `--alphabet` is supplied.
const DEFAULT_BASE: usize = 5;

/// Dispatches the `maskdecode` subcommand.
pub(crate) fn run_maskdecode(args: &MaskdecodeArgs) -> ExitCode {
    if args.self_test {
        return run_self_test(args.seed);
    }
    let cfg = MaskCfg {
        widths: args.widths.clone(),
        top_cells: args.top,
    };
    let (analysis, label) = match resolve_and_run(args, &cfg) {
        Ok(resolved) => resolved,
        Err(error) => {
            eprintln!("maskdecode error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print_analysis(&analysis, &label, &cfg);
    ExitCode::SUCCESS
}

fn resolve_and_run(args: &MaskdecodeArgs, cfg: &MaskCfg) -> Result<(MaskAnalysis, String), String> {
    if args.input_file.is_none() && !args.stdin {
        let analysis = maskdecode::analyze_embedded_one(cfg).map_err(|error| error.to_string())?;
        return Ok((analysis, "embedded practice puzzle one".to_owned()));
    }
    let text = resolve_input_text(None, args.input_file.as_ref(), args.stdin)
        .map_err(|error| format!("failed to read input: {error}"))?;
    let parsed = parse_cli_sequence(&text, args.alphabet.as_deref(), false)
        .map_err(|error| error.to_string())?;
    let base = args
        .alphabet
        .as_deref()
        .map_or(DEFAULT_BASE, |spec| spec.chars().count());
    let label = args
        .input_file
        .as_ref()
        .map_or_else(|| "stdin".to_owned(), |path| path.display().to_string());
    let analysis = maskdecode::analyze_mask_decode(&parsed.glyphs, base, cfg)
        .map_err(|error| error.to_string())?;
    Ok((analysis, label))
}

fn print_analysis(analysis: &MaskAnalysis, label: &str, cfg: &MaskCfg) {
    println!("maskdecode: masked C_n-walk ASCII readout (direction bit 1 = the +1 step)");
    println!("  input: {label}");
    match analysis {
        MaskAnalysis::NotAWalk(detail) => print_not_a_walk(detail),
        MaskAnalysis::Walk(report) => print_report(report, cfg),
    }
}

fn print_not_a_walk(detail: &NotAWalkDetail) {
    println!(
        "  walk gate: step {} ({} -> {}) has difference {} mod {}, not ±1",
        detail.position, detail.from, detail.to, detail.diff, detail.base
    );
    println!();
    println!(
        "VERDICT: NotAWalk — the input is not a ±1 walk on C_{}; the masked readout does not apply.",
        detail.base
    );
}

fn print_report(report: &MaskReport, cfg: &MaskCfg) {
    println!(
        "  carrier: {} digits over base {} -> {} direction bits, start digit {}",
        report.n_digits, report.base, report.n_bits, report.start_digit
    );
    println!(
        "  sweep: {} cells = mask {{static, alternating}} x widths {:?} x offsets 0..w x order {{MSB, LSB}} x polarity {{plain, complemented}} x direction {{forward, reversed}}",
        report.cells_swept, cfg.widths
    );
    println!(
        "  note: the alternating mask with phase b0=1 equals the complemented polarity of b0=0, so phase is not a separate axis"
    );
    println!();
    println!("Top cells by (letter fraction, then printable fraction):");
    for (rank, cell) in report.top.iter().enumerate() {
        println!(
            "  {:>2}. {:<48} letters {:>3}/{:<3} printable {:>3}/{:<3} \"{}\"",
            rank + 1,
            cell.params.label(),
            cell.n_letters,
            cell.n_chunks,
            cell.n_printable,
            cell.n_chunks,
            cell.rendered
        );
    }
    println!();
    if report.candidates.is_empty() {
        println!("Candidates (letter fraction 1.0 over all full chunks): none");
    } else {
        println!(
            "Candidates (letter fraction 1.0 over all full chunks): {}",
            report.candidates.len()
        );
        for candidate in &report.candidates {
            print_candidate(candidate);
        }
    }
    println!();
    print_verdict(report);
}

fn print_candidate(candidate: &CandidateCell) {
    println!("  {}", candidate.readout.params.label());
    if candidate.head_missing_bits == 0 {
        println!("    head: chunk-aligned (no partial chunk)");
    } else {
        println!(
            "    head: {} observed bits + {} missing -> letter/space completions {:?}",
            candidate.readout.head_bits, candidate.head_missing_bits, candidate.head_options
        );
    }
    if candidate.tail_missing_bits == 0 {
        println!("    tail: chunk-aligned (no partial chunk)");
    } else {
        println!(
            "    tail: {} observed bits + {} missing -> letter/space completions {:?}",
            candidate.readout.tail_bits, candidate.tail_missing_bits, candidate.tail_options
        );
    }
    if candidate.completions.is_empty() {
        println!("    no letter/space completion exists; the candidate cannot be round-tripped");
    }
    for completion in &candidate.completions {
        println!(
            "    completion \"{}\"  RoundTrip {}/{}{}",
            completion.text,
            completion.matched,
            completion.total,
            if completion.exact() { "  EXACT" } else { "" }
        );
    }
}

fn print_verdict(report: &MaskReport) {
    match report.verdict {
        MaskVerdict::VerifiedDecode => {
            if let Some((candidate, completion)) = report.verified() {
                println!(
                    "VERDICT: VerifiedDecode — \"{}\" (RoundTrip {}/{}; {})",
                    completion.text,
                    completion.matched,
                    completion.total,
                    candidate.readout.params.label()
                );
            }
        }
        MaskVerdict::Candidate => println!(
            "VERDICT: Candidate — a full-letter readout exists but no completion round-trips exactly; not a decode."
        ),
        MaskVerdict::Negative => println!(
            "VERDICT: Negative — no cell reached letter fraction 1.0; no masked ASCII readout at these widths."
        ),
    }
}

fn run_self_test(seed: u64) -> ExitCode {
    let report = match maskdecode::maskdecode_self_test(seed) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("maskdecode self-test error: {error}");
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

fn print_self_test(seed: u64, report: &MaskSelfTest) {
    println!("maskdecode self-test (seed=0x{seed:016x}):");
    println!(
        "  planted positive (alternating mask): {}",
        pass_fail(report.planted_alternating.passed())
    );
    println!(
        "  planted positive (static mask): {}",
        pass_fail(report.planted_static.passed())
    );
    println!(
        "  matched null (SplitMix64 random ±1 walk): {}",
        pass_fail(report.null_negative)
    );
    println!(
        "  not-a-walk control: {}",
        pass_fail(report.not_a_walk_detected)
    );
    let one = &report.one_regression;
    println!(
        "  embedded one regression: {} (text {:?}, RoundTrip {}/{}, completions {})",
        pass_fail(one.passed()),
        one.text.as_deref().unwrap_or("<none>"),
        one.matched,
        one.total,
        one.n_completions
    );
    println!(
        "  SELF-TEST: {}",
        if report.passed() { "PASS" } else { "FAIL" }
    );
}

fn pass_fail(value: bool) -> &'static str {
    if value { "PASS" } else { "FAIL" }
}

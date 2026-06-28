//! The `ragbaby` subcommand: keyed-alphabet crack of a practice letter-puzzle,
//! plus the planted-recovery positive control (`--control`).

use std::process::ExitCode;

use noita_eye_puzzle::attack::{keystream, quadgram, ragbaby};

use crate::cli::args_attack::RagbabyArgs;
use crate::cli::shared::{display_prefix, resolve_input_text};

fn ragbaby_search_config(args: &RagbabyArgs) -> ragbaby::RagbabySearchConfig {
    ragbaby::RagbabySearchConfig {
        restarts: args.restarts,
        iterations: args.iterations,
        basin_hops: args.basin_hops,
        t0: ragbaby::DEFAULT_T0,
        t1: ragbaby::DEFAULT_T1,
        seed: args.seed,
        null_trials: args.null_trials,
        matched_null_trials: args.matched_null_trials,
    }
}

fn ragbaby_numberings(args: &RagbabyArgs) -> Vec<ragbaby::Numbering> {
    if args.numbering.is_empty() {
        ragbaby::Numbering::all().to_vec()
    } else {
        args.numbering
            .iter()
            .map(|numbering| (*numbering).into())
            .collect()
    }
}

fn ragbaby_input_text(args: &RagbabyArgs) -> Result<String, ExitCode> {
    if let Some(puzzle) = args.puzzle {
        return Ok(keystream::practice_puzzle_text(puzzle.into()).to_owned());
    }
    match resolve_input_text(None, args.input_file.as_ref(), args.stdin) {
        Ok(text) => Ok(text),
        Err(error) => {
            eprintln!("failed to read input: {error}");
            Err(ExitCode::FAILURE)
        }
    }
}

pub(crate) fn run_ragbaby(args: &RagbabyArgs) -> ExitCode {
    // The keyed-alphabet search assumes the modulus equals the kept-alphabet size,
    // which only holds for the three supported bases; reject anything else up front
    // rather than risk an out-of-bounds move on a mismatched key length.
    for &base in &args.bases {
        if !matches!(base, 24..=26) {
            eprintln!("invalid --bases value {base}: only 24, 25, 26 are supported");
            return ExitCode::FAILURE;
        }
    }
    let model = match quadgram::QuadgramModel::english() {
        Ok(model) => model,
        Err(error) => {
            eprintln!("quadgram model error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let cfg = ragbaby_search_config(args);
    if args.control {
        return run_ragbaby_control(args, &cfg, &model);
    }
    let text = match ragbaby_input_text(args) {
        Ok(text) => text,
        Err(code) => return code,
    };
    let numberings = ragbaby_numberings(args);
    let signs = args.sign.signs();
    let mut candidates: Vec<ragbaby::RagbabyCandidate> = Vec::new();
    for &base in &args.bases {
        for &numbering in &numberings {
            for &sign in &signs {
                let (cipher, nums) = ragbaby::prepare(&text, numbering, base);
                if cipher.is_empty() {
                    continue;
                }
                let problem = ragbaby::RagbabyProblem {
                    cipher: &cipher,
                    nums: &nums,
                    base,
                    sign,
                    numbering,
                };
                candidates.push(ragbaby::crack_with_model(&problem, &cfg, &model));
            }
        }
    }
    if candidates.is_empty() {
        eprintln!("no cipher letters in input");
        return ExitCode::FAILURE;
    }
    print_ragbaby_table(&candidates);
    print_ragbaby_best(&candidates);

    let label = args
        .label
        .clone()
        .or_else(|| args.puzzle.map(|puzzle| puzzle.label().to_owned()))
        .unwrap_or_else(|| "input".to_owned());
    emit_ragbaby_verdict(&candidates, &args.candidates_dir, &label, args.seed)
}

fn run_ragbaby_control(
    args: &RagbabyArgs,
    cfg: &ragbaby::RagbabySearchConfig,
    model: &quadgram::QuadgramModel,
) -> ExitCode {
    let numberings = ragbaby_numberings(args);
    let numbering = numberings
        .first()
        .copied()
        .unwrap_or(ragbaby::Numbering::Std);
    let signs = args.sign.signs();
    let sign = signs.first().copied().unwrap_or(ragbaby::Sign::Plus);
    let control = ragbaby::ControlConfig {
        lengths: args.control_lengths.clone(),
        bases: args.bases.clone(),
        trials: args.control_trials,
        numbering,
        sign,
        search: *cfg,
    };
    let points = ragbaby::control_sweep(quadgram::ENGLISH_CORPUS_LARGE, &control, model);
    println!(
        "control numbering={} sign={} restarts={} iters={} basin={} t0={} t1={}",
        numbering.name(),
        sign.label(),
        cfg.restarts,
        cfg.iterations,
        cfg.basin_hops,
        cfg.t0,
        cfg.t1,
    );
    println!(
        "{:>5} {:>4} {:>6} {:>9} {:>8} {:>8}",
        "len", "base", "trials", "recov>=.9", "med_acc", "mean_acc"
    );
    for point in &points {
        println!(
            "{:>5} {:>4} {:>6} {:>9.2} {:>8.3} {:>8.3}",
            point.length,
            point.base,
            point.trials,
            point.recovery_rate,
            point.median_acc,
            point.mean_acc,
        );
    }
    ExitCode::SUCCESS
}

fn print_ragbaby_table(candidates: &[ragbaby::RagbabyCandidate]) {
    println!("Ragbaby candidates: hypothesis, not decode");
    println!(
        "survives requires the matched-null (search-overfitting) gate and round-trip and held-out"
    );
    println!(
        "{:>4} {:>11} {:>5} {:>10} {:>12} {:>10} {:>10} {:>8}",
        "base", "numbering", "sign", "best", "matched_mean", "matched_z", "round_trip", "survives"
    );
    for candidate in candidates {
        println!(
            "{:>4} {:>11} {:>5} {:>10.4} {:>12.4} {:>10.2} {:>10} {:>8}",
            candidate.base,
            candidate.numbering.name(),
            candidate.sign.label(),
            candidate.best_score,
            candidate.matched_mean,
            candidate.matched_z,
            candidate.round_trip_ok,
            candidate.survives,
        );
    }
}

fn print_ragbaby_best(candidates: &[ragbaby::RagbabyCandidate]) {
    let best = candidates
        .iter()
        .filter(|candidate| candidate.survives)
        .max_by(|left, right| left.matched_z.total_cmp(&right.matched_z))
        .or_else(|| {
            candidates
                .iter()
                .max_by(|left, right| left.best_score.total_cmp(&right.best_score))
        });
    let Some(best) = best else {
        return;
    };
    println!(
        "best ({}):",
        if best.survives {
            "surviving, highest matched_z"
        } else {
            "non-surviving, highest mean score"
        }
    );
    println!(
        "  base: {}  numbering: {}  sign: {}",
        best.base,
        best.numbering.name(),
        best.sign.label()
    );
    println!(
        "  best_score (mean): {:.4}  matched_z: {:.4}  matched_mean: {:.4}",
        best.best_score, best.matched_z, best.matched_mean
    );
    println!(
        "  decrypt: {}",
        display_prefix(&best.render_plaintext(), 120)
    );
}

fn emit_ragbaby_verdict(
    candidates: &[ragbaby::RagbabyCandidate],
    candidates_dir: &std::path::Path,
    label: &str,
    seed: u64,
) -> ExitCode {
    let survivors: Vec<&ragbaby::RagbabyCandidate> = candidates
        .iter()
        .filter(|candidate| candidate.survives)
        .collect();
    if survivors.is_empty() {
        println!(
            "honest-negative: no (base, numbering, sign) keyed-alphabet candidate cleared the round-trip + matched-null (z>={:.0} and margin>={:.0} nat) + held-out gates. A clean honest negative is a success, not an error.",
            ragbaby::Z_THRESHOLD,
            ragbaby::MIN_NAT_MARGIN,
        );
        return ExitCode::SUCCESS;
    }
    for candidate in survivors {
        println!(
            "hypothesis (not a confirmed decode; cleared the matched-null gate): base={} numbering={} sign={} matched_z={:.2}",
            candidate.base,
            candidate.numbering.name(),
            candidate.sign.label(),
            candidate.matched_z,
        );
        println!("  full decrypt: {}", candidate.render_plaintext());
        match ragbaby::write_ragbaby_record(candidates_dir, label, seed, candidate) {
            Ok(path) => println!("  record: {}", path.display()),
            Err(error) => {
                eprintln!("failed to write candidate record: {error}");
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}

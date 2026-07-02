//! Handler for the `pairclass` subcommand.

use std::process::ExitCode;

use noita_eye_puzzle::attack::pairclass::{
    self, Lexicon, NullGate, PlantOutcome, PowerCfg, PowerReport, SolveInput, SolveReport,
    StreamPrep, TruthFate, WalkViolation, build_lexicon, measure_power, null_gate,
    pairclass_self_test, parse_wordlist, prepare_stream, solve, solve_cfg,
};

use crate::cli::args_pairclass::PairclassArgs;
use crate::cli::shared::{parse_cli_sequence, resolve_input_text};

/// Dispatches the `pairclass` subcommand.
pub(crate) fn run_pairclass(args: &PairclassArgs) -> ExitCode {
    if args.self_test {
        return run_self_test(args.seed);
    }
    match run_analysis(args) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("pairclass error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Resolves the input stream (embedded `two` when no input flag is given).
fn resolve_values(
    args: &PairclassArgs,
) -> Result<(Vec<noita_eye_puzzle::core::glyph::Glyph>, String), String> {
    if args.input_file.is_none() && !args.stdin {
        let values = pairclass::embedded_two().map_err(|error| error.to_string())?;
        return Ok((values, "embedded practice puzzle two".to_owned()));
    }
    let text = resolve_input_text(None, args.input_file.as_ref(), args.stdin)
        .map_err(|error| format!("failed to read input: {error}"))?;
    let alphabet = args.alphabet.as_deref().or(Some(pairclass::TWO_ALPHABET));
    let parsed = parse_cli_sequence(&text, alphabet, false).map_err(|error| error.to_string())?;
    let label = args
        .input_file
        .as_ref()
        .map_or_else(|| "stdin".to_owned(), |path| path.display().to_string());
    Ok((parsed.glyphs, label))
}

/// The main (non-self-test) analysis path.
fn run_analysis(args: &PairclassArgs) -> Result<ExitCode, String> {
    let (values, label) = resolve_values(args)?;
    println!("pairclass: pair-class decipherment (token = the walk's direction-bit pair)");
    println!("  input: {label}");
    let prep = match prepare_stream(
        &values,
        args.modulus,
        args.phase,
        args.reversed,
        args.min_anchor_len,
    )
    .map_err(|error| error.to_string())?
    {
        Ok(prep) => prep,
        Err(violation) => {
            print_not_a_walk(&violation);
            return Ok(ExitCode::SUCCESS);
        }
    };
    print_derivation(args, &prep);
    let Some(wordlist_path) = args.wordlist.as_ref() else {
        println!();
        println!(
            "No --wordlist supplied: derivation only. Pass --wordlist <file> to run the solver."
        );
        return Ok(ExitCode::SUCCESS);
    };
    let lexicon = build_wordlist(wordlist_path, args.vocab_cap)?;
    println!(
        "  lexicon: {} words, {} trie nodes (cap {})",
        lexicon.n_words(),
        lexicon.n_nodes(),
        args.vocab_cap
    );
    let cfg = solve_cfg(
        args.beam,
        args.max_gaps,
        args.max_gap_len,
        args.gap_penalty,
        args.top,
        args.max_mem_mib,
    );
    if let Some(power) = maybe_run_controls(args, &prep, &lexicon, &cfg)? {
        if !power.cleared_bar {
            print_power(args, &power);
            println!();
            println!(
                "VERDICT: ControlsFailed — mean plant recovery {:.3} < bar {:.3}; \
                 the real stream was NOT scored (controls-first).",
                power.mean_recovery, args.plant_bar
            );
            return Ok(ExitCode::SUCCESS);
        }
        print_power(args, &power);
    }
    run_real_stream(args, &prep, &lexicon, &cfg)
}

/// Builds the lexicon from a wordlist file.
fn build_wordlist(path: &std::path::Path, cap: usize) -> Result<Lexicon, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("failed to read wordlist {}: {error}", path.display()))?;
    build_lexicon(&parse_wordlist(&text, cap)).map_err(|error| error.to_string())
}

/// Runs the controls-first power measurement when a plant source is supplied.
fn maybe_run_controls(
    args: &PairclassArgs,
    prep: &StreamPrep,
    lexicon: &Lexicon,
    cfg: &noita_eye_puzzle::attack::pairclass::SolveCfg,
) -> Result<Option<PowerReport>, String> {
    let Some(plant_path) = args.plant_text_file.as_ref() else {
        return Ok(None);
    };
    let text = std::fs::read_to_string(plant_path).map_err(|error| {
        format!(
            "failed to read plant text {}: {error}",
            plant_path.display()
        )
    })?;
    let power = measure_power(
        &text,
        &PowerCfg {
            n_plants: args.plants,
            plant_len: prep.tokens.len(),
            n_classes: prep.n_classes,
            longest_tie: prep.longest_tie,
            bar: args.plant_bar,
            seed: args.seed,
        },
        lexicon,
        cfg,
    )
    .map_err(|error| error.to_string())?;
    Ok(Some(power))
}

/// Scores the real stream (behind passing controls) and gates it against the
/// matched null.
fn run_real_stream(
    args: &PairclassArgs,
    prep: &StreamPrep,
    lexicon: &Lexicon,
    cfg: &noita_eye_puzzle::attack::pairclass::SolveCfg,
) -> Result<ExitCode, String> {
    let tie_to = (!prep.tie_table.is_empty()).then_some(prep.tie_table.as_slice());
    let report = solve(
        &SolveInput {
            tokens: &prep.tokens,
            n_classes: prep.n_classes,
            tie_to,
            lexicon,
            truth: None,
            seed_coloring: None,
        },
        cfg,
    )
    .map_err(|error| error.to_string())?;
    print_solutions(&report);
    let real_best = report.solutions.first().map(|s| s.score);
    let gate = maybe_null_gate(args, prep, lexicon, cfg, real_best)?;
    print_verdict(&report, gate.as_ref());
    Ok(ExitCode::SUCCESS)
}

/// Runs the matched-null gate when `--null-trials > 0`.
fn maybe_null_gate(
    args: &PairclassArgs,
    prep: &StreamPrep,
    lexicon: &Lexicon,
    cfg: &noita_eye_puzzle::attack::pairclass::SolveCfg,
    real_best: Option<f32>,
) -> Result<Option<NullGate>, String> {
    if args.null_trials == 0 {
        return Ok(None);
    }
    let gate = null_gate(
        &prep.tokens,
        prep.n_classes,
        lexicon,
        cfg,
        args.null_trials,
        real_best,
        args.seed,
    )
    .map_err(|error| error.to_string())?;
    Ok(Some(gate))
}

fn print_not_a_walk(violation: &WalkViolation) {
    println!(
        "  walk gate: step {} ({} -> {}) has residue difference {} mod {}, not ±1",
        violation.position, violation.from, violation.to, violation.diff, violation.modulus
    );
    println!();
    println!(
        "VERDICT: NotAWalk — the residue channel is not a ±1 walk on C_{}; \
         the pair-class model does not apply.",
        violation.modulus
    );
}

fn print_derivation(args: &PairclassArgs, prep: &StreamPrep) {
    println!(
        "  derivation: modulus {}, phase {}{}, {} tokens over {} classes",
        args.modulus,
        args.phase,
        if args.reversed { ", reversed" } else { "" },
        prep.tokens.len(),
        prep.n_classes
    );
    let mut marginals = [0usize; 4];
    for &token in &prep.tokens {
        if let Some(slot) = marginals.get_mut(usize::from(token)) {
            *slot += 1;
        }
    }
    println!("  token marginals (classes 0..4): {marginals:?}");
    if args.min_anchor_len == 0 {
        println!("  ties: disabled (--min-anchor-len 0)");
    } else if let Some((src, dst, len)) = prep.longest_tie {
        println!(
            "  ties: {} tied positions; longest run {} tokens (positions {}.. == {}..)",
            prep.n_tied, len, src, dst
        );
    } else {
        println!(
            "  ties: {} tied positions (no run at min-anchor-len {})",
            prep.n_tied, args.min_anchor_len
        );
    }
}

fn print_power(args: &PairclassArgs, power: &PowerReport) {
    println!();
    println!(
        "Controls-first power ({} plants, bar {:.3}):",
        args.plants, args.plant_bar
    );
    for (index, plant) in power.plants.iter().enumerate() {
        println!(
            "  plant {:>2}: recovery {:.3}  coloring {:.3}  {}",
            index,
            plant.recovery,
            plant.coloring_accuracy,
            render_fate(plant)
        );
    }
    println!(
        "  mean recovery {:.3}  mean coloring {:.3}  {}",
        power.mean_recovery,
        power.mean_coloring_accuracy,
        if power.cleared_bar {
            "CLEARED"
        } else {
            "BELOW BAR"
        }
    );
}

fn render_fate(plant: &PlantOutcome) -> String {
    match plant.fate {
        Some(TruthFate::Found { score }) => format!("truth FOUND (score {score:.1})"),
        Some(TruthFate::OutScored {
            truth_score,
            best_score,
        }) => format!("truth OUT-SCORED ({truth_score:.1} < {best_score:.1})"),
        Some(TruthFate::BeamPruned {
            position,
            truth_best,
            cutoff,
        }) => format!("truth BEAM-PRUNED @ pos {position} ({truth_best:.1} < cutoff {cutoff:.1})"),
        Some(TruthFate::Infeasible { position }) => format!("truth INFEASIBLE @ pos {position}"),
        None => "no truth track".to_owned(),
    }
}

fn print_solutions(report: &SolveReport) {
    println!();
    println!(
        "Candidate decodes (top {}, expanded {} states, {} feasible finals, est. peak {} MiB):",
        report.solutions.len(),
        report.expanded,
        report.feasible_final,
        report.estimated_mib
    );
    if report.solutions.is_empty() {
        println!("  none: no full segmentation under the lexicon/gap policy");
        return;
    }
    for (rank, solution) in report.solutions.iter().enumerate() {
        println!(
            "  {:>2}. score {:.2}  gaps {}  \"{}\"",
            rank + 1,
            solution.score,
            solution.gaps_used,
            solution.rendered
        );
    }
}

fn print_verdict(report: &SolveReport, gate: Option<&NullGate>) {
    println!();
    let Some(best) = report.solutions.first() else {
        println!("VERDICT: Negative — no full segmentation; not a candidate.");
        return;
    };
    if let Some(gate) = gate {
        let p = gate.p_value();
        let cleared = gate.null_ge_real == 0;
        println!(
            "  null gate: {} Markov resamples, {} reached the real best, empirical p = {:.3}",
            gate.null_bests.len(),
            gate.null_ge_real,
            p
        );
        if cleared {
            println!(
                "VERDICT: Candidate — best \"{}\" clears the matched null (p = {:.3}); \
                 a hypothesis for human review, never a decode.",
                best.rendered, p
            );
        } else {
            println!(
                "VERDICT: NullArtifact — the matched null reaches the real score \
                 ({}/{} resamples); the segmentation is not a signal.",
                gate.null_ge_real,
                gate.null_bests.len()
            );
        }
    } else {
        println!(
            "VERDICT: Candidate (ungated) — best \"{}\"; pass --null-trials to gate it. \
             A high score without null clearance is not a decode.",
            best.rendered
        );
    }
}

fn run_self_test(seed: u64) -> ExitCode {
    let report = match pairclass_self_test(seed) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("pairclass self-test error: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!("pairclass self-test (seed=0x{seed:016x}):");
    println!(
        "  planted positive (recovery {:.3}): {}",
        report.plant.recovery,
        pass_fail(report.plant.passed())
    );
    println!("  matched Markov null: {}", pass_fail(report.null.passed()));
    println!(
        "  forced-prune instrumentation: {}",
        pass_fail(report.prune.passed())
    );
    println!("  walk gate control: {}", pass_fail(report.walk_gate));
    println!(
        "  embedded two regression (348 tokens, marginals {:?}): {}",
        report.two.marginals,
        pass_fail(report.two.passed())
    );
    println!(
        "  SELF-TEST: {}",
        if report.passed() { "PASS" } else { "FAIL" }
    );
    if report.passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn pass_fail(value: bool) -> &'static str {
    if value { "PASS" } else { "FAIL" }
}

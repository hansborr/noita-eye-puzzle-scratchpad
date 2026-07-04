//! Handler for the `pairclass` subcommand.

#[path = "pairclass_anchor_report.rs"]
mod pairclass_anchor_report;
#[path = "pairclass_pattern_crib.rs"]
mod pairclass_pattern_crib;
#[path = "pairclass_selftest_report.rs"]
mod pairclass_selftest_report;
#[path = "pairclass_structured.rs"]
mod pairclass_structured;
#[path = "pairclass_structured_report.rs"]
mod pairclass_structured_report;

use std::process::ExitCode;

use noita_eye_puzzle::attack::pairclass::{
    self, AnchorHarvestMode, AnchorHarvestRetentionReport, AnchorNullCfg, AnchorPowerReport,
    Lexicon, NullGate, PlantOutcome, PowerCfg, PowerReport, SolveInput, SolveReport, StreamPrep,
    TruthFate, WalkViolation, anchor_null_gate, build_lexicon, harvest_anchor_colorings,
    measure_anchor_harvest_retention, measure_anchor_seed_power, measure_power, null_gate,
    parse_wordlist, prepare_stream, solve, solve_anchor_seeded, solve_cfg,
};

use crate::cli::args_pairclass::{PairclassArgs, PairclassHarvestMode, PairclassSearchOrder};
use crate::cli::shared::{parse_cli_sequence, resolve_input_text};
use pairclass_anchor_report::{
    anchor_ladder, print_anchor_harvest_retention, print_anchor_harvest_verdict,
    print_anchor_harvest_window, print_anchor_power, print_anchor_solutions, print_anchor_verdict,
};
use pairclass_pattern_crib::run_pattern_crib_analysis;
use pairclass_selftest_report::run_self_test;
use pairclass_structured::run_structured_analysis;

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
    if args.pattern_crib_scan.unwrap_or(false) {
        return run_pattern_crib_analysis(args, &prep);
    }
    let Some(wordlist_path) = args.wordlist.as_ref() else {
        println!();
        println!(
            "No --wordlist supplied: derivation only. Pass --wordlist <file> to run the solver."
        );
        return Ok(ExitCode::SUCCESS);
    };
    let word_entries = read_word_entries(wordlist_path, args.vocab_cap)?;
    let lexicon = build_wordlist_from_entries(&word_entries)?;
    println!(
        "  lexicon: {} words, {} trie nodes (cap {})",
        lexicon.n_words(),
        lexicon.n_nodes(),
        args.vocab_cap
    );
    let full_cfg = solve_cfg(
        args.beam,
        args.max_gaps,
        args.max_gap_len,
        args.gap_penalty,
        args.top,
        args.max_mem_mib,
    );
    let phrase_cfg = solve_cfg(
        args.phrase_beam,
        args.phrase_max_gaps,
        args.phrase_max_gap_len,
        args.phrase_gap_penalty,
        args.phrase_top,
        args.max_mem_mib,
    );
    if harvest_only_enabled(args) && args.search_order != PairclassSearchOrder::AnchorSeed {
        return Err("--harvest-only requires --anchor-seed".to_owned());
    }
    if args.coloring_family.is_some() {
        return run_structured_analysis(args, &values, &word_entries, &lexicon, &full_cfg);
    }
    if args.search_order == PairclassSearchOrder::AnchorSeed {
        return run_anchor_analysis(args, &prep, &lexicon, &phrase_cfg, &full_cfg);
    }
    if let Some(power) = maybe_run_controls(args, &prep, &lexicon, &full_cfg)? {
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
    run_real_stream(args, &prep, &lexicon, &full_cfg)
}

/// Builds the lexicon from a wordlist file.
fn read_word_entries(path: &std::path::Path, cap: usize) -> Result<Vec<(String, u64)>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("failed to read wordlist {}: {error}", path.display()))?;
    Ok(parse_wordlist(&text, cap))
}

/// Builds the lexicon from parsed word entries.
fn build_wordlist_from_entries(entries: &[(String, u64)]) -> Result<Lexicon, String> {
    build_lexicon(entries).map_err(|error| error.to_string())
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

/// Runs controls-first anchor-seeded analysis.
fn run_anchor_analysis(
    args: &PairclassArgs,
    prep: &StreamPrep,
    lexicon: &Lexicon,
    phrase_cfg: &noita_eye_puzzle::attack::pairclass::SolveCfg,
    full_cfg: &noita_eye_puzzle::attack::pairclass::SolveCfg,
) -> Result<ExitCode, String> {
    let harvest_mode = anchor_harvest_mode(args.harvest_mode);
    if harvest_only_enabled(args) {
        if let Some(power) = maybe_run_anchor_harvest_controls(args, prep, lexicon, phrase_cfg)? {
            print_anchor_harvest_retention(args, &power);
            print_anchor_harvest_verdict(&power);
        } else {
            let harvest =
                harvest_anchor_colorings(prep, lexicon, phrase_cfg, args.phrase_top, harvest_mode)
                    .map_err(|error| error.to_string())?;
            print_anchor_harvest_window(args, &harvest);
        }
        return Ok(ExitCode::SUCCESS);
    }
    if let Some(power) =
        maybe_run_anchor_controls(args, prep, lexicon, phrase_cfg, full_cfg, harvest_mode)?
    {
        print_anchor_power(args, &power);
        if !power.cleared_bar {
            println!();
            println!(
                "VERDICT: ControlsFailed — mean plant recovery {:.3} < bar {:.3}; \
                 the real stream was NOT scored (controls-first). {}",
                power.mean_recovery,
                args.plant_bar,
                anchor_ladder(&power)
            );
            return Ok(ExitCode::SUCCESS);
        }
    }
    run_anchor_stream(args, prep, lexicon, phrase_cfg, full_cfg, harvest_mode)
}

fn harvest_only_enabled(args: &PairclassArgs) -> bool {
    args.harvest_only.unwrap_or(false)
}

/// Converts the CLI enum to the library harvest mode.
fn anchor_harvest_mode(mode: PairclassHarvestMode) -> AnchorHarvestMode {
    match mode {
        PairclassHarvestMode::Beam => AnchorHarvestMode::ScoreBeam,
        PairclassHarvestMode::Enumerate => AnchorHarvestMode::Enumerate,
    }
}

/// Runs the anchor-seeded controls-first power measurement.
fn maybe_run_anchor_controls(
    args: &PairclassArgs,
    prep: &StreamPrep,
    lexicon: &Lexicon,
    phrase_cfg: &noita_eye_puzzle::attack::pairclass::SolveCfg,
    full_cfg: &noita_eye_puzzle::attack::pairclass::SolveCfg,
    harvest_mode: AnchorHarvestMode,
) -> Result<Option<AnchorPowerReport>, String> {
    let Some(plant_path) = args.plant_text_file.as_ref() else {
        return Ok(None);
    };
    let text = std::fs::read_to_string(plant_path).map_err(|error| {
        format!(
            "failed to read plant text {}: {error}",
            plant_path.display()
        )
    })?;
    let power = measure_anchor_seed_power(
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
        phrase_cfg,
        full_cfg,
        args.phrase_top,
        harvest_mode,
    )
    .map_err(|error| error.to_string())?;
    Ok(Some(power))
}

/// Runs Phase-1-only anchor harvest retention controls.
fn maybe_run_anchor_harvest_controls(
    args: &PairclassArgs,
    prep: &StreamPrep,
    lexicon: &Lexicon,
    phrase_cfg: &noita_eye_puzzle::attack::pairclass::SolveCfg,
) -> Result<Option<AnchorHarvestRetentionReport>, String> {
    let Some(plant_path) = args.plant_text_file.as_ref() else {
        return Ok(None);
    };
    let text = std::fs::read_to_string(plant_path).map_err(|error| {
        format!(
            "failed to read plant text {}: {error}",
            plant_path.display()
        )
    })?;
    let power = measure_anchor_harvest_retention(
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
        phrase_cfg,
        args.phrase_top,
        anchor_harvest_mode(args.harvest_mode),
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
            accept_partial_final: false,
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

/// Scores the real stream with the anchor-seeded pipeline.
fn run_anchor_stream(
    args: &PairclassArgs,
    prep: &StreamPrep,
    lexicon: &Lexicon,
    phrase_cfg: &noita_eye_puzzle::attack::pairclass::SolveCfg,
    full_cfg: &noita_eye_puzzle::attack::pairclass::SolveCfg,
    harvest_mode: AnchorHarvestMode,
) -> Result<ExitCode, String> {
    let report = solve_anchor_seeded(
        prep,
        lexicon,
        phrase_cfg,
        full_cfg,
        args.phrase_top,
        harvest_mode,
        None,
    )
    .map_err(|error| error.to_string())?;
    print_anchor_solutions(args, &report);
    let real_best = report.solutions.first().map(|seeded| seeded.solution.score);
    let gate = maybe_anchor_null_gate(
        args,
        prep,
        lexicon,
        phrase_cfg,
        full_cfg,
        harvest_mode,
        real_best,
    )?;
    print_anchor_verdict(&report, gate.as_ref());
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

/// Runs the anchor-mode matched-null gate when `--null-trials > 0`.
fn maybe_anchor_null_gate(
    args: &PairclassArgs,
    prep: &StreamPrep,
    lexicon: &Lexicon,
    phrase_cfg: &noita_eye_puzzle::attack::pairclass::SolveCfg,
    full_cfg: &noita_eye_puzzle::attack::pairclass::SolveCfg,
    harvest_mode: AnchorHarvestMode,
    real_best: Option<f32>,
) -> Result<Option<NullGate>, String> {
    if args.null_trials == 0 {
        return Ok(None);
    }
    let gate = anchor_null_gate(
        prep,
        lexicon,
        phrase_cfg,
        full_cfg,
        args.phrase_top,
        harvest_mode,
        &AnchorNullCfg {
            null_trials: args.null_trials,
            real_best,
            seed: args.seed,
        },
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

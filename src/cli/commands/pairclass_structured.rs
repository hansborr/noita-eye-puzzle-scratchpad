//! Structured-coloring `pairclass` CLI driver.

use std::process::ExitCode;

use noita_eye_puzzle::attack::pairclass::{
    Lexicon, PowerCfg, StreamPrep, StructuredFamilyProfile, StructuredNegativeReport,
    StructuredNullCfg, StructuredNullGate, StructuredRunCfg, StructuredStream,
    confirm_structured_top_candidates, measure_structured_power,
    measure_structured_random_negative, prepare_stream, run_structured_oracle_decode,
    structured_null_gate_streams,
};

use crate::cli::args_pairclass::{PairclassArgs, PairclassColoringFamily, PairclassSearchOrder};

use super::pairclass_structured_report::{
    print_structured_negative, print_structured_null, print_structured_power,
    print_structured_solutions, print_structured_verdict,
};

struct NamedPrep {
    label: String,
    prep: StreamPrep,
}

struct StructuredControls {
    negative: StructuredNegativeReport,
    null: StructuredNullGate,
    score_floor: f32,
}

/// Runs Avenue-A structured-coloring enumeration and oracle decode.
pub(crate) fn run_structured_analysis(
    args: &PairclassArgs,
    values: &[noita_eye_puzzle::core::glyph::Glyph],
    word_entries: &[(String, u64)],
    lexicon: &Lexicon,
    cfg: &noita_eye_puzzle::attack::pairclass::SolveCfg,
) -> Result<ExitCode, String> {
    if args.search_order == PairclassSearchOrder::AnchorSeed {
        return Err("--coloring-family cannot be combined with --anchor-seed".to_owned());
    }
    if args.plant_text_file.is_none() {
        return Err(
            "--coloring-family requires --plant-text-file for controls-first scoring".to_owned(),
        );
    }
    if args.null_trials == 0 {
        return Err(
            "--coloring-family requires --null-trials > 0 for controls-first scoring".to_owned(),
        );
    }
    if args.plants == 0 {
        return Err("--coloring-family requires --plants >= 1 for non-vacuous controls".to_owned());
    }
    let run_cfg = structured_run_cfg(args)?;
    let variants = prepare_structured_variants(values, args)?;
    println!();
    println!(
        "Structured coloring mode: profile {:?}, rank-beam {}, confirm-beam {}, top {}, extra-decodes {}, full base coverage decoded, marginal-l1 {:.3}, score-margin {:.2}",
        run_cfg.profile,
        run_cfg.rank_beam,
        cfg.beam,
        cfg.top,
        run_cfg.max_decodes,
        run_cfg.marginal_l1,
        run_cfg.score_margin
    );
    println!(
        "  controls, nulls, real ranking, and verdict statistics use rank-beam; full-beam confirmation is rendering only."
    );
    for variant in &variants {
        print_structured_variant(variant);
    }
    let Some(controls) =
        run_structured_controls(args, &variants, word_entries, lexicon, cfg, &run_cfg)?
    else {
        return Ok(ExitCode::SUCCESS);
    };
    let streams = structured_streams(&variants);
    let mut report = run_structured_oracle_decode(&streams, word_entries, lexicon, cfg, &run_cfg)
        .map_err(|error| error.to_string())?;
    let real_best = report.best_score();
    let null_ge_real = count_null_ge(controls.null.null_bests.as_slice(), real_best);
    let null = StructuredNullGate {
        real_best,
        null_bests: controls.null.null_bests,
        null_ge_real,
        null_ge_floor: controls.null.null_ge_floor,
    };
    let confirm_error = confirm_structured_top_candidates(&mut report, &streams, lexicon, cfg)
        .err()
        .map(|error| error.to_string());
    print_structured_solutions(
        &report,
        controls.negative.max_score,
        null.max_score(),
        run_cfg.rank_beam,
    );
    if let Some(error) = confirm_error {
        println!();
        println!(
            "Confirm-beam rendering unavailable for at least one top candidate ({error}); rank-beam verdict statistics are unchanged."
        );
    }
    print_structured_null(&null, Some(controls.score_floor), run_cfg.rank_beam);
    print_structured_verdict(
        &report,
        &controls.negative,
        Some(&null),
        run_cfg.score_margin,
    );
    Ok(ExitCode::SUCCESS)
}

fn run_structured_controls(
    args: &PairclassArgs,
    variants: &[NamedPrep],
    word_entries: &[(String, u64)],
    lexicon: &Lexicon,
    cfg: &noita_eye_puzzle::attack::pairclass::SolveCfg,
    run_cfg: &StructuredRunCfg,
) -> Result<Option<StructuredControls>, String> {
    let plant_path = args
        .plant_text_file
        .as_ref()
        .ok_or_else(|| "--coloring-family requires --plant-text-file".to_owned())?;
    let plant_text = std::fs::read_to_string(plant_path).map_err(|error| {
        format!(
            "failed to read plant text {}: {error}",
            plant_path.display()
        )
    })?;
    let control_prep = variants
        .first()
        .ok_or_else(|| "structured mode prepared no stream variants".to_owned())?;
    let power_cfg = PowerCfg {
        n_plants: args.plants,
        plant_len: control_prep.prep.tokens.len(),
        n_classes: control_prep.prep.n_classes,
        longest_tie: control_prep.prep.longest_tie,
        bar: args.plant_bar,
        seed: args.seed,
    };
    let positive =
        measure_structured_power(&plant_text, &power_cfg, word_entries, lexicon, cfg, run_cfg)
            .map_err(|error| error.to_string())?;
    print_structured_power(args, &positive);
    let Some(score_floor) = positive.score_floor else {
        println!();
        println!(
            "VERDICT: ControlsFailed — structured positive produced no score floor; the real stream was NOT scored."
        );
        return Ok(None);
    };
    if !positive.cleared_bar {
        println!();
        println!(
            "VERDICT: ControlsFailed — structured positive did not fire; the real stream was NOT scored."
        );
        return Ok(None);
    }
    let negative = measure_structured_random_negative(
        &plant_text,
        &power_cfg,
        word_entries,
        lexicon,
        cfg,
        run_cfg,
        Some(score_floor),
    )
    .map_err(|error| error.to_string())?;
    print_structured_negative(&negative, run_cfg.rank_beam);
    if !negative.quiet {
        println!();
        println!(
            "VERDICT: ControlsFailed — random-coloring negative fired; the real stream was NOT scored."
        );
        return Ok(None);
    }
    let prep_variants: Vec<StreamPrep> = variants
        .iter()
        .map(|variant| variant.prep.clone())
        .collect();
    let pre_null = structured_null_gate_streams(
        &prep_variants,
        word_entries,
        lexicon,
        cfg,
        run_cfg,
        &StructuredNullCfg {
            null_trials: args.null_trials,
            real_best: None,
            score_floor: Some(score_floor),
            seed: args.seed,
        },
    )
    .map_err(|error| error.to_string())?;
    print_structured_null(&pre_null, Some(score_floor), run_cfg.rank_beam);
    if pre_null.null_ge_floor > 0 {
        println!();
        println!(
            "VERDICT: ControlsFailed — matched Markov null reached the positive score floor; the real stream was NOT scored."
        );
        return Ok(None);
    }
    Ok(Some(StructuredControls {
        negative,
        null: pre_null,
        score_floor,
    }))
}

fn structured_run_cfg(args: &PairclassArgs) -> Result<StructuredRunCfg, String> {
    let profile = match args.coloring_family {
        Some(PairclassColoringFamily::Core) => StructuredFamilyProfile::Core,
        Some(PairclassColoringFamily::Toy) => StructuredFamilyProfile::Toy,
        None => return Err("--coloring-family missing".to_owned()),
    };
    if args.structured_rank_beam == 0 {
        return Err("--structured-rank-beam must be >= 1".to_owned());
    }
    Ok(StructuredRunCfg {
        profile,
        max_decodes: args.structured_max_decodes,
        rank_beam: args.structured_rank_beam,
        marginal_l1: args.structured_marginal_l1,
        score_margin: args.structured_score_margin,
    })
}

fn prepare_structured_variants(
    values: &[noita_eye_puzzle::core::glyph::Glyph],
    args: &PairclassArgs,
) -> Result<Vec<NamedPrep>, String> {
    let mut variants = Vec::with_capacity(4);
    for reversed in [false, true] {
        for phase in [0usize, 1] {
            let label = format!("phase{}{}", phase, if reversed { "-reversed" } else { "" });
            let prep =
                match prepare_stream(values, args.modulus, phase, reversed, args.min_anchor_len)
                    .map_err(|error| error.to_string())?
                {
                    Ok(prep) => prep,
                    Err(violation) => {
                        return Err(format!(
                            "stream variant {label} failed the walk gate at step {} ({} -> {})",
                            violation.position, violation.from, violation.to
                        ));
                    }
                };
            variants.push(NamedPrep { label, prep });
        }
    }
    Ok(variants)
}

fn structured_streams(variants: &[NamedPrep]) -> Vec<StructuredStream<'_>> {
    variants
        .iter()
        .map(|variant| StructuredStream {
            label: variant.label.as_str(),
            tokens: &variant.prep.tokens,
            n_classes: variant.prep.n_classes,
            tie_to: (!variant.prep.tie_table.is_empty())
                .then_some(variant.prep.tie_table.as_slice()),
        })
        .collect()
}

fn print_structured_variant(variant: &NamedPrep) {
    let mut marginals = [0usize; 4];
    for &token in &variant.prep.tokens {
        if let Some(slot) = marginals.get_mut(usize::from(token)) {
            *slot += 1;
        }
    }
    println!(
        "  variant {}: {} tokens, marginals {:?}, tied {}",
        variant.label,
        variant.prep.tokens.len(),
        marginals,
        variant.prep.n_tied
    );
}

fn count_null_ge(null_bests: &[Option<f32>], real_best: Option<f32>) -> usize {
    let Some(real) = real_best else {
        return 0;
    };
    null_bests
        .iter()
        .filter(|score| score.is_some_and(|null| null >= real))
        .count()
}

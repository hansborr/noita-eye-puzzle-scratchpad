//! Structured-coloring `pairclass` CLI driver.

use std::process::ExitCode;

use noita_eye_puzzle::attack::pairclass::{
    Lexicon, PowerCfg, StreamPrep, StructuredControlCfg, StructuredFamilyProfile,
    StructuredNegativeReport, StructuredNullCfg, StructuredPowerReport, StructuredRunCfg,
    StructuredStream, StructuredVerdictCfg, StructuredVerdictProfile,
    confirm_structured_top_candidates, measure_structured_power,
    measure_structured_random_negative, prepare_stream, run_structured_oracle_decode,
    structured_null_gate_streams,
};

use crate::cli::args_pairclass::{PairclassArgs, PairclassColoringFamily, PairclassSearchOrder};

use super::pairclass_structured_report::{
    print_structured_negative, print_structured_null, print_structured_power,
    print_structured_solutions, print_structured_verdict,
};

const CURATED_CONTROL_NULL_TRIALS: usize = 19;
const CURATED_REAL_NULL_TRIALS: usize = 49;
const CURATED_NEGATIVE_CONTROLS: usize = 3;
const BROAD_CONTROL_NULL_TRIALS: usize = 2;
const BROAD_REAL_NULL_TRIALS: usize = 20;
const BROAD_NEGATIVE_CONTROLS: usize = 6;
const TOY_CONTROL_NULL_TRIALS: usize = 2;
const TOY_REAL_NULL_TRIALS: usize = 2;
const TOY_NEGATIVE_CONTROLS: usize = 1;
const CURATED_POSITIVE_ALPHA: f64 = 0.05;
const CURATED_REAL_ALPHA: f64 = 0.02;
const CURATED_TRUTH_TOP_RANK: usize = 3;

struct NamedPrep {
    label: String,
    prep: StreamPrep,
}

#[derive(Clone, Copy)]
struct StructuredTierRules {
    verdict_cfg: StructuredVerdictCfg,
    control_null_trials: usize,
    real_null_trials: usize,
    negative_controls: usize,
    negative_alpha: f64,
}

struct StructuredControls {
    positive: StructuredPowerReport,
    negative: StructuredNegativeReport,
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
    if args.plants == 0 {
        return Err("--coloring-family requires --plants >= 1 for non-vacuous controls".to_owned());
    }
    let run_cfg = structured_run_cfg(args)?;
    let rules = structured_tier_rules(args, run_cfg.profile);
    let variants = prepare_structured_variants(values, args)?;
    println!();
    println!(
        "Structured coloring mode: profile {:?}, rank-beam {}, confirm-beam {}, top {}, extra-decodes {}, full base coverage ranked, marginal-l1 {:.3}, control-nulls {}, real-nulls {}, negative-controls {}",
        run_cfg.profile,
        run_cfg.rank_beam,
        cfg.beam,
        cfg.top,
        run_cfg.max_decodes,
        run_cfg.marginal_l1,
        rules.control_null_trials,
        rules.real_null_trials,
        rules.negative_controls
    );
    println!(
        "  controls, nulls, real ranking, and verdict statistics use rank-beam; full-beam confirmation is rendering only."
    );
    for variant in &variants {
        print_structured_variant(variant);
    }
    let Some(controls) = run_structured_controls(
        args,
        &variants,
        word_entries,
        lexicon,
        cfg,
        &run_cfg,
        &rules,
    )?
    else {
        return Ok(ExitCode::SUCCESS);
    };
    let streams = structured_streams(&variants);
    let mut report = run_structured_oracle_decode(&streams, word_entries, lexicon, cfg, &run_cfg)
        .map_err(|error| error.to_string())?;
    let prep_variants: Vec<StreamPrep> = variants
        .iter()
        .map(|variant| variant.prep.clone())
        .collect();
    let real_null = structured_null_gate_streams(
        &prep_variants,
        word_entries,
        lexicon,
        cfg,
        &run_cfg,
        &StructuredNullCfg {
            null_trials: rules.real_null_trials,
            observed_best: report.best_score(),
            seed: args.seed,
        },
    )
    .map_err(|error| error.to_string())?;
    let confirm_error = confirm_structured_top_candidates(&mut report, &streams, lexicon, cfg)
        .err()
        .map(|error| error.to_string());
    print_structured_solutions(&report, Some(&real_null), run_cfg.rank_beam);
    if let Some(error) = confirm_error {
        println!();
        println!(
            "Confirm-beam rendering unavailable for at least one top candidate ({error}); rank-beam verdict statistics are unchanged."
        );
    }
    print_structured_null("real stream", &real_null, run_cfg.rank_beam);
    print_structured_verdict(
        &report,
        &controls.positive,
        &controls.negative,
        &real_null,
        &rules.verdict_cfg,
        rules.negative_alpha,
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
    rules: &StructuredTierRules,
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
    let positive_power_cfg = PowerCfg {
        n_plants: args.plants,
        plant_len: control_prep.prep.tokens.len(),
        n_classes: control_prep.prep.n_classes,
        longest_tie: control_prep.prep.longest_tie,
        bar: args.plant_bar,
        seed: args.seed,
    };
    let positive = measure_structured_power(
        &plant_text,
        &positive_power_cfg,
        word_entries,
        lexicon,
        cfg,
        run_cfg,
        rules.control_null_trials,
    )
    .map_err(|error| error.to_string())?;
    print_structured_power(args, &positive, &rules.verdict_cfg);
    if positive_controls_hard_failed(&positive, rules) {
        println!();
        println!(
            "VERDICT: ControlsFailed - structured positive controls did not decode truth or clear the recovery gate (mean >= --plant-bar and no plant below --plant-floor); the real stream was NOT scored."
        );
        return Ok(None);
    }
    let negative_power_cfg = PowerCfg {
        n_plants: rules.negative_controls,
        ..positive_power_cfg
    };
    let negative = measure_structured_random_negative(
        &plant_text,
        &negative_power_cfg,
        word_entries,
        lexicon,
        cfg,
        run_cfg,
        &StructuredControlCfg {
            null_trials: rules.control_null_trials,
            candidate_alpha: rules.negative_alpha,
        },
    )
    .map_err(|error| error.to_string())?;
    print_structured_negative(&negative, run_cfg.rank_beam, rules.negative_alpha);
    Ok(Some(StructuredControls { positive, negative }))
}

fn positive_controls_hard_failed(
    positive: &StructuredPowerReport,
    rules: &StructuredTierRules,
) -> bool {
    if !positive.all_truth_decoded() {
        return true;
    }
    !positive.recovery_gate_cleared(rules.verdict_cfg.plant_bar, rules.verdict_cfg.plant_floor)
}

fn structured_tier_rules(
    args: &PairclassArgs,
    profile: StructuredFamilyProfile,
) -> StructuredTierRules {
    let (verdict_profile, control_default, real_default, negative_default, real_alpha) =
        match profile {
            StructuredFamilyProfile::CoreCurated => (
                StructuredVerdictProfile::Curated,
                CURATED_CONTROL_NULL_TRIALS,
                CURATED_REAL_NULL_TRIALS,
                CURATED_NEGATIVE_CONTROLS,
                CURATED_REAL_ALPHA,
            ),
            StructuredFamilyProfile::Core => (
                StructuredVerdictProfile::Broad,
                BROAD_CONTROL_NULL_TRIALS,
                BROAD_REAL_NULL_TRIALS,
                BROAD_NEGATIVE_CONTROLS,
                f64::NAN,
            ),
            StructuredFamilyProfile::Toy => (
                StructuredVerdictProfile::Broad,
                TOY_CONTROL_NULL_TRIALS,
                TOY_REAL_NULL_TRIALS,
                TOY_NEGATIVE_CONTROLS,
                f64::NAN,
            ),
        };
    let control_null_trials = default_if_zero(args.control_null_trials, control_default);
    let real_null_trials = default_if_zero(args.null_trials, real_default);
    let negative_controls = args.negative_controls.unwrap_or(negative_default);
    let negative_alpha = match verdict_profile {
        StructuredVerdictProfile::Curated => CURATED_POSITIVE_ALPHA,
        StructuredVerdictProfile::Broad => 1.0 / (control_null_trials as f64 + 1.0),
    };
    StructuredTierRules {
        verdict_cfg: StructuredVerdictCfg {
            profile: verdict_profile,
            plant_bar: args.plant_bar,
            plant_floor: args.plant_floor,
            positive_alpha: CURATED_POSITIVE_ALPHA,
            curated_truth_top_rank: CURATED_TRUTH_TOP_RANK,
            real_alpha,
        },
        control_null_trials,
        real_null_trials,
        negative_controls,
        negative_alpha,
    }
}

fn default_if_zero(value: usize, default: usize) -> usize {
    if value == 0 { default } else { value }
}

fn structured_run_cfg(args: &PairclassArgs) -> Result<StructuredRunCfg, String> {
    let profile = match args.coloring_family {
        Some(PairclassColoringFamily::Core) => StructuredFamilyProfile::Core,
        Some(PairclassColoringFamily::CoreCurated) => StructuredFamilyProfile::CoreCurated,
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

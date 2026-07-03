//! Reporting helpers for structured-coloring `pairclass` mode.

use noita_eye_puzzle::attack::pairclass::{
    StructuredNegativeReport, StructuredNullGate, StructuredPlantOutcome, StructuredPowerReport,
    StructuredRunReport, StructuredVerdict, StructuredVerdictCfg, StructuredVerdictProfile,
    structured_verdict,
};

use crate::cli::args_pairclass::PairclassArgs;

pub(crate) fn print_structured_power(
    args: &PairclassArgs,
    power: &StructuredPowerReport,
    verdict_cfg: &StructuredVerdictCfg,
) {
    println!();
    println!(
        "Structured-coloring positive controls ({} plants, bar {:.3}, rank-beam {}, control null alpha {:.3}):",
        args.plants, args.plant_bar, args.structured_rank_beam, verdict_cfg.positive_alpha
    );
    for (index, plant) in power.plants.iter().enumerate() {
        println!(
            "  plant {:>2}: recovery {:.3}  truth-gen-rank {}  truth-score-rank {}  truth-score {}  best-score {}  {}  null_ge {}  p_emp {}  null-margin {}",
            index,
            plant.recovery,
            opt_rank(plant.truth_candidate_rank),
            opt_rank(plant.truth_score_rank),
            opt_score(plant.truth_score),
            opt_score(plant.best_score),
            truth_status(plant),
            opt_null_ge(plant.null.as_ref()),
            opt_p(plant.null.as_ref()),
            opt_null_margin(plant.null.as_ref())
        );
    }
    println!(
        "  mean recovery {:.3}  truth-best {}/{}  truth-top-{} {}/{}  curated-pass {}/{}  {}",
        power.mean_recovery,
        power.truth_best_count(),
        power.plants.len(),
        verdict_cfg.curated_truth_top_rank,
        power.truth_top_count(verdict_cfg.curated_truth_top_rank),
        power.plants.len(),
        power.curated_pass_count(
            args.plant_bar,
            verdict_cfg.positive_alpha,
            verdict_cfg.curated_truth_top_rank
        ),
        power.plants.len(),
        if power.cleared_bar {
            "RECOVERY CLEARED"
        } else {
            "BELOW RECOVERY BAR"
        }
    );
}

pub(crate) fn print_structured_negative(
    negative: &StructuredNegativeReport,
    rank_beam: usize,
    candidate_alpha: f64,
) {
    println!();
    println!("Random-coloring negative controls (rank-beam {rank_beam}):");
    for (index, plant) in negative.plants.iter().enumerate() {
        println!(
            "  plant {:>2}: best-score {}  null_ge {}  p_emp {}  null-margin {}  {}",
            index,
            opt_score(plant.best_score),
            opt_null_ge(plant.null.as_ref()),
            opt_p(plant.null.as_ref()),
            opt_null_margin(plant.null.as_ref()),
            if plant.null_significant(candidate_alpha) {
                "candidate-like"
            } else {
                "quiet"
            }
        );
    }
    println!(
        "  candidate-like {}/{} at p_emp <= {:.3}  {}",
        negative.false_positive_count(candidate_alpha),
        negative.plants.len(),
        candidate_alpha,
        if negative.quiet {
            "QUIET"
        } else {
            "MEASURED FP"
        }
    );
}

pub(crate) fn print_structured_null(label: &str, null: &StructuredNullGate, rank_beam: usize) {
    println!();
    println!(
        "Structured Markov null for {label} (rank-beam {}): {} trials, observed-best {}, null_ge {}, p_emp {:.3}, null-margin {}",
        rank_beam,
        null.null_bests.len(),
        opt_score(null.observed_best),
        null.null_ge,
        null.p_value(),
        opt_null_margin(Some(null))
    );
}

pub(crate) fn print_structured_solutions(
    report: &StructuredRunReport,
    real_null: Option<&StructuredNullGate>,
    rank_beam: usize,
) {
    println!();
    println!(
        "Structured oracle candidates (rank-beam {}, base {}, relabels {}, ranked {} = guaranteed {} + extra {}, filter-dropped {}, filter-l1-cut {}, cap-dropped {}, cap-l1-cut {}):",
        rank_beam,
        report.generation.base_colorings,
        report.generation.expanded_relabels,
        report.generation.candidates.len(),
        report.generation.guaranteed_candidates,
        report.generation.extra_candidates,
        report.generation.dropped_by_filter,
        opt_f64(report.generation.l1_at_filter_cut),
        report.generation.dropped_by_cap,
        opt_f64(report.generation.l1_at_cut)
    );
    if report.solutions.is_empty() {
        println!("  none: no full segmentation under the lexicon/gap policy");
        return;
    }
    for (index, attempt) in report.solutions.iter().enumerate() {
        let Some(solution) = attempt.solution.as_ref() else {
            continue;
        };
        println!(
            "  {:>2}. rank-score {:.2}  {}  stream {}  family {}  projection {}  order {}  transform {}  l1 {:.3} chi2 {:.2} {}  \"{}\"",
            index + 1,
            solution.score,
            best_null_stats(index, real_null),
            attempt.meta.stream_label,
            attempt.meta.family,
            attempt.meta.projection,
            attempt.meta.order,
            attempt.meta.transform,
            attempt.meta.marginal_l1,
            attempt.meta.marginal_chi2,
            if attempt.meta.marginal_pass {
                "marginal-pass"
            } else {
                "near-best-relabel"
            },
            solution.rendered
        );
        if let Some(confirm) = attempt.confirm.as_ref() {
            if let Some(solution) = confirm.solution.as_ref() {
                println!(
                    "      confirm-beam rendering (beam {}, score {:.2}, expanded {}, feasible {}): \"{}\"",
                    confirm.beam,
                    solution.score,
                    confirm.expanded,
                    confirm.feasible_final,
                    solution.rendered
                );
            } else {
                println!(
                    "      confirm-beam rendering (beam {}, expanded {}, feasible {}): no full segmentation",
                    confirm.beam, confirm.expanded, confirm.feasible_final
                );
            }
        }
    }
}

pub(crate) fn print_structured_verdict(
    report: &StructuredRunReport,
    positive: &StructuredPowerReport,
    negative: &StructuredNegativeReport,
    real_null: &StructuredNullGate,
    verdict_cfg: &StructuredVerdictCfg,
    negative_alpha: f64,
) {
    println!();
    let verdict = structured_verdict(report, positive, negative, real_null, verdict_cfg);
    match verdict {
        StructuredVerdict::Candidate => println!(
            "VERDICT: Candidate - best rank-beam structured candidate clears its matched Markov null (null_ge {}, p_emp {:.3}); confirm-beam text is rendering only; a hypothesis for review, never a decode.",
            real_null.null_ge,
            real_null.p_value()
        ),
        StructuredVerdict::NoCandidate => print_no_candidate(
            report,
            positive,
            negative,
            real_null,
            verdict_cfg,
            negative_alpha,
        ),
        StructuredVerdict::LowPowerNoExclusion => {
            print_low_power(positive, negative, real_null, negative_alpha);
        }
        StructuredVerdict::ControlsFailed => println!(
            "VERDICT: ControlsFailed - structured controls did not validate this scoring surface; the real-stream result is not trusted."
        ),
    }
}

fn print_no_candidate(
    report: &StructuredRunReport,
    positive: &StructuredPowerReport,
    negative: &StructuredNegativeReport,
    real_null: &StructuredNullGate,
    verdict_cfg: &StructuredVerdictCfg,
    negative_alpha: f64,
) {
    let drop_note = drop_accounting_note(report);
    match verdict_cfg.profile {
        StructuredVerdictProfile::Curated => println!(
            "VERDICT: NoCandidate - within the enumerated narrow curated family, using rank-beam scoring and a matched Markov null over the same candidate surface, no real-stream candidate cleared p <= {:.3} (null_ge {}, p_emp {:.3}). The claim is limited to this family, this scoring statistic, this beam, and the measured positive-control power reported here.{}",
            verdict_cfg.real_alpha,
            real_null.null_ge,
            real_null.p_value(),
            drop_note
        ),
        StructuredVerdictProfile::Broad => println!(
            "VERDICT: NoCandidate - no rank-beam structured candidate in the broad deterministic-coloring family achieved matched-null significance (null_ge {}, p_emp {:.3}). This is a no-candidate result for the tested scoring surface, not an exclusion of the broad family. Planted score power was {}/{} truth-best; random negatives measured {}/{} candidate-like at p_emp <= {:.3}.{}",
            real_null.null_ge,
            real_null.p_value(),
            positive.truth_best_count(),
            positive.plants.len(),
            negative.false_positive_count(negative_alpha),
            negative.plants.len(),
            negative_alpha,
            drop_note
        ),
    }
}

fn print_low_power(
    positive: &StructuredPowerReport,
    negative: &StructuredNegativeReport,
    real_null: &StructuredNullGate,
    negative_alpha: f64,
) {
    println!(
        "VERDICT: LowPowerNoExclusion - no rank-beam structured candidate in the broad deterministic-coloring family achieved matched-null significance (null_ge {}, p_emp {:.3}). This is a no-candidate result for the tested scoring surface, not an exclusion of the broad family. Planted controls recovered truth, but broad-family score power was {}/{} truth-best; random negatives measured {}/{} candidate-like at p_emp <= {:.3}.",
        real_null.null_ge,
        real_null.p_value(),
        positive.truth_best_count(),
        positive.plants.len(),
        negative.false_positive_count(negative_alpha),
        negative.plants.len(),
        negative_alpha
    );
}

fn drop_accounting_note(report: &StructuredRunReport) -> String {
    if clean_family_exclusion(report) {
        return String::new();
    }
    format!(
        " Inconclusive drop accounting: {} candidates were cap-dropped and {} relabels were filter-dropped, so this is not a clean family exclusion.",
        report.generation.dropped_by_cap, report.generation.dropped_by_filter
    )
}

fn clean_family_exclusion(report: &StructuredRunReport) -> bool {
    report.generation.dropped_by_cap == 0 && report.generation.dropped_by_filter == 0
}

fn best_null_stats(index: usize, real_null: Option<&StructuredNullGate>) -> String {
    if index != 0 {
        return "best-null p_emp n/a".to_owned();
    }
    real_null.map_or_else(
        || "best-null p_emp n/a".to_owned(),
        |null| {
            format!(
                "best-null_ge {} p_emp {:.3} null-margin {}",
                null.null_ge,
                null.p_value(),
                opt_null_margin(Some(null))
            )
        },
    )
}

fn opt_rank(value: Option<usize>) -> String {
    value.map_or_else(|| "none".to_owned(), |rank| format!("#{rank}"))
}

fn opt_score(value: Option<f32>) -> String {
    value.map_or_else(|| "none".to_owned(), |score| format!("{score:.2}"))
}

fn opt_f64(value: Option<f64>) -> String {
    value.map_or_else(|| "none".to_owned(), |score| format!("{score:.3}"))
}

fn opt_p(value: Option<&StructuredNullGate>) -> String {
    value.map_or_else(
        || "none".to_owned(),
        |null| format!("{:.3}", null.p_value()),
    )
}

fn opt_null_ge(value: Option<&StructuredNullGate>) -> String {
    value.map_or_else(
        || "none".to_owned(),
        |null| format!("{}/{}", null.null_ge, null.null_bests.len()),
    )
}

fn opt_null_margin(value: Option<&StructuredNullGate>) -> String {
    value
        .and_then(StructuredNullGate::null_margin)
        .map_or_else(|| "none".to_owned(), |margin| format!("{margin:.2}"))
}

fn truth_status(plant: &StructuredPlantOutcome) -> &'static str {
    match (
        plant.truth_candidate_rank,
        plant.truth_score,
        plant.truth_is_family_best,
    ) {
        (Some(_rank), Some(_score), true) => "truth family-best",
        (Some(_rank), Some(_score), false) => "truth scored",
        (Some(_rank), None, _) => "truth dropped at rank-beam",
        (None, _score, _) => "truth not enumerated",
    }
}

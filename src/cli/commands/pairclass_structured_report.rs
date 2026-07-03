//! Reporting helpers for structured-coloring `pairclass` mode.

use noita_eye_puzzle::attack::pairclass::{
    StructuredNegativeReport, StructuredNullGate, StructuredPowerReport, StructuredRunReport,
};

use crate::cli::args_pairclass::PairclassArgs;

pub(crate) fn print_structured_power(args: &PairclassArgs, power: &StructuredPowerReport) {
    println!();
    println!(
        "Structured-coloring positive controls ({} plants, bar {:.3}, rank-beam {}):",
        args.plants, args.plant_bar, args.structured_rank_beam
    );
    for (index, plant) in power.plants.iter().enumerate() {
        println!(
            "  plant {:>2}: recovery {:.3}  truth-rank {}  truth-score {}  best-score {}",
            index,
            plant.recovery,
            opt_rank(plant.truth_candidate_rank),
            opt_score(plant.truth_score),
            opt_score(plant.best_score)
        );
    }
    println!(
        "  mean recovery {:.3}  score-floor {}  {}",
        power.mean_recovery,
        opt_score(power.score_floor),
        if power.cleared_bar {
            "FIRED"
        } else {
            "BELOW BAR"
        }
    );
}

pub(crate) fn print_structured_negative(negative: &StructuredNegativeReport, rank_beam: usize) {
    println!();
    println!("Random-coloring negative controls (rank-beam {rank_beam}):");
    for (index, plant) in negative.plants.iter().enumerate() {
        println!(
            "  plant {:>2}: recovery {:.3}  truth-rank {}  best-score {}  {}",
            index,
            plant.recovery,
            opt_rank(plant.truth_candidate_rank),
            opt_score(plant.best_score),
            if plant.fired { "FIRED" } else { "quiet" }
        );
    }
    println!(
        "  max score {}  fired {}/{}  {}",
        opt_score(negative.max_score),
        negative.fired,
        negative.plants.len(),
        if negative.quiet { "QUIET" } else { "FIRED" }
    );
}

pub(crate) fn print_structured_null(
    null: &StructuredNullGate,
    score_floor: Option<f32>,
    rank_beam: usize,
) {
    println!();
    println!(
        "Structured Markov null (rank-beam {}): {} trials, {} reached score floor {}, {} reached real best {}, empirical p = {:.3}",
        rank_beam,
        null.null_bests.len(),
        null.null_ge_floor,
        opt_score(score_floor),
        null.null_ge_real,
        opt_score(null.real_best),
        null.p_value()
    );
}

pub(crate) fn print_structured_solutions(
    report: &StructuredRunReport,
    random_max: Option<f32>,
    null_max: Option<f32>,
    rank_beam: usize,
) {
    println!();
    println!(
        "Structured oracle candidates (rank-beam {}, base {}, relabels {}, decoded {} = base-best {} + extra {}, filter-dropped {}, filter-l1-cut {}, cap-dropped {}, cap-l1-cut {}):",
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
            "  {:>2}. rank-score {:.2}  rand-margin {}  null-margin {}  stream {}  family {}  projection {}  order {}  transform {}  l1 {:.3} chi2 {:.2} {}  \"{}\"",
            index + 1,
            solution.score,
            opt_margin(solution.score, random_max),
            opt_margin(solution.score, null_max),
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
                "best-relabel"
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
    negative: &StructuredNegativeReport,
    null: Option<&StructuredNullGate>,
    score_margin: f32,
) {
    println!();
    let Some(best) = report.solutions.first() else {
        if clean_family_exclusion(report) {
            println!(
                "VERDICT: Negative — these deterministic families produced no survivor under the stated profile/filter/LM settings."
            );
        } else {
            println!(
                "VERDICT: Inconclusive — no structured survivor was decoded, but {} candidates were cap-dropped and {} relabels were filter-dropped; this is not a clean family exclusion.",
                report.generation.dropped_by_cap, report.generation.dropped_by_filter
            );
        }
        return;
    };
    let Some(solution) = best.solution.as_ref() else {
        if clean_family_exclusion(report) {
            println!("VERDICT: Negative — no full segmentation; not a candidate.");
        } else {
            println!(
                "VERDICT: Inconclusive — no full segmentation, but cap/filter drops mean this is not a clean family exclusion."
            );
        }
        return;
    };
    let random_max = negative.max_score;
    let null_max = null.and_then(StructuredNullGate::max_score);
    let clears_random = clears_baseline(solution.score, random_max, score_margin);
    let clears_null = clears_baseline(solution.score, null_max, score_margin)
        && null.is_none_or(|gate| gate.null_ge_real == 0);
    if clears_random && clears_null {
        println!(
            "VERDICT: Candidate — best rank-beam structured survivor clears random-coloring and matched-null baselines; confirm-beam text is rendering only; a hypothesis for review, never a decode."
        );
    } else {
        println!(
            "VERDICT: NullArtifact — best rank-beam structured survivor did not clear the random/null baseline margins; confirm-beam text is rendering only; not a candidate."
        );
    }
}

fn clean_family_exclusion(report: &StructuredRunReport) -> bool {
    report.generation.dropped_by_cap == 0 && report.generation.dropped_by_filter == 0
}

fn clears_baseline(score: f32, baseline: Option<f32>, margin: f32) -> bool {
    baseline.is_none_or(|base| score > base + margin)
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

fn opt_margin(score: f32, baseline: Option<f32>) -> String {
    baseline.map_or_else(|| "n/a".to_owned(), |base| format!("{:.2}", score - base))
}

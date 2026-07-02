//! Anchor-seeded `pairclass` CLI reporting helpers.

use noita_eye_puzzle::attack::pairclass::{
    AnchorPlantOutcome, AnchorPowerReport, AnchorSeedReport, NullGate, TruthFate,
};

use crate::cli::args_pairclass::PairclassArgs;

pub(super) fn print_anchor_power(args: &PairclassArgs, power: &AnchorPowerReport) {
    println!();
    println!(
        "Controls-first anchor power ({} plants, bar {:.3}):",
        args.plants, args.plant_bar
    );
    for (index, plant) in power.plants.iter().enumerate() {
        println!(
            "  plant {:>2}: recovery {:.3}  coloring {:.3}  truth-seed {}  \
             window {}  harvest {} seeds {}  occupancy {}/{} {}  full {}",
            index,
            plant.recovery,
            plant.coloring_accuracy,
            render_truth_seed(plant.truth_seed_rank),
            render_fate(plant.truth_window_fate),
            plant.harvested,
            plant.seeds_run,
            plant.max_occupancy,
            args.phrase_beam,
            if plant.saturated { "SATURATED" } else { "open" },
            render_fate(plant.winning_fate)
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

pub(super) fn anchor_ladder(power: &AnchorPowerReport) -> String {
    let all_harvested = power
        .plants
        .iter()
        .all(|plant| plant.truth_seed_rank.is_some());
    let missed = power
        .plants
        .iter()
        .filter(|plant| plant.truth_seed_rank.is_none());
    if all_harvested {
        return "ladder: truth was harvested; investigate Phase-2/objective behavior.".to_owned();
    }
    let missed_plants: Vec<&AnchorPlantOutcome> = missed.collect();
    let has_infeasible = missed_plants
        .iter()
        .any(|plant| matches!(plant.truth_window_fate, Some(TruthFate::Infeasible { .. })));
    let has_beam_pruned = missed_plants
        .iter()
        .any(|plant| matches!(plant.truth_window_fate, Some(TruthFate::BeamPruned { .. })));
    if has_infeasible && has_beam_pruned {
        return "ladder: mixed truth-window failures; coverage/gap/lexicon limits and score-pruning/LM label-bias."
            .to_owned();
    }
    if has_infeasible {
        return "ladder: truth window was infeasible; coverage/gap/lexicon limit.".to_owned();
    }
    if has_beam_pruned {
        return "ladder: truth window was beam-pruned; score-pruning/LM label-bias.".to_owned();
    }
    if missed_plants.iter().any(|plant| {
        matches!(
            plant.truth_window_fate,
            Some(TruthFate::Found { .. } | TruthFate::OutScored { .. })
        )
    }) {
        return "ladder: truth survived the window but missed harvested top-K; increase phrase-top/oversample."
            .to_owned();
    }
    let missed_open = missed_plants
        .iter()
        .any(|plant| plant.truth_seed_rank.is_none() && !plant.saturated);
    let missed_saturated = missed_plants
        .iter()
        .any(|plant| plant.truth_seed_rank.is_none() && plant.saturated);
    if missed_open {
        return "ladder: truth was not harvested before saturation; coverage/gap/lexicon limit."
            .to_owned();
    }
    if missed_saturated {
        return "ladder: truth was not harvested and phrase beam saturated; score-pruning/LM label-bias."
            .to_owned();
    }
    "ladder: mixed plant outcomes; inspect per-plant harvest ranks and saturation.".to_owned()
}

pub(super) fn print_anchor_solutions(args: &PairclassArgs, report: &AnchorSeedReport) {
    println!();
    let window = report.harvest.window;
    println!(
        "Anchor-seeded search: window {}..{}, tied offsets {}..{} == {}..{}, \
         harvest {}/{} colorings, peak {} MiB",
        window.start,
        window.start + window.len,
        window.first_offset,
        window.first_offset + window.span_len,
        window.second_offset,
        window.second_offset + window.span_len,
        report.harvest.distinct_colorings.len(),
        report.harvest.effective_top,
        report.estimated_peak_mib
    );
    println!(
        "  phrase harvest: beam {}, solutions {}, expanded {}, feasible {}, occupancy {}/{} {}, est. {} MiB",
        args.phrase_beam,
        report.harvest.solutions_seen,
        report.harvest.expanded,
        report.harvest.feasible_final,
        report.harvest.max_occupancy,
        args.phrase_beam,
        if report.harvest.saturated {
            "SATURATED"
        } else {
            "open"
        },
        report.harvest.estimated_mib
    );
    println!(
        "Candidate decodes (top {}, seeds {}, expanded {} states):",
        report.solutions.len(),
        report.seeds_run,
        report.total_expanded
    );
    if report.solutions.is_empty() {
        println!("  none: no full segmentation under the seeded lexicon/gap policy");
        return;
    }
    for (rank, seeded) in report.solutions.iter().enumerate() {
        println!(
            "  {:>2}. score {:.2}  seed #{} ({:.2})  gaps {}  \"{}\"",
            rank + 1,
            seeded.solution.score,
            seeded.seed_rank,
            seeded.seed_score,
            seeded.solution.gaps_used,
            seeded.solution.rendered
        );
    }
}

pub(super) fn print_anchor_verdict(report: &AnchorSeedReport, gate: Option<&NullGate>) {
    println!();
    let Some(best) = report.solutions.first() else {
        println!("VERDICT: Negative — no full seeded segmentation; not a candidate.");
        return;
    };
    if let Some(gate) = gate {
        let p = gate.p_value();
        println!(
            "  anchor null gate: {} Markov resamples, {} reached the real best, empirical p = {:.3}",
            gate.null_bests.len(),
            gate.null_ge_real,
            p
        );
        if gate.null_ge_real == 0 {
            println!(
                "VERDICT: Candidate — best \"{}\" clears the matched null (p = {:.3}); \
                 a hypothesis for human review, never a decode.",
                best.solution.rendered, p
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
            best.solution.rendered
        );
    }
}

fn render_truth_seed(rank: Option<usize>) -> String {
    rank.map_or_else(|| "not-harvested".to_owned(), |rank| format!("#{rank}"))
}

fn render_fate(fate: Option<TruthFate>) -> String {
    match fate {
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

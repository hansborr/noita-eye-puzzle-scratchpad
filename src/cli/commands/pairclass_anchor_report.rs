//! Anchor-seeded `pairclass` CLI reporting helpers.

use std::fmt::Write as _;

use noita_eye_puzzle::attack::pairclass::{
    AnchorHarvestReport, AnchorHarvestRetentionReport, AnchorPlantOutcome, AnchorPowerReport,
    AnchorSeedReport, NullGate, TruthFate,
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

pub(super) fn print_anchor_harvest_retention(
    args: &PairclassArgs,
    power: &AnchorHarvestRetentionReport,
) {
    println!();
    println!(
        "Controls-first anchor harvest-only retention ({} plants, mode {}, requested {}):",
        args.plants,
        harvest_mode_label(args.harvest_mode),
        args.phrase_top
    );
    for (index, plant) in power.plants.iter().enumerate() {
        println!(
            "  plant {:>2}: truth {}  harvest {}  window {} span {}  max-occ {}  \
             sat-pos {}  in-occ1 {}  completed {}  partial {}  cap-hit {}  budget-hit {}{}",
            index,
            render_truth_seed(plant.truth_seed_rank),
            plant.harvested,
            plant.window_len,
            plant.span_len,
            plant.max_occupancy,
            render_optional_usize(plant.saturation_position),
            render_occ1_saturation(plant.saturation_position, plant.span_len),
            render_optional_usize(plant.saturation_completed_occupancy),
            render_optional_usize(plant.saturation_partial_occupancy),
            yes_no(plant.cap_hit),
            yes_no(plant.budget_hit),
            render_harvest_overflow(plant.dropped_colorings, plant.parse_budget)
        );
        println!(
            "            occ1-widths {}",
            render_occ1_widths(&plant.layer_occupancies, plant.span_len)
        );
    }
}

pub(super) fn print_anchor_harvest_window(args: &PairclassArgs, harvest: &AnchorHarvestReport) {
    println!();
    println!(
        "Real anchor harvest-only window (mode {}, requested {}):",
        harvest_mode_label(args.harvest_mode),
        args.phrase_top
    );
    println!(
        "  harvest {}  window {} span {}  max-occ {}  sat-pos {}  in-occ1 {}  \
         completed {}  partial {}  cap-hit {}  budget-hit {}{}",
        harvest.distinct_colorings.len(),
        harvest.window.len,
        harvest.window.span_len,
        harvest.max_occupancy,
        render_optional_usize(harvest.saturation_position),
        render_occ1_saturation(harvest.saturation_position, harvest.window.span_len),
        render_optional_usize(harvest.saturation_completed_occupancy),
        render_optional_usize(harvest.saturation_partial_occupancy),
        yes_no(harvest.cap_hit),
        yes_no(harvest.budget_hit),
        render_harvest_overflow(harvest.dropped_colorings, harvest.parse_budget)
    );
    println!(
        "  occ1-widths {}",
        render_occ1_widths(&harvest.layer_occupancies, harvest.window.span_len)
    );
    println!();
    println!(
        "VERDICT: HarvestWindowOnly — the real stream window was harvested only; no Phase-2 solve \
         ran and no null ran."
    );
}

pub(super) fn print_anchor_harvest_verdict(power: &AnchorHarvestRetentionReport) {
    println!();
    if power.all_retained && !power.any_cap_hit && !power.any_budget_hit {
        println!(
            "VERDICT: HarvestRetained — truth retained on all plants without cap/budget saturation; \
             the real stream was NOT scored and no null ran."
        );
    } else if power.all_retained {
        println!(
            "VERDICT: HarvestRetainedAtSaturation — truth retained on all plants, but at least one \
             harvest hit the cap/budget; the real stream was NOT scored and no null ran."
        );
    } else if power.any_cap_hit || power.any_budget_hit {
        println!(
            "VERDICT: HarvestSaturatedMiss — at least one plant's true window coloring was not \
             retained before cap/budget saturation; this is a tractability result, not an \
             exhaustive anchor-negative. The real stream was NOT scored and no null ran."
        );
    } else {
        println!(
            "VERDICT: HarvestMissedTruth — at least one plant's true window coloring was not retained; \
             the real stream was NOT scored and no null ran."
        );
    }
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

fn harvest_mode_label(mode: crate::cli::args_pairclass::PairclassHarvestMode) -> &'static str {
    match mode {
        crate::cli::args_pairclass::PairclassHarvestMode::Beam => "beam",
        crate::cli::args_pairclass::PairclassHarvestMode::Enumerate => "enumerate",
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn render_optional_usize(value: Option<usize>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| value.to_string())
}

fn render_occ1_saturation(position: Option<usize>, span_len: usize) -> &'static str {
    match position {
        Some(position) if position < span_len => "yes",
        Some(_) => "no",
        None => "-",
    }
}

fn render_occ1_widths(widths: &[usize], span_len: usize) -> String {
    if widths.is_empty() {
        return "-".to_owned();
    }
    let take = widths.len().min(span_len.saturating_add(1));
    let mut out = String::new();
    for (index, width) in widths.iter().take(take).enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        let _ignored = write!(out, "{index}:{width}");
    }
    out
}

fn render_harvest_overflow(dropped: usize, parse_budget: Option<u64>) -> String {
    let budget = parse_budget.map_or_else(String::new, |budget| format!("  budget {budget}"));
    if dropped == 0 {
        budget
    } else {
        format!("  dropped {dropped}{budget}")
    }
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

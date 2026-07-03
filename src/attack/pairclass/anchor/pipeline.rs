//! Phase-2, controls, and null orchestration for anchor-seeded pairclass.

use std::collections::BTreeSet;

use super::{
    AnchorHarvestMode, AnchorHarvestReport, AnchorWindow, harvest_anchor_colorings_with_truth,
};
use crate::attack::pairclass::campaign::{NullGate, PowerCfg, StreamPrep};
use crate::attack::pairclass::plant::{
    CopySpan, Plant, PlantSpec, copy_ties, markov_resample, plant_from_text,
};
use crate::attack::pairclass::solve::{Solution, SolveCfg, SolveInput, TruthFate, solve};
use crate::attack::pairclass::ties::tie_targets;
use crate::attack::pairclass::{Lexicon, PairclassError};

/// One full-stream solution found from a harvested seed.
#[derive(Clone, Debug)]
pub struct AnchorSeededSolution {
    /// One-based harvest seed rank.
    pub seed_rank: usize,
    /// Phrase-window score of the seed coloring.
    pub seed_score: f32,
    /// Full-stream solution.
    pub solution: Solution,
}

/// Per-seed full solve summary.
#[derive(Clone, Debug)]
pub struct SeededOutcome {
    /// One-based harvest seed rank.
    pub seed_rank: usize,
    /// Best full-stream score from this seed.
    pub best_score: Option<f32>,
    /// Candidates offered during this full solve.
    pub expanded: u64,
    /// Feasible full-stream finals.
    pub feasible_final: usize,
    /// True-path fate for plant runs.
    pub truth: Option<TruthFate>,
}

/// Full two-phase anchor-seeded report.
#[derive(Clone, Debug)]
pub struct AnchorSeedReport {
    /// Phase-1 harvest report.
    pub harvest: AnchorHarvestReport,
    /// Number of harvested seeds attempted in Phase 2.
    pub seeds_run: usize,
    /// Per-seed full solve summaries.
    pub seed_outcomes: Vec<SeededOutcome>,
    /// Best distinct full-stream solutions across all seeds.
    pub solutions: Vec<AnchorSeededSolution>,
    /// Total candidates offered across harvest plus all seeded solves.
    pub total_expanded: u64,
    /// Maximum full-solve memory estimate across seeds.
    pub full_estimated_mib: usize,
    /// Peak estimate: max(phase 1, one phase-2 solve).
    pub estimated_peak_mib: usize,
}

/// One planted control under the anchor-seeded pipeline.
#[derive(Clone, Debug)]
pub struct AnchorPlantOutcome {
    /// Fraction of plant letters the best full solution recovered.
    pub recovery: f64,
    /// Fraction of the plant's used letters whose class was correct.
    pub coloring_accuracy: f64,
    /// Truth fate in the seeded solve that produced the winning full score.
    pub winning_fate: Option<TruthFate>,
    /// Truth fate inside the phrase-window harvest.
    pub truth_window_fate: Option<TruthFate>,
    /// One-based rank at which the true harvest-window coloring appeared.
    pub truth_seed_rank: Option<usize>,
    /// Distinct colorings harvested.
    pub harvested: usize,
    /// Seeded full solves attempted.
    pub seeds_run: usize,
    /// Phrase-harvest maximum kept-state occupancy.
    pub max_occupancy: usize,
    /// Whether the phrase beam saturated during harvest.
    pub saturated: bool,
    /// Best full-stream score.
    pub best_score: Option<f32>,
}

/// One planted control under the Phase-1-only anchor harvest.
#[derive(Clone, Debug)]
pub struct AnchorHarvestPlantOutcome {
    /// One-based rank at which the true harvest-window coloring appeared.
    pub truth_seed_rank: Option<usize>,
    /// Distinct colorings harvested.
    pub harvested: usize,
    /// Harvest-window length in tokens.
    pub window_len: usize,
    /// Repeated-span length in tokens.
    pub span_len: usize,
    /// Phrase-harvest maximum kept-state occupancy.
    pub max_occupancy: usize,
    /// Token position where enumeration first reached its budget.
    pub saturation_position: Option<usize>,
    /// Width of the last completed layer when the budget was hit.
    pub saturation_completed_occupancy: Option<usize>,
    /// Width of the in-progress next layer when the budget was hit.
    pub saturation_partial_occupancy: Option<usize>,
    /// Completed layer widths; index = consumed window tokens.
    pub layer_occupancies: Vec<usize>,
    /// Whether the distinct-coloring cap was hit.
    pub cap_hit: bool,
    /// Whether the deterministic parse budget was hit.
    pub budget_hit: bool,
    /// Distinct colorings dropped by cap selection.
    pub dropped_colorings: usize,
    /// Parse-transition budget for LM-free enumeration.
    pub parse_budget: Option<u64>,
}

/// Controls-first Phase-1-only anchor harvest retention report.
#[derive(Clone, Debug)]
pub struct AnchorHarvestRetentionReport {
    /// Per-plant outcomes.
    pub plants: Vec<AnchorHarvestPlantOutcome>,
    /// Whether every plant retained the true window coloring.
    pub all_retained: bool,
    /// Whether any plant hit the distinct-coloring cap.
    pub any_cap_hit: bool,
    /// Whether any plant hit the deterministic parse budget.
    pub any_budget_hit: bool,
}

/// Controls-first power report for the anchor-seeded pipeline.
#[derive(Clone, Debug)]
pub struct AnchorPowerReport {
    /// Per-plant outcomes.
    pub plants: Vec<AnchorPlantOutcome>,
    /// Mean letter recovery across plants.
    pub mean_recovery: f64,
    /// Mean coloring accuracy across plants.
    pub mean_coloring_accuracy: f64,
    /// Whether `mean_recovery` cleared the configured bar.
    pub cleared_bar: bool,
}

/// Parameters specific to anchor-mode Markov null gating.
#[derive(Clone, Copy, Debug)]
pub struct AnchorNullCfg {
    /// Number of Markov resamples.
    pub null_trials: usize,
    /// Real stream's best score.
    pub real_best: Option<f32>,
    /// Deterministic null seed.
    pub seed: u64,
}

/// Runs the full stream once per harvested coloring and keeps the best finals.
///
/// # Errors
/// Propagates harvest and solver errors.
pub fn solve_anchor_seeded(
    prep: &StreamPrep,
    lexicon: &Lexicon,
    phrase_cfg: &SolveCfg,
    full_cfg: &SolveCfg,
    phrase_top: usize,
    harvest_mode: AnchorHarvestMode,
    truth: Option<&[u8]>,
) -> Result<AnchorSeedReport, PairclassError> {
    let harvest = harvest_anchor_colorings_with_truth(
        prep,
        lexicon,
        phrase_cfg,
        phrase_top,
        harvest_mode,
        truth,
    )?;
    let tie_to = (!prep.tie_table.is_empty()).then_some(prep.tie_table.as_slice());
    let mut outcomes = Vec::with_capacity(harvest.distinct_colorings.len());
    let mut collected = Vec::new();
    let mut total_expanded = harvest.expanded;
    let mut full_estimated_mib = 0usize;
    for seed in &harvest.distinct_colorings {
        let report = solve(
            &SolveInput {
                tokens: &prep.tokens,
                n_classes: prep.n_classes,
                tie_to,
                lexicon,
                truth,
                seed_coloring: Some(&seed.coloring),
                accept_partial_final: false,
            },
            full_cfg,
        )?;
        total_expanded = total_expanded.saturating_add(report.expanded);
        full_estimated_mib = full_estimated_mib.max(report.estimated_mib);
        outcomes.push(SeededOutcome {
            seed_rank: seed.rank,
            best_score: report.solutions.first().map(|solution| solution.score),
            expanded: report.expanded,
            feasible_final: report.feasible_final,
            truth: report.truth,
        });
        for solution in report.solutions {
            collected.push(AnchorSeededSolution {
                seed_rank: seed.rank,
                seed_score: seed.score,
                solution,
            });
        }
    }
    let solutions = rank_seeded_solutions(collected, full_cfg.top);
    let seeds_run = harvest.distinct_colorings.len();
    let estimated_peak_mib = harvest.estimated_mib.max(full_estimated_mib);
    Ok(AnchorSeedReport {
        harvest,
        seeds_run,
        seed_outcomes: outcomes,
        solutions,
        total_expanded,
        full_estimated_mib,
        estimated_peak_mib,
    })
}

/// Runs planted controls through the same two-phase pipeline as the real stream.
///
/// # Errors
/// Propagates plant construction, harvest, and solver errors.
pub fn measure_anchor_seed_power(
    text: &str,
    power: &PowerCfg,
    lexicon: &Lexicon,
    phrase_cfg: &SolveCfg,
    full_cfg: &SolveCfg,
    phrase_top: usize,
    harvest_mode: AnchorHarvestMode,
) -> Result<AnchorPowerReport, PairclassError> {
    let letters = text_letters(text);
    let copy = tie_to_copy(power.longest_tie, power.plant_len);
    let mut plants = Vec::with_capacity(power.n_plants);
    for index in 0..power.n_plants {
        let start = plant_slice_start(letters.len(), power.plant_len, index, power.n_plants);
        let source: String = letters
            .get(start..)
            .unwrap_or(&[])
            .iter()
            .map(|&letter| char::from(b'a' + letter.min(25)))
            .collect();
        let spec = PlantSpec {
            len: power.plant_len,
            n_classes: power.n_classes,
            copy,
        };
        let plant = plant_from_text(&source, &spec, power.seed.wrapping_add(index as u64))?;
        let prep = plant_prep(&plant, copy)?;
        plants.push(solve_anchor_plant(
            &plant,
            &prep,
            lexicon,
            phrase_cfg,
            full_cfg,
            phrase_top,
            harvest_mode,
        )?);
    }
    let mean_recovery = mean(plants.iter().map(|plant| plant.recovery));
    let mean_coloring_accuracy = mean(plants.iter().map(|plant| plant.coloring_accuracy));
    Ok(AnchorPowerReport {
        plants,
        mean_recovery,
        mean_coloring_accuracy,
        cleared_bar: mean_recovery >= power.bar,
    })
}

/// Runs planted controls through Phase 1 only and reports true-coloring retention.
///
/// # Errors
/// Propagates plant construction and harvest errors.
pub fn measure_anchor_harvest_retention(
    text: &str,
    power: &PowerCfg,
    lexicon: &Lexicon,
    phrase_cfg: &SolveCfg,
    phrase_top: usize,
    harvest_mode: AnchorHarvestMode,
) -> Result<AnchorHarvestRetentionReport, PairclassError> {
    let letters = text_letters(text);
    let copy = tie_to_copy(power.longest_tie, power.plant_len);
    let mut plants = Vec::with_capacity(power.n_plants);
    for index in 0..power.n_plants {
        let start = plant_slice_start(letters.len(), power.plant_len, index, power.n_plants);
        let source: String = letters
            .get(start..)
            .unwrap_or(&[])
            .iter()
            .map(|&letter| char::from(b'a' + letter.min(25)))
            .collect();
        let spec = PlantSpec {
            len: power.plant_len,
            n_classes: power.n_classes,
            copy,
        };
        let plant = plant_from_text(&source, &spec, power.seed.wrapping_add(index as u64))?;
        let prep = plant_prep(&plant, copy)?;
        let harvest = harvest_anchor_colorings_with_truth(
            &prep,
            lexicon,
            phrase_cfg,
            phrase_top,
            harvest_mode,
            Some(&plant.letters),
        )?;
        plants.push(AnchorHarvestPlantOutcome {
            truth_seed_rank: truth_seed_rank(&plant, &harvest),
            harvested: harvest.distinct_colorings.len(),
            window_len: harvest.window.len,
            span_len: harvest.window.span_len,
            max_occupancy: harvest.max_occupancy,
            saturation_position: harvest.saturation_position,
            saturation_completed_occupancy: harvest.saturation_completed_occupancy,
            saturation_partial_occupancy: harvest.saturation_partial_occupancy,
            layer_occupancies: harvest.layer_occupancies.clone(),
            cap_hit: harvest.cap_hit,
            budget_hit: harvest.budget_hit,
            dropped_colorings: harvest.dropped_colorings,
            parse_budget: harvest.parse_budget,
        });
    }
    let all_retained = plants.iter().all(|plant| plant.truth_seed_rank.is_some());
    let any_cap_hit = plants.iter().any(|plant| plant.cap_hit);
    let any_budget_hit = plants.iter().any(|plant| plant.budget_hit);
    Ok(AnchorHarvestRetentionReport {
        plants,
        all_retained,
        any_cap_hit,
        any_budget_hit,
    })
}

/// Runs the anchor-seeded pipeline on order-1 Markov resamples.
///
/// # Errors
/// Propagates resample, harvest, and solver errors.
pub fn anchor_null_gate(
    prep: &StreamPrep,
    lexicon: &Lexicon,
    phrase_cfg: &SolveCfg,
    full_cfg: &SolveCfg,
    phrase_top: usize,
    harvest_mode: AnchorHarvestMode,
    null_cfg: &AnchorNullCfg,
) -> Result<NullGate, PairclassError> {
    let mut null_bests = Vec::with_capacity(null_cfg.null_trials);
    let mut null_ge_real = 0usize;
    for trial in 0..null_cfg.null_trials {
        let tokens = markov_resample(
            &prep.tokens,
            prep.n_classes,
            null_cfg.seed.wrapping_add(trial as u64),
        )?;
        let null_prep = StreamPrep {
            tokens,
            n_classes: prep.n_classes,
            tie_table: prep.tie_table.clone(),
            n_tied: prep.n_tied,
            longest_tie: prep.longest_tie,
        };
        let report = solve_anchor_seeded(
            &null_prep,
            lexicon,
            phrase_cfg,
            full_cfg,
            phrase_top,
            harvest_mode,
            None,
        )?;
        let best = report.solutions.first().map(|seeded| seeded.solution.score);
        if let (Some(null), Some(real)) = (best, null_cfg.real_best)
            && null >= real
        {
            null_ge_real += 1;
        }
        null_bests.push(best);
    }
    Ok(NullGate {
        real_best: null_cfg.real_best,
        null_bests,
        null_ge_real,
    })
}

/// Ranks full solutions across seeds and deduplicates by decoded letters.
fn rank_seeded_solutions(
    mut solutions: Vec<AnchorSeededSolution>,
    limit: usize,
) -> Vec<AnchorSeededSolution> {
    solutions.sort_by(|a, b| {
        b.solution
            .score
            .total_cmp(&a.solution.score)
            .then_with(|| a.seed_rank.cmp(&b.seed_rank))
            .then_with(|| a.solution.letters.cmp(&b.solution.letters))
    });
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for solution in solutions {
        if seen.insert(solution.solution.letters.clone()) {
            out.push(solution);
            if out.len() >= limit {
                break;
            }
        }
    }
    out
}

/// Solves and scores one planted control.
fn solve_anchor_plant(
    plant: &Plant,
    prep: &StreamPrep,
    lexicon: &Lexicon,
    phrase_cfg: &SolveCfg,
    full_cfg: &SolveCfg,
    phrase_top: usize,
    harvest_mode: AnchorHarvestMode,
) -> Result<AnchorPlantOutcome, PairclassError> {
    let report = solve_anchor_seeded(
        prep,
        lexicon,
        phrase_cfg,
        full_cfg,
        phrase_top,
        harvest_mode,
        Some(&plant.letters),
    )?;
    let truth_seed_rank = truth_seed_rank(plant, &report.harvest);
    let best = report.solutions.first();
    let winning_fate = best.and_then(|seeded| {
        report
            .seed_outcomes
            .iter()
            .find(|outcome| outcome.seed_rank == seeded.seed_rank)
            .and_then(|outcome| outcome.truth)
    });
    Ok(AnchorPlantOutcome {
        recovery: best.map_or(0.0, |seeded| {
            letter_recovery(&seeded.solution.letters, &plant.letters)
        }),
        coloring_accuracy: best.map_or(0.0, |seeded| coloring_accuracy(&seeded.solution, plant)),
        winning_fate,
        truth_window_fate: report.harvest.truth,
        truth_seed_rank,
        harvested: report.harvest.distinct_colorings.len(),
        seeds_run: report.seeds_run,
        max_occupancy: report.harvest.max_occupancy,
        saturated: report.harvest.saturated,
        best_score: best.map(|seeded| seeded.solution.score),
    })
}

/// Builds a plant stream prep with the imposed copy span as its longest tie.
fn plant_prep(plant: &Plant, copy: Option<CopySpan>) -> Result<StreamPrep, PairclassError> {
    let (tie_table, n_tied, longest_tie) = if let Some(span) = copy {
        let table = tie_targets(&copy_ties(span, plant.tokens.len())?, plant.tokens.len());
        let n_tied = table.iter().filter(|slot| slot.is_some()).count();
        (table, n_tied, Some((span.src, span.dst, span.len)))
    } else {
        (Vec::new(), 0, None)
    };
    Ok(StreamPrep {
        tokens: plant.tokens.clone(),
        n_classes: max_class(&plant.tokens),
        tie_table,
        n_tied,
        longest_tie,
    })
}

/// Maps the real stream's anchor length into the plant topology.
fn tie_to_copy(longest_tie: Option<(usize, usize, usize)>, plant_len: usize) -> Option<CopySpan> {
    let (_src, _dst, span_len) = longest_tie?;
    let span_len = span_len.min(plant_len / 3).max(1);
    if plant_len < 3 * span_len {
        return None;
    }
    Some(CopySpan {
        src: 0,
        dst: plant_len / 3,
        len: span_len,
    })
}

/// Finds the rank where the harvest surfaced the plant's true window coloring.
fn truth_seed_rank(plant: &Plant, harvest: &AnchorHarvestReport) -> Option<usize> {
    let truth = truth_window_coloring(plant, harvest.window);
    harvest
        .distinct_colorings
        .iter()
        .position(|seed| seed.coloring == truth)
        .map(|index| index + 1)
}

/// True coloring restricted to letters used in the harvest window.
fn truth_window_coloring(plant: &Plant, window: AnchorWindow) -> [Option<u8>; 26] {
    let mut coloring = [None; 26];
    let end = window.start.saturating_add(window.len);
    for &letter in plant.letters.get(window.start..end).unwrap_or(&[]) {
        if let Some(slot) = coloring.get_mut(usize::from(letter)) {
            *slot = plant.coloring.get(usize::from(letter)).copied();
        }
    }
    coloring
}

/// Fraction of positions where `found` equals `truth`.
fn letter_recovery(found: &[u8], truth: &[u8]) -> f64 {
    if truth.is_empty() {
        return 0.0;
    }
    let matched = found.iter().zip(truth).filter(|(a, b)| a == b).count();
    matched as f64 / truth.len() as f64
}

/// Fraction of the plant's used letters whose induced class matches truth.
fn coloring_accuracy(solution: &Solution, plant: &Plant) -> f64 {
    let mut used = [false; 26];
    for &letter in &plant.letters {
        if let Some(slot) = used.get_mut(usize::from(letter)) {
            *slot = true;
        }
    }
    let total = used.iter().filter(|slot| **slot).count();
    if total == 0 {
        return 0.0;
    }
    let mut correct = 0usize;
    for (letter, is_used) in used.iter().enumerate() {
        if !is_used {
            continue;
        }
        let induced = solution.coloring.get(letter).copied().flatten();
        let truth = plant.coloring.get(letter).copied();
        if let (Some(induced), Some(truth)) = (induced, truth)
            && induced == truth
        {
            correct += 1;
        }
    }
    correct as f64 / total as f64
}

/// The class count in use for a token stream.
fn max_class(tokens: &[u8]) -> u8 {
    tokens.iter().copied().max().map_or(1, |max| max + 1)
}

/// Extracts lowercase letters from source text.
fn text_letters(text: &str) -> Vec<u8> {
    text.chars()
        .filter_map(|ch| {
            let lower = ch.to_ascii_lowercase();
            lower.is_ascii_lowercase().then(|| lower as u8 - b'a')
        })
        .collect()
}

/// Distinct start offsets so plants sample different regions of the source.
fn plant_slice_start(available: usize, plant_len: usize, index: usize, n_plants: usize) -> usize {
    if available <= plant_len || n_plants == 0 {
        return 0;
    }
    let span = available - plant_len;
    (span / n_plants.max(1)) * index
}

/// Arithmetic mean of an iterator of `f64` (`0.0` when empty).
fn mean(values: impl Iterator<Item = f64>) -> f64 {
    let (sum, count) = values.fold((0.0, 0usize), |(sum, count), value| {
        (sum + value, count + 1)
    });
    if count == 0 { 0.0 } else { sum / count as f64 }
}

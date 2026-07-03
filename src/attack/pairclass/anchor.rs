//! Anchor-seeded two-phase search for the pair-class solver.
//!
//! Phase 1 solves the dense repeated-span window that covers both occurrences
//! of the longest token tie, with the equality ties active. It harvests the
//! top distinct induced colorings. Phase 2 lives in this module's later
//! orchestration helpers; this file starts with the harvest primitive so it
//! can be tested independently.

mod enumerate;
mod pipeline;

use std::collections::BTreeMap;

use enumerate::harvest_anchor_colorings_enumerate;

pub use pipeline::{
    AnchorHarvestPlantOutcome, AnchorHarvestRetentionReport, AnchorNullCfg, AnchorPlantOutcome,
    AnchorPowerReport, AnchorSeedReport, AnchorSeededSolution, SeededOutcome, anchor_null_gate,
    measure_anchor_harvest_retention, measure_anchor_seed_power, solve_anchor_seeded,
};

use super::campaign::StreamPrep;
use super::solve::{Solution, SolveCfg, SolveInput, TruthFate, solve};
use super::ties::tie_targets;
use super::{Lexicon, PairclassError};

/// Hard cap on distinct harvested seed colorings.
pub const MAX_HARVEST_COLORINGS: usize = 50_000;

/// Number of phrase segmentations examined per requested distinct coloring.
const HARVEST_OVERSAMPLE: usize = 4;

/// Phase-1 harvest strategy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorHarvestMode {
    /// Existing word-LM score-beam harvest.
    ScoreBeam,
    /// LM-free hard-constraint window enumeration.
    Enumerate,
}

/// A contiguous two-occurrence anchor window in token coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorWindow {
    /// Start in the full token stream.
    pub start: usize,
    /// Window length in tokens.
    pub len: usize,
    /// Offset of the earlier repeated span within the window.
    pub first_offset: usize,
    /// Offset of the later repeated span within the window.
    pub second_offset: usize,
    /// Length of the tied phrase in tokens.
    pub span_len: usize,
}

/// One distinct coloring harvested from the phrase window.
#[derive(Clone, Debug)]
pub struct HarvestedColoring {
    /// One-based rank of the phrase solution that first produced this coloring.
    pub rank: usize,
    /// Phrase-window score of that solution (`0.0` for LM-free enumeration).
    pub score: f32,
    /// Number of letters pinned by this coloring.
    pub pinned: usize,
    /// Gap segments used by the representative parse.
    pub gaps_used: u8,
    /// Gap letters used by the representative parse.
    pub gap_letters: usize,
    /// Class per plaintext letter; `None` means the phrase did not use it.
    pub coloring: [Option<u8>; 26],
    /// Phrase-window rendering for diagnostics.
    pub rendered: String,
}

/// Phrase-harvest report.
#[derive(Clone, Debug)]
pub struct AnchorHarvestReport {
    /// Harvest strategy used to produce the report.
    pub mode: AnchorHarvestMode,
    /// The two-occurrence window that was solved.
    pub window: AnchorWindow,
    /// Requested distinct-coloring count.
    pub requested_top: usize,
    /// Effective distinct-coloring target after beam/cap limits.
    pub effective_top: usize,
    /// Phrase solutions inspected before deduplication.
    pub solutions_seen: usize,
    /// Distinct harvested colorings, ranked best first.
    pub distinct_colorings: Vec<HarvestedColoring>,
    /// Candidates offered to phrase-beam selection.
    pub expanded: u64,
    /// Feasible phrase finals.
    pub feasible_final: usize,
    /// Maximum kept-state occupancy in the phrase solve.
    pub max_occupancy: usize,
    /// Token position where LM-free enumeration first reached its budget.
    pub saturation_position: Option<usize>,
    /// Width of the last fully completed layer when the budget was hit.
    pub saturation_completed_occupancy: Option<usize>,
    /// Width of the in-progress next layer when the budget was hit.
    pub saturation_partial_occupancy: Option<usize>,
    /// Completed layer widths; index = number of consumed window tokens.
    pub layer_occupancies: Vec<usize>,
    /// Whether the phrase beam filled, proving score-based pruning occurred.
    pub saturated: bool,
    /// The phrase solve's checked peak-memory estimate.
    pub estimated_mib: usize,
    /// Truth fate inside the phrase-window harvest, for planted controls.
    pub truth: Option<TruthFate>,
    /// Whether the distinct-coloring cap was hit.
    pub cap_hit: bool,
    /// Whether the LM-free enumerator hit its deterministic parse budget.
    pub budget_hit: bool,
    /// Distinct colorings dropped by the cap's LM-free coverage selection.
    pub dropped_colorings: usize,
    /// Deterministic parse-transition budget for LM-free enumeration.
    pub parse_budget: Option<u64>,
}

/// Harvests distinct seed colorings from the two-occurrence anchor window.
///
/// # Errors
/// Propagates solver errors, rejects missing or malformed anchors, and enforces
/// the fixed harvest-size cap.
pub fn harvest_anchor_colorings(
    prep: &StreamPrep,
    lexicon: &Lexicon,
    phrase_cfg: &SolveCfg,
    phrase_top: usize,
    mode: AnchorHarvestMode,
) -> Result<AnchorHarvestReport, PairclassError> {
    harvest_anchor_colorings_with_truth(prep, lexicon, phrase_cfg, phrase_top, mode, None)
}

/// Harvests colorings while tracking full-stream truth restricted to the window.
fn harvest_anchor_colorings_with_truth(
    prep: &StreamPrep,
    lexicon: &Lexicon,
    phrase_cfg: &SolveCfg,
    phrase_top: usize,
    mode: AnchorHarvestMode,
    truth: Option<&[u8]>,
) -> Result<AnchorHarvestReport, PairclassError> {
    let window = anchor_window(prep)?;
    let effective_top = effective_phrase_top(mode, phrase_cfg.beam, phrase_top)?;
    let end = window
        .start
        .checked_add(window.len)
        .ok_or(PairclassError::SpanOutOfRange)?;
    let tokens = prep
        .tokens
        .get(window.start..end)
        .ok_or(PairclassError::SpanOutOfRange)?;
    let truth_window = truth
        .map(|letters| {
            letters
                .get(window.start..end)
                .ok_or(PairclassError::TruthLengthMismatch {
                    truth: letters.len(),
                    tokens: prep.tokens.len(),
                })
        })
        .transpose()?;
    let tie_table = window_ties(window);
    let input = HarvestWindowInput {
        window,
        requested_top: phrase_top,
        effective_top,
        tokens,
        n_classes: prep.n_classes,
        tie_table: &tie_table,
        lexicon,
    };
    match mode {
        AnchorHarvestMode::ScoreBeam => {
            harvest_anchor_colorings_score_beam(input, phrase_cfg, truth_window)
        }
        AnchorHarvestMode::Enumerate => harvest_anchor_colorings_enumerate(input, phrase_cfg),
    }
}

/// Shared harvest-window context after anchor extraction.
#[derive(Clone, Copy)]
struct HarvestWindowInput<'a> {
    window: AnchorWindow,
    requested_top: usize,
    effective_top: usize,
    tokens: &'a [u8],
    n_classes: u8,
    tie_table: &'a [Option<usize>],
    lexicon: &'a Lexicon,
}

/// Existing LM score-beam harvest.
fn harvest_anchor_colorings_score_beam(
    input: HarvestWindowInput<'_>,
    phrase_cfg: &SolveCfg,
    truth_window: Option<&[u8]>,
) -> Result<AnchorHarvestReport, PairclassError> {
    let mut cfg = *phrase_cfg;
    cfg.top = phrase_solution_cap(phrase_cfg.beam, input.effective_top);
    let report = solve(
        &SolveInput {
            tokens: input.tokens,
            n_classes: input.n_classes,
            tie_to: Some(input.tie_table),
            lexicon: input.lexicon,
            truth: truth_window,
            seed_coloring: None,
            accept_partial_final: true,
        },
        &cfg,
    )?;
    let saturated = report.max_occupancy >= phrase_cfg.beam;
    let solutions_seen = report.solutions.len();
    let distinct_colorings = dedup_colorings(report.solutions, input.effective_top);
    Ok(AnchorHarvestReport {
        mode: AnchorHarvestMode::ScoreBeam,
        window: input.window,
        requested_top: input.requested_top,
        effective_top: input.effective_top,
        solutions_seen,
        distinct_colorings,
        expanded: report.expanded,
        feasible_final: report.feasible_final,
        max_occupancy: report.max_occupancy,
        saturation_position: None,
        saturation_completed_occupancy: None,
        saturation_partial_occupancy: None,
        layer_occupancies: Vec::new(),
        saturated,
        estimated_mib: report.estimated_mib,
        truth: report.truth,
        cap_hit: false,
        budget_hit: false,
        dropped_colorings: 0,
        parse_budget: None,
    })
}

/// Builds the minimal contiguous window covering both occurrences.
fn anchor_window(prep: &StreamPrep) -> Result<AnchorWindow, PairclassError> {
    let (src, dst, span_len) = prep.longest_tie.ok_or(PairclassError::AnchorUnavailable)?;
    if span_len == 0 || src >= dst {
        return Err(PairclassError::SpanOutOfRange);
    }
    let end = dst
        .checked_add(span_len)
        .ok_or(PairclassError::SpanOutOfRange)?;
    if end > prep.tokens.len() {
        return Err(PairclassError::SpanOutOfRange);
    }
    Ok(AnchorWindow {
        start: src,
        len: end - src,
        first_offset: 0,
        second_offset: dst - src,
        span_len,
    })
}

/// Local tie table for the two repeated phrases inside `window`.
fn window_ties(window: AnchorWindow) -> Vec<Option<usize>> {
    let pairs: Vec<(usize, usize)> = (0..window.span_len)
        .map(|offset| (window.first_offset + offset, window.second_offset + offset))
        .collect();
    tie_targets(&pairs, window.len)
}

/// Validates and bounds the requested distinct-coloring target.
fn effective_phrase_top(
    mode: AnchorHarvestMode,
    beam: usize,
    phrase_top: usize,
) -> Result<usize, PairclassError> {
    if beam == 0 {
        return Err(PairclassError::BeamZero);
    }
    if phrase_top == 0 {
        return Err(PairclassError::PhraseTopZero);
    }
    if phrase_top > MAX_HARVEST_COLORINGS {
        return Err(PairclassError::PhraseTopTooLarge {
            requested: phrase_top,
            cap: MAX_HARVEST_COLORINGS,
        });
    }
    Ok(match mode {
        AnchorHarvestMode::ScoreBeam => phrase_top.min(beam),
        AnchorHarvestMode::Enumerate => phrase_top,
    })
}

/// Number of phrase solutions to ask the ordinary solver to render.
fn phrase_solution_cap(beam: usize, effective_top: usize) -> usize {
    effective_top
        .saturating_mul(HARVEST_OVERSAMPLE)
        .min(beam)
        .min(MAX_HARVEST_COLORINGS)
}

/// Deduplicates phrase solutions by coloring, preserving rank diagnostics.
fn dedup_colorings(solutions: Vec<Solution>, limit: usize) -> Vec<HarvestedColoring> {
    let mut by_coloring: BTreeMap<[Option<u8>; 26], HarvestedColoring> = BTreeMap::new();
    for (index, solution) in solutions.into_iter().enumerate() {
        let pinned = solution
            .coloring
            .iter()
            .filter(|slot| slot.is_some())
            .count();
        let candidate = HarvestedColoring {
            rank: index + 1,
            score: solution.score,
            pinned,
            gaps_used: solution.gaps_used,
            gap_letters: solution
                .rendered
                .bytes()
                .filter(u8::is_ascii_uppercase)
                .count(),
            coloring: solution.coloring,
            rendered: solution.rendered,
        };
        let _slot = by_coloring
            .entry(candidate.coloring)
            .and_modify(|existing| {
                if candidate.score > existing.score {
                    *existing = candidate.clone();
                }
            })
            .or_insert(candidate);
    }
    let mut out: Vec<HarvestedColoring> = by_coloring.into_values().collect();
    out.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| b.pinned.cmp(&a.pinned))
            .then_with(|| a.rank.cmp(&b.rank))
            .then_with(|| a.coloring.cmp(&b.coloring))
    });
    out.truncate(limit);
    out
}

//! Anchor-seeded two-phase search for the pair-class solver.
//!
//! Phase 1 solves the dense repeated-span window that covers both occurrences
//! of the longest token tie, with the equality ties active. It harvests the
//! top distinct induced colorings. Phase 2 lives in this module's later
//! orchestration helpers; this file starts with the harvest primitive so it
//! can be tested independently.

mod pipeline;

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

pub use pipeline::{
    AnchorHarvestPlantOutcome, AnchorHarvestRetentionReport, AnchorNullCfg, AnchorPlantOutcome,
    AnchorPowerReport, AnchorSeedReport, AnchorSeededSolution, SeededOutcome, anchor_null_gate,
    measure_anchor_harvest_retention, measure_anchor_seed_power, solve_anchor_seeded,
};

use super::campaign::StreamPrep;
use super::lexicon::ROOT;
use super::solve::{
    Solution, SolveCfg, SolveInput, TruthFate, estimate_peak_mib, pin_class, solve,
};
use super::ties::tie_targets;
use super::{Lexicon, PairclassError};

/// Hard cap on distinct harvested seed colorings.
pub const MAX_HARVEST_COLORINGS: usize = 50_000;

/// Number of phrase segmentations examined per requested distinct coloring.
const HARVEST_OVERSAMPLE: usize = 4;

/// Maximum parse transitions visited by the LM-free enumerator.
const ENUMERATE_MAX_PARSE_BUDGET: u64 = 100_000_000;

/// Minimum parse transitions visited before budget saturation is possible.
const ENUMERATE_MIN_PARSE_BUDGET: u64 = 1_000_000;

/// Parse-budget multiplier applied to `phrase_cfg.beam * window_len`.
const ENUMERATE_PARSE_BUDGET_FACTOR: u64 = 4;

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
        saturated,
        estimated_mib: report.estimated_mib,
        truth: report.truth,
        cap_hit: false,
        budget_hit: false,
        dropped_colorings: 0,
        parse_budget: None,
    })
}

/// LM-free hard-constraint window enumeration harvest.
fn harvest_anchor_colorings_enumerate(
    input: HarvestWindowInput<'_>,
    phrase_cfg: &SolveCfg,
) -> Result<AnchorHarvestReport, PairclassError> {
    validate_enumeration_input(input.tokens, input.n_classes, input.tie_table)?;
    let estimated_mib = estimate_peak_mib(
        input.tokens.len(),
        input.effective_top,
        input.lexicon.n_nodes(),
    );
    if estimated_mib > phrase_cfg.max_mem_mib {
        return Err(PairclassError::MemoryCap {
            estimated_mib,
            cap_mib: phrase_cfg.max_mem_mib,
        });
    }
    let parse_budget = enumerate_parse_budget(phrase_cfg.beam, input.tokens.len());
    let enum_cfg = EnumerateCfg {
        max_gaps: phrase_cfg.max_gaps.max(2),
        max_gap_len: phrase_cfg
            .max_gap_len
            .max(input.window.len.min(usize::from(u8::MAX)) as u8),
        limit: input.effective_top,
        parse_budget,
    };
    let result = Enumerator::new(
        input.tokens,
        input.n_classes,
        input.tie_table,
        input.lexicon,
        enum_cfg,
    )
    .run();
    Ok(AnchorHarvestReport {
        mode: AnchorHarvestMode::Enumerate,
        window: input.window,
        requested_top: input.requested_top,
        effective_top: input.effective_top,
        solutions_seen: result.feasible_final,
        distinct_colorings: result.distinct_colorings,
        expanded: result.expanded,
        feasible_final: result.feasible_final,
        max_occupancy: result.max_retained,
        saturated: result.cap_hit || result.budget_hit,
        estimated_mib,
        truth: None,
        cap_hit: result.cap_hit,
        budget_hit: result.budget_hit,
        dropped_colorings: result.dropped_colorings,
        parse_budget: Some(parse_budget),
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

/// Validates the subset of [`SolveInput`] contract needed by enumeration.
fn validate_enumeration_input(
    tokens: &[u8],
    n_classes: u8,
    tie_table: &[Option<usize>],
) -> Result<(), PairclassError> {
    if tokens.is_empty() {
        return Err(PairclassError::EmptyInput);
    }
    if n_classes == 0 || n_classes > super::MAX_CLASSES {
        return Err(PairclassError::TooManyClasses {
            found: usize::from(n_classes),
        });
    }
    if let Some(bad) = tokens.iter().find(|&&token| token >= n_classes) {
        return Err(PairclassError::TooManyClasses {
            found: usize::from(*bad) + 1,
        });
    }
    if tie_table.len() != tokens.len() {
        return Err(PairclassError::SpanOutOfRange);
    }
    let broken = tie_table
        .iter()
        .enumerate()
        .any(|(position, target)| target.is_some_and(|src| src >= position));
    if broken {
        return Err(PairclassError::SpanOutOfRange);
    }
    Ok(())
}

/// Deterministic transition budget for LM-free enumeration.
fn enumerate_parse_budget(phrase_beam: usize, window_len: usize) -> u64 {
    let scaled = (phrase_beam as u64)
        .saturating_mul(window_len.max(1) as u64)
        .saturating_mul(ENUMERATE_PARSE_BUDGET_FACTOR);
    scaled.clamp(ENUMERATE_MIN_PARSE_BUDGET, ENUMERATE_MAX_PARSE_BUDGET)
}

/// Enumeration policy derived from the phrase-harvest config.
#[derive(Clone, Copy)]
struct EnumerateCfg {
    max_gaps: u8,
    max_gap_len: u8,
    limit: usize,
    parse_budget: u64,
}

/// One recursive parse state. The tied letter history lives in `EnumPath`.
#[derive(Clone, Copy)]
struct EnumState {
    position: usize,
    node: u32,
    gap_len: u8,
    gaps_used: u8,
    gap_letters: usize,
    classes: u64,
    pinned: u32,
}

/// One accepted transition out of a parse state.
#[derive(Clone, Copy)]
struct EnumTransition {
    letter: u8,
    node: u32,
    gap_len: u8,
    gaps_used: u8,
    gap: bool,
    segment_start: bool,
}

impl EnumState {
    fn root() -> Self {
        Self {
            position: 0,
            node: ROOT,
            gap_len: 0,
            gaps_used: 0,
            gap_letters: 0,
            classes: 0,
            pinned: 0,
        }
    }
}

/// Mutable parse backtrace, retained only to enforce ties and render finals.
struct EnumPath {
    letters: Vec<u8>,
    gaps: Vec<bool>,
    segment_starts: Vec<bool>,
}

impl EnumPath {
    fn with_capacity(len: usize) -> Self {
        Self {
            letters: Vec::with_capacity(len),
            gaps: Vec::with_capacity(len),
            segment_starts: Vec::with_capacity(len),
        }
    }

    fn push(&mut self, letter: u8, gap: bool, segment_start: bool) {
        self.letters.push(letter);
        self.gaps.push(gap);
        self.segment_starts.push(segment_start);
    }

    fn pop(&mut self) {
        let _letter = self.letters.pop();
        let _gap = self.gaps.pop();
        let _start = self.segment_starts.pop();
    }

    fn render(&self) -> String {
        let mut out = String::with_capacity(self.letters.len() + self.letters.len() / 4);
        for (index, &letter) in self.letters.iter().enumerate() {
            if index > 0 && self.segment_starts.get(index).copied().unwrap_or(false) {
                out.push(' ');
            }
            let ch = char::from(b'a' + letter.min(super::N_LETTERS - 1));
            if self.gaps.get(index).copied().unwrap_or(false) {
                out.push(ch.to_ascii_uppercase());
            } else {
                out.push(ch);
            }
        }
        out
    }
}

/// Enumeration result before conversion into [`AnchorHarvestReport`].
struct EnumerateResult {
    distinct_colorings: Vec<HarvestedColoring>,
    expanded: u64,
    feasible_final: usize,
    max_retained: usize,
    cap_hit: bool,
    budget_hit: bool,
    dropped_colorings: usize,
}

/// LM-free window enumerator.
struct Enumerator<'a> {
    tokens: &'a [u8],
    n_classes: u8,
    tie_table: &'a [Option<usize>],
    lexicon: &'a Lexicon,
    cfg: EnumerateCfg,
    path: EnumPath,
    collector: ColoringCollector,
    expanded: u64,
    feasible_final: usize,
    budget_hit: bool,
    gap_letter_limit: usize,
}

impl<'a> Enumerator<'a> {
    fn new(
        tokens: &'a [u8],
        n_classes: u8,
        tie_table: &'a [Option<usize>],
        lexicon: &'a Lexicon,
        cfg: EnumerateCfg,
    ) -> Self {
        Self {
            tokens,
            n_classes,
            tie_table,
            lexicon,
            cfg,
            path: EnumPath::with_capacity(tokens.len()),
            collector: ColoringCollector::new(cfg.limit),
            expanded: 0,
            feasible_final: 0,
            budget_hit: false,
            gap_letter_limit: 0,
        }
    }

    fn run(mut self) -> EnumerateResult {
        for gap_letter_limit in 0..=self.tokens.len() {
            self.gap_letter_limit = gap_letter_limit;
            self.walk(EnumState::root());
            if self.budget_hit {
                break;
            }
        }
        let max_retained = self.collector.len();
        let (distinct_colorings, cap_hit, dropped_colorings) = self.collector.finish();
        EnumerateResult {
            distinct_colorings,
            expanded: self.expanded,
            feasible_final: self.feasible_final,
            max_retained,
            cap_hit,
            budget_hit: self.budget_hit,
            dropped_colorings,
        }
    }

    fn walk(&mut self, state: EnumState) {
        if self.budget_hit {
            return;
        }
        if state.position == self.tokens.len() {
            self.collect_final(state);
            return;
        }
        let Some(&token) = self.tokens.get(state.position) else {
            return;
        };
        if let Some(src) = self.tie_table.get(state.position).copied().flatten() {
            if let Some(&letter) = self.path.letters.get(src) {
                self.try_letter(state, letter, token);
            }
            return;
        }
        for letter in 0..super::N_LETTERS {
            self.try_letter(state, letter, token);
            if self.budget_hit {
                break;
            }
        }
    }

    fn try_letter(&mut self, state: EnumState, letter: u8, token: u8) {
        if letter >= super::N_LETTERS || token >= self.n_classes {
            return;
        }
        let Some((classes, pinned)) = pin_class(state.classes, state.pinned, letter, token) else {
            return;
        };
        let pinned_state = EnumState {
            classes,
            pinned,
            ..state
        };
        if state.gap_len > 0 {
            if let Some(child) = self.lexicon.child(ROOT, letter) {
                self.emit_word(pinned_state, letter, child, true);
            }
            if state.gap_len < self.cfg.max_gap_len {
                self.emit_gap(
                    pinned_state,
                    letter,
                    state.gap_len + 1,
                    state.gaps_used,
                    false,
                );
            }
            return;
        }
        if state.node == ROOT {
            if let Some(child) = self.lexicon.child(ROOT, letter) {
                self.emit_word(pinned_state, letter, child, true);
            }
            if state.gaps_used < self.cfg.max_gaps {
                self.emit_gap(pinned_state, letter, 1, state.gaps_used + 1, true);
            }
            return;
        }
        if let Some(child) = self.lexicon.child(state.node, letter) {
            self.emit_word(pinned_state, letter, child, false);
        }
        if self.lexicon.word_logp(state.node).is_some() {
            if let Some(child) = self.lexicon.child(ROOT, letter) {
                self.emit_word(pinned_state, letter, child, true);
            }
            if state.gaps_used < self.cfg.max_gaps {
                self.emit_gap(pinned_state, letter, 1, state.gaps_used + 1, true);
            }
        }
    }

    fn emit_word(&mut self, state: EnumState, letter: u8, node: u32, segment_start: bool) {
        self.emit(
            state,
            EnumTransition {
                letter,
                node,
                gap_len: 0,
                gaps_used: state.gaps_used,
                gap: false,
                segment_start,
            },
        );
    }

    fn emit_gap(
        &mut self,
        state: EnumState,
        letter: u8,
        gap_len: u8,
        gaps_used: u8,
        segment_start: bool,
    ) {
        self.emit(
            state,
            EnumTransition {
                letter,
                node: ROOT,
                gap_len,
                gaps_used,
                gap: true,
                segment_start,
            },
        );
    }

    fn emit(&mut self, state: EnumState, transition: EnumTransition) {
        if self.expanded >= self.cfg.parse_budget {
            self.budget_hit = true;
            return;
        }
        let next_gap_letters = state.gap_letters + usize::from(transition.gap);
        if next_gap_letters > self.gap_letter_limit {
            return;
        }
        self.expanded += 1;
        let next = EnumState {
            position: state.position + 1,
            node: transition.node,
            gap_len: transition.gap_len,
            gaps_used: transition.gaps_used,
            gap_letters: next_gap_letters,
            ..state
        };
        self.path
            .push(transition.letter, transition.gap, transition.segment_start);
        self.walk(next);
        self.path.pop();
    }

    fn collect_final(&mut self, state: EnumState) {
        if state.gap_letters != self.gap_letter_limit {
            return;
        }
        if state.gap_len == 0 && self.lexicon.word_logp(state.node).is_none() && state.node == ROOT
        {
            return;
        }
        self.feasible_final += 1;
        let candidate = HarvestedColoring {
            rank: 0,
            score: 0.0,
            pinned: state.pinned.count_ones() as usize,
            gaps_used: state.gaps_used,
            gap_letters: state.gap_letters,
            coloring: coloring_from_pins(state.classes, state.pinned),
            rendered: self.path.render(),
        };
        self.collector.offer(candidate);
    }
}

/// Builds the 26-slot coloring from packed pin state.
fn coloring_from_pins(classes: u64, pinned: u32) -> [Option<u8>; 26] {
    std::array::from_fn(|letter| {
        if pinned & (1u32 << letter) == 0 {
            None
        } else {
            Some(((classes >> (2 * letter)) & 0b11) as u8)
        }
    })
}

type CoverageKey = (usize, Reverse<usize>, Reverse<usize>, [Option<u8>; 26]);

/// Distinct-coloring collector with LM-free coverage cap selection.
struct ColoringCollector {
    limit: usize,
    by_coloring: BTreeMap<[Option<u8>; 26], HarvestedColoring>,
    retained: BTreeSet<CoverageKey>,
    cap_hit: bool,
    dropped_colorings: usize,
}

impl ColoringCollector {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            by_coloring: BTreeMap::new(),
            retained: BTreeSet::new(),
            cap_hit: false,
            dropped_colorings: 0,
        }
    }

    fn len(&self) -> usize {
        self.by_coloring.len()
    }

    fn offer(&mut self, candidate: HarvestedColoring) {
        let key = coverage_key(&candidate);
        if let Some(existing) = self.by_coloring.get(&candidate.coloring) {
            let old_key = coverage_key(existing);
            if key > old_key {
                let _removed = self.retained.remove(&old_key);
                let _inserted = self.retained.insert(key);
                let _old = self.by_coloring.insert(candidate.coloring, candidate);
            }
            return;
        }
        if self.by_coloring.len() < self.limit {
            let _inserted = self.retained.insert(key);
            let _old = self.by_coloring.insert(candidate.coloring, candidate);
            return;
        }
        self.cap_hit = true;
        if let Some(&worst_key) = self.retained.iter().next()
            && key > worst_key
        {
            let evicted = worst_key.3;
            let _removed = self.retained.remove(&worst_key);
            let _old = self.by_coloring.remove(&evicted);
            let _inserted = self.retained.insert(key);
            let _old = self.by_coloring.insert(candidate.coloring, candidate);
        }
        self.dropped_colorings = self.dropped_colorings.saturating_add(1);
    }

    fn finish(self) -> (Vec<HarvestedColoring>, bool, usize) {
        let mut out: Vec<HarvestedColoring> = self.by_coloring.into_values().collect();
        out.sort_by(|a, b| {
            b.pinned
                .cmp(&a.pinned)
                .then_with(|| a.gaps_used.cmp(&b.gaps_used))
                .then_with(|| a.gap_letters.cmp(&b.gap_letters))
                .then_with(|| a.coloring.cmp(&b.coloring))
                .then_with(|| a.rendered.cmp(&b.rendered))
        });
        for (index, coloring) in out.iter_mut().enumerate() {
            coloring.rank = index + 1;
        }
        (out, self.cap_hit, self.dropped_colorings)
    }
}

fn coverage_key(candidate: &HarvestedColoring) -> CoverageKey {
    (
        candidate.pinned,
        Reverse(usize::from(candidate.gaps_used)),
        Reverse(candidate.gap_letters),
        candidate.coloring,
    )
}

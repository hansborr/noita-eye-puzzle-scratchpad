//! LM-free anchor-window harvest by merged hard-constraint enumeration.
//!
//! This is a layered DAG dynamic program over parse state. The merge key keeps
//! exactly the future-relevant hard constraints: trie/gap state, gap count,
//! letter-class pins, and the first-occurrence letters still needed to verify
//! the tied second occurrence. Scores are never read for ordering or pruning;
//! `word_logp(node).is_some()` is used only as the lexicon word-end predicate.

use std::collections::BTreeMap;

mod collector;
mod frontier;
mod suffix;

use collector::ColoringCollector;
use frontier::StateLayer;
use suffix::SuffixTrie;

use super::super::lexicon::ROOT;
use super::super::solve::{SolveCfg, estimate_peak_mib, pin_class};
use super::super::{MAX_CLASSES, N_LETTERS, PairclassError};
use super::{AnchorHarvestMode, AnchorHarvestReport, HarvestWindowInput, HarvestedColoring};

/// Maximum parse transitions visited by the LM-free enumerator.
const ENUMERATE_MAX_PARSE_BUDGET: u64 = 100_000_000;
/// Minimum parse transitions visited before budget saturation is possible.
const ENUMERATE_MIN_PARSE_BUDGET: u64 = 1_000_000;
/// Parse-budget multiplier applied to `phrase_cfg.beam * window_len`.
const ENUMERATE_PARSE_BUDGET_FACTOR: u64 = 4;
/// Layer merge cap for the DP frontier. Saturation is reported as a budget hit.
const ENUMERATE_LAYER_STATE_BUDGET: usize = 10_000;

const NO_PARENT: u32 = u32::MAX;
const UNKNOWN_TIE_LETTER: u8 = u8::MAX;
const LETTER_MASK: u8 = 0x1f;
const FLAG_SEGMENT_START: u8 = 1 << 5;
const FLAG_GAP: u8 = 1 << 6;

/// LM-free hard-constraint window enumeration harvest.
pub(super) fn harvest_anchor_colorings_enumerate(
    input: HarvestWindowInput<'_>,
    phrase_cfg: &SolveCfg,
) -> Result<AnchorHarvestReport, PairclassError> {
    validate_enumeration_input(input.tokens, input.n_classes, input.tie_table)?;
    let estimated_mib = estimate_peak_mib(
        input.tokens.len(),
        phrase_cfg.beam.max(input.effective_top),
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
        layer_state_budget: ENUMERATE_LAYER_STATE_BUDGET,
    };
    let result = Enumerator::new(input, enum_cfg).run();
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

/// Validates the subset of [`super::super::solve::SolveInput`] needed here.
fn validate_enumeration_input(
    tokens: &[u8],
    n_classes: u8,
    tie_table: &[Option<usize>],
) -> Result<(), PairclassError> {
    if tokens.is_empty() {
        return Err(PairclassError::EmptyInput);
    }
    if n_classes == 0 || n_classes > MAX_CLASSES {
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
    layer_state_budget: usize,
}

/// Future-relevant DP state. Representative diagnostics live in `DpValue`.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
struct DpKey {
    node: u32,
    gap_len: u8,
    gaps_used: u8,
    gap_node: u32,
    classes: u64,
    pinned: u32,
    tie_letters: Vec<u8>,
}

#[derive(Clone, Copy)]
struct DpValue {
    arena: u32,
    gap_letters: usize,
}

#[derive(Clone, Copy)]
struct EnumTransition {
    letter: u8,
    node: u32,
    gap_len: u8,
    gaps_used: u8,
    gap_node: u32,
    gap: bool,
    segment_start: bool,
}

struct EmitBase<'a> {
    position: usize,
    key: &'a DpKey,
    value: DpValue,
    pins: (u64, u32),
    letter: u8,
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

/// Compact representative backtrace, one entry per retained DP representative.
struct EnumArena {
    parents: Vec<u32>,
    packed: Vec<u8>,
}

impl EnumArena {
    fn with_capacity(entries: usize) -> Self {
        Self {
            parents: Vec::with_capacity(entries),
            packed: Vec::with_capacity(entries),
        }
    }

    fn push(&mut self, parent: u32, packed: u8) -> u32 {
        let index = self.parents.len() as u32;
        self.parents.push(parent);
        self.packed.push(packed);
        index
    }

    fn chain(&self, index: u32) -> Vec<u8> {
        let mut out = Vec::new();
        let mut at = index;
        while at != NO_PARENT {
            let Some(&packed) = self.packed.get(at as usize) else {
                break;
            };
            out.push(packed);
            at = self.parents.get(at as usize).copied().unwrap_or(NO_PARENT);
        }
        out.reverse();
        out
    }

    fn render(&self, index: u32) -> String {
        let chain = self.chain(index);
        let mut out = String::with_capacity(chain.len() + chain.len() / 4);
        for (position, packed) in chain.iter().enumerate() {
            if position > 0 && packed & FLAG_SEGMENT_START != 0 {
                out.push(' ');
            }
            let ch = char::from(b'a' + (packed & LETTER_MASK).min(N_LETTERS - 1));
            if packed & FLAG_GAP != 0 {
                out.push(ch.to_ascii_uppercase());
            } else {
                out.push(ch);
            }
        }
        out
    }
}

/// LM-free window enumerator.
struct Enumerator<'a> {
    input: HarvestWindowInput<'a>,
    cfg: EnumerateCfg,
    suffix_trie: SuffixTrie,
    arena: EnumArena,
    collector: ColoringCollector,
    expanded: u64,
    feasible_final: usize,
    parse_budget_hit: bool,
    state_budget_hit: bool,
}

impl<'a> Enumerator<'a> {
    fn new(input: HarvestWindowInput<'a>, cfg: EnumerateCfg) -> Self {
        let arena_cap = input
            .tokens
            .len()
            .saturating_mul(input.effective_top.min(4096));
        Self {
            input,
            cfg,
            suffix_trie: SuffixTrie::from_lexicon(input.lexicon, usize::from(cfg.max_gap_len)),
            arena: EnumArena::with_capacity(arena_cap),
            collector: ColoringCollector::new(cfg.limit),
            expanded: 0,
            feasible_final: 0,
            parse_budget_hit: false,
            state_budget_hit: false,
        }
    }

    fn run(mut self) -> EnumerateResult {
        let mut current = BTreeMap::new();
        let _old = current.insert(
            DpKey {
                node: ROOT,
                gap_len: 0,
                gaps_used: 0,
                gap_node: ROOT,
                classes: 0,
                pinned: 0,
                tie_letters: vec![UNKNOWN_TIE_LETTER; self.input.window.span_len],
            },
            DpValue {
                arena: NO_PARENT,
                gap_letters: 0,
            },
        );
        let mut max_retained = current.len();
        for position in 0..self.input.tokens.len() {
            if current.is_empty() {
                return self.finish(max_retained);
            }
            let mut next = StateLayer::new(self.cfg.layer_state_budget, position + 1);
            for (key, value) in &current {
                self.expand_state(position, key, *value, &mut next);
                if self.parse_budget_hit {
                    max_retained = max_retained.max(next.len());
                    return self.finish(max_retained);
                }
            }
            max_retained = max_retained.max(next.len());
            self.state_budget_hit |= next.saturated;
            current = next.into_states();
        }
        self.collect_finals(current);
        self.finish(max_retained)
    }

    fn finish(self, max_retained: usize) -> EnumerateResult {
        let (distinct_colorings, cap_hit, dropped_colorings) = self.collector.finish();
        EnumerateResult {
            distinct_colorings,
            expanded: self.expanded,
            feasible_final: self.feasible_final,
            max_retained,
            cap_hit,
            budget_hit: self.parse_budget_hit || self.state_budget_hit,
            dropped_colorings,
        }
    }

    fn expand_state(
        &mut self,
        position: usize,
        key: &DpKey,
        value: DpValue,
        next: &mut StateLayer,
    ) {
        let Some(&token) = self.input.tokens.get(position) else {
            return;
        };
        if let Some(src) = self.input.tie_table.get(position).copied().flatten() {
            if let Some(letter) = self.tied_source_letter(key, src) {
                self.try_letter(position, key, value, letter, token, next);
            }
            return;
        }
        for letter in 0..N_LETTERS {
            self.try_letter(position, key, value, letter, token, next);
            if self.parse_budget_hit {
                break;
            }
        }
    }

    fn try_letter(
        &mut self,
        position: usize,
        key: &DpKey,
        value: DpValue,
        letter: u8,
        token: u8,
        next: &mut StateLayer,
    ) {
        if letter >= N_LETTERS || token >= self.input.n_classes {
            return;
        }
        let Some((classes, pinned)) = pin_class(key.classes, key.pinned, letter, token) else {
            return;
        };
        let base = EmitBase {
            position,
            key,
            value,
            pins: (classes, pinned),
            letter,
        };
        if key.gap_len > 0 {
            if value.gap_letters == position {
                if key.gap_len < self.cfg.max_gap_len
                    && let Some(child) = self.suffix_trie.child(key.gap_node, letter)
                {
                    self.emit_gap(&base, (key.gap_len + 1, key.gaps_used, child), false, next);
                }
                if self.suffix_trie.terminal(key.gap_node)
                    && let Some(child) = self.input.lexicon.child(ROOT, letter)
                {
                    self.emit_word(&base, child, true, next);
                }
            }
            return;
        }
        if key.node == ROOT {
            if let Some(child) = self.input.lexicon.child(ROOT, letter) {
                self.emit_word(&base, child, true, next);
            }
            if value.gap_letters == position
                && key.gaps_used < self.cfg.max_gaps
                && let Some(child) = self.suffix_trie.child(ROOT, letter)
            {
                self.emit_gap(&base, (1, key.gaps_used + 1, child), true, next);
            }
            return;
        }
        if let Some(child) = self.input.lexicon.child(key.node, letter) {
            self.emit_word(&base, child, false, next);
        }
        if self.input.lexicon.word_logp(key.node).is_some()
            && let Some(child) = self.input.lexicon.child(ROOT, letter)
        {
            self.emit_word(&base, child, true, next);
        }
    }

    fn emit_word(
        &mut self,
        base: &EmitBase<'_>,
        node: u32,
        segment_start: bool,
        next: &mut StateLayer,
    ) {
        self.emit_transition(
            base.position,
            base.key,
            base.value,
            base.pins,
            EnumTransition {
                letter: base.letter,
                node,
                gap_len: 0,
                gaps_used: base.key.gaps_used,
                gap_node: ROOT,
                gap: false,
                segment_start,
            },
            next,
        );
    }

    fn emit_gap(
        &mut self,
        base: &EmitBase<'_>,
        gap: (u8, u8, u32),
        segment_start: bool,
        next: &mut StateLayer,
    ) {
        let (gap_len, gaps_used, gap_node) = gap;
        self.emit_transition(
            base.position,
            base.key,
            base.value,
            base.pins,
            EnumTransition {
                letter: base.letter,
                node: ROOT,
                gap_len,
                gaps_used,
                gap_node,
                gap: true,
                segment_start,
            },
            next,
        );
    }

    fn emit_transition(
        &mut self,
        position: usize,
        key: &DpKey,
        value: DpValue,
        pins: (u64, u32),
        transition: EnumTransition,
        next: &mut StateLayer,
    ) {
        if self.expanded >= self.cfg.parse_budget {
            self.parse_budget_hit = true;
            return;
        }
        let mut tie_letters = self.next_tie_letters(key, position, transition.letter);
        if self.can_drop_tie_letters(position + 1) {
            tie_letters.clear();
        }
        let next_key = DpKey {
            node: transition.node,
            gap_len: transition.gap_len,
            gaps_used: transition.gaps_used,
            gap_node: transition.gap_node,
            classes: pins.0,
            pinned: pins.1,
            tie_letters,
        };
        let next_gap_letters = value.gap_letters + usize::from(transition.gap);
        let packed = transition.letter
            | if transition.gap { FLAG_GAP } else { 0 }
            | if transition.segment_start {
                FLAG_SEGMENT_START
            } else {
                0
            };
        self.expanded += 1;
        next.offer(
            next_key,
            value.arena,
            packed,
            next_gap_letters,
            &mut self.arena,
        );
    }

    fn tied_source_letter(&self, key: &DpKey, src: usize) -> Option<u8> {
        let offset = src.checked_sub(self.input.window.first_offset)?;
        key.tie_letters
            .get(offset)
            .copied()
            .filter(|&letter| letter != UNKNOWN_TIE_LETTER)
    }

    fn next_tie_letters(&self, key: &DpKey, position: usize, letter: u8) -> Vec<u8> {
        let mut tie_letters = key.tie_letters.clone();
        let first_start = self.input.window.first_offset;
        let first_end = first_start.saturating_add(self.input.window.span_len);
        if (first_start..first_end).contains(&position) {
            let offset = position - first_start;
            if let Some(slot) = tie_letters.get_mut(offset) {
                *slot = letter;
            }
        }
        tie_letters
    }

    fn can_drop_tie_letters(&self, next_position: usize) -> bool {
        let second_end = self
            .input
            .window
            .second_offset
            .saturating_add(self.input.window.span_len);
        next_position >= second_end
    }

    fn collect_finals(&mut self, finals: BTreeMap<DpKey, DpValue>) {
        for (key, value) in finals {
            if value.gap_letters == self.input.tokens.len() || !self.accept_final(&key) {
                continue;
            }
            self.feasible_final += 1;
            self.collector.offer(HarvestedColoring {
                rank: 0,
                score: 0.0,
                pinned: key.pinned.count_ones() as usize,
                gaps_used: key.gaps_used,
                gap_letters: value.gap_letters,
                coloring: coloring_from_pins(key.classes, key.pinned),
                rendered: self.arena.render(value.arena),
            });
        }
    }

    fn accept_final(&self, key: &DpKey) -> bool {
        key.gap_len > 0 || self.input.lexicon.word_logp(key.node).is_some() || key.node != ROOT
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

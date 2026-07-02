//! Beam-search primitives: the packed state, the bounded selection heap, the
//! backtrace arena, and one position's expansion. These are the internals of
//! [`super::solve`]; the memory contract lives here — the heap keeps at most
//! `beam` survivors and the arena grows one entry per kept state per position.

use std::cmp::Ordering;
use std::cmp::Reverse;
use std::collections::BinaryHeap;

use super::super::N_LETTERS;
use super::super::lexicon::{Lexicon, ROOT};
use super::{SolveCfg, SolveInput, TruthFate};

/// Arena sentinel for "no parent" (the pre-stream state).
pub(super) const NO_PARENT: u32 = u32::MAX;
/// Packed-letter flag: this letter starts a new segment (word or gap).
pub(super) const FLAG_SEGMENT_START: u8 = 1 << 5;
/// Packed-letter flag: this letter is inside a gap (out-of-vocabulary) segment.
pub(super) const FLAG_GAP: u8 = 1 << 6;
/// Mask extracting the letter from a packed arena byte.
pub(super) const LETTER_MASK: u8 = 0x1f;

/// One in-flight beam state.
#[derive(Clone, Copy, Debug)]
pub(super) struct State {
    /// 2-bit class per letter (valid where `pinned`).
    pub(super) classes: u64,
    /// Bitmask of letters with an assigned class.
    pub(super) pinned: u32,
    /// Current trie node (`ROOT` = at a word boundary; only pre-stream or in a
    /// gap).
    pub(super) node: u32,
    /// Current gap length (`0` = not in a gap).
    pub(super) gap_len: u8,
    /// Gap segments consumed.
    pub(super) gaps_used: u8,
    /// This state extends the truth prefix.
    pub(super) truth: bool,
    /// Accumulated score.
    pub(super) score: f32,
    /// Arena index of this state's last letter (`NO_PARENT` pre-stream).
    pub(super) arena: u32,
}

impl State {
    /// The pre-stream root state.
    pub(super) fn root(truth: bool, seed_coloring: Option<&[Option<u8>]>) -> Self {
        let mut state = Self {
            classes: 0,
            pinned: 0,
            node: ROOT,
            gap_len: 0,
            gaps_used: 0,
            truth,
            score: 0.0,
            arena: NO_PARENT,
        };
        if let Some(seed) = seed_coloring {
            for (letter, class) in seed
                .iter()
                .enumerate()
                .filter_map(|(letter, slot)| slot.map(|class| (letter, class)))
            {
                let bit = 1u32 << letter;
                let shift = 2 * letter;
                state.classes |= u64::from(class) << shift;
                state.pinned |= bit;
            }
        }
        state
    }
}

/// A candidate produced by expanding one state with one letter.
#[derive(Clone, Copy, Debug)]
pub(super) struct Candidate {
    pub(super) state: State,
    /// Parent arena index (the expanded state's `arena`).
    pub(super) parent: u32,
    /// Letter plus segment flags, as stored in the arena.
    pub(super) packed: u8,
}

impl Candidate {
    /// Deterministic total-order key after the score.
    fn tiebreak(&self) -> (u64, u32, u32, u8, u8, u8, u32, bool) {
        (
            self.state.classes,
            self.state.pinned,
            self.state.node,
            self.state.gap_len,
            self.state.gaps_used,
            self.packed,
            self.parent,
            self.state.truth,
        )
    }
}

/// Heap wrapper giving candidates a deterministic total order by score.
#[derive(Clone, Copy, Debug)]
pub(super) struct HeapCand(Candidate);

impl PartialEq for HeapCand {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for HeapCand {}
impl PartialOrd for HeapCand {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for HeapCand {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .state
            .score
            .total_cmp(&other.0.state.score)
            .then_with(|| self.0.tiebreak().cmp(&other.0.tiebreak()))
    }
}

/// A bounded top-`cap` selection heap (min-heap of the kept candidates).
pub(super) struct BoundedBeam {
    heap: BinaryHeap<Reverse<HeapCand>>,
    cap: usize,
}

impl BoundedBeam {
    fn new(cap: usize) -> Self {
        Self {
            heap: BinaryHeap::with_capacity(cap + 1),
            cap,
        }
    }

    fn offer(&mut self, candidate: Candidate) {
        let wrapped = HeapCand(candidate);
        if self.heap.len() < self.cap {
            self.heap.push(Reverse(wrapped));
            return;
        }
        if let Some(Reverse(worst)) = self.heap.peek()
            && wrapped > *worst
        {
            let _evicted = self.heap.pop();
            self.heap.push(Reverse(wrapped));
        }
    }

    /// The current selection cutoff (worst kept score), if any.
    fn cutoff(&self) -> Option<f32> {
        self.heap.peek().map(|Reverse(worst)| worst.0.state.score)
    }

    /// Drains the kept candidates, best first.
    pub(super) fn into_kept(self) -> Vec<Candidate> {
        let mut kept: Vec<HeapCand> = self.heap.into_iter().map(|Reverse(c)| c).collect();
        kept.sort_by(|a, b| b.cmp(a));
        kept.into_iter().map(|HeapCand(c)| c).collect()
    }
}

/// The backtrace arena: one `(parent, packed letter)` entry per kept state per
/// position.
pub(super) struct Arena {
    parents: Vec<u32>,
    packed: Vec<u8>,
}

impl Arena {
    pub(super) fn with_capacity(entries: usize) -> Self {
        Self {
            parents: Vec::with_capacity(entries),
            packed: Vec::with_capacity(entries),
        }
    }

    pub(super) fn push(&mut self, parent: u32, packed: u8) -> u32 {
        let index = self.parents.len() as u32;
        self.parents.push(parent);
        self.packed.push(packed);
        index
    }

    /// The letter `steps` positions before the entry at `index`.
    fn letter_back(&self, index: u32, steps: usize) -> Option<u8> {
        let mut at = index;
        for _hop in 0..steps {
            at = self.parents.get(at as usize).copied()?;
            if at == NO_PARENT {
                return None;
            }
        }
        self.packed
            .get(at as usize)
            .map(|packed| packed & LETTER_MASK)
    }

    /// Reconstructs the packed-letter chain ending at `index` (stream order).
    pub(super) fn chain(&self, index: u32) -> Vec<u8> {
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
}

/// Per-position truth bookkeeping.
#[derive(Clone, Copy)]
pub(super) struct TruthTrack {
    pub(super) alive: bool,
    pub(super) fate: Option<TruthFate>,
}

impl TruthTrack {
    pub(super) fn new(active: bool) -> Self {
        Self {
            alive: active,
            fate: None,
        }
    }
}

/// One position's expansion products.
pub(super) struct StepOutcome {
    pub(super) beam: BoundedBeam,
    pub(super) offered: u64,
    pub(super) stats: StepStats,
}

/// The truth-relevant slice of a [`StepOutcome`], usable after the beam moves.
pub(super) struct StepStats {
    truth_offered: u64,
    truth_best: f32,
    cutoff: f32,
}

/// Sizes used by the up-front memory estimate.
#[must_use]
pub(super) fn state_bytes() -> usize {
    std::mem::size_of::<State>()
}

/// Heap-entry byte size used by the up-front memory estimate.
#[must_use]
pub(super) fn heap_entry_bytes() -> usize {
    std::mem::size_of::<Reverse<HeapCand>>() + std::mem::size_of::<Candidate>()
}

/// Expands every state with every admissible letter at `position`.
pub(super) fn expand_position(
    states: &[State],
    input: &SolveInput<'_>,
    cfg: &SolveCfg,
    arena: &Arena,
    position: usize,
    token: u8,
) -> StepOutcome {
    let mut beam = BoundedBeam::new(cfg.beam);
    let mut offered = 0u64;
    let mut truth_offered = 0u64;
    let mut truth_best = f32::NEG_INFINITY;
    let tie_target = input
        .tie_to
        .and_then(|table| table.get(position).copied().flatten());
    let truth_letter = input.truth.and_then(|t| t.get(position)).copied();
    for state in states {
        let forced = tie_target
            .and_then(|src| arena.letter_back(state.arena, position.saturating_sub(1) - src));
        if tie_target.is_some() && forced.is_none() && position > 0 {
            // A broken backtrace would silently drop the tie; skip the state.
            continue;
        }
        for letter in 0..N_LETTERS {
            if forced.is_some_and(|f| f != letter) {
                continue;
            }
            let Some((classes, pinned)) = pin(state.classes, state.pinned, letter, token) else {
                continue;
            };
            let truth_cand = state.truth && truth_letter.is_some_and(|t| t == letter);
            emit_transitions(
                state,
                letter,
                (classes, pinned),
                input.lexicon,
                cfg,
                &mut |c| {
                    let candidate = Candidate {
                        state: State {
                            truth: truth_cand,
                            ..c.state
                        },
                        ..c
                    };
                    offered += 1;
                    if truth_cand {
                        truth_offered += 1;
                        if candidate.state.score > truth_best {
                            truth_best = candidate.state.score;
                        }
                    }
                    beam.offer(candidate);
                },
            );
        }
    }
    let cutoff = beam.cutoff().unwrap_or(f32::NEG_INFINITY);
    StepOutcome {
        beam,
        offered,
        stats: StepStats {
            truth_offered,
            truth_best,
            cutoff,
        },
    }
}

/// Pins `letter` to `class`, or checks an existing pin. `None` = conflict.
pub(super) fn pin(classes: u64, pinned: u32, letter: u8, class: u8) -> Option<(u64, u32)> {
    let bit = 1u32 << letter;
    let shift = 2 * u32::from(letter);
    if pinned & bit != 0 {
        let existing = ((classes >> shift) & 0b11) as u8;
        (existing == class).then_some((classes, pinned))
    } else {
        Some((classes | (u64::from(class) << shift), pinned | bit))
    }
}

/// Emits every lexicon/gap transition for `(state, letter)`.
fn emit_transitions(
    state: &State,
    letter: u8,
    pins: (u64, u32),
    lexicon: &Lexicon,
    cfg: &SolveCfg,
    emit: &mut dyn FnMut(Candidate),
) {
    let (classes, pinned) = pins;
    let base = State {
        classes,
        pinned,
        truth: false,
        ..*state
    };
    let make = |node: u32, gap_len: u8, gaps_used: u8, score: f32, flags: u8| Candidate {
        state: State {
            node,
            gap_len,
            gaps_used,
            score,
            arena: NO_PARENT,
            ..base
        },
        parent: state.arena,
        packed: letter | flags,
    };
    if state.gap_len > 0 {
        if state.gap_len < cfg.max_gap_len {
            emit(make(
                ROOT,
                state.gap_len + 1,
                state.gaps_used,
                state.score - cfg.gap_penalty,
                FLAG_GAP,
            ));
        }
        if let Some(child) = lexicon.child(ROOT, letter) {
            emit(make(
                child,
                0,
                state.gaps_used,
                state.score,
                FLAG_SEGMENT_START,
            ));
        }
        return;
    }
    if state.node == ROOT {
        // Pre-stream boundary: start the first word or open the first gap.
        if let Some(child) = lexicon.child(ROOT, letter) {
            emit(make(
                child,
                0,
                state.gaps_used,
                state.score,
                FLAG_SEGMENT_START,
            ));
        }
        if state.gaps_used < cfg.max_gaps {
            emit(make(
                ROOT,
                1,
                state.gaps_used + 1,
                state.score - cfg.gap_penalty,
                FLAG_GAP | FLAG_SEGMENT_START,
            ));
        }
        return;
    }
    if let Some(child) = lexicon.child(state.node, letter) {
        emit(make(child, 0, state.gaps_used, state.score, 0));
    }
    if let Some(word_logp) = lexicon.word_logp(state.node) {
        let closed = state.score + word_logp;
        if let Some(child) = lexicon.child(ROOT, letter) {
            emit(make(child, 0, state.gaps_used, closed, FLAG_SEGMENT_START));
        }
        if state.gaps_used < cfg.max_gaps {
            emit(make(
                ROOT,
                1,
                state.gaps_used + 1,
                closed - cfg.gap_penalty,
                FLAG_GAP | FLAG_SEGMENT_START,
            ));
        }
    }
}

/// Applies one position's truth bookkeeping to `track`.
pub(super) fn update_truth(
    track: &mut TruthTrack,
    kept: &[Candidate],
    stats: &StepStats,
    position: usize,
) {
    if !track.alive || track.fate.is_some() {
        return;
    }
    if stats.truth_offered == 0 {
        track.fate = Some(TruthFate::Infeasible { position });
        track.alive = false;
        return;
    }
    if !kept.iter().any(|candidate| candidate.state.truth) {
        track.fate = Some(TruthFate::BeamPruned {
            position,
            truth_best: stats.truth_best,
            cutoff: stats.cutoff,
        });
        track.alive = false;
    }
}

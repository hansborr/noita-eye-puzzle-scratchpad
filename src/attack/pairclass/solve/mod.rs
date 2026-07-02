//! The dictionary-propagation beam solver over letter positions.
//!
//! Each state carries the coloring induced so far (26 x 2-bit classes plus a
//! pinned mask, both in machine words), the current trie node or gap segment,
//! and a backtrace-arena index. Expansion streams candidates through a bounded
//! heap of exactly `beam` survivors, so peak memory is a checked function of
//! `beam` and the stream length — never of how many expansions the search
//! visits. When truth letters are supplied the solver tracks the true path's
//! fate exactly: at every position it knows whether truth-consistent states
//! were generated, and whether any survived selection (the BEAM-PRUNED vs
//! OUT-SCORED attribution that decided the 2026 campaign rounds).
//!
//! The beam-search primitives (packed state, bounded heap, arena, expansion)
//! live in the private [`beam`] submodule; this module owns the public API,
//! the position-by-position driver, and result assembly.

mod beam;

use beam::{Arena, FLAG_GAP, FLAG_SEGMENT_START, LETTER_MASK, State, TruthTrack};

use super::lexicon::Lexicon;
use super::{MAX_CLASSES, N_LETTERS, PairclassError};

/// Solver budget and policy knobs.
#[derive(Clone, Copy, Debug)]
pub struct SolveCfg {
    /// Beam width (kept states per position) — the memory knob.
    pub beam: usize,
    /// Maximum number of gap (out-of-vocabulary) segments.
    pub max_gaps: u8,
    /// Maximum length of one gap segment.
    pub max_gap_len: u8,
    /// Per-letter score penalty inside a gap segment (positive; subtracted).
    pub gap_penalty: f32,
    /// Number of distinct-letter solutions to report.
    pub top: usize,
    /// Refuse to run when the estimated peak memory exceeds this cap.
    pub max_mem_mib: usize,
}

impl Default for SolveCfg {
    fn default() -> Self {
        Self {
            beam: 20_000,
            max_gaps: 2,
            max_gap_len: 8,
            gap_penalty: 3.6,
            top: 5,
            max_mem_mib: 2048,
        }
    }
}

/// One solve problem: the token stream plus model context.
#[derive(Clone, Copy, Debug)]
pub struct SolveInput<'a> {
    /// Token classes, one per letter position (values `0..4`).
    pub tokens: &'a [u8],
    /// Number of classes in use (`1..=4`).
    pub n_classes: u8,
    /// Optional per-position tie targets (earlier position each must equal).
    pub tie_to: Option<&'a [Option<usize>]>,
    /// The word lexicon.
    pub lexicon: &'a Lexicon,
    /// Optional truth letters (`0..26`) for true-path instrumentation.
    pub truth: Option<&'a [u8]>,
    /// Optional 26-slot seed coloring: class per letter, `None` = unpinned.
    pub seed_coloring: Option<&'a [Option<u8>]>,
}

/// The fate of the true path through the search, when truth was supplied.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TruthFate {
    /// The best final solution is the truth path.
    Found {
        /// Its final score.
        score: f32,
    },
    /// Truth survived to the end but ranked below the best found solution.
    OutScored {
        /// Best truth-path final score.
        truth_score: f32,
        /// The winning (non-truth) score.
        best_score: f32,
    },
    /// Truth candidates were generated at `position` but none survived
    /// selection — the beam evicted the true path.
    BeamPruned {
        /// Position of the eviction.
        position: usize,
        /// Best truth-candidate score offered there.
        truth_best: f32,
        /// The selection cutoff (worst kept score).
        cutoff: f32,
    },
    /// No truth-consistent candidate could be generated at `position` under
    /// the lexicon/gap policy (the truth text is not representable).
    Infeasible {
        /// First position where truth could not extend.
        position: usize,
    },
}

/// One reported solution (a candidate, never a decode).
#[derive(Clone, Debug)]
pub struct Solution {
    /// Decoded letters (`0..26`), one per position.
    pub letters: Vec<u8>,
    /// Display rendering: spaces at segment starts, gap letters uppercase.
    pub rendered: String,
    /// Final score (sum of word log-probabilities minus gap penalties).
    pub score: f32,
    /// The induced coloring: class per letter, `None` = letter unused.
    pub coloring: [Option<u8>; 26],
    /// Gap segments used.
    pub gaps_used: u8,
    /// Whether this solution is the truth path (truth runs only).
    pub is_truth: bool,
}

/// The solver's report.
#[derive(Clone, Debug)]
pub struct SolveReport {
    /// Top distinct-letter solutions, best first (empty = no segmentation).
    pub solutions: Vec<Solution>,
    /// True-path fate, when truth letters were supplied.
    pub truth: Option<TruthFate>,
    /// Candidates offered to selection across all positions.
    pub expanded: u64,
    /// Feasible complete states at the final position.
    pub feasible_final: usize,
    /// Maximum kept-state occupancy at any position.
    pub max_occupancy: usize,
    /// The up-front peak-memory estimate that was checked against the cap.
    pub estimated_mib: usize,
}

/// Driver counters passed into final report assembly.
#[derive(Clone, Copy)]
struct DriverStats {
    expanded: u64,
    max_occupancy: usize,
    estimated_mib: usize,
}

/// Estimates the solver's peak memory in MiB for the given problem size.
#[must_use]
pub fn estimate_peak_mib(n_positions: usize, beam: usize, lexicon_nodes: usize) -> usize {
    let state = beam::state_bytes();
    let arena = n_positions.saturating_mul(beam).saturating_mul(5);
    let beams = beam.saturating_mul(2 * state + beam::heap_entry_bytes());
    let lex = lexicon_nodes.saturating_mul(108);
    (arena + beams + lex).div_ceil(1024 * 1024)
}

/// Runs the beam solve.
///
/// # Errors
/// Rejects empty/oversized token classes, zero beams, malformed tie tables or
/// truth lengths, and — the memory contract — a configuration whose estimated
/// peak exceeds `cfg.max_mem_mib` ([`PairclassError::MemoryCap`]).
pub fn solve(input: &SolveInput<'_>, cfg: &SolveCfg) -> Result<SolveReport, PairclassError> {
    validate(input, cfg)?;
    let n = input.tokens.len();
    let estimated_mib = estimate_peak_mib(n, cfg.beam, input.lexicon.n_nodes());
    if estimated_mib > cfg.max_mem_mib {
        return Err(PairclassError::MemoryCap {
            estimated_mib,
            cap_mib: cfg.max_mem_mib,
        });
    }
    let mut arena = Arena::with_capacity(n.saturating_mul(cfg.beam.min(4096)));
    let mut states = vec![State::root(input.truth.is_some(), input.seed_coloring)];
    let mut track = TruthTrack::new(input.truth.is_some());
    let mut expanded = 0u64;
    let mut max_occupancy = states.len();
    for (position, &token) in input.tokens.iter().enumerate() {
        let step = beam::expand_position(&states, input, cfg, &arena, position, token);
        expanded += step.offered;
        let kept = step.beam.into_kept();
        beam::update_truth(&mut track, &kept, &step.stats, position);
        states = kept
            .into_iter()
            .map(|candidate| {
                let index = arena.push(candidate.parent, candidate.packed);
                State {
                    arena: index,
                    ..candidate.state
                }
            })
            .collect();
        max_occupancy = max_occupancy.max(states.len());
        if states.is_empty() {
            break;
        }
    }
    Ok(finish(
        input,
        cfg,
        &arena,
        states,
        track,
        DriverStats {
            expanded,
            max_occupancy,
            estimated_mib,
        },
    ))
}

/// Finalizes states (words must close), ranks solutions, resolves truth fate.
fn finish(
    input: &SolveInput<'_>,
    cfg: &SolveCfg,
    arena: &Arena,
    states: Vec<State>,
    track: TruthTrack,
    metrics: DriverStats,
) -> SolveReport {
    let mut finals: Vec<State> = states
        .into_iter()
        .filter_map(|state| {
            if state.gap_len > 0 {
                return Some(state);
            }
            input.lexicon.word_logp(state.node).map(|word_logp| State {
                score: state.score + word_logp,
                ..state
            })
        })
        .collect();
    finals.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.arena.cmp(&b.arena))
    });
    let feasible_final = finals.len();
    let truth_final_best = finals
        .iter()
        .filter(|state| state.truth)
        .map(|state| state.score)
        .fold(f32::NEG_INFINITY, f32::max);
    let truth = resolve_truth_fate(input, &finals, track, truth_final_best);
    let mut seen = std::collections::BTreeSet::new();
    let mut solutions = Vec::new();
    for state in &finals {
        let chain = arena.chain(state.arena);
        let letters: Vec<u8> = chain.iter().map(|packed| packed & LETTER_MASK).collect();
        if !seen.insert(letters.clone()) {
            continue;
        }
        solutions.push(render_solution(state, &chain, letters));
        if solutions.len() >= cfg.top {
            break;
        }
    }
    SolveReport {
        solutions,
        truth,
        expanded: metrics.expanded,
        feasible_final,
        max_occupancy: metrics.max_occupancy,
        estimated_mib: metrics.estimated_mib,
    }
}

/// Decides the end-of-stream truth fate.
fn resolve_truth_fate(
    input: &SolveInput<'_>,
    finals: &[State],
    track: TruthTrack,
    truth_final_best: f32,
) -> Option<TruthFate> {
    let _present: &[u8] = input.truth?;
    if let Some(fate) = track.fate {
        return Some(fate);
    }
    let Some(best) = finals.first() else {
        return Some(TruthFate::Infeasible {
            position: input.tokens.len(),
        });
    };
    if !truth_final_best.is_finite() {
        return Some(TruthFate::Infeasible {
            position: input.tokens.len(),
        });
    }
    if best.truth {
        Some(TruthFate::Found { score: best.score })
    } else {
        Some(TruthFate::OutScored {
            truth_score: truth_final_best,
            best_score: best.score,
        })
    }
}

/// Renders one final state into a reportable [`Solution`].
fn render_solution(state: &State, chain: &[u8], letters: Vec<u8>) -> Solution {
    let mut rendered = String::with_capacity(chain.len() + chain.len() / 4);
    for (index, packed) in chain.iter().enumerate() {
        if index > 0 && packed & FLAG_SEGMENT_START != 0 {
            rendered.push(' ');
        }
        let letter = packed & LETTER_MASK;
        let ch = char::from(b'a' + letter.min(25));
        if packed & FLAG_GAP != 0 {
            rendered.push(ch.to_ascii_uppercase());
        } else {
            rendered.push(ch);
        }
    }
    let mut coloring = [None; 26];
    for (letter, slot) in coloring.iter_mut().enumerate() {
        if state.pinned & (1u32 << letter) != 0 {
            *slot = Some(((state.classes >> (2 * letter)) & 0b11) as u8);
        }
    }
    Solution {
        letters,
        rendered,
        score: state.score,
        coloring,
        gaps_used: state.gaps_used,
        is_truth: state.truth,
    }
}

/// Validates the input/config contract shared by every entry path.
fn validate(input: &SolveInput<'_>, cfg: &SolveCfg) -> Result<(), PairclassError> {
    if input.tokens.is_empty() {
        return Err(PairclassError::EmptyInput);
    }
    if cfg.beam == 0 {
        return Err(PairclassError::BeamZero);
    }
    if input.n_classes == 0 || input.n_classes > MAX_CLASSES {
        return Err(PairclassError::TooManyClasses {
            found: usize::from(input.n_classes),
        });
    }
    if let Some(bad) = input.tokens.iter().find(|&&t| t >= input.n_classes) {
        return Err(PairclassError::TooManyClasses {
            found: usize::from(*bad) + 1,
        });
    }
    if let Some(table) = input.tie_to {
        if table.len() != input.tokens.len() {
            return Err(PairclassError::SpanOutOfRange);
        }
        let broken = table
            .iter()
            .enumerate()
            .any(|(p, target)| target.is_some_and(|src| src >= p));
        if broken {
            return Err(PairclassError::SpanOutOfRange);
        }
    }
    if let Some(truth) = input.truth {
        if truth.len() != input.tokens.len() {
            return Err(PairclassError::TruthLengthMismatch {
                truth: truth.len(),
                tokens: input.tokens.len(),
            });
        }
        if truth.iter().any(|&letter| letter >= N_LETTERS) {
            return Err(PairclassError::SpanOutOfRange);
        }
    }
    if let Some(seed) = input.seed_coloring {
        if seed.len() != usize::from(N_LETTERS) {
            return Err(PairclassError::SeedColoringLength { len: seed.len() });
        }
        for (letter, class) in seed
            .iter()
            .enumerate()
            .filter_map(|(letter, slot)| slot.map(|class| (letter, class)))
        {
            if class >= input.n_classes {
                return Err(PairclassError::SeedColoringClass {
                    letter,
                    class,
                    n_classes: input.n_classes,
                });
            }
        }
    }
    Ok(())
}

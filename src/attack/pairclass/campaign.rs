//! Orchestration the CLI calls: stream preparation, the controls-first plant
//! power measurement, and the matched-null gate. Kept in the library so the
//! same functions are exercised by tests, per the repo's instrument rule.

use super::plant::{CopySpan, PlantSpec, markov_resample, plant_from_text};
use super::solve::{Solution, SolveCfg, SolveInput, TruthFate, solve};
use super::ties::{maximal_repeats, tie_targets, token_ties};
use super::{Lexicon, PairDerivation, PairclassError, derive_pair_tokens};
use crate::core::glyph::Glyph;

/// A prepared token stream plus its derived tie structure.
#[derive(Clone, Debug)]
pub struct StreamPrep {
    /// Pair tokens at the requested phase.
    pub tokens: Vec<u8>,
    /// Distinct classes in use.
    pub n_classes: u8,
    /// Per-position tie targets (empty table when ties are disabled).
    pub tie_table: Vec<Option<usize>>,
    /// Number of tied (non-representative) positions.
    pub n_tied: usize,
    /// The longest tie span in token coordinates (`(src, dst, len)`), if any —
    /// used to give planted controls a matched repeat topology.
    pub longest_tie: Option<(usize, usize, usize)>,
}

/// Derives pair tokens and ties from a residue-walk stream.
///
/// # Errors
/// [`PairclassError::NotAWalk`](PairclassError) is surfaced by the caller via
/// the returned [`PairDerivation`]; construction errors propagate directly.
pub fn prepare_stream(
    values: &[Glyph],
    modulus: usize,
    phase: usize,
    reversed: bool,
    min_anchor_len: usize,
) -> Result<Result<StreamPrep, super::WalkViolation>, PairclassError> {
    let derivation = derive_pair_tokens(values, modulus)?;
    let PairDerivation::Walk(pair) = derivation else {
        let PairDerivation::NotAWalk(violation) = derivation else {
            unreachable!("derivation is Walk or NotAWalk");
        };
        return Ok(Err(violation));
    };
    let bits: Vec<bool> = if reversed {
        pair.bits.iter().rev().copied().collect()
    } else {
        pair.bits.clone()
    };
    let tokens = pair_tokens_from_bits(&bits, phase);
    let n_classes = tokens.iter().copied().max().map_or(1, |m| m + 1);
    let (tie_table, n_tied, longest_tie) = if min_anchor_len == 0 {
        (Vec::new(), 0, None)
    } else {
        let spans = maximal_repeats(&bits, min_anchor_len);
        let pairs = token_ties(&spans, phase, tokens.len());
        let table = tie_targets(&pairs, tokens.len());
        let n_tied = table.iter().filter(|slot| slot.is_some()).count();
        (table, n_tied, longest_token_run(&pairs))
    };
    Ok(Ok(StreamPrep {
        tokens,
        n_classes,
        tie_table,
        n_tied,
        longest_tie,
    }))
}

/// The longest contiguous tied-token run: `(src_start, dst_start, len)` where
/// positions `src_start + i` and `dst_start + i` are tied for `i < len`.
///
/// `token_ties` emits each span's pairs in order with a constant token shift,
/// so a run is a maximal stretch where `src` increments by 1 and `dst - src`
/// holds. Returns the longest such run (the repeat most useful as a matched
/// plant topology).
fn longest_token_run(pairs: &[(usize, usize)]) -> Option<(usize, usize, usize)> {
    let mut best: Option<(usize, usize, usize)> = None;
    let mut run_start: Option<(usize, usize)> = None;
    let mut run_len = 0usize;
    let mut prev: Option<(usize, usize)> = None;
    for &(src, dst) in pairs {
        let continues = prev.is_some_and(|(psrc, pdst)| src == psrc + 1 && dst == pdst + 1);
        if continues {
            run_len += 1;
        } else {
            run_start = Some((src, dst));
            run_len = 1;
        }
        if let Some((rsrc, rdst)) = run_start
            && best.is_none_or(|(_, _, len)| run_len > len)
        {
            best = Some((rsrc, rdst, run_len));
        }
        prev = Some((src, dst));
    }
    best
}

/// Pair tokens from a bit stream at `phase` (token = `2*b0 + b1`).
fn pair_tokens_from_bits(bits: &[bool], phase: usize) -> Vec<u8> {
    let body = bits.get(phase..).unwrap_or(&[]);
    body.chunks_exact(2)
        .map(|pair| match pair {
            [b0, b1] => (u8::from(*b0) << 1) | u8::from(*b1),
            _ => 0,
        })
        .collect()
}

/// One planted control's outcome.
#[derive(Clone, Debug)]
pub struct PlantOutcome {
    /// Fraction of plant letters the best solution recovered.
    pub recovery: f64,
    /// Fraction of the plant's used letters whose induced class was correct.
    pub coloring_accuracy: f64,
    /// The tracked true-path fate.
    pub fate: Option<TruthFate>,
    /// The best solution's score (`None` = no full segmentation).
    pub best_score: Option<f32>,
}

/// The controls-first power measurement.
#[derive(Clone, Debug)]
pub struct PowerReport {
    /// Per-plant outcomes.
    pub plants: Vec<PlantOutcome>,
    /// Mean letter recovery across plants.
    pub mean_recovery: f64,
    /// Mean coloring accuracy across plants.
    pub mean_coloring_accuracy: f64,
    /// Whether `mean_recovery` cleared the bar.
    pub cleared_bar: bool,
}

/// Parameters for a controls-first power measurement.
#[derive(Clone, Copy, Debug)]
pub struct PowerCfg {
    /// Number of planted controls to run.
    pub n_plants: usize,
    /// Plant length in letters (match the real token count).
    pub plant_len: usize,
    /// Coloring classes to use.
    pub n_classes: u8,
    /// The real stream's longest tie in token coordinates, mirrored into each
    /// plant's repeat topology.
    pub longest_tie: Option<(usize, usize, usize)>,
    /// Mean-recovery bar the plants must clear.
    pub bar: f64,
    /// Deterministic base seed.
    pub seed: u64,
}

/// Runs planted controls, each from a distinct slice of `text`, through the
/// identical solver with truth tracking.
///
/// Each plant imposes a copy span mirroring the real stream's longest tie (when
/// supplied) so its repeat topology matches. The plant's own tie table is
/// derived from that copy span.
///
/// # Errors
/// Propagates plant-construction and solver errors.
pub fn measure_power(
    text: &str,
    power: &PowerCfg,
    lexicon: &Lexicon,
    cfg: &SolveCfg,
) -> Result<PowerReport, PairclassError> {
    let letters: Vec<u8> = text
        .chars()
        .filter_map(|ch| {
            let lower = ch.to_ascii_lowercase();
            lower.is_ascii_lowercase().then(|| lower as u8 - b'a')
        })
        .collect();
    let copy = tie_to_copy(power.longest_tie, power.plant_len);
    let mut plants = Vec::with_capacity(power.n_plants);
    for index in 0..power.n_plants {
        let start = plant_slice_start(letters.len(), power.plant_len, index, power.n_plants);
        let source: String = letters
            .get(start..)
            .unwrap_or(&[])
            .iter()
            .map(|&l| char::from(b'a' + l.min(25)))
            .collect();
        let spec = PlantSpec {
            len: power.plant_len,
            n_classes: power.n_classes,
            copy,
        };
        let plant = plant_from_text(&source, &spec, power.seed.wrapping_add(index as u64))?;
        let ties = plant_ties(copy, power.plant_len);
        let outcome = solve_plant(&plant, ties.as_deref(), lexicon, cfg)?;
        plants.push(outcome);
    }
    let mean_recovery = mean(plants.iter().map(|p| p.recovery));
    let mean_coloring_accuracy = mean(plants.iter().map(|p| p.coloring_accuracy));
    Ok(PowerReport {
        plants,
        mean_recovery,
        mean_coloring_accuracy,
        cleared_bar: mean_recovery >= power.bar,
    })
}

/// Maps a token-coordinate tie to a within-plant copy span (both fit `len`).
fn tie_to_copy(longest_tie: Option<(usize, usize, usize)>, plant_len: usize) -> Option<CopySpan> {
    let (_src, _dst, span_len) = longest_tie?;
    let span_len = span_len.min(plant_len / 3).max(1);
    if plant_len < 3 * span_len {
        return None;
    }
    // Place the repeat at the front third and the middle third of the plant.
    Some(CopySpan {
        src: 0,
        dst: plant_len / 3,
        len: span_len,
    })
}

/// The plant's tie table (from its copy span).
fn plant_ties(copy: Option<CopySpan>, plant_len: usize) -> Option<Vec<Option<usize>>> {
    let span = copy?;
    let pairs = super::plant::copy_ties(span, plant_len).ok()?;
    Some(tie_targets(&pairs, plant_len))
}

/// Solves one plant and scores recovery + coloring accuracy against truth.
fn solve_plant(
    plant: &super::plant::Plant,
    ties: Option<&[Option<usize>]>,
    lexicon: &Lexicon,
    cfg: &SolveCfg,
) -> Result<PlantOutcome, PairclassError> {
    let report = solve(
        &SolveInput {
            tokens: &plant.tokens,
            n_classes: max_class(&plant.tokens),
            tie_to: ties,
            lexicon,
            truth: Some(&plant.letters),
            seed_coloring: None,
        },
        cfg,
    )?;
    let best = report.solutions.first();
    Ok(PlantOutcome {
        recovery: best.map_or(0.0, |s| letter_recovery(&s.letters, &plant.letters)),
        coloring_accuracy: best.map_or(0.0, |s| coloring_accuracy(s, plant)),
        fate: report.truth,
        best_score: best.map(|s| s.score),
    })
}

/// The matched order-1 Markov null gate on a real token stream.
#[derive(Clone, Debug)]
pub struct NullGate {
    /// The real stream's best score (`None` = no full segmentation).
    pub real_best: Option<f32>,
    /// Each null resample's best score.
    pub null_bests: Vec<Option<f32>>,
    /// Nulls whose best score reached or beat the real best.
    pub null_ge_real: usize,
}

impl NullGate {
    /// The one-sided empirical p-value (fraction of nulls `>=` the real best).
    #[must_use]
    pub fn p_value(&self) -> f64 {
        if self.null_bests.is_empty() {
            return f64::NAN;
        }
        (self.null_ge_real as f64 + 1.0) / (self.null_bests.len() as f64 + 1.0)
    }
}

/// Runs the identical search on `null_trials` Markov resamples of `tokens`.
///
/// # Errors
/// Propagates resample and solver errors.
pub fn null_gate(
    tokens: &[u8],
    n_classes: u8,
    lexicon: &Lexicon,
    cfg: &SolveCfg,
    null_trials: usize,
    real_best: Option<f32>,
    seed: u64,
) -> Result<NullGate, PairclassError> {
    let mut null_bests = Vec::with_capacity(null_trials);
    let mut null_ge_real = 0usize;
    for trial in 0..null_trials {
        let resampled = markov_resample(tokens, n_classes, seed.wrapping_add(trial as u64))?;
        let report = solve(
            &SolveInput {
                tokens: &resampled,
                n_classes,
                tie_to: None,
                lexicon,
                truth: None,
                seed_coloring: None,
            },
            cfg,
        )?;
        let best = report.solutions.first().map(|s| s.score);
        if let (Some(null), Some(real)) = (best, real_best)
            && null >= real
        {
            null_ge_real += 1;
        }
        null_bests.push(best);
    }
    Ok(NullGate {
        real_best,
        null_bests,
        null_ge_real,
    })
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
fn coloring_accuracy(solution: &Solution, plant: &super::plant::Plant) -> f64 {
    let mut used = [false; 26];
    for &letter in &plant.letters {
        if let Some(slot) = used.get_mut(usize::from(letter)) {
            *slot = true;
        }
    }
    let total = used.iter().filter(|u| **u).count();
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
    tokens.iter().copied().max().map_or(1, |m| m + 1)
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

/// Builds the [`SolveCfg`] the campaign uses from raw knobs.
#[must_use]
pub fn solve_cfg(
    beam: usize,
    max_gaps: u8,
    max_gap_len: u8,
    gap_penalty: f32,
    top: usize,
    max_mem_mib: usize,
) -> SolveCfg {
    SolveCfg {
        beam,
        max_gaps,
        max_gap_len,
        gap_penalty,
        top,
        max_mem_mib,
    }
}

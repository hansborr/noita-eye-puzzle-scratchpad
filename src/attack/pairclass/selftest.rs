//! Self-validation for the pair-class instrument: a planted positive control,
//! the matched Markov null, a forced-prune instrumentation check, the walk
//! gate, and the embedded-`two` structural regression.
//!
//! The planted scenario is deliberately small (a 64-letter sentence over a
//! 38-word lexicon) so the positive control is *recoverable*: it validates the
//! machinery (derivation, ties, pins, beam, backtrace, truth tracking), not
//! the search's power at the real target's length — power at length must be
//! measured with full-size plants (`--plant-text-file`), per the campaign
//! discipline.

use super::campaign::StreamPrep;
use super::plant::{CopySpan, Plant, PlantSpec, markov_resample, plant_from_text};
use super::solve::{SolveCfg, SolveInput, TruthFate, solve};
use super::ties::{TieSpan, maximal_repeats, tie_targets};
use super::{
    PairDerivation, PairclassError, TWO_MODULUS, derive_pair_tokens, embedded_two,
    harvest_anchor_colorings,
    lexicon::{Lexicon, build_lexicon, parse_wordlist},
};
use crate::core::glyph::Glyph;

/// Phase-0 pair-token marginals of the embedded `two` (classes `0..4`).
pub const TWO_PHASE0_MARGINALS: [usize; 4] = [107, 51, 143, 47];

/// The maximal eps-repeat anchors of the embedded `two` (bit positions).
///
/// Five are the campaign's recorded independent anchors; `(232, 506, 41)` is
/// the *transitive composition* of the 68-bit anchor (gap 120) and the 41-bit
/// anchor (gap 154): `bits[232..273] == bits[352..393] == bits[506..547]`, a
/// genuine exact repeat at the composed gap 274 that the exhaustive per-gap
/// scan lists and the campaign's independent-anchor list did not enumerate.
pub const TWO_ANCHORS: [TieSpan; 6] = [
    TieSpan {
        a: 231,
        b: 351,
        len: 68,
    },
    TieSpan {
        a: 5,
        b: 555,
        len: 51,
    },
    TieSpan {
        a: 232,
        b: 506,
        len: 41,
    },
    TieSpan {
        a: 352,
        b: 506,
        len: 41,
    },
    TieSpan {
        a: 108,
        b: 572,
        len: 37,
    },
    TieSpan {
        a: 22,
        b: 108,
        len: 34,
    },
];

/// The anchor length floor at which exactly the five recorded spans appear.
pub const TWO_ANCHOR_MIN_LEN: usize = 34;

/// The planted sentence (64 letters; the first 19 letters repeat at 25).
const PLANT_SENTENCE: &str =
    "the black dog sat on the bed and the black dog sat on the rug so the night was long";
/// The plant's natural repeated span, used as its tie topology.
const PLANT_REPEAT: CopySpan = CopySpan {
    src: 0,
    dst: 25,
    len: 19,
};
/// Plant length in letters.
const PLANT_LEN: usize = 64;
/// Beam width for the plant and null legs.
const PLANT_BEAM: usize = 512;

/// The embedded mini-lexicon: the sentence words dominate the distractors so
/// the planted truth is score-recoverable by construction.
const MINI_WORDLIST: &str = "the 1000\nand 500\nblack 400\ndog 380\nsat 360\non 340\nbed 320\n\
rug 300\nso 280\nnight 260\nwas 240\nlong 220\na 100\ni 95\nto 90\nof 85\nin 80\nit 75\nis 70\n\
be 65\nat 60\nhe 55\nwe 50\nor 45\nan 40\nas 35\nby 30\nno 25\nnot 20\nall 15\nthis 12\nthat 10\n\
with 8\nfrom 6\nhave 5\nthey 4\nstone 3\nwind 2\n";

/// The planted-positive leg.
#[derive(Clone, Debug)]
pub struct PlantLeg {
    /// Fraction of plant letters recovered by the best solution.
    pub recovery: f64,
    /// The tracked truth fate.
    pub fate: Option<TruthFate>,
    /// The plant leg's best (winning) score, reused by the null leg.
    pub best_score: Option<f32>,
}

impl PlantLeg {
    /// Passed: the truth path won and recovery is at least `0.9`.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.recovery >= 0.9 && matches!(self.fate, Some(TruthFate::Found { .. }))
    }
}

/// The matched-null leg (order-1 Markov resample of the plant tokens).
#[derive(Clone, Debug)]
pub struct NullLeg {
    /// The plant's winning score.
    pub plant_best: Option<f32>,
    /// The null stream's winning score (`None` = no full segmentation).
    pub null_best: Option<f32>,
}

impl NullLeg {
    /// Passed: the null never reaches the plant's score.
    #[must_use]
    pub fn passed(&self) -> bool {
        match (self.plant_best, self.null_best) {
            (Some(plant), Some(null)) => null < plant,
            (Some(_), None) => true,
            (None, _) => false,
        }
    }
}

/// The forced-prune instrumentation leg (beam 1 must evict the truth).
#[derive(Clone, Debug)]
pub struct PruneLeg {
    /// The tracked truth fate at beam 1.
    pub fate: Option<TruthFate>,
}

impl PruneLeg {
    /// Passed: the instrumentation reported a beam eviction.
    #[must_use]
    pub fn passed(&self) -> bool {
        matches!(self.fate, Some(TruthFate::BeamPruned { .. }))
    }
}

/// The anchor-seeded mechanism leg.
#[derive(Clone, Debug)]
pub struct AnchorLeg {
    /// Recovery when the plant's true coloring is pre-seeded.
    pub oracle_recovery: f64,
    /// One-based harvest rank of the plant's true window coloring.
    pub harvested_truth_rank: Option<usize>,
    /// Distinct harvested colorings.
    pub harvested: usize,
    /// Phrase-harvest maximum kept-state occupancy.
    pub max_occupancy: usize,
    /// Whether the phrase beam saturated during harvest.
    pub saturated: bool,
}

impl AnchorLeg {
    /// Passed: seeded oracle recovers the plant and harvest surfaces truth.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.oracle_recovery >= 0.9 && self.harvested_truth_rank.is_some()
    }
}

/// The embedded-`two` structural regression leg.
#[derive(Clone, Debug)]
pub struct TwoRegression {
    /// Phase-0 token count (expected 348).
    pub n_tokens: usize,
    /// Phase-0 marginals (expected [`TWO_PHASE0_MARGINALS`]).
    pub marginals: [usize; 4],
    /// Maximal repeats at the recorded floor (expected [`TWO_ANCHORS`]).
    pub anchors: Vec<TieSpan>,
}

impl TwoRegression {
    /// Passed: token count, marginals, and the five anchors all reproduce.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.n_tokens == 348
            && self.marginals == TWO_PHASE0_MARGINALS
            && self.anchors == TWO_ANCHORS
    }
}

/// Outcome of `pairclass --self-test`.
#[derive(Clone, Debug)]
pub struct PairclassSelfTest {
    /// Planted positive control.
    pub plant: PlantLeg,
    /// Matched Markov null.
    pub null: NullLeg,
    /// Forced-prune instrumentation check.
    pub prune: PruneLeg,
    /// Anchor-seeded mechanism check.
    pub anchor: AnchorLeg,
    /// The `±1` walk gate rejected a non-walk stream.
    pub walk_gate: bool,
    /// Embedded-`two` derivation regression.
    pub two: TwoRegression,
}

impl PairclassSelfTest {
    /// `true` iff every leg passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.plant.passed()
            && self.null.passed()
            && self.prune.passed()
            && self.anchor.passed()
            && self.walk_gate
            && self.two.passed()
    }
}

/// Runs every self-test leg through the same library functions the CLI uses.
///
/// # Errors
/// Propagates any [`PairclassError`] from plant construction or the solver —
/// a self-test that cannot even construct its scenario is a failure.
pub fn pairclass_self_test(seed: u64) -> Result<PairclassSelfTest, PairclassError> {
    let lexicon = build_lexicon(&parse_wordlist(MINI_WORDLIST, usize::MAX))?;
    let plant_spec = PlantSpec {
        len: PLANT_LEN,
        n_classes: 4,
        copy: None,
    };
    let plant = plant_from_text(PLANT_SENTENCE, &plant_spec, seed)?;
    let ties = tie_targets(
        &super::plant::copy_ties(PLANT_REPEAT, PLANT_LEN)?,
        PLANT_LEN,
    );
    let plant_leg = run_plant_leg(&plant, &ties, &lexicon)?;
    let null_leg = run_null_leg(&plant, plant_leg.best_score, &lexicon, seed)?;
    let prune_leg = run_prune_leg(&plant, &ties, &lexicon)?;
    let anchor_leg = run_anchor_leg(&plant, &ties, &lexicon)?;
    Ok(PairclassSelfTest {
        plant: plant_leg,
        null: null_leg,
        prune: prune_leg,
        anchor: anchor_leg,
        walk_gate: walk_gate_leg()?,
        two: two_regression_leg()?,
    })
}

/// Fraction of positions where `found` matches `truth`.
#[must_use]
pub fn recovery_fraction(found: &[u8], truth: &[u8]) -> f64 {
    if truth.is_empty() {
        return 0.0;
    }
    let matched = found
        .iter()
        .zip(truth.iter())
        .filter(|(a, b)| a == b)
        .count();
    matched as f64 / truth.len() as f64
}

fn plant_cfg(beam: usize) -> SolveCfg {
    SolveCfg {
        beam,
        top: 3,
        ..SolveCfg::default()
    }
}

fn run_plant_leg(
    plant: &super::plant::Plant,
    ties: &[Option<usize>],
    lexicon: &Lexicon,
) -> Result<PlantLeg, PairclassError> {
    let report = solve(
        &SolveInput {
            tokens: &plant.tokens,
            n_classes: 4,
            tie_to: Some(ties),
            lexicon,
            truth: Some(&plant.letters),
            seed_coloring: None,
        },
        &plant_cfg(PLANT_BEAM),
    )?;
    let best = report.solutions.first();
    Ok(PlantLeg {
        recovery: best.map_or(0.0, |solution| {
            recovery_fraction(&solution.letters, &plant.letters)
        }),
        fate: report.truth,
        best_score: best.map(|solution| solution.score),
    })
}

fn run_null_leg(
    plant: &super::plant::Plant,
    plant_best: Option<f32>,
    lexicon: &Lexicon,
    seed: u64,
) -> Result<NullLeg, PairclassError> {
    let null_tokens = markov_resample(&plant.tokens, 4, seed)?;
    let report = solve(
        &SolveInput {
            tokens: &null_tokens,
            n_classes: 4,
            tie_to: None,
            lexicon,
            truth: None,
            seed_coloring: None,
        },
        &plant_cfg(PLANT_BEAM),
    )?;
    Ok(NullLeg {
        plant_best,
        null_best: report.solutions.first().map(|solution| solution.score),
    })
}

fn run_prune_leg(
    plant: &super::plant::Plant,
    ties: &[Option<usize>],
    lexicon: &Lexicon,
) -> Result<PruneLeg, PairclassError> {
    let report = solve(
        &SolveInput {
            tokens: &plant.tokens,
            n_classes: 4,
            tie_to: Some(ties),
            lexicon,
            truth: Some(&plant.letters),
            seed_coloring: None,
        },
        &plant_cfg(1),
    )?;
    Ok(PruneLeg { fate: report.truth })
}

fn run_anchor_leg(
    plant: &super::plant::Plant,
    ties: &[Option<usize>],
    lexicon: &Lexicon,
) -> Result<AnchorLeg, PairclassError> {
    let truth_seed = truth_seed_coloring(plant);
    let oracle = solve(
        &SolveInput {
            tokens: &plant.tokens,
            n_classes: 4,
            tie_to: Some(ties),
            lexicon,
            truth: Some(&plant.letters),
            seed_coloring: Some(&truth_seed),
        },
        &plant_cfg(PLANT_BEAM),
    )?;
    let oracle_recovery = oracle.solutions.first().map_or(0.0, |solution| {
        recovery_fraction(&solution.letters, &plant.letters)
    });
    let prep = StreamPrep {
        tokens: plant.tokens.clone(),
        n_classes: 4,
        tie_table: ties.to_vec(),
        n_tied: ties.iter().filter(|slot| slot.is_some()).count(),
        longest_tie: Some((PLANT_REPEAT.src, PLANT_REPEAT.dst, PLANT_REPEAT.len)),
    };
    let phrase_cfg = SolveCfg {
        beam: 4096,
        max_gaps: 6,
        max_gap_len: 8,
        top: 128,
        ..SolveCfg::default()
    };
    let harvest = harvest_anchor_colorings(&prep, lexicon, &phrase_cfg, 128)?;
    let truth = truth_window_coloring(plant, harvest.window.start, harvest.window.len);
    let harvested_truth_rank = harvest
        .distinct_colorings
        .iter()
        .position(|seed| seed.coloring == truth)
        .map(|index| index + 1);
    Ok(AnchorLeg {
        oracle_recovery,
        harvested_truth_rank,
        harvested: harvest.distinct_colorings.len(),
        max_occupancy: harvest.max_occupancy,
        saturated: harvest.saturated,
    })
}

fn truth_seed_coloring(plant: &Plant) -> [Option<u8>; 26] {
    std::array::from_fn(|index| plant.coloring.get(index).copied())
}

fn truth_window_coloring(plant: &Plant, start: usize, len: usize) -> [Option<u8>; 26] {
    let mut coloring = [None; 26];
    let end = start.saturating_add(len);
    for &letter in plant.letters.get(start..end).unwrap_or(&[]) {
        if let Some(slot) = coloring.get_mut(usize::from(letter)) {
            *slot = plant.coloring.get(usize::from(letter)).copied();
        }
    }
    coloring
}

/// A repeated residue is the C3 walk violation (`diff 0`).
fn walk_gate_leg() -> Result<bool, PairclassError> {
    let values = [Glyph(0), Glyph(1), Glyph(1), Glyph(2)];
    Ok(matches!(
        derive_pair_tokens(&values, TWO_MODULUS)?,
        PairDerivation::NotAWalk(_)
    ))
}

fn two_regression_leg() -> Result<TwoRegression, PairclassError> {
    let values = embedded_two()?;
    let derivation = derive_pair_tokens(&values, TWO_MODULUS)?;
    let PairDerivation::Walk(pair_tokens) = derivation else {
        return Err(PairclassError::Fixture(
            "embedded two failed the walk gate".to_owned(),
        ));
    };
    Ok(TwoRegression {
        n_tokens: pair_tokens.tokens(0).len(),
        marginals: pair_tokens.marginals(0),
        anchors: maximal_repeats(&pair_tokens.bits, TWO_ANCHOR_MIN_LEN),
    })
}

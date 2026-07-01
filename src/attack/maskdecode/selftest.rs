//! Planted controls, matched null, walk-gate control, and the recorded-`one`
//! regression for `maskdecode --self-test`.

use crate::attack::rlcodec::RlError;
use crate::core::glyph::Glyph;
use crate::nulls::null::{SplitMix64, mix_seed, random_index_below};

use super::verify::walk_digits;
use super::{
    BitOrder, CellParams, MaskAnalysis, MaskCfg, MaskError, MaskKind, MaskVerdict, ONE_BASE,
    Polarity, ReadDirection, analyze_embedded_one, analyze_mask_decode, mask_encode,
};

/// Planted-control phrase (mixed case + spaces, 29 chars = 203 message bits).
pub const PLANT_PHRASE: &str = "Walks on the pentagon at dawn";
/// The verified plaintext of the embedded practice puzzle `one`.
pub const ONE_SOLUTION: &str = "Permutation Representation Destination";
/// The recorded solve cell for embedded `one`.
pub const ONE_CELL: CellParams = CellParams {
    mask: MaskKind::Alternating,
    width: 7,
    offset: 6,
    order: BitOrder::MsbFirst,
    polarity: Polarity::Plain,
    direction: ReadDirection::Forward,
};
/// Digit count of the embedded practice puzzle `one`.
pub const ONE_DIGIT_COUNT: usize = 266;

const PLANT_ALTERNATING_START: usize = 3;
const PLANT_STATIC_START: usize = 2;
const NULL_TAG: u64 = 0x6d61_736b_0011_0001;

/// One planted-positive leg of the self-test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MaskPlantLeg {
    /// The sweep verdict was `VerifiedDecode`.
    pub verified: bool,
    /// Some exact-round-trip completion equals the planted phrase verbatim.
    pub recovered: bool,
    /// The recovering candidate sits at the planted cell parameters.
    pub cell_matches: bool,
}

impl MaskPlantLeg {
    /// `true` iff the plant was verified, recovered verbatim, at its cell.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.verified && self.recovered && self.cell_matches
    }

    const fn failed() -> Self {
        Self {
            verified: false,
            recovered: false,
            cell_matches: false,
        }
    }
}

/// The recorded-solve regression leg on the embedded `one`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaskOneRegression {
    /// Digits reproduced by the canonical exact completion's round-trip.
    pub matched: usize,
    /// Total ciphertext digits.
    pub total: usize,
    /// Completions at the canonical verified cell (`1` = unique).
    pub n_completions: usize,
    /// The canonical exact completion text.
    pub text: Option<String>,
    /// The canonical verified cell parameters.
    pub cell: Option<CellParams>,
}

impl MaskOneRegression {
    /// `true` iff the sweep reproduces the recorded solve exactly:
    /// [`ONE_SOLUTION`] at [`ONE_CELL`], unique completion, round-trip
    /// `266/266`.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.matched == ONE_DIGIT_COUNT
            && self.total == ONE_DIGIT_COUNT
            && self.n_completions == 1
            && self.text.as_deref() == Some(ONE_SOLUTION)
            && self.cell == Some(ONE_CELL)
    }

    const fn missing() -> Self {
        Self {
            matched: 0,
            total: 0,
            n_completions: 0,
            text: None,
            cell: None,
        }
    }
}

/// Outcome of `maskdecode --self-test`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaskSelfTest {
    /// Planted positive under the alternating (conv-alt) mask.
    pub planted_alternating: MaskPlantLeg,
    /// Planted positive under the static mask (proves mask-axis coverage).
    pub planted_static: MaskPlantLeg,
    /// The matched-null random walk produced the `Negative` verdict.
    pub null_negative: bool,
    /// A non-`±1` input produced the `NotAWalk` verdict.
    pub not_a_walk_detected: bool,
    /// The embedded `one` reproduced the recorded verified decode.
    pub one_regression: MaskOneRegression,
}

impl MaskSelfTest {
    /// `true` iff every self-test leg passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.planted_alternating.passed()
            && self.planted_static.passed()
            && self.null_negative
            && self.not_a_walk_detected
            && self.one_regression.passed()
    }
}

/// Runs the planted positives (alternating + static mask), the `SplitMix64`
/// matched null, the walk-gate control, and the recorded-`one` regression,
/// all through [`analyze_mask_decode`] — the same function the CLI scan calls.
///
/// # Errors
/// Returns [`MaskError`] if a control fails to construct or analyze.
pub fn maskdecode_self_test(seed: u64) -> Result<MaskSelfTest, MaskError> {
    let cfg = MaskCfg::default();
    Ok(MaskSelfTest {
        planted_alternating: plant_leg(MaskKind::Alternating, PLANT_ALTERNATING_START, &cfg)?,
        planted_static: plant_leg(MaskKind::Static, PLANT_STATIC_START, &cfg)?,
        null_negative: null_leg(seed, &cfg)?,
        not_a_walk_detected: not_a_walk_leg(&cfg)?,
        one_regression: one_leg(&cfg)?,
    })
}

fn plant_leg(mask: MaskKind, start: usize, cfg: &MaskCfg) -> Result<MaskPlantLeg, MaskError> {
    let params = CellParams {
        mask,
        width: 7,
        offset: 0,
        order: BitOrder::MsbFirst,
        polarity: Polarity::Plain,
        direction: ReadDirection::Forward,
    };
    let digits = mask_encode(PLANT_PHRASE, &params, ONE_BASE, start)?;
    let MaskAnalysis::Walk(report) = analyze_mask_decode(&digits, ONE_BASE, cfg)? else {
        return Ok(MaskPlantLeg::failed());
    };
    let hit = report.candidates.iter().find(|candidate| {
        candidate
            .completions
            .iter()
            .any(|completion| completion.exact() && completion.text == PLANT_PHRASE)
    });
    Ok(MaskPlantLeg {
        verified: report.verdict == MaskVerdict::VerifiedDecode,
        recovered: hit.is_some(),
        cell_matches: hit.is_some_and(|candidate| candidate.readout.params == params),
    })
}

fn null_leg(seed: u64, cfg: &MaskCfg) -> Result<bool, MaskError> {
    let mut rng = SplitMix64::new(mix_seed(seed, NULL_TAG));
    let start = random_index_below(ONE_BASE, &mut rng).map_err(RlError::from)?;
    let bits: Vec<bool> = (0..ONE_DIGIT_COUNT - 1)
        .map(|_position| rng.next_u64() & 1 == 1)
        .collect();
    let digits = walk_digits(start, &bits, ONE_BASE);
    let MaskAnalysis::Walk(report) = analyze_mask_decode(&digits, ONE_BASE, cfg)? else {
        return Ok(false);
    };
    Ok(report.verdict == MaskVerdict::Negative)
}

fn not_a_walk_leg(cfg: &MaskCfg) -> Result<bool, MaskError> {
    let digits = [Glyph(0), Glyph(2), Glyph(4), Glyph(1), Glyph(3)];
    Ok(matches!(
        analyze_mask_decode(&digits, ONE_BASE, cfg)?,
        MaskAnalysis::NotAWalk(_)
    ))
}

fn one_leg(cfg: &MaskCfg) -> Result<MaskOneRegression, MaskError> {
    let MaskAnalysis::Walk(report) = analyze_embedded_one(cfg)? else {
        return Ok(MaskOneRegression::missing());
    };
    let Some((candidate, completion)) = report.verified() else {
        return Ok(MaskOneRegression::missing());
    };
    Ok(MaskOneRegression {
        matched: completion.matched,
        total: completion.total,
        n_completions: candidate.completions.len(),
        text: Some(completion.text.clone()),
        cell: Some(candidate.readout.params),
    })
}

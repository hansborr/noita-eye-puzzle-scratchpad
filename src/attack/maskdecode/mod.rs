//! Masked `C_n`-walk ASCII readout: the instrument that packages the verified
//! practice-puzzle-`one` solve.
//!
//! `maskdecode` reads a base-`n` digit stream as a walk on the cycle `C_n`:
//! every adjacent transition must be `+1` or `-1 mod n` (otherwise the honest
//! [`MaskAnalysis::NotAWalk`] verdict applies and no readout is attempted).
//! The walk becomes direction bits (`1` = the `+1`/up move), a deterministic
//! mask is `XOR`ed over those bits, and the masked stream is read as fixed-width
//! ASCII. The sweep covers mask {static `b_i = 0`, alternating `b_i = i mod 2`}
//! x chunk width x chunk offset x bit order {`MSB`, `LSB`} x polarity {plain,
//! complemented} x direction {forward, reversed}. The alternating mask with
//! phase `b_0 = 1` is exactly the complemented polarity of the `b_0 = 0` mask,
//! so phase is deliberately not a separate axis.
//!
//! A cell whose full chunks are all ASCII letters/space is only a
//! **candidate**. It is promoted to a **verified decode** by the decisive
//! gate: enumerate the letter/space completions of any partial head/tail
//! chunk, re-encode each completed text under the same cell parameters from
//! the observed starting digit, and require every ciphertext digit to be
//! reproduced exactly (`RoundTrip total/total`).
//!
//! On the embedded practice puzzle `one` (266 base-5 digits) this yields the
//! recorded solve: mask=alternating, width 7, offset 6, `MSB`-first, forward,
//! plain reads `ermutation Representation Destination`; the 6 observed head
//! bits `010000` complete uniquely to `P` (`0x50`); and the re-encoded 38-char
//! message `Permutation Representation Destination` reproduces all 266 digits
//! from starting digit 4 (`RoundTrip 266/266`). A mirror twin — reversed
//! direction + `LSB`-first at the complementary offset, reading the
//! character-reversed message — verifies too, as it must for any solve; the
//! canonical tie-break lists the forward cell first.

use std::fmt;

use crate::attack::rlcodec::{RlError, one_practice_digits};
use crate::core::glyph::Glyph;
use crate::nulls::null::RandomBoundError;

mod params;
mod selftest;
mod sweep;
mod verify;

#[cfg(test)]
mod tests;

pub use params::{BitOrder, CellParams, MaskKind, Polarity, ReadDirection};
pub use selftest::{
    MaskOneRegression, MaskPlantLeg, MaskSelfTest, ONE_CELL, ONE_DIGIT_COUNT, ONE_SOLUTION,
    PLANT_PHRASE, maskdecode_self_test,
};
pub use verify::{mask_encode, mask_encode_trimmed};

/// Default ASCII chunk widths swept by the CLI.
pub const DEFAULT_WIDTHS: &[usize] = &[5, 6, 7, 8];
/// Largest supported chunk width (chunk values must fit a `u32` `char` probe).
pub const MAX_WIDTH: usize = 16;
/// Smallest base whose `+1` and `-1` steps are distinguishable (`1 != n-1`).
pub const MIN_BASE: usize = 3;
/// Default number of ranked cells kept in the report.
pub const DEFAULT_TOP_CELLS: usize = 8;
/// Default deterministic seed (used by the self-test's matched null).
pub const DEFAULT_SEED: u64 = 0x6d61_736b_900d_0001;
/// Walk base of the embedded practice puzzle `one`.
pub const ONE_BASE: usize = 5;

/// Error type for `maskdecode`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MaskError {
    /// The base cannot host a direction-resolved `±1` walk.
    InvalidBase {
        /// The rejected base.
        base: usize,
    },
    /// Fewer than two digits: no transition exists.
    TooFewDigits {
        /// Number of digits supplied.
        count: usize,
    },
    /// A digit value was not below the declared base.
    SymbolOutOfRange {
        /// The offending digit value.
        value: usize,
        /// The declared base it must stay below.
        base: usize,
    },
    /// A chunk width outside `1..=MAX_WIDTH` was requested.
    InvalidWidth {
        /// The rejected width.
        width: usize,
    },
    /// The width sweep list was empty.
    EmptyWidths,
    /// A character does not fit the cell's chunk width during re-encoding.
    UnencodableChar {
        /// The offending character.
        ch: char,
        /// The chunk width it must fit.
        width: usize,
    },
    /// The requested starting digit was not below the base.
    InvalidStartDigit {
        /// The rejected starting digit.
        start: usize,
        /// The declared base.
        base: usize,
    },
    /// The base exceeds the largest digit a [`Glyph`] index can carry.
    BaseTooLarge {
        /// The rejected base.
        base: usize,
        /// The largest supported base.
        max: usize,
    },
    /// Head/tail trims leave no message bits to carry.
    InvalidTrim {
        /// Requested head skip in bits.
        head_skip: usize,
        /// Requested tail skip in bits.
        tail_skip: usize,
        /// Total message bits available before trimming.
        available: usize,
    },
    /// A shared `rlcodec` primitive (embedded fixture, random draw) failed.
    Rl(RlError),
}

impl From<RlError> for MaskError {
    fn from(error: RlError) -> Self {
        Self::Rl(error)
    }
}

impl From<RandomBoundError> for MaskError {
    fn from(error: RandomBoundError) -> Self {
        Self::Rl(RlError::from(error))
    }
}

impl fmt::Display for MaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::InvalidBase { base } => write!(
                f,
                "base {base} cannot host a direction-resolved ±1 walk (need >= {MIN_BASE})"
            ),
            Self::TooFewDigits { count } => {
                write!(f, "need at least two digits, have {count}")
            }
            Self::SymbolOutOfRange { value, base } => {
                write!(f, "digit {value} is not below the declared base {base}")
            }
            Self::InvalidWidth { width } => {
                write!(f, "chunk width {width} is outside 1..={MAX_WIDTH}")
            }
            Self::EmptyWidths => write!(f, "the width sweep list is empty"),
            Self::UnencodableChar { ch, width } => {
                write!(f, "character {ch:?} does not fit a {width}-bit chunk")
            }
            Self::InvalidStartDigit { start, base } => {
                write!(f, "starting digit {start} is not below the base {base}")
            }
            Self::BaseTooLarge { base, max } => {
                write!(f, "base {base} exceeds the largest supported base {max}")
            }
            Self::InvalidTrim {
                head_skip,
                tail_skip,
                available,
            } => write!(
                f,
                "trims (head {head_skip} + tail {tail_skip}) do not leave any of the {available} message bits"
            ),
            Self::Rl(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for MaskError {}

/// The decoded chunks of one cell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellReadout {
    /// The cell parameters.
    pub params: CellParams,
    /// Number of full `width`-bit chunks.
    pub n_chunks: usize,
    /// Full chunks decoding to ASCII letters or space.
    pub n_letters: usize,
    /// Full chunks decoding to printable ASCII (`0x20..=0x7E`).
    pub n_printable: usize,
    /// Observed bits of the partial head chunk (equals `offset`).
    pub head_bits: usize,
    /// Observed bits of the partial tail chunk (`0` when chunk-aligned).
    pub tail_bits: usize,
    /// Decoded text with `.` for non-printable chunks.
    pub rendered: String,
}

impl CellReadout {
    /// Fraction of full chunks that are ASCII letters or space.
    #[must_use]
    pub fn letter_fraction(&self) -> f64 {
        if self.n_chunks == 0 {
            0.0
        } else {
            self.n_letters as f64 / self.n_chunks as f64
        }
    }

    /// Fraction of full chunks that are printable ASCII.
    #[must_use]
    pub fn printable_fraction(&self) -> f64 {
        if self.n_chunks == 0 {
            0.0
        } else {
            self.n_printable as f64 / self.n_chunks as f64
        }
    }

    /// `true` iff every full chunk is a letter/space (letter fraction `1.0`).
    #[must_use]
    pub const fn all_letters(&self) -> bool {
        self.n_chunks > 0 && self.n_letters == self.n_chunks
    }
}

/// One completed message hypothesis for a candidate cell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Completion {
    /// The full completed text (head completion + chunks + tail completion).
    pub text: String,
    /// The head-chunk completion character, if the head was partial.
    pub head_char: Option<char>,
    /// The tail-chunk completion character, if the tail was partial.
    pub tail_char: Option<char>,
    /// Ciphertext digits reproduced exactly by the round-trip re-encode.
    pub matched: usize,
    /// Total ciphertext digits.
    pub total: usize,
}

impl Completion {
    /// `true` iff the round-trip reproduced every ciphertext digit.
    #[must_use]
    pub const fn exact(&self) -> bool {
        self.total > 0 && self.matched == self.total
    }
}

/// A full-letter cell plus its completion/round-trip verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateCell {
    /// The full-letter readout.
    pub readout: CellReadout,
    /// Missing head bits (`width - offset` when the head is partial, else 0).
    pub head_missing_bits: usize,
    /// Missing tail bits (`width - tail_bits` when the tail is partial, else 0).
    pub tail_missing_bits: usize,
    /// Letter/space completions of the partial head chunk (empty when aligned).
    pub head_options: Vec<char>,
    /// Letter/space completions of the partial tail chunk (empty when aligned).
    pub tail_options: Vec<char>,
    /// Completed message hypotheses with their round-trip results.
    pub completions: Vec<Completion>,
}

impl CandidateCell {
    /// The first completion whose round-trip is exact, if any.
    #[must_use]
    pub fn verified(&self) -> Option<&Completion> {
        self.completions
            .iter()
            .find(|completion| completion.exact())
    }
}

/// Where and how the `±1` walk law was violated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotAWalkDetail {
    /// Step index of the first violation (between digits `position` and
    /// `position + 1`).
    pub position: usize,
    /// Digit before the violating move.
    pub from: usize,
    /// Digit after the violating move.
    pub to: usize,
    /// The realized `(to - from) mod base` difference.
    pub diff: usize,
    /// The declared base.
    pub base: usize,
}

/// Verdict of a completed sweep on a valid walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaskVerdict {
    /// A full-letter readout round-trips every ciphertext digit exactly.
    VerifiedDecode,
    /// A full-letter readout exists but no completion round-trips exactly.
    Candidate,
    /// No cell reached letter fraction `1.0`.
    Negative,
}

impl MaskVerdict {
    /// Display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::VerifiedDecode => "VerifiedDecode",
            Self::Candidate => "Candidate",
            Self::Negative => "Negative",
        }
    }
}

/// Full sweep report for a valid `±1` walk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaskReport {
    /// Number of input digits.
    pub n_digits: usize,
    /// Walk base.
    pub base: usize,
    /// Number of direction bits (one fewer than the digit count).
    pub n_bits: usize,
    /// The observed first digit (the round-trip re-encode starts here).
    pub start_digit: usize,
    /// Number of cells swept.
    pub cells_swept: usize,
    /// Ranked cells (letter fraction, then printable fraction, then the
    /// canonical key), truncated to the configured count.
    pub top: Vec<CellReadout>,
    /// Verified/attempted full-letter candidates in canonical rank order.
    pub candidates: Vec<CandidateCell>,
    /// Overall verdict.
    pub verdict: MaskVerdict,
}

impl MaskReport {
    /// The canonical verified candidate and its exact completion, if any.
    #[must_use]
    pub fn verified(&self) -> Option<(&CandidateCell, &Completion)> {
        self.candidates.iter().find_map(|candidate| {
            candidate
                .verified()
                .map(|completion| (candidate, completion))
        })
    }
}

/// Outcome of a `maskdecode` analysis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MaskAnalysis {
    /// The input is a clean `±1` walk; the full sweep report.
    Walk(MaskReport),
    /// The input violates the `±1` law; no readout applies (honest
    /// inapplicability, analogous to the codec engine's `Untransducible`).
    NotAWalk(NotAWalkDetail),
}

impl MaskAnalysis {
    /// The four-way verdict label
    /// (`VerifiedDecode`/`Candidate`/`Negative`/`NotAWalk`).
    #[must_use]
    pub const fn verdict_label(&self) -> &'static str {
        match self {
            Self::Walk(report) => report.verdict.label(),
            Self::NotAWalk(_) => "NotAWalk",
        }
    }
}

/// Configuration for one `maskdecode` run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaskCfg {
    /// ASCII chunk widths to sweep (each in `1..=MAX_WIDTH`).
    pub widths: Vec<usize>,
    /// Number of ranked cells to keep in the report.
    pub top_cells: usize,
}

impl Default for MaskCfg {
    fn default() -> Self {
        Self {
            widths: DEFAULT_WIDTHS.to_vec(),
            top_cells: DEFAULT_TOP_CELLS,
        }
    }
}

fn validate_cfg(cfg: &MaskCfg) -> Result<(), MaskError> {
    if cfg.widths.is_empty() {
        return Err(MaskError::EmptyWidths);
    }
    for &width in &cfg.widths {
        validate_width(width)?;
    }
    Ok(())
}

pub(crate) fn validate_width(width: usize) -> Result<(), MaskError> {
    if width == 0 || width > MAX_WIDTH {
        return Err(MaskError::InvalidWidth { width });
    }
    Ok(())
}

/// Runs the masked-readout sweep on the provided digit stream.
///
/// # Errors
/// Returns [`MaskError`] for configuration problems (empty/out-of-range
/// widths), a base below [`MIN_BASE`], fewer than two digits, or a digit not
/// below the base. A non-`±1` transition is **not** an error: it yields the
/// honest [`MaskAnalysis::NotAWalk`] verdict.
pub fn analyze_mask_decode(
    digits: &[Glyph],
    base: usize,
    cfg: &MaskCfg,
) -> Result<MaskAnalysis, MaskError> {
    validate_cfg(cfg)?;
    if base < MIN_BASE {
        return Err(MaskError::InvalidBase { base });
    }
    if digits.len() < 2 {
        return Err(MaskError::TooFewDigits {
            count: digits.len(),
        });
    }
    let bits = match sweep::derive_direction_bits(digits, base)? {
        sweep::Derivation::Walk(bits) => bits,
        sweep::Derivation::NotAWalk(detail) => return Ok(MaskAnalysis::NotAWalk(detail)),
    };
    let start_digit = digits.first().map_or(0, |glyph| usize::from(glyph.0));

    let cells = sweep::enumerate_cells(&cfg.widths);
    let mut readouts: Vec<CellReadout> = cells
        .iter()
        .map(|params| sweep::read_cell(&bits, params))
        .collect();
    sweep::rank_readouts(&mut readouts);

    let candidates: Vec<CandidateCell> = readouts
        .iter()
        .filter(|readout| readout.all_letters())
        .map(|readout| verify::verify_candidate(readout, &bits, digits, base))
        .collect();
    let verdict = if candidates
        .iter()
        .any(|candidate| candidate.verified().is_some())
    {
        MaskVerdict::VerifiedDecode
    } else if candidates.is_empty() {
        MaskVerdict::Negative
    } else {
        MaskVerdict::Candidate
    };

    Ok(MaskAnalysis::Walk(MaskReport {
        n_digits: digits.len(),
        base,
        n_bits: bits.len(),
        start_digit,
        cells_swept: cells.len(),
        top: readouts.iter().take(cfg.top_cells).cloned().collect(),
        candidates,
        verdict,
    }))
}

/// Runs the masked-readout sweep on the embedded practice puzzle `one`.
///
/// # Errors
/// Returns [`MaskError`] if the embedded fixture fails to parse or the sweep
/// configuration is invalid.
pub fn analyze_embedded_one(cfg: &MaskCfg) -> Result<MaskAnalysis, MaskError> {
    let digits = one_practice_digits()?;
    analyze_mask_decode(&digits, ONE_BASE, cfg)
}

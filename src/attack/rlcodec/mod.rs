//! Run-length codec battery for `±1`-walk (cyclic-difference) puzzles.
//!
//! This module is the library half of the `rlcodec` instrument. Its target is a
//! base-`b` digit sequence whose every first difference is `±1 mod b` — a clean
//! walk on the cycle `C_b`. The *carrier* the instrument analyses is **not** the
//! raw digits, nor the up/down bit string, but the **direction-blind run-length
//! magnitude sequence** `M`: the lengths of the maximal same-direction runs of
//! the walk.
//!
//! On practice puzzle `one` (266 base-5 digits, all 265 transitions `±1 mod 5`)
//! the carrier is settled by a polarity-blind exact repeat: the 26-run block
//! `M[16..42] == M[69..95]` recurs with **opposite run-direction parity**, so the
//! channel that repeats is direction-blind — any codec that reads up/down is the
//! wrong layer (see [`magnitude_census`]).
//!
//! ## Honesty discipline (binding — see `AGENTS.md`)
//!
//! A high n-gram score is **not** a decode. Every codec in the battery is scored
//! against a **matched null** — an order-1 Markov resample of that codec's
//! *decoded symbol stream* (NOT a magnitude-level resample, which would destroy the
//! carrier repeat and yield a false positive), re-scored by the *same* substitution
//! search — and a codec is only a `survivor` if it beats that null at `p < 0.05`. The variable-length comma/prefix codecs score *near
//! English* under a free substitution hill-climb (pareidolia on a short,
//! large-alphabet text) yet do **not** beat the matched null — that `p > 0.05` is
//! the whole point. The expected verdict on real `one` is an **honest negative**;
//! the planted positive control ([`rlcodec_self_test`]) exists only to prove the
//! gate *can* fire.

use std::fmt;

use crate::analysis::translate_isomorph::IsoScanError;
use crate::attack::quadgram::QuadgramError;
use crate::nulls::null::RandomBoundError;

mod battery;
mod census;
mod codecs;
mod derive;
mod plant;
mod search;
mod selftest;

#[cfg(test)]
mod tests;

pub use battery::{
    BatteryReport, CodecVerdict, DerivationSummary, default_battery_cfg, evaluate_codec,
    gate_symbol_stream, run_battery,
};
pub use census::{CensusAnchor, CensusReport, magnitude_census};
pub(crate) use codecs::name_seed_tag;
pub use codecs::{RlCodec, all_codecs, alphabet_size};
pub use derive::{
    ONE_PRACTICE_PUZZLE, RunLengthDerivation, derive_magnitudes, one_practice_digits,
    parse_base_digits,
};
pub use plant::{
    DEFAULT_COMMA_SEP, DEFAULT_PLANT_BASE, PLANT_PLAINTEXT, encode_comma, english_letters,
    partition_of,
};
pub use search::{MIN_LETTERS, SubResult, substitution_search};
pub(crate) use selftest::planted_positive_symbols;
pub use selftest::{SelfTestReport, rlcodec_self_test};

/// Default deterministic seed for the battery's search and matched nulls.
pub const DEFAULT_SEED: u64 = 0x726c_636f_6465_6301;
/// Default number of matched-null trials per codec (CLI report budget).
pub const DEFAULT_NULL_TRIALS: usize = 80;
/// Default substitution-search random restarts (CLI report budget).
pub const DEFAULT_RESTARTS: usize = 10;
/// Default substitution-search proposals per restart (CLI report budget).
pub const DEFAULT_ITERS: usize = 1_500;
/// Default number of census anchors reported.
pub const DEFAULT_TOP_K: usize = 8;
/// Default number of census matched-null trials (cheap longest-repeat draws).
pub const DEFAULT_CENSUS_NULL_TRIALS: usize = 200;
/// Significance threshold a codec must clear to be flagged a survivor.
pub const SURVIVOR_ALPHA: f64 = 0.05;

/// Configuration for one battery run.
///
/// The CLI report uses the larger [`default_battery_cfg`] budget; the in-process
/// self-test and the library tests use deliberately small budgets so
/// `make verify` stays fast (the honest negative is robust to budget, and the
/// planted positive control fires on a strong, long English plaintext).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatteryCfg {
    /// Matched-null trials per codec.
    pub null_trials: usize,
    /// Substitution-search random restarts.
    pub restarts: usize,
    /// Substitution-search proposals per restart.
    pub iters: usize,
    /// Number of census anchors to report.
    pub top_k: usize,
    /// Census matched-null trials.
    pub census_null_trials: usize,
    /// Deterministic seed for the search and every matched null.
    pub seed: u64,
}

/// An error from the run-length codec battery.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RlError {
    /// A base below 2 cannot host a `±1` walk.
    InvalidBase {
        /// The rejected base.
        base: usize,
    },
    /// Fewer than two digits: no first difference exists.
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
    /// A first-difference move was not `±1 mod base` (not a clean walk on `C_b`).
    NonUnitStep {
        /// Digit before the move.
        from: usize,
        /// Digit after the move.
        to: usize,
        /// The realized `(to - from) mod base` difference.
        diff: usize,
        /// The declared base.
        base: usize,
    },
    /// A non-digit character appeared while parsing a base-`b` digit string.
    InvalidDigit {
        /// The offending character.
        character: char,
    },
    /// The run-length encode produced no magnitudes (degenerate input).
    EmptyMagnitudes,
    /// The bundled English quadgram model could not be built.
    Quadgram(QuadgramError),
    /// A translate-isomorph helper (anchor scan / Markov resample) failed.
    Iso(IsoScanError),
    /// An in-crate random draw rejected its bound.
    Random(RandomBoundError),
}

impl From<QuadgramError> for RlError {
    fn from(error: QuadgramError) -> Self {
        Self::Quadgram(error)
    }
}

impl From<IsoScanError> for RlError {
    fn from(error: IsoScanError) -> Self {
        Self::Iso(error)
    }
}

impl From<RandomBoundError> for RlError {
    fn from(error: RandomBoundError) -> Self {
        Self::Random(error)
    }
}

impl fmt::Display for RlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBase { base } => {
                write!(f, "base {base} cannot host a ±1 walk (need >= 2)")
            }
            Self::TooFewDigits { count } => {
                write!(f, "need at least two digits, have {count}")
            }
            Self::SymbolOutOfRange { value, base } => {
                write!(f, "digit {value} is not below the declared base {base}")
            }
            Self::NonUnitStep {
                from,
                to,
                diff,
                base,
            } => write!(
                f,
                "transition {from}->{to} is {diff} mod {base}, not ±1: input is not a clean ±1 walk"
            ),
            Self::InvalidDigit { character } => {
                write!(f, "invalid base digit {character:?}")
            }
            Self::EmptyMagnitudes => write!(f, "run-length encoding produced no magnitudes"),
            Self::Quadgram(error) => write!(f, "quadgram model: {error}"),
            Self::Iso(error) => write!(f, "translate-isomorph helper: {error}"),
            Self::Random(error) => write!(f, "random draw rejected bound {}", error.bound),
        }
    }
}

impl std::error::Error for RlError {}

/// The `0`-based magnitude carrier stream and its alphabet size.
///
/// Magnitudes are `>= 1`; the carrier maps each magnitude `m` to `m - 1` so the
/// alphabet is the maximum magnitude (`>= 1`). This is the stream the
/// translate-isomorph anchor scan and the census order-1 Markov matched null run
/// on.
pub(crate) fn magnitude_carrier(magnitudes: &[usize]) -> (Vec<u32>, usize) {
    let max_magnitude = magnitudes.iter().copied().max().unwrap_or(1).max(1);
    let stream = magnitudes
        .iter()
        .map(|&m| u32::try_from(m.saturating_sub(1)).unwrap_or(0))
        .collect();
    (stream, max_magnitude)
}

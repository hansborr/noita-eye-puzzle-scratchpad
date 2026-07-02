//! Pair-class decipherment instrument for `±1`-walk carriers with an
//! expanding two-symbols-per-letter codec (the practice-puzzle-`two`
//! rotor-carrier model).
//!
//! Under that model each plaintext letter emits two walk steps, so the walk's
//! direction-bit *pair* is a public 4-class image of the plaintext: the token
//! stream is the plaintext pushed through an unknown 4-coloring of the
//! alphabet, attackable with no knowledge of the hidden deck channel. This
//! module derives the token streams (both pair phases), locates exact repeated
//! spans (tie anchors, a *plaintext-repeat hypothesis*), and runs a
//! dictionary-propagation beam solver over the letter positions in which the
//! coloring is induced incrementally and tied positions are hard letter
//! equalities.
//!
//! Memory is bounded by construction: beam selection streams candidate
//! expansions through a bounded heap (never materializing more than `beam`
//! survivors plus one candidate), and the backtrace arena grows exactly one
//! entry per kept state per position. [`solve()`] estimates its peak before
//! allocating and refuses to start past the configured cap — the 2026 Python
//! prototype of this search OOM-crashed its host; the Rust port makes that
//! failure mode a checked error instead.
//!
//! The solver emits **candidates, never decodes**: a full segmentation is a
//! hypothesis to be gated against the matched order-1 Markov token null and
//! anchor consistency, and calibrated with planted controls
//! ([`measure_power`]). The campaign record for the model lives in
//! `research/data/practice-puzzles/CODEC-RESULTS.md` §"rotor-carrier campaign".

mod anchor;
mod campaign;
mod lexicon;
mod plant;
mod selftest;
mod solve;
#[cfg(test)]
mod tests;
mod ties;

pub use anchor::{
    AnchorHarvestReport, AnchorNullCfg, AnchorPlantOutcome, AnchorPowerReport, AnchorSeedReport,
    AnchorSeededSolution, AnchorWindow, HarvestedColoring, MAX_HARVEST_COLORINGS, SeededOutcome,
    anchor_null_gate, harvest_anchor_colorings, measure_anchor_seed_power, solve_anchor_seeded,
};
pub use campaign::{
    NullGate, PlantOutcome, PowerCfg, PowerReport, StreamPrep, measure_power, null_gate,
    prepare_stream, solve_cfg,
};

pub use lexicon::{Lexicon, build_lexicon, parse_wordlist};
pub use plant::{CopySpan, Plant, PlantSpec, copy_ties, markov_resample, plant_from_text};
pub use selftest::{
    NullLeg, PairclassSelfTest, PlantLeg, PruneLeg, TWO_ANCHOR_MIN_LEN, TWO_ANCHORS,
    TWO_PHASE0_MARGINALS, TwoRegression, pairclass_self_test, recovery_fraction,
};
pub use solve::{Solution, SolveCfg, SolveInput, SolveReport, TruthFate, estimate_peak_mib, solve};
pub use ties::{TieSpan, maximal_repeats, tie_targets, token_ties};

/// Default deterministic seed for plants, nulls, and the self-test.
pub const DEFAULT_SEED: u64 = 0x7061_6972_636c_6173;

use crate::core::glyph::{Alphabet, Glyph};
use crate::core::ingest;

/// The walk modulus of the `two` rotor channel (`r = value mod 3`).
pub const TWO_MODULUS: usize = 3;
/// The ciphertext alphabet of practice puzzle `two`.
pub const TWO_ALPHABET: &str = "ABCDEFGHIJKL";
/// Number of pair-token classes the packed solver supports.
pub const MAX_CLASSES: u8 = 4;
/// Letters of the solver's plaintext alphabet (`a..z`).
pub const N_LETTERS: u8 = 26;

/// Errors from derivation, lexicon building, planting, or the solver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PairclassError {
    /// The input stream is empty (or too short to derive any pair token).
    EmptyInput,
    /// A stream value is out of range for the declared modulus derivation.
    SymbolOutOfRange {
        /// Offending value.
        value: usize,
        /// Number of distinct input symbols.
        n_symbols: usize,
    },
    /// The walk modulus must be at least 3 for `±1` directions to differ.
    ModulusTooSmall {
        /// The rejected modulus.
        modulus: usize,
    },
    /// The token stream uses more classes than the packed solver supports.
    TooManyClasses {
        /// Distinct classes found.
        found: usize,
    },
    /// The wordlist produced no usable `a..z` words.
    EmptyLexicon,
    /// The beam width must be at least 1.
    BeamZero,
    /// The solver's estimated peak memory exceeds the configured cap.
    MemoryCap {
        /// Estimated peak in MiB.
        estimated_mib: usize,
        /// Configured cap in MiB.
        cap_mib: usize,
    },
    /// The plant source text has too few `a..z` letters.
    PlantTooShort {
        /// Letters required.
        needed: usize,
        /// Letters available.
        have: usize,
    },
    /// A plant copy span or tie table refers to out-of-range positions.
    SpanOutOfRange,
    /// A truth stream's length does not match the token stream.
    TruthLengthMismatch {
        /// Truth letters supplied.
        truth: usize,
        /// Token positions to cover.
        tokens: usize,
    },
    /// A seed coloring did not have one slot per plaintext letter.
    SeedColoringLength {
        /// Slots supplied.
        len: usize,
    },
    /// A seed coloring assigned a class outside the stream's class range.
    SeedColoringClass {
        /// Letter index (`0..26`).
        letter: usize,
        /// Rejected class.
        class: u8,
        /// Number of classes in the stream.
        n_classes: u8,
    },
    /// Anchor-seeded mode was requested without a usable repeated span.
    AnchorUnavailable,
    /// The requested harvest size must be at least one.
    PhraseTopZero,
    /// The requested harvest size exceeds the fixed safety cap.
    PhraseTopTooLarge {
        /// Requested distinct colorings.
        requested: usize,
        /// Maximum accepted distinct colorings.
        cap: usize,
    },
    /// A deterministic null-model helper rejected its bound.
    NullModel(String),
    /// The embedded `two` fixture failed to parse (should be unreachable).
    Fixture(String),
}

impl std::fmt::Display for PairclassError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "input stream is empty or shorter than one pair"),
            Self::SymbolOutOfRange { value, n_symbols } => {
                write!(
                    f,
                    "stream value {value} out of range for {n_symbols} symbols"
                )
            }
            Self::ModulusTooSmall { modulus } => {
                write!(f, "walk modulus {modulus} < 3: +1 and -1 steps coincide")
            }
            Self::TooManyClasses { found } => {
                write!(
                    f,
                    "token stream has {found} classes; the packed solver supports <= 4"
                )
            }
            Self::EmptyLexicon => write!(f, "wordlist contains no usable a..z words"),
            Self::BeamZero => write!(f, "beam width must be >= 1"),
            Self::MemoryCap {
                estimated_mib,
                cap_mib,
            } => write!(
                f,
                "estimated peak memory {estimated_mib} MiB exceeds --max-mem-mib {cap_mib}; \
                 lower --beam or raise the cap"
            ),
            Self::PlantTooShort { needed, have } => {
                write!(f, "plant text has {have} letters; {needed} needed")
            }
            Self::SpanOutOfRange => write!(f, "span or tie refers to out-of-range positions"),
            Self::TruthLengthMismatch { truth, tokens } => {
                write!(
                    f,
                    "truth has {truth} letters but the stream has {tokens} tokens"
                )
            }
            Self::SeedColoringLength { len } => {
                write!(f, "seed coloring has {len} slots; expected 26")
            }
            Self::SeedColoringClass {
                letter,
                class,
                n_classes,
            } => write!(
                f,
                "seed coloring maps letter {letter} to class {class}, outside 0..{n_classes}"
            ),
            Self::AnchorUnavailable => write!(
                f,
                "anchor-seeded mode needs a longest repeated tie span; enable anchors or lower \
                 --min-anchor-len"
            ),
            Self::PhraseTopZero => write!(f, "--phrase-top must be >= 1"),
            Self::PhraseTopTooLarge { requested, cap } => {
                write!(f, "--phrase-top {requested} exceeds the safety cap {cap}")
            }
            Self::NullModel(detail) => write!(f, "null-model failure: {detail}"),
            Self::Fixture(detail) => write!(f, "embedded fixture failure: {detail}"),
        }
    }
}

impl std::error::Error for PairclassError {}

/// The first walk violation: a transition whose residue difference is not `±1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalkViolation {
    /// Transition index (between values `position` and `position + 1`).
    pub position: usize,
    /// Residue stepped from.
    pub from: usize,
    /// Residue stepped to.
    pub to: usize,
    /// The offending difference mod the modulus.
    pub diff: usize,
    /// The walk modulus.
    pub modulus: usize,
}

/// Outcome of the walk gate on the residue channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PairDerivation {
    /// Every transition was `±1`: the derived direction bits.
    Walk(PairTokens),
    /// The residue channel is not a `±1` walk; the pair-class model does not
    /// apply.
    NotAWalk(WalkViolation),
}

/// Direction bits of a verified `±1` residue walk, with pair-token accessors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairTokens {
    /// Input stream length in symbols.
    pub n_values: usize,
    /// The walk modulus used for the residue channel.
    pub modulus: usize,
    /// Direction bits (`true` = the `+1` step); `n_values - 1` entries.
    pub bits: Vec<bool>,
}

impl PairTokens {
    /// Pair tokens at the given phase: token `k` packs bits
    /// `(phase + 2k, phase + 2k + 1)` as `2*b0 + b1`.
    #[must_use]
    pub fn tokens(&self, phase: usize) -> Vec<u8> {
        let body = self.bits.get(phase..).unwrap_or(&[]);
        body.chunks_exact(2)
            .map(|pair| match pair {
                [b0, b1] => (u8::from(*b0) << 1) | u8::from(*b1),
                _ => 0,
            })
            .collect()
    }

    /// Token-class histogram (classes `0..4`) at the given phase.
    #[must_use]
    pub fn marginals(&self, phase: usize) -> [usize; 4] {
        let mut counts = [0usize; 4];
        for token in self.tokens(phase) {
            if let Some(slot) = counts.get_mut(usize::from(token)) {
                *slot += 1;
            }
        }
        counts
    }
}

/// Derives the direction bits of the residue channel `r = value mod modulus`,
/// gating on every transition being `±1 mod modulus`.
///
/// # Errors
/// [`PairclassError::ModulusTooSmall`] below modulus 3 and
/// [`PairclassError::EmptyInput`] for streams shorter than two values.
pub fn derive_pair_tokens(
    values: &[Glyph],
    modulus: usize,
) -> Result<PairDerivation, PairclassError> {
    if modulus < 3 {
        return Err(PairclassError::ModulusTooSmall { modulus });
    }
    if values.len() < 2 {
        return Err(PairclassError::EmptyInput);
    }
    let mut bits = Vec::with_capacity(values.len() - 1);
    for (position, pair) in values.windows(2).enumerate() {
        let [a, b] = pair else { continue };
        let from = usize::from(a.0) % modulus;
        let to = usize::from(b.0) % modulus;
        let diff = (to + modulus - from) % modulus;
        if diff == 1 {
            bits.push(true);
        } else if diff == modulus - 1 {
            bits.push(false);
        } else {
            return Ok(PairDerivation::NotAWalk(WalkViolation {
                position,
                from,
                to,
                diff,
                modulus,
            }));
        }
    }
    Ok(PairDerivation::Walk(PairTokens {
        n_values: values.len(),
        modulus,
        bits,
    }))
}

/// The embedded practice puzzle `two` (698 symbols over [`TWO_ALPHABET`]).
///
/// # Errors
/// [`PairclassError::Fixture`] if the checked-in fixture fails to parse
/// (unreachable for the committed file; kept as an error so the library never
/// panics).
pub fn embedded_two() -> Result<Vec<Glyph>, PairclassError> {
    let raw = include_str!("../../../research/data/practice-puzzles/two");
    let alphabet = Alphabet::from_chars(TWO_ALPHABET)
        .map_err(|c| PairclassError::Fixture(format!("bad alphabet char {c:?}")))?;
    let transparent = ingest::TransparentSet::default();
    let parsed = ingest::parse_sequence(
        raw,
        ingest::SequenceLayer::CipherAlphabet {
            alphabet: &alphabet,
            transparent: &transparent,
        },
    )
    .map_err(|error| PairclassError::Fixture(error.to_string()))?;
    Ok(parsed.glyphs)
}

/// Validates a raw token stream (values `0..4`) and reports its class count.
///
/// # Errors
/// [`PairclassError::EmptyInput`] on an empty stream and
/// [`PairclassError::TooManyClasses`] when a token is outside `0..4`.
pub fn validate_tokens(tokens: &[u8]) -> Result<u8, PairclassError> {
    if tokens.is_empty() {
        return Err(PairclassError::EmptyInput);
    }
    let max = tokens.iter().copied().max().unwrap_or(0);
    if max >= MAX_CLASSES {
        return Err(PairclassError::TooManyClasses {
            found: usize::from(max) + 1,
        });
    }
    Ok(max + 1)
}

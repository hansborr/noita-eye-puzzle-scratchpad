//! Closure-shadow hidden-state key search for repeated-span GAK structure.
//!
//! The instrument derives its closure group from raw equality-pattern isomorphs,
//! treats that group as a lower-bound shadow, and emits quotient candidates only.
//! It never scores language and never promotes a survivor to a decode.

use std::fmt;

use crate::analysis::isomorph_map::{self, GroupClosure, IsoMapError, IsoMapReport};
use crate::ciphers::CipherError;

mod anchors;
mod control;
mod engine;
mod ranking;
#[cfg(test)]
mod tests;

pub use control::{ShadowSearchSelfTest, shadow_search_self_test};
pub use engine::{
    CanonicalClass, FiberReport, KeyChoice, RepresentativeKey, ScoredSurvivor, SearchSummary,
};
pub use isomorph_map::{
    DEFAULT_CLOSURE_CAP, DEFAULT_MIN_SPAN_LEN, DEFAULT_NULL_TRIALS, DEFAULT_SEED, DEFAULT_TOP_K,
    DEFAULT_TRIM,
};

/// Default minimum post-trim hard-anchor length.
pub const DEFAULT_HARD_MIN_LEN: usize = 8;
/// Default minimum raw literal-repeat length considered as a soft anchor.
pub const DEFAULT_SOFT_MIN_LEN: usize = 5;
/// Default maximum raw literal-repeat length considered as a soft anchor.
pub const DEFAULT_SOFT_MAX_LEN: usize = 7;
/// Default boundary trim for literal-repeat soft anchors.
pub const DEFAULT_SOFT_TRIM: usize = 1;
/// Default maximum canonical classes retained in the report artifact.
pub const DEFAULT_CLASS_REPORT_LIMIT: usize = 64;

const MIN_STREAM_LEN: usize = 4;

/// Configuration for the closure-shadow hidden-state key search.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShadowSearchConfig {
    /// Minimum raw equality-pattern span length passed to `isomap`.
    pub min_span_len: usize,
    /// Boundary trim used while extracting full column maps for closure.
    pub map_trim: usize,
    /// Boundary trim applied to hard equality anchors.
    pub hard_anchor_trim: usize,
    /// Minimum hard-anchor length after trimming.
    pub hard_min_len: usize,
    /// Maximum number of raw pattern-isomorph span pairs kept by `isomap`.
    pub top_k: usize,
    /// Number of order-1 Markov null trials for `isomap`.
    pub null_trials: usize,
    /// Maximum generated closure size.
    pub closure_cap: usize,
    /// Deterministic seed used by null calibration and controls.
    pub seed: u64,
    /// Minimum raw literal-repeat length considered as a soft anchor.
    pub soft_min_len: usize,
    /// Maximum raw literal-repeat length considered as a soft anchor.
    pub soft_max_len: usize,
    /// Boundary trim applied to soft anchors.
    pub soft_trim: usize,
    /// Maximum top canonical classes retained in the report.
    pub class_report_limit: usize,
}

impl Default for ShadowSearchConfig {
    fn default() -> Self {
        Self {
            min_span_len: DEFAULT_MIN_SPAN_LEN,
            map_trim: DEFAULT_TRIM,
            hard_anchor_trim: DEFAULT_TRIM,
            hard_min_len: DEFAULT_HARD_MIN_LEN,
            top_k: DEFAULT_TOP_K,
            null_trials: DEFAULT_NULL_TRIALS,
            closure_cap: DEFAULT_CLOSURE_CAP,
            seed: DEFAULT_SEED,
            soft_min_len: DEFAULT_SOFT_MIN_LEN,
            soft_max_len: DEFAULT_SOFT_MAX_LEN,
            soft_trim: DEFAULT_SOFT_TRIM,
            class_report_limit: DEFAULT_CLASS_REPORT_LIMIT,
        }
    }
}

/// One span-equality constraint derived from ciphertext structure.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Anchor {
    /// First start position after trim.
    pub first: usize,
    /// Second start position after trim.
    pub second: usize,
    /// Trimmed anchor length.
    pub length: usize,
    /// Raw first start before trim.
    pub raw_first: usize,
    /// Raw second start before trim.
    pub raw_second: usize,
    /// Raw span length before trim.
    pub raw_length: usize,
    /// Boundary trim applied per side.
    pub trim: usize,
}

/// Reason a search refused to enumerate keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoBasisReason {
    /// The raw equality-pattern detector did not clear its matched null.
    NoSignificantIsomorphStructure,
    /// Significant spans existed, but none yielded a full column map.
    NoFullColumnMaps,
    /// Full maps closed only to the trivial group.
    TrivialClosure,
    /// The closure and observed stream did not imply any legal readout symbols.
    NoLegalReadouts,
    /// Trimming removed every hard anchor that could support the search.
    NoHardAnchors,
}

impl NoBasisReason {
    /// Stable display string for reports and artifacts.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::NoSignificantIsomorphStructure => "no-significant-isomorph-structure",
            Self::NoFullColumnMaps => "no-full-column-maps",
            Self::TrivialClosure => "trivial-closure",
            Self::NoLegalReadouts => "no-legal-readouts",
            Self::NoHardAnchors => "no-hard-anchors",
        }
    }
}

/// Outcome of a closure-shadow key-search run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShadowSearchOutcome {
    /// The instrument refused to search because the closure basis was not
    /// supported by the input.
    NoBasis {
        /// Refusal reason.
        reason: NoBasisReason,
    },
    /// Keys were enumerated and quotient candidates were scored.
    Searched {
        /// Search counts, score histogram, and top canonical classes.
        summary: SearchSummary,
        /// Deduplicated q-index survivor sequences with key multiplicities.
        survivors: Vec<ScoredSurvivor>,
    },
}

/// Complete output from the closure-shadow key-search instrument.
#[derive(Clone, Debug, PartialEq)]
pub struct ShadowSearchReport {
    /// Raw input length.
    pub input_len: usize,
    /// Declared alphabet size.
    pub alphabet_size: usize,
    /// The upstream isomorph-map detector output used as the basis.
    pub isomap: IsoMapReport,
    /// Closure generated from the full column maps, if enough basis existed.
    pub closure: Option<GroupClosure>,
    /// Legal readout symbols derived from the closure and observed stream.
    pub legal_readouts: Vec<usize>,
    /// Fiber sizes and group-element indices for each legal readout.
    pub fibers: Vec<FiberReport>,
    /// Total key-space size `|G| * product(|F_q|)`, if it could be derived.
    pub key_space: Option<u128>,
    /// Boundary-trimmed hard anchors derived from pattern isomorphs.
    pub hard_anchors: Vec<Anchor>,
    /// Boundary-trimmed soft anchors derived from short literal repeats.
    pub soft_anchors: Vec<Anchor>,
    /// Search refusal or survivor/ranking output.
    pub outcome: ShadowSearchOutcome,
}

/// Error returned by the closure-shadow key-search instrument.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShadowSearchError {
    /// The declared alphabet size was zero.
    EmptyAlphabet,
    /// The stream is too short for this structural search.
    StreamTooShort {
        /// Raw symbol count.
        length: usize,
    },
    /// A symbol is outside the declared alphabet.
    SymbolOutsideAlphabet {
        /// Raw position in the stream.
        position: usize,
        /// Observed symbol value.
        symbol: usize,
        /// Declared alphabet size.
        alphabet_size: usize,
    },
    /// Trimming would remove an entire anchor.
    TrimTooLarge {
        /// Requested trim.
        trim: usize,
        /// Raw span length.
        length: usize,
    },
    /// Isomorph-map detection or closure failed.
    IsoMap(IsoMapError),
    /// Permutation validation or composition failed.
    Permutation(CipherError),
    /// A legal readout had no corresponding closure fiber.
    MissingFiber {
        /// Readout symbol.
        readout: usize,
    },
    /// The computed key space overflowed `u128`.
    KeySpaceOverflow,
    /// More legal readouts were derived than can be stored in a q-index stream.
    TooManyLegalReadouts {
        /// Derived legal-readout count.
        count: usize,
    },
}

impl From<IsoMapError> for ShadowSearchError {
    fn from(error: IsoMapError) -> Self {
        Self::IsoMap(error)
    }
}

impl From<CipherError> for ShadowSearchError {
    fn from(error: CipherError) -> Self {
        Self::Permutation(error)
    }
}

impl fmt::Display for ShadowSearchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyAlphabet => write!(formatter, "alphabet size must be non-zero"),
            Self::StreamTooShort { length } => {
                write!(
                    formatter,
                    "stream too short: need at least {MIN_STREAM_LEN} symbols, have {length}"
                )
            }
            Self::SymbolOutsideAlphabet {
                position,
                symbol,
                alphabet_size,
            } => write!(
                formatter,
                "symbol {symbol} at position {position} is outside alphabet size {alphabet_size}"
            ),
            Self::TrimTooLarge { trim, length } => write!(
                formatter,
                "boundary trim {trim} per side leaves no core in span length {length}"
            ),
            Self::IsoMap(error) => write!(formatter, "isomorph-map basis error: {error}"),
            Self::Permutation(error) => write!(formatter, "permutation error: {error}"),
            Self::MissingFiber { readout } => {
                write!(formatter, "no closure fiber found for readout {readout}")
            }
            Self::KeySpaceOverflow => write!(formatter, "key-space size overflowed u128"),
            Self::TooManyLegalReadouts { count } => write!(
                formatter,
                "derived {count} legal readouts, exceeding the q-index stream limit"
            ),
        }
    }
}

impl std::error::Error for ShadowSearchError {}

/// Runs closure derivation, two-pass key filtering, deduplication, soft scoring,
/// and canonical-class ranking.
///
/// A searched outcome contains quotient candidates under the closure (shadow)
/// group only. The closure is a lower bound; for `two`, an order-48 shadow
/// survivor does not certify a key in the reported order-96 true group.
///
/// # Errors
/// Returns [`ShadowSearchError`] for invalid input, invalid trims, permutation
/// failures, random-draw failures from the upstream null, or key-space overflow.
#[allow(
    clippy::too_many_lines,
    reason = "top-level production orchestration keeps the stage ordering explicit"
)]
pub fn run_shadow_search(
    values: &[u16],
    alphabet_size: usize,
    config: ShadowSearchConfig,
) -> Result<ShadowSearchReport, ShadowSearchError> {
    validate_input(values, alphabet_size)?;
    let isomap = isomorph_map::isomorph_map_scan(
        values,
        alphabet_size,
        config.min_span_len,
        config.map_trim,
        config.top_k,
        config.null_trials,
        config.seed,
    )?;
    let soft_anchors = anchors::derive_soft_anchors(
        values,
        config.soft_min_len,
        config.soft_max_len,
        config.soft_trim,
    )?;

    if !isomap.significant {
        return Ok(no_basis_report(
            values,
            alphabet_size,
            isomap,
            None,
            soft_anchors,
            NoBasisReason::NoSignificantIsomorphStructure,
        ));
    }

    let full_maps: Vec<Vec<usize>> = isomap
        .maps
        .iter()
        .filter_map(|map| map.permutation.clone())
        .collect();
    if full_maps.is_empty() {
        return Ok(no_basis_report(
            values,
            alphabet_size,
            isomap,
            None,
            soft_anchors,
            NoBasisReason::NoFullColumnMaps,
        ));
    }

    let closure = isomorph_map::close_full_maps(&full_maps, alphabet_size, config.closure_cap)?;
    if closure.order <= 1 {
        return Ok(no_basis_report(
            values,
            alphabet_size,
            isomap,
            Some(closure),
            soft_anchors,
            NoBasisReason::TrivialClosure,
        ));
    }

    let prepared = engine::prepare_basis(values, alphabet_size, &closure)?;
    if prepared.legal_readouts.is_empty() {
        return Ok(no_basis_report(
            values,
            alphabet_size,
            isomap,
            Some(closure),
            soft_anchors,
            NoBasisReason::NoLegalReadouts,
        ));
    }

    let hard_anchors = anchors::derive_hard_anchors(
        &isomap.maps,
        &closure.elements,
        prepared.legal_readouts.len(),
        config.hard_anchor_trim,
        config.hard_min_len,
    )?;
    if hard_anchors.is_empty() {
        return Ok(ShadowSearchReport {
            input_len: values.len(),
            alphabet_size,
            isomap,
            closure: Some(closure),
            legal_readouts: prepared.legal_readouts,
            fibers: prepared.fiber_reports,
            key_space: Some(prepared.key_space),
            hard_anchors,
            soft_anchors,
            outcome: ShadowSearchOutcome::NoBasis {
                reason: NoBasisReason::NoHardAnchors,
            },
        });
    }

    let search = engine::search(values, &prepared, &hard_anchors, &soft_anchors, config)?;
    Ok(ShadowSearchReport {
        input_len: values.len(),
        alphabet_size,
        isomap,
        closure: Some(closure),
        legal_readouts: prepared.legal_readouts,
        fibers: prepared.fiber_reports,
        key_space: Some(prepared.key_space),
        hard_anchors,
        soft_anchors,
        outcome: ShadowSearchOutcome::Searched {
            summary: search.summary,
            survivors: search.survivors,
        },
    })
}

fn validate_input(values: &[u16], alphabet_size: usize) -> Result<(), ShadowSearchError> {
    if alphabet_size == 0 {
        return Err(ShadowSearchError::EmptyAlphabet);
    }
    if values.len() < MIN_STREAM_LEN {
        return Err(ShadowSearchError::StreamTooShort {
            length: values.len(),
        });
    }
    for (position, &symbol) in values.iter().enumerate() {
        let symbol = usize::from(symbol);
        if symbol >= alphabet_size {
            return Err(ShadowSearchError::SymbolOutsideAlphabet {
                position,
                symbol,
                alphabet_size,
            });
        }
    }
    Ok(())
}

fn no_basis_report(
    values: &[u16],
    alphabet_size: usize,
    isomap: IsoMapReport,
    closure: Option<GroupClosure>,
    soft_anchors: Vec<Anchor>,
    reason: NoBasisReason,
) -> ShadowSearchReport {
    ShadowSearchReport {
        input_len: values.len(),
        alphabet_size,
        isomap,
        closure,
        legal_readouts: Vec::new(),
        fibers: Vec::new(),
        key_space: None,
        hard_anchors: Vec::new(),
        soft_anchors,
        outcome: ShadowSearchOutcome::NoBasis { reason },
    }
}

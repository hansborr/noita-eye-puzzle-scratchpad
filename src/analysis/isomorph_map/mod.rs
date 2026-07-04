//! Equality-pattern isomorph column-map extraction and group-closure reporting.
//!
//! This module is the full-symbol companion to [`crate::analysis::translate_isomorph`].
//! It searches the raw ciphertext stream for pairs of spans with the same
//! equality pattern: positions that are equal in the first span are equal in the
//! second span, and positions that differ in the first span also differ in the
//! second. The aligned symbols need not be the same symbols. A surviving span
//! pair therefore induces a per-position symbol map `ct[i+k] -> ct[j+k]`, which
//! is extracted after an explicit boundary trim so 1-2 chance-matching edge
//! symbols do not corrupt the structural map.
//!
//! Reported maps and closures are **structural lower bounds**, never decodes.
//! The matched null is an order-1 Markov resample of the same raw symbol stream,
//! so a span pair must clear the observed transition law rather than a
//! structure-destroying shuffle.

use std::fmt;

use crate::analysis::translate_isomorph::{IsoScanError, markov_resample};
use crate::ciphers::{CipherError, validate_permutation};
use crate::nulls::null::{RandomBoundError, SplitMix64, add_one_p_value};

mod group;
#[cfg(test)]
mod tests;

pub use group::{
    BlockSystem, ChainValidation, ChainViolation, GroupClosure, close_full_maps,
    compose_partial_maps, validate_chains,
};

/// Default number of Markov matched-null trials.
pub const DEFAULT_NULL_TRIALS: usize = 200;
/// Default maximum number of span pairs enumerated after calibration.
pub const DEFAULT_TOP_K: usize = 64;
/// Default boundary trim applied before extracting column maps.
pub const DEFAULT_TRIM: usize = 2;
/// Default floor on the raw equality-pattern span length.
pub const DEFAULT_MIN_SPAN_LEN: usize = 8;
/// Default closure cap. Exceeding this means the generated group is no longer a
/// cheap stage-1 structural lower bound.
pub const DEFAULT_CLOSURE_CAP: usize = 100_000;
/// Default deterministic seed for the matched null and controls.
pub const DEFAULT_SEED: u64 = 0x6973_6f6d_6170_0001;

const MIN_STREAM_LEN: usize = 4;

/// Error returned by the equality-pattern isomorph-map instrument.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IsoMapError {
    /// The declared alphabet size was zero.
    EmptyAlphabet,
    /// The stream is too short to scan.
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
    /// Boundary trimming leaves no aligned positions to read.
    TrimTooLarge {
        /// Requested boundary trim per side.
        trim: usize,
        /// Minimum raw span length.
        min_span_len: usize,
    },
    /// A Monte-Carlo draw rejected its bound.
    RandomBound {
        /// Rejected exclusive upper bound.
        bound: usize,
    },
    /// Permutation validation failed while closing full maps.
    Permutation(CipherError),
    /// The generated closure exceeded the configured cap.
    ClosureCapExceeded {
        /// Configured cap.
        cap: usize,
    },
}

impl From<RandomBoundError> for IsoMapError {
    fn from(error: RandomBoundError) -> Self {
        Self::RandomBound { bound: error.bound }
    }
}

impl From<IsoScanError> for IsoMapError {
    fn from(error: IsoScanError) -> Self {
        match error {
            IsoScanError::EmptyAlphabet => Self::EmptyAlphabet,
            IsoScanError::StreamTooShort { length } => Self::StreamTooShort { length },
            IsoScanError::RandomDraw { bound } => Self::RandomBound { bound },
            IsoScanError::ZeroModulus | IsoScanError::ModulusTooLarge { .. } => {
                Self::Permutation(CipherError::InternalInvariant {
                    context: "raw Markov resample projection error",
                })
            }
        }
    }
}

impl From<CipherError> for IsoMapError {
    fn from(error: CipherError) -> Self {
        Self::Permutation(error)
    }
}

impl fmt::Display for IsoMapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyAlphabet => write!(f, "alphabet size must be non-zero"),
            Self::StreamTooShort { length } => {
                write!(
                    f,
                    "stream too short: need at least {MIN_STREAM_LEN} symbols, have {length}"
                )
            }
            Self::SymbolOutsideAlphabet {
                position,
                symbol,
                alphabet_size,
            } => write!(
                f,
                "symbol {symbol} at position {position} is outside alphabet size {alphabet_size}"
            ),
            Self::TrimTooLarge { trim, min_span_len } => write!(
                f,
                "boundary trim {trim} per side leaves no core in minimum span length {min_span_len}"
            ),
            Self::RandomBound { bound } => write!(f, "random draw rejected bound {bound}"),
            Self::Permutation(error) => write!(f, "permutation error: {error}"),
            Self::ClosureCapExceeded { cap } => {
                write!(f, "generated permutation closure exceeded cap {cap}")
            }
        }
    }
}

impl std::error::Error for IsoMapError {}

/// One equality-pattern isomorph span pair in the raw stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PatternSpan {
    /// Raw span length before boundary trimming.
    pub length: usize,
    /// First start position.
    pub first: usize,
    /// Second start position.
    pub second: usize,
    /// Translation distance `second - first`.
    pub gap: usize,
}

/// Classification of an extracted column map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapKind {
    /// The trimmed span determines a bijection over the entire alphabet.
    Full,
    /// The trimmed span determines only a partial injection.
    Partial,
}

/// A boundary-trimmed symbol map extracted from one pattern-isomorph span pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColumnMap {
    /// Span pair that produced the map.
    pub span: PatternSpan,
    /// Positions trimmed from each side before extraction.
    pub trim: usize,
    /// Number of aligned positions used after trimming.
    pub core_len: usize,
    /// Number of boundary positions deliberately excluded from extraction.
    pub boundary_positions_dropped: usize,
    /// Map classification.
    pub kind: MapKind,
    /// Partial map `source_symbol -> target_symbol`; missing entries are `None`.
    pub mapping: Vec<Option<usize>>,
    /// Full permutation, present only when `kind == Full`.
    pub permutation: Option<Vec<usize>>,
}

/// Monte-Carlo calibration for the longest equality-pattern isomorph.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PatternNull {
    /// Number of matched-null trials.
    pub trials: usize,
    /// Mean longest pattern-isomorph length across null trials.
    pub mean_longest: f64,
    /// Largest longest-pattern length reached by any null trial.
    pub ceiling: usize,
    /// Add-one p-value for the observed maximum.
    pub p_value: f64,
}

/// Complete output of the detector and column-map extractor.
#[derive(Clone, Debug, PartialEq)]
pub struct IsoMapReport {
    /// Raw input length.
    pub input_len: usize,
    /// Declared alphabet size.
    pub alphabet_size: usize,
    /// Longest equality-pattern span pair in the raw stream.
    pub observed_max: usize,
    /// Minimum raw span length used for surviving-pair enumeration.
    pub threshold: usize,
    /// Boundary trim applied to every surviving span pair.
    pub trim: usize,
    /// Whether `observed_max` cleared the matched-null ceiling.
    pub significant: bool,
    /// Matched-null calibration.
    pub null: PatternNull,
    /// Surviving span pairs, longest first.
    pub spans: Vec<PatternSpan>,
    /// Extracted maps for the surviving span pairs.
    pub maps: Vec<ColumnMap>,
    /// Number of extracted full bijections.
    pub full_map_count: usize,
    /// Number of extracted partial injections.
    pub partial_map_count: usize,
}

/// Runs equality-pattern isomorph detection and extracts boundary-trimmed column
/// maps from the surviving span pairs.
///
/// The returned maps are structural candidates only; downstream closure is a
/// lower bound on the state group generated by observed full maps.
///
/// # Errors
/// Returns [`IsoMapError`] for invalid input, invalid trimming, random-draw
/// failures, or permutation-validation failures.
pub fn isomorph_map_scan(
    values: &[u16],
    alphabet_size: usize,
    min_span_len: usize,
    trim: usize,
    top_k: usize,
    null_trials: usize,
    seed: u64,
) -> Result<IsoMapReport, IsoMapError> {
    validate_input(values, alphabet_size)?;
    if min_span_len <= trim.saturating_mul(2) {
        return Err(IsoMapError::TrimTooLarge { trim, min_span_len });
    }

    let observed_max = longest_pattern_isomorph_len(values, alphabet_size);
    let stream: Vec<u32> = values.iter().map(|&v| u32::from(v)).collect();
    let mut rng = SplitMix64::new(seed);
    let mut null_sum = 0u64;
    let mut null_ceiling = 0usize;
    let mut reached = 0usize;
    for _ in 0..null_trials {
        let resampled = markov_resample(&stream, alphabet_size, &mut rng)?;
        let trial_values = u32_to_u16_stream(&resampled);
        let trial_max = longest_pattern_isomorph_len(&trial_values, alphabet_size);
        null_sum += trial_max as u64;
        null_ceiling = null_ceiling.max(trial_max);
        if trial_max >= observed_max {
            reached += 1;
        }
    }
    let mean_longest = if null_trials == 0 {
        0.0
    } else {
        null_sum as f64 / null_trials as f64
    };
    let null = PatternNull {
        trials: null_trials,
        mean_longest,
        ceiling: null_ceiling,
        p_value: add_one_p_value(reached, null_trials),
    };
    let significant = null_trials > 0 && observed_max > null_ceiling;
    let threshold = (null_ceiling + 1).max(min_span_len);
    let spans = if significant {
        find_pattern_spans(values, alphabet_size, threshold, top_k)
    } else {
        Vec::new()
    };
    let mut maps = Vec::with_capacity(spans.len());
    for span in &spans {
        maps.push(extract_column_map(values, alphabet_size, *span, trim)?);
    }
    let full_map_count = maps.iter().filter(|map| map.kind == MapKind::Full).count();
    let partial_map_count = maps.len().saturating_sub(full_map_count);

    Ok(IsoMapReport {
        input_len: values.len(),
        alphabet_size,
        observed_max,
        threshold,
        trim,
        significant,
        null,
        spans,
        maps,
        full_map_count,
        partial_map_count,
    })
}

fn validate_input(values: &[u16], alphabet_size: usize) -> Result<(), IsoMapError> {
    if alphabet_size == 0 {
        return Err(IsoMapError::EmptyAlphabet);
    }
    if values.len() < MIN_STREAM_LEN {
        return Err(IsoMapError::StreamTooShort {
            length: values.len(),
        });
    }
    for (position, &symbol) in values.iter().enumerate() {
        let symbol = usize::from(symbol);
        if symbol >= alphabet_size {
            return Err(IsoMapError::SymbolOutsideAlphabet {
                position,
                symbol,
                alphabet_size,
            });
        }
    }
    Ok(())
}

fn u32_to_u16_stream(values: &[u32]) -> Vec<u16> {
    values
        .iter()
        .map(|&value| u16::try_from(value).unwrap_or(0))
        .collect()
}

#[derive(Clone, Debug)]
struct PatternScratch {
    forward_seen: Vec<u32>,
    forward: Vec<usize>,
    reverse_seen: Vec<u32>,
    reverse: Vec<usize>,
    epoch: u32,
}

impl PatternScratch {
    fn new(alphabet_size: usize) -> Self {
        Self {
            forward_seen: vec![0; alphabet_size],
            forward: vec![0; alphabet_size],
            reverse_seen: vec![0; alphabet_size],
            reverse: vec![0; alphabet_size],
            epoch: 0,
        }
    }

    fn next_epoch(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        if self.epoch == 0 {
            self.forward_seen.fill(0);
            self.reverse_seen.fill(0);
            self.epoch = 1;
        }
    }
}

fn pattern_lcp(
    values: &[u16],
    alphabet_size: usize,
    first: usize,
    second: usize,
    scratch: &mut PatternScratch,
) -> usize {
    debug_assert!(first < second);
    let max_len = values.len().saturating_sub(second);
    scratch.next_epoch();
    let mut len = 0usize;
    while len < max_len {
        let Some(source) = values.get(first + len).map(|&value| usize::from(value)) else {
            break;
        };
        let Some(target) = values.get(second + len).map(|&value| usize::from(value)) else {
            break;
        };
        debug_assert!(source < alphabet_size);
        debug_assert!(target < alphabet_size);

        let source_seen = scratch
            .forward_seen
            .get(source)
            .is_some_and(|&seen| seen == scratch.epoch);
        let target_seen = scratch
            .reverse_seen
            .get(target)
            .is_some_and(|&seen| seen == scratch.epoch);
        if source_seen && scratch.forward.get(source).copied() != Some(target) {
            break;
        }
        if target_seen && scratch.reverse.get(target).copied() != Some(source) {
            break;
        }
        if !source_seen {
            let Some(seen) = scratch.forward_seen.get_mut(source) else {
                break;
            };
            *seen = scratch.epoch;
            let Some(mapped) = scratch.forward.get_mut(source) else {
                break;
            };
            *mapped = target;
        }
        if !target_seen {
            let Some(seen) = scratch.reverse_seen.get_mut(target) else {
                break;
            };
            *seen = scratch.epoch;
            let Some(mapped) = scratch.reverse.get_mut(target) else {
                break;
            };
            *mapped = source;
        }
        len += 1;
    }
    len
}

fn longest_pattern_isomorph_len(values: &[u16], alphabet_size: usize) -> usize {
    if values.len() < 2 {
        return 0;
    }
    let mut scratch = PatternScratch::new(alphabet_size);
    let mut best = 0usize;
    for first in 0..values.len() {
        for second in (first + 1)..values.len() {
            let len = pattern_lcp(values, alphabet_size, first, second, &mut scratch);
            best = best.max(len);
        }
    }
    best
}

fn find_pattern_spans(
    values: &[u16],
    alphabet_size: usize,
    threshold: usize,
    top_k: usize,
) -> Vec<PatternSpan> {
    if threshold == 0 || top_k == 0 || threshold > values.len() {
        return Vec::new();
    }
    let mut scratch = PatternScratch::new(alphabet_size);
    let mut candidates = Vec::new();
    for first in 0..values.len() {
        for second in (first + 1)..values.len() {
            let length = pattern_lcp(values, alphabet_size, first, second, &mut scratch);
            if length >= threshold {
                candidates.push(PatternSpan {
                    length,
                    first,
                    second,
                    gap: second - first,
                });
            }
        }
    }
    candidates.sort_by(|left, right| {
        right
            .length
            .cmp(&left.length)
            .then_with(|| left.gap.cmp(&right.gap))
            .then_with(|| left.first.cmp(&right.first))
    });
    let mut kept: Vec<PatternSpan> = Vec::new();
    for candidate in candidates {
        let nested = kept.iter().any(|existing| {
            existing.gap == candidate.gap
                && existing.first <= candidate.first
                && candidate.first + candidate.length <= existing.first + existing.length
        });
        if !nested {
            kept.push(candidate);
            if kept.len() >= top_k {
                break;
            }
        }
    }
    kept
}

fn extract_column_map(
    values: &[u16],
    alphabet_size: usize,
    span: PatternSpan,
    trim: usize,
) -> Result<ColumnMap, IsoMapError> {
    let core_len = span.length.saturating_sub(trim.saturating_mul(2));
    if core_len == 0 {
        return Err(IsoMapError::TrimTooLarge {
            trim,
            min_span_len: span.length,
        });
    }
    let mut mapping = vec![None; alphabet_size];
    let mut reverse = vec![None; alphabet_size];
    for offset in trim..(span.length - trim) {
        let source = values
            .get(span.first + offset)
            .map(|&value| usize::from(value))
            .ok_or(IsoMapError::Permutation(CipherError::InternalInvariant {
                context: "pattern-isomorph source lookup",
            }))?;
        let target = values
            .get(span.second + offset)
            .map(|&value| usize::from(value))
            .ok_or(IsoMapError::Permutation(CipherError::InternalInvariant {
                context: "pattern-isomorph target lookup",
            }))?;
        match mapping.get(source).copied().flatten() {
            Some(existing) if existing != target => {
                return Err(IsoMapError::Permutation(CipherError::InternalInvariant {
                    context: "pattern-isomorph source collision",
                }));
            }
            Some(_) => {}
            None => {
                let Some(slot) = mapping.get_mut(source) else {
                    return Err(IsoMapError::Permutation(CipherError::InternalInvariant {
                        context: "pattern-isomorph source map slot",
                    }));
                };
                *slot = Some(target);
            }
        }
        match reverse.get(target).copied().flatten() {
            Some(existing) if existing != source => {
                return Err(IsoMapError::Permutation(CipherError::InternalInvariant {
                    context: "pattern-isomorph target collision",
                }));
            }
            Some(_) => {}
            None => {
                let Some(slot) = reverse.get_mut(target) else {
                    return Err(IsoMapError::Permutation(CipherError::InternalInvariant {
                        context: "pattern-isomorph target map slot",
                    }));
                };
                *slot = Some(source);
            }
        }
    }
    let permutation = mapping.iter().copied().collect::<Option<Vec<_>>>();
    let kind = if let Some(permutation) = permutation.as_deref() {
        validate_permutation("isomorph column map", permutation, alphabet_size)?;
        MapKind::Full
    } else {
        MapKind::Partial
    };
    Ok(ColumnMap {
        span,
        trim,
        core_len,
        boundary_positions_dropped: span.length - core_len,
        kind,
        mapping,
        permutation,
    })
}

//! Planted positive controls and the matched order-1 Markov token null.
//!
//! A plant takes real English text, optionally imposes a repeated-span
//! topology (mirroring the tie anchors of the real target), pushes it through
//! a seed-deterministic random coloring, and yields the token stream plus the
//! ground truth. Solving the plant with truth tracking measures the search's
//! *power* at the target's length — the controls-first discipline that gates
//! every real-stream claim. The Markov resample is the matched null: same
//! marginals and first-order transitions, no plaintext.

use crate::nulls::null::{SplitMix64, mix_seed, random_index_below};

use super::{MAX_CLASSES, PairclassError};

/// Seed-domain tag for the plant coloring.
const COLORING_TAG: u64 = 0x7061_6972_636c_0001;
/// Seed-domain tag for the Markov resample.
const RESAMPLE_TAG: u64 = 0x7061_6972_636c_0002;

/// A copy-span instruction: `letters[dst..dst+len] = letters[src..src+len]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CopySpan {
    /// Source start (letter position).
    pub src: usize,
    /// Destination start (letter position, must be `> src`).
    pub dst: usize,
    /// Span length in letters.
    pub len: usize,
}

/// Plant construction parameters.
#[derive(Clone, Copy, Debug)]
pub struct PlantSpec {
    /// Plant length in letters.
    pub len: usize,
    /// Number of coloring classes (`1..=4`).
    pub n_classes: u8,
    /// Optional imposed repeated span (tie-anchor topology).
    pub copy: Option<CopySpan>,
}

/// A planted control: truth letters, the hidden coloring, and the tokens.
#[derive(Clone, Debug)]
pub struct Plant {
    /// Truth letters (`0..26`).
    pub letters: Vec<u8>,
    /// The hidden coloring (class per letter of the alphabet).
    pub coloring: [u8; 26],
    /// The public token stream (`coloring[letter]` per position).
    pub tokens: Vec<u8>,
}

/// Builds a plant from source text (letters `a..z` are kept, case-folded).
///
/// # Errors
/// [`PairclassError::PlantTooShort`] when the text has fewer than `spec.len`
/// letters, [`PairclassError::SpanOutOfRange`] for a bad copy span,
/// [`PairclassError::TooManyClasses`] for `n_classes` outside `1..=4`, and
/// [`PairclassError::NullModel`] if the deterministic RNG rejects its bound.
pub fn plant_from_text(text: &str, spec: &PlantSpec, seed: u64) -> Result<Plant, PairclassError> {
    if spec.n_classes == 0 || spec.n_classes > MAX_CLASSES {
        return Err(PairclassError::TooManyClasses {
            found: usize::from(spec.n_classes),
        });
    }
    if spec.len == 0 {
        return Err(PairclassError::EmptyInput);
    }
    let mut letters: Vec<u8> = text
        .chars()
        .filter_map(|ch| {
            let lower = ch.to_ascii_lowercase();
            lower.is_ascii_lowercase().then(|| lower as u8 - b'a')
        })
        .take(spec.len)
        .collect();
    if letters.len() < spec.len {
        return Err(PairclassError::PlantTooShort {
            needed: spec.len,
            have: letters.len(),
        });
    }
    if let Some(span) = spec.copy {
        apply_copy(&mut letters, span)?;
    }
    let mut rng = SplitMix64::new(mix_seed(seed, COLORING_TAG));
    let mut coloring = [0u8; 26];
    for slot in &mut coloring {
        let class = random_index_below(usize::from(spec.n_classes), &mut rng)
            .map_err(|error| PairclassError::NullModel(format!("bad bound {}", error.bound)))?;
        *slot = class as u8;
    }
    let tokens = letters
        .iter()
        .map(|&letter| coloring.get(usize::from(letter)).copied().unwrap_or(0))
        .collect();
    Ok(Plant {
        letters,
        coloring,
        tokens,
    })
}

/// Applies a copy span (the imposed plaintext repeat).
fn apply_copy(letters: &mut [u8], span: CopySpan) -> Result<(), PairclassError> {
    let src_end = span.src.checked_add(span.len);
    let dst_end = span.dst.checked_add(span.len);
    let (Some(src_end), Some(dst_end)) = (src_end, dst_end) else {
        return Err(PairclassError::SpanOutOfRange);
    };
    if span.dst <= span.src || src_end > letters.len() || dst_end > letters.len() {
        return Err(PairclassError::SpanOutOfRange);
    }
    for offset in 0..span.len {
        let value = letters.get(span.src + offset).copied();
        if let (Some(value), Some(slot)) = (value, letters.get_mut(span.dst + offset)) {
            *slot = value;
        }
    }
    Ok(())
}

/// Tie pairs implied by a copy span: position `dst + i` equals `src + i`.
///
/// # Errors
/// [`PairclassError::SpanOutOfRange`] when the span exceeds `n_positions` or
/// `dst <= src`.
pub fn copy_ties(
    span: CopySpan,
    n_positions: usize,
) -> Result<Vec<(usize, usize)>, PairclassError> {
    let src_end = span.src.checked_add(span.len);
    let dst_end = span.dst.checked_add(span.len);
    let (Some(src_end), Some(dst_end)) = (src_end, dst_end) else {
        return Err(PairclassError::SpanOutOfRange);
    };
    if span.dst <= span.src || src_end > n_positions || dst_end > n_positions {
        return Err(PairclassError::SpanOutOfRange);
    }
    Ok((0..span.len)
        .map(|offset| (span.src + offset, span.dst + offset))
        .collect())
}

/// Order-1 Markov (transition-preserving) resample of a token stream.
///
/// Starts at the real stream's first token and samples each successor from
/// the real stream's transition counts. A row with no observed successors
/// (possible only for the final token's class) falls back to the global
/// marginals. Deterministic in `seed`.
///
/// # Errors
/// [`PairclassError::EmptyInput`] on an empty stream,
/// [`PairclassError::TooManyClasses`] on out-of-range tokens, and
/// [`PairclassError::NullModel`] if the deterministic RNG rejects its bound.
pub fn markov_resample(tokens: &[u8], n_classes: u8, seed: u64) -> Result<Vec<u8>, PairclassError> {
    let k = usize::from(n_classes);
    if tokens.is_empty() {
        return Err(PairclassError::EmptyInput);
    }
    if n_classes == 0 || n_classes > MAX_CLASSES {
        return Err(PairclassError::TooManyClasses {
            found: usize::from(n_classes),
        });
    }
    if let Some(&bad) = tokens.iter().find(|&&t| usize::from(t) >= k) {
        return Err(PairclassError::TooManyClasses {
            found: usize::from(bad) + 1,
        });
    }
    let mut transitions = vec![0u64; k * k];
    let mut marginals = vec![0u64; k];
    for (index, &token) in tokens.iter().enumerate() {
        if let Some(slot) = marginals.get_mut(usize::from(token)) {
            *slot += 1;
        }
        if index + 1 < tokens.len() {
            let next = tokens.get(index + 1).copied().unwrap_or(0);
            if let Some(slot) = transitions.get_mut(usize::from(token) * k + usize::from(next)) {
                *slot += 1;
            }
        }
    }
    let mut rng = SplitMix64::new(mix_seed(seed, RESAMPLE_TAG));
    let mut out = Vec::with_capacity(tokens.len());
    let mut current = tokens.first().copied().unwrap_or(0);
    out.push(current);
    while out.len() < tokens.len() {
        let row_start = usize::from(current) * k;
        let row = transitions.get(row_start..row_start + k).unwrap_or(&[]);
        let weights = if row.iter().sum::<u64>() > 0 {
            row
        } else {
            marginals.as_slice()
        };
        current = sample_weighted(weights, &mut rng)?;
        out.push(current);
    }
    Ok(out)
}

/// Samples an index proportionally to `weights` (which must sum to `> 0`).
fn sample_weighted(weights: &[u64], rng: &mut SplitMix64) -> Result<u8, PairclassError> {
    let total: u64 = weights.iter().sum();
    if total == 0 {
        return Err(PairclassError::NullModel(
            "weighted sample over an all-zero row".to_owned(),
        ));
    }
    let bound = usize::try_from(total)
        .map_err(|_error| PairclassError::NullModel("weight total overflow".to_owned()))?;
    let mut draw = random_index_below(bound, rng)
        .map_err(|error| PairclassError::NullModel(format!("bad bound {}", error.bound)))?
        as u64;
    for (index, &weight) in weights.iter().enumerate() {
        if draw < weight {
            return Ok(index as u8);
        }
        draw -= weight;
    }
    Ok((weights.len().saturating_sub(1)) as u8)
}

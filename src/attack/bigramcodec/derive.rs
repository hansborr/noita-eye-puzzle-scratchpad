//! Token streams for the bigram-order codec gate.

use std::collections::BTreeMap;

use crate::core::glyph::Glyph;

use super::BigramError;

/// Token stream families scanned by `bigramcodec`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StreamKind {
    /// Non-overlapping consecutive digit pairs.
    DigitPairs,
    /// Overlapping directed edges of the base walk.
    Edges,
    /// Non-overlapping pairs of run-length magnitudes.
    MagPairs,
}

impl StreamKind {
    /// Stable CLI/report label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::DigitPairs => "digit-pairs",
            Self::Edges => "edges",
            Self::MagPairs => "mag-pairs",
        }
    }

    pub(crate) const fn seed_tag(self) -> u64 {
        match self {
            Self::DigitPairs => 0x6469_6769_7470_0001,
            Self::Edges => 0x6564_6765_7300_0001,
            Self::MagPairs => 0x6d61_6770_6169_0001,
        }
    }
}

/// Returns the three token stream families in report order.
#[must_use]
pub fn all_streams() -> [StreamKind; 3] {
    [
        StreamKind::DigitPairs,
        StreamKind::Edges,
        StreamKind::MagPairs,
    ]
}

/// Dense token stream plus the raw symbols that were densified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenStream {
    /// Token family.
    pub kind: StreamKind,
    /// Dense token ids in `0..distinct_count`.
    pub tokens: Vec<usize>,
    /// Raw symbols before dense relabeling.
    pub raw_symbols: Vec<usize>,
    /// Distinct raw symbols, sorted by raw value.
    pub raw_inventory: Vec<usize>,
    /// Source units consumed by this tokenization: digits or magnitudes.
    pub source_units: usize,
    /// Unpaired trailing source units not tokenized.
    pub dropped_tail: usize,
}

impl TokenStream {
    /// Number of token symbols after dense relabeling.
    #[must_use]
    pub fn distinct_count(&self) -> usize {
        self.raw_inventory.len()
    }
}

/// Builds one requested token stream from the already-derived carrier.
///
/// # Errors
/// Returns [`BigramError`] if the stream would be empty or if `mag-pairs` would
/// collide because a magnitude exceeds the declared base.
pub fn tokenize(
    kind: StreamKind,
    digits: &[Glyph],
    magnitudes: &[usize],
    base: usize,
) -> Result<TokenStream, BigramError> {
    let (raw_symbols, source_units, dropped_tail) = match kind {
        StreamKind::DigitPairs => digit_pairs(digits, base),
        StreamKind::Edges => edges(digits, base),
        StreamKind::MagPairs => mag_pairs(magnitudes, base)?,
    };
    if raw_symbols.is_empty() {
        return Err(BigramError::EmptyStream { stream: kind });
    }
    let (tokens, raw_inventory) = densify(&raw_symbols);
    Ok(TokenStream {
        kind,
        tokens,
        raw_symbols,
        raw_inventory,
        source_units,
        dropped_tail,
    })
}

fn digit_pairs(digits: &[Glyph], base: usize) -> (Vec<usize>, usize, usize) {
    let mut raw = Vec::with_capacity(digits.len() / 2);
    let chunks = digits.chunks_exact(2);
    let dropped = chunks.remainder().len();
    for chunk in chunks {
        if let [a, b] = chunk {
            raw.push(usize::from(a.0) * base + usize::from(b.0));
        }
    }
    (raw, digits.len(), dropped)
}

fn edges(digits: &[Glyph], base: usize) -> (Vec<usize>, usize, usize) {
    let raw = digits
        .windows(2)
        .filter_map(|pair| match pair {
            [a, b] => Some(usize::from(a.0) * base + usize::from(b.0)),
            _ => None,
        })
        .collect();
    (raw, digits.len(), 0)
}

fn mag_pairs(magnitudes: &[usize], base: usize) -> Result<(Vec<usize>, usize, usize), BigramError> {
    let mut raw = Vec::with_capacity(magnitudes.len() / 2);
    let chunks = magnitudes.chunks_exact(2);
    let dropped = chunks.remainder().len();
    for chunk in chunks {
        if let [a, b] = chunk {
            if *a == 0 || *a > base {
                return Err(BigramError::MagnitudeExceedsBase {
                    magnitude: *a,
                    base,
                });
            }
            if *b == 0 || *b > base {
                return Err(BigramError::MagnitudeExceedsBase {
                    magnitude: *b,
                    base,
                });
            }
            raw.push((a - 1) * base + (b - 1));
        }
    }
    Ok((raw, magnitudes.len(), dropped))
}

fn densify(raw_symbols: &[usize]) -> (Vec<usize>, Vec<usize>) {
    let mut map = BTreeMap::new();
    for &symbol in raw_symbols {
        let next = map.len();
        let _previous = map.entry(symbol).or_insert(next);
    }
    let raw_inventory = map.keys().copied().collect::<Vec<_>>();
    let tokens = raw_symbols
        .iter()
        .map(|symbol| map.get(symbol).copied().unwrap_or(0))
        .collect();
    (tokens, raw_inventory)
}

//! The codec family: each [`RlCodec`] transduces the magnitude carrier `M` into a
//! symbol stream that the substitution search then scores as candidate English.
//!
//! Symbol streams are canonicalised to dense ids (`0..k`) by first appearance, so
//! the alphabet size is exactly the number of distinct symbols and the partition
//! is relabel-invariant (the property the planted positive control checks).

use std::collections::HashMap;
use std::hash::Hash;

/// Polybius square side: the magnitude pair `(a, b)` packs to `side*(a-1)+(b-1)`.
const POLYBIUS_SIDE: usize = 5;
/// Base-5 radix for the [`RlCodec::Base5Group`] group value.
const BASE5_RADIX: usize = 5;
/// Shortest decoded symbol stream a codec will emit (anything shorter is
/// degenerate — no structure to search).
const MIN_STREAM: usize = 2;

/// A run-length codec: a fixed rule turning the magnitude carrier into symbols.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RlCodec {
    /// Each magnitude is its own symbol (a 5-symbol stream — too few for English,
    /// kept for a uniform verdict).
    Direct,
    /// Fixed 5×5 Polybius over magnitude pairs `(M[2i+phase], M[2i+1+phase])`,
    /// packed `5*(a-1)+(b-1)`.
    Polybius {
        /// Pairing phase (`0` or `1`).
        phase: usize,
    },
    /// The base-5 value of each fixed-width group of magnitudes.
    Base5Group {
        /// Group width (`2` or `3`).
        group_len: usize,
        /// Starting offset into `M`.
        offset: usize,
    },
    /// Variable-length: split `M` on `value == sep`; each chunk is one symbol.
    Comma {
        /// Separator magnitude value (`1..=5`).
        sep: usize,
    },
    /// Variable-length: split `M` *after* each `value == t` (terminator
    /// inclusive); each chunk is one symbol.
    Term {
        /// Terminator magnitude value (`1..=5`).
        t: usize,
    },
    /// The raw magnitude pair `(M[2i+phase], M[2i+1+phase])` as a symbol (the
    /// substitution hill-climb's pair channel).
    PairSub {
        /// Pairing phase (`0` or `1`).
        phase: usize,
    },
}

impl RlCodec {
    /// A stable display name (the self-test keys on `"Comma{sep=4}"`).
    #[must_use]
    pub fn name(&self) -> String {
        match *self {
            Self::Direct => "Direct".to_owned(),
            Self::Polybius { phase } => format!("Polybius{{phase={phase}}}"),
            Self::Base5Group { group_len, offset } => {
                format!("Base5Group{{len={group_len},off={offset}}}")
            }
            Self::Comma { sep } => format!("Comma{{sep={sep}}}"),
            Self::Term { t } => format!("Term{{t={t}}}"),
            Self::PairSub { phase } => format!("PairSub{{phase={phase}}}"),
        }
    }

    /// A deterministic per-variant seed tag, mixed into the search/null seeds so
    /// codecs do not share a random stream.
    #[must_use]
    pub(crate) fn seed_tag(&self) -> u64 {
        name_seed_tag(&self.name())
    }

    /// Decodes the magnitude carrier into a dense symbol stream.
    ///
    /// Returns `None` when the codec cannot produce a searchable stream (too
    /// short, or fewer than two chunks), so the battery records a degenerate
    /// verdict rather than a misleading score.
    #[must_use]
    pub fn decode(&self, magnitudes: &[usize]) -> Option<Vec<usize>> {
        match *self {
            Self::Direct => decode_direct(magnitudes),
            Self::Polybius { phase } => decode_polybius(magnitudes, phase),
            Self::Base5Group { group_len, offset } => {
                decode_base5_group(magnitudes, group_len, offset)
            }
            Self::Comma { sep } => decode_comma(magnitudes, sep),
            Self::Term { t } => decode_term(magnitudes, t),
            Self::PairSub { phase } => decode_pair_sub(magnitudes, phase),
        }
    }
}

/// A deterministic per-name seed tag (FNV-style mix of the name bytes), so two
/// differently-named candidates never share a random stream.
///
/// Shared between [`RlCodec::seed_tag`] and the `cribfit` instrument's candidate
/// gating, so both derive their search/null seeds the same way.
#[must_use]
pub(crate) fn name_seed_tag(name: &str) -> u64 {
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    for byte in name.bytes() {
        state = state
            .rotate_left(7)
            .wrapping_add(u64::from(byte))
            .wrapping_mul(0x0100_0000_01b3);
    }
    state
}

/// The fixed, deterministic codec order the battery evaluates.
#[must_use]
pub fn all_codecs() -> Vec<RlCodec> {
    let mut codecs = vec![RlCodec::Direct];
    for phase in [0usize, 1] {
        codecs.push(RlCodec::Polybius { phase });
    }
    for offset in [0usize, 1] {
        codecs.push(RlCodec::Base5Group {
            group_len: 2,
            offset,
        });
    }
    for offset in [0usize, 1, 2] {
        codecs.push(RlCodec::Base5Group {
            group_len: 3,
            offset,
        });
    }
    for sep in 1..=5 {
        codecs.push(RlCodec::Comma { sep });
    }
    for t in 1..=5 {
        codecs.push(RlCodec::Term { t });
    }
    for phase in [0usize, 1] {
        codecs.push(RlCodec::PairSub { phase });
    }
    codecs
}

/// Number of distinct symbols in a decoded stream.
#[must_use]
pub fn alphabet_size(stream: &[usize]) -> usize {
    stream
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<usize>>()
        .len()
}

/// Maps each distinct key to a dense id (`0..k`) by order of first appearance.
fn canonicalize<K: Eq + Hash + Clone>(keys: &[K]) -> Vec<usize> {
    let mut ids: HashMap<K, usize> = HashMap::new();
    let mut out = Vec::with_capacity(keys.len());
    for key in keys {
        let next = ids.len();
        let id = *ids.entry(key.clone()).or_insert(next);
        out.push(id);
    }
    out
}

/// Wraps a canonicalised stream, returning `None` when it is too short.
fn finish(stream: Vec<usize>) -> Option<Vec<usize>> {
    if stream.len() < MIN_STREAM {
        None
    } else {
        Some(stream)
    }
}

fn decode_direct(magnitudes: &[usize]) -> Option<Vec<usize>> {
    finish(canonicalize(magnitudes))
}

fn decode_polybius(magnitudes: &[usize], phase: usize) -> Option<Vec<usize>> {
    let mut raw = Vec::new();
    let mut index = phase;
    while let (Some(&a), Some(&b)) = (magnitudes.get(index), magnitudes.get(index + 1)) {
        raw.push(POLYBIUS_SIDE * a.saturating_sub(1) + b.saturating_sub(1));
        index += 2;
    }
    finish(canonicalize(&raw))
}

fn decode_base5_group(magnitudes: &[usize], group_len: usize, offset: usize) -> Option<Vec<usize>> {
    if group_len == 0 {
        return None;
    }
    let mut raw = Vec::new();
    let mut index = offset;
    while index + group_len <= magnitudes.len() {
        let mut value = 0usize;
        let mut complete = true;
        for step in 0..group_len {
            if let Some(&m) = magnitudes.get(index + step) {
                value = value * BASE5_RADIX + m.saturating_sub(1);
            } else {
                complete = false;
                break;
            }
        }
        if complete {
            raw.push(value);
        }
        index += group_len;
    }
    finish(canonicalize(&raw))
}

fn decode_comma(magnitudes: &[usize], sep: usize) -> Option<Vec<usize>> {
    let mut chunks: Vec<Vec<usize>> = Vec::new();
    let mut current: Vec<usize> = Vec::new();
    for &m in magnitudes {
        if m == sep {
            chunks.push(std::mem::take(&mut current));
        } else {
            current.push(m);
        }
    }
    chunks.push(current);
    finish(canonicalize(&chunks))
}

fn decode_term(magnitudes: &[usize], t: usize) -> Option<Vec<usize>> {
    let mut chunks: Vec<Vec<usize>> = Vec::new();
    let mut current: Vec<usize> = Vec::new();
    for &m in magnitudes {
        current.push(m);
        if m == t {
            chunks.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    finish(canonicalize(&chunks))
}

fn decode_pair_sub(magnitudes: &[usize], phase: usize) -> Option<Vec<usize>> {
    let mut raw: Vec<(usize, usize)> = Vec::new();
    let mut index = phase;
    while let (Some(&a), Some(&b)) = (magnitudes.get(index), magnitudes.get(index + 1)) {
        raw.push((a, b));
        index += 2;
    }
    finish(canonicalize(&raw))
}

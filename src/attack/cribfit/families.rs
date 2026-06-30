//! Codec families and the language-free crib-consistency test.
//!
//! Each family transduces the magnitude carrier `M` into an output symbol stream
//! and is tested by a single necessary condition: **a repeated plaintext span must
//! decode identically.** For per-run families (cumulative-sum) and for the
//! memoryful move-to-front code this is checked directly by occurrence-equality
//! across the crib windows; for the run/bit-periodic keyed families it is decided
//! analytically by the gap divisibility (handled in [`super::mod`]).
//!
//! A family that fails occurrence-equality on any crib is excluded *without any
//! language judgement* — the filter's whole value is that it constrains the
//! hypothesis space before a single quadgram is scored.

use std::collections::HashMap;

use super::crib::AnchorPair;

/// The largest letter alphabet a candidate can inject into (English `A..Z`); a
/// decoded stream wider than this can never be a monoalphabetic English plaintext.
pub(crate) const ENGLISH_ALPHABET: usize = 26;

/// One token of a tokenization: a dense id of its *input* content (used to confirm
/// the two crib windows really carry the same plaintext) and the run index where
/// the token begins (used to map a run-index crib window onto token positions).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Token {
    /// Dense id of the token's input content (by first appearance).
    key: usize,
    /// Run index where the token's content begins.
    run_start: usize,
}

/// Per-anchor occurrence-equality result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorConsistency {
    /// Crib repeat length (run-length magnitudes).
    pub length: usize,
    /// Number of output positions actually compared across the two windows.
    pub compared: usize,
    /// Number of compared positions whose outputs agree.
    pub agreements: usize,
    /// Whether the two windows mapped onto equal-count, content-matched token spans
    /// (a precondition for a meaningful comparison).
    pub aligned: bool,
}

impl AnchorConsistency {
    /// `true` only when the windows aligned and *every* compared output agrees.
    #[must_use]
    pub const fn consistent(&self) -> bool {
        self.aligned && self.agreements == self.compared && self.compared > 0
    }
}

/// The crib-consistency verdict of one candidate: per-anchor detail plus the
/// conjunction (consistent ⟺ identical decode across every crib).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsistencyVerdict {
    /// Per-anchor occurrence-equality.
    pub anchors: Vec<AnchorConsistency>,
    /// `true` only when every anchor is individually consistent.
    pub consistent: bool,
}

/// One decoded candidate awaiting (or excluded from) the language gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CribCandidate {
    /// Display name (e.g. `CumulativeSumMod{n=21}`, `Mtf{tok=single}`).
    pub name: String,
    /// The canonical dense output symbol stream.
    pub symbols: Vec<usize>,
    /// Distinct output symbols (the decoded alphabet size).
    pub alphabet: usize,
    /// Crib-consistency verdict.
    pub consistency: ConsistencyVerdict,
    /// Whether the decoded alphabet is in `[MIN_LETTERS, 26]` (gateable as English).
    pub english_viable: bool,
}

impl CribCandidate {
    /// `true` when the candidate both survives the filter and could host English —
    /// the precondition for spending a language gate on it.
    #[must_use]
    pub const fn gateable(&self) -> bool {
        self.consistency.consistent && self.english_viable
    }
}

/// Maps each distinct value to a dense id (`0..k`) by order of first appearance.
fn dense_ids(values: &[usize]) -> Vec<usize> {
    let mut ids: HashMap<usize, usize> = HashMap::new();
    values
        .iter()
        .map(|&v| {
            let next = ids.len();
            *ids.entry(v).or_insert(next)
        })
        .collect()
}

/// Maps each distinct content vector to a dense id by first appearance.
fn dense_content_ids(contents: &[Vec<usize>]) -> Vec<usize> {
    let mut ids: HashMap<&[usize], usize> = HashMap::new();
    contents
        .iter()
        .map(|content| {
            let next = ids.len();
            *ids.entry(content.as_slice()).or_insert(next)
        })
        .collect()
}

/// Checks occurrence-equality of an output stream across the cribs.
///
/// `tokens[t].run_start` locates each output position in run-index space, so a crib
/// window `[first, first+length)` maps to the tokens starting inside it. Two windows
/// are *aligned* when they cover equal token counts with matching input content; an
/// aligned anchor is consistent only when every output also agrees. Per-run streams
/// (one token per run) align trivially, so this one routine serves every family.
fn occurrence_consistency(
    tokens: &[Token],
    outputs: &[usize],
    anchors: &[AnchorPair],
) -> ConsistencyVerdict {
    // Each window is the (input key, emitted output) of every token that *starts*
    // inside the crib's run-index span, so per-run and variable-length families are
    // handled uniformly without indexing.
    let window = |start: usize, length: usize| -> Vec<(usize, usize)> {
        tokens
            .iter()
            .enumerate()
            .filter(|(_, tok)| tok.run_start >= start && tok.run_start < start + length)
            .map(|(idx, tok)| (tok.key, outputs.get(idx).copied().unwrap_or(usize::MAX)))
            .collect()
    };
    let mut results = Vec::with_capacity(anchors.len());
    for anchor in anchors {
        let a = window(anchor.first, anchor.length);
        let b = window(anchor.second, anchor.length);
        // Aligned ⟺ equal token counts with matching input content (same plaintext).
        let aligned = a.len() == b.len() && a.iter().zip(&b).all(|(x, y)| x.0 == y.0);
        let compared = a.len();
        let agreements = if aligned {
            a.iter().zip(&b).filter(|(x, y)| x.1 == y.1).count()
        } else {
            0
        };
        results.push(AnchorConsistency {
            length: anchor.length,
            compared,
            agreements,
            aligned,
        });
    }
    let consistent = !results.is_empty() && results.iter().all(AnchorConsistency::consistent);
    ConsistencyVerdict {
        anchors: results,
        consistent,
    }
}

/// Builds the per-run token list (one token per run, `run_start == run index`).
fn per_run_tokens(magnitudes: &[usize]) -> Vec<Token> {
    magnitudes
        .iter()
        .enumerate()
        .map(|(i, &m)| Token {
            key: m,
            run_start: i,
        })
        .collect()
}

/// Family 1 — `CumulativeSumMod(n)`: `output[i] = (Σ M[0..=i]) mod n`.
///
/// Crib-consistent ⟺ `n | bit-gap` for every anchor (proven: the per-window output
/// offset equals the bit-gap). The output is a **bounded-increment walk**
/// (consecutive symbols differ by `M[i] ∈ 1..=5 mod n`), so it merely re-expresses
/// the carrier and cannot host general English; it is gated only for the record.
#[must_use]
pub fn cumsum_candidate(magnitudes: &[usize], n: usize, anchors: &[AnchorPair]) -> CribCandidate {
    let mut acc = 0usize;
    let residues: Vec<usize> = magnitudes
        .iter()
        .map(|&m| {
            acc = if n == 0 { 0 } else { (acc + m) % n };
            acc
        })
        .collect();
    let symbols = dense_ids(&residues);
    let alphabet = distinct(&symbols);
    let tokens = per_run_tokens(magnitudes);
    let consistency = occurrence_consistency(&tokens, &symbols, anchors);
    CribCandidate {
        name: format!("CumulativeSumMod{{n={n}}}"),
        english_viable: english_viable(alphabet),
        alphabet,
        consistency,
        symbols,
    }
}

/// A tokenization of `M` for the move-to-front family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tokenization {
    /// One token per run (the carrier magnitude itself).
    Single,
    /// Fixed pairs `(M[2i+phase], M[2i+1+phase])`.
    Pair {
        /// Pairing phase (`0` or `1`).
        phase: usize,
    },
    /// Variable-length chunks split on `M == sep` (separator excluded).
    Comma {
        /// Separator magnitude.
        sep: usize,
    },
    /// Variable-length chunks ended *after* each `M == t` (terminator included).
    Term {
        /// Terminator magnitude.
        t: usize,
    },
}

impl Tokenization {
    /// The fixed, deterministic tokenization order the MTF family evaluates.
    #[must_use]
    pub fn all() -> Vec<Self> {
        let mut out = vec![
            Self::Single,
            Self::Pair { phase: 0 },
            Self::Pair { phase: 1 },
        ];
        out.extend((1..=5).map(|sep| Self::Comma { sep }));
        out.extend((1..=5).map(|t| Self::Term { t }));
        out
    }

    /// A stable display tag (`single`, `pair@0`, `comma=4`, `term=2`).
    #[must_use]
    pub fn tag(&self) -> String {
        match *self {
            Self::Single => "single".to_owned(),
            Self::Pair { phase } => format!("pair@{phase}"),
            Self::Comma { sep } => format!("comma={sep}"),
            Self::Term { t } => format!("term={t}"),
        }
    }

    /// Tokenizes `M` into `(content, run_start)` pairs (content keys assigned later).
    fn tokenize(&self, magnitudes: &[usize]) -> Vec<(Vec<usize>, usize)> {
        match *self {
            Self::Single => magnitudes
                .iter()
                .enumerate()
                .map(|(i, &m)| (vec![m], i))
                .collect(),
            Self::Pair { phase } => {
                let mut out = Vec::new();
                let mut i = phase;
                while let (Some(&a), Some(&b)) = (magnitudes.get(i), magnitudes.get(i + 1)) {
                    out.push((vec![a, b], i));
                    i += 2;
                }
                out
            }
            Self::Comma { sep } => chunk_excluding(magnitudes, sep),
            Self::Term { t } => chunk_including(magnitudes, t),
        }
    }
}

/// Splits `magnitudes` on `sep` (separator excluded from any chunk); each chunk
/// carries the run index where its content begins.
fn chunk_excluding(magnitudes: &[usize], sep: usize) -> Vec<(Vec<usize>, usize)> {
    let mut out = Vec::new();
    let mut content = Vec::new();
    let mut chunk_start = 0usize;
    for (i, &m) in magnitudes.iter().enumerate() {
        if m == sep {
            out.push((std::mem::take(&mut content), chunk_start));
            chunk_start = i + 1;
        } else {
            content.push(m);
        }
    }
    out.push((content, chunk_start));
    out
}

/// Splits `magnitudes` after each `t` (terminator included in the chunk).
fn chunk_including(magnitudes: &[usize], t: usize) -> Vec<(Vec<usize>, usize)> {
    let mut out = Vec::new();
    let mut content = Vec::new();
    let mut chunk_start = 0usize;
    for (i, &m) in magnitudes.iter().enumerate() {
        if content.is_empty() {
            chunk_start = i;
        }
        content.push(m);
        if m == t {
            out.push((std::mem::take(&mut content), chunk_start));
        }
    }
    if !content.is_empty() {
        out.push((content, chunk_start));
    }
    out
}

/// Move-to-front rank code over a token-id stream: each token emits its current
/// position in the recency list (a fresh token emits the list's current length),
/// then moves to the front. This is a codec **with memory** — the table state
/// entering a span depends on the entire prefix — so two identical input spans
/// generally emit *different* ranks, which is exactly what the crib filter detects.
fn mtf_ranks(keys: &[usize]) -> Vec<usize> {
    let mut table: Vec<usize> = Vec::new();
    keys.iter()
        .map(|&k| {
            if let Some(pos) = table.iter().position(|&x| x == k) {
                let _ = table.remove(pos);
                table.insert(0, k);
                pos
            } else {
                let rank = table.len();
                table.insert(0, k);
                rank
            }
        })
        .collect()
}

/// Family 4 — `EvolvingTableMtf(tokenization)`: move-to-front rank code over a
/// tokenization of `M`. Crib-consistency is data-dependent and checked directly.
#[must_use]
pub fn mtf_candidate(
    magnitudes: &[usize],
    tokenization: Tokenization,
    anchors: &[AnchorPair],
) -> CribCandidate {
    let raw = tokenization.tokenize(magnitudes);
    let contents: Vec<Vec<usize>> = raw.iter().map(|(content, _)| content.clone()).collect();
    let keys = dense_content_ids(&contents);
    let tokens: Vec<Token> = keys
        .iter()
        .zip(&raw)
        .map(|(&key, &(_, run_start))| Token { key, run_start })
        .collect();
    let outputs = dense_ids(&mtf_ranks(&keys));
    let alphabet = distinct(&outputs);
    let consistency = occurrence_consistency(&tokens, &outputs, anchors);
    CribCandidate {
        name: format!("Mtf{{tok={}}}", tokenization.tag()),
        english_viable: english_viable(alphabet),
        alphabet,
        consistency,
        symbols: outputs,
    }
}

/// Number of distinct symbols.
fn distinct(symbols: &[usize]) -> usize {
    symbols
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<usize>>()
        .len()
}

/// Whether a decoded alphabet could host a monoalphabetic English plaintext.
fn english_viable(alphabet: usize) -> bool {
    (crate::attack::rlcodec::MIN_LETTERS..=ENGLISH_ALPHABET).contains(&alphabet)
}

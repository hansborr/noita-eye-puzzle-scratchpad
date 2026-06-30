//! Codec families and the language-free crib-consistency test.
//!
//! Each family transduces the magnitude carrier `M` into an output symbol stream
//! and is tested by a single necessary condition: **a repeated plaintext span must
//! decode identically.** For per-run families (cumulative-sum) and for the
//! memoryful move-to-front code this is checked directly by occurrence-equality
//! across the crib windows; for run-periodic keyed families it is decided
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
/// the two crib windows really carry the same plaintext) and the run span it
/// occupies (used to test whether a crib window aligns to token boundaries).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Token {
    /// Dense id of the token's input content (by first appearance).
    key: usize,
    /// Run index where the token's content begins.
    run_start: usize,
    /// Number of runs the token covers (`0` for an empty chunk, which covers none).
    run_len: usize,
}

/// Per-anchor occurrence-equality result.
///
/// The crib-equality test is only *sound* when the repeated carrier span aligns to
/// plaintext-token boundaries. `aligned` records that precondition: a window aligns
/// only when its tokens **exactly tile** the run span with **no token straddling
/// either boundary** (and the two windows tile to equal counts with matching input
/// content). When `aligned` is false the test is *inapplicable* to that crib — the
/// tokenization's boundaries do not line up across the repeat — which is **not** an
/// exclusion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorConsistency {
    /// Crib repeat length (run-length magnitudes).
    pub length: usize,
    /// Number of output positions actually compared across the two windows.
    pub compared: usize,
    /// Number of compared positions whose outputs agree.
    pub agreements: usize,
    /// Whether both windows exactly tile their run span on token boundaries with no
    /// straddle (the soundness precondition for comparing this crib).
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
/// three-way classification.
///
/// A candidate is in exactly one of three states. **Applicable + consistent**: the
/// tokenization aligns to every crib and decodes each identically (it survives the
/// filter). **Applicable + inconsistent (excluded)**: it aligns but at least one
/// crib decodes differently, so under the "repeated plaintext decodes identically"
/// necessary condition the codec is excluded. **Inapplicable**: the tokenization's
/// boundaries do not align across the cribs, so the filter cannot judge it — it is
/// *set aside*, never excluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsistencyVerdict {
    /// Per-anchor occurrence-equality.
    pub anchors: Vec<AnchorConsistency>,
    /// `true` when every crib aligns to token boundaries (the filter applies).
    pub applicable: bool,
    /// `true` only when applicable *and* every crib decodes identically.
    pub consistent: bool,
}

impl ConsistencyVerdict {
    /// `true` when the filter applies and the candidate fails it (a genuine
    /// crib-inconsistency exclusion).
    #[must_use]
    pub const fn excluded(&self) -> bool {
        self.applicable && !self.consistent
    }

    /// `true` when the tokenization does not align to the cribs, so the filter
    /// cannot judge it (set aside, not excluded).
    #[must_use]
    pub const fn inapplicable(&self) -> bool {
        !self.applicable
    }
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

/// Returns the `(input key, emitted output)` of the tokens that **exactly tile** the
/// run window `[start, start + length)`, or `None` when the window is not aligned to
/// token boundaries.
///
/// A window is aligned only when no token straddles either boundary (no token starts
/// before `start` yet extends into the window, and none starts inside yet extends
/// past the end) **and** the in-window tokens tile the span with no gap. Per-run
/// tokenizations tile trivially; a variable-rate tokenization whose chunk boundaries
/// fall mid-window — or that drops separator runs, leaving a gap — is therefore
/// *inapplicable*, not silently compared on its in-window subset (the false-accept
/// blind spot).
fn aligned_window(
    tokens: &[Token],
    outputs: &[usize],
    start: usize,
    length: usize,
) -> Option<Vec<(usize, usize)>> {
    let end = start + length;
    // No token may straddle either boundary.
    for tok in tokens {
        let token_end = tok.run_start + tok.run_len;
        let straddles_start = tok.run_start < start && token_end > start;
        let straddles_end = tok.run_start < end && token_end > end;
        if straddles_start || straddles_end {
            return None;
        }
    }
    // The in-window tokens must tile [start, end) contiguously with no gap.
    let mut cursor = start;
    let mut cells = Vec::new();
    for (idx, tok) in tokens.iter().enumerate() {
        if tok.run_len == 0 || tok.run_start < start || tok.run_start + tok.run_len > end {
            continue;
        }
        if tok.run_start != cursor {
            return None; // a gap (e.g. a dropped separator run) or an overlap
        }
        cursor = tok.run_start + tok.run_len;
        cells.push((tok.key, outputs.get(idx).copied().unwrap_or(usize::MAX)));
    }
    if cursor == end { Some(cells) } else { None }
}

/// Classifies an output stream across the cribs into the three-way verdict.
///
/// Each crib is *aligned* only when both windows tile to token boundaries with
/// matching input content; an aligned crib is consistent when every output also
/// agrees. A crib that does not align is recorded as inapplicable (`aligned =
/// false`), never as an exclusion. The candidate is `applicable` when every crib
/// aligns, and `consistent` when, additionally, every crib decodes identically.
fn occurrence_consistency(
    tokens: &[Token],
    outputs: &[usize],
    anchors: &[AnchorPair],
) -> ConsistencyVerdict {
    let mut results = Vec::with_capacity(anchors.len());
    for anchor in anchors {
        let a = aligned_window(tokens, outputs, anchor.first, anchor.length);
        let b = aligned_window(tokens, outputs, anchor.second, anchor.length);
        let (compared, agreements, aligned) = match (a, b) {
            (Some(a), Some(b))
                if a.len() == b.len() && a.iter().zip(&b).all(|(x, y)| x.0 == y.0) =>
            {
                let agreements = a.iter().zip(&b).filter(|(x, y)| x.1 == y.1).count();
                (a.len(), agreements, true)
            }
            // Both windows tiled but their token counts / contents disagree: the
            // boundaries do not correspond, so the crib is inapplicable, not failed.
            _ => (0, 0, false),
        };
        results.push(AnchorConsistency {
            length: anchor.length,
            compared,
            agreements,
            aligned,
        });
    }
    let applicable = !results.is_empty() && results.iter().all(|anchor| anchor.aligned);
    let consistent = applicable && results.iter().all(AnchorConsistency::consistent);
    ConsistencyVerdict {
        anchors: results,
        applicable,
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
            run_len: 1,
        })
        .collect()
}

/// Family 1 — `CumulativeSumMod(n)`: `output[i] = (Σ M[0..=i]) mod n`.
///
/// Crib-consistent ⟺ `n | bit-gap` for every anchor (proven: the per-window output
/// offset equals the bit-gap). The output is a **bounded-increment walk**
/// (consecutive symbols differ by `M[i] ∈ 1..=5 mod n`) — a strong structural
/// constraint on what English it could carry, but not a proof of impossibility — so
/// the matched-null gate, not the walk structure, is the evidence.
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

/// Family 3 — `BitPeriodicSubst(p)`: a bit-periodic keyed substitution over `M`.
///
/// The most general substitution keyed by the run's bit-coset is exactly a free
/// monoalphabetic map on the augmented symbol `(M[i], (Σ M[0..i]) mod p)`, where
/// the prefix sum is exclusive (the bit-start position of run `i`). Repeated crib
/// windows are consistent precisely when their coset offset is zero, i.e. `p`
/// divides the bit-gap; the direct occurrence check below confirms that condition
/// on the realized per-run stream before the existing matched-null gate scores it.
#[must_use]
pub fn bitperiodic_candidate(
    magnitudes: &[usize],
    p: usize,
    anchors: &[AnchorPair],
) -> CribCandidate {
    let period = p.max(1);
    let mut prefix = 0usize;
    let packed: Vec<usize> = magnitudes
        .iter()
        .map(|&m| {
            let coset = if p == 0 { 0 } else { prefix % p };
            let packed = m * period + coset;
            prefix += m;
            packed
        })
        .collect();
    let symbols = dense_ids(&packed);
    let alphabet = distinct(&symbols);
    let tokens = per_run_tokens(magnitudes);
    let consistency = occurrence_consistency(&tokens, &symbols, anchors);
    CribCandidate {
        name: format!("BitPeriodicSubst{{p={p}}}"),
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

    /// Tokenizes `M` into `(content, run_start, run_len)` tuples (content keys
    /// assigned later). `run_len` is the number of *runs* the token covers, which
    /// the alignment test uses to detect boundary straddles and tiling gaps.
    fn tokenize(&self, magnitudes: &[usize]) -> Vec<(Vec<usize>, usize, usize)> {
        match *self {
            Self::Single => magnitudes
                .iter()
                .enumerate()
                .map(|(i, &m)| (vec![m], i, 1))
                .collect(),
            Self::Pair { phase } => {
                let mut out = Vec::new();
                let mut i = phase;
                while let (Some(&a), Some(&b)) = (magnitudes.get(i), magnitudes.get(i + 1)) {
                    out.push((vec![a, b], i, 2));
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
/// carries the run index where its content begins and the count of content runs.
/// Because the separator runs belong to no chunk, the chunks do **not** tile `M` —
/// a separator inside a crib window leaves a gap, so the alignment test sets such a
/// window aside as inapplicable.
fn chunk_excluding(magnitudes: &[usize], sep: usize) -> Vec<(Vec<usize>, usize, usize)> {
    let mut out = Vec::new();
    let mut content = Vec::new();
    let mut chunk_start = 0usize;
    for (i, &m) in magnitudes.iter().enumerate() {
        if m == sep {
            let len = content.len();
            out.push((std::mem::take(&mut content), chunk_start, len));
            chunk_start = i + 1;
        } else {
            content.push(m);
        }
    }
    let len = content.len();
    out.push((content, chunk_start, len));
    out
}

/// Splits `magnitudes` after each `t` (terminator included in the chunk). Every run
/// belongs to exactly one chunk, so these chunks tile `M`; a crib window is aligned
/// only when both its boundaries fall on chunk boundaries.
fn chunk_including(magnitudes: &[usize], t: usize) -> Vec<(Vec<usize>, usize, usize)> {
    let mut out = Vec::new();
    let mut content = Vec::new();
    let mut chunk_start = 0usize;
    for (i, &m) in magnitudes.iter().enumerate() {
        if content.is_empty() {
            chunk_start = i;
        }
        content.push(m);
        if m == t {
            let len = content.len();
            out.push((std::mem::take(&mut content), chunk_start, len));
        }
    }
    if !content.is_empty() {
        let len = content.len();
        out.push((content, chunk_start, len));
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
    let contents: Vec<Vec<usize>> = raw.iter().map(|(content, _, _)| content.clone()).collect();
    let keys = dense_content_ids(&contents);
    let tokens: Vec<Token> = keys
        .iter()
        .zip(&raw)
        .map(|(&key, &(_, run_start, run_len))| Token {
            key,
            run_start,
            run_len,
        })
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

//! The ciphertext-autokey (feedback) deck substrate: permutation tables, the
//! deterministic forward decode, the crib run/match statistics, and the planted
//! encrypt used by the self-test.
//!
//! See [`super`] for the cryptanalytic derivation. This file holds only the
//! mechanism, kept free of reporting or null-model concerns. All slice access is
//! checked (`.get().copied().unwrap_or(..)`); every index is provably in range by
//! construction (permutation indices `< count`, card values `< deck_size`), so the
//! fallbacks are never taken and the helpers are total.

use crate::nulls::null::{RandomBoundError, SplitMix64, random_index_below};

/// Maximum supported deck size for the exhaustive feedback search. The
/// advance-map search space is `(deck_size!)^deck_size`; at `deck_size = 4` that
/// is `24^4 = 331_776`, the `two` configuration. Five would be `120^5 ≈ 2.5e10`,
/// far beyond an exhaustive sweep, so the search refuses it.
pub const MAX_SEARCH_DECK: usize = 4;

/// Which composition side the deck advance uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// `D_{i+1} = D_i ∘ g(q_i)` (post-compose). With the forward readout the
    /// initial deck `D0` cancels from every crib equality, so the search over `g`
    /// alone is fully general for this convention.
    Right,
    /// `D_{i+1} = g(q_i) ∘ D_i` (pre-compose).
    Left,
}

/// Which readout maps the hidden deck and the observed card channel to the
/// recovered plaintext deck-symbol `t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Readout {
    /// `t_i = D_i(q_i)` — the card value at observed position `q_i`. With
    /// right-compose, `D0` cancels from crib equalities (`t_i = D0(P_i(q_i))` and
    /// `D0` is a bijection), so this is the fully-general, `D0`-free convention.
    Forward,
    /// `t_i = D_i^{-1}(q_i)` — the position of card `q_i` (the existing
    /// plaintext-autokey solver's convention). `D0` does not cancel here, so the
    /// search fixes `D0 = identity` (a documented representative slice).
    Inverse,
}

impl Side {
    /// Stable lowercase tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Right => "right",
            Self::Left => "left",
        }
    }
}

impl Readout {
    /// Stable lowercase tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Forward => "forward",
            Self::Inverse => "inverse",
        }
    }
}

/// A `(side, readout)` decode convention.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Convention {
    /// Composition side of the deck advance.
    pub side: Side,
    /// Readout mapping deck + card channel to `t`.
    pub readout: Readout,
}

impl Convention {
    /// The four conventions, canonical (forward/right, the `D0`-free one) first.
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [
            Self {
                side: Side::Right,
                readout: Readout::Forward,
            },
            Self {
                side: Side::Left,
                readout: Readout::Forward,
            },
            Self {
                side: Side::Right,
                readout: Readout::Inverse,
            },
            Self {
                side: Side::Left,
                readout: Readout::Inverse,
            },
        ]
    }

    /// Whether the initial deck `D0` provably cancels from crib equalities, so the
    /// search over `g` at `D0 = identity` is fully general.
    ///
    /// `D0` is the *outermost* factor exactly when it ends up outside the readout:
    /// - `forward/right`: `D_i = D0 ∘ A_i`, `t_i = D0(A_i(q_i))` — `D0` outside.
    /// - `inverse/left`: `D_i = A_i ∘ D0`, `t_i = D0^{-1}(A_i^{-1}(q_i))` — `D0^{-1}`
    ///   outside.
    ///
    /// In both, a crib equality `t[a] == t[b]` is invariant under the common
    /// bijection, so it does not depend on `D0`. For `forward/left` and
    /// `inverse/right` the `D0` factor lands *inside* the readout (applied to the
    /// differing `q` values), so it does not cancel and the search is the
    /// `D0 = identity` representative slice.
    #[must_use]
    pub const fn d0_cancels(self) -> bool {
        matches!(
            self,
            Self {
                side: Side::Right,
                readout: Readout::Forward,
            } | Self {
                side: Side::Left,
                readout: Readout::Inverse,
            }
        )
    }
}

/// Precomputed permutation tables over `deck_size` cards: the `deck_size!`
/// permutations, their dense composition table, and inverses.
pub struct Perms {
    deck_size: usize,
    entries: Vec<Vec<usize>>,
    /// Flat `count * count` composition table: `compose[a*count + b]` is the index
    /// of `entries[a] ∘ entries[b]` with `(p ∘ g)[x] = p[g[x]]`.
    compose: Vec<usize>,
    inverse: Vec<usize>,
    identity: usize,
}

impl Perms {
    /// Builds the tables for `deck_size` cards. The factorial blow-up is bounded by
    /// the [`MAX_SEARCH_DECK`] guard the caller enforces.
    #[must_use]
    pub fn build(deck_size: usize) -> Self {
        let entries = enumerate_perms(deck_size);
        let count = entries.len();
        let mut index = std::collections::BTreeMap::new();
        for (i, p) in entries.iter().enumerate() {
            let _previous = index.insert(p.clone(), i);
        }
        let mut compose = vec![0usize; count * count];
        for (a, pa) in entries.iter().enumerate() {
            for (b, pb) in entries.iter().enumerate() {
                let product: Vec<usize> = pb
                    .iter()
                    .map(|&x| pa.get(x).copied().unwrap_or(x))
                    .collect();
                if let Some(slot) = compose.get_mut(a * count + b) {
                    *slot = index.get(&product).copied().unwrap_or(0);
                }
            }
        }
        let mut inverse = vec![0usize; count];
        for (i, p) in entries.iter().enumerate() {
            let mut inv = vec![0usize; deck_size];
            for (pos, &val) in p.iter().enumerate() {
                if let Some(slot) = inv.get_mut(val) {
                    *slot = pos;
                }
            }
            if let Some(slot) = inverse.get_mut(i) {
                *slot = index.get(&inv).copied().unwrap_or(0);
            }
        }
        let identity = index
            .get(&(0..deck_size).collect::<Vec<_>>())
            .copied()
            .unwrap_or(0);
        Self {
            deck_size,
            entries,
            compose,
            inverse,
            identity,
        }
    }

    /// Number of permutations (`deck_size!`).
    #[must_use]
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Identity permutation index.
    #[must_use]
    pub fn identity(&self) -> usize {
        self.identity
    }

    /// `entries[p][x]` — the image of `x` under permutation index `p`.
    #[inline]
    fn apply(&self, p: usize, x: usize) -> usize {
        self.entries
            .get(p)
            .and_then(|row| row.get(x))
            .copied()
            .unwrap_or(0)
    }

    /// Composition-table lookup: index of `entries[a] ∘ entries[b]`.
    #[inline]
    fn compose(&self, a: usize, b: usize) -> usize {
        self.compose.get(a * self.count() + b).copied().unwrap_or(0)
    }

    /// Inverse-permutation index of `p`.
    #[inline]
    fn inverse(&self, p: usize) -> usize {
        self.inverse.get(p).copied().unwrap_or(0)
    }
}

/// Enumerates the `deck_size!` permutations of `0..deck_size` in lexicographic
/// order (recursive build; deck sizes are tiny).
fn enumerate_perms(deck_size: usize) -> Vec<Vec<usize>> {
    let mut out = Vec::new();
    let mut current = Vec::with_capacity(deck_size);
    let mut used = vec![false; deck_size];
    permute(deck_size, &mut current, &mut used, &mut out);
    out
}

fn permute(
    deck_size: usize,
    current: &mut Vec<usize>,
    used: &mut [bool],
    out: &mut Vec<Vec<usize>>,
) {
    if current.len() == deck_size {
        out.push(current.clone());
        return;
    }
    for v in 0..deck_size {
        if used.get(v).copied().unwrap_or(true) {
            continue;
        }
        if let Some(slot) = used.get_mut(v) {
            *slot = true;
        }
        current.push(v);
        permute(deck_size, current, used, out);
        let _popped = current.pop();
        if let Some(slot) = used.get_mut(v) {
            *slot = false;
        }
    }
}

/// An advance map `g: card-value -> permutation index`, one slot per card value.
pub type AdvanceMap = Vec<usize>;

/// Evolves the deck across `q` and writes the recovered `t = readout(D, q)` into
/// `out` for every position up to `len`. `out` is reused across candidates.
///
/// `D0 = identity` is used throughout; for the `Forward`/`Right` convention this
/// is fully general (the initial deck cancels from every crib equality), and for
/// the other conventions it is the representative slice the search documents.
pub fn decode_into(
    perms: &Perms,
    q: &[usize],
    g: &AdvanceMap,
    convention: Convention,
    len: usize,
    out: &mut Vec<usize>,
) {
    out.clear();
    let mut deck = perms.identity();
    for &qi in q.iter().take(len) {
        let read_deck = match convention.readout {
            Readout::Forward => deck,
            Readout::Inverse => perms.inverse(deck),
        };
        out.push(perms.apply(read_deck, qi));
        let gi = g.get(qi).copied().unwrap_or_else(|| perms.identity());
        deck = match convention.side {
            Side::Right => perms.compose(deck, gi),
            Side::Left => perms.compose(gi, deck),
        };
    }
}

/// A crib anchor in *ciphertext* coordinates (already offset from the rotor
/// difference channel): the two aligned start positions and the span length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CribAnchor {
    /// First (smaller) ciphertext start position.
    pub first: usize,
    /// Second (larger) ciphertext start position.
    pub second: usize,
    /// Aligned span length.
    pub length: usize,
}

/// Longest contiguous run, and total count, of positions `s` in `[0, length)`
/// where `t[first+s] == t[second+s]` in the decoded stream `t`.
#[must_use]
pub fn crib_run_count(t: &[usize], anchor: CribAnchor) -> (usize, usize) {
    let mut best = 0usize;
    let mut current = 0usize;
    let mut count = 0usize;
    for s in 0..anchor.length {
        let (Some(&a), Some(&b)) = (
            t.get(anchor.first.saturating_add(s)),
            t.get(anchor.second.saturating_add(s)),
        ) else {
            break;
        };
        if a == b {
            current += 1;
            count += 1;
            best = best.max(current);
        } else {
            current = 0;
        }
    }
    (best, count)
}

/// The best advance map for a `(convention)` over the deck channel `q` and the
/// crib `anchors`, scored by the **joint minimum** crib run across all anchors
/// (a single `g` must reproduce a repeat at every anchor — a spurious `g` that
/// overfits one anchor scores low on the minimum).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BestMap {
    /// The recovered advance map (one permutation index per card value).
    pub g: AdvanceMap,
    /// Minimum crib run across all anchors (the gated statistic).
    pub min_run: usize,
    /// Per-anchor longest crib run for `g` (longest anchor first, caller order).
    pub per_anchor_runs: Vec<usize>,
    /// Per-anchor total crib match count for `g`.
    pub per_anchor_counts: Vec<usize>,
}

/// Exhaustively searches every advance map `g ∈ (deck_size!)^deck_size`, returning
/// the one maximizing the joint-minimum crib run across `anchors`.
///
/// The search evolves the deck only as far as the furthest anchor end. `D0` is
/// fixed to identity (see [`Convention::d0_cancels`]). The hot loop is
/// allocation-free (a reused decode buffer, an inline joint minimum with an
/// early-out once a candidate cannot beat the best). Returns `None` only when
/// there are no anchors.
#[must_use]
pub fn search_best_map(
    perms: &Perms,
    q: &[usize],
    anchors: &[CribAnchor],
    convention: Convention,
) -> Option<BestMap> {
    if anchors.is_empty() {
        return None;
    }
    let deck_size = perms.deck_size;
    let perm_count = perms.count();
    let max_end = anchors
        .iter()
        .map(|a| a.second.saturating_add(a.length))
        .max()
        .unwrap_or(0);
    let decode_len = max_end.min(q.len());

    let mut g = vec![0usize; deck_size];
    let mut t = vec![0usize; decode_len];
    let total = pow_usize(perm_count, deck_size);
    let mut best_min = 0usize;
    let mut best_g = vec![perms.identity(); deck_size];
    for code in 0..total {
        decode_g(code, perm_count, &mut g);
        evolve_record(perms, q, &g, convention, &mut t);
        let mut min_run = usize::MAX;
        for anchor in anchors {
            let run = longest_crib_run(&t, *anchor);
            if run < min_run {
                min_run = run;
                if min_run <= best_min {
                    break; // cannot beat the incumbent; skip the rest
                }
            }
        }
        if min_run > best_min {
            best_min = min_run;
            best_g.copy_from_slice(&g);
        }
    }

    // Recompute the full per-anchor breakdown for the winner.
    evolve_record(perms, q, &best_g, convention, &mut t);
    let mut per_anchor_runs = Vec::with_capacity(anchors.len());
    let mut per_anchor_counts = Vec::with_capacity(anchors.len());
    for &anchor in anchors {
        let (run, count) = crib_run_count(&t, anchor);
        per_anchor_runs.push(run);
        per_anchor_counts.push(count);
    }
    Some(BestMap {
        g: best_g,
        min_run: best_min,
        per_anchor_runs,
        per_anchor_counts,
    })
}

/// The longest contiguous crib run (the cheap inline statistic the search loop
/// uses; [`crib_run_count`] additionally returns the total match count).
fn longest_crib_run(t: &[usize], anchor: CribAnchor) -> usize {
    let mut best = 0usize;
    let mut current = 0usize;
    for s in 0..anchor.length {
        let (Some(&a), Some(&b)) = (
            t.get(anchor.first.saturating_add(s)),
            t.get(anchor.second.saturating_add(s)),
        ) else {
            break;
        };
        if a == b {
            current += 1;
            best = best.max(current);
        } else {
            current = 0;
        }
    }
    best
}

/// Evolves the deck across `q` and writes `t[i] = readout(D_i, q_i)` by index into
/// the preallocated `t` (length is the decode length). Allocation-free.
fn evolve_record(
    perms: &Perms,
    q: &[usize],
    g: &AdvanceMap,
    convention: Convention,
    t: &mut [usize],
) {
    let mut deck = perms.identity();
    for (slot, &qi) in t.iter_mut().zip(q.iter()) {
        let read_deck = match convention.readout {
            Readout::Forward => deck,
            Readout::Inverse => perms.inverse(deck),
        };
        *slot = perms.apply(read_deck, qi);
        let gi = g.get(qi).copied().unwrap_or_else(|| perms.identity());
        deck = match convention.side {
            Side::Right => perms.compose(deck, gi),
            Side::Left => perms.compose(gi, deck),
        };
    }
}

/// Decodes a mixed-radix `code` into `g` (each of `deck_size` slots is a
/// permutation index in `0..perm_count`).
fn decode_g(mut code: usize, perm_count: usize, g: &mut [usize]) {
    for slot in g.iter_mut() {
        if perm_count == 0 {
            *slot = 0;
        } else {
            *slot = code % perm_count;
            code /= perm_count;
        }
    }
}

/// `base^exp` for small inputs (the search-space size).
fn pow_usize(base: usize, exp: usize) -> usize {
    let mut acc = 1usize;
    for _ in 0..exp {
        acc = acc.saturating_mul(base);
    }
    acc
}

/// Encrypts a planted plaintext deck-symbol stream `t` under a known advance map
/// `g` and `convention`, returning the deck channel `q` (the inverse of
/// [`decode_into`]). Used only by the self-test to plant a positive control.
///
/// Encryption inverts the readout: `Forward` needs `q_i = D_i^{-1}(t_i)`,
/// `Inverse` needs `q_i = D_i(t_i)`. The deck then advances on the *emitted*
/// `q_i`, exactly as the decode reads it.
#[must_use]
pub fn encrypt_deck_channel(
    perms: &Perms,
    t: &[usize],
    g: &AdvanceMap,
    convention: Convention,
) -> Vec<usize> {
    let mut deck = perms.identity();
    let mut q = Vec::with_capacity(t.len());
    for &ti in t {
        let qi = match convention.readout {
            // decode: t = D(q)      => encrypt: q = D^{-1}(t)
            Readout::Forward => perms.apply(perms.inverse(deck), ti),
            // decode: t = D^{-1}(q) => encrypt: q = D(t)
            Readout::Inverse => perms.apply(deck, ti),
        };
        q.push(qi);
        let gi = g.get(qi).copied().unwrap_or_else(|| perms.identity());
        deck = match convention.side {
            Side::Right => perms.compose(deck, gi),
            Side::Left => perms.compose(gi, deck),
        };
    }
    q
}

/// Draws a random advance map (`deck_size` permutation indices) from `rng`.
///
/// # Errors
/// Returns [`RandomBoundError`] if the permutation count cannot bound a draw.
pub fn random_advance_map(
    perms: &Perms,
    rng: &mut SplitMix64,
) -> Result<AdvanceMap, RandomBoundError> {
    let mut g = Vec::with_capacity(perms.deck_size);
    for _ in 0..perms.deck_size {
        g.push(random_index_below(perms.count(), rng)?);
    }
    Ok(g)
}

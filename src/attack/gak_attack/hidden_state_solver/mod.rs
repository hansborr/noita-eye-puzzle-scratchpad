//! Hidden-state (deck-stabilizer) GAK solver and a hidden-vs-visible
//! discriminator.
//!
//! This is a **synthetic-validated** port of two cryptanalysis tools. On a
//! known-answer synthetic deck-stabilizer GAK the solver recovers the per-letter
//! key and plaintext to >90% accuracy (the positive control). The decode is a
//! Viterbi over the 24 deck states which — because the deck transition is
//! deterministic given the observed top card — collapses to a forward walk from
//! each initial deck; a held-out-scored genetic search recovers the hidden
//! permutations (see the `solver` submodule). **Nothing here decodes the
//! practice puzzle `two` or the eye glyphs** — those remain unsolved/blocked on
//! the unknown codec and composition convention, and the `two` test records that
//! as an honest negative.
//!
//! ## The cipher this targets (convention B)
//!
//! A direct product `C3 × S4` realized as a card deck plus a 3-state rotor:
//! - state = `(deck, r)` with `deck` a permutation of `0..4` and `r` in `0..3`;
//! - each plaintext symbol `a` in `0..8` carries a key `(eps_a, pi_a)` where the
//!   class shift `eps_a` is in `{1, 2}` (never `0`, so the class always changes)
//!   and `pi_a` is a deck permutation with `pi_a[0] == t_a`;
//! - update on symbol `a`: `r <- (r + eps_a) mod 3`, then
//!   `deck <- compose(deck, pi_a)` (**post-compose**, the hidden-state move);
//! - visible symbol = `top * 3 + r` where `top = deck[0]` (the top card).
//!
//! The visible alphabet is `4 * 3 = 12`. The observable readout splits as
//! `class = symbol mod 3 = r` (so the per-step `eps` is observable from class
//! differences) and `top = symbol / 3 = deck[0]` (a many-valued projection of the
//! hidden deck). The eight plaintext symbols partition into eight fixed cosets
//! `(eps, t)` with `eps` in `{1, 2}` and `t = pi[0]` in `0..4`; the attacker is
//! assumed to know that coset structure and searches only the hidden full
//! permutation behind each coset.
//!
//! The **visible-state** sibling (convention A) pre-composes
//! (`deck <- compose(pi_a, deck)`), so the top card is a function of the *old*
//! top alone — a low-memory Markov chain. The Markov-excess discriminator
//! ([`markov_excess`]) separates the two: post-compose leaks more memory when
//! conditioning on two prior symbols.

use std::collections::BTreeMap;

use super::GakAttackError;

/// Deck size (cards `0..4`); the hidden state is the whole deck.
const DECK_SIZE: usize = 4;
/// Class modulus of the rotor (`C3`).
const CLASS_MOD: usize = 3;
/// Number of plaintext symbols: two class shifts times four top-image cosets.
const NUM_PLAIN_SYMBOLS: usize = 8;

// =====================================================================
// A. Deck/permutation machinery (the cipher substrate).
// =====================================================================

/// Composes two deck permutations in the cipher's convention
/// `compose(p, q)[i] = p[q[i]]`.
///
/// # Errors
/// Returns [`GakAttackError::SymbolOutOfRange`] if an image escapes `0..4`
/// (an internal invariant for the validated `S4` permutations used here).
fn compose_perm(p: [u8; DECK_SIZE], q: [u8; DECK_SIZE]) -> Result<[u8; DECK_SIZE], GakAttackError> {
    let mut out = [0u8; DECK_SIZE];
    for (slot, &qi) in out.iter_mut().zip(q.iter()) {
        *slot = *p
            .get(usize::from(qi))
            .ok_or(GakAttackError::SymbolOutOfRange {
                value: usize::from(qi),
            })?;
    }
    Ok(out)
}

/// Enumerates the 24 permutations of `0..4` in lexicographic order.
fn all_decks() -> Vec<[u8; DECK_SIZE]> {
    let mut decks = Vec::with_capacity(24);
    for a in 0..DECK_SIZE {
        for b in 0..DECK_SIZE {
            if b == a {
                continue;
            }
            for c in 0..DECK_SIZE {
                if c == a || c == b {
                    continue;
                }
                for d in 0..DECK_SIZE {
                    if d == a || d == b || d == c {
                        continue;
                    }
                    decks.push([a as u8, b as u8, c as u8, d as u8]);
                }
            }
        }
    }
    decks
}

/// Precomputed deck tables: the 24 permutations, their index lookup, the dense
/// composition table, the top-card of each deck, and the decks bucketed by top
/// card (for drawing per-coset permutations).
pub(crate) struct DeckTables {
    decks: Vec<[u8; DECK_SIZE]>,
    compose: Vec<usize>,
    top: Vec<usize>,
    inverse: Vec<[usize; DECK_SIZE]>,
    decks_by_top: Vec<Vec<usize>>,
}

impl DeckTables {
    /// Builds the deck tables once.
    ///
    /// # Errors
    /// Returns [`GakAttackError::SymbolOutOfRange`] if a composed permutation is
    /// not found in the index (an internal invariant, since the set is closed).
    pub(crate) fn build() -> Result<Self, GakAttackError> {
        let decks = all_decks();
        let count = decks.len();
        let mut index_of: BTreeMap<[u8; DECK_SIZE], usize> = BTreeMap::new();
        for (i, deck) in decks.iter().enumerate() {
            let _previous = index_of.insert(*deck, i);
        }
        let mut top = Vec::with_capacity(count);
        for deck in &decks {
            top.push(usize::from(
                *deck
                    .first()
                    .ok_or(GakAttackError::SymbolOutOfRange { value: 0 })?,
            ));
        }
        let mut compose = vec![0usize; count.saturating_mul(count)];
        for (a, deck_a) in decks.iter().enumerate() {
            for (b, deck_b) in decks.iter().enumerate() {
                let product = compose_perm(*deck_a, *deck_b)?;
                let product_index = *index_of
                    .get(&product)
                    .ok_or(GakAttackError::SymbolOutOfRange { value: a })?;
                if let Some(slot) = compose.get_mut(a.saturating_mul(count).saturating_add(b)) {
                    *slot = product_index;
                }
            }
        }
        let mut decks_by_top: Vec<Vec<usize>> = vec![Vec::new(); DECK_SIZE];
        for (i, &top_value) in top.iter().enumerate() {
            if let Some(bucket) = decks_by_top.get_mut(top_value) {
                bucket.push(i);
            }
        }
        let mut inverse = Vec::with_capacity(count);
        for deck in &decks {
            let mut inv = [0usize; DECK_SIZE];
            for (position, &value) in deck.iter().enumerate() {
                if let Some(slot) = inv.get_mut(usize::from(value)) {
                    *slot = position;
                }
            }
            inverse.push(inv);
        }
        Ok(Self {
            decks,
            compose,
            top,
            inverse,
            decks_by_top,
        })
    }

    /// Number of deck states (always 24).
    fn count(&self) -> usize {
        self.decks.len()
    }

    /// Index of the identity deck `[0, 1, 2, 3]`.
    fn identity_index(&self) -> Result<usize, GakAttackError> {
        let mut identity = [0u8; DECK_SIZE];
        for (slot, value) in identity.iter_mut().zip(0u8..) {
            *slot = value;
        }
        self.decks
            .iter()
            .position(|deck| *deck == identity)
            .ok_or(GakAttackError::SymbolOutOfRange { value: 0 })
    }

    /// Composition-table lookup: index of `compose(decks[a], decks[b])`.
    fn compose_index(&self, a: usize, b: usize) -> Result<usize, GakAttackError> {
        self.compose
            .get(a.saturating_mul(self.count()).saturating_add(b))
            .copied()
            .ok_or(GakAttackError::SymbolOutOfRange { value: a })
    }

    /// Top card of deck index `d`.
    fn top_of(&self, d: usize) -> Result<usize, GakAttackError> {
        self.top
            .get(d)
            .copied()
            .ok_or(GakAttackError::SymbolOutOfRange { value: d })
    }

    /// Position holding card `value` in deck index `d` (`decks[d]^{-1}[value]`).
    fn inverse_position(&self, d: usize, value: usize) -> Result<usize, GakAttackError> {
        self.inverse
            .get(d)
            .and_then(|inv| inv.get(value))
            .copied()
            .ok_or(GakAttackError::SymbolOutOfRange { value: d })
    }
}

// =====================================================================
// B. Keys, cosets, and the synthetic generator (held-back ground truth).
// =====================================================================

/// The fixed `(eps, t)` coset of plaintext symbol `sym` in `0..8`.
///
/// `sym = 4 * (eps - 1) + t` with `eps` in `{1, 2}` and `t` (the top-image
/// `pi[0]`) in `0..4`. This is the visible coset structure the attacker is
/// assumed to know; only the hidden full permutation behind each coset is
/// searched.
///
/// # Errors
/// Returns [`GakAttackError::SymbolOutOfRange`] if `sym >= 8`.
fn coset_of_symbol(sym: usize) -> Result<(usize, usize), GakAttackError> {
    if sym >= NUM_PLAIN_SYMBOLS {
        return Err(GakAttackError::SymbolOutOfRange { value: sym });
    }
    Ok((sym / DECK_SIZE + 1, sym % DECK_SIZE))
}

/// A key for the eight plaintext symbols: the chosen deck-permutation index per
/// symbol. The `(eps, t)` coset of each symbol is fixed by [`coset_of_symbol`].
#[derive(Clone)]
pub(crate) struct DeckKey {
    perm_index: Vec<usize>,
}

/// Which composition convention a deck-stabilizer GAK uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeckConvention {
    /// Post-compose `deck <- compose(deck, pi)` — the hidden-state regime that
    /// matches `two`'s observable signature and that the Viterbi solver targets.
    HiddenState,
    /// Pre-compose `deck <- compose(pi, deck)` — the visible-state (low-memory)
    /// regime used only as the discriminator's negative reference.
    VisibleState,
}

// =====================================================================
// C. Markov-excess discriminator (hidden-state vs visible-state).
// =====================================================================

/// Conditional entropy `H(Y | X)` in bits from `(x, y)` observations.
fn conditional_entropy(pairs: &[(usize, usize)]) -> f64 {
    let mut by_x: BTreeMap<usize, BTreeMap<usize, usize>> = BTreeMap::new();
    for &(x, y) in pairs {
        *by_x.entry(x).or_default().entry(y).or_insert(0usize) += 1;
    }
    let total = pairs.len() as f64;
    if total <= 0.0 {
        return 0.0;
    }
    let mut entropy = 0.0;
    for inner in by_x.values() {
        let nx: usize = inner.values().sum();
        let nx_f = nx as f64;
        let mut hx = 0.0;
        for &count in inner.values() {
            let p = count as f64 / nx_f;
            hx -= p * p.log2();
        }
        entropy += (nx_f / total) * hx;
    }
    entropy
}

/// The Markov-excess statistic `H(s_t | s_{t-1}) - H(s_t | s_{t-2}, s_{t-1})`.
///
/// A large value means conditioning on two prior symbols reveals much more than
/// one — the signature of a **hidden-state** (post-compose) GAK. A visible-state
/// (Markov) GAK has a small value. On the validated fixtures the visible-state
/// synthetic scores well below the hidden-state synthetic, and the real puzzle
/// `two` scores on the hidden-state side.
///
/// # Errors
/// Returns [`GakAttackError`] if `symbols` is shorter than 3 or a symbol is not
/// below `alphabet_size`.
pub(crate) fn markov_excess(symbols: &[u8], alphabet_size: usize) -> Result<f64, GakAttackError> {
    if symbols.len() < 3 {
        return Err(GakAttackError::EmptyTemplate);
    }
    for &symbol in symbols {
        if usize::from(symbol) >= alphabet_size {
            return Err(GakAttackError::SymbolOutOfRange {
                value: usize::from(symbol),
            });
        }
    }
    let mut order1: Vec<(usize, usize)> = Vec::with_capacity(symbols.len());
    let mut order2: Vec<(usize, usize)> = Vec::with_capacity(symbols.len());
    for window in symbols.windows(2) {
        if let [a, b] = window {
            order1.push((usize::from(*a), usize::from(*b)));
        }
    }
    for window in symbols.windows(3) {
        if let [a, b, c] = window {
            let context = usize::from(*a)
                .saturating_mul(alphabet_size)
                .saturating_add(usize::from(*b));
            order2.push((context, usize::from(*c)));
        }
    }
    Ok(conditional_entropy(&order1) - conditional_entropy(&order2))
}

// =====================================================================
// D. Plaintext bigram language model.
// =====================================================================

/// A smoothed bigram language model over a fixed symbol alphabet, in natural-log
/// units, used to score candidate decodes.
pub(crate) struct BigramLm {
    k: usize,
    log_bigram: Vec<f64>,
}

impl BigramLm {
    /// Trains the model on `symbols` over a `k`-symbol alphabet with additive
    /// `smoothing` (matching the validated `(count + s) / (unigram + s * k)`).
    ///
    /// # Errors
    /// Returns [`GakAttackError`] if `k == 0`, `smoothing` is not finite and
    /// positive, or a symbol is not below `k`.
    pub(crate) fn from_symbols(
        symbols: &[usize],
        k: usize,
        smoothing: f64,
    ) -> Result<Self, GakAttackError> {
        if k == 0 || !smoothing.is_finite() || smoothing <= 0.0 {
            return Err(GakAttackError::EmptyTemplate);
        }
        let mut unigram = vec![0usize; k];
        let mut bigram = vec![0usize; k.saturating_mul(k)];
        for &symbol in symbols {
            let slot = unigram
                .get_mut(symbol)
                .ok_or(GakAttackError::SymbolOutOfRange { value: symbol })?;
            *slot += 1;
        }
        for window in symbols.windows(2) {
            if let [a, b] = window {
                let slot = bigram
                    .get_mut(a.saturating_mul(k).saturating_add(*b))
                    .ok_or(GakAttackError::SymbolOutOfRange { value: *a })?;
                *slot += 1;
            }
        }
        let mut log_bigram = vec![0.0f64; k.saturating_mul(k)];
        for a in 0..k {
            let ua = *unigram
                .get(a)
                .ok_or(GakAttackError::SymbolOutOfRange { value: a })? as f64;
            let denom = ua + smoothing * k as f64;
            for b in 0..k {
                let count = *bigram
                    .get(a.saturating_mul(k).saturating_add(b))
                    .ok_or(GakAttackError::SymbolOutOfRange { value: b })?
                    as f64;
                if let Some(slot) = log_bigram.get_mut(a.saturating_mul(k).saturating_add(b)) {
                    *slot = ((count + smoothing) / denom).ln();
                }
            }
        }
        Ok(Self { k, log_bigram })
    }

    /// Bigram log-probability `log P(b | a)`.
    ///
    /// # Errors
    /// Returns [`GakAttackError`] if `a` or `b` is out of range.
    fn bigram(&self, a: usize, b: usize) -> Result<f64, GakAttackError> {
        self.log_bigram
            .get(a.saturating_mul(self.k).saturating_add(b))
            .copied()
            .ok_or(GakAttackError::SymbolOutOfRange { value: a })
    }

    /// Mean per-bigram log-probability of `symbols` under this model — the
    /// English-fit reference used to calibrate the honest negative.
    ///
    /// # Errors
    /// Returns [`GakAttackError`] if `symbols` has fewer than two symbols or a
    /// symbol is out of range.
    pub(crate) fn mean_bigram_log_prob(&self, symbols: &[usize]) -> Result<f64, GakAttackError> {
        if symbols.len() < 2 {
            return Err(GakAttackError::EmptyTemplate);
        }
        let mut sum = 0.0;
        let mut pairs = 0usize;
        for window in symbols.windows(2) {
            if let [a, b] = window {
                sum += self.bigram(*a, *b)?;
                pairs += 1;
            }
        }
        Ok(sum / pairs as f64)
    }
}

// =====================================================================
// Submodule wiring.
// =====================================================================

mod solver;

pub(crate) use solver::{decode_with_key, draw_key, encrypt, solve_hidden_state_gak};

#[cfg(test)]
mod tests;

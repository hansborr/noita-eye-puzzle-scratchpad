//! Hidden-state (deck-stabilizer, convention B) GAK decode + held-out genetic
//! search, plus the synthetic generator ([`draw_key`]/[`encrypt`]).
//!
//! The deck transition is deterministic given the observed top card, so the
//! Viterbi over the 24 deck states collapses to one forward walk from each
//! initial deck consistent with the first top; the LM only selects among those
//! (`<= 6`) walks. A recombining (genetic) search over the hidden per-coset
//! permutations, selected by held-out LM score, then reaches the true key past
//! the partially-correct deceptive local optima. **Synthetic-validated only.**

use std::cmp::Ordering;

use super::{
    BigramLm, CLASS_MOD, DECK_SIZE, DeckConvention, DeckKey, DeckTables, GakAttackError,
    NUM_PLAIN_SYMBOLS, coset_of_symbol,
};
use crate::nulls::null::{SplitMix64, random_index_below};

/// Draws a deterministic key from `seed`.
///
/// # Errors
/// Returns [`GakAttackError`] if key construction fails.
pub(crate) fn draw_key(tables: &DeckTables, seed: u64) -> Result<DeckKey, GakAttackError> {
    let mut rng = SplitMix64::new(seed);
    random_key(tables, &mut rng)
}

/// Encrypts an 8-symbol `plaintext` under `key` and `convention`, returning the
/// 12-symbol visible ciphertext (`top * 3 + r`).
///
/// # Errors
/// Returns [`GakAttackError`] if a plaintext symbol is out of range or a table
/// lookup fails.
pub(crate) fn encrypt(
    plaintext: &[usize],
    key: &DeckKey,
    tables: &DeckTables,
    convention: DeckConvention,
) -> Result<Vec<u8>, GakAttackError> {
    let mut deck = tables.identity_index()?;
    let mut r = 0usize;
    let mut out = Vec::with_capacity(plaintext.len());
    for &sym in plaintext {
        let (eps, _t) = coset_of_symbol(sym)?;
        r = (r + eps) % CLASS_MOD;
        let pi = *key
            .perm_index
            .get(sym)
            .ok_or(GakAttackError::SymbolOutOfRange { value: sym })?;
        deck = match convention {
            DeckConvention::HiddenState => tables.compose_index(deck, pi)?,
            DeckConvention::VisibleState => tables.compose_index(pi, deck)?,
        };
        let symbol = tables
            .top_of(deck)?
            .saturating_mul(CLASS_MOD)
            .saturating_add(r);
        out.push(
            u8::try_from(symbol)
                .map_err(|_overflow| GakAttackError::SymbolOutOfRange { value: symbol })?,
        );
    }
    Ok(out)
}

// =====================================================================
// E. Deterministic deck decode + held-out genetic search.
// =====================================================================

/// The decoded ciphertext problem: the observable top-card (`q`) and class
/// channels, the per-step class shift (`eps`), the initial decks consistent with
/// the first observed top, and the substrate/LM the decode needs.
///
/// The deck transition is **deterministic** given the observed top: the
/// `top == q[t]` constraint leaves exactly one candidate symbol per deck, so the
/// Viterbi over all 24 deck states collapses to one forward walk from each
/// initial deck, and the LM only selects among those (`<= 6`) initial decks.
struct DeckProblem<'tables, 'lm> {
    q: Vec<usize>,
    eps: Vec<usize>,
    init_decks: Vec<usize>,
    n: usize,
    tables: &'tables DeckTables,
    lm: &'lm BigramLm,
}

impl<'tables, 'lm> DeckProblem<'tables, 'lm> {
    /// Splits the ciphertext into the observable top-card and class channels and
    /// the per-step `eps`, and gathers the initial decks consistent with the
    /// first top.
    fn from_ciphertext(
        ciphertext: &[u8],
        tables: &'tables DeckTables,
        lm: &'lm BigramLm,
    ) -> Result<Self, GakAttackError> {
        let n = ciphertext.len();
        if n < 2 {
            return Err(GakAttackError::EmptyTemplate);
        }
        let mut q = Vec::with_capacity(n);
        let mut class = Vec::with_capacity(n);
        for &symbol in ciphertext {
            let value = usize::from(symbol);
            q.push(value / CLASS_MOD);
            class.push(value % CLASS_MOD);
        }
        let mut eps = Vec::with_capacity(n.saturating_sub(1));
        for i in 1..n {
            let a = *class
                .get(i - 1)
                .ok_or(GakAttackError::SymbolOutOfRange { value: i })?;
            let b = *class
                .get(i)
                .ok_or(GakAttackError::SymbolOutOfRange { value: i })?;
            // Convention-B forbids a zero class shift: `eps` is only 1 or 2, so the
            // rotor class always changes. A same-class adjacency (`shift == 0`) is
            // impossible under the real cipher; without this guard the later
            // `saturating_sub(1)` would alias it into the `eps == 1` cosets and
            // silently decode a malformed or shuffled stream. Reject it instead so
            // the no-same-class precondition is load-bearing, not assumed.
            let shift = (b + CLASS_MOD - a) % CLASS_MOD;
            if shift == 0 {
                return Err(GakAttackError::SameClassAdjacency { position: i });
            }
            eps.push(shift);
        }
        let q0 = *q
            .first()
            .ok_or(GakAttackError::SymbolOutOfRange { value: 0 })?;
        let mut init_decks = Vec::new();
        for d in 0..tables.count() {
            if tables.top_of(d)? == q0 {
                init_decks.push(d);
            }
        }
        Ok(Self {
            q,
            eps,
            init_decks,
            n,
            tables,
            lm,
        })
    }

    /// Forward-decodes from one initial deck: at each step the observed top
    /// `q[t]` and class shift `eps` force the plaintext symbol (the symbol whose
    /// coset top equals `deck^{-1}[q[t]]` in the observed eps group), then the
    /// key's permutation for that symbol advances the deck.
    fn decode_from(&self, key: &DeckKey, init: usize) -> Result<Vec<usize>, GakAttackError> {
        let mut deck = init;
        let mut path = Vec::with_capacity(self.n.saturating_sub(1));
        for t in 1..self.n {
            let e = *self
                .eps
                .get(t - 1)
                .ok_or(GakAttackError::SymbolOutOfRange { value: t })?;
            let qt = *self
                .q
                .get(t)
                .ok_or(GakAttackError::SymbolOutOfRange { value: t })?;
            let top_image = self.tables.inverse_position(deck, qt)?;
            let sym = e
                .saturating_sub(1)
                .saturating_mul(DECK_SIZE)
                .saturating_add(top_image);
            path.push(sym);
            let pi = *key
                .perm_index
                .get(sym)
                .ok_or(GakAttackError::SymbolOutOfRange { value: sym })?;
            deck = self.tables.compose_index(deck, pi)?;
        }
        Ok(path)
    }

    /// Held-out LM score over the second half of a decoded path (so an over-fit
    /// first half cannot inflate the score).
    fn held_out(&self, path: &[usize]) -> Result<f64, GakAttackError> {
        if path.len() < 2 {
            return Ok(f64::NEG_INFINITY);
        }
        let half = path.len() / 2;
        let mut score = 0.0;
        for i in (half + 1)..path.len() {
            let a = *path
                .get(i - 1)
                .ok_or(GakAttackError::SymbolOutOfRange { value: i })?;
            let b = *path
                .get(i)
                .ok_or(GakAttackError::SymbolOutOfRange { value: i })?;
            score += self.lm.bigram(a, b)?;
        }
        Ok(score)
    }

    /// The held-out LM score of the forward decode from one initial deck,
    /// accumulated without materializing the path (the allocation-free fitness
    /// used inside the genetic search).
    fn score_from(&self, key: &DeckKey, init: usize) -> Result<f64, GakAttackError> {
        let path_len = self.n.saturating_sub(1);
        let half = path_len / 2;
        let mut deck = init;
        let mut prev_sym: Option<usize> = None;
        let mut score = 0.0;
        for t in 1..self.n {
            let e = *self
                .eps
                .get(t - 1)
                .ok_or(GakAttackError::SymbolOutOfRange { value: t })?;
            let qt = *self
                .q
                .get(t)
                .ok_or(GakAttackError::SymbolOutOfRange { value: t })?;
            let top_image = self.tables.inverse_position(deck, qt)?;
            let sym = e
                .saturating_sub(1)
                .saturating_mul(DECK_SIZE)
                .saturating_add(top_image);
            // Path index of this symbol is `t - 1`; held-out scores indices
            // `> half`, i.e. positions `t - 1 > half`.
            if let Some(previous) = prev_sym
                && t.saturating_sub(1) > half
            {
                score += self.lm.bigram(previous, sym)?;
            }
            prev_sym = Some(sym);
            let pi = *key
                .perm_index
                .get(sym)
                .ok_or(GakAttackError::SymbolOutOfRange { value: sym })?;
            deck = self.tables.compose_index(deck, pi)?;
        }
        Ok(score)
    }

    /// Best held-out score over the initial decks (allocation-free fitness).
    fn score(&self, key: &DeckKey) -> Result<f64, GakAttackError> {
        let mut best = f64::NEG_INFINITY;
        for &init in &self.init_decks {
            let score = self.score_from(key, init)?;
            if score > best {
                best = score;
            }
        }
        Ok(best)
    }

    /// Decodes under `key`, keeping the initial deck with the best held-out
    /// score. Returns `(held_out_score, decoded path)`.
    fn decode(&self, key: &DeckKey) -> Result<(f64, Vec<usize>), GakAttackError> {
        let mut best = f64::NEG_INFINITY;
        let mut best_path: Vec<usize> = Vec::new();
        for &init in &self.init_decks {
            let path = self.decode_from(key, init)?;
            let score = self.held_out(&path)?;
            if score > best {
                best = score;
                best_path = path;
            }
        }
        Ok((best, best_path))
    }
}

/// Sets symbol `sym` to a uniformly random permutation from its coset (the
/// genetic mutation operator and a random-key building block).
fn perturb_symbol(
    key: &mut DeckKey,
    tables: &DeckTables,
    sym: usize,
    rng: &mut SplitMix64,
) -> Result<(), GakAttackError> {
    let (_eps, t) = coset_of_symbol(sym)?;
    let bucket = tables
        .decks_by_top
        .get(t)
        .ok_or(GakAttackError::SymbolOutOfRange { value: t })?;
    let pick = random_index_below(bucket.len(), rng)?;
    let proposal = *bucket
        .get(pick)
        .ok_or(GakAttackError::SymbolOutOfRange { value: pick })?;
    if let Some(slot) = key.perm_index.get_mut(sym) {
        *slot = proposal;
    }
    Ok(())
}

/// Tournament size for parent selection.
const TOURNAMENT: usize = 3;
/// Per-symbol mutation probability, in percent.
const MUTATION_PERCENT: u64 = 18;

/// Uniform per-symbol crossover: each symbol's permutation is taken from one
/// parent or the other. Both parents are valid keys, so the child is too.
fn crossover(a: &DeckKey, b: &DeckKey, rng: &mut SplitMix64) -> Result<DeckKey, GakAttackError> {
    let mut perm_index = Vec::with_capacity(NUM_PLAIN_SYMBOLS);
    for sym in 0..NUM_PLAIN_SYMBOLS {
        let source = if rng.next_u64() & 1 == 0 { a } else { b };
        perm_index.push(
            *source
                .perm_index
                .get(sym)
                .ok_or(GakAttackError::SymbolOutOfRange { value: sym })?,
        );
    }
    Ok(DeckKey { perm_index })
}

/// Mutates each symbol independently with probability `MUTATION_PERCENT`.
fn mutate(
    key: &mut DeckKey,
    tables: &DeckTables,
    rng: &mut SplitMix64,
) -> Result<(), GakAttackError> {
    for sym in 0..NUM_PLAIN_SYMBOLS {
        if rng.next_u64() % 100 < MUTATION_PERCENT {
            perturb_symbol(key, tables, sym, rng)?;
        }
    }
    Ok(())
}

/// Tournament selection over a best-first-sorted population: draw `TOURNAMENT`
/// members and return the fittest (smallest index).
fn tournament(population_len: usize, rng: &mut SplitMix64) -> Result<usize, GakAttackError> {
    let mut best = population_len.saturating_sub(1);
    for _ in 0..TOURNAMENT {
        let idx = random_index_below(population_len, rng)?;
        if idx < best {
            best = idx;
        }
    }
    Ok(best)
}

/// Sorts a population best-first by held-out fitness.
fn sort_population(population: &mut [(f64, DeckKey)]) {
    population.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(Ordering::Equal));
}

/// Held-out-scored genetic search over the hidden per-coset permutations.
///
/// Random local optima are only *partially* correct (correct on different symbol
/// subsets), so uniform per-symbol crossover recombines them into the true key
/// far more reliably than restarts of a single hill-climb. Returns the best
/// `(held_out_score, path)`.
fn genetic_search(
    problem: &DeckProblem<'_, '_>,
    tables: &DeckTables,
    population_size: usize,
    generations: usize,
    seed: u64,
) -> Result<(f64, Vec<usize>), GakAttackError> {
    let mut rng = SplitMix64::new(seed);
    let mut population: Vec<(f64, DeckKey)> = Vec::with_capacity(population_size);
    for _ in 0..population_size {
        let key = random_key(tables, &mut rng)?;
        let fitness = problem.score(&key)?;
        population.push((fitness, key));
    }
    sort_population(&mut population);
    let elite = (population_size / 5).max(1);
    for _generation in 0..generations {
        let mut next: Vec<(f64, DeckKey)> = Vec::with_capacity(population_size);
        for member in population.iter().take(elite) {
            next.push((member.0, member.1.clone()));
        }
        while next.len() < population_size {
            let pa = tournament(population.len(), &mut rng)?;
            let pb = tournament(population.len(), &mut rng)?;
            let parent_a = &population
                .get(pa)
                .ok_or(GakAttackError::SymbolOutOfRange { value: pa })?
                .1;
            let parent_b = &population
                .get(pb)
                .ok_or(GakAttackError::SymbolOutOfRange { value: pb })?
                .1;
            let mut child = crossover(parent_a, parent_b, &mut rng)?;
            mutate(&mut child, tables, &mut rng)?;
            let fitness = problem.score(&child)?;
            next.push((fitness, child));
        }
        sort_population(&mut next);
        population = next;
    }
    let best = population
        .first()
        .ok_or(GakAttackError::SymbolOutOfRange { value: 0 })?;
    problem.decode(&best.1)
}

/// Draws a random valid key: each symbol gets a uniform permutation from its
/// coset (top image fixed by [`coset_of_symbol`]).
fn random_key(tables: &DeckTables, rng: &mut SplitMix64) -> Result<DeckKey, GakAttackError> {
    let mut key = DeckKey {
        perm_index: vec![0usize; NUM_PLAIN_SYMBOLS],
    };
    for sym in 0..NUM_PLAIN_SYMBOLS {
        perturb_symbol(&mut key, tables, sym, rng)?;
    }
    Ok(key)
}

/// The result of a hidden-state GAK solve.
pub(crate) struct DeckGakRecovery {
    /// The recovered plaintext symbols for ciphertext positions `1..n`.
    pub(crate) plaintext: Vec<usize>,
}

/// Decodes `ciphertext` under a *given* key, returning `(held_out_score, decoded
/// plaintext)`. Used by the positive control's known-key diagnostic.
///
/// # Errors
/// Returns [`GakAttackError`] if the tables cannot be built or the decode fails.
pub(crate) fn decode_with_key(
    ciphertext: &[u8],
    lm: &BigramLm,
    key: &DeckKey,
) -> Result<(f64, Vec<usize>), GakAttackError> {
    let tables = DeckTables::build()?;
    let problem = DeckProblem::from_ciphertext(ciphertext, &tables, lm)?;
    problem.decode(key)
}

/// Solves a hidden-state (deck-stabilizer, convention B) GAK ciphertext against a
/// plaintext bigram LM by deterministic deck decode with a held-out-scored
/// genetic search over the hidden per-coset permutations.
///
/// The held-out selection is what defeats the always-fits-something overfitting
/// artifact; the recombining search is what reaches the (rare-basin) true
/// optimum past the partially-correct deceptive local optima.
///
/// **Synthetic-validated only.** A recovered plaintext is meaningful when the
/// coset structure and convention hold (the positive control); on real `two` the
/// convention/codec are unknown, so the result is not an English decode.
///
/// # Errors
/// Returns [`GakAttackError`] if the ciphertext is too short, the tables cannot
/// be built, or a draw/lookup fails.
pub(crate) fn solve_hidden_state_gak(
    ciphertext: &[u8],
    lm: &BigramLm,
    population_size: usize,
    generations: usize,
    seed: u64,
) -> Result<DeckGakRecovery, GakAttackError> {
    let tables = DeckTables::build()?;
    let problem = DeckProblem::from_ciphertext(ciphertext, &tables, lm)?;
    let (_score, plaintext) =
        genetic_search(&problem, &tables, population_size.max(2), generations, seed)?;
    Ok(DeckGakRecovery { plaintext })
}

use super::*;

// =====================================================================
// unit 2a — real GAK on the deck stabilizer (non-trivial hidden subgroup).
//
// Everything above is the trivial-H GCTAK gate (the proof-of-life positive
// control). Below is the actual contribution the wiki asks for: a constraint-
// propagation attack on real GAK (`H = Stab(top) = S_{n-1}`, `|H| = (n-1)! > 1`)
// realized by `GakKey::deck`. It is **synthetic-only** (we hold ground truth, so
// recovering the key is legitimate) and reports a measured tractability bound:
// where partial recovery breaks as `n` / `|H|` grows. A low/zero recovered
// fraction at larger `n` is the expected, valuable result — a measured negative.
//
// ## Why this is hard (the deck quirk that the attack must honor)
//
// State `g ∈ S_n`, update `g ← π_a ∘ g`, visible symbol `s = c(g) = g^{-1}[top]`.
// The next visible symbol is `s' = (π_a ∘ g)^{-1}[top] = g^{-1}[π_a^{-1}[top]]`,
// which depends on `g^{-1}` evaluated at `π_a^{-1}[top]` — i.e. on the whole
// hidden permutation, not just on `s`. So a single visible symbol can transition
// to many next-symbols under the same letter across different hidden states
// (`Chaining-Conflicts.md`: cycles of unequal length are normal; edge overlap
// does not prove context equality). Only within one fixed context (one aligned
// isomorph occurrence pair) is the action a partial permutation, and two arrows
// out of (or into) one symbol there is a true conflict that proves a bad isomorph
// assumption (not a discovery) and aborts that branch.
// =====================================================================

/// How the per-letter `p(a)` permutations are drawn for a real-GAK deck fixture.
///
/// Both regimes are generated so the next unit can validate the tentative
/// small-support prior (idea 2): when `small_support_radius > 0` the draws are
/// near-identity (a base permutation composed with `≤k` transpositions), the
/// regime in which `Deck-Cipher.md`'s shared-sections evidence would hold; when
/// `0` the draws are unconstrained `S_n`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeckLetterRegime {
    /// Unconstrained `S_n`: each `p(a)` is a uniform random permutation.
    Unconstrained,
    /// Tentative small-support: each `p(a)` is a base permutation composed with
    /// `≤radius` random transpositions (near-identity). Not a hard constraint.
    SmallSupport {
        /// Maximum number of transpositions from the shared base (`≤k`).
        radius: usize,
    },
}

impl DeckLetterRegime {
    /// Returns a short report label for this regime.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Unconstrained => "unconstrained S_n",
            Self::SmallSupport { .. } => "tentative small-support",
        }
    }
}

/// Held-back ground truth for one synthetic **real-GAK deck** fixture.
///
/// As with [`SyntheticFixture`] the attack always holds this so every claim is
/// checkable. Unlike the GCTAK fixture the hidden subgroup is non-trivial, so the
/// per-letter visible-coset action is *not* a fixed permutation — the ground
/// truth scored against is the per-letter coset-edge multimap derived from the key
/// (the internal `truth_coset_edges` helper).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeckFixture {
    /// Plaintext letter stream (each [`Glyph`] is a letter index).
    pub plaintext: Vec<Glyph>,
    /// Ciphertext coset stream (visible top-card positions) from [`gak_encrypt`].
    pub ciphertext: Vec<Glyph>,
    /// The deck key, held back for ground-truth checks (per-letter `S_n`
    /// permutations + initial deck state).
    pub key: GakKey,
    /// Deck size `n` (`|C| = n`, `|G| = n!`, `|H| = (n-1)!`).
    pub state_size: usize,
    /// How the per-letter permutations were drawn.
    pub regime: DeckLetterRegime,
    /// The order of the hidden subgroup `|H| = (n-1)!` (saturating; for the small
    /// `n` we sweep it never overflows). Reported so the tractability bound can be
    /// read against `|H|`, not just `n`.
    pub hidden_subgroup_order: u128,
}

/// Computes `(n-1)!` as the deck-stabilizer hidden-subgroup order `|H|`,
/// saturating at [`u128::MAX`] (never reached for the small `n` we sweep).
#[must_use]
pub(crate) fn deck_hidden_subgroup_order(state_size: usize) -> u128 {
    let mut product: u128 = 1;
    let upper = state_size.saturating_sub(1);
    for factor in 2..=upper {
        product = product.saturating_mul(factor as u128);
    }
    product
}

/// Builds a synthetic **real-GAK deck** fixture with held-back ground truth.
///
/// The deck realization ([`GakKey::deck`], [`CosetReadout::TopCard`]) gives a
/// genuinely non-trivial hidden subgroup `H = Stab(top) = S_{n-1}` (`|H| > 1`):
/// the visible ciphertext symbol is the position of the marked card and the rest
/// of the deck is the hidden state. `num_pt_letters` distinct permutations of
/// `0..n` become the letters; under [`DeckLetterRegime::SmallSupport`] they are
/// drawn near-identity. The plaintext is the same repeated-phrase template the
/// GCTAK gate uses, so the ciphertext is isomorph-rich (the attack's bite).
///
/// # Errors
/// Returns [`GakAttackError`] when `n` is too small for the requested letters,
/// when a generated permutation/key is rejected by the cipher primitives, or when
/// a generated symbol cannot be represented.
pub fn generate_deck_fixture(
    state_size: usize,
    regime: DeckLetterRegime,
    config: GakAttackConfig,
    seed: u64,
) -> Result<DeckFixture, GakAttackError> {
    // Real-GAK deck attack requires n >= 3: at n = 2, H = S_1 is trivial (GCTAK,
    // not real GAK) and the n-1 merge threshold collapses to 1 (a single shared
    // edge could merge). The default sweep (5..=8) is unaffected.
    if state_size < 3 {
        return Err(GakAttackError::DeckStateSizeTooSmall { state_size });
    }
    // The deck `S_n` has `n!` elements; `num_pt_letters` distinct non-identity
    // permutations are always available for the small `n` we attack.
    if config.num_pt_letters == 0 {
        return Err(GakAttackError::TooManyLetters {
            requested: config.num_pt_letters,
            available: 0,
        });
    }

    let mut rng = SplitMix64::new(seed);

    // Draw `num_pt_letters` distinct, non-identity permutations of `0..n`. Under
    // SmallSupport they share a base and differ by ≤radius transpositions.
    let letters = draw_deck_letters(state_size, regime, config.num_pt_letters, &mut rng)?;

    // The deck readout itself is the right-coset projection, so `GakKey::deck`'s
    // identity-state injectivity check is sufficient for invertibility; no doubles
    // option is forced here (the attack must tolerate adjacent-equal symbols, a
    // normal deck-GAK occurrence).
    let key = GakKey::deck(state_size, letters, GakKeyOptions::default())?;

    let plaintext = repeated_phrase_template(config, config.num_pt_letters, &mut rng)?;
    if plaintext.is_empty() {
        return Err(GakAttackError::EmptyTemplate);
    }
    let ciphertext = gak_encrypt(&plaintext, &key)?;

    Ok(DeckFixture {
        plaintext,
        ciphertext,
        key,
        state_size,
        regime,
        hidden_subgroup_order: deck_hidden_subgroup_order(state_size),
    })
}

/// Maximum re-rolls when drawing a distinct non-identity deck letter.
const MAX_DECK_LETTER_DRAWS: usize = 256;

/// Draws `count` distinct non-identity permutations of `0..n` for the deck
/// letters, honoring the [`DeckLetterRegime`] and the deck's coset-injectivity
/// rule.
///
/// `Unconstrained` draws uniform `S_n` elements; `SmallSupport { radius }` draws a
/// single shared base then perturbs it by `≤radius` transpositions per letter
/// (near-identity, `Deck-Cipher.md`). Bounded re-rolls enforce three properties
/// [`GakKey::deck`] requires for an invertible key from the identity state:
/// non-identity, distinct permutations, and — crucially — distinct readout cosets
/// `π_a^{-1}[top]` (the position of the marked card after one step), since two
/// letters sharing that coset would be indistinguishable in the ciphertext. The
/// marked card is `0` (the deck readout's `reference_value`).
fn draw_deck_letters(
    state_size: usize,
    regime: DeckLetterRegime,
    count: usize,
    rng: &mut SplitMix64,
) -> Result<Vec<Vec<usize>>, GakAttackError> {
    let identity: Vec<usize> = (0..state_size).collect();
    let base = match regime {
        DeckLetterRegime::Unconstrained => identity.clone(),
        DeckLetterRegime::SmallSupport { .. } => shuffled_permutation(state_size, rng)?,
    };
    let mut chosen: Vec<Vec<usize>> = Vec::with_capacity(count);
    // The readout coset of a permutation `π` from the identity state is the
    // position holding card `0`, i.e. `π^{-1}[0]` = the index `j` with `π[j] == 0`.
    let mut used_cosets: BTreeSet<usize> = BTreeSet::new();
    for _letter in 0..count {
        let mut candidate = identity.clone();
        for _draw in 0..MAX_DECK_LETTER_DRAWS {
            candidate = match regime {
                DeckLetterRegime::Unconstrained => shuffled_permutation(state_size, rng)?,
                DeckLetterRegime::SmallSupport { radius } => {
                    let mut perturbed = base.clone();
                    apply_small_support(&mut perturbed, radius.max(1), rng)?;
                    perturbed
                }
            };
            let coset = candidate.iter().position(|&card| card == 0);
            let acceptable = candidate != identity
                && !chosen.contains(&candidate)
                && coset.is_some_and(|c| !used_cosets.contains(&c));
            if acceptable {
                break;
            }
        }
        if let Some(coset) = candidate.iter().position(|&card| card == 0) {
            let _added = used_cosets.insert(coset);
        }
        chosen.push(candidate);
    }
    Ok(chosen)
}

// ---------------------------------------------------------------------
// B. Deck visible-coset action-recovery attack (idea 1).
//
// The attack reads per-letter visible-coset transitions where contexts compose as
// permutations, not scalars. The recovery's equations come from the shared
// `chaining_graph` chain links (load-bearing — `phrase_column_evidence` sources its
// prev->next edges straight out of `chain_links_for_pair`). It then light-merges the
// single-valued cores under a group-dependent overlap threshold — a deliberately
// conservative merge, not full Schreier-graph constraint propagation (the
// multi-valued part is left to idea 3's hidden-state marginalization, and is
// measured here as the obstruction).
// ---------------------------------------------------------------------

/// A directed visible-coset edge `from -> to` observed under one fixed context.
///
/// Sourced from [`chaining_graph::chain_links_for_pair`] over aligned isomorph
/// occurrences: each [`ChainLink`]'s `(from, to)` is one such edge (the action of
/// the context that maps one occurrence's column to the other's). The attack
/// never invents edges — they come straight from the shared chain-link primitive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CosetEdge {
    /// Source visible coset symbol.
    pub(crate) from: u8,
    /// Image visible coset symbol under the context action.
    pub(crate) to: u8,
}

/// The per-context action distilled from the chain links of one aligned isomorph
/// occurrence pair: a partial map on the visible coset alphabet, plus its true-
/// conflict flag.
///
/// A context's action must be a partial permutation (single-valued forward and
/// backward). Two distinct arrows out of one symbol, or into one symbol, is a
/// **true conflict** (`Chaining-Conflicts.md`): it proves a bad isomorph
/// assumption, so the branch is aborted rather than counted as a discovery.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ContextAction {
    /// Forward partial permutation `from -> to`.
    forward: BTreeMap<u8, u8>,
    /// The distinct directed edges (for the group-dependent overlap threshold).
    edges: BTreeSet<CosetEdge>,
    /// `true` once a true conflict (non-functional forward or backward) is seen.
    pub(crate) true_conflict: bool,
}

impl ContextAction {
    /// Inserts one observed edge, setting [`Self::true_conflict`] if it violates
    /// the partial-permutation law (forward or backward single-valuedness).
    pub(crate) fn insert(&mut self, edge: CosetEdge) {
        let _added = self.edges.insert(edge);
        match self.forward.get(&edge.from) {
            Some(existing) if *existing != edge.to => {
                // Two arrows out of `from` under one fixed context => true conflict.
                self.true_conflict = true;
                return;
            }
            Some(_) => return,
            None => {}
        }
        // Backward check: two arrows into `to` under one fixed context.
        if self
            .forward
            .iter()
            .any(|(k, v)| *v == edge.to && *k != edge.from)
        {
            self.true_conflict = true;
            return;
        }
        let _old = self.forward.insert(edge.from, edge.to);
    }
}

/// The chain-link substrate of the deck attack: per-context coset actions plus
/// the global per-letter edge evidence, all derived from the shared
/// [`chain_links_for_pair`] primitive.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ChainSubstrate {
    /// One [`ContextAction`] per aligned isomorph occurrence pair (one context).
    pub(crate) contexts: Vec<ContextAction>,
    /// Number of true-conflict aborts encountered while building contexts.
    pub(crate) true_conflict_aborts: usize,
    /// Number of distinct visible coset symbols touched by any chain link
    /// (chain-link coverage).
    pub(crate) symbols_touched: usize,
}

/// Builds the chain-link substrate for the deck attack (coverage + fixed-context
/// conflict detection — not the recovery substrate).
///
/// Load-bearing reuse: occurrences are grouped by their length-`core_len` prefix
/// [`PatternSignature`] (the isomorph core), and each ordered occurrence pair within
/// a core group becomes one fixed context whose coset edges are exactly the
/// [`chain_links_for_pair`] output over the full `window_len` window (core +
/// extension). This is genuine reuse of the shared primitive, not a second graph.
///
/// **Why a core prefix.** Grouping by the full window makes every pair a partial
/// bijection by construction (same full-window signature ⇒ identical equality
/// pattern ⇒ no conflict), so a fixed-context true conflict could never fire.
/// Grouping by the core prefix lets two windows that share the core but diverge in
/// the over-extension tail be aligned — and a divergent tail can produce two arrows
/// out of / into one symbol under that single fixed alignment, which is exactly a
/// genuine **bad isomorph alignment** (over-extension past the true core), the only
/// thing that can produce a real true conflict. The production caller passes
/// `core_len == window_len` (full-window grouping, no extension), so the shipped
/// numbers are unchanged; a smaller `core_len` is what exercises the conflict guard.
///
/// A fixed context whose action carries a true conflict is dropped (its branch
/// aborts) and counted in [`ChainSubstrate::true_conflict_aborts`].
pub(crate) fn build_chain_substrate(
    ciphertext: &[SymbolValue],
    window_len: usize,
    core_len: usize,
) -> ChainSubstrate {
    let core_len = core_len.min(window_len);
    let mut by_core_signature: BTreeMap<PatternSignature, Vec<usize>> = BTreeMap::new();
    if ciphertext.len() >= window_len {
        for start in 0..=ciphertext.len().saturating_sub(window_len) {
            let Some(core) = ciphertext.get(start..start.saturating_add(core_len)) else {
                continue;
            };
            let signature = PatternSignature::from_window(core);
            if signature.has_repeated_symbol() {
                by_core_signature.entry(signature).or_default().push(start);
            }
        }
    }

    let mut substrate = ChainSubstrate::default();
    let mut touched: BTreeSet<u8> = BTreeSet::new();
    let mut context_index: u32 = 0;
    for starts in by_core_signature.values() {
        if starts.len() < 2 {
            continue;
        }
        // Spacing filter: genuine repeated-phrase occurrences are ≥window apart;
        // this drops coincidental short matches inside the mixing runs (the same
        // discipline the GCTAK solver uses).
        let filtered = spacing_filter(starts, window_len);
        for (left_index, &upper_start) in filtered.iter().enumerate() {
            for &lower_start in filtered.iter().skip(left_index.saturating_add(1)) {
                let (Some(upper_window), Some(lower_window)) = (
                    ciphertext.get(upper_start..upper_start.saturating_add(window_len)),
                    ciphertext.get(lower_start..lower_start.saturating_add(window_len)),
                ) else {
                    continue;
                };
                let upper = AlignedOccurrence {
                    message: 0,
                    window: upper_window,
                    core_len,
                };
                let lower = AlignedOccurrence {
                    message: 0,
                    window: lower_window,
                    core_len,
                };
                let context = ContextId::new(context_index);
                context_index = context_index.saturating_add(1);
                let Ok(links) = chain_links_for_pair(context, &upper, &lower) else {
                    continue;
                };
                // One fixed context = one aligned occurrence pair. Within this single
                // alignment two arrows out of / into one symbol can only come from a
                // bad isomorph alignment (an over-extended tail), never from normal
                // hidden-state variation — so a true conflict here is a genuine abort.
                let mut action = ContextAction::default();
                for link in &links {
                    let _ins = touched.insert(link.from.get());
                    let _ins = touched.insert(link.to.get());
                    action.insert(CosetEdge {
                        from: link.from.get(),
                        to: link.to.get(),
                    });
                }
                if action.true_conflict {
                    // Fixed-context true-conflict abort: bad isomorph alignment.
                    substrate.true_conflict_aborts =
                        substrate.true_conflict_aborts.saturating_add(1);
                    continue;
                }
                substrate.contexts.push(action);
            }
        }
    }
    substrate.symbols_touched = touched.len();
    substrate
}

/// Keeps only occurrence starts that are at least `window_len` apart (drops
/// coincidental overlapping matches).
pub(crate) fn spacing_filter(starts: &[usize], window_len: usize) -> Vec<usize> {
    let mut filtered: Vec<usize> = Vec::new();
    let mut last: Option<usize> = None;
    for &start in starts {
        let accept = match last {
            Some(prev) => start >= prev.saturating_add(window_len),
            None => true,
        };
        if accept {
            filtered.push(start);
            last = Some(start);
        }
    }
    filtered
}

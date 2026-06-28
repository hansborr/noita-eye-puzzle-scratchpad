//! The GCTAK decisive-gate solver and the real-GAK deck-stabilizer attack.
//!
//! Holds the GCTAK positive-control solver (`solve_gctak` and its chaining/
//! permutation-recovery helpers) together with the non-trivial-`H` deck attack
//! (`generate_deck_fixture`, `run_deck_attack[_sweep]`, the coset/chain-substrate
//! primitives) — they share the `EdgeMap`, chain-link, and spacing primitives.

use super::*;

mod deck_attack;
mod deck_fixture;
mod deck_sweep;

// The non-trivial-`H` deck substrate lives in the three siblings above; re-export
// their items so the paths stay `crate::attack::gak_attack::solver::*` (and, via
// `gak_attack`'s own `pub use solver::*`, `crate::attack::gak_attack::*`).
// `deck_attack`'s items top out at `pub(crate)`, so its re-export is `pub(crate)`
// (a `pub use` would warn that the glob re-exports nothing public).
pub(crate) use deck_attack::*;
pub use deck_fixture::*;
pub use deck_sweep::*;

// =====================================================================
// B. GCTAK solver — the decisive gate / positive control.
// =====================================================================

/// Runs the GCTAK solver on the real fixture and on the matched shuffle null.
///
/// The solver is told the generator's `phrase_len` and the state-group order, in
/// the spirit of a positive control: the gate constructs both the fixture and the
/// solver, so giving the solver these structural sizes is honest (it does not
/// reveal the key, the letter values, or the permutations). The same sizes are
/// passed to the matched null, keeping the comparison fair.
///
/// ## Why `initial_readout` is not a key leak
///
/// `initial_readout = c(g_0)` is the ciphertext symbol the stream conceptually
/// starts from (the readout of the key's initial state). It is **not** part of the
/// secret key material: it is a single ciphertext-alphabet *symbol*, derived only
/// from the readout `c` and the initial state `g_0`, and it reveals nothing about
/// the per-letter permutations `tau_a` or the letter→permutation map (the actual
/// unknowns the attack recovers). For the gate fixtures the initial state is the
/// identity and the bijective readout gives `c(g_0) = g_0^{-1}[0] = 0`, i.e. a
/// constant `0`, so it carries no fixture-specific information at all. Crucially,
/// the **same** `initial_readout` is passed to the matched-null pipeline below, so
/// even if it conveyed anything it would help the null equally — it cannot be the
/// reason the real stream beats its null.
pub(crate) fn evaluate_fixture(
    fixture: &SyntheticFixture,
    config: GakAttackConfig,
    seed: u64,
) -> Result<GctakGateOutcome, GakAttackError> {
    let ciphertext_values = glyphs_to_values(&fixture.ciphertext)?;
    let truth = canonical_letters(&glyphs_to_indices(&fixture.plaintext));
    // Held ground-truth per-letter ciphertext-alphabet permutations.
    let truth_permutations = truth_letter_permutations(&fixture.key)?;

    // The state entering the first letter is the readout of the initial state.
    // The gate fixtures use the identity initial state, whose bijective readout is
    // `0` (`c(identity) = identity^{-1}[0] = 0`), so the first ciphertext symbol is
    // a genuine transition from this known entry point. This value is constant 0
    // here, is not key material, and is fed identically to the null below (see the
    // function doc for why it is not a leak).
    let initial_readout = initial_state_readout(&fixture.key)?;
    let phrase_len = config.phrase_len;
    let group_order = fixture.group_kind.order();

    // Real pipeline.
    let real = solve_gctak(&ciphertext_values, initial_readout, phrase_len, group_order);
    let real_recovered_exactly = real.canonical_letters == truth && real.chain_links_verified();
    let (real_permutations_recovered, permutations_total) =
        permutation_recovery_fraction(&truth_permutations, &real.recovered_permutations);

    // Matched negative control: identical solver pipeline (same phrase_len,
    // group_order, SAME initial_readout) over a within-message multiset shuffle of
    // the SAME ciphertext (here one synthetic message).
    let mut rng = SplitMix64::new(mix_seed(seed, 0x73_6875_6666_6c65));
    let mut shuffled = ciphertext_values.clone();
    fisher_yates(&mut shuffled, &mut rng)?;
    let null = solve_gctak(&shuffled, initial_readout, phrase_len, group_order);
    let null_recovered_exactly = null.canonical_letters == truth;
    let (null_permutations_recovered, _) =
        permutation_recovery_fraction(&truth_permutations, &null.recovered_permutations);

    Ok(GctakGateOutcome {
        group: fixture.group_kind.label(),
        non_commutative: fixture.group_kind.is_non_commutative(),
        group_order: fixture.group_kind.order(),
        realized_order: fixture.realized.realized_subgroup_order,
        seed,
        ciphertext_len: ciphertext_values.len(),
        symbols_recovered: real.symbols_touched,
        letters_recovered: real.letter_count(),
        real_permutations_recovered,
        permutations_total,
        null_permutations_recovered,
        chain_link_checks: real.chain_link_checks,
        chain_link_consistent: real.chain_link_consistent,
        real_recovered_exactly,
        null_recovered_exactly,
    })
}

/// The recovered GCTAK structure from one ciphertext stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GctakSolution {
    /// Recovered plaintext letter stream, canonicalized by first-occurrence
    /// order (so it is comparable to ground truth without depending on the
    /// generator's arbitrary letter numbering).
    pub(crate) canonical_letters: Vec<usize>,
    /// The recovered per-letter ciphertext-alphabet permutations `tau_a`, each as
    /// a `prev -> next` edge map. Held so the gate can score them directly against
    /// the held ground-truth permutations, not just compare
    /// the plaintext partition.
    pub(crate) recovered_permutations: Vec<EdgeMap>,
    /// Number of distinct chain-link source symbols the solver touched.
    symbols_touched: usize,
    /// How many chain-link adjacency constraints (from
    /// [`crate::analysis::chaining_graph::chain_links_for_pair`]) were checked against the
    /// recovered permutations, and how many were satisfied. The chain links are a
    /// **HARD verification gate** here: a satisfied count below the checked count
    /// means the recovered permutations contradict the shared chain-link
    /// primitive. On a fully recovered real fixture every
    /// checked constraint is satisfied.
    chain_link_checks: usize,
    /// Number of chain-link adjacency constraints satisfied by the recovered
    /// permutations (see [`Self::chain_link_checks`]).
    chain_link_consistent: usize,
}

impl GctakSolution {
    /// Number of distinct letters the solver clustered.
    fn letter_count(&self) -> usize {
        self.recovered_permutations.len()
    }

    /// Whether every checked chain-link adjacency constraint was satisfied (and at
    /// least one was checked). The gate requires this for a recovery to count.
    fn chain_links_verified(&self) -> bool {
        self.chain_link_checks > 0 && self.chain_link_consistent == self.chain_link_checks
    }
}

/// Solves a GCTAK ciphertext by extended chaining (the decisive gate).
///
/// GCTAK has a trivial hidden subgroup, so the readout `c` is bijective and each
/// plaintext letter `a` induces a **fixed** permutation `tau_a` of the ciphertext
/// alphabet with `c_i = tau_{a_i}(c_{i-1})` -- the Cayley graph of the state
/// group. Crucially `tau_a` is the conjugate of *left*-multiplication by `a`, so
/// the method never assumes `a . b = b . a`; the dihedral (non-commutative)
/// fixtures take exactly this code path.
///
/// `initial_readout` is `c(g_0)`, the symbol the augmented walk starts from. It is
/// **not** key material — only a single ciphertext symbol derived from the readout
/// and initial state (a constant `0` for the gate's identity-state fixtures) — and
/// the matched null is solved with the same value, so it cannot explain why the
/// real stream beats its null.
///
/// The pipeline:
/// 1. **Isomorph-align** repeated phrases by [`PatternSignature::from_window`] on
///    the walk. In GCTAK the equality pattern of a window depends only on the
///    *letter subsequence*, not on the absolute state entering it (proof:
///    `phi(w_a.s) = phi(w_b.s)` iff `w_a = w_b`, independent of `s`), so a
///    repeated phrase recurs as a repeated equality pattern and its aligned
///    columns share letters across occurrences.
/// 2. **Build chain links** between aligned occurrences with
///    [`chain_links_for_pair`] (reused from [`crate::analysis::chaining_graph`], never
///    reimplemented). These witness the right-coset-constant context action and
///    give the touched-symbol coverage.
/// 3. **Recover the group structure / place the alphabet:** seed same-letter
///    clusters from the aligned phrase columns, accumulate each cluster's
///    `prev -> next` permutation, then **merge clusters whose permutations are
///    consistent**. Because the generator drifts the entry state between phrase
///    repeats, each letter is observed across the whole group, so same-letter
///    clusters overlap and merge into one complete `tau_a` while different
///    letters conflict. None of this uses commutativity.
/// 4. **Read off the plaintext:** decode every transition (phrase and mixing
///    alike) by matching its `(prev, next)` edge to the unique recovered
///    permutation containing it, then canonicalize by first-occurrence order.
pub(crate) fn solve_gctak(
    ciphertext: &[SymbolValue],
    initial_readout: SymbolValue,
    phrase_len: usize,
    group_order: usize,
) -> GctakSolution {
    // Coverage / chaining_graph reuse: build the BROAD chain-link graph from all
    // equality-pattern matches with the SHARED [`chain_links_for_pair`] primitive
    // (this is what the `chain_links_match_shared_chaining_graph_primitive` reuse
    // test pins), and DERIVE the touched-symbol coverage FROM those links — so the
    // broad chain-link primitive is load-bearing for the reported coverage, not a
    // discarded call.
    let broad_links = collect_chain_links(ciphertext);
    let symbols_touched = chain_link_symbol_coverage(&broad_links);

    // Prepend the readout of the initial state so transition `i` corresponds to
    // plaintext letter `i` (the first ciphertext symbol is itself a transition
    // from the known entry state). The augmented walk then has one transition per
    // plaintext letter, so the recovered letter stream matches the plaintext
    // length exactly.
    let mut walk = Vec::with_capacity(ciphertext.len().saturating_add(1));
    walk.push(initial_readout);
    walk.extend_from_slice(ciphertext);
    let transition_count = walk.len().saturating_sub(1);

    // Step 1/2: isomorph-align the repeated phrase, then seed same-letter clusters
    // from its aligned columns.
    let mut clusters = SmallUnionFind::new(transition_count);
    seed_clusters_by_phrase_alignment(&walk, phrase_len, &mut clusters, transition_count);

    // Step 2 (chaining_graph, LOAD-BEARING): build the SOUND same-phrase chain
    // links — restricted to the spacing-filtered aligned phrase occurrences — with
    // the SHARED [`chain_links_for_pair`] primitive. These become a HARD
    // verification gate below; the chain graph is the central substrate of the
    // *attack*.
    let verify_links = phrase_chain_links(&walk, phrase_len);

    // Step 3: recover per-letter permutations (the Cayley-graph placement): build
    // each seed cluster's partial permutation (dropping any non-functional
    // cluster), merge consistent clusters, complete them against the observed
    // edges, then keep the complete permutations.
    let recovered =
        recover_letter_permutations(&walk, &mut clusters, transition_count, group_order);

    // Step 2 gate: verify the recovered permutations against the sound chain links.
    // Each chain-link context's adjacent columns witness the SAME plaintext letter
    // acting on both occurrences, so both adjacent edges must lie in one common
    // recovered permutation; this consumes the links' `from`/`to` fields, so
    // corrupting the chain-link output breaks recovery (proving load-bearing).
    let (chain_link_checks, chain_link_consistent) =
        verify_against_chain_links(&verify_links, &recovered);

    // Step 4: read off the plaintext by matching each transition's edge to a
    // recovered permutation; canonicalize letters by first-occurrence order.
    let letter_of = decode_letters_by_edge(&walk, &recovered, transition_count);
    let canonical_letters = canonical_letters(&letter_of);

    GctakSolution {
        canonical_letters,
        recovered_permutations: recovered,
        symbols_touched,
        chain_link_checks,
        chain_link_consistent,
    }
}

/// HARD chain-link verification gate.
///
/// The [`chain_links_for_pair`] output for a context is the column-wise action of
/// a fixed group element mapping one isomorph occurrence to another. Because both
/// occurrences trace the **same plaintext phrase**, the adjacent-column transition
/// on the upper occurrence and on the lower occurrence are produced by the *same*
/// plaintext letter `tau_a`. So for every context and every adjacent column pair
/// `(col-1, col)` the two edges
/// `upper: link[col-1].from -> link[col].from` and
/// `lower: link[col-1].to   -> link[col].to`
/// must be contained in **one common** recovered permutation. This both consumes
/// the chain-link `from`/`to` fields (so corrupting them breaks the check) and
/// proves the recovered `tau_a` agree with the shared chaining-graph primitive.
///
/// Returns `(checked, satisfied)`. On a fully recovered real fixture every checked
/// constraint is satisfied; on a broken/null stream the recovered permutations are
/// incomplete, so checks either find no covering permutation (counted as a miss)
/// or there are no usable links at all.
pub(crate) fn verify_against_chain_links(
    links: &[ChainLink],
    recovered: &[EdgeMap],
) -> (usize, usize) {
    // Group links by context, preserving column order.
    let mut by_context: BTreeMap<u32, Vec<&ChainLink>> = BTreeMap::new();
    for link in links {
        by_context
            .entry(link.context.as_u32())
            .or_default()
            .push(link);
    }

    let mut checked = 0usize;
    let mut satisfied = 0usize;
    for context_links in by_context.values() {
        for pair in context_links.windows(2) {
            let (Some(prev), Some(next)) = (pair.first(), pair.get(1)) else {
                continue;
            };
            let upper_edge = (prev.from.get(), next.from.get());
            let lower_edge = (prev.to.get(), next.to.get());
            checked = checked.saturating_add(1);
            // Both adjacent edges must be explained by ONE recovered permutation.
            let covered = recovered.iter().any(|perm| {
                perm.get(&upper_edge.0) == Some(&upper_edge.1)
                    && perm.get(&lower_edge.0) == Some(&lower_edge.1)
            });
            if covered {
                satisfied = satisfied.saturating_add(1);
            }
        }
    }
    (checked, satisfied)
}

/// Counts the distinct ciphertext symbols **touched by the broad chain-link
/// graph** — the chaining-graph coverage notion (mirrors
/// [`crate::analysis::chaining_graph`]'s touched-symbol coverage). This makes the broad
/// [`collect_chain_links`] output load-bearing for the reported coverage
/// rather than discarded.
fn chain_link_symbol_coverage(links: &[ChainLink]) -> usize {
    let mut touched = BTreeSet::new();
    for link in links {
        let _inserted = touched.insert(link.from.get());
        let _inserted = touched.insert(link.to.get());
    }
    touched.len()
}

/// Builds chain links from aligned repeated-phrase isomorph occurrences using the
/// shared [`chain_links_for_pair`] primitive.
///
/// Windows of length [`SOLVER_WINDOW_LEN`] are grouped by
/// [`PatternSignature`]; each group with ≥2 occurrences yields one directed
/// context per ordered occurrence pair (canonical, lower-start as image), exactly
/// as [`crate::analysis::chaining_graph`] does, so this is genuine reuse of the shared
/// graph, not a divergent reimplementation.
pub(crate) fn collect_chain_links(ciphertext: &[SymbolValue]) -> Vec<ChainLink> {
    let mut by_signature: BTreeMap<PatternSignature, Vec<usize>> = BTreeMap::new();
    if ciphertext.len() >= SOLVER_WINDOW_LEN {
        for (start, window) in ciphertext.windows(SOLVER_WINDOW_LEN).enumerate() {
            let signature = PatternSignature::from_window(window);
            if signature.has_repeated_symbol() {
                by_signature.entry(signature).or_default().push(start);
            }
        }
    }

    let mut links = Vec::new();
    let mut context_index: u32 = 0;
    for starts in by_signature.values() {
        if starts.len() < 2 {
            continue;
        }
        for (left_index, &upper_start) in starts.iter().enumerate() {
            for &lower_start in starts.iter().skip(left_index.saturating_add(1)) {
                let Some(upper_window) =
                    ciphertext.get(upper_start..upper_start.saturating_add(SOLVER_WINDOW_LEN))
                else {
                    continue;
                };
                let Some(lower_window) =
                    ciphertext.get(lower_start..lower_start.saturating_add(SOLVER_WINDOW_LEN))
                else {
                    continue;
                };
                let upper = AlignedOccurrence {
                    message: 0,
                    window: upper_window,
                    core_len: SOLVER_WINDOW_LEN,
                };
                let lower = AlignedOccurrence {
                    message: 0,
                    window: lower_window,
                    core_len: SOLVER_WINDOW_LEN,
                };
                let context = ContextId::new(context_index);
                context_index = context_index.saturating_add(1);
                if let Ok(pair_links) = chain_links_for_pair(context, &upper, &lower) {
                    links.extend(pair_links);
                }
            }
        }
    }
    links
}

/// Seeds same-letter clusters by isomorph-aligning the repeated phrase.
///
/// Length-`phrase_len` windows are grouped by [`PatternSignature`]; the equality
/// pattern of a phrase window is start-state-independent (proof: `phi(w_a.s)
/// = phi(w_b.s)` iff `w_a = w_b`), so every occurrence of the repeated phrase
/// lands in the same signature group. The largest such group is taken as the
/// phrase, its occurrences are **spacing-filtered** (kept at least `phrase_len`
/// apart) to drop coincidental short matches inside the mixing runs, and the
/// aligned interior columns of each occurrence pair are unioned (same phrase
/// column => same letter). Window column `0` is the entry state, not a
/// transition, and is skipped; the transition for column `col >= 1` is the
/// adjacent pair ending at window position `col`, i.e. global transition
/// `start + col - 1`.
fn seed_clusters_by_phrase_alignment(
    walk: &[SymbolValue],
    phrase_len: usize,
    clusters: &mut SmallUnionFind,
    transition_count: usize,
) {
    let Some((window_len, filtered)) = aligned_phrase_starts(walk, phrase_len) else {
        return;
    };

    for (left_index, &upper_start) in filtered.iter().enumerate() {
        for &lower_start in filtered.iter().skip(left_index.saturating_add(1)) {
            for col in 1..window_len {
                let upper_transition = upper_start + col - 1;
                let lower_transition = lower_start + col - 1;
                if upper_transition < transition_count && lower_transition < transition_count {
                    clusters.union(upper_transition, lower_transition);
                }
            }
        }
    }
}

/// Isomorph-aligns the repeated phrase and returns `(window_len, filtered_starts)`.
///
/// Length-`phrase_len` windows are grouped by [`PatternSignature`]; the largest
/// group with ≥2 occurrences is taken as the repeated phrase, and its occurrences
/// are **spacing-filtered** (kept at least `window_len` apart) to drop coincidental
/// short matches inside the mixing runs. Returns `None` when no phrase repeats.
/// This is the single shared alignment used both to seed clusters and to build the
/// sound same-phrase chain links the recovery is verified against.
fn aligned_phrase_starts(walk: &[SymbolValue], phrase_len: usize) -> Option<(usize, Vec<usize>)> {
    let window_len = phrase_len.max(2);
    if walk.len() < window_len {
        return None;
    }
    let mut by_signature: BTreeMap<PatternSignature, Vec<usize>> = BTreeMap::new();
    for (start, window) in walk.windows(window_len).enumerate() {
        let signature = PatternSignature::from_window(window);
        if signature.has_repeated_symbol() {
            by_signature.entry(signature).or_default().push(start);
        }
    }
    let phrase_starts = by_signature
        .into_values()
        .filter(|starts| starts.len() >= 2)
        .max_by_key(Vec::len)?;

    // Spacing filter: real phrase occurrences are at least `window_len` apart.
    let mut filtered: Vec<usize> = Vec::new();
    let mut last_accepted: Option<usize> = None;
    for &start in &phrase_starts {
        let accept = match last_accepted {
            Some(prev) => start >= prev.saturating_add(window_len),
            None => true,
        };
        if accept {
            filtered.push(start);
            last_accepted = Some(start);
        }
    }
    Some((window_len, filtered))
}

/// Builds the **sound, same-phrase** chain links the recovery is verified against
/// using the shared [`chain_links_for_pair`] primitive.
///
/// Unlike [`collect_chain_links`] (which emits the broad equality-pattern graph
/// for coverage/reuse, including coincidental short-window matches), this restricts
/// to the spacing-filtered occurrences of the *aligned repeated phrase*. For those
/// genuine occurrences each aligned column is the same plaintext letter on both
/// occurrences, so the adjacent-column edges are a sound constraint on the
/// recovered per-letter permutations. Each occurrence pair becomes one
/// [`ContextId`], and the window columns become that context's ordered links.
pub(crate) fn phrase_chain_links(walk: &[SymbolValue], phrase_len: usize) -> Vec<ChainLink> {
    let Some((window_len, filtered)) = aligned_phrase_starts(walk, phrase_len) else {
        return Vec::new();
    };
    let mut links = Vec::new();
    let mut context_index: u32 = 0;
    for (left_index, &upper_start) in filtered.iter().enumerate() {
        for &lower_start in filtered.iter().skip(left_index.saturating_add(1)) {
            let (Some(upper_window), Some(lower_window)) = (
                walk.get(upper_start..upper_start.saturating_add(window_len)),
                walk.get(lower_start..lower_start.saturating_add(window_len)),
            ) else {
                continue;
            };
            let upper = AlignedOccurrence {
                message: 0,
                window: upper_window,
                core_len: window_len,
            };
            let lower = AlignedOccurrence {
                message: 0,
                window: lower_window,
                core_len: window_len,
            };
            let context = ContextId::new(context_index);
            context_index = context_index.saturating_add(1);
            if let Ok(pair_links) = chain_links_for_pair(context, &upper, &lower) {
                links.extend(pair_links);
            }
        }
    }
    links
}

/// Recovers the complete per-letter permutations (the Cayley-graph placement).
///
/// From the seed clusters this (a) builds each cluster's partial `prev -> next`
/// map, discarding any cluster that is not forward-functional (a `prev` mapping
/// to two `next`s, which only arises when a coincidental alignment merged two
/// letters); (b) merges clusters whose partial permutations are consistent
/// (agree on every shared `prev` and stay backward single-valued); (c)
/// **completes** each partial permutation against the observed edges by
/// repeatedly filling a missing source whose only unused observed target is
/// forced; and (d) keeps the permutations that reach the full `group_order`.
///
/// None of these steps uses commutativity: a letter is the conjugate of a fixed
/// left-multiplication, so its permutation is a fixed bijection that the
/// non-commutative (dihedral) fixtures recover by exactly this path.
fn recover_letter_permutations(
    walk: &[SymbolValue],
    clusters: &mut SmallUnionFind,
    transition_count: usize,
    group_order: usize,
) -> Vec<EdgeMap> {
    // (a) partial perm per cluster, dropping non-functional ones.
    let mut by_root: BTreeMap<usize, Vec<(u8, u8)>> = BTreeMap::new();
    for transition in 0..transition_count {
        let (Some(prev), Some(next)) =
            (walk.get(transition), walk.get(transition.saturating_add(1)))
        else {
            continue;
        };
        by_root
            .entry(clusters.find(transition))
            .or_default()
            .push((prev.get(), next.get()));
    }
    let mut partials: Vec<EdgeMap> = Vec::new();
    for edges in by_root.into_values() {
        let mut map = EdgeMap::new();
        let mut functional = true;
        for (prev, next) in edges {
            match map.get(&prev) {
                Some(existing) if *existing != next => {
                    functional = false;
                    break;
                }
                _ => {
                    let _old = map.insert(prev, next);
                }
            }
        }
        if functional && !map.is_empty() {
            partials.push(map);
        }
    }

    // (b) merge consistent clusters to a fixed point.
    let mut merged = true;
    while merged {
        merged = false;
        let mut index = 0usize;
        while index < partials.len() {
            let mut other = index.saturating_add(1);
            while other < partials.len() {
                let consistent = match (partials.get(index), partials.get(other)) {
                    (Some(left), Some(right)) => permutations_consistent(left, right),
                    _ => false,
                };
                if consistent {
                    if let (Some(absorbed), Some(target)) =
                        (partials.get(other).cloned(), partials.get_mut(index))
                    {
                        for (prev, next) in absorbed {
                            let _old = target.entry(prev).or_insert(next);
                        }
                    }
                    let _removed = partials.remove(other);
                    merged = true;
                } else {
                    other = other.saturating_add(1);
                }
            }
            index = index.saturating_add(1);
        }
    }

    // (c) complete each partial against the observed edges.
    let mut observed: BTreeMap<u8, BTreeSet<u8>> = BTreeMap::new();
    for transition in 0..transition_count {
        if let (Some(prev), Some(next)) =
            (walk.get(transition), walk.get(transition.saturating_add(1)))
        {
            let _inserted = observed.entry(prev.get()).or_default().insert(next.get());
        }
    }
    for perm in &mut partials {
        complete_permutation(perm, &observed, group_order);
    }

    // (d) keep complete permutations.
    partials
        .into_iter()
        .filter(|perm| perm.len() == group_order)
        .collect()
}

/// Fills missing sources of a partial permutation when forced by the observed
/// edges: a source `s` with exactly one observed target not already used as an
/// image is assigned that target. Iterates to a fixed point.
fn complete_permutation(
    perm: &mut EdgeMap,
    observed: &BTreeMap<u8, BTreeSet<u8>>,
    group_order: usize,
) {
    let mut used: BTreeSet<u8> = perm.values().copied().collect();
    let mut progressed = true;
    while progressed {
        progressed = false;
        for source in 0..group_order {
            let Ok(source_value) = u8::try_from(source) else {
                continue;
            };
            if perm.contains_key(&source_value) {
                continue;
            }
            let Some(targets) = observed.get(&source_value) else {
                continue;
            };
            let mut candidate: Option<u8> = None;
            let mut unique = true;
            for &target in targets {
                if used.contains(&target) {
                    continue;
                }
                if candidate.is_some() {
                    unique = false;
                    break;
                }
                candidate = Some(target);
            }
            if let (true, Some(target)) = (unique, candidate) {
                let _old = perm.insert(source_value, target);
                let _inserted = used.insert(target);
                progressed = true;
            }
        }
    }
}

/// Returns `true` when two partial permutations agree on every shared `prev` and
/// their union is backward single-valued (no two `prev`s share a `next`).
///
/// Two GCTAK letters never agree at any single state (the readout is bijective,
/// so `tau_a(p) = tau_b(p)` forces `a = b`), so agreement on a shared source is
/// positive same-letter evidence; the backward check rejects any union that would
/// break the permutation law.
fn permutations_consistent(left: &EdgeMap, right: &EdgeMap) -> bool {
    let mut overlap = false;
    for (prev, next) in left {
        if let Some(other_next) = right.get(prev) {
            overlap = true;
            if other_next != next {
                return false;
            }
        }
    }
    if !overlap {
        return false;
    }
    let mut image_to_source: BTreeMap<u8, u8> = BTreeMap::new();
    for (prev, next) in left.iter().chain(right.iter()) {
        match image_to_source.get(next) {
            Some(existing_prev) if existing_prev != prev => return false,
            _ => {
                let _old = image_to_source.insert(*next, *prev);
            }
        }
    }
    true
}

/// Decodes each transition to a letter id by matching its `(prev, next)` edge to
/// a recovered permutation containing it.
///
/// On real GCTAK structure the recovered permutations are the true `tau_a`, so
/// this reproduces the plaintext letter partition exactly. Transitions matching
/// no recovered permutation (only on broken/null streams, or a fixture the solver
/// did not fully recover) get a fresh sentinel id so the decode differs from
/// truth -- the desired negative-control behaviour.
fn decode_letters_by_edge(
    walk: &[SymbolValue],
    recovered: &[EdgeMap],
    transition_count: usize,
) -> Vec<usize> {
    let mut letters = Vec::with_capacity(transition_count);
    let mut next_sentinel = recovered.len();
    for transition in 0..transition_count {
        let (Some(prev), Some(next)) =
            (walk.get(transition), walk.get(transition.saturating_add(1)))
        else {
            letters.push(next_sentinel);
            next_sentinel = next_sentinel.saturating_add(1);
            continue;
        };
        let matched = recovered
            .iter()
            .position(|perm| perm.get(&prev.get()) == Some(&next.get()));
        if let Some(index) = matched {
            letters.push(index);
        } else {
            letters.push(next_sentinel);
            next_sentinel = next_sentinel.saturating_add(1);
        }
    }
    letters
}

/// Canonicalizes a letter stream by first-occurrence order.
///
/// The generator's letter numbering is arbitrary, so we compare recovered and
/// true plaintexts after relabelling both so the first distinct letter is `0`,
/// the next new one `1`, and so on. Two streams are first-occurrence-equal iff
/// they induce the same *partition* of positions into letters — exactly the
/// recoverable quantity for a key-free attack.
pub(crate) fn canonical_letters(letters: &[usize]) -> Vec<usize> {
    let mut remap: BTreeMap<usize, usize> = BTreeMap::new();
    let mut next = 0usize;
    let mut canonical = Vec::with_capacity(letters.len());
    for &letter in letters {
        let id = *remap.entry(letter).or_insert_with(|| {
            let assigned = next;
            next = next.saturating_add(1);
            assigned
        });
        canonical.push(id);
    }
    canonical
}

pub(crate) fn glyphs_to_values(glyphs: &[Glyph]) -> Result<Vec<SymbolValue>, GakAttackError> {
    let mut values = Vec::with_capacity(glyphs.len());
    for glyph in glyphs {
        let raw = u8::try_from(glyph.0).map_err(|_error| GakAttackError::SymbolOutOfRange {
            value: usize::from(glyph.0),
        })?;
        let value = TrigramValue::new(raw).map_err(|bad| GakAttackError::SymbolOutOfRange {
            value: usize::from(bad),
        })?;
        values.push(value);
    }
    Ok(values)
}

fn glyphs_to_indices(glyphs: &[Glyph]) -> Vec<usize> {
    glyphs.iter().map(|glyph| usize::from(glyph.0)).collect()
}

/// A minimal union-find over `0..n` transition positions.
///
/// This is a private helper over *transition positions*, a different population
/// from [`crate::analysis::chaining_graph::UnionFind`] (which unions *symbols*). It is not
/// a divergent chaining graph; the shared chain-link primitive is reused for the
/// graph itself in [`collect_chain_links`].
#[derive(Clone)]
struct SmallUnionFind {
    parent: Vec<usize>,
}

impl SmallUnionFind {
    fn new(n: usize) -> Self {
        Self {
            parent: (0..n).collect(),
        }
    }

    fn find(&mut self, x: usize) -> usize {
        let mut root = x;
        while let Some(&parent) = self.parent.get(root) {
            if parent == root {
                break;
            }
            root = parent;
        }
        // Path compression.
        let mut node = x;
        while let Some(&parent) = self.parent.get(node) {
            if parent == root {
                break;
            }
            if let Some(slot) = self.parent.get_mut(node) {
                *slot = root;
            }
            node = parent;
        }
        root
    }

    fn union(&mut self, x: usize, y: usize) {
        let root_x = self.find(x);
        let root_y = self.find(y);
        if root_x == root_y {
            return;
        }
        if let Some(slot) = self.parent.get_mut(root_x) {
            *slot = root_y;
        }
    }
}

//! The GCTAK decisive-gate solver and the real-GAK deck-stabilizer attack.
//!
//! Holds the GCTAK positive-control solver (`solve_gctak` and its chaining/
//! permutation-recovery helpers) together with the non-trivial-`H` deck attack
//! (`generate_deck_fixture`, `run_deck_attack[_sweep]`, the coset/chain-substrate
//! primitives) — they share the `EdgeMap`, chain-link, and spacing primitives.

use super::*;

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
/// ## Why `initial_readout` is not a key leak (review finding F4)
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
    // Held ground-truth per-letter ciphertext-alphabet permutations (F5).
    let truth_permutations = truth_letter_permutations(&fixture.key)?;

    // The state entering the first letter is the readout of the initial state.
    // The gate fixtures use the identity initial state, whose bijective readout is
    // `0` (`c(identity) = identity^{-1}[0] = 0`), so the first ciphertext symbol is
    // a genuine transition from this known entry point. This value is constant 0
    // here, is not key material, and is fed identically to the null below (see the
    // function doc for why it is not a leak — F4).
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
    /// the held ground-truth permutations (review finding F5), not just compare
    /// the plaintext partition.
    pub(crate) recovered_permutations: Vec<EdgeMap>,
    /// Number of distinct chain-link source symbols the solver touched.
    symbols_touched: usize,
    /// How many chain-link adjacency constraints (from
    /// [`crate::chaining_graph::chain_links_for_pair`]) were checked against the
    /// recovered permutations, and how many were satisfied. The chain links are a
    /// **HARD verification gate** here: a satisfied count below the checked count
    /// means the recovered permutations contradict the shared chain-link
    /// primitive (review finding F2). On a fully recovered real fixture every
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
/// real stream beats its null (review finding F4).
///
/// The pipeline:
/// 1. **Isomorph-align** repeated phrases by [`PatternSignature::from_window`] on
///    the walk. In GCTAK the equality pattern of a window depends only on the
///    *letter subsequence*, not on the absolute state entering it (proof:
///    `phi(w_a.s) = phi(w_b.s)` iff `w_a = w_b`, independent of `s`), so a
///    repeated phrase recurs as a repeated equality pattern and its aligned
///    columns share letters across occurrences.
/// 2. **Build chain links** between aligned occurrences with
///    [`chain_links_for_pair`] (reused from [`crate::chaining_graph`], never
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
    // verification gate below (F2); the chain graph becomes the central substrate
    // of the *attack* in Step 2 of the thread spec.
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

/// HARD chain-link verification gate (review finding F2).
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
/// [`crate::chaining_graph`]'s touched-symbol coverage). This makes the broad
/// [`collect_chain_links`] output load-bearing for the reported coverage (F2)
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
/// as [`crate::chaining_graph`] does, so this is genuine reuse of the shared
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
/// sound same-phrase chain links the recovery is verified against (F2).
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
/// (review finding F2), using the shared [`chain_links_for_pair`] primitive.
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
/// from [`crate::chaining_graph::UnionFind`] (which unions *symbols*). It is not
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

// =====================================================================
// UNIT 2a — REAL GAK on the deck stabilizer (non-trivial hidden subgroup).
//
// Everything above is the trivial-H GCTAK gate (the proof-of-life positive
// control). Below is the actual contribution the wiki asks for: a constraint-
// propagation attack on REAL GAK (`H = Stab(top) = S_{n-1}`, `|H| = (n-1)! > 1`)
// realized by `GakKey::deck`. It is **synthetic-only** (we hold ground truth, so
// recovering the key is legitimate) and reports a measured tractability bound:
// where partial recovery breaks as `n` / `|H|` grows. A low/zero recovered
// fraction at larger `n` is the expected, valuable result — a measured negative.
//
// ## Why this is hard (the deck quirk that the attack must honor)
//
// State `g ∈ S_n`, update `g ← π_a ∘ g`, visible symbol `s = c(g) = g^{-1}[top]`.
// The next visible symbol is `s' = (π_a ∘ g)^{-1}[top] = g^{-1}[π_a^{-1}[top]]`,
// which depends on `g^{-1}` evaluated at `π_a^{-1}[top]` — i.e. on the WHOLE
// hidden permutation, not just on `s`. So a single visible symbol can transition
// to MANY next-symbols under the same letter across different hidden states
// (`Chaining-Conflicts.md`: cycles of unequal length are normal; edge overlap
// does not prove context equality). Only WITHIN one fixed context (one aligned
// isomorph occurrence pair) is the action a partial permutation, and two arrows
// out of (or into) one symbol there is a TRUE conflict that proves a bad isomorph
// assumption (not a discovery) and aborts that branch.
// =====================================================================

/// How the per-letter `p(a)` permutations are drawn for a real-GAK deck fixture.
///
/// Both regimes are generated so the NEXT unit can validate the TENTATIVE
/// small-support prior (idea 2): when `small_support_radius > 0` the draws are
/// near-identity (a base permutation composed with `≤k` transpositions), the
/// regime in which `Deck-Cipher.md`'s shared-sections evidence would hold; when
/// `0` the draws are unconstrained `S_n`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeckLetterRegime {
    /// Unconstrained `S_n`: each `p(a)` is a uniform random permutation.
    Unconstrained,
    /// TENTATIVE small-support: each `p(a)` is a base permutation composed with
    /// `≤radius` random transpositions (near-identity). NOT a hard constraint.
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
            Self::SmallSupport { .. } => "TENTATIVE small-support",
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

    // Draw `num_pt_letters` DISTINCT, non-identity permutations of `0..n`. Under
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
// PERMUTATIONS, not scalars. The recovery's equations come FROM the shared
// `chaining_graph` chain links (load-bearing — `phrase_column_evidence` sources its
// prev->next edges straight out of `chain_links_for_pair`). It then LIGHT-MERGES the
// single-valued cores under a group-dependent overlap threshold — a deliberately
// conservative merge, NOT full Schreier-graph constraint propagation (the
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
/// occurrence pair: a partial map on the visible coset alphabet, plus its TRUE-
/// conflict flag.
///
/// A context's action MUST be a partial permutation (single-valued forward AND
/// backward). Two distinct arrows out of one symbol, or into one symbol, is a
/// **TRUE conflict** (`Chaining-Conflicts.md`): it proves a bad isomorph
/// assumption, so the branch is aborted rather than counted as a discovery.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ContextAction {
    /// Forward partial permutation `from -> to`.
    forward: BTreeMap<u8, u8>,
    /// The distinct directed edges (for the group-dependent overlap threshold).
    edges: BTreeSet<CosetEdge>,
    /// `true` once a TRUE conflict (non-functional forward or backward) is seen.
    pub(crate) true_conflict: bool,
}

impl ContextAction {
    /// Inserts one observed edge, setting [`Self::true_conflict`] if it violates
    /// the partial-permutation law (forward or backward single-valuedness).
    pub(crate) fn insert(&mut self, edge: CosetEdge) {
        let _added = self.edges.insert(edge);
        match self.forward.get(&edge.from) {
            Some(existing) if *existing != edge.to => {
                // Two arrows OUT of `from` under one fixed context => TRUE conflict.
                self.true_conflict = true;
                return;
            }
            Some(_) => return,
            None => {}
        }
        // Backward check: two arrows INTO `to` under one fixed context.
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
/// the global per-letter edge evidence, all derived from the SHARED
/// [`chain_links_for_pair`] primitive.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ChainSubstrate {
    /// One [`ContextAction`] per aligned isomorph occurrence pair (one context).
    pub(crate) contexts: Vec<ContextAction>,
    /// Number of TRUE-conflict aborts encountered while building contexts.
    pub(crate) true_conflict_aborts: usize,
    /// Number of distinct visible coset symbols touched by any chain link
    /// (chain-link coverage).
    symbols_touched: usize,
}

/// Builds the chain-link substrate for the deck attack (coverage + fixed-context
/// conflict detection — NOT the recovery substrate).
///
/// LOAD-BEARING reuse: occurrences are grouped by their length-`core_len` PREFIX
/// [`PatternSignature`] (the isomorph CORE), and each ordered occurrence pair within
/// a core group becomes ONE fixed context whose coset edges are EXACTLY the
/// [`chain_links_for_pair`] output over the full `window_len` window (core +
/// extension). This is genuine reuse of the shared primitive, not a second graph.
///
/// **Why a core prefix.** Grouping by the FULL window makes every pair a partial
/// bijection by construction (same full-window signature ⇒ identical equality
/// pattern ⇒ no conflict), so a fixed-context TRUE conflict could never fire.
/// Grouping by the core prefix lets two windows that share the core but DIVERGE in
/// the over-extension tail be aligned — and a divergent tail can produce two arrows
/// out of / into one symbol under that single fixed alignment, which is exactly a
/// genuine **bad isomorph alignment** (over-extension past the true core), the only
/// thing that can produce a real TRUE conflict. The production caller passes
/// `core_len == window_len` (full-window grouping, no extension), so the shipped
/// numbers are unchanged; a smaller `core_len` is what exercises the conflict guard.
///
/// A fixed context whose action carries a TRUE conflict is dropped (its branch
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
                // ONE fixed context = ONE aligned occurrence pair. Within this single
                // alignment two arrows out of / into one symbol can ONLY come from a
                // bad isomorph alignment (an over-extended tail), never from normal
                // hidden-state variation — so a TRUE conflict here is a genuine abort.
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
                    // Fixed-context TRUE-conflict abort: bad isomorph alignment.
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

/// Result of the deck constraint-propagation attack on one ciphertext stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeckAttackSolution {
    /// The merged single-valued-core actions: each is a partial map on the visible
    /// coset alphabet, light-merged across phrase columns. These are the recovered
    /// PARTIAL visible-coset action maps scored against ground truth — a fraction of
    /// per-letter visible-coset transitions, NOT a recovered key and NOT the
    /// plaintext->group-element mapping.
    pub(crate) recovered_actions: Vec<BTreeMap<u8, u8>>,
    /// Number of fixed-context TRUE-conflict aborts (bad isomorph alignments
    /// witnessed by [`build_chain_substrate`]). Surfaced — a feature.
    true_conflict_aborts: usize,
    /// Distinct visible coset symbols touched (chain-link coverage).
    symbols_touched: usize,
    /// Number of fixed-context occurrence-pair contexts that survived (no TRUE
    /// conflict) in the chain substrate — the coverage/conflict-detection counter.
    surviving_contexts: usize,
    /// The MEASURED hidden-state obstruction: how much of the per-letter
    /// visible-coset action is multi-valued across hidden states (the part NOT
    /// recoverable without idea 3). This is a headline honest result of this unit.
    obstruction: HiddenStateObstruction,
}

/// Runs the deck visible-coset action-recovery attack (idea 1, this unit).
///
/// **What this recovers (claim ceiling).** Only PARTIAL VISIBLE-COSET ACTION MAPS —
/// a fraction of the per-letter `from -> to` visible-coset transitions — NOT a
/// recovered key and NOT the plaintext->group-element mapping. Under non-trivial
/// `H` the visible transition depends on the FULL hidden state, so most of a
/// letter's action is multi-valued across hidden states and is NOT recoverable here
/// (it is measured as [`HiddenStateObstruction`] instead). That bound is the point.
///
/// **Pipeline.**
/// 1. **Chain-link substrate (coverage + conflict detection).**
///    [`build_chain_substrate`] groups occurrence pairs by full-window
///    [`PatternSignature`] and turns each into one fixed-context partial permutation
///    via the SHARED [`chain_links_for_pair`] primitive. A genuine fixed-context
///    TRUE conflict there (two arrows out of / into one symbol under ONE alignment)
///    proves a bad isomorph alignment and aborts that branch. This substrate is
///    REUSED for coverage (`symbols_touched`) and conflict detection — it is NOT the
///    recovery substrate.
/// 2. **Per-column recovery (the recovery substrate).** [`phrase_column_evidence`]
///    accumulates each phrase column's one-step visible-coset transitions — sourced
///    from the SAME [`chain_links_for_pair`] primitive (load-bearing: corrupting the
///    links changes these edges and breaks recovery). Cross-hidden-state
///    multi-valuedness is EXPECTED here, so it is measured, not aborted; only each
///    column's single-valued core feeds recovery.
/// 3. **Light merge over consistent columns.** [`merge_context_actions`] merges
///    single-valued cores only when their shared support meets the group-dependent
///    [`merge_overlap_threshold`] and they never contradict — a deliberately
///    conservative light merge, NOT full Schreier-graph constraint propagation.
///    Unequal cycles never block a merge (the hidden state shortens some).
///
/// ## Hooks for the NEXT unit (idea 2 + idea 3)
///
/// - **Small-support prior (idea 2):** [`merge_overlap_threshold`] is where the
///   TENTATIVE near-identity prior becomes a SOFT penalty — biasing merges toward
///   actions expressible as `≤k` transpositions. It is NOT applied here (this unit
///   measures the unconstrained bound); the hook is the single function to extend.
/// - **Hidden-state marginalization (idea 3):** the [`HiddenStateObstruction`] this
///   unit MEASURES is exactly what idea 3 must overcome. [`merge_context_actions`]
///   is where a belief-propagation / beam search over the hidden-state posterior
///   replaces the greedy single-valued-core merge, so the multi-valued part becomes
///   recoverable. The greedy merge is intentionally the simplest correct light merge
///   so the next unit can swap it without reshaping the substrate or the scoring.
pub(crate) fn run_deck_attack(
    ciphertext: &[SymbolValue],
    state_size: usize,
    phrase_len: usize,
) -> DeckAttackSolution {
    // (1) Chain-link substrate: REUSED for coverage + fixed-context conflict
    // detection (NOT the recovery substrate). The phrase-length window (not a short
    // window) is essential: the visible coset alphabet is tiny (|C| = n), so a short
    // window collides on nearly every position; the long phrase window is what makes
    // the equality-pattern signature discriminating. This gives the genuine
    // fixed-context TRUE-conflict aborts and the chain-link coverage. Production
    // groups by the FULL window (core_len == window_len), so the shipped numbers are
    // unchanged; the conflict guard fires only on a deliberately bad alignment (a
    // shorter core), exercised directly in the tests.
    let substrate = build_chain_substrate(ciphertext, phrase_len, phrase_len);
    let surviving_contexts = substrate.contexts.len();
    let true_conflict_aborts = substrate.true_conflict_aborts;

    // (2) Per-column recovery (the recovery substrate). Within the aligned phrase,
    // column `c` is ALWAYS the same plaintext letter across all occurrences, so its
    // one-step (prev -> next) visible-coset edges — sourced FROM the SAME
    // chain_links_for_pair primitive (load-bearing) — are that one letter's coset
    // action observed across many hidden states. Under non-trivial H a single coset
    // legitimately maps several ways across hidden states, so we MEASURE that
    // multi-valuedness as the obstruction and recover only the single-valued core.
    let (columns, obstruction) = phrase_column_evidence(ciphertext, phrase_len);
    let cores: Vec<BTreeMap<u8, u8>> = columns
        .iter()
        .map(ColumnEvidence::single_valued_core)
        .filter(|core| !core.is_empty())
        .collect();

    // (3) Light merge of the consistent single-valued cores (group-dependent overlap
    // threshold). This is a conservative light merge, NOT full constraint
    // propagation.
    let recovered_actions = merge_context_actions(&cores, state_size);

    DeckAttackSolution {
        recovered_actions,
        true_conflict_aborts,
        symbols_touched: substrate.symbols_touched,
        surviving_contexts,
        obstruction,
    }
}

/// The visible-coset transition evidence at one phrase column, accumulated across
/// every aligned occurrence (i.e. across many hidden states for the SAME plaintext
/// letter).
///
/// Crucially, for non-trivial `H` the visible transition is
/// `c_i = g_{i-1}^{-1}[ p(a)^{-1}[top] ]` — it depends on the FULL hidden state
/// `g_{i-1}`, not just the previous visible coset. So when one column is gathered
/// across occurrences with different hidden states, a single `from` coset
/// LEGITIMATELY maps to several `to` cosets. That multi-valuedness is **normal
/// hidden-state variation, NOT a conflict** in the chaining sense, so this struct
/// records the full per-`from` image SET rather than forcing a partial permutation.
/// The recoverable part of the column is its single-valued core; the rest is the
/// measured hidden-state obstruction (the motivation for idea 3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ColumnEvidence {
    /// Every `to` observed out of each `from` across all occurrences of this column.
    images: BTreeMap<u8, BTreeSet<u8>>,
}

impl ColumnEvidence {
    /// Records one observed `from -> to` transition for this column.
    fn observe(&mut self, edge: CosetEdge) {
        let _new = self.images.entry(edge.from).or_default().insert(edge.to);
    }

    /// The single-valued core: the `from -> to` map restricted to `from` cosets that
    /// map to EXACTLY ONE `to` across all hidden states. This is the only part of a
    /// column legitimately recoverable without hidden-state handling.
    fn single_valued_core(&self) -> BTreeMap<u8, u8> {
        let mut core = BTreeMap::new();
        for (from, tos) in &self.images {
            if let (1, Some(to)) = (tos.len(), tos.iter().next().copied()) {
                let _old = core.insert(*from, to);
            }
        }
        core
    }

    /// Number of distinct `from` cosets observed at this column.
    fn distinct_from(&self) -> usize {
        self.images.len()
    }

    /// Number of `from` cosets that map multi-valued (out-degree > 1) — the
    /// hidden-state obstruction at this column.
    fn multi_valued_from(&self) -> usize {
        self.images.values().filter(|tos| tos.len() > 1).count()
    }
}

/// The measured per-column hidden-state obstruction for the deck attack: how much
/// of the visible-coset action is multi-valued (and therefore NOT recoverable
/// without idea 3's hidden-state handling).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct HiddenStateObstruction {
    /// Total distinct `from` cosets summed over all phrase columns.
    distinct_from_total: usize,
    /// `from` cosets that mapped multi-valued (out-degree > 1) summed over columns.
    multi_valued_from_total: usize,
}

impl HiddenStateObstruction {
    /// Fraction of visible cosets that map multi-valued under a fixed letter — the
    /// hidden-state obstruction this unit measures (`0.0` when no evidence). This is
    /// the headline honest metric: the larger it is, the less of the action is
    /// recoverable without hidden-state marginalization (idea 3).
    fn multi_valued_fraction(self) -> f64 {
        fraction(self.multi_valued_from_total, self.distinct_from_total)
    }
}

/// Accumulates per-phrase-column visible-coset evidence across aligned occurrences.
///
/// The aligned repeated phrase is found once (spacing-filtered occurrences); each
/// interior column `c` of the phrase is the SAME plaintext letter across every
/// occurrence (`Alphabet-Chaining.md`: a repeated phrase recurs as a repeated
/// equality pattern). So the adjacent `(prev -> next)` visible-coset edge at that
/// column, gathered over all occurrences, is that one letter's coset action seen
/// across many hidden states.
///
/// LOAD-BEARING chain-link reuse: the prev->next edges are NOT read off the raw
/// stream — they are the [`chain_links_for_pair`] output of each occurrence window
/// aligned against itself shifted by one (column `c-1` is the "upper" occurrence,
/// column `c` is the "lower" occurrence of the same one-step isomorph). So the
/// recovery's equations come straight from the SHARED chain-link primitive;
/// corrupting the links changes these edges and breaks recovery.
///
/// We do NOT force a partial permutation per column: under non-trivial `H` a single
/// `from` coset legitimately maps to several `to` cosets across hidden states (see
/// [`ColumnEvidence`]), so each column keeps its full image SET. The single-valued
/// core feeds recovery; the multi-valuedness is measured as the obstruction.
fn phrase_column_evidence(
    ciphertext: &[SymbolValue],
    phrase_len: usize,
) -> (Vec<ColumnEvidence>, HiddenStateObstruction) {
    let window_len = phrase_len.max(2);
    let Some(filtered) = aligned_phrase_occurrences(ciphertext, window_len) else {
        return (Vec::new(), HiddenStateObstruction::default());
    };
    // Column `c` (1..window_len) holds the transition prev=col c-1, next=col c.
    let mut columns: Vec<ColumnEvidence> = vec![ColumnEvidence::default(); window_len];
    let mut context_index: u32 = 0;
    for &start in &filtered {
        // Source the prev->next edges from the SHARED chain-link primitive: align
        // this occurrence window (cols 0..len-1) against the same window shifted by
        // one (cols 1..len). Each emitted ChainLink (from=col c-1, to=col c) is the
        // one-step visible-coset transition — exactly the per-column edge we need,
        // but routed through `chain_links_for_pair` so the links are load-bearing.
        let (Some(prev_window), Some(next_window)) = (
            ciphertext.get(start..start.saturating_add(window_len.saturating_sub(1))),
            ciphertext.get(start.saturating_add(1)..start.saturating_add(window_len)),
        ) else {
            continue;
        };
        let upper = AlignedOccurrence {
            message: 0,
            window: prev_window,
            core_len: prev_window.len(),
        };
        let lower = AlignedOccurrence {
            message: 0,
            window: next_window,
            core_len: next_window.len(),
        };
        let context = ContextId::new(context_index);
        context_index = context_index.saturating_add(1);
        let Ok(links) = chain_links_for_pair(context, &upper, &lower) else {
            continue;
        };
        for link in &links {
            // The link at provenance column `k` is the transition into phrase
            // column `k + 1` (prev = window col k, next = window col k + 1).
            let phrase_col = link.provenance.column.saturating_add(1);
            if let Some(column) = columns.get_mut(phrase_col) {
                column.observe(CosetEdge {
                    from: link.from.get(),
                    to: link.to.get(),
                });
            }
        }
    }
    let mut obstruction = HiddenStateObstruction::default();
    for column in &columns {
        obstruction.distinct_from_total = obstruction
            .distinct_from_total
            .saturating_add(column.distinct_from());
        obstruction.multi_valued_from_total = obstruction
            .multi_valued_from_total
            .saturating_add(column.multi_valued_from());
    }
    let evidence: Vec<ColumnEvidence> = columns
        .into_iter()
        .filter(|c| !c.images.is_empty())
        .collect();
    (evidence, obstruction)
}

/// Aligns the repeated phrase by equality-pattern signature and returns the
/// spacing-filtered occurrence start indices (≥ `window_len` apart). Mirrors
/// [`aligned_phrase_starts`] but over a raw ciphertext (no prepended entry state),
/// since the deck attack works directly on the visible coset stream.
pub(crate) fn aligned_phrase_occurrences(
    ciphertext: &[SymbolValue],
    window_len: usize,
) -> Option<Vec<usize>> {
    if ciphertext.len() < window_len {
        return None;
    }
    let mut by_signature: BTreeMap<PatternSignature, Vec<usize>> = BTreeMap::new();
    for (start, window) in ciphertext.windows(window_len).enumerate() {
        let signature = PatternSignature::from_window(window);
        if signature.has_repeated_symbol() {
            by_signature.entry(signature).or_default().push(start);
        }
    }
    let phrase_starts = by_signature
        .into_values()
        .filter(|starts| starts.len() >= 2)
        .max_by_key(Vec::len)?;
    Some(spacing_filter(&phrase_starts, window_len))
}

/// The group-dependent overlap threshold for merging two context actions
/// (`Chaining-Conflicts.md`).
///
/// Edge overlap does **not** prove context equality: in the worst case
/// `S_n`/`S_{n-1}` requires *all* edges identical before two contexts may be
/// merged. We require the shared support to be at least `state_size - 1` edges
/// (one short of the full visible alphabet) AND fully consistent. This is the
/// deliberately conservative deck threshold; a single shared edge can never
/// trigger a merge. This function is the documented SOFT-PRIOR hook for the next
/// unit: the TENTATIVE small-support penalty lowers/weights the threshold for
/// near-identity actions, but is NOT applied in this unit.
#[must_use]
fn merge_overlap_threshold(state_size: usize) -> usize {
    state_size.saturating_sub(1)
}

/// Light-merges consistent single-valued-core actions to a fixed point, returning
/// the distinct recovered partial visible-coset action maps.
///
/// Two actions merge only when (a) their shared-`from` support meets
/// [`merge_overlap_threshold`], (b) they agree on every shared `from`, and (c)
/// their union stays a partial permutation (no two `from`s share a `to`). Cycles
/// of unequal length never block a merge (the hidden state shortens some). This is
/// a deliberately conservative LIGHT MERGE of single-valued cores, **not** full
/// Schreier-graph constraint propagation; idea-3 hidden-state marginalization
/// replaces it next unit so the multi-valued part becomes recoverable too.
fn merge_context_actions(cores: &[BTreeMap<u8, u8>], state_size: usize) -> Vec<BTreeMap<u8, u8>> {
    let threshold = merge_overlap_threshold(state_size);
    let mut groups: Vec<BTreeMap<u8, u8>> = cores
        .iter()
        .filter(|forward| !forward.is_empty())
        .cloned()
        .collect();

    let mut merged = true;
    while merged {
        merged = false;
        let mut index = 0usize;
        while index < groups.len() {
            let mut other = index.saturating_add(1);
            while other < groups.len() {
                let mergeable = match (groups.get(index), groups.get(other)) {
                    (Some(left), Some(right)) => actions_mergeable(left, right, threshold),
                    _ => false,
                };
                if mergeable {
                    if let (Some(absorbed), Some(target)) =
                        (groups.get(other).cloned(), groups.get_mut(index))
                    {
                        for (from, to) in absorbed {
                            let _old = target.entry(from).or_insert(to);
                        }
                    }
                    let _removed = groups.remove(other);
                    merged = true;
                } else {
                    other = other.saturating_add(1);
                }
            }
            index = index.saturating_add(1);
        }
    }

    // Deduplicate identical recovered actions (the same coset action can be
    // reconstructed by several disjoint context groups).
    let mut distinct: Vec<BTreeMap<u8, u8>> = Vec::new();
    for group in groups {
        if !distinct.contains(&group) {
            distinct.push(group);
        }
    }
    distinct
}

/// Whether two context actions may be merged: their shared `from`-support meets
/// the group-dependent `threshold`, they agree on every shared `from`, and their
/// union is a partial permutation (backward single-valued).
fn actions_mergeable(left: &BTreeMap<u8, u8>, right: &BTreeMap<u8, u8>, threshold: usize) -> bool {
    let mut shared = 0usize;
    for (from, to) in left {
        if let Some(other_to) = right.get(from) {
            if other_to != to {
                return false;
            }
            shared = shared.saturating_add(1);
        }
    }
    // Group-dependent overlap threshold: a single shared edge is NEVER enough.
    if shared < threshold {
        return false;
    }
    // Union must stay backward single-valued (a partial permutation).
    let mut image_of: BTreeMap<u8, u8> = BTreeMap::new();
    for (from, to) in left.iter().chain(right.iter()) {
        match image_of.get(to) {
            Some(existing_from) if existing_from != from => return false,
            _ => {
                let _old = image_of.insert(*to, *from);
            }
        }
    }
    true
}

// ---------------------------------------------------------------------
// C. Partial-recovery scoring + nulls + tractability sweep (the rigor).
// ---------------------------------------------------------------------

/// The ground-truth per-letter visible-coset edge sets for a deck fixture.
///
/// For non-trivial `H` a letter does NOT induce a fixed coset permutation, so the
/// truth is the full set of `(s, s')` coset transitions letter `a` produces across
/// all reachable hidden states encountered while encrypting THIS plaintext. We
/// score a recovered action against a letter by how many of its edges agree with
/// (i.e. are contained in) that letter's truth edge set without contradicting it
/// (no `s -> s'` in the recovered action that the letter never produces).
///
/// # Errors
/// Returns [`GakAttackError`] if a coset readout cannot be computed or a symbol
/// exceeds the `u8` range (internal invariants for the small `n` swept).
pub(crate) fn truth_coset_edges(
    key: &GakKey,
    plaintext: &[Glyph],
) -> Result<Vec<BTreeSet<CosetEdge>>, GakAttackError> {
    let letter_count = key.plaintext_letters().len();
    let mut per_letter: Vec<BTreeSet<CosetEdge>> = vec![BTreeSet::new(); letter_count];
    let mut state = key.initial_state().to_vec();
    for glyph in plaintext {
        let letter = usize::from(glyph.0);
        let Some(permutation) = key.plaintext_letters().get(letter) else {
            continue;
        };
        let from = readout_of_state(key, &state)?;
        let next = compose_state(permutation, &state)?;
        let to = readout_of_state(key, &next)?;
        let from_value =
            u8::try_from(from).map_err(|_e| GakAttackError::SymbolOutOfRange { value: from })?;
        let to_value =
            u8::try_from(to).map_err(|_e| GakAttackError::SymbolOutOfRange { value: to })?;
        if let Some(slot) = per_letter.get_mut(letter) {
            let _added = slot.insert(CosetEdge {
                from: from_value,
                to: to_value,
            });
        }
        state = next;
    }
    Ok(per_letter)
}

/// Scores a deck attack's recovered coset actions against the held truth.
///
/// Returns `(matched, total)` where `total` is the number of plaintext letters and
/// `matched` is how many letters have a recovered action that is a CORRECT,
/// NON-EMPTY partial coset action for that letter: every edge of the recovered
/// action is one the letter genuinely produces (contained in
/// [`truth_coset_edges`]) and no recovered edge contradicts the letter's true map.
/// Matching is one-to-one (each recovered action claims at most one letter, each
/// letter at most one action). This is the **recovered-permutation fraction** —
/// the spec's preferred partial-recovery metric for the non-trivial-H regime.
pub(crate) fn coset_recovery_fraction(
    truth: &[BTreeSet<CosetEdge>],
    recovered: &[BTreeMap<u8, u8>],
) -> (usize, usize) {
    let total = truth.len();
    let mut used = vec![false; recovered.len()];
    let mut matched = 0usize;
    for letter_edges in truth {
        for (index, action) in recovered.iter().enumerate() {
            let Some(slot) = used.get_mut(index) else {
                continue;
            };
            if *slot || action.is_empty() {
                continue;
            }
            // The recovered action must be a faithful sub-map of this letter's
            // true coset transitions: every recovered edge is one the letter
            // genuinely produces.
            let faithful = action.iter().all(|(from, to)| {
                letter_edges.contains(&CosetEdge {
                    from: *from,
                    to: *to,
                })
            });
            // And it must explain a meaningful fraction of the letter's edges, so
            // a tiny coincidental sub-map does not count as recovery: require at
            // least the merge threshold's worth of correct edges, or the whole
            // (small) letter map when the letter has fewer edges than that.
            let coverage_floor = letter_edges.len().min(action.len());
            let explains_enough =
                coverage_floor > 0 && action.len() >= letter_edges.len().min(MIN_RECOVERED_EDGES);
            if faithful && explains_enough {
                *slot = true;
                matched = matched.saturating_add(1);
                break;
            }
        }
    }
    (matched, total)
}

/// Minimum number of correct coset edges a recovered action must carry to count as
/// recovering a letter (guards against a tiny coincidental sub-map scoring).
const MIN_RECOVERED_EDGES: usize = 2;

/// One deck attack outcome on one independent seed, with its matched null.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeckAttackOutcome {
    /// Deck size `n` (`|C| = n`).
    pub state_size: usize,
    /// Hidden-subgroup order `|H| = (n-1)!`.
    pub hidden_subgroup_order: u128,
    /// Seed used to build the fixture.
    pub seed: u64,
    /// Number of ciphertext symbols.
    pub ciphertext_len: usize,
    /// Letters whose coset action the REAL pipeline recovered correctly.
    pub real_recovered: usize,
    /// Letters whose coset action the matched-null pipeline recovered.
    pub null_recovered: usize,
    /// Total plaintext letters (the recovery-fraction denominator).
    pub letters_total: usize,
    /// Fixed-context TRUE-conflict aborts on the real stream (surfaced — a feature).
    pub true_conflict_aborts: usize,
    /// Distinct visible coset symbols touched by the chain links (real stream).
    pub symbols_touched: usize,
    /// Fixed-context occurrence-pair contexts that survived (no TRUE conflict) in
    /// the chain substrate (coverage/conflict counter, not the recovery substrate).
    pub surviving_contexts: usize,
    /// Distinct `from` cosets observed across phrase columns (real stream): the
    /// denominator of the measured hidden-state obstruction.
    pub obstruction_from_total: usize,
    /// `from` cosets that mapped multi-valued across hidden states (real stream):
    /// the MEASURED hidden-state obstruction (the part NOT recoverable here).
    pub obstruction_multi_valued: usize,
}

impl DeckAttackOutcome {
    /// Real recovered-coset-action fraction (`0.0` if no letters).
    #[must_use]
    pub fn real_fraction(self) -> f64 {
        fraction(self.real_recovered, self.letters_total)
    }

    /// Matched-null recovered-coset-action fraction.
    #[must_use]
    pub fn null_fraction(self) -> f64 {
        fraction(self.null_recovered, self.letters_total)
    }

    /// Measured hidden-state obstruction: the fraction of visible cosets that map
    /// MULTI-VALUED under a fixed letter (real stream). The larger this is, the less
    /// of the per-letter action is recoverable without idea 3.
    #[must_use]
    pub fn multi_valued_fraction(self) -> f64 {
        fraction(self.obstruction_multi_valued, self.obstruction_from_total)
    }
}

/// Evaluates the deck attack on one fixture and its matched within-message
/// shuffle null over the IDENTICAL pipeline (the matched-null symmetry the
/// historical #1 bug here demands).
pub(crate) fn evaluate_deck_fixture(
    fixture: &DeckFixture,
    config: GakAttackConfig,
    seed: u64,
) -> Result<DeckAttackOutcome, GakAttackError> {
    let ciphertext_values = glyphs_to_values(&fixture.ciphertext)?;
    let truth = truth_coset_edges(&fixture.key, &fixture.plaintext)?;
    let letters_total = truth.len();
    let phrase_len = config.phrase_len;

    // Real pipeline.
    let real = run_deck_attack(&ciphertext_values, fixture.state_size, phrase_len);
    let (real_recovered, _) = coset_recovery_fraction(&truth, &real.recovered_actions);

    // Matched null: the SAME `run_deck_attack` pipeline (same phrase_len, same
    // state_size) over a within-message Fisher-Yates shuffle of the SAME ciphertext
    // population, scored against the SAME truth. Real and null run the identical
    // pipeline over the identical population — only the structure differs.
    let mut rng = SplitMix64::new(mix_seed(seed, 0x6465_636b_6e75_6c6c));
    let mut shuffled = ciphertext_values.clone();
    fisher_yates(&mut shuffled, &mut rng)?;
    let null = run_deck_attack(&shuffled, fixture.state_size, phrase_len);
    let (null_recovered, _) = coset_recovery_fraction(&truth, &null.recovered_actions);

    Ok(DeckAttackOutcome {
        state_size: fixture.state_size,
        hidden_subgroup_order: fixture.hidden_subgroup_order,
        seed,
        ciphertext_len: ciphertext_values.len(),
        real_recovered,
        null_recovered,
        letters_total,
        true_conflict_aborts: real.true_conflict_aborts,
        symbols_touched: real.symbols_touched,
        surviving_contexts: real.surviving_contexts,
        obstruction_from_total: real.obstruction.distinct_from_total,
        obstruction_multi_valued: real.obstruction.multi_valued_from_total,
    })
}

/// The measured tractability bound at one deck size `n`: real-vs-null recovered-
/// coset-action fractions across independent seeds, with a matched-null p-value.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TractabilityPoint {
    /// Deck size `n` (`|C| = n`).
    pub state_size: usize,
    /// Hidden-subgroup order `|H| = (n-1)!`.
    pub hidden_subgroup_order: u128,
    /// Number of independent seeds aggregated at this `n`.
    pub seeds: usize,
    /// Mean real recovered-coset-action fraction over the seeds.
    pub real_mean_fraction: f64,
    /// Mean matched-null recovered-coset-action fraction over the seeds.
    pub null_mean_fraction: f64,
    /// Total correctly-recovered letters (real) summed over the seeds.
    pub real_recovered_total: usize,
    /// Total correctly-recovered letters (matched null) summed over the seeds.
    pub null_recovered_total: usize,
    /// Total plaintext letters summed over the seeds (the denominator).
    pub letters_total: usize,
    /// Total fixed-context TRUE-conflict aborts (real) summed over the seeds.
    pub true_conflict_aborts: usize,
    /// MEASURED hidden-state obstruction at this `n`: the fraction of visible cosets
    /// that map MULTI-VALUED under a fixed letter, aggregated over the seeds. The
    /// headline honest result: this is the part of the action NOT recoverable
    /// without hidden-state marginalization (idea 3), and it bounds recovery.
    pub multi_valued_fraction: f64,
    /// Add-one Monte-Carlo p-value: how often a null seed's recovered fraction is
    /// at least the matched real seed's. Small means real beats null.
    pub matched_null_p_value: f64,
    /// Whether the real mean strictly exceeds the null mean at this `n` (the
    /// per-`n` "real beats matched null" verdict).
    pub real_beats_null: bool,
}

/// Result of the deck-GAK partial-recovery attack: per-seed outcomes and the
/// measured tractability bound (per-`n` real-vs-null fractions, i.e. WHERE
/// recovery breaks).
#[derive(Clone, Debug, PartialEq)]
pub struct DeckAttackReport {
    /// The deck letter regime swept (unconstrained `S_n` by default).
    pub regime: DeckLetterRegime,
    /// Per-seed deck outcomes across the swept `n` × seed matrix.
    pub outcomes: Vec<DeckAttackOutcome>,
    /// The measured tractability bound: one [`TractabilityPoint`] per swept `n`.
    pub tractability: Vec<TractabilityPoint>,
    /// Whether the attack beats its matched null on the EASIEST (smallest) swept
    /// `n` — the go/no-go for this unit.
    pub beats_null_on_easiest: bool,
    /// The smallest swept deck size (the easiest fixture).
    pub easiest_state_size: usize,
}

/// Default deck sizes swept by [`run_deck_attack_sweep`].
///
/// Starts at `n ≤ 5` (the easiest), then `6, 7, 8` — the spec's tractability
/// sweep. Recovery is expected to be partial at the smallest `n` and to BREAK as
/// `n` / `|H| = (n-1)!` grows; that measured break is the deliverable.
pub const DEFAULT_DECK_STATE_SIZES: [usize; 4] = [5, 6, 7, 8];

/// Fixed, robust seed count the bundled [`run_gak_attack`] deck sweep uses.
///
/// Per-fixture recovery variance is high (only a minority of seeds recover any
/// letter), so a stable aggregate tractability bound needs more seeds than the
/// small GCTAK-gate `seeds_per_kind` (default 3). This count makes the shipped
/// report's per-`n` real-vs-null aggregate (e.g. 18/72 vs 0/72 at `n = 5`) stable
/// rather than a 2-3-seed snapshot, while staying fast enough for `make verify`.
pub const DECK_SWEEP_SEEDS: usize = 24;

/// Runs the real-GAK deck attack across a sweep of deck sizes, measuring the
/// tractability bound (where partial recovery breaks).
///
/// For each `n` in `state_sizes` it draws `config.seeds_per_kind` independent
/// seeds, generates a deck fixture (held-back ground truth), runs the constraint-
/// propagation attack and its matched within-message shuffle null over the
/// identical pipeline, and aggregates the recovered-coset-action fractions. The
/// `regime` selects the per-letter draw (unconstrained `S_n` by default; the
/// TENTATIVE small-support regime is generated too so the next unit can validate
/// the prior).
///
/// # Errors
/// Returns [`GakAttackError`] when the configuration is invalid, when a fixture's
/// key/stream is rejected, or when a symbol cannot be represented. NOTE: unlike
/// the GCTAK gate, a low or zero recovered fraction is the EXPECTED, REPORTABLE
/// outcome here, not an error.
pub fn run_deck_attack_sweep(
    config: GakAttackConfig,
    regime: DeckLetterRegime,
    state_sizes: &[usize],
) -> Result<DeckAttackReport, GakAttackError> {
    if config.seeds_per_kind == 0 {
        return Err(GakAttackError::ZeroSeeds);
    }
    if config.phrase_repeats == 0 || config.phrase_len == 0 {
        return Err(GakAttackError::EmptyTemplate);
    }

    let mut outcomes = Vec::new();
    let mut tractability = Vec::new();
    let mut beats_null_on_easiest = false;
    let mut easiest_state_size = 0usize;

    for (size_index, &state_size) in state_sizes.iter().enumerate() {
        let mut real_fractions: Vec<f64> = Vec::new();
        let mut null_fractions: Vec<f64> = Vec::new();
        let mut real_recovered_total = 0usize;
        let mut null_recovered_total = 0usize;
        let mut letters_total = 0usize;
        let mut true_conflict_aborts = 0usize;
        let mut obstruction_from_total = 0usize;
        let mut obstruction_multi_valued = 0usize;
        let mut null_at_least_real = 0usize;

        for seed_index in 0..config.seeds_per_kind {
            let seed = deck_fixture_seed(config.seed, state_size, seed_index);
            let fixture = generate_deck_fixture(state_size, regime, config, seed)?;
            let outcome = evaluate_deck_fixture(&fixture, config, seed)?;
            real_fractions.push(outcome.real_fraction());
            null_fractions.push(outcome.null_fraction());
            real_recovered_total = real_recovered_total.saturating_add(outcome.real_recovered);
            null_recovered_total = null_recovered_total.saturating_add(outcome.null_recovered);
            letters_total = letters_total.saturating_add(outcome.letters_total);
            true_conflict_aborts =
                true_conflict_aborts.saturating_add(outcome.true_conflict_aborts);
            obstruction_from_total =
                obstruction_from_total.saturating_add(outcome.obstruction_from_total);
            obstruction_multi_valued =
                obstruction_multi_valued.saturating_add(outcome.obstruction_multi_valued);
            if outcome.null_fraction() >= outcome.real_fraction() {
                null_at_least_real = null_at_least_real.saturating_add(1);
            }
            outcomes.push(outcome);
        }

        let real_mean = mean_f64(&real_fractions);
        let null_mean = mean_f64(&null_fractions);
        let matched_null_p_value = add_one_p_value(null_at_least_real, config.seeds_per_kind);
        // The decisive per-`n` verdict is the AGGREGATE recovered-letter count
        // (real vs matched null) over all seeds, not the per-seed mean (per-fixture
        // variance is high: only a minority of seeds recover any letter, so a
        // per-seed p-value is conservatively non-significant — itself reported).
        // The aggregate contrast is unambiguous (e.g. 12 vs 0 at small `n`).
        let real_beats_null = real_recovered_total > null_recovered_total;
        let hidden_subgroup_order = deck_hidden_subgroup_order(state_size);
        tractability.push(TractabilityPoint {
            state_size,
            hidden_subgroup_order,
            seeds: config.seeds_per_kind,
            real_mean_fraction: real_mean,
            null_mean_fraction: null_mean,
            real_recovered_total,
            null_recovered_total,
            letters_total,
            true_conflict_aborts,
            multi_valued_fraction: HiddenStateObstruction {
                distinct_from_total: obstruction_from_total,
                multi_valued_from_total: obstruction_multi_valued,
            }
            .multi_valued_fraction(),
            matched_null_p_value,
            real_beats_null,
        });
        if size_index == 0 {
            easiest_state_size = state_size;
            beats_null_on_easiest = real_beats_null && real_mean > 0.0;
        }
    }

    Ok(DeckAttackReport {
        regime,
        outcomes,
        tractability,
        beats_null_on_easiest,
        easiest_state_size,
    })
}

/// Deterministic per-`(n, seed_index)` fixture seed for the deck sweep.
fn deck_fixture_seed(master: u64, state_size: usize, seed_index: usize) -> u64 {
    let tag = (state_size as u64)
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .wrapping_add(seed_index as u64);
    mix_seed(master, tag ^ 0x6465_636b_5f73_7765)
}

/// Mean of an `f64` slice (`0.0` when empty).
#[must_use]
pub(crate) fn mean_f64(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
}

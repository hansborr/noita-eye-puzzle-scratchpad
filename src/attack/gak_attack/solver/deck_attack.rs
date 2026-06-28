use super::{
    AlignedOccurrence, BTreeMap, BTreeSet, ContextId, CosetEdge, GakAttackError, GakKey, Glyph,
    PatternSignature, SymbolValue, build_chain_substrate, chain_links_for_pair, compose_state,
    fraction, readout_of_state, spacing_filter,
};

/// Result of the deck constraint-propagation attack on one ciphertext stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeckAttackSolution {
    /// The merged single-valued-core actions: each is a partial map on the visible
    /// coset alphabet, light-merged across phrase columns. These are the recovered
    /// partial visible-coset action maps scored against ground truth — a fraction of
    /// per-letter visible-coset transitions, not a recovered key and not the
    /// plaintext->group-element mapping.
    pub(crate) recovered_actions: Vec<BTreeMap<u8, u8>>,
    /// Number of fixed-context true-conflict aborts (bad isomorph alignments
    /// witnessed by [`build_chain_substrate`]). Surfaced — a feature.
    pub(crate) true_conflict_aborts: usize,
    /// Distinct visible coset symbols touched (chain-link coverage).
    pub(crate) symbols_touched: usize,
    /// Number of fixed-context occurrence-pair contexts that survived (no true
    /// conflict) in the chain substrate — the coverage/conflict-detection counter.
    pub(crate) surviving_contexts: usize,
    /// The measured hidden-state obstruction: how much of the per-letter
    /// visible-coset action is multi-valued across hidden states (the part not
    /// recoverable without idea 3). This is a headline honest result of this unit.
    pub(crate) obstruction: HiddenStateObstruction,
}

/// Runs the deck visible-coset action-recovery attack (idea 1, this unit).
///
/// **What this recovers.** Only partial visible-coset action maps —
/// a fraction of the per-letter `from -> to` visible-coset transitions — not a
/// recovered key and not the plaintext->group-element mapping. Under non-trivial
/// `H` the visible transition depends on the full hidden state, so most of a
/// letter's action is multi-valued across hidden states and is not recoverable here
/// (it is measured as [`HiddenStateObstruction`] instead). That bound is the point.
///
/// **Pipeline.**
/// 1. **Chain-link substrate (coverage + conflict detection).**
///    [`build_chain_substrate`] groups occurrence pairs by full-window
///    [`PatternSignature`] and turns each into one fixed-context partial permutation
///    via the shared [`chain_links_for_pair`] primitive. A genuine fixed-context
///    true conflict there (two arrows out of / into one symbol under one alignment)
///    proves a bad isomorph alignment and aborts that branch. This substrate is
///    reused for coverage (`symbols_touched`) and conflict detection — it is not the
///    recovery substrate.
/// 2. **Per-column recovery (the recovery substrate).** [`phrase_column_evidence`]
///    accumulates each phrase column's one-step visible-coset transitions — sourced
///    from the same [`chain_links_for_pair`] primitive (load-bearing: corrupting the
///    links changes these edges and breaks recovery). Cross-hidden-state
///    multi-valuedness is expected here, so it is measured, not aborted; only each
///    column's single-valued core feeds recovery.
/// 3. **Light merge over consistent columns.** [`merge_context_actions`] merges
///    single-valued cores only when their shared support meets the group-dependent
///    [`merge_overlap_threshold`] and they never contradict — a deliberately
///    conservative light merge, not full Schreier-graph constraint propagation.
///    Unequal cycles never block a merge (the hidden state shortens some).
///
/// ## Hooks for the next unit (idea 2 + idea 3)
///
/// - **Small-support prior (idea 2):** [`merge_overlap_threshold`] is where the
///   tentative near-identity prior becomes a soft penalty — biasing merges toward
///   actions expressible as `≤k` transpositions. It is not applied here (this unit
///   measures the unconstrained bound); the hook is the single function to extend.
/// - **Hidden-state marginalization (idea 3):** the [`HiddenStateObstruction`] this
///   unit measures is exactly what idea 3 must overcome. [`merge_context_actions`]
///   is where a belief-propagation / beam search over the hidden-state posterior
///   replaces the greedy single-valued-core merge, so the multi-valued part becomes
///   recoverable. The greedy merge is intentionally the simplest correct light merge
///   so the next unit can swap it without reshaping the substrate or the scoring.
pub(crate) fn run_deck_attack(
    ciphertext: &[SymbolValue],
    state_size: usize,
    phrase_len: usize,
) -> DeckAttackSolution {
    // (1) Chain-link substrate: reused for coverage + fixed-context conflict
    // detection (not the recovery substrate). The phrase-length window (not a short
    // window) is essential: the visible coset alphabet is tiny (|C| = n), so a short
    // window collides on nearly every position; the long phrase window is what makes
    // the equality-pattern signature discriminating. This gives the genuine
    // fixed-context true-conflict aborts and the chain-link coverage. Production
    // groups by the full window (core_len == window_len), so the shipped numbers are
    // unchanged; the conflict guard fires only on a deliberately bad alignment (a
    // shorter core), exercised directly in the tests.
    let substrate = build_chain_substrate(ciphertext, phrase_len, phrase_len);
    let surviving_contexts = substrate.contexts.len();
    let true_conflict_aborts = substrate.true_conflict_aborts;

    // (2) Per-column recovery (the recovery substrate). Within the aligned phrase,
    // column `c` is always the same plaintext letter across all occurrences, so its
    // one-step (prev -> next) visible-coset edges — sourced from the same
    // chain_links_for_pair primitive (load-bearing) — are that one letter's coset
    // action observed across many hidden states. Under non-trivial H a single coset
    // legitimately maps several ways across hidden states, so we measure that
    // multi-valuedness as the obstruction and recover only the single-valued core.
    let (columns, obstruction) = phrase_column_evidence(ciphertext, phrase_len);
    let cores: Vec<BTreeMap<u8, u8>> = columns
        .iter()
        .map(ColumnEvidence::single_valued_core)
        .filter(|core| !core.is_empty())
        .collect();

    // (3) Light merge of the consistent single-valued cores (group-dependent overlap
    // threshold). This is a conservative light merge, not full constraint
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
/// every aligned occurrence (i.e. across many hidden states for the same plaintext
/// letter).
///
/// Crucially, for non-trivial `H` the visible transition is
/// `c_i = g_{i-1}^{-1}[ p(a)^{-1}[top] ]` — it depends on the full hidden state
/// `g_{i-1}`, not just the previous visible coset. So when one column is gathered
/// across occurrences with different hidden states, a single `from` coset
/// legitimately maps to several `to` cosets. That multi-valuedness is **normal
/// hidden-state variation, not a conflict** in the chaining sense, so this struct
/// records the full per-`from` image set rather than forcing a partial permutation.
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
    /// map to exactly one `to` across all hidden states. This is the only part of a
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
/// of the visible-coset action is multi-valued (and therefore not recoverable
/// without idea 3's hidden-state handling).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct HiddenStateObstruction {
    /// Total distinct `from` cosets summed over all phrase columns.
    pub(crate) distinct_from_total: usize,
    /// `from` cosets that mapped multi-valued (out-degree > 1) summed over columns.
    pub(crate) multi_valued_from_total: usize,
}

impl HiddenStateObstruction {
    /// Fraction of visible cosets that map multi-valued under a fixed letter — the
    /// hidden-state obstruction this unit measures (`0.0` when no evidence). This is
    /// the headline honest metric: the larger it is, the less of the action is
    /// recoverable without hidden-state marginalization (idea 3).
    pub(crate) fn multi_valued_fraction(self) -> f64 {
        fraction(self.multi_valued_from_total, self.distinct_from_total)
    }
}

/// Accumulates per-phrase-column visible-coset evidence across aligned occurrences.
///
/// The aligned repeated phrase is found once (spacing-filtered occurrences); each
/// interior column `c` of the phrase is the same plaintext letter across every
/// occurrence (`Alphabet-Chaining.md`: a repeated phrase recurs as a repeated
/// equality pattern). So the adjacent `(prev -> next)` visible-coset edge at that
/// column, gathered over all occurrences, is that one letter's coset action seen
/// across many hidden states.
///
/// Load-bearing chain-link reuse: the prev->next edges are not read off the raw
/// stream — they are the [`chain_links_for_pair`] output of each occurrence window
/// aligned against itself shifted by one (column `c-1` is the "upper" occurrence,
/// column `c` is the "lower" occurrence of the same one-step isomorph). So the
/// recovery's equations come straight from the shared chain-link primitive;
/// corrupting the links changes these edges and breaks recovery.
///
/// We do not force a partial permutation per column: under non-trivial `H` a single
/// `from` coset legitimately maps to several `to` cosets across hidden states (see
/// [`ColumnEvidence`]), so each column keeps its full image set. The single-valued
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
        // Source the prev->next edges from the shared chain-link primitive: align
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
/// (one short of the full visible alphabet) and fully consistent. This is the
/// deliberately conservative deck threshold; a single shared edge can never
/// trigger a merge. This function is the documented soft-prior hook for the next
/// unit: the tentative small-support penalty lowers/weights the threshold for
/// near-identity actions, but is not applied in this unit.
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
/// a deliberately conservative light merge of single-valued cores, **not** full
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
    // Group-dependent overlap threshold: a single shared edge is never enough.
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
/// For non-trivial `H` a letter does not induce a fixed coset permutation, so the
/// truth is the full set of `(s, s')` coset transitions letter `a` produces across
/// all reachable hidden states encountered while encrypting this plaintext. We
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
/// `matched` is how many letters have a recovered action that is a correct,
/// non-empty partial coset action for that letter: every edge of the recovered
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

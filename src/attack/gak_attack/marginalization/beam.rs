//! Idea-3 hidden-state marginalization: the bounded beam / belief-propagation
//! per-column coset-edge recovery and the single-stream marginalization attack.
//!
//! Split out of the `marginalization` parent module (whose unit overview frames
//! the experiment and whose sweep/validation harness consumes these primitives).
//! The beam builds on the deck attack's coset-edge and chain-link primitives from
//! the `solver` sibling, reached through the enclosing `gak_attack` module.

use super::super::*;

/// Default beam width for the idea-3 hidden-state marginalization.
///
/// The beam keeps at most this many candidate per-letter coset-edge hypotheses per
/// column while propagating across the column's hidden-state branches. Bounding the
/// width is the point (`Explanation-of-Progress.md`: full hidden-state enumeration
/// is infeasible "even with only two hidden states per letter"); the bound and the
/// number of dropped beams are REPORTED, never silently truncated.
pub const DEFAULT_BEAM_WIDTH: usize = 8;

/// Fraction of a column's aligned occurrences placed in the HELD-OUT validation
/// fold (the rest are the TRAIN fold). A deterministic stride keeps the split
/// reproducible. The held-out fold is the constraint source idea 3 scores beams by;
/// it is NEVER used to build candidate edges.
pub(crate) const HELD_OUT_STRIDE: usize = 2;

/// Whether the TENTATIVE small-support prior (idea 2) is applied to the idea-3 beam.
///
/// The prior is **TENTATIVE everywhere** (`Deck-Cipher.md`'s shared-sections
/// evidence is a heuristic, not a hard constraint). The signal it exploits: when the
/// per-letter permutations are near-identity from a shared base
/// ([`DeckLetterRegime::SmallSupport`]), each letter's visible-coset action is more
/// COMPACT, so its genuine edges recur across occurrences and carry HIGHER
/// train-support, while spurious low-support edges are noise. So when [`Self::On`]
/// the beam admits only candidate edges whose TRAIN support meets a minimum count
/// — a soft confidence floor that should improve precision on small-support truth
/// and, on unconstrained truth where genuine edges are NOT compact, FAIL GRACEFULLY
/// (it cannot reward a wrong assumption; at worst it drops genuine low-support
/// edges, never inventing any). Reported with its toggle state so no result silently
/// depends on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmallSupportPrior {
    /// The prior is OFF: every train edge is a candidate. Branches are still admitted
    /// in TRAIN-SUPPORT-rank order under the [`DEFAULT_BEAM_WIDTH`] cap, and a branch is
    /// kept only when it STRICTLY improves held-out generalization (the smaller-set
    /// tie-break) — so "held-out generalization" is the SELECTION rule among
    /// support-ranked, width-capped candidates, not a free search over all subsets.
    Off,
    /// The prior is ON (TENTATIVE): only train edges with support `>= min_support`
    /// are candidate branches (a soft confidence floor), biasing recovery toward the
    /// compact, recurrent action a near-identity small-support letter produces.
    On {
        /// Minimum TRAIN-fold occurrence support a candidate edge must have to be
        /// admissible when the prior is ON. TENTATIVE.
        min_support: usize,
    },
}

impl SmallSupportPrior {
    /// Returns a short report label for this prior toggle.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Off => "OFF (support-rank + width-cap candidates, held-out-strict select)",
            Self::On { .. } => "ON (TENTATIVE small-support confidence floor)",
        }
    }

    /// Whether the prior is enabled.
    #[must_use]
    pub const fn is_on(self) -> bool {
        matches!(self, Self::On { .. })
    }

    /// The minimum TRAIN support an edge needs to be a candidate branch under this
    /// prior: `1` when OFF (every train edge is admissible), `min_support` when ON.
    #[must_use]
    const fn min_candidate_support(self) -> usize {
        match self {
            Self::Off => 1,
            Self::On { min_support } => {
                if min_support == 0 {
                    1
                } else {
                    min_support
                }
            }
        }
    }
}

/// One candidate per-letter coset-edge hypothesis carried by the idea-3 beam.
///
/// A beam item is a growing SET of admitted `from -> to` coset edges (the per-letter
/// marginal over hidden states being reconstructed) together with the held-out
/// validation tallies that score it. Unlike the 2a single-valued core, a beam item
/// is allowed to admit several `to` images of one `from` (different hidden-state
/// branches of the SAME letter) — that is the marginalization. It stays a valid
/// hypothesis as long as held-out branches keep landing inside it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct BeamItem {
    /// Admitted directed coset edges (the recovered per-letter marginal so far).
    pub(crate) admitted: BTreeSet<CosetEdge>,
    /// Number of held-out branches this item correctly predicted (each held-out
    /// `(from, to)` already present in `admitted`). Higher is better.
    held_out_hits: usize,
    /// Number of held-out branches this item failed to predict (held-out edge
    /// absent from `admitted`). Lower is better.
    held_out_misses: usize,
}

impl BeamItem {
    /// The held-out generalization score in `[0, 1]`: the fraction of held-out
    /// branches that landed inside the admitted edge set. This is the core idea-3
    /// score — a beam that admits genuine same-letter branches predicts held-out
    /// branches that an unrelated edge set would miss.
    ///
    /// This is pure held-out RECALL (`hits / (hits + misses)`), with NO precision /
    /// false-positive term: admitting a further branch can only keep or raise the hit
    /// count, so the score is monotonically NON-DECREASING in the admitted-set size and
    /// never penalizes over-admission on its own. The discrimination against padding is
    /// supplied by the smaller-admitted-set tie-break in [`beam_recover_column`] (a
    /// branch is selected only when it STRICTLY improves this recall), NOT by this score
    /// — do not read a precision property into it.
    fn generalization(&self) -> f64 {
        let total = self.held_out_hits.saturating_add(self.held_out_misses);
        fraction(self.held_out_hits, total)
    }
}

/// The held-back evidence for one phrase column under a TRAIN / HELD-OUT split.
///
/// The aligned phrase column is one plaintext letter across all occurrences. We
/// split its occurrences deterministically into a TRAIN fold (the candidate edges)
/// and a HELD-OUT fold (the validation branches). Both folds are sourced from the
/// SHARED [`chain_links_for_pair`] primitive (load-bearing). The TRAIN edges carry a
/// support count (how many TRAIN occurrences witnessed them) so the beam can
/// propagate the strongest branches first.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SplitColumnEvidence {
    /// TRAIN-fold edges with their occurrence-support counts.
    pub(crate) train_support: BTreeMap<CosetEdge, usize>,
    /// HELD-OUT-fold branches (the validation set), in occurrence order.
    pub(crate) held_out: Vec<CosetEdge>,
}

/// Builds per-column TRAIN/HELD-OUT evidence for the idea-3 marginalization.
///
/// Mirrors [`phrase_column_evidence`] (same aligned phrase, same SHARED
/// [`chain_links_for_pair`] source — load-bearing) but partitions each column's
/// occurrences into a TRAIN fold (every occurrence index NOT on the held-out stride)
/// and a HELD-OUT fold (every `HELD_OUT_STRIDE`-th occurrence). The held-out fold is
/// reserved purely for scoring beams — it never contributes a candidate edge, so the
/// validation is genuinely out-of-sample.
pub(crate) fn split_column_evidence(
    ciphertext: &[SymbolValue],
    phrase_len: usize,
) -> Vec<SplitColumnEvidence> {
    let window_len = phrase_len.max(2);
    let Some(filtered) = aligned_phrase_occurrences(ciphertext, window_len) else {
        return Vec::new();
    };
    let mut columns: Vec<SplitColumnEvidence> = vec![SplitColumnEvidence::default(); window_len];
    let mut context_index: u32 = 0;
    for (occurrence_index, &start) in filtered.iter().enumerate() {
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
        // Deterministic fold assignment: every HELD_OUT_STRIDE-th occurrence is the
        // validation fold; the rest are training. Reserving the held-out fold keeps
        // the chain-link validation out-of-sample (the idea-3 score is genuine).
        let is_held_out = HELD_OUT_STRIDE != 0 && occurrence_index % HELD_OUT_STRIDE == 0;
        for link in &links {
            let phrase_col = link.provenance.column.saturating_add(1);
            let Some(column) = columns.get_mut(phrase_col) else {
                continue;
            };
            let edge = CosetEdge {
                from: link.from.get(),
                to: link.to.get(),
            };
            if is_held_out {
                column.held_out.push(edge);
            } else {
                let support = column.train_support.entry(edge).or_insert(0);
                *support = support.saturating_add(1);
            }
        }
    }
    columns
        .into_iter()
        .filter(|c| !c.train_support.is_empty() || !c.held_out.is_empty())
        .collect()
}

/// Runs the idea-3 bounded beam over one column's hidden-state branches.
///
/// The beam reconstructs the per-letter coset-edge marginal by admitting TRAIN
/// branches in DESCENDING support order (most-witnessed hidden-state branch first),
/// scoring each support-ranked prefix against the HELD-OUT fold, and selecting the
/// best-generalizing prefix. The width bound makes only the first `beam_width`
/// support-ranked prefixes ELIGIBLE: `best` is chosen strictly from those, and the
/// deeper, lower-support prefixes are genuinely DROPPED (never built, never
/// selectable). This is a belief propagation over hidden-state branches — each
/// admitted edge is one branch of the letter's action, the held-out fold is the
/// posterior evidence, and the width caps the admitted-set size so we never chase the
/// long tail of rare branches (full enumeration is infeasible —
/// `Explanation-of-Progress.md`).
///
/// Returns `(best_item, beams_dropped)` where `best_item` is the highest-scoring beam
/// AMONG THE IN-WIDTH CANDIDATES (its `admitted` set is the recovered per-letter
/// marginal for this column) and `beams_dropped` is how many support-ranked candidate
/// prefixes fell outside the width bound and so were ineligible for selection
/// (surfaced — no silent truncation). The TENTATIVE small-support `prior` plugs in as
/// the candidate-pruning floor: when ON it removes train branches whose support is
/// below [`SmallSupportPrior::min_candidate_support`] BEFORE the beam runs, biasing
/// recovery toward the compact, recurrent action a near-identity letter produces.
pub(crate) fn beam_recover_column(
    column: &SplitColumnEvidence,
    beam_width: usize,
    prior: SmallSupportPrior,
) -> (BeamItem, usize) {
    let min_support = prior.min_candidate_support();
    // Candidate branches ordered by TRAIN support (descending), then by edge for a
    // deterministic tiebreak. The most-supported branches are the hidden states the
    // train fold sampled most often — the safest to admit first. The TENTATIVE
    // small-support prior prunes low-support branches up front (idea-2 hook).
    let mut ranked: Vec<(CosetEdge, usize)> = column
        .train_support
        .iter()
        .filter(|(_edge, support)| **support >= min_support)
        .map(|(edge, support)| (*edge, *support))
        .collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    // Build the prefix-`k` candidate beams in SUPPORT-RANK order: prefix k admits the
    // top-k most-supported train branches. There are `ranked.len() + 1` candidate
    // prefixes in principle (k = 0..=len), but the width bound makes only the first
    // `beam_width` of them (the highest-support, smallest-admitted prefixes) ELIGIBLE
    // for selection. The deeper, lower-support prefixes are genuinely DROPPED — never
    // built, never selectable — which is what `beams_dropped` reports. The bound is
    // load-bearing: it caps admitted-set growth so we never chase the long tail of
    // rare hidden-state branches (and never enumerate the 2^len subsets). At larger
    // scale this bound is what keeps the search tractable.
    let total_candidate_prefixes = ranked.len().saturating_add(1);
    let eligible_prefixes = total_candidate_prefixes.min(beam_width);
    let beams_dropped = total_candidate_prefixes.saturating_sub(eligible_prefixes);

    let mut beams: Vec<BeamItem> = Vec::new();
    let mut admitted: BTreeSet<CosetEdge> = BTreeSet::new();
    for prefix_len in 0..eligible_prefixes {
        if let Some((edge, _support)) = prefix_len
            .checked_sub(1)
            .and_then(|index| ranked.get(index))
        {
            let _added = admitted.insert(*edge);
        }
        let (held_out_hits, held_out_misses) = score_held_out(&admitted, &column.held_out);
        beams.push(BeamItem {
            admitted: admitted.clone(),
            held_out_hits,
            held_out_misses,
        });
    }

    // Rank the ELIGIBLE beams: maximize held-out generalization, then prefer the
    // SMALLER admitted set at equal generalization. `generalization()` is pure held-out
    // recall and is monotonically non-decreasing as the prefix grows (admitting a
    // further branch can only keep or raise the hit count); preferring the larger set on
    // a tie would therefore admit every train branch the moment held-out recall
    // saturates — including support-rank padding that the held-out fold never validated.
    // Preferring the SMALLER set means a branch is admitted ONLY when it STRICTLY
    // improves held-out generalization, making "admits the branches that generalize and
    // prunes the rest" literally true (no out-of-sample-blind padding). `best` is chosen
    // ONLY from the in-width candidates, so the dropped beams are truly ineligible.
    beams.sort_by(|a, b| {
        b.generalization()
            .partial_cmp(&a.generalization())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.admitted.len().cmp(&b.admitted.len()))
    });

    let best = beams.into_iter().next().unwrap_or_default();
    (best, beams_dropped)
}

/// Scores an admitted edge set against a held-out fold: `(hits, misses)` where a hit
/// is a held-out branch already present in `admitted` (correctly predicted
/// out-of-sample) and a miss is one absent from it. This is the out-of-sample
/// chain-link validation that drives the beam (no ground-truth peek).
fn score_held_out(admitted: &BTreeSet<CosetEdge>, held_out: &[CosetEdge]) -> (usize, usize) {
    let mut hits = 0usize;
    let mut misses = 0usize;
    for edge in held_out {
        if admitted.contains(edge) {
            hits = hits.saturating_add(1);
        } else {
            misses = misses.saturating_add(1);
        }
    }
    (hits, misses)
}

/// Result of the idea-3 hidden-state marginalization on one ciphertext stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MarginalizationSolution {
    /// The recovered per-letter (per-column) coset-edge marginals: each is the
    /// best beam's admitted edge set — a PARTIAL visible-coset action recovery that
    /// ADMITS multi-valued `from` cosets (the hidden-state marginal), NOT a recovered
    /// key and NOT the plaintext->group-element mapping. This is what idea 3 recovers
    /// beyond the 2a single-valued core.
    pub(crate) recovered_columns: Vec<BTreeSet<CosetEdge>>,
    /// The 2a single-valued-core baseline edge sets on the SAME columns (for the
    /// like-for-like "does marginalization recover more" comparison).
    pub(super) baseline_columns: Vec<BTreeMap<u8, u8>>,
    /// Total beams pruned by the width bound across all columns (no silent
    /// truncation — surfaced).
    pub(crate) beams_dropped: usize,
    /// The beam width bound used (surfaced).
    beam_width: usize,
    /// The small-support prior toggle used (surfaced).
    prior: SmallSupportPrior,
}

/// Runs the idea-3 hidden-state marginalization attack on a ciphertext stream.
///
/// For each aligned phrase column (one plaintext letter) it builds the TRAIN /
/// HELD-OUT split ([`split_column_evidence`], sourced from the SHARED
/// [`chain_links_for_pair`] primitive — load-bearing), then runs the bounded beam
/// ([`beam_recover_column`]) to admit the train hidden-state branches that
/// generalize to the held-out fold. It returns the recovered per-column marginals,
/// the 2a single-valued-core baseline on the same columns, and the disclosed beam
/// width + dropped-beam count.
///
/// Under non-trivial `H` the recovered object is the per-letter coset-edge MARGINAL
/// over hidden states (multi-valued `from` allowed), NOT a permutation — that is the
/// whole point of marginalizing the hidden state. It is a PARTIAL visible-coset
/// action recovery on SYNTHETIC ground truth, never a recovered key.
pub(crate) fn run_marginalization_attack(
    ciphertext: &[SymbolValue],
    phrase_len: usize,
    beam_width: usize,
    prior: SmallSupportPrior,
) -> MarginalizationSolution {
    let split = split_column_evidence(ciphertext, phrase_len);
    // The 2a baseline single-valued cores on the SAME columns: a `from` that maps
    // exactly one way across ALL (train+held-out) branches. This is the like-for-like
    // baseline the marginalization is compared against.
    let baseline_columns: Vec<BTreeMap<u8, u8>> = split
        .iter()
        .map(single_valued_core_of_split)
        .filter(|core| !core.is_empty())
        .collect();

    let mut recovered_columns: Vec<BTreeSet<CosetEdge>> = Vec::new();
    let mut beams_dropped = 0usize;
    for column in &split {
        let (best, dropped) = beam_recover_column(column, beam_width, prior);
        beams_dropped = beams_dropped.saturating_add(dropped);
        if !best.admitted.is_empty() {
            recovered_columns.push(best.admitted);
        }
    }

    MarginalizationSolution {
        recovered_columns,
        baseline_columns,
        beams_dropped,
        beam_width,
        prior,
    }
}

/// The 2a single-valued core of one split column: the `from` cosets that map to
/// exactly one `to` across ALL of the column's branches (train + held-out combined),
/// matching [`ColumnEvidence::single_valued_core`] but over the split evidence. This
/// is the baseline the idea-3 marginal is compared against on identical columns.
pub(crate) fn single_valued_core_of_split(column: &SplitColumnEvidence) -> BTreeMap<u8, u8> {
    let mut images: BTreeMap<u8, BTreeSet<u8>> = BTreeMap::new();
    for edge in column
        .train_support
        .keys()
        .copied()
        .chain(column.held_out.iter().copied())
    {
        let _new = images.entry(edge.from).or_default().insert(edge.to);
    }
    let mut core = BTreeMap::new();
    for (from, tos) in &images {
        if let (1, Some(to)) = (tos.len(), tos.iter().next().copied()) {
            let _old = core.insert(*from, to);
        }
    }
    core
}

/// Scores a set of recovered per-column coset-edge marginals against the held truth,
/// returning the count of TRUE edges recovered and the total truth edges.
///
/// For each recovered column we attribute it to the best-matching letter (the letter
/// whose truth edge set contains the most of the column's recovered edges) and count
/// only the recovered edges that are GENUINELY in that letter's truth. Each letter is
/// claimed by at most one column (one-to-one), so a column cannot double-count a
/// letter's edges. This is the idea-3 analogue of [`coset_recovery_fraction`] but at
/// EDGE granularity (the marginal admits multi-valued `from`, so we score edges, not
/// whole-letter permutations). Returns `(true_edges_recovered, truth_edges_total)`.
pub(super) fn marginal_edge_recovery(
    truth: &[BTreeSet<CosetEdge>],
    recovered_columns: &[BTreeSet<CosetEdge>],
) -> (usize, usize) {
    let truth_total: usize = truth.iter().map(BTreeSet::len).sum();
    let mut used = vec![false; truth.len()];
    let mut recovered_true = 0usize;
    // Greedy one-to-one attribution: process columns by descending size so the
    // largest (most informative) marginals claim their letter first.
    let mut order: Vec<usize> = (0..recovered_columns.len()).collect();
    order.sort_by_key(|&i| {
        recovered_columns
            .get(i)
            .map_or(0, |c| usize::MAX.saturating_sub(c.len()))
    });
    for column_index in order {
        let Some(column) = recovered_columns.get(column_index) else {
            continue;
        };
        let mut best_letter: Option<usize> = None;
        let mut best_true = 0usize;
        for (letter_index, letter_edges) in truth.iter().enumerate() {
            if used.get(letter_index).copied().unwrap_or(true) {
                continue;
            }
            let true_count = column.iter().filter(|e| letter_edges.contains(e)).count();
            if true_count > best_true {
                best_true = true_count;
                best_letter = Some(letter_index);
            }
        }
        if let Some(letter_index) = best_letter {
            if let Some(slot) = used.get_mut(letter_index) {
                *slot = true;
            }
            recovered_true = recovered_true.saturating_add(best_true);
        }
    }
    (recovered_true, truth_total)
}

/// Scores the 2a single-valued-core baseline columns against truth at EDGE
/// granularity, for the like-for-like comparison with [`marginal_edge_recovery`].
///
/// Each baseline core is a `from -> to` map (single-valued by construction); we
/// attribute each core to its best-matching letter (one-to-one) and count its edges
/// that are genuinely in that letter's truth. Returns `(true_edges, truth_total)`
/// over the SAME truth denominator as the marginal so the two fractions are
/// directly comparable (the answer to "does marginalization recover MORE").
pub(super) fn baseline_edge_recovery(
    truth: &[BTreeSet<CosetEdge>],
    baseline_columns: &[BTreeMap<u8, u8>],
) -> (usize, usize) {
    let as_edges: Vec<BTreeSet<CosetEdge>> = baseline_columns
        .iter()
        .map(|core| {
            core.iter()
                .map(|(from, to)| CosetEdge {
                    from: *from,
                    to: *to,
                })
                .collect()
        })
        .collect();
    marginal_edge_recovery(truth, &as_edges)
}

//! The held-out attack core: the embargoed-consensus coverage-weighted scoring
//! algorithm and its synthetic positive control.
//!
//! This is ONE indivisible scoring algorithm — the per-message held-out evaluation,
//! the embargoed-consensus predictor, the matched within-message shuffle-null tail,
//! and the synthetic isomorph-rich positive control all share the private
//! [`HeldOutScore`] / [`EyeMessageEvidence`] internals, so they are not split
//! further. It recovers STRUCTURE, never cleartext.

use super::super::*;

/// Builds the per-message held-out isomorph evaluation for the REAL eye streams.
///
/// For each message (boundaries kept, never concatenated) this aligns the message's
/// isomorph occurrences by [`PatternSignature`] over the Thread-3 window range,
/// splits whole signature groups deterministically into TRAIN and HELD-OUT folds,
/// builds context-colored partial actions from each occurrence pair with the SHARED
/// [`chain_links_for_pair`] primitive (load-bearing — never a second graph), and
/// scores the held-out fold by the EMBARGOED-CONSENSUS statistic
/// ([`EyeMessageEvidence::held_out_score`]): a held-out edge scores only when `>= 2`
/// train contexts from DISTINCT signature groups, physically embargoed from the
/// held-out context, AGREE on it. The authoritative null significance is the full
/// trial tail in [`eyes_matched_null_tail`].
///
/// `safe_spans_by_message` supplies, in the SAME order as `keys`, the Thread-3
/// safe spans each message's Gate-1 chaining is restricted to. A message without
/// safe spans yields no admitted windows (and therefore no scored edges).
pub(super) fn eyes_per_message_held_out(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    safe_spans_by_message: &[Vec<(usize, usize)>],
) -> Vec<EyeMessageHeldOut> {
    let mut rows = Vec::with_capacity(message_values.len());
    for (index, (key, values)) in keys.iter().copied().zip(message_values).enumerate() {
        let safe_filter = safe_spans_by_message
            .get(index)
            .map_or(SafeWindowFilter::restrict(&[]), |spans| {
                SafeWindowFilter::restrict(spans.as_slice())
            });
        let evidence = eyes_message_evidence(values, safe_filter);
        // Real held-out scoring: the recovered TRAIN context-action LIBRARY predicts
        // the held-out fold via the EMBARGOED-CONSENSUS coverage-weighted statistic
        // (only genuinely transferable cross-group structure scores).
        let real_score = evidence.held_out_score();
        rows.push(EyeMessageHeldOut {
            message_key: key,
            length: values.len(),
            isomorph_groups: evidence.isomorph_groups,
            aligned_pairs: evidence.aligned_pairs,
            symbols_touched: evidence.symbols_touched,
            true_conflict_aborts: evidence.true_conflict_aborts,
            real_held_out_hits: real_score.hits,
            real_held_out_misses: real_score.misses,
            real_held_out_ambiguous: real_score.ambiguous,
            real_score: real_score.coverage_weighted(),
        });
    }
    rows
}

/// Provenance of one context action: which isomorph signature group it came from and
/// the physical spans of its two aligned occurrences, used to enforce the positional
/// embargo (no train context may predict a held-out context it physically overlaps or
/// shares a signature group with — the nested/overlapping-window leak guard).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ContextProvenance {
    /// Stable id of the isomorph signature group this context belongs to.
    signature_id: u64,
    /// `[start, end)` of the upper occurrence in the message.
    upper: (usize, usize),
    /// `[start, end)` of the lower occurrence in the message.
    lower: (usize, usize),
}

impl ContextProvenance {
    /// Whether this context physically overlaps (or is immediately adjacent to)
    /// `other` on either occurrence span — the embargo predicate.
    fn touches(self, other: ContextProvenance) -> bool {
        spans_touch(self.upper, other.upper)
            || spans_touch(self.upper, other.lower)
            || spans_touch(self.lower, other.upper)
            || spans_touch(self.lower, other.lower)
    }
}

/// Whether two half-open spans overlap or are immediately adjacent (a 1-symbol gap
/// still counts as touching, to be conservative about leakage).
fn spans_touch(a: (usize, usize), b: (usize, usize)) -> bool {
    let (a_start, a_end) = a;
    let (b_start, b_end) = b;
    a_start <= b_end.saturating_add(1) && b_start <= a_end.saturating_add(1)
}

/// Restricts Gate-1 chaining to the Thread-3 SAFE ISOMORPH EXTENTS for one message
/// (ENFORCED, not just claimed). Thread 3 exports conservative per-message safe
/// spans where a cross-message aligned isomorph extends without over-reaching; Gate 1
/// admits an isomorph occurrence window only when its `[start, end)` lies ENTIRELY
/// within one of those safe spans for this message, so chaining never over-extends
/// past a Thread-3 break.
///
/// `spans == None` means NO restriction: used ONLY for the synthetic positive control
/// fixture, which is not a corpus message and has no Thread-3 extent (so the detector
/// is validated on its full known signal). For the real eyes, `spans` is always the
/// (possibly empty) Thread-3 safe-span list for that message — an empty list means
/// Thread 3 found no safe extent there, so NO window in that message is admitted.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SafeWindowFilter<'a> {
    /// `Some(spans)` restricts to those half-open safe spans; `None` admits all.
    spans: Option<&'a [(usize, usize)]>,
}

impl<'a> SafeWindowFilter<'a> {
    /// The unrestricted filter (synthetic positive control only — admits everything).
    pub(crate) const fn unrestricted() -> Self {
        Self { spans: None }
    }

    /// Restricts to the given Thread-3 safe spans for one real eye message.
    const fn restrict(spans: &'a [(usize, usize)]) -> Self {
        Self { spans: Some(spans) }
    }

    /// Whether a window `[start, end)` is admissible: always when unrestricted, else
    /// only when fully contained in at least one Thread-3 safe span.
    fn admits(self, window: (usize, usize)) -> bool {
        match self.spans {
            None => true,
            Some(spans) => spans.iter().any(|&(s, e)| s <= window.0 && window.1 <= e),
        }
    }
}

/// One CONTEXT-COLORED partial action: the injective `from -> to` map of ONE aligned
/// isomorph occurrence pair (`Graph-Chaining.md`: GAK chaining is a Schreier coset
/// graph of context-colored partial permutations, NOT one global symbol map). TRUE
/// conflicts (two arrows out of / into one symbol under this one context) are
/// rejected at construction, so a context action is always a partial bijection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct EyeContextAction {
    /// Forward partial bijection `from -> to` for this single context.
    pub(crate) forward: BTreeMap<u8, u8>,
    /// Provenance for the positional embargo and same-group rejection.
    provenance: ContextProvenance,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct EyeMessageEvidence {
    /// TRAIN-fold context actions (one per train isomorph occurrence pair). The
    /// recovered "model" is this LIBRARY of context-colored partial permutations,
    /// NOT a collapsed global map — the wiki-faithful object.
    pub(crate) train_contexts: Vec<EyeContextAction>,
    /// HELD-OUT-fold context actions (from DISJOINT signature groups). Validation
    /// only; never contributes a train context.
    pub(crate) held_out_contexts: Vec<EyeContextAction>,
    /// Distinct isomorph signature groups (≥2 occurrences).
    isomorph_groups: usize,
    /// Aligned isomorph occurrence pairs that yielded chain links.
    pub(crate) aligned_pairs: usize,
    /// Distinct reading-layer symbols touched by any chain link (coverage).
    pub(crate) symbols_touched: usize,
    /// Fixed-context TRUE-conflict aborts (bad isomorph alignments).
    true_conflict_aborts: usize,
}

/// Anchor links a held-out context exposes (non-scored) to IDENTIFY a matching train
/// action class. The remaining links are scored. `Chaining-Conflicts.md`: near
/// `S_n/S_{n-1}` edge overlap is unsafe, so identification requires the anchor to
/// agree on enough links with a UNIQUE compatible train context.
const HELD_OUT_ANCHOR_LINKS: usize = 3;

/// Minimum exact shared anchor edges a train context must match to be a candidate
/// identification for a held-out context. A single shared edge is never enough
/// (`Chaining-Conflicts.md`: edge overlap does not prove context equality).
const MIN_ANCHOR_AGREEMENT: usize = 2;

/// Minimum number of held-out SCORED links (predicted decisions) required before the
/// coverage-weighted score is meaningful; below this the model committed too little
/// to distinguish from chance and the message contributes nothing.
const MIN_HELD_OUT_COVERAGE: usize = 4;

impl EyeContextAction {
    /// Inserts one observed `from -> to` edge, returning `false` (a TRUE conflict) if
    /// it violates the partial-bijection law (two arrows out of / into one symbol).
    fn insert(&mut self, from: u8, to: u8) -> bool {
        match self.forward.get(&from) {
            Some(existing) if *existing != to => return false,
            Some(_) => return true,
            None => {}
        }
        if self.forward.iter().any(|(k, v)| *v == to && *k != from) {
            return false;
        }
        let _old = self.forward.insert(from, to);
        true
    }

    /// Number of edges where this action and `other` agree exactly on a shared
    /// source (the exact shared-edge support used for identification).
    fn shared_agreement(&self, other: &Self) -> usize {
        self.forward
            .iter()
            .filter(|(from, to)| other.forward.get(*from) == Some(*to))
            .count()
    }

    /// Whether this action CONTRADICTS `other` on any shared source (a `from` both
    /// map, to different `to`s) — the chaining incompatibility test.
    fn contradicts(&self, other: &Self) -> bool {
        self.forward.iter().any(|(from, to)| {
            other
                .forward
                .get(from)
                .is_some_and(|other_to| other_to != to)
        })
    }
}

/// EMBARGOED-CONSENSUS coverage-weighted held-out score for one message.
///
/// For each HELD-OUT context, an anchor subset of its links (the first
/// [`HELD_OUT_ANCHOR_LINKS`]) selects the EMBARGOED compatible TRAIN contexts (a
/// DIFFERENT signature group, NO physical span overlap/adjacency, agreeing on at
/// least [`MIN_ANCHOR_AGREEMENT`] anchor edges, never contradicting). A non-anchor
/// held-out edge scores only when at least [`MIN_INDEPENDENT_PROOFS`] of those train
/// contexts FROM DISTINCT SIGNATURE GROUPS AGREE on its image: a correct image is a
/// HIT, a wrong agreed image a MISS, and anything else (no consensus, too few
/// independent groups, disagreement) is AMBIGUOUS (no prediction). The score is the
/// coverage-weighted excess correctness `(A-1)*hits - A*misses (ambiguous
/// unpenalized)` with `A = 83`, so only genuinely TRANSFERABLE cross-group structure
/// scores — exactly what a within-message shuffle (no transferable structure detected
/// by this gate) cannot produce.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct HeldOutScore {
    /// Held-out links predicted correctly by the embargoed-consensus predictor.
    hits: usize,
    /// Held-out links predicted incorrectly.
    misses: usize,
    /// Held-out links with no unique confident prediction (ambiguous / uncovered).
    ambiguous: usize,
}

impl HeldOutScore {
    /// The coverage-weighted excess-correctness scalar, `A = 83`.
    ///
    /// `score = (A-1)*hits - A*misses`. A HIT is a CONFIDENT, CORRECT, UNIQUELY
    /// identified held-out prediction, worth `A-1` because under random guessing the
    /// chance of hitting the right one of `A` symbols is only `1/A`; a MISS is a
    /// CONFIDENT WRONG prediction, penalized slightly harder (`A`) so a model that
    /// commits noisily nets negative. AMBIGUOUS links (no unique identification — "I
    /// don't know") are NOT penalized: ambiguity is the honest near-`S_83` outcome,
    /// not a false claim, and a within-message shuffle produces mostly ambiguity. So
    /// genuine reusable context structure (many confident correct, few wrong) scores
    /// high; a shuffle (few confident, mostly ambiguous) scores near zero.
    ///
    /// COVERAGE CLAMP (an explicit extra gate, applied per message BEFORE the
    /// `(A-1)*hits - A*misses` statistic): below [`MIN_HELD_OUT_COVERAGE`]
    /// confident decisions (`hits + misses`) the message committed too little to be
    /// meaningful, so its coverage-weighted score is clamped to `0`. This clamp is
    /// part of the scored statistic and is documented as such in the candidate
    /// record and the CLI report; it is symmetric (applied identically to the real
    /// eyes and to every matched-null shuffle), so it cannot manufacture a
    /// real-vs-null gap.
    fn coverage_weighted(self) -> i64 {
        let decisions = self.hits.saturating_add(self.misses);
        if decisions < MIN_HELD_OUT_COVERAGE {
            return 0;
        }
        let alphabet = i64::try_from(EYE_READING_ALPHABET_SIZE).unwrap_or(i64::MAX);
        let hits = i64::try_from(self.hits).unwrap_or(i64::MAX);
        let misses = i64::try_from(self.misses).unwrap_or(i64::MAX);
        (alphabet.saturating_sub(1)).saturating_mul(hits) - alphabet.saturating_mul(misses)
    }

    /// SCOREABLE held-out edges = `hits + misses + ambiguous`: every held-out edge
    /// that entered the embargoed-consensus predictor for this population. Used to
    /// size the population-relative material-effect bar: the MAX achievable
    /// coverage-weighted score on a population is `scoreable * (A-1)` (every edge a
    /// HIT), so the bar can be a fraction of THAT, fair to whatever population is
    /// under test (the eyes, or the much larger synthetic positive control).
    fn scoreable_edges(self) -> usize {
        self.hits
            .saturating_add(self.misses)
            .saturating_add(self.ambiguous)
    }

    /// Accumulates another message's held-out counts into this aggregate.
    fn merge(&mut self, other: HeldOutScore) {
        self.hits = self.hits.saturating_add(other.hits);
        self.misses = self.misses.saturating_add(other.misses);
        self.ambiguous = self.ambiguous.saturating_add(other.ambiguous);
    }
}

/// Maximum coverage-weighted score achievable on a population with `scoreable_edges`
/// scoreable held-out edges: every edge a confident HIT, worth `A-1` each. This is
/// the population's own ceiling, so a fraction of it is a FAIR material-effect bar
/// for that population — unlike an absolute bar pinned to one population's size.
pub(crate) fn max_achievable_score(scoreable_edges: usize) -> f64 {
    let alphabet_minus_one = EYE_READING_ALPHABET_SIZE.saturating_sub(1);
    let max_edges =
        u64::try_from(scoreable_edges.saturating_mul(alphabet_minus_one)).unwrap_or(u64::MAX);
    // `as f64` on a u64 is the intended (lossy-at-extremes) conversion; the eyes'
    // and control's populations are far below the f64-exact integer range.
    max_edges as f64
}

impl EyeMessageEvidence {
    /// Scores the held-out fold against the recovered TRAIN context-action library
    /// using anchor identification + coverage-weighted excess correctness.
    fn held_out_score(&self) -> HeldOutScore {
        let mut score = HeldOutScore::default();
        for held in &self.held_out_contexts {
            self.score_one_held_out_context(held, &mut score);
        }
        score
    }

    /// Scores a held-out context with the EMBARGOED-CONSENSUS predictor.
    ///
    /// A held-out context's anchor links identify the compatible TRAIN contexts, but —
    /// crucially — only TRAIN contexts that are PROVENANCE-EMBARGOED from the held-out
    /// one: from a DIFFERENT signature group AND with no physically overlapping or
    /// adjacent occurrence span ([`ContextProvenance::touches`]). This is the leak fix:
    /// the false positive came from nested/overlapping windows (the same isomorph at
    /// length 8 vs 9, or a directly-adjacent occurrence) trivially reproducing the
    /// held-out edges — exactly the local low-entropy agreement a within-message
    /// shuffle also manufactures. Embargoing physically-overlapping and same-group
    /// train contexts forces the prediction to come from a DISTINCT, NON-ADJACENT part
    /// of the corpus, so only genuinely TRANSFERABLE structure can score. A non-anchor
    /// held-out edge scores only when at least [`MIN_INDEPENDENT_PROOFS`] embargoed
    /// train contexts (from DISTINCT signature groups) cover its source and ALL agree
    /// on the image. The `pi^k` positive control (a real recurring action) passes; the
    /// near-`S_83` eyes (no transferable structure DETECTED BY THIS GATE) do not.
    fn score_one_held_out_context(&self, held: &EyeContextAction, score: &mut HeldOutScore) {
        // Anchor = the first HELD_OUT_ANCHOR_LINKS edges (deterministic, by source).
        let mut anchor = EyeContextAction::default();
        let mut scored: Vec<(u8, u8)> = Vec::new();
        for (index, (from, to)) in held.forward.iter().enumerate() {
            if index < HELD_OUT_ANCHOR_LINKS {
                let _ok = anchor.insert(*from, *to);
            } else {
                scored.push((*from, *to));
            }
        }
        if scored.is_empty() || anchor.forward.len() < MIN_ANCHOR_AGREEMENT {
            return;
        }

        // Compatible train contexts, EMBARGOED: a different signature group AND no
        // physical span overlap/adjacency with the held-out context, agreeing on
        // >= MIN_ANCHOR_AGREEMENT anchor edges and never contradicting the anchor.
        let compatible: Vec<&EyeContextAction> = self
            .train_contexts
            .iter()
            .filter(|train| {
                train.provenance.signature_id != held.provenance.signature_id
                    && !train.provenance.touches(held.provenance)
                    && train.shared_agreement(&anchor) >= MIN_ANCHOR_AGREEMENT
                    && !train.contradicts(&anchor)
            })
            .collect();
        if compatible.is_empty() {
            score.ambiguous = score.ambiguous.saturating_add(scored.len());
            return;
        }

        for (from, to) in scored {
            match predict_by_embargoed_consensus(&compatible, from) {
                Prediction::Confident(image) if image == to => {
                    score.hits = score.hits.saturating_add(1);
                }
                Prediction::Confident(_) => score.misses = score.misses.saturating_add(1),
                Prediction::None => score.ambiguous = score.ambiguous.saturating_add(1),
            }
        }
    }
}

/// Minimum number of DISTINCT-signature-group embargoed train contexts that must
/// cover a held-out source and agree on its image before it scores. Two independent
/// contexts agreeing is strong evidence of transferable structure; a single one could
/// be coincidence.
const MIN_INDEPENDENT_PROOFS: usize = 2;

/// A held-out-source prediction outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Prediction {
    /// At least [`MIN_INDEPENDENT_PROOFS`] embargoed train contexts from DISTINCT
    /// signature groups agree on this image.
    Confident(u8),
    /// No confident prediction (too few independent contexts, or they disagree).
    None,
}

/// Predicts a held-out source from the EMBARGOED compatible train contexts: returns
/// [`Prediction::Confident`] only when at least [`MIN_INDEPENDENT_PROOFS`] contexts
/// from DISTINCT signature groups cover the source and ALL agree on the image (any
/// disagreement among the embargoed contexts ⇒ [`Prediction::None`]). Requiring the
/// agreement across DISTINCT signature groups (not just distinct contexts) is what
/// makes the prediction reflect transferable structure rather than the recurrence of a
/// single local isomorph.
fn predict_by_embargoed_consensus(compatible: &[&EyeContextAction], from: u8) -> Prediction {
    let mut image: Option<u8> = None;
    let mut groups: BTreeSet<u64> = BTreeSet::new();
    for train in compatible {
        if let Some(&predicted) = train.forward.get(&from) {
            match image {
                Some(existing) if existing != predicted => return Prediction::None,
                _ => image = Some(predicted),
            }
            let _new = groups.insert(train.provenance.signature_id);
        }
    }
    match image {
        Some(value) if groups.len() >= MIN_INDEPENDENT_PROOFS => Prediction::Confident(value),
        _ => Prediction::None,
    }
}

/// Distills the TRAIN/HELD-OUT chain-link evidence from one eye message.
///
/// Isomorph occurrences are found by grouping every window (over the Thread-3
/// window range) by its [`PatternSignature`]; each signature group with ≥2
/// repeat-bearing occurrences is an isomorph (one distinct context family). The
/// SIGNATURE GROUPS are split deterministically (by a stable hash of the rendered
/// signature) into TRAIN and HELD-OUT — so train and held-out are DISJOINT
/// contexts, the strict out-of-sample regime. Within a TRAIN group, ordered
/// occurrence pairs become fixed contexts whose chain links come straight from
/// [`chain_links_for_pair`]; a non-functional fixed-context action (two arrows out
/// of / into one symbol under ONE alignment) is a TRUE conflict — a bad isomorph
/// alignment — dropped and counted, never a discovery. Train edges feed the
/// recovered model's `from -> {to}` image sets; HELD-OUT group chain links are the
/// validation set.
///
/// `safe_filter` restricts which isomorph occurrence windows are admitted: a
/// window is only used when [`SafeWindowFilter::admits`] accepts its `[start, end)`,
/// so on the real eyes chaining stays WITHIN Thread-3's safe isomorph extents and
/// never over-extends. The synthetic positive control passes the unrestricted filter.
/// The restriction is positional, so the matched within-message shuffle null (which
/// preserves positions) sees the identical admissibility — the null stays symmetric.
pub(crate) fn eyes_message_evidence(
    values: &[TrigramValue],
    safe_filter: SafeWindowFilter<'_>,
) -> EyeMessageEvidence {
    let mut evidence = EyeMessageEvidence::default();
    let mut touched: BTreeSet<u8> = BTreeSet::new();
    let mut context_index: u32 = 0;

    for window_len in EYE_ISOMORPH_MIN_WINDOW..=EYE_ISOMORPH_MAX_WINDOW {
        if values.len() < window_len {
            continue;
        }
        let mut by_signature: BTreeMap<PatternSignature, Vec<usize>> = BTreeMap::new();
        for (start, window) in values.windows(window_len).enumerate() {
            // Admit a window only when it lies within a Thread-3 safe extent (the
            // real eyes); the synthetic control's unrestricted filter admits every
            // window. Applied BEFORE signature grouping so chaining never sees an
            // over-extended occurrence.
            if !safe_filter.admits((start, start.saturating_add(window_len))) {
                continue;
            }
            let signature = PatternSignature::from_window(window);
            if signature.has_repeated_symbol() {
                by_signature.entry(signature).or_default().push(start);
            }
        }
        for (signature, starts) in &by_signature {
            // Spacing-filter coincidental overlaps (same discipline as the deck
            // substrate): genuine isomorph occurrences are ≥window apart.
            let filtered = spacing_filter(starts, window_len);
            if filtered.len() < 2 {
                continue;
            }
            evidence.isomorph_groups = evidence.isomorph_groups.saturating_add(1);
            // WHOLE-GROUP fold assignment (strict, out-of-sample): the entire
            // signature group is TRAIN or HELD-OUT, so train and held-out are
            // disjoint context families. The split is a stable hash of the rendered
            // signature (reproducible, no clock, balanced across the corpus).
            let signature_id = signature_fold_hash(signature, window_len);
            let is_held_out = HELD_OUT_STRIDE != 0
                && usize::try_from(signature_id)
                    .unwrap_or(0)
                    .is_multiple_of(HELD_OUT_STRIDE);
            for (left_index, &upper_start) in filtered.iter().enumerate() {
                for &lower_start in filtered.iter().skip(left_index.saturating_add(1)) {
                    let (Some(upper_window), Some(lower_window)) = (
                        values.get(upper_start..upper_start.saturating_add(window_len)),
                        values.get(lower_start..lower_start.saturating_add(window_len)),
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
                    let Ok(links) = chain_links_for_pair(context, &upper, &lower) else {
                        continue;
                    };
                    // Build ONE context-colored partial action from this occurrence
                    // pair (Graph-Chaining.md). A fixed-context TRUE conflict (two
                    // arrows out of / into one symbol under ONE alignment) is a bad
                    // isomorph alignment (Chaining-Conflicts.md): dropped, counted,
                    // never a discovery.
                    let mut action = EyeContextAction {
                        forward: BTreeMap::new(),
                        provenance: ContextProvenance {
                            signature_id,
                            upper: (upper_start, upper_start.saturating_add(window_len)),
                            lower: (lower_start, lower_start.saturating_add(window_len)),
                        },
                    };
                    let mut conflicted = false;
                    for link in &links {
                        let _ins = touched.insert(link.from.get());
                        let _ins = touched.insert(link.to.get());
                        if !action.insert(link.from.get(), link.to.get()) {
                            conflicted = true;
                            break;
                        }
                    }
                    if conflicted {
                        evidence.true_conflict_aborts =
                            evidence.true_conflict_aborts.saturating_add(1);
                        continue;
                    }
                    evidence.aligned_pairs = evidence.aligned_pairs.saturating_add(1);
                    if is_held_out {
                        evidence.held_out_contexts.push(action);
                    } else {
                        evidence.train_contexts.push(action);
                    }
                }
            }
        }
    }
    evidence.symbols_touched = touched.len();
    evidence
}

/// A stable, clock-free fold hash for a signature group (the rendered equality
/// pattern + window length). Used to assign WHOLE isomorph groups to the TRAIN or
/// HELD-OUT fold reproducibly and roughly evenly.
fn signature_fold_hash(signature: &PatternSignature, window_len: usize) -> u64 {
    let mut hash: u64 = 0x9e37_79b9_7f4a_7c15 ^ window_len as u64;
    for &value in signature.values() {
        hash = hash
            .wrapping_mul(0x0100_0000_01b3)
            .wrapping_add(value as u64 + 1);
    }
    stateless_splitmix(hash)
}

/// The safe-span restriction for one population's aggregate held-out scoring.
///
/// `PerMessage(spans)` (the real eyes) applies the Thread-3 safe filter to each
/// message by index; `Unrestricted` (the synthetic positive control, a single
/// non-corpus fixture) admits every window so the detector is validated on its full
/// known signal.
#[derive(Clone, Copy, Debug)]
pub(crate) enum AggregateSafeFilter<'a> {
    /// Restrict each message by its Thread-3 safe spans (in `message_values` order).
    PerMessage(&'a [Vec<(usize, usize)>]),
    /// Admit every window (synthetic positive control only).
    Unrestricted,
}

impl<'a> AggregateSafeFilter<'a> {
    /// The filter for the message at `index` (unrestricted control, or this message's
    /// Thread-3 safe spans — an absent index restricts to no admitted window).
    fn for_message(self, index: usize) -> SafeWindowFilter<'a> {
        match self {
            AggregateSafeFilter::Unrestricted => SafeWindowFilter::unrestricted(),
            AggregateSafeFilter::PerMessage(spans_by_message) => spans_by_message
                .get(index)
                .map_or(SafeWindowFilter::restrict(&[]), |spans| {
                    SafeWindowFilter::restrict(spans.as_slice())
                }),
        }
    }
}

/// Scores the aggregate held-out outcome across all messages for one (possibly
/// shuffled) corpus, using the IDENTICAL per-message pipeline and safe-span filter.
///
/// Returns the aggregate [`HeldOutScore`] (hits / misses / ambiguous), from which the
/// scalar coverage-weighted score is recomputed per message so the real eyes and each
/// matched-null shuffle are scored identically. Surfacing the aggregate counts also
/// gives the population's SCOREABLE-edge total, which sizes the material-effect bar
/// (a fraction of the population's own max achievable score).
fn eyes_aggregate_held_out(
    message_values: &[Vec<TrigramValue>],
    safe_filter: AggregateSafeFilter<'_>,
) -> HeldOutScore {
    let mut aggregate = HeldOutScore::default();
    for (index, values) in message_values.iter().enumerate() {
        let evidence = eyes_message_evidence(values, safe_filter.for_message(index));
        aggregate.merge(evidence.held_out_score());
    }
    aggregate
}

/// Scores the aggregate REAL coverage-weighted held-out score across all messages for
/// one (possibly shuffled) corpus, using the IDENTICAL per-message pipeline.
///
/// The score rewards CONFIDENT, CORRECT, UNIQUE held-out predictions and penalizes
/// ambiguity — a corpus with genuine reusable context structure scores high; a
/// within-message shuffle (no reusable context classes) scores near zero / negative.
/// The coverage clamp is applied PER MESSAGE (so it stays symmetric across real and
/// null), hence the per-message recomputation rather than clamping the aggregate.
pub(crate) fn eyes_aggregate_score(
    message_values: &[Vec<TrigramValue>],
    safe_filter: AggregateSafeFilter<'_>,
) -> i64 {
    let mut total: i64 = 0;
    for (index, values) in message_values.iter().enumerate() {
        let evidence = eyes_message_evidence(values, safe_filter.for_message(index));
        total = total.saturating_add(evidence.held_out_score().coverage_weighted());
    }
    total
}

/// Runs the matched within-message shuffle null for the eyes held-out gate.
///
/// Each trial shuffles every message's symbol multiset in place (`fisher_yates`
/// over a clone — multiset and length conserved, only arrangement varies, exactly
/// the `isomorph_null` discipline) and re-runs the IDENTICAL aggregate held-out
/// pipeline. Returns `(null_at_least_real, null_mean_score)`: how many trials had
/// aggregate coverage-weighted score at least the real aggregate (the matched-null
/// upper tail), and the mean null score. A high count / comparable mean means the
/// real eyes do NOT beat the null — the expected outcome.
///
/// # Errors
/// Returns [`GakAttackError`] if a shuffle draw bound does not fit the PRNG.
pub(super) fn eyes_matched_null_tail(
    message_values: &[Vec<TrigramValue>],
    config: &EyesAttackConfig,
    safe_spans_by_message: &[Vec<(usize, usize)>],
    real_score: i64,
) -> Result<(usize, f64), GakAttackError> {
    // The caller guarantees `config.trials >= 1` (the EyesZeroTrials guard), so the
    // null mean is always defined over a non-empty sample.
    let mut null_at_least_real = 0usize;
    let mut null_sum: i128 = 0;
    for trial in 0..config.trials {
        let mut rng = SplitMix64::new(mix_seed(
            config.seed,
            0x6579_6573_6e75_6c6c ^ u64::try_from(trial).unwrap_or(u64::MAX),
        ));
        let mut shuffled = message_values.to_vec();
        for values in &mut shuffled {
            fisher_yates(values, &mut rng)?;
        }
        // The shuffle preserves positions, so the SAME Thread-3 safe spans apply —
        // the null is scored under the identical safe-extent restriction (symmetric).
        let null_score = eyes_aggregate_score(
            &shuffled,
            AggregateSafeFilter::PerMessage(safe_spans_by_message),
        );
        null_sum = null_sum.saturating_add(i128::from(null_score));
        if null_score >= real_score {
            null_at_least_real = null_at_least_real.saturating_add(1);
        }
    }
    let trials = config.trials.max(1);
    let null_mean = null_sum as f64 / trials as f64;
    Ok((null_at_least_real, null_mean))
}

/// Runs the held-out POSITIVE CONTROL on a SYNTHETIC isomorph-rich eye-shaped
/// fixture: the predictor must fire on KNOWN signal.
///
/// The fixture (see [`synthetic_isomorph_rich_eye_message`]) carries a FIXED global
/// action `pi` recurring across isomorph groups, so train context classes recur and
/// held-out anchors uniquely identify them. The same per-message held-out pipeline
/// must give a real coverage-weighted score that strictly beats the worst-case
/// (max) matched within-message shuffle null over the control trials AND clears the
/// control's OWN population-relative material-effect bar (a fraction of the
/// control's max achievable score). If it does not fire, the held-out gate is not
/// trustworthy. The fixture is scored UNRESTRICTED (it is not a corpus message and
/// has no Thread-3 safe extent), so the detector is validated on its full known
/// signal.
///
/// # Errors
/// Returns [`GakAttackError`] if a generated value is out of range or a shuffle
/// bound does not fit the PRNG.
pub(crate) fn eyes_held_out_positive_control(
    config: &EyesAttackConfig,
) -> Result<HeldOutPositiveControl, GakAttackError> {
    let fixture = synthetic_isomorph_rich_eye_message(config.seed)?;
    let fixture_slice = std::slice::from_ref(&fixture);
    let real_aggregate = eyes_aggregate_held_out(fixture_slice, AggregateSafeFilter::Unrestricted);
    let real_score = eyes_aggregate_score(fixture_slice, AggregateSafeFilter::Unrestricted);
    let scoreable_edges = real_aggregate.scoreable_edges();

    // Worst-case (max) matched within-message null score over the control trials.
    let mut null_score = i64::MIN;
    let control_trials = config.trials.clamp(1, POSITIVE_CONTROL_NULL_TRIALS);
    for trial in 0..control_trials {
        let mut rng = SplitMix64::new(mix_seed(
            config.seed,
            0x7063_5f73_796e_7468 ^ u64::try_from(trial).unwrap_or(u64::MAX),
        ));
        let mut shuffled = fixture.clone();
        fisher_yates(&mut shuffled, &mut rng)?;
        let trial_score = eyes_aggregate_score(
            std::slice::from_ref(&shuffled),
            AggregateSafeFilter::Unrestricted,
        );
        if trial_score > null_score {
            null_score = trial_score;
        }
    }
    // FIRE: the real signal's coverage-weighted score strictly beats
    // the WORST-CASE null over the control trials AND its real-vs-null excess clears
    // the control's OWN population-relative material-effect bar — the SAME fair gate
    // the eyes are judged against, so the bar is proven achievable by genuine signal.
    let control_excess =
        f64::from(i32::try_from(real_score.saturating_sub(null_score)).unwrap_or(i32::MAX));
    let control_bar = EYES_MATERIAL_EFFECT_FRACTION * max_achievable_score(scoreable_edges);
    let fired = real_score > null_score && real_score > 0 && control_excess >= control_bar;
    Ok(HeldOutPositiveControl {
        real_score,
        null_score,
        scoreable_edges,
        fired,
    })
}

/// Number of matched-null trials used for the held-out positive control (kept small
/// so the control is fast; the control is a fire/no-fire check, not a headline).
const POSITIVE_CONTROL_NULL_TRIALS: usize = 64;

/// Builds a synthetic isomorph-rich, GLOBALLY-CONSISTENT eye-shaped message for the
/// held-out positive control.
///
/// The fixture stacks several blocks that are copies of one random base block, each
/// advanced by the SAME fixed alphabet bijection `pi` (block `k` is `pi^k(base)`).
/// Aligned occurrences of the same equality pattern across blocks are therefore
/// related by a FIXED, GLOBALLY CONSISTENT, SINGLE-VALUED chain-link action
/// (`from -> to = pi^d` for block gap `d`) — exactly the transferable structure the
/// strict held-out test detects: a `from -> to` recovered from a TRAIN signature
/// group predicts DISJOINT HELD-OUT groups, and a within-message shuffle destroys it
/// (the matched null cannot reproduce a consistent `pi`). All values stay inside the
/// reading-layer range.
///
/// # Errors
/// Returns [`GakAttackError`] if a generated value exceeds the reading-layer range.
pub(crate) fn synthetic_isomorph_rich_eye_message(
    seed: u64,
) -> Result<Vec<TrigramValue>, GakAttackError> {
    let alphabet = EYE_READING_ALPHABET_SIZE;
    let mut rng = SplitMix64::new(mix_seed(seed, 0x6579_6573_6669_7874));
    // The fixed alphabet bijection pi: the GLOBAL, consistent chain-link action.
    // pi is NEAR-IDENTITY (a small, fixed number of transpositions over the FIRST
    // few alphabet symbols) so that pi^d acts on a SMALL, STABLE support: the same
    // compact action recurs IDENTICALLY across many well-separated blocks and yields
    // robust cross-group consensus (the embargoed predictor needs >= 2 distinct
    // non-overlapping signature groups to agree). A full random pi would scramble the
    // whole alphabet after a few steps and make cross-group consensus seed-fragile.
    let mut pi: Vec<usize> = (0..alphabet).collect();
    for k in 0..4usize {
        // Transpose adjacent low symbols: a tiny, deterministic, seed-independent
        // support so the action class is stable across every seed.
        let i = (2 * k) % alphabet;
        let j = (2 * k + 1) % alphabet;
        pi.swap(i, j);
    }

    // A random base block over the SMALL support region plus internal repeats so its
    // windows are repeat-bearing isomorphs that pi acts on non-trivially.
    let support = 12usize;
    let block_len = 18usize;
    let mut base: Vec<usize> = Vec::with_capacity(block_len);
    for _ in 0..block_len {
        // Draw from the small support region so pi acts on most of the block.
        let v = (random_index_below(support, &mut rng)?).min(alphabet.saturating_sub(1));
        base.push(v);
    }
    if let (Some(a), Some(slot)) = (base.first().copied(), base.get_mut(6)) {
        *slot = a;
    }
    if let (Some(a), Some(slot)) = (base.get(3).copied(), base.get_mut(11)) {
        *slot = a;
    }
    if let (Some(a), Some(slot)) = (base.get(2).copied(), base.get_mut(15)) {
        *slot = a;
    }

    // Stack MANY blocks block_k = pi^k(base) so the same pi^d action recurs across a
    // dozen+ well-separated, DISTINCT signature groups (robust cross-group consensus).
    // A short random spacer separates blocks so the boundary does not forge a spurious
    // long isomorph.
    let blocks = 16usize;
    let mut raw: Vec<usize> = Vec::new();
    let mut current = base;
    for block in 0..blocks {
        if block > 0 {
            raw.push(support.saturating_add(block % 8));
            current = current
                .iter()
                .map(|&v| pi.get(v).copied().unwrap_or(v))
                .collect();
        }
        raw.extend_from_slice(&current);
    }

    let mut values = Vec::with_capacity(raw.len());
    for v in raw {
        let raw_value =
            u8::try_from(v).map_err(|_error| GakAttackError::SymbolOutOfRange { value: v })?;
        let value =
            TrigramValue::new(raw_value).map_err(|bad| GakAttackError::SymbolOutOfRange {
                value: usize::from(bad),
            })?;
        values.push(value);
    }
    Ok(values)
}

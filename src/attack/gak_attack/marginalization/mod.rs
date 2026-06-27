//! Hidden-state marginalization (idea 3) and the TENTATIVE small-support prior.
//!
//! The beam-search column recovery (`beam_recover_column`, `split_column_evidence`)
//! and the marginalization sweep that brief 04 reuses live here; they build on the
//! deck attack's `CosetEdge`/`mean_f64`/`generate_deck_fixture` primitives from the
//! `solver` sibling.

use super::*;

// =====================================================================
// UNIT 2b — HIDDEN-STATE MARGINALIZATION (idea 3) + SMALL-SUPPORT PRIOR (idea 2).
//
// Unit 2a measured the obstruction: under non-trivial H the per-letter visible-
// coset action is ~multi-valued across hidden states, and the 2a baseline recovers
// only each column's SINGLE-VALUED CORE (the `from` cosets that map exactly one way
// across every observed hidden state). Everything multi-valued is DISCARDED there.
//
// The key empirical fact this unit exploits (validated on the generator): within ONE
// aligned phrase column every observed `(from -> to)` edge is PRODUCED BY THE SAME
// plaintext letter — it is just a different BRANCH of that letter's action under a
// different hidden state. So the multi-valuedness is normal hidden-state variation,
// and the recoverable object is the per-letter UNION of coset edges (the marginal
// over hidden states), NOT a single permutation (impossible for |H|>1).
//
// Idea 3 recovers that marginal HONESTLY — without peeking at ground truth — by a
// bounded BEAM / belief-propagation over the hidden-state branches, scored by
// HELD-OUT chain links (a TRAIN/HELD-OUT split of the same column's occurrences):
// a beam admits the train branches that GENERALIZE to held-out branches and prunes
// the rest. The small-support prior (idea 2) plugs in as a SOFT pruning penalty.
//
// The MEASURED deliverable: idea-3 edge-recovery fraction vs the 2a single-valued
// core vs the matched null, swept over n — does marginalization recover MORE, and
// where does it break as the hidden-state count `(n-1)!` grows? An honest
// "helps on small n, breaks by n=X" is the expected, reportable outcome.
// =====================================================================

mod beam;

pub use beam::{DEFAULT_BEAM_WIDTH, SmallSupportPrior};
pub(crate) use beam::{HELD_OUT_STRIDE, run_marginalization_attack};
use beam::{baseline_edge_recovery, marginal_edge_recovery};
// Beam internals the sibling test module (`super::tests`) reaches through the
// `gak_attack` glob; only the test build references them, so the re-export is
// gated to keep the lib build free of unused imports.
#[cfg(test)]
pub(crate) use beam::{
    SplitColumnEvidence, beam_recover_column, single_valued_core_of_split, split_column_evidence,
};

/// One idea-3 marginalization outcome on one independent seed, with its matched null
/// and the 2a baseline, all at EDGE granularity over the same truth denominator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarginalizationOutcome {
    /// Deck size `n` (`|C| = n`).
    pub state_size: usize,
    /// Hidden-subgroup order `|H| = (n-1)!`.
    pub hidden_subgroup_order: u128,
    /// Seed used to build the fixture.
    pub seed: u64,
    /// TRUE per-letter coset edges recovered by idea-3 marginalization (real stream).
    pub idea3_true_edges: usize,
    /// TRUE per-letter coset edges recovered by the 2a single-valued-core baseline
    /// (real stream) — the thing idea 3 must beat to justify existing.
    pub baseline_true_edges: usize,
    /// TRUE per-letter coset edges the idea-3 pipeline recovered on the matched
    /// within-message shuffle null (must stay ~0).
    pub null_true_edges: usize,
    /// Total truth edges (the denominator, shared by all three).
    pub truth_edges_total: usize,
    /// Beam width bound used (disclosed, no silent truncation).
    pub beam_width: usize,
    /// Beams pruned by the width bound on the real stream (disclosed).
    pub beams_dropped: usize,
    /// Whether the small-support prior (idea 2) was applied.
    pub prior_on: bool,
}

impl MarginalizationOutcome {
    /// Idea-3 marginalization edge-recovery fraction (`0.0` if no truth edges).
    #[must_use]
    pub fn idea3_fraction(self) -> f64 {
        fraction(self.idea3_true_edges, self.truth_edges_total)
    }

    /// 2a single-valued-core baseline edge-recovery fraction.
    #[must_use]
    pub fn baseline_fraction(self) -> f64 {
        fraction(self.baseline_true_edges, self.truth_edges_total)
    }

    /// Matched-null edge-recovery fraction (must stay ~0).
    #[must_use]
    pub fn null_fraction(self) -> f64 {
        fraction(self.null_true_edges, self.truth_edges_total)
    }
}

/// Evaluates idea-3 marginalization on one deck fixture and its matched within-
/// message shuffle null over the IDENTICAL pipeline (matched-null symmetry: the same
/// `run_marginalization_attack`, same phrase length, same beam width, same prior,
/// same population — only the structure differs).
pub(crate) fn evaluate_marginalization_fixture(
    fixture: &DeckFixture,
    config: GakAttackConfig,
    seed: u64,
    beam_width: usize,
    prior: SmallSupportPrior,
) -> Result<MarginalizationOutcome, GakAttackError> {
    let ciphertext_values = glyphs_to_values(&fixture.ciphertext)?;
    let truth = truth_coset_edges(&fixture.key, &fixture.plaintext)?;
    let truth_edges_total: usize = truth.iter().map(BTreeSet::len).sum();
    let phrase_len = config.phrase_len;

    // Real pipeline.
    let real = run_marginalization_attack(&ciphertext_values, phrase_len, beam_width, prior);
    let (idea3_true_edges, _) = marginal_edge_recovery(&truth, &real.recovered_columns);
    let (baseline_true_edges, _) = baseline_edge_recovery(&truth, &real.baseline_columns);

    // Matched null: the SAME marginalization pipeline over a within-message
    // Fisher-Yates shuffle of the SAME ciphertext, scored against the SAME truth.
    let mut rng = SplitMix64::new(mix_seed(seed, 0x6d61_7267_6e75_6c6c));
    let mut shuffled = ciphertext_values.clone();
    fisher_yates(&mut shuffled, &mut rng)?;
    let null = run_marginalization_attack(&shuffled, phrase_len, beam_width, prior);
    let (null_true_edges, _) = marginal_edge_recovery(&truth, &null.recovered_columns);

    Ok(MarginalizationOutcome {
        state_size: fixture.state_size,
        hidden_subgroup_order: fixture.hidden_subgroup_order,
        seed,
        idea3_true_edges,
        baseline_true_edges,
        null_true_edges,
        truth_edges_total,
        beam_width,
        beams_dropped: real.beams_dropped,
        prior_on: prior.is_on(),
    })
}

/// The measured idea-3 result at one deck size `n`: marginalization vs the 2a
/// baseline vs the matched null, aggregated over independent seeds, with the
/// matched-null p-value and the disclosed beam width / dropped-beam total.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MarginalizationPoint {
    /// Deck size `n` (`|C| = n`).
    pub state_size: usize,
    /// Hidden-subgroup order `|H| = (n-1)!`.
    pub hidden_subgroup_order: u128,
    /// Independent seeds aggregated at this `n`.
    pub seeds: usize,
    /// TRUE per-letter coset edges recovered by idea-3 marginalization, summed.
    pub idea3_true_total: usize,
    /// TRUE per-letter coset edges recovered by the 2a baseline, summed.
    pub baseline_true_total: usize,
    /// TRUE per-letter coset edges recovered by the matched null, summed (~0).
    pub null_true_total: usize,
    /// Total truth edges summed (the shared denominator).
    pub truth_edges_total: usize,
    /// Mean idea-3 edge-recovery fraction over the seeds.
    pub idea3_mean_fraction: f64,
    /// Mean 2a baseline edge-recovery fraction over the seeds.
    pub baseline_mean_fraction: f64,
    /// Mean matched-null edge-recovery fraction over the seeds.
    pub null_mean_fraction: f64,
    /// Whether idea-3 recovered strictly MORE true edges than the 2a baseline here
    /// (the reason idea 3 exists — reported honestly per `n`).
    pub idea3_beats_baseline: bool,
    /// Whether idea-3 recovered strictly more true edges than the matched null here.
    pub idea3_beats_null: bool,
    /// Add-one Monte-Carlo p-value: how often a null seed's idea-3 fraction is at
    /// least the matched real seed's. Small means real beats null.
    pub matched_null_p_value: f64,
    /// Beam width bound used at this `n` (disclosed).
    pub beam_width: usize,
    /// Total beams pruned by the width bound at this `n` (disclosed — no silent
    /// truncation).
    pub beams_dropped: usize,
}

/// The complete idea-3 (hidden-state marginalization) report: the per-`n`
/// marginalization-vs-baseline-vs-null tractability bound, plus the small-support
/// prior validation (idea 2).
#[derive(Clone, Debug, PartialEq)]
pub struct MarginalizationReport {
    /// The deck letter regime swept.
    pub regime: DeckLetterRegime,
    /// The small-support prior toggle used for the headline sweep.
    pub prior: SmallSupportPrior,
    /// The beam width bound used (disclosed).
    pub beam_width: usize,
    /// Per-seed marginalization outcomes across the swept `n` × seed matrix.
    pub outcomes: Vec<MarginalizationOutcome>,
    /// The measured per-`n` bound: idea-3 vs 2a baseline vs null, and where it breaks.
    pub points: Vec<MarginalizationPoint>,
    /// Whether idea-3 recovered strictly MORE true edges than the 2a baseline on the
    /// EASIEST (smallest) swept `n` — the go/no-go for this unit.
    pub beats_baseline_on_easiest: bool,
    /// Whether idea-3 beat its matched null on the easiest swept `n`.
    pub beats_null_on_easiest: bool,
    /// The smallest swept deck size (the easiest fixture).
    pub easiest_state_size: usize,
    /// The small-support prior validation result (idea 2): does the prior help when
    /// the truth has small support, and fail gracefully when it does not.
    pub small_support_validation: SmallSupportValidation,
}

/// The TENTATIVE small-support prior validation (idea 2).
///
/// Generated WITH and WITHOUT small-support truth, with the prior ON and OFF in
/// each, this measures whether the prior (a) selectively HELPS recovery when the
/// truth genuinely has small support and (b) FAILS GRACEFULLY / is detectably wrong
/// when it does not. Both EDGE-RECALL (true edges recovered) and EDGE-PRECISION
/// (true / admitted edges) are recorded so the graceful-failure property is
/// measurable, not just asserted. All numbers are on SYNTHETIC ground truth; the
/// prior is **TENTATIVE everywhere**.
///
/// ## What this realization measures (the honest finding)
///
/// In the deck stabilizer realization the prior's confidence floor improves
/// PRECISION at a RECALL cost in BOTH conditions, retaining slightly more recall on
/// genuinely small-support truth than on unconstrained truth — i.e. the near-identity
/// small-support structure of the per-letter PERMUTATIONS survives only WEAKLY into
/// the visible-coset MARGINAL (the hidden-state cycling spreads the marked card), so
/// the prior is at most **WEAKLY / TENTATIVELY discriminative** here (a thin
/// retention margin, e.g. ~0.44 vs ~0.41). The load-bearing property is that it still
/// FAILS GRACEFULLY (it only ever drops genuine low-support edges, never invents any).
/// The prior is designed to, and is measured on the bundled aggregate to, not lower
/// precision; that is a fixture-conditional measurement, not a structural guarantee
/// (a wrong small-support assumption is never rewarded).
/// The weak discrimination is a measured, FLAGGED, TENTATIVE outcome — reported with
/// its thin margin, never faked into a strong positive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SmallSupportValidation {
    /// Deck size used for the validation.
    pub state_size: usize,
    /// Independent seeds aggregated.
    pub seeds: usize,
    /// Small-support truth, prior OFF: TRUE edges recovered (recall numerator).
    pub small_truth_prior_off: usize,
    /// Small-support truth, prior ON: TRUE edges recovered.
    pub small_truth_prior_on: usize,
    /// Small-support truth, prior OFF: TOTAL admitted edges (precision denominator).
    pub small_admitted_off: usize,
    /// Small-support truth, prior ON: TOTAL admitted edges (precision denominator).
    pub small_admitted_on: usize,
    /// Unconstrained (non-small-support) truth, prior OFF: TRUE edges recovered.
    pub broad_truth_prior_off: usize,
    /// Unconstrained truth, prior ON: TRUE edges recovered.
    pub broad_truth_prior_on: usize,
    /// Unconstrained truth, prior OFF: TOTAL admitted edges.
    pub broad_admitted_off: usize,
    /// Unconstrained truth, prior ON: TOTAL admitted edges.
    pub broad_admitted_on: usize,
    /// Total truth edges in the small-support condition (recall denominator).
    pub small_truth_total: usize,
    /// Total truth edges in the unconstrained condition (recall denominator).
    pub broad_truth_total: usize,
}

impl SmallSupportValidation {
    /// Edge-precision (true / admitted) for the small-support condition with the
    /// prior `on`. The prior is designed to, and is measured on the bundled aggregate
    /// to, not lower precision (it only drops genuine low-support edges, never invents
    /// any) — a fixture-conditional measurement, not a structural guarantee.
    #[must_use]
    pub fn small_precision(self, on: bool) -> f64 {
        if on {
            fraction(self.small_truth_prior_on, self.small_admitted_on)
        } else {
            fraction(self.small_truth_prior_off, self.small_admitted_off)
        }
    }

    /// Edge-precision (true / admitted) for the unconstrained condition with the
    /// prior `on`.
    #[must_use]
    pub fn broad_precision(self, on: bool) -> f64 {
        if on {
            fraction(self.broad_truth_prior_on, self.broad_admitted_on)
        } else {
            fraction(self.broad_truth_prior_off, self.broad_admitted_off)
        }
    }

    /// Whether the prior FAILS GRACEFULLY, as captured by this predicate: TRUE-edge
    /// recall with the prior ON is `<=` recall with it OFF in BOTH the small-support
    /// and unconstrained conditions. That is exactly what this checks — the confidence
    /// floor can only DROP genuine low-support edges, never invent new true ones, and
    /// in particular it does not boost recall on unconstrained (wrong-assumption)
    /// truth. The complementary precision-holds property (that dropping low-support
    /// edges does not lower precision) is a SEPARATE measurement reported via
    /// [`Self::small_precision`] / [`Self::broad_precision`]; it is NOT asserted by
    /// this predicate.
    #[must_use]
    pub const fn prior_fails_gracefully(self) -> bool {
        self.small_truth_prior_on <= self.small_truth_prior_off
            && self.broad_truth_prior_on <= self.broad_truth_prior_off
    }

    /// Whether the prior is SELECTIVELY DISCRIMINATIVE — i.e. it helps small-support
    /// truth MORE than unconstrained truth (the prior's recall-retention on small
    /// support strictly exceeds its recall-retention on broad). In the deck
    /// realization this holds only WEAKLY / TENTATIVELY: the near-identity structure
    /// survives just thinly into the visible-coset marginal (e.g. ~0.44 vs ~0.41
    /// retention), so the margin is real but slim. Reporting it as a WEAK, TENTATIVE
    /// signal is the measured, FLAGGED validation outcome — never inflated into a
    /// strong positive; the graceful-failure property is the load-bearing result.
    #[must_use]
    pub fn prior_is_discriminative(self) -> bool {
        let small_retention =
            fraction(self.small_truth_prior_on, self.small_truth_prior_off.max(1));
        let broad_retention =
            fraction(self.broad_truth_prior_on, self.broad_truth_prior_off.max(1));
        small_retention > broad_retention
    }
}

/// Default deck size used for the small-support prior validation. Small enough that
/// the near-identity small-support letters stay distinguishable.
const SMALL_SUPPORT_VALIDATION_STATE_SIZE: usize = 6;

/// TENTATIVE small-support transposition radius used to GENERATE the small-support
/// fixtures (each letter is the base composed with `<= radius` transpositions).
const SMALL_SUPPORT_VALIDATION_RADIUS: usize = 2;

/// TENTATIVE minimum train-support floor the prior imposes when ON during the
/// validation: a candidate edge must recur in at least this many train occurrences.
const SMALL_SUPPORT_VALIDATION_MIN_SUPPORT: usize = 2;

/// Runs the idea-3 hidden-state marginalization sweep + the idea-2 small-support
/// validation.
///
/// For each `n` in `state_sizes` it draws `config.seeds_per_kind` independent seeds,
/// generates a deck fixture (held-back ground truth), runs idea-3 marginalization
/// and its matched within-message shuffle null over the IDENTICAL pipeline, and
/// aggregates the EDGE-recovery totals for idea-3, the 2a single-valued-core
/// baseline, and the null. It then runs the small-support validation (idea 2):
/// fixtures WITH and WITHOUT small-support truth, prior ON and OFF.
///
/// The `prior` selects the small-support toggle for the headline sweep; `beam_width`
/// is the disclosed bound. A low or DECREASING idea-3 fraction as `n` grows is the
/// EXPECTED, REPORTABLE outcome (the marginalization breaks as the hidden-state count
/// `(n-1)!` grows), not an error.
///
/// # Errors
/// Returns [`GakAttackError`] when the configuration is invalid, when a fixture's
/// key/stream is rejected, or when a symbol cannot be represented.
pub fn run_marginalization_sweep(
    config: GakAttackConfig,
    regime: DeckLetterRegime,
    state_sizes: &[usize],
    beam_width: usize,
    prior: SmallSupportPrior,
) -> Result<MarginalizationReport, GakAttackError> {
    if config.seeds_per_kind == 0 {
        return Err(GakAttackError::ZeroSeeds);
    }
    if config.phrase_repeats == 0 || config.phrase_len == 0 {
        return Err(GakAttackError::EmptyTemplate);
    }

    let mut outcomes = Vec::new();
    let mut points = Vec::new();
    let mut beats_baseline_on_easiest = false;
    let mut beats_null_on_easiest = false;
    let mut easiest_state_size = 0usize;

    for (size_index, &state_size) in state_sizes.iter().enumerate() {
        let mut idea3_fractions: Vec<f64> = Vec::new();
        let mut baseline_fractions: Vec<f64> = Vec::new();
        let mut null_fractions: Vec<f64> = Vec::new();
        let mut idea3_true_total = 0usize;
        let mut baseline_true_total = 0usize;
        let mut null_true_total = 0usize;
        let mut truth_edges_total = 0usize;
        let mut beams_dropped = 0usize;
        let mut null_at_least_real = 0usize;

        for seed_index in 0..config.seeds_per_kind {
            let seed = marginalization_fixture_seed(config.seed, state_size, seed_index);
            let fixture = generate_deck_fixture(state_size, regime, config, seed)?;
            let outcome =
                evaluate_marginalization_fixture(&fixture, config, seed, beam_width, prior)?;
            idea3_fractions.push(outcome.idea3_fraction());
            baseline_fractions.push(outcome.baseline_fraction());
            null_fractions.push(outcome.null_fraction());
            idea3_true_total = idea3_true_total.saturating_add(outcome.idea3_true_edges);
            baseline_true_total = baseline_true_total.saturating_add(outcome.baseline_true_edges);
            null_true_total = null_true_total.saturating_add(outcome.null_true_edges);
            truth_edges_total = truth_edges_total.saturating_add(outcome.truth_edges_total);
            beams_dropped = beams_dropped.saturating_add(outcome.beams_dropped);
            if outcome.null_fraction() >= outcome.idea3_fraction() {
                null_at_least_real = null_at_least_real.saturating_add(1);
            }
            outcomes.push(outcome);
        }

        let idea3_beats_baseline = idea3_true_total > baseline_true_total;
        let idea3_beats_null = idea3_true_total > null_true_total;
        let matched_null_p_value = add_one_p_value(null_at_least_real, config.seeds_per_kind);
        let hidden_subgroup_order = deck_hidden_subgroup_order(state_size);
        points.push(MarginalizationPoint {
            state_size,
            hidden_subgroup_order,
            seeds: config.seeds_per_kind,
            idea3_true_total,
            baseline_true_total,
            null_true_total,
            truth_edges_total,
            idea3_mean_fraction: mean_f64(&idea3_fractions),
            baseline_mean_fraction: mean_f64(&baseline_fractions),
            null_mean_fraction: mean_f64(&null_fractions),
            idea3_beats_baseline,
            idea3_beats_null,
            matched_null_p_value,
            beam_width,
            beams_dropped,
        });
        if size_index == 0 {
            easiest_state_size = state_size;
            beats_baseline_on_easiest = idea3_beats_baseline;
            beats_null_on_easiest = idea3_beats_null;
        }
    }

    let small_support_validation = run_small_support_validation(config, beam_width)?;

    Ok(MarginalizationReport {
        regime,
        prior,
        beam_width,
        outcomes,
        points,
        beats_baseline_on_easiest,
        beats_null_on_easiest,
        easiest_state_size,
        small_support_validation,
    })
}

/// Runs the TENTATIVE small-support prior validation (idea 2).
///
/// Generates fixtures in TWO truth conditions — genuinely small-support
/// ([`DeckLetterRegime::SmallSupport`]) and unconstrained `S_n`
/// ([`DeckLetterRegime::Unconstrained`]) — and runs idea-3 marginalization with the
/// prior OFF and ON in each. The validating directions: the prior should HELP (or at
/// least not hurt) when the truth genuinely has small support, and FAIL GRACEFULLY
/// (not reward the wrong assumption) when the truth does not.
///
/// # Errors
/// Returns [`GakAttackError`] when a fixture's key/stream is rejected or a symbol
/// cannot be represented.
pub(crate) fn run_small_support_validation(
    config: GakAttackConfig,
    beam_width: usize,
) -> Result<SmallSupportValidation, GakAttackError> {
    let state_size = SMALL_SUPPORT_VALIDATION_STATE_SIZE;
    let radius = SMALL_SUPPORT_VALIDATION_RADIUS;
    let prior_off = SmallSupportPrior::Off;
    let prior_on = SmallSupportPrior::On {
        min_support: SMALL_SUPPORT_VALIDATION_MIN_SUPPORT,
    };

    let mut small_off = 0usize;
    let mut small_on = 0usize;
    let mut small_adm_off = 0usize;
    let mut small_adm_on = 0usize;
    let mut broad_off = 0usize;
    let mut broad_on = 0usize;
    let mut broad_adm_off = 0usize;
    let mut broad_adm_on = 0usize;
    let mut small_total = 0usize;
    let mut broad_total = 0usize;

    for seed_index in 0..config.seeds_per_kind {
        // Distinct seed stream from the headline sweep so the validation is its own
        // experiment.
        let small_seed = marginalization_fixture_seed(
            config.seed ^ 0x736d_616c_6c5f_7373,
            state_size,
            seed_index,
        );
        let small_fixture = generate_deck_fixture(
            state_size,
            DeckLetterRegime::SmallSupport { radius },
            config,
            small_seed,
        )?;
        let small_truth = truth_coset_edges(&small_fixture.key, &small_fixture.plaintext)?;
        small_total = small_total.saturating_add(small_truth.iter().map(BTreeSet::len).sum());
        let small_values = glyphs_to_values(&small_fixture.ciphertext)?;
        let off =
            run_marginalization_attack(&small_values, config.phrase_len, beam_width, prior_off);
        let on = run_marginalization_attack(&small_values, config.phrase_len, beam_width, prior_on);
        small_off = small_off
            .saturating_add(marginal_edge_recovery(&small_truth, &off.recovered_columns).0);
        small_on =
            small_on.saturating_add(marginal_edge_recovery(&small_truth, &on.recovered_columns).0);
        small_adm_off = small_adm_off.saturating_add(admitted_edge_count(&off.recovered_columns));
        small_adm_on = small_adm_on.saturating_add(admitted_edge_count(&on.recovered_columns));

        let broad_seed = marginalization_fixture_seed(
            config.seed ^ 0x6272_6f61_645f_7373,
            state_size,
            seed_index,
        );
        let broad_fixture = generate_deck_fixture(
            state_size,
            DeckLetterRegime::Unconstrained,
            config,
            broad_seed,
        )?;
        let broad_truth = truth_coset_edges(&broad_fixture.key, &broad_fixture.plaintext)?;
        broad_total = broad_total.saturating_add(broad_truth.iter().map(BTreeSet::len).sum());
        let broad_values = glyphs_to_values(&broad_fixture.ciphertext)?;
        let off_b =
            run_marginalization_attack(&broad_values, config.phrase_len, beam_width, prior_off);
        let on_b =
            run_marginalization_attack(&broad_values, config.phrase_len, beam_width, prior_on);
        broad_off = broad_off
            .saturating_add(marginal_edge_recovery(&broad_truth, &off_b.recovered_columns).0);
        broad_on = broad_on
            .saturating_add(marginal_edge_recovery(&broad_truth, &on_b.recovered_columns).0);
        broad_adm_off = broad_adm_off.saturating_add(admitted_edge_count(&off_b.recovered_columns));
        broad_adm_on = broad_adm_on.saturating_add(admitted_edge_count(&on_b.recovered_columns));
    }

    Ok(SmallSupportValidation {
        state_size,
        seeds: config.seeds_per_kind,
        small_truth_prior_off: small_off,
        small_truth_prior_on: small_on,
        small_admitted_off: small_adm_off,
        small_admitted_on: small_adm_on,
        broad_truth_prior_off: broad_off,
        broad_truth_prior_on: broad_on,
        broad_admitted_off: broad_adm_off,
        broad_admitted_on: broad_adm_on,
        small_truth_total: small_total,
        broad_truth_total: broad_total,
    })
}

/// Total admitted edges across recovered columns (the precision denominator for the
/// small-support validation).
#[must_use]
fn admitted_edge_count(columns: &[BTreeSet<CosetEdge>]) -> usize {
    columns.iter().map(BTreeSet::len).sum()
}

/// Deterministic per-`(n, seed_index)` fixture seed for the idea-3 sweep (a distinct
/// stream from the 2a deck sweep so the two are independent experiments).
fn marginalization_fixture_seed(master: u64, state_size: usize, seed_index: usize) -> u64 {
    let tag = (state_size as u64)
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .wrapping_add(seed_index as u64);
    mix_seed(master, tag ^ 0x6d61_7267_5f73_7765)
}

//! Thread 4 GAK-attack spike: synthetic generator + GCTAK decisive gate.
//!
//! This module is the project's go/no-go gate for any attempt to attack the
//! Noita eye-glyph puzzle by pure cryptanalysis: **no GCTAK solve, no GAK
//! attempt.** The GCTAK gate and the synthetic GAK/deck fixtures (Units 1a/2a/2b)
//! are **synthetic-only** — they never touch the eye corpus, so the ground truth
//! is ours to hold. The single unit that *does* run against the verified eye
//! corpus is Unit 2c ([`run_gak_attack_eyes`], Step 3 of
//! `research/gak-threads/specs/thread-4-spec.md`): it measures the standing
//! **BLOCKED** conclusion against matched within-message nulls and asserts no
//! decode. The strongest defensible statement about the eyes is unchanged and
//! stated here so nothing downstream can drift past it:
//!
//! > The eyes are deterministic, engine-generated, strikingly structured data of
//! > unknown meaning; unsolved; no primary developer source confirms recoverable
//! > plaintext.
//!
//! On the *synthetic* ciphers this module generates we hold the ground truth, so
//! "recovering the key" here is legitimate — a recovered key, not an assumed
//! mapping. That privilege does not transfer to the eyes.
//!
//! ## Wiki sources this unit encodes
//!
//! - `Group-Autokey-(GAK).md` — the GAK definition realized by
//!   [`crate::ciphers::GakKey`].
//! - `Group-Ciphertext‐Autokey-(GCTAK).md` — GAK with a **trivial** hidden
//!   subgroup, so the ciphertext readout `c` is bijective. This is the family the
//!   gate solves.
//! - `Alphabet-Chaining.md` / `Graph-Chaining.md` — isomorph alignment → chain
//!   links; GCTAK is the Cayley graph of the state group. The chain-link
//!   primitive is **reused** from [`crate::chaining_graph`], never reimplemented.
//! - `Explanation-of-Progress.md` — states GCTAK is fully solvable by extended
//!   chaining; this module is that solver, validated on ground truth.
//!
//! ## Discipline (mirrors [`crate::cipher_attack`])
//!
//! - The GCTAK solver is a **positive control**: it must fire on known signal. If
//!   it cannot recover a synthetic GCTAK key, that is a methodology bug surfaced
//!   as [`GakAttackError::PositiveControlFailed`], never reported as a data
//!   finding.
//! - Every recovery claim is paired with a **matched negative control**: the same
//!   pipeline run on a within-message multiset shuffle of the ciphertext
//!   ([`crate::null::fisher_yates`]) must *not* achieve exact recovery, so the
//!   real structure is provably the reason recovery works.
//! - A negative or partial result is the **expected, reportable** outcome of the
//!   later GAK steps — not a failure of the thread.
//!
//! ## The small-support prior is TENTATIVE
//!
//! The generator exposes a `small_support_radius` knob that draws each per-letter
//! permutation as a base permutation composed with `≤k` random transpositions
//! (`Deck-Cipher.md`'s shared-sections evidence). This is a **TENTATIVE search
//! heuristic to validate, not a hard constraint**, and the GCTAK gate does not
//! depend on it (it runs in the unconstrained regime by default).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::chaining_graph::{
    AlignedOccurrence, ChainLink, ContextId, SymbolValue, chain_links_for_pair,
};
use crate::ciphers::{CosetReadout, GakKey, GakKeyOptions, compose_permutations, gak_encrypt};
use crate::glyph::Glyph;
use crate::isomorph::PatternSignature;
use crate::language::{self, LanguageModel};
use crate::null::{
    SplitMix64, add_one_p_value, fisher_yates, mix_seed, random_index_below, shuffled_permutation,
    stateless_splitmix,
};
use crate::orders;
use crate::perfect_isomorphism;
use crate::report::{self, Report};
use crate::trigram::TrigramValue;

mod error;
mod eyes;
// `generator`/`solver`/`marginalization` are `pub(crate)` so the solve pipeline
// (brief 04) can import their internals; this widens no external (`pub`) surface —
// the public path stays `crate::gak_attack::*` via the `pub use` block below.
pub(crate) mod generator;
#[cfg(test)]
mod known_answer; // Thread G1: known-answer validation on practice puzzles.
pub(crate) mod marginalization;
pub(crate) mod solver;

pub use error::GakAttackError;
pub use eyes::*;
pub use generator::*;
pub use marginalization::*;
pub use solver::*;

/// Default deterministic seed for the GCTAK gate fixture matrix.
pub const DEFAULT_SEED: u64 = 0x6761_6b5f_6763_7461;
/// Default number of seeds drawn per (group-kind) fixture in the gate matrix.
pub const DEFAULT_SEEDS_PER_KIND: usize = 3;
/// Default cyclic-group order used by gate fixtures.
pub const DEFAULT_CYCLIC_ORDER: usize = 6;
/// Default dihedral half-order `k`; the dihedral group `D_{2k}` has order `2k`.
pub const DEFAULT_DIHEDRAL_HALF_ORDER: usize = 4;
/// Default number of distinct plaintext letters (group generators) per fixture.
pub const DEFAULT_NUM_PT_LETTERS: usize = 3;
/// Default number of repeated phrases in the generated plaintext template.
///
/// Chosen large enough that, together with the random mixing runs between
/// repeats, each phrase column observes its letter's permutation across enough
/// distinct group states for the consistency merge plus completion to recover the
/// full per-letter permutation.
pub const DEFAULT_PHRASE_REPEATS: usize = 40;
/// Default length (in letters) of each repeated phrase.
///
/// A long phrase gives a long, distinctive equality-pattern signature so the
/// isomorph alignment locks onto the true repeated phrase and not a coincidental
/// short pattern inside the mixing runs.
pub const DEFAULT_PHRASE_LEN: usize = 12;
/// Default tentative small-support radius (`≤k` transpositions); `0` means the
/// unconstrained regime used by the GCTAK gate.
pub const DEFAULT_SMALL_SUPPORT_RADIUS: usize = 0;

/// Minimum isomorph window length the solver aligns on. Phrases are longer than
/// this so repeated phrases are always isomorph-rich.
const SOLVER_WINDOW_LEN: usize = 4;

/// Length of the random mixing run inserted between phrase repeats so the entry
/// state drifts over the whole state group. Kept short so the phrase remains the
/// dominant repeated equality pattern.
const MIXING_RUN_LEN: usize = 1;

/// Configuration for the GCTAK decisive gate.
///
/// The hidden subgroup is fixed to [`HiddenSubgroupKind::Trivial`] for this unit;
/// later units extend the matrix. Fields are sized so later units (the
/// small-support attack, partial-recovery null) can extend this without
/// reshaping it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GakAttackConfig {
    /// Deterministic master seed for the fixture matrix.
    pub seed: u64,
    /// Number of distinct seeds drawn per group kind.
    pub seeds_per_kind: usize,
    /// Cyclic-group order `m`.
    pub cyclic_order: usize,
    /// Dihedral half-order `k` (`D_{2k}`, order `2k`).
    pub dihedral_half_order: usize,
    /// Number of distinct plaintext letters (group generators).
    pub num_pt_letters: usize,
    /// Number of repeated phrases in the plaintext template.
    pub phrase_repeats: usize,
    /// Length in letters of each repeated phrase.
    pub phrase_len: usize,
    /// Tentative small-support radius (`≤k` transpositions); `0` is unconstrained.
    pub small_support_radius: usize,
}

impl Default for GakAttackConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_SEED,
            seeds_per_kind: DEFAULT_SEEDS_PER_KIND,
            cyclic_order: DEFAULT_CYCLIC_ORDER,
            dihedral_half_order: DEFAULT_DIHEDRAL_HALF_ORDER,
            num_pt_letters: DEFAULT_NUM_PT_LETTERS,
            phrase_repeats: DEFAULT_PHRASE_REPEATS,
            phrase_len: DEFAULT_PHRASE_LEN,
            small_support_radius: DEFAULT_SMALL_SUPPORT_RADIUS,
        }
    }
}

/// Outcome of the GCTAK solver on one **independent** synthetic seed, with its
/// matched null.
///
/// One outcome is one independent draw — these are the honest backbone the gate's
/// recovery RATE is computed from. No retry selection happens here (review
/// finding F1); the retry-selected exemplar is a separate, explicitly-labelled
/// field on the report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GctakGateOutcome {
    /// Group kind of the fixture.
    pub group: &'static str,
    /// Whether the group is non-commutative (the dihedral witness).
    pub non_commutative: bool,
    /// Declared base group order `|G|`.
    pub group_order: usize,
    /// Realized subgroup order from the constructed key (equals `group_order` at
    /// `small_support_radius == 0`; see [`RealizedStructure`]).
    pub realized_order: usize,
    /// Seed used to build the fixture.
    pub seed: u64,
    /// Number of ciphertext symbols in the fixture.
    pub ciphertext_len: usize,
    /// Number of distinct chain-link source symbols recovered by the solver.
    pub symbols_recovered: usize,
    /// Number of distinct plaintext letters the solver clustered.
    pub letters_recovered: usize,
    /// Number of held-truth per-letter permutations recovered exactly by the real
    /// pipeline (review finding F5).
    pub real_permutations_recovered: usize,
    /// Total held-truth per-letter permutations (the denominator for the recovery
    /// fraction).
    pub permutations_total: usize,
    /// Number of held-truth per-letter permutations the matched-null pipeline
    /// recovered (must stay low; the structure is destroyed).
    pub null_permutations_recovered: usize,
    /// Number of chain-link adjacency constraints the real pipeline checked
    /// (review finding F2).
    pub chain_link_checks: usize,
    /// Number of those chain-link constraints satisfied by the recovered
    /// permutations. Equals `chain_link_checks` on a fully recovered real fixture.
    pub chain_link_consistent: usize,
    /// Whether the real (unshuffled) pipeline recovered the plaintext exactly
    /// (up to the canonical first-occurrence relabelling of letters).
    pub real_recovered_exactly: bool,
    /// Whether the matched shuffle-null pipeline recovered the plaintext exactly
    /// (it must be `false` for the contrast to be meaningful).
    pub null_recovered_exactly: bool,
}

/// Recovery-RATE summary for one group kind across independent seeds.
///
/// This is the gate's headline evidence (review finding F1): the real recovery
/// rate (a fraction of independent seeds) versus the matched-null recovery rate
/// (which must be ~0). No retry selection enters these counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryRate {
    /// Group kind label these rates are for.
    pub group: &'static str,
    /// Whether the group is non-commutative.
    pub non_commutative: bool,
    /// Number of independent seeds drawn.
    pub seeds: usize,
    /// Independent seeds whose real stream recovered the plaintext exactly.
    pub real_recovered: usize,
    /// Independent seeds whose matched shuffle null recovered exactly (must be ~0).
    pub null_recovered: usize,
}

impl RecoveryRate {
    /// Real recovery rate as a fraction of independent seeds (`0.0` if no seeds).
    #[must_use]
    pub fn real_fraction(self) -> f64 {
        fraction(self.real_recovered, self.seeds)
    }

    /// Matched-null recovery rate as a fraction of independent seeds.
    #[must_use]
    pub fn null_fraction(self) -> f64 {
        fraction(self.null_recovered, self.seeds)
    }
}

/// Returns `numerator / denominator` as `f64`, or `0.0` when `denominator == 0`.
#[must_use]
fn fraction(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

/// An **illustrative, retry-selected exemplar** fixture for one group kind.
///
/// This is NOT the gate's pass evidence — the gate passes on the recovery RATE
/// (see [`RecoveryRate`]). This is a single deterministically-chosen seed whose
/// fixture the solver recovered exactly, kept only to show a concrete worked
/// example with its full per-fixture outcome and the number of seeds skipped to
/// reach it (review finding F1). No report field implies every seed recovers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetrySelectedExemplar {
    /// The per-fixture outcome of the chosen exemplar seed.
    pub outcome: GctakGateOutcome,
    /// Number of deterministic seeds tried (including the chosen one) before a
    /// recoverable fixture was found — a transparency counter, never a rate.
    pub attempts_used: usize,
}

/// Documented minimum real recovery rate the gate requires per group kind.
///
/// GCTAK is the wiki's *fully solvable* baseline, but completing every per-letter
/// permutation from a finite random stream is not guaranteed for every seed (it
/// is the hard part the broader GAK thread studies). The commutative cyclic case
/// recovers on essentially every seed; the non-commutative dihedral case recovers
/// on a large majority. This threshold is the floor BOTH must clear, and the real
/// rate must additionally strictly exceed the matched-null rate (which is ~0).
pub const MIN_REAL_RECOVERY_RATE: f64 = 0.8;

/// Complete report for the GCTAK decisive gate.
#[derive(Clone, Debug, PartialEq)]
pub struct GakAttackReport {
    /// Configuration used for the run.
    pub config: GakAttackConfig,
    /// The hidden-subgroup regime of this unit (always trivial-H / GCTAK).
    pub hidden_subgroup: HiddenSubgroupKind,
    /// Per-seed gate outcomes across the independent seed × group-kind matrix
    /// (the honest backbone; no retry selection).
    pub outcomes: Vec<GctakGateOutcome>,
    /// Recovery-RATE summary per group kind (the gate's headline, F1).
    pub rates: Vec<RecoveryRate>,
    /// One retry-selected illustrative exemplar per group kind (NOT pass
    /// evidence; explicitly labelled, F1).
    pub exemplars: Vec<RetrySelectedExemplar>,
    /// Documented minimum real recovery rate the gate required.
    pub min_real_recovery_rate: f64,
    /// Whether every group kind cleared [`MIN_REAL_RECOVERY_RATE`] on the real
    /// stream AND strictly exceeded its matched-null rate. This is the gate's
    /// PASS condition (rate-beats-null, not a single lucky seed).
    pub rate_gate_passed: bool,
    /// Whether the shuffle null failed to recover on every independent seed (the
    /// expected, required contrast; the null rate is ~0).
    pub all_null_failed: bool,
    /// The **real-GAK** (non-trivial hidden subgroup) deck-attack partial-recovery
    /// result: the unit-2a contribution. Carries the per-`n` tractability bound
    /// (recovered-coset-action fraction real vs null, TRUE-conflict aborts) for
    /// the deck stabilizer `H = S_{n-1}`. A low/zero fraction as `n` grows is the
    /// expected, reportable outcome — a measured tractability bound, not a failure.
    pub deck: DeckAttackReport,
    /// The **unit-2b** hidden-state marginalization (idea 3) + small-support prior
    /// (idea 2) result: the per-`n` measured comparison of idea-3 edge-recovery vs
    /// the 2a single-valued-core baseline vs the matched null, the disclosed beam
    /// width / dropped-beam totals, and the TENTATIVE small-support validation. A
    /// "helps on small n, breaks by n=X" shape is the expected, reportable outcome.
    pub marginalization: MarginalizationReport,
}

impl Report for GakAttackReport {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(
            &mut out,
            "Thread 4 synthetic GAK-attack (GCTAK decisive gate)"
        );
        report::appendln!(
            &mut out,
            "hidden subgroup: {}",
            self.hidden_subgroup.label()
        );
        report::appendln!(&mut out, "seed: {}", self.config.seed);
        report::appendln!(
            &mut out,
            "seeds per group kind: {}",
            self.config.seeds_per_kind
        );
        report::appendln!(
            &mut out,
            "cyclic order: {}; dihedral D_2k half-order k: {}",
            self.config.cyclic_order,
            self.config.dihedral_half_order
        );
        report::appendln!(
            &mut out,
            "plaintext letters: {}; phrase repeats: {}; phrase length: {}",
            self.config.num_pt_letters,
            self.config.phrase_repeats,
            self.config.phrase_len
        );
        report::appendln!(
            &mut out,
            "TENTATIVE small-support radius (<=k transpositions): {} (0 = unconstrained gate regime)",
            self.config.small_support_radius
        );
        report::appendln!(
            &mut out,
            "wiki pages this unit encodes: Group-Autokey-(GAK).md; Group-Ciphertext-Autokey-(GCTAK).md; Alphabet-Chaining.md / Graph-Chaining.md"
        );
        report::appendln!(&mut out);
        append_gak_attack_rates(&mut out, self);
        report::appendln!(&mut out);
        append_gak_attack_outcomes(&mut out, self);
        report::appendln!(&mut out);
        append_gak_attack_exemplars(&mut out, self);
        report::appendln!(&mut out);
        append_gak_attack_deck(&mut out, self);
        report::appendln!(&mut out);
        append_gak_attack_marginalization(&mut out, self);
        report::appendln!(&mut out);
        append_gak_attack_interpretation(&mut out, self);
        out
    }
}

fn append_gak_attack_marginalization(out: &mut String, attack_report: &GakAttackReport) {
    let marg = &attack_report.marginalization;
    report::appendln!(
        out,
        "UNIT 2b hidden-state marginalization (idea 3) + TENTATIVE small-support prior (idea 2)"
    );
    report::appendln!(
        out,
        "  idea 3 overcomes the unit-2a obstruction: instead of collapsing each phrase column to its single-valued core (the 2a baseline), a BOUNDED BEAM / belief-propagation over the hidden-state branches admits the multi-valued branches that GENERALIZE to a HELD-OUT chain-link fold (a TRAIN/HELD-OUT split of the same column's occurrences). The recovered object is the per-letter visible-coset edge MARGINAL over hidden states (multi-valued from allowed) -- a PARTIAL visible-coset action recovery, NOT a recovered key, NOT the plaintext->group-element mapping. SYNTHETIC-ONLY."
    );
    report::appendln!(
        out,
        "  beam width bound: {} (DISCLOSED, no silent truncation; dropped beams are reported per n)",
        marg.beam_width
    );
    report::appendln!(
        out,
        "  small-support prior (idea 2) for the headline sweep: {}",
        marg.prior.label()
    );
    report::appendln!(
        out,
        "  decimals tagged (mean) are PER-SEED MEAN fractions; the recov/edges columns are AGGREGATE totals over all seeds (the aggregate ratio differs slightly from the per-seed mean)."
    );
    report::appendln!(
        out,
        "  {:<4} {:>12} {:>7} {:>13} {:>11} {:>9} {:>11} {:>9} {:>11} {:>8} {:>8} {:>7} {:>8}",
        "n",
        "|H|=(n-1)!",
        "seeds",
        "i3 recov/edges",
        "i3 (mean)",
        "core recov",
        "core (mean)",
        "null recov",
        "null (mean)",
        "i3>core",
        "i3>null",
        "p",
        "dropped"
    );
    for point in &marg.points {
        report::appendln!(
            out,
            "  {:<4} {:>12} {:>7} {:>13} {:>11} {:>9} {:>11} {:>9} {:>11} {:>8} {:>8} {:>7} {:>8}",
            point.state_size,
            point.hidden_subgroup_order,
            point.seeds,
            format!("{}/{}", point.idea3_true_total, point.truth_edges_total),
            format!("{:.3}", point.idea3_mean_fraction),
            point.baseline_true_total,
            format!("{:.3}", point.baseline_mean_fraction),
            point.null_true_total,
            format!("{:.3}", point.null_mean_fraction),
            report::yes_no(point.idea3_beats_baseline),
            report::yes_no(point.idea3_beats_null),
            format!("{:.3}", point.matched_null_p_value),
            point.beams_dropped
        );
    }
    report::appendln!(
        out,
        "  MEASURED result: idea-3 marginalization recovers SEVERAL-FOLD more true per-letter coset edges than the 2a single-valued core at every n (the multi-valued branches the core discards are most of the action), and beats the matched null. It is STRONGEST at the smallest n and BREAKS as the hidden-state count |H| = (n-1)! grows (the train fold samples a shrinking share of the hidden states), degrading toward -- never below -- the 2a baseline. \"Helps on small n, breaks as n grows\" is the expected, reportable outcome, not a thread failure. (This wording holds on the default-seed sweep; non-default --seed runs are not gate-guaranteed -- see the table above.)"
    );
    append_gak_attack_small_support(out, &marg.small_support_validation);
}

fn append_gak_attack_small_support(out: &mut String, validation: &SmallSupportValidation) {
    report::appendln!(
        out,
        "  TENTATIVE small-support prior validation (idea 2; the prior is a heuristic to validate, NOT a hard constraint, labelled everywhere)"
    );
    report::appendln!(
        out,
        "    method: generate fixtures WITH small-support truth and WITHOUT (unconstrained S_n), run idea-3 with the prior OFF and ON in each (n={}, {} seeds), and measure edge-recall + edge-precision.",
        validation.state_size,
        validation.seeds
    );
    report::appendln!(
        out,
        "    small-support truth: recall on/off = {}/{} of {}; precision on/off = {:.3}/{:.3}",
        validation.small_truth_prior_on,
        validation.small_truth_prior_off,
        validation.small_truth_total,
        validation.small_precision(true),
        validation.small_precision(false)
    );
    report::appendln!(
        out,
        "    unconstrained truth: recall on/off = {}/{} of {}; precision on/off = {:.3}/{:.3}",
        validation.broad_truth_prior_on,
        validation.broad_truth_prior_off,
        validation.broad_truth_total,
        validation.broad_precision(true),
        validation.broad_precision(false)
    );
    report::appendln!(
        out,
        "    prior FAILS GRACEFULLY (the robust, structural guarantee): {} -- its confidence floor only ever DROPS genuine low-support edges (recall ON <= OFF in both conditions) and never invents any, so precision is held or improved and a WRONG small-support assumption is never rewarded.",
        report::yes_no(validation.prior_fails_gracefully())
    );
    report::appendln!(
        out,
        "    prior is SELECTIVELY discriminative (weak, TENTATIVE signal): {} -- in the deck realization the near-identity structure of the per-letter permutations only WEAKLY survives into the visible-coset marginal (hidden-state cycling spreads the marked card), so the prior helps small-support truth only marginally more than unconstrained truth. This thin margin is reported as TENTATIVE; the graceful-failure property is the load-bearing result.",
        report::yes_no(validation.prior_is_discriminative())
    );
}

fn append_gak_attack_deck(out: &mut String, attack_report: &GakAttackReport) {
    let deck = &attack_report.deck;
    report::appendln!(
        out,
        "REAL-GAK deck attack (non-trivial hidden subgroup H = Stab(top) = S_(n-1), |H| = (n-1)! > 1)"
    );
    report::appendln!(
        out,
        "  this is the community's stated open problem. What this unit recovers is PARTIAL visible-coset action recovery (a fraction of per-letter visible-coset transitions; NOT a recovered key, NOT the plaintext->group-element mapping), plus a MEASURED bound on how far that gets. SYNTHETIC-ONLY (we hold ground truth)."
    );
    report::appendln!(out, "  per-letter draw regime: {}", deck.regime.label());
    report::appendln!(
        out,
        "  measured obstruction: under non-trivial H the visible transition depends on the FULL hidden state, so most of a letter's visible-coset action is multi-valued across hidden states. The recoverable part (single-valued core) is bounded by this multi-valuedness -- which MOTIVATES idea 3 (hidden-state marginalization)."
    );
    report::appendln!(
        out,
        "  {:<4} {:>12} {:>7} {:>20} {:>20} {:>12} {:>14} {:>9} {:>6}",
        "n",
        "|H|=(n-1)!",
        "seeds",
        "real (recov/letters)",
        "null (recov/letters)",
        "real>null",
        "multivalued-frac",
        "aborts",
        "p"
    );
    for tractability in &deck.tractability {
        report::appendln!(
            out,
            "  {:<4} {:>12} {:>7} {:>11} {:>8} {:>11} {:>8} {:>12} {:>14} {:>9} {:>6}",
            tractability.state_size,
            tractability.hidden_subgroup_order,
            tractability.seeds,
            format!(
                "{}/{}",
                tractability.real_recovered_total, tractability.letters_total
            ),
            format!("{:.3}", tractability.real_mean_fraction),
            format!(
                "{}/{}",
                tractability.null_recovered_total, tractability.letters_total
            ),
            format!("{:.3}", tractability.null_mean_fraction),
            report::yes_no(tractability.real_beats_null),
            format!("{:.3}", tractability.multi_valued_fraction),
            tractability.true_conflict_aborts,
            format!("{:.3}", tractability.matched_null_p_value)
        );
    }
    report::appendln!(
        out,
        "  multivalued-frac: the MEASURED hidden-state obstruction (fraction of visible cosets that map multi-valued under a fixed letter). Larger => less recoverable here; this is the headline honest result of the unit and the motivation for idea 3."
    );
    report::appendln!(
        out,
        "  fixed-context TRUE-conflict aborts (a FEATURE, not a bug): occurrence-pair alignments where two arrows out of / into one symbol under ONE fixed alignment proved a bad isomorph alignment and were dropped, protecting honesty. (Cross-hidden-state multi-valuedness is NOT a conflict -- it is the measured obstruction above.)"
    );
    report::appendln!(
        out,
        "  beats matched null on the easiest fixture (n={}): {}",
        deck.easiest_state_size,
        report::yes_no(deck.beats_null_on_easiest)
    );
    report::appendln!(
        out,
        "  measured negative is the deliverable: partial visible-coset action recovery stays SMALL and roughly FLAT across n (it does NOT climb with n), bounded by the hidden-state obstruction; this is the expected, reportable outcome, not a thread failure. The matched null is destroyed at small n and only begins to match real at larger n / some seeds. (This wording holds on the default-seed sweep; non-default --seed runs are not gate-guaranteed -- see the table above.)"
    );
    report::appendln!(
        out,
        "  the per-seed p-value is conservative (high per-fixture variance) and is non-significant on its own -- say so; the aggregate contrast is the AGGREGATE recovered-letter count real vs null."
    );
    report::appendln!(
        out,
        "  TENTATIVE small-support prior + hidden-state marginalization are the NEXT unit: this unit only generates both regimes and leaves documented hooks (the overlap-threshold merge and the single-valued-core light merge), it does NOT apply those priors."
    );
}

fn append_gak_attack_rates(out: &mut String, attack_report: &GakAttackReport) {
    report::appendln!(
        out,
        "rate-beats-null gate (the gate is the RATE vs null, NOT a single seed)"
    );
    report::appendln!(
        out,
        "  required minimum real recovery rate per group kind: {:.3}",
        attack_report.min_real_recovery_rate
    );
    report::appendln!(
        out,
        "  {:<10} {:<7} {:>6} {:>18} {:>18}",
        "group",
        "noncomm",
        "seeds",
        "real-rate (real/n)",
        "null-rate (null/n)"
    );
    for rate in &attack_report.rates {
        report::appendln!(
            out,
            "  {:<10} {:<7} {:>6} {:>10} {:>7} {:>10} {:>7}",
            rate.group,
            report::yes_no(rate.non_commutative),
            rate.seeds,
            format!("{:.3}", rate.real_fraction()),
            format!("{}/{}", rate.real_recovered, rate.seeds),
            format!("{:.3}", rate.null_fraction()),
            format!("{}/{}", rate.null_recovered, rate.seeds)
        );
    }
    report::appendln!(
        out,
        "  rate-vs-null gate passed (real rate clears floor AND strictly exceeds matched-null rate): {}",
        report::yes_no(attack_report.rate_gate_passed)
    );
    report::appendln!(
        out,
        "  matched shuffle null failed to recover on every independent seed (required contrast): {}",
        report::yes_no(attack_report.all_null_failed)
    );
}

fn append_gak_attack_outcomes(out: &mut String, attack_report: &GakAttackReport) {
    report::appendln!(
        out,
        "per-seed outcomes and per-letter permutation-recovery fractions (real vs null)"
    );
    report::appendln!(
        out,
        "  {:<10} {:>10} {:>6} {:>20} {:>20} {:>16}",
        "group",
        "|G|/real",
        "ct-len",
        "real perm-recovery",
        "null perm-recovery",
        "chain-links ok"
    );
    for outcome in &attack_report.outcomes {
        report::appendln!(
            out,
            "  {:<10} {:>5}/{:<4} {:>6} {:>13} {:>6} {:>13} {:>6} {:>8}/{:<7}",
            outcome.group,
            outcome.group_order,
            outcome.realized_order,
            outcome.ciphertext_len,
            format!(
                "{}/{}",
                outcome.real_permutations_recovered, outcome.permutations_total
            ),
            format!(
                "{:.3}",
                fraction(
                    outcome.real_permutations_recovered,
                    outcome.permutations_total
                )
            ),
            format!(
                "{}/{}",
                outcome.null_permutations_recovered, outcome.permutations_total
            ),
            format!(
                "{:.3}",
                fraction(
                    outcome.null_permutations_recovered,
                    outcome.permutations_total
                )
            ),
            outcome.chain_link_consistent,
            outcome.chain_link_checks
        );
    }
}

fn append_gak_attack_exemplars(out: &mut String, attack_report: &GakAttackReport) {
    report::appendln!(
        out,
        "retry-selected exemplars (ILLUSTRATIONS ONLY, NOT pass evidence; the gate passes on the RATE above)"
    );
    for exemplar in &attack_report.exemplars {
        let outcome = exemplar.outcome;
        report::appendln!(
            out,
            "  {} exemplar: seed {} found after {} attempt(s); real per-letter permutation recovery {}/{}; chain-links {}/{} satisfied",
            outcome.group,
            outcome.seed,
            exemplar.attempts_used,
            outcome.real_permutations_recovered,
            outcome.permutations_total,
            outcome.chain_link_consistent,
            outcome.chain_link_checks
        );
    }
    report::appendln!(
        out,
        "  note: an exemplar is an illustration of one worked seed, not evidence every seed recovers."
    );
}

fn append_gak_attack_interpretation(out: &mut String, attack_report: &GakAttackReport) {
    if attack_report.rate_gate_passed {
        report::appendln!(
            out,
            "Interpretation: on these SYNTHETIC-ONLY GCTAK fixtures (we hold the ground-truth key), the extended-chaining solver recovers per-letter permutations at a real rate that clears the documented floor and strictly beats its matched within-message shuffle null. This validates the methodology as a positive control; it is NOT a decode."
        );
    } else {
        report::appendln!(
            out,
            "Interpretation: the rate-beats-null gate did not pass for every group kind on these SYNTHETIC-ONLY fixtures. A negative or partial result is the expected, reportable outcome of the broader GAK thread, not a failure of it."
        );
    }
    report::appendln!(
        out,
        "REAL-GAK deck interpretation: on the non-trivial-H deck stabilizer (real GAK, |H|>1) the attack achieves PARTIAL visible-coset action recovery (a fraction of per-letter visible-coset transitions; NOT a recovered key, NOT the plaintext->group-element mapping). That fraction stays SMALL and roughly FLAT across n -- bounded by the MEASURED hidden-state obstruction (the multi-valuedness of the visible-coset action across hidden states), which is the part not recoverable without idea 3. The matched null is destroyed at small n and only begins to match real at larger n / some seeds. This measured obstruction is the contribution the wiki asks for and motivates idea 3; it is computed on SYNTHETIC ground truth and says nothing about the eyes. (The FLAT/destroyed-null wording holds on the default-seed sweep; non-default --seed runs are not gate-guaranteed -- see the table above.)"
    );
    report::appendln!(
        out,
        "UNIT 2b idea-3 interpretation: hidden-state marginalization (a bounded beam over hidden-state branches, scored by held-out chain links) recovers MARKEDLY more of the per-letter visible-coset action than the 2a single-valued-core baseline on SYNTHETIC small-n deck GAK -- but only PARTIAL visible-coset action recovery (an edge marginal over hidden states), NEVER a recovered key and NEVER the plaintext->group-element mapping. It breaks as |H| = (n-1)! grows; a marginal/negative result at larger n is the expected outcome. The TENTATIVE small-support prior is validated (fails gracefully; only weakly discriminative in this realization) and is OFF in the headline sweep so no result silently depends on it. The beam width and dropped-beam counts are disclosed (no silent truncation). (The MARKEDLY-more wording holds on the default-seed sweep; non-default --seed runs are not gate-guaranteed -- see the table above.)"
    );
    report::appendln!(
        out,
        "Synthetic-only disclaimer: this unit NEVER touches the eye corpus; it generates and solves its own GCTAK ciphertexts whose key it holds. No claim here transfers to the eyes."
    );
    report::appendln!(
        out,
        "Claim ceiling: the eyes remain deterministic, engine-generated, strikingly structured data of unknown meaning; unsolved; no primary developer source confirms recoverable plaintext. This run says nothing about recoverable eye plaintext."
    );
    report::appendln!(
        out,
        "TENTATIVE small-support prior: the <=k-swaps / small-support search heuristic is a TENTATIVE prior to validate, not a hard constraint; the GCTAK gate runs unconstrained (radius 0) and does not depend on it."
    );
    report::appendln!(
        out,
        "Reportable-negative framing: a negative or partial recovery result in later GAK steps is the expected, reportable outcome, not a thread failure."
    );
}

/// Runs the GCTAK decisive gate across the synthetic fixture matrix.
///
/// For each group kind (commutative cyclic and non-commutative dihedral) it draws
/// `config.seeds_per_kind` **independent** seeds, generates a GCTAK fixture with
/// held-back ground truth for each, runs the extended-chaining solver, and runs
/// the matched within-message shuffle null over the same pipeline. The gate's PASS
/// condition is the **recovery RATE versus the matched null** (review finding F1):
/// across the independent seeds, the real recovery rate must clear
/// [`MIN_REAL_RECOVERY_RATE`] *and* strictly exceed the matched-null rate (which
/// is ~0). It is **not** conditioned on a retry-selected lucky seed; a separate,
/// explicitly-labelled [`RetrySelectedExemplar`] per kind is reported only as an
/// illustrative worked example.
///
/// A seed whose matched shuffle null *does* recover exactly is a hard
/// [`GakAttackError::PositiveControlFailed`] (the recovery would be vacuous).
///
/// # Errors
/// Returns [`GakAttackError`] when the configuration is invalid, when a generated
/// key or stream is rejected by the cipher primitives, when a generated symbol
/// cannot be represented, or when the matched null recovers exactly
/// ([`GakAttackError::PositiveControlFailed`]).
pub fn run_gak_attack(config: GakAttackConfig) -> Result<GakAttackReport, GakAttackError> {
    validate_config(config)?;

    let mut outcomes = Vec::new();
    let mut rates = Vec::new();
    let mut exemplars = Vec::new();
    let mut all_null_failed = true;
    let mut rate_gate_passed = true;

    for kind_index in 0..2 {
        let group_kind = group_kind_for(config, kind_index);

        // The honest backbone: evaluate every INDEPENDENT seed once (no retry).
        let mut real_recovered = 0usize;
        let mut null_recovered = 0usize;
        for seed_index in 0..config.seeds_per_kind {
            let seed = fixture_seed(config.seed, kind_index, seed_index);
            let fixture = generate_fixture(group_kind, config, seed)?;
            let outcome = evaluate_fixture(&fixture, config, seed)?;
            if outcome.null_recovered_exactly {
                // Matched null recovered exactly: recovery would be vacuous.
                return Err(GakAttackError::PositiveControlFailed {
                    group: outcome.group,
                    seed,
                    real_recovered: outcome.real_recovered_exactly,
                    null_recovered: outcome.null_recovered_exactly,
                });
            }
            if outcome.real_recovered_exactly {
                real_recovered = real_recovered.saturating_add(1);
            }
            if outcome.null_recovered_exactly {
                null_recovered = null_recovered.saturating_add(1);
            }
            all_null_failed = all_null_failed && !outcome.null_recovered_exactly;
            outcomes.push(outcome);
        }

        let rate = RecoveryRate {
            group: group_kind.label(),
            non_commutative: group_kind.is_non_commutative(),
            seeds: config.seeds_per_kind,
            real_recovered,
            null_recovered,
        };
        // PASS per kind: real rate clears the documented floor AND strictly beats
        // the matched-null rate (~0). This is rate-beats-null, not a lucky seed.
        let kind_passed = rate.real_fraction() >= MIN_REAL_RECOVERY_RATE
            && rate.real_fraction() > rate.null_fraction();
        rate_gate_passed = rate_gate_passed && kind_passed;
        rates.push(rate);

        // Illustrative-only retry-selected exemplar (NOT pass evidence, F1).
        let exemplar = retry_selected_exemplar(group_kind, config)?;
        exemplars.push(exemplar);
    }

    // Unit 2a: the REAL-GAK (non-trivial-H) deck attack, swept over deck sizes to
    // measure the tractability bound. This is the actual contribution; its partial
    // or negative recovery is the expected, reportable outcome and does NOT gate
    // the GCTAK positive control above. The deck sweep uses a FIXED, robust seed
    // count ([`DECK_SWEEP_SEEDS`]) independent of the small GCTAK-gate
    // `seeds_per_kind`, so the reported tractability bound is stable rather than a
    // 2-3-seed snapshot (per-fixture recovery variance is high).
    let deck_config = GakAttackConfig {
        seeds_per_kind: DECK_SWEEP_SEEDS,
        ..config
    };
    let deck = run_deck_attack_sweep(
        deck_config,
        DeckLetterRegime::Unconstrained,
        &DEFAULT_DECK_STATE_SIZES,
    )?;

    // Unit 2b: hidden-state marginalization (idea 3) + the TENTATIVE small-support
    // prior (idea 2), swept over the same deck sizes with the same robust seed count.
    // The headline sweep runs the prior OFF (support-rank + width-cap candidates,
    // held-out-strict selection); the
    // small-support prior is validated separately inside the report. A "helps on
    // small n, breaks by n=X" shape is the expected, reportable outcome and does NOT
    // gate the GCTAK positive control above.
    let marginalization = run_marginalization_sweep(
        deck_config,
        DeckLetterRegime::Unconstrained,
        &DEFAULT_DECK_STATE_SIZES,
        DEFAULT_BEAM_WIDTH,
        SmallSupportPrior::Off,
    )?;

    Ok(GakAttackReport {
        config,
        hidden_subgroup: HiddenSubgroupKind::Trivial,
        outcomes,
        rates,
        exemplars,
        min_real_recovery_rate: MIN_REAL_RECOVERY_RATE,
        rate_gate_passed,
        all_null_failed,
        deck,
        marginalization,
    })
}

/// Maximum number of deterministic seeds tried to find the illustrative exemplar.
///
/// Exact GCTAK recovery from isomorphs is the wiki's *fully solvable* baseline,
/// but completing every per-letter permutation from a finite stream is not
/// guaranteed for every random fixture (it is the hard part the broader GAK
/// thread studies). The retry is used ONLY to pick a concrete worked example to
/// display; the gate's PASS condition is the recovery RATE, not this exemplar.
const MAX_FIXTURE_ATTEMPTS: usize = 16;

/// Picks a single **illustrative, retry-selected exemplar** fixture (review
/// finding F1): the first deterministic seed (from a kind-specific base) whose
/// GCTAK fixture the solver recovers exactly while the matched shuffle null does
/// not.
///
/// This is a presentation convenience — a concrete worked example with its
/// per-fixture outcome and the number of seeds skipped to reach it. It is **not**
/// the gate's pass evidence (that is the rate-beats-null criterion in
/// [`run_gak_attack`]). A seed where the **shuffle null recovers** is still a hard
/// error (vacuous recovery) and aborts. If no nearby fixture is recoverable within
/// [`MAX_FIXTURE_ATTEMPTS`], the harness reports it as a positive-control failure,
/// but the rate gate above is the authoritative signal.
fn retry_selected_exemplar(
    group_kind: GroupKind,
    config: GakAttackConfig,
) -> Result<RetrySelectedExemplar, GakAttackError> {
    let base_seed = fixture_seed(config.seed, kind_index_of(group_kind), usize::MAX);
    let mut last_real_recovered = false;
    for attempt in 0..MAX_FIXTURE_ATTEMPTS {
        let seed = mix_seed(base_seed, attempt as u64 ^ 0x6174_7465_6d70_7401);
        let fixture = generate_fixture(group_kind, config, seed)?;
        let outcome = evaluate_fixture(&fixture, config, seed)?;
        if outcome.null_recovered_exactly {
            return Err(GakAttackError::PositiveControlFailed {
                group: outcome.group,
                seed,
                real_recovered: outcome.real_recovered_exactly,
                null_recovered: outcome.null_recovered_exactly,
            });
        }
        last_real_recovered = outcome.real_recovered_exactly;
        if outcome.real_recovered_exactly {
            return Ok(RetrySelectedExemplar {
                outcome,
                attempts_used: attempt.saturating_add(1),
            });
        }
    }
    Err(GakAttackError::PositiveControlFailed {
        group: group_kind.label(),
        seed: base_seed,
        real_recovered: last_real_recovered,
        null_recovered: false,
    })
}

/// Returns the matrix kind index for a group kind (cyclic = 0, dihedral = 1).
const fn kind_index_of(group_kind: GroupKind) -> usize {
    match group_kind {
        GroupKind::Cyclic { .. } => 0,
        GroupKind::Dihedral { .. } => 1,
    }
}

fn validate_config(config: GakAttackConfig) -> Result<(), GakAttackError> {
    if config.seeds_per_kind == 0 {
        return Err(GakAttackError::ZeroSeeds);
    }
    if config.cyclic_order < 2 {
        return Err(GakAttackError::CyclicOrderTooSmall {
            order: config.cyclic_order,
        });
    }
    if config.dihedral_half_order < 3 {
        return Err(GakAttackError::DihedralHalfOrderTooSmall {
            half_order: config.dihedral_half_order,
        });
    }
    if config.num_pt_letters < 2 {
        return Err(GakAttackError::TooFewLetters {
            requested: config.num_pt_letters,
        });
    }
    if config.phrase_repeats == 0 || config.phrase_len == 0 {
        return Err(GakAttackError::EmptyTemplate);
    }
    // The decisive GCTAK gate runs UNCONSTRAINED (radius 0); the TENTATIVE
    // small-support prior is only exercised by the deck / marginalization sweeps. A
    // nonzero radius here would either crash the gate (not injective on cosets) or
    // silently change its declared assumptions, so reject it rather than honor it.
    if config.small_support_radius != 0 {
        return Err(GakAttackError::SmallSupportRadiusUnsupported {
            requested: config.small_support_radius,
        });
    }
    Ok(())
}

fn group_kind_for(config: GakAttackConfig, kind_index: usize) -> GroupKind {
    match kind_index {
        0 => GroupKind::Cyclic {
            order: config.cyclic_order,
        },
        _ => GroupKind::Dihedral {
            half_order: config.dihedral_half_order,
        },
    }
}

fn fixture_seed(master: u64, kind_index: usize, seed_index: usize) -> u64 {
    let tag = (kind_index as u64)
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .wrapping_add(seed_index as u64);
    mix_seed(master, tag ^ 0x6763_7461_6b5f_0001)
}

#[cfg(test)]
mod tests;

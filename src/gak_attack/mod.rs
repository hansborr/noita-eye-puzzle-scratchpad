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
use crate::trigram::TrigramValue;

mod error;
mod generator;
mod solver;

pub use error::GakAttackError;
pub use generator::*;
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
const HELD_OUT_STRIDE: usize = 2;

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
struct BeamItem {
    /// Admitted directed coset edges (the recovered per-letter marginal so far).
    admitted: BTreeSet<CosetEdge>,
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
struct SplitColumnEvidence {
    /// TRAIN-fold edges with their occurrence-support counts.
    train_support: BTreeMap<CosetEdge, usize>,
    /// HELD-OUT-fold branches (the validation set), in occurrence order.
    held_out: Vec<CosetEdge>,
}

/// Builds per-column TRAIN/HELD-OUT evidence for the idea-3 marginalization.
///
/// Mirrors [`phrase_column_evidence`] (same aligned phrase, same SHARED
/// [`chain_links_for_pair`] source — load-bearing) but partitions each column's
/// occurrences into a TRAIN fold (every occurrence index NOT on the held-out stride)
/// and a HELD-OUT fold (every `HELD_OUT_STRIDE`-th occurrence). The held-out fold is
/// reserved purely for scoring beams — it never contributes a candidate edge, so the
/// validation is genuinely out-of-sample.
fn split_column_evidence(
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
fn beam_recover_column(
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
struct MarginalizationSolution {
    /// The recovered per-letter (per-column) coset-edge marginals: each is the
    /// best beam's admitted edge set — a PARTIAL visible-coset action recovery that
    /// ADMITS multi-valued `from` cosets (the hidden-state marginal), NOT a recovered
    /// key and NOT the plaintext->group-element mapping. This is what idea 3 recovers
    /// beyond the 2a single-valued core.
    recovered_columns: Vec<BTreeSet<CosetEdge>>,
    /// The 2a single-valued-core baseline edge sets on the SAME columns (for the
    /// like-for-like "does marginalization recover more" comparison).
    baseline_columns: Vec<BTreeMap<u8, u8>>,
    /// Total beams pruned by the width bound across all columns (no silent
    /// truncation — surfaced).
    beams_dropped: usize,
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
fn run_marginalization_attack(
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
fn single_valued_core_of_split(column: &SplitColumnEvidence) -> BTreeMap<u8, u8> {
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
fn marginal_edge_recovery(
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
fn baseline_edge_recovery(
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
fn evaluate_marginalization_fixture(
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
fn run_small_support_validation(
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

// =====================================================================
// UNIT 2c — EYES STEP 3: point the matured attack at the REAL eye corpus.
//
// This is the ONLY unit that touches the real eyes, and the highest honesty-risk
// unit in the project. The CLAIM CEILING is absolute on every output:
//
//   The eyes are deterministic, engine-generated, strikingly structured data of
//   unknown meaning; unsolved; no primary developer source confirms recoverable
//   plaintext.
//
// Nothing this unit prints, writes, or returns may be stronger. The standing
// conclusion — the eye decode is BLOCKED on the unknown symbol→meaning mapping —
// does NOT change unless a candidate survives the held-out + Thread-3 gates below,
// and even then it is a HYPOTHESIS, never a decode. The EXPECTED, fully reportable
// outcome of this unit is NO surviving candidate: with a near-`S_83` group and very
// little text (`Alphabet-Chaining.md`: "it might actually be unrealistic to expect
// chaining to ever work for the eyes"), a clean honest negative is a SUCCESS here.
//
// ## What is recovered vs what is NOT (the honest reality, encoded)
//
// The attack recovers STRUCTURE (visible-coset actions / chain-link constraints),
// NOT cleartext. Even a full recovery of the eye group structure yields abstract
// plaintext-letter INDICES, not readable text, because mapping symbols→letters
// needs an external ANCHOR (exactly the standing blocker). So a "candidate
// cleartext" can ONLY arise by ADDITIONALLY hypothesizing a symbol→letter mapping,
// which the claim ceiling forbids inventing as a finding. The cleartext path is
// therefore SPECULATIVE, gated, Finnish-weighted, and never primary.
//
// ## Entry path (EXACT — never deviate)
//
//   orders::corpus_grids() → orders::accepted_honeycomb_order()
//   → orders::read_corpus_message_values(&grids, order)
//
// PER-MESSAGE streams, message boundaries KEPT; NEVER concatenate across messages;
// NEVER re-select a reading order. (notes/reading-streams.md, notes/api-analysis.md)
//
// ## The kill gates (in spec order; every candidate is a HYPOTHESIS until ALL pass)
//
// 1. HELD-OUT isomorphs. Recover on a SUBSET of each message's isomorph chain links
//    (the TRAIN fold), and require the recovered structure to PREDICT the HELD-OUT
//    fold it was not trained on, beating a MATCHED within-message shuffle null
//    (`fisher_yates` + `add_one_p_value`, identical pipeline/population). An
//    unconstrained fit that cannot predict held-out structure is coincidence.
// 2. THREAD-3 perfect-iso consistency. The implied model must be consistent with
//    `perfect_isomorphism`'s scan: no manufactured TRUE conflicts
//    (`robust_internal_violations == 0`), chaining ONLY within the safe isomorph
//    extents (never over-extending). Reuse the Thread-3 API; never re-derive.
// 3. (LAST, SPECULATIVE) cleartext plausibility — ONLY if (1) AND (2) pass. Score an
//    implied plaintext under the Finnish AND English models behind a matched null;
//    the symbol→letter mapping is a HYPOTHESIS, never recovered, never primary.
// =====================================================================

/// Reading-layer alphabet size of the eye reading layer (`|C|` upper bound), used
/// as the deck `state_size` proxy for the eye chain-link merge threshold.
pub const EYE_READING_ALPHABET_SIZE: usize = orders::READING_LAYER_ALPHABET_SIZE;

/// Minimum gap-pattern window the eye isomorph alignment scans (matches Thread 3's
/// `DEFAULT_MIN_WINDOW`, so the held-out chain links are read from the same
/// isomorph regime Thread 3 validated).
pub const EYE_ISOMORPH_MIN_WINDOW: usize = perfect_isomorphism::DEFAULT_MIN_WINDOW;

/// Maximum gap-pattern window the eye isomorph alignment scans (matches Thread 3's
/// `DEFAULT_MAX_WINDOW`).
pub const EYE_ISOMORPH_MAX_WINDOW: usize = perfect_isomorphism::DEFAULT_MAX_WINDOW;

/// Default deterministic seed for the eyes Step-3 matched within-message null.
pub const EYES_DEFAULT_SEED: u64 = 0x6579_6573_5f73_7470;

/// Default matched within-message shuffle-null trial count for the eyes Step-3 gate.
pub const EYES_DEFAULT_TRIALS: usize = 2_000;

/// Default beam-width LABEL recorded in the eyes candidate-record filename/header;
/// it does NOT affect the eyes held-out scoring (the eyes run performs no per-column
/// marginalization).
pub const EYES_DEFAULT_BEAM_WIDTH: usize = DEFAULT_BEAM_WIDTH;

/// Default directory under which the mandatory eyes candidate record is written.
pub const EYES_DEFAULT_CANDIDATES_DIR: &str = "research/gak-threads/candidates";

/// Configuration for the eyes Step-3 attack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EyesAttackConfig {
    /// Deterministic seed for the matched within-message shuffle null and the
    /// derived candidate-record label (NO wall-clock is ever read).
    pub seed: u64,
    /// Matched within-message shuffle-null trials.
    pub trials: usize,
    /// Disclosed beam-width label recorded in the candidate-record filename/header;
    /// does NOT affect the eyes held-out scoring (the eyes run performs no per-column
    /// marginalization).
    pub beam_width: usize,
    /// Directory under which the mandatory candidate record is written.
    pub candidates_dir: PathBuf,
}

impl Default for EyesAttackConfig {
    fn default() -> Self {
        Self {
            seed: EYES_DEFAULT_SEED,
            trials: EYES_DEFAULT_TRIALS,
            beam_width: EYES_DEFAULT_BEAM_WIDTH,
            candidates_dir: PathBuf::from(EYES_DEFAULT_CANDIDATES_DIR),
        }
    }
}

/// The held-out isomorph evaluation for ONE eye message, real vs matched null.
///
/// Mirrors the synthetic idea-3 held-out machinery but over the real eye isomorphs:
/// the per-message isomorph occurrences are split into a TRAIN fold (the candidate
/// chain links) and a HELD-OUT fold (the validation chain links); the recovered
/// structure (the admitted train edges) must predict the held-out fold. Real and
/// the matched within-message multiset shuffle run the IDENTICAL pipeline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EyeMessageHeldOut {
    /// Message key (e.g. `east1`).
    pub message_key: &'static str,
    /// Reading-layer symbols in this message.
    pub length: usize,
    /// Distinct isomorph signature groups (≥2 occurrences) found in this message.
    pub isomorph_groups: usize,
    /// Aligned isomorph occurrence pairs that yielded chain links.
    pub aligned_pairs: usize,
    /// Distinct reading-layer symbols touched by any chain link (coverage).
    pub symbols_touched: usize,
    /// Fixed-context TRUE-conflict aborts (bad isomorph alignments) on the real
    /// stream — surfaced as a feature (`Chaining-Conflicts.md`).
    pub true_conflict_aborts: usize,
    /// Held-out chain links the uniquely-identified TRAIN context predicted
    /// correctly (real stream).
    pub real_held_out_hits: usize,
    /// Held-out chain links predicted incorrectly (real stream).
    pub real_held_out_misses: usize,
    /// Held-out chain links with no unique confident prediction (real stream).
    pub real_held_out_ambiguous: usize,
    /// The coverage-weighted excess-correctness score for this message (real
    /// stream) — the gate statistic, `(A-1)*hits - A*misses (ambiguous unpenalized)`.
    pub real_score: i64,
}

/// The Thread-3 perfect-isomorphism consistency verdict consulted at Step 3.
///
/// This is read straight from [`perfect_isomorphism::run_perfect_isomorphism`]
/// (the Thread-3 API is REUSED, never re-derived). A candidate may only be named
/// if Thread 3 reports zero robust internal violations (no manufactured TRUE
/// conflicts) and supplies the safe isomorph extents Gate-1 chaining is ENFORCED to
/// stay within (F2 — see `eyes_three_consultation`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ThreeConsistency {
    /// Thread-3 robust strong-bar internal-violation count (must be `0` for a
    /// consistent model: a non-zero count is a manufactured TRUE conflict).
    pub robust_internal_violations: usize,
    /// Number of conservative safe isomorph extents Thread 3 exported. Gate-1
    /// chaining is ENFORCED to stay within the per-message spans these project to
    /// (F2); an occurrence window is admitted only inside a safe span.
    pub safe_extents: usize,
    /// Whether Thread 3's own positive control fired (the scan is trustworthy).
    pub positive_control_fired: bool,
    /// Whether the candidate model is CONSISTENT with Thread 3: zero robust
    /// internal violations AND the positive control fired.
    pub consistent: bool,
}

/// The complete eyes Step-3 report (the standing "decode blocked" conclusion,
/// measured honestly).
#[derive(Clone, Debug, PartialEq)]
pub struct EyesAttackReport {
    /// Configuration used for the run (carries the seed-derived record label).
    pub config: EyesAttackConfig,
    /// The reading order used (pinned: the accepted honeycomb order, stable name
    /// `standard36-u012-d012`).
    pub order_name: String,
    /// Total reading-layer symbols across all nine messages (must be `1036`).
    pub total_symbols: usize,
    /// Distinct reading-layer symbols across all messages (must be `83`).
    pub distinct_symbols: usize,
    /// Per-message held-out evaluations (real vs matched null), boundaries kept.
    pub per_message: Vec<EyeMessageHeldOut>,
    /// Aggregate real held-out hits across all messages (correct unique predictions).
    pub real_held_out_hits_total: usize,
    /// Aggregate real held-out misses across all messages (wrong predictions).
    pub real_held_out_misses_total: usize,
    /// Aggregate real held-out ambiguous links (no unique confident prediction).
    pub real_held_out_ambiguous_total: usize,
    /// The aggregate real coverage-weighted excess-correctness SCORE (the gate
    /// statistic, summed over messages).
    pub real_score: i64,
    /// SCOREABLE held-out edges on the real eyes (`hits + misses + ambiguous`) — the
    /// population whose own max-achievable score sizes the F1 material-effect bar.
    pub scoreable_edges: usize,
    /// The eyes' MAX achievable coverage-weighted score (`scoreable_edges * (A-1)`,
    /// i.e. every scoreable edge a confident HIT). The material-effect bar is a
    /// fraction of THIS, so a genuine eye signal COULD clear the bar (F1: fair gate).
    pub max_achievable_score: f64,
    /// The mean matched within-message shuffle-null coverage-weighted score.
    pub null_mean_score: f64,
    /// The POPULATION-RELATIVE MATERIAL-EFFECT threshold the real excess had to clear
    /// (`EYES_MATERIAL_EFFECT_FRACTION` of the eyes' own [`Self::max_achievable_score`])
    /// — the effect-size bar that makes p-value significance necessary but not
    /// sufficient, fair to the population under test (F1).
    pub material_effect_threshold: f64,
    /// Whether the real-vs-null-mean excess cleared the population-relative
    /// material-effect bar. Expected `false` for the eyes (their real-vs-null
    /// excess does not clear the bar).
    pub material_effect_met: bool,
    /// Matched within-message shuffle-null trials run.
    pub trials: usize,
    /// Number of null trials whose aggregate coverage-weighted score was at least
    /// the real aggregate score (the matched-null upper tail).
    pub null_at_least_real: usize,
    /// Add-one matched-null p-value for the coverage-weighted score.
    pub matched_null_p_value: f64,
    /// Whether the real aggregate coverage-weighted score STRICTLY beats the matched
    /// within-message shuffle null (kill gate 1). Expected `false` for the eyes.
    pub held_out_beats_null: bool,
    /// The held-out positive control on the synthetic isomorph-rich eye-shaped
    /// fixture (the predictor must fire on KNOWN signal).
    pub held_out_positive_control: HeldOutPositiveControl,
    /// The Thread-3 perfect-isomorphism consistency verdict (kill gate 2).
    pub three_consistency: ThreeConsistency,
    /// THE VERDICT: did ANY candidate survive BOTH structural gates? Expected NO.
    /// A `true` here would be flagged loudly and logged as a HYPOTHESIS, never a
    /// decode.
    pub candidate_survived: bool,
    /// The SPECULATIVE cleartext-plausibility result, present ONLY if both
    /// structural gates passed; `None` is the expected case (gate 3 not run).
    pub speculative_cleartext: Option<SpeculativeCleartext>,
    /// Absolute path of the candidate record this run wrote.
    pub record_path: PathBuf,
}

/// The held-out positive control on a SYNTHETIC isomorph-rich eye-shaped fixture.
///
/// The held-out predictor must fire on KNOWN signal: a synthetic message built so a
/// FIXED global action recurs across isomorph groups must yield a real
/// coverage-weighted score that strictly beats its matched within-message shuffle
/// null (the shuffle destroys the reusable context classes). If it does not, the
/// held-out gate is not trustworthy and the run aborts
/// ([`GakAttackError::HeldOutPositiveControlFailed`]) — a methodology failure, never
/// an eye finding.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HeldOutPositiveControl {
    /// Real coverage-weighted held-out score on the synthetic fixture.
    pub real_score: i64,
    /// Worst-case (max) matched-null coverage-weighted score over the control
    /// shuffles (the value the real signal must strictly beat).
    pub null_score: i64,
    /// SCOREABLE held-out edges on the synthetic fixture (`hits + misses +
    /// ambiguous`). Used to size the control's OWN population material-effect bar so
    /// F1's validation ("the detector still clears its own bar") is checked on the
    /// control's population, not the eyes'.
    pub scoreable_edges: usize,
    /// Whether the predictor fired: the real signal strictly beats the worst-case
    /// matched null AND its real-vs-null excess clears the control's OWN
    /// population-relative material-effect bar (F1) — so the detector is validated on
    /// the same fair gate the eyes are judged against.
    pub fired: bool,
}

/// The SPECULATIVE cleartext-plausibility result (kill gate 3).
///
/// Present ONLY when a candidate survived BOTH structural gates (the expected case
/// is `None`). The symbol→letter mapping is a HYPOTHESIS, never recovered; this is
/// never primary evidence. Both Finnish and English are scored behind a matched
/// null, with Finnish weighted highly (Noita is a Finnish game). The implied
/// plaintext is logged VERBATIM to the candidate record for human review.
#[derive(Clone, Debug, PartialEq)]
pub struct SpeculativeCleartext {
    /// The implied plaintext under the HYPOTHESIZED symbol→letter mapping (logged
    /// verbatim — a HYPOTHESIS, never a decode).
    pub implied_plaintext: String,
    /// Finnish bigram mean log-likelihood of the implied plaintext.
    pub finnish_score: f64,
    /// English bigram mean log-likelihood of the implied plaintext.
    pub english_score: f64,
    /// Matched-null mean Finnish score over shuffled mappings.
    pub finnish_null_mean: f64,
    /// Matched-null mean English score over shuffled mappings.
    pub english_null_mean: f64,
    /// Whether the implied plaintext beats the matched mapping null in Finnish.
    pub beats_finnish_null: bool,
    /// Whether the implied plaintext beats the matched mapping null in English.
    pub beats_english_null: bool,
}

/// The held-out Gate-1 evaluation: per-message rows, aggregate score, matched-null
/// tail, and the population-relative material-effect verdict.
struct Gate1Evaluation {
    per_message: Vec<EyeMessageHeldOut>,
    real_held_out_hits_total: usize,
    real_held_out_misses_total: usize,
    real_held_out_ambiguous_total: usize,
    real_score: i64,
    /// SCOREABLE held-out edges on the real eyes (`hits + misses + ambiguous`) — the
    /// population whose own max-achievable score sizes the F1 bar.
    scoreable_edges: usize,
    /// The eyes' MAX achievable coverage-weighted score (`scoreable_edges * (A-1)`):
    /// the bar is a fraction of THIS, so genuine eye signal could clear it.
    max_achievable_score: f64,
    null_at_least_real: usize,
    null_mean_score: f64,
    matched_null_p_value: f64,
    material_effect_threshold: f64,
    material_effect_met: bool,
    held_out_beats_null: bool,
}

/// Runs the eyes Gate-1 held-out evaluation: the embargoed-consensus coverage-
/// weighted score on the real per-message streams vs the matched within-message
/// shuffle null, plus the POPULATION-RELATIVE material-effect bar (statistical
/// significance is NECESSARY but NOT SUFFICIENT — F1: the real-vs-null excess must
/// reach [`EYES_MATERIAL_EFFECT_FRACTION`] of the eyes' OWN max achievable score
/// `scoreable_edges * (A-1)`, a bar that scales to whatever population is under test
/// so a genuine eye signal COULD clear it, rather than an absolute value pinned to
/// the much larger synthetic positive control's population).
///
/// Gate-1 chaining is restricted to the Thread-3 safe extents via
/// `safe_spans_by_message` (F2), applied identically to the real eyes and the matched
/// null so the null stays symmetric.
///
/// # Errors
/// Returns [`GakAttackError`] if a matched-null shuffle draw bound does not fit.
fn eyes_gate1_evaluation(
    keys: &[&'static str],
    message_values: &[Vec<TrigramValue>],
    config: &EyesAttackConfig,
    safe_spans_by_message: &[Vec<(usize, usize)>],
) -> Result<Gate1Evaluation, GakAttackError> {
    let per_message = eyes_per_message_held_out(keys, message_values, safe_spans_by_message);
    let real_held_out_hits_total: usize = per_message.iter().map(|m| m.real_held_out_hits).sum();
    let real_held_out_misses_total: usize =
        per_message.iter().map(|m| m.real_held_out_misses).sum();
    let real_held_out_ambiguous_total: usize =
        per_message.iter().map(|m| m.real_held_out_ambiguous).sum();
    let real_score = eyes_aggregate_score(
        message_values,
        AggregateSafeFilter::PerMessage(safe_spans_by_message),
    );

    let (null_at_least_real, null_mean_score) =
        eyes_matched_null_tail(message_values, config, safe_spans_by_message, real_score)?;
    let matched_null_p_value = add_one_p_value(null_at_least_real, config.trials);

    // F1: a POPULATION-RELATIVE bar. The eyes' own scoreable held-out edges fix their
    // max achievable score `scoreable_edges * (A-1)`; the bar is a fraction of THAT,
    // so a genuine eye signal capturing >= EYES_MATERIAL_EFFECT_FRACTION of the signal
    // achievable on ITS OWN population clears it. This is fair (the bar is below the
    // eyes' max) and validated (the positive control clears its own population's bar).
    let scoreable_edges = real_held_out_hits_total
        .saturating_add(real_held_out_misses_total)
        .saturating_add(real_held_out_ambiguous_total);
    let max_achievable = max_achievable_score(scoreable_edges);
    let real_excess = real_score as f64 - null_mean_score;
    let material_effect_threshold = EYES_MATERIAL_EFFECT_FRACTION * max_achievable;
    let material_effect_met = max_achievable > 0.0 && real_excess >= material_effect_threshold;
    let held_out_beats_null = real_score > 0
        && real_score as f64 > null_mean_score
        && matched_null_p_value <= EYES_SIGNIFICANCE_ALPHA
        && material_effect_met;

    Ok(Gate1Evaluation {
        per_message,
        real_held_out_hits_total,
        real_held_out_misses_total,
        real_held_out_ambiguous_total,
        real_score,
        scoreable_edges,
        max_achievable_score: max_achievable,
        null_at_least_real,
        null_mean_score,
        matched_null_p_value,
        material_effect_threshold,
        material_effect_met,
        held_out_beats_null,
    })
}

/// Runs the eyes Step-3 attack on the verified eye corpus and writes the mandatory
/// candidate record.
///
/// The standing conclusion is the eye decode is BLOCKED on the unknown
/// symbol→meaning mapping. This run measures honestly whether that holds: it points
/// the matured chain-link attack at the real per-message eye streams, evaluates the
/// held-out isomorph gate against a matched within-message shuffle null, consults
/// Thread 3's perfect-isomorphism consistency, and ONLY if BOTH structural gates
/// pass runs the SPECULATIVE Finnish/English cleartext scoring. The expected
/// outcome is NO surviving candidate; the candidate record is written either way.
///
/// # Errors
/// Returns [`GakAttackError`] when the corpus cannot be read, when Thread 3's scan
/// fails, when the held-out positive control does not fire on known synthetic
/// signal, when a language model cannot be built, or when the candidate record
/// cannot be written.
pub fn run_gak_attack_eyes(config: EyesAttackConfig) -> Result<EyesAttackReport, GakAttackError> {
    // ZERO-TRIALS GUARD: the held-out gate's significance is the matched
    // within-message shuffle null, so it must have at least one draw — zero trials
    // would define the p-value and null mean over an empty sample (same discipline
    // as the other modules' ZeroTrials rejection). Reject up front, never a finding.
    if config.trials == 0 {
        return Err(GakAttackError::EyesZeroTrials);
    }

    // ENTRY PATH (exact): per-message streams, boundaries kept, accepted order.
    let grids = orders::corpus_grids()?;
    let keys: Vec<&'static str> = grids
        .iter()
        .map(crate::orders::GlyphGrid::message_key)
        .collect();
    let order = orders::accepted_honeycomb_order();
    let message_values = orders::read_corpus_message_values(&grids, order)?;

    let total_symbols: usize = message_values.iter().map(Vec::len).sum();
    let distinct_symbols: BTreeSet<u8> = message_values
        .iter()
        .flatten()
        .map(|value| value.get())
        .collect();
    let distinct_symbols = distinct_symbols.len();

    // GATE 1 PRELUDE: the held-out POSITIVE CONTROL must fire on KNOWN signal — now
    // including clearing the control's OWN population-relative material-effect bar
    // (F1), so the bar is proven achievable by genuine signal before the eyes face it.
    let held_out_positive_control = eyes_held_out_positive_control(&config)?;
    if !held_out_positive_control.fired {
        return Err(GakAttackError::HeldOutPositiveControlFailed {
            real_score: held_out_positive_control.real_score,
            null_score: held_out_positive_control.null_score,
        });
    }

    // THREAD-3 CONSULTATION (REUSE the Thread-3 API), run ONCE up front: it yields
    // both the Gate-2 consistency verdict AND the per-message safe isomorph spans
    // Gate-1 chaining is ENFORCED to stay within (F2). Run before Gate 1 so Gate 1 can
    // restrict chaining to those extents.
    let three = eyes_three_consultation(&keys)?;
    let three_consistency = three.verdict;
    let safe_spans_by_message = three.safe_spans_by_message;

    // GATE 1: per-message held-out isomorph recovery vs a MATCHED within-message
    // shuffle null, CHAINING RESTRICTED to the Thread-3 safe extents (F2), plus the
    // population-relative material-effect bar (the leak-proof, codex-validated
    // embargoed-consensus statistic). Boundaries are kept.
    let gate1 = eyes_gate1_evaluation(&keys, &message_values, &config, &safe_spans_by_message)?;

    // GATE 3 + VERDICT + record/report assembly (factored out to keep this entry
    // point thin; the speculative Gate 3 stays gated behind both structural gates).
    finalize_eyes_run(EyesRunFinalize {
        config,
        order,
        message_values,
        total_symbols,
        distinct_symbols,
        gate1,
        three_consistency,
        held_out_positive_control,
    })
}

/// Inputs to [`finalize_eyes_run`]: the structural-gate outputs plus the run context
/// needed to assemble the candidate record and the [`EyesAttackReport`].
struct EyesRunFinalize {
    config: EyesAttackConfig,
    order: orders::ReadingOrder,
    message_values: Vec<Vec<TrigramValue>>,
    total_symbols: usize,
    distinct_symbols: usize,
    gate1: Gate1Evaluation,
    three_consistency: ThreeConsistency,
    held_out_positive_control: HeldOutPositiveControl,
}

/// Runs the SPECULATIVE Gate 3 (only if both structural gates passed), determines the
/// final verdict, writes the mandatory candidate record, and builds the report.
///
/// The verdict is unchanged: a candidate survives ONLY if Gate 1 (held-out beats the
/// matched null AND clears the population-relative material-effect bar) AND Gate 2
/// (Thread-3 consistency) both pass. The expected outcome is NO surviving candidate.
///
/// # Errors
/// Returns [`GakAttackError`] if the language models cannot be built (Gate 3 only) or
/// the candidate record cannot be written.
fn finalize_eyes_run(inputs: EyesRunFinalize) -> Result<EyesAttackReport, GakAttackError> {
    let EyesRunFinalize {
        config,
        order,
        message_values,
        total_symbols,
        distinct_symbols,
        gate1,
        three_consistency,
        held_out_positive_control,
    } = inputs;

    let candidate_survived = gate1.held_out_beats_null && three_consistency.consistent;
    let speculative_cleartext = if candidate_survived {
        Some(eyes_speculative_cleartext(&message_values, &config)?)
    } else {
        None
    };

    let order_name = order.name();
    let trials = config.trials;
    let record_path = config.candidates_dir.join(eyes_record_filename(&config));
    write_eyes_candidate_record(
        &record_path,
        &EyesRecordInputs {
            config: &config,
            order_name: &order_name,
            total_symbols,
            distinct_symbols,
            per_message: &gate1.per_message,
            real_held_out_hits_total: gate1.real_held_out_hits_total,
            real_held_out_misses_total: gate1.real_held_out_misses_total,
            real_held_out_ambiguous_total: gate1.real_held_out_ambiguous_total,
            real_score: gate1.real_score,
            scoreable_edges: gate1.scoreable_edges,
            max_achievable_score: gate1.max_achievable_score,
            null_mean_score: gate1.null_mean_score,
            material_effect_threshold: gate1.material_effect_threshold,
            material_effect_met: gate1.material_effect_met,
            matched_null_p_value: gate1.matched_null_p_value,
            null_at_least_real: gate1.null_at_least_real,
            held_out_beats_null: gate1.held_out_beats_null,
            held_out_positive_control,
            three_consistency,
            candidate_survived,
            speculative_cleartext: speculative_cleartext.as_ref(),
        },
    )?;

    Ok(EyesAttackReport {
        config,
        order_name,
        total_symbols,
        distinct_symbols,
        per_message: gate1.per_message,
        real_held_out_hits_total: gate1.real_held_out_hits_total,
        real_held_out_misses_total: gate1.real_held_out_misses_total,
        real_held_out_ambiguous_total: gate1.real_held_out_ambiguous_total,
        real_score: gate1.real_score,
        scoreable_edges: gate1.scoreable_edges,
        max_achievable_score: gate1.max_achievable_score,
        null_mean_score: gate1.null_mean_score,
        material_effect_threshold: gate1.material_effect_threshold,
        material_effect_met: gate1.material_effect_met,
        trials,
        null_at_least_real: gate1.null_at_least_real,
        matched_null_p_value: gate1.matched_null_p_value,
        held_out_beats_null: gate1.held_out_beats_null,
        held_out_positive_control,
        three_consistency,
        candidate_survived,
        speculative_cleartext,
        record_path,
    })
}

/// Significance threshold for the eyes Step-3 matched-null held-out tail. A real
/// coverage-weighted score must clear this add-one p-value (and beat the null mean)
/// to count as "beats null"; it is the same `0.05` convention used elsewhere.
const EYES_SIGNIFICANCE_ALPHA: f64 = 0.05;

/// POPULATION-RELATIVE MATERIAL-EFFECT fraction (codex's "effect size, not just
/// p-value"; F1): the real-vs-null-mean held-out excess must reach this FRACTION of
/// the population's OWN max achievable score (`scoreable_edges * (A-1)`) for a
/// candidate to pass Gate 1. Anchoring the bar to the SAME population under test (not
/// to the much larger synthetic positive control's population) makes it FAIR: a
/// genuine eye signal that captures >= 25% of the signal achievable on its own
/// held-out edges clears it, while a thin isomorph-richness leak (excess ~0) fails.
/// The detector is still VALIDATED because the positive control must clear ITS OWN
/// population's bar by the same rule. Set to one quarter of the achievable signal —
/// generous to a real recovery, fatal to a thin leak.
pub const EYES_MATERIAL_EFFECT_FRACTION: f64 = 0.25;

/// Trial count for the Thread-3 consistency consultation. The fields we read
/// (robust internal violations, safe extents, positive-control fire) are
/// trial-count-independent, so this is kept small for speed while still exercising
/// Thread 3's own null/positive-control machinery.
const EYES_THREE_CONSISTENCY_TRIALS: usize = 64;

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
/// `safe_spans_by_message` (F2) supplies, in the SAME order as `keys`, the Thread-3
/// safe spans each message's Gate-1 chaining is restricted to. A message without
/// safe spans yields no admitted windows (and therefore no scored edges).
fn eyes_per_message_held_out(
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
/// (F2 — ENFORCED, not just claimed). Thread 3 exports conservative per-message safe
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
struct SafeWindowFilter<'a> {
    /// `Some(spans)` restricts to those half-open safe spans; `None` admits all.
    spans: Option<&'a [(usize, usize)]>,
}

impl<'a> SafeWindowFilter<'a> {
    /// The unrestricted filter (synthetic positive control only — admits everything).
    const fn unrestricted() -> Self {
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
struct EyeContextAction {
    /// Forward partial bijection `from -> to` for this single context.
    forward: BTreeMap<u8, u8>,
    /// Provenance for the positional embargo and same-group rejection.
    provenance: ContextProvenance,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct EyeMessageEvidence {
    /// TRAIN-fold context actions (one per train isomorph occurrence pair). The
    /// recovered "model" is this LIBRARY of context-colored partial permutations,
    /// NOT a collapsed global map — the wiki-faithful object.
    train_contexts: Vec<EyeContextAction>,
    /// HELD-OUT-fold context actions (from DISJOINT signature groups). Validation
    /// only; never contributes a train context.
    held_out_contexts: Vec<EyeContextAction>,
    /// Distinct isomorph signature groups (≥2 occurrences).
    isomorph_groups: usize,
    /// Aligned isomorph occurrence pairs that yielded chain links.
    aligned_pairs: usize,
    /// Distinct reading-layer symbols touched by any chain link (coverage).
    symbols_touched: usize,
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
    /// size the population-relative material-effect bar in F1: the MAX achievable
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
/// for that population (F1) — unlike an absolute bar pinned to one population's size.
fn max_achievable_score(scoreable_edges: usize) -> f64 {
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
/// `safe_filter` (F2) restricts which isomorph occurrence windows are admitted: a
/// window is only used when [`SafeWindowFilter::admits`] accepts its `[start, end)`,
/// so on the real eyes chaining stays WITHIN Thread-3's safe isomorph extents and
/// never over-extends. The synthetic positive control passes the unrestricted filter.
/// The restriction is positional, so the matched within-message shuffle null (which
/// preserves positions) sees the identical admissibility — the null stays symmetric.
fn eyes_message_evidence(
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
            // F2: admit a window only when it lies within a Thread-3 safe extent (the
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
enum AggregateSafeFilter<'a> {
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
/// gives the population's SCOREABLE-edge total, which sizes the F1 material-effect bar
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
fn eyes_aggregate_score(
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
fn eyes_matched_null_tail(
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
/// control's OWN population-relative material-effect bar (F1: a fraction of the
/// control's max achievable score). If it does not fire, the held-out gate is not
/// trustworthy. The fixture is scored UNRESTRICTED (it is not a corpus message and
/// has no Thread-3 safe extent), so the detector is validated on its full known
/// signal.
///
/// # Errors
/// Returns [`GakAttackError`] if a generated value is out of range or a shuffle
/// bound does not fit the PRNG.
fn eyes_held_out_positive_control(
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
    // FIRE (F1-validated): the real signal's coverage-weighted score strictly beats
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
fn synthetic_isomorph_rich_eye_message(seed: u64) -> Result<Vec<TrigramValue>, GakAttackError> {
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

/// The Thread-3 consultation: the consistency verdict PLUS the per-message safe
/// isomorph spans Gate-1 chaining is ENFORCED to stay within (F2).
struct ThreeConsultation {
    /// The Gate-2 consistency verdict consumed by the report.
    verdict: ThreeConsistency,
    /// For each message (in the SAME order as the corpus keys), the half-open safe
    /// spans Thread 3 exported for that message. Gate-1 windows are admitted only
    /// within these spans; an empty inner list means Thread 3 found no safe extent in
    /// that message, so NO Gate-1 window there is admitted.
    safe_spans_by_message: Vec<Vec<(usize, usize)>>,
}

/// Consults Thread 3's perfect-isomorphism scan for the consistency gate AND the
/// safe-extent enforcement (REUSE — run ONCE, both products derived from one report).
///
/// Reads the Thread-3 report's `robust_internal_violations` (must be `0` — a
/// non-zero count is a manufactured TRUE conflict), `safe_extents` (the conservative
/// per-message spans Gate-1 chaining is RESTRICTED to — F2), and
/// `positive_control_fired` (the scan is trustworthy). The candidate model is
/// CONSISTENT only if there are zero robust internal violations and the positive
/// control fired. The per-message safe spans are projected from the cross-message
/// extents and returned in `keys` order so Gate 1 can enforce them.
///
/// # Errors
/// Returns [`GakAttackError::PerfectIsomorphism`] if the Thread-3 scan fails.
fn eyes_three_consultation(keys: &[&'static str]) -> Result<ThreeConsultation, GakAttackError> {
    // The fields we consult — robust internal violations, safe extents, and the
    // positive-control fire — are DETERMINISTIC in the trial count (trials only
    // size the null band we do not read here), so a small trial count gives the
    // identical verdict far faster. We still run a non-trivial count so Thread 3's
    // own ZeroTrials guard and positive control execute normally.
    let report = perfect_isomorphism::run_perfect_isomorphism(
        perfect_isomorphism::PerfectIsomorphismConfig {
            trials: EYES_THREE_CONSISTENCY_TRIALS,
            ..perfect_isomorphism::PerfectIsomorphismConfig::default()
        },
    )?;
    let consistent = report.robust_internal_violations == 0 && report.positive_control_fired;
    let safe_spans_by_message = eyes_safe_spans_by_message(&report.safe_extents, keys);
    Ok(ThreeConsultation {
        verdict: ThreeConsistency {
            robust_internal_violations: report.robust_internal_violations,
            safe_extents: report.safe_extents.len(),
            positive_control_fired: report.positive_control_fired,
            consistent,
        },
        safe_spans_by_message,
    })
}

/// Projects the cross-message Thread-3 safe extents onto PER-MESSAGE half-open spans,
/// in the SAME order as `keys` (F2 enforcement input).
///
/// Each [`perfect_isomorphism::SafeIsomorphExtent`] is a SAFE cross-message aligned
/// isomorph: its `pair = (left_key, right_key)` carries a `left_span` in the left
/// message and a `right_span` in the right message. A Gate-1 occurrence window in
/// message `key` is admissible only inside a span where THIS message safely
/// participates in a cross-message isomorph alignment, so we collect, for each key,
/// every left span whose `pair.0 == key` and every right span whose `pair.1 == key`.
/// Messages with no safe extent get an empty span list (no Gate-1 window admitted).
fn eyes_safe_spans_by_message(
    extents: &[perfect_isomorphism::SafeIsomorphExtent],
    keys: &[&'static str],
) -> Vec<Vec<(usize, usize)>> {
    keys.iter()
        .map(|&key| {
            let mut spans: Vec<(usize, usize)> = Vec::new();
            for extent in extents {
                if extent.pair.0 == key {
                    spans.push((extent.left_span.start, extent.left_span.end()));
                }
                if extent.pair.1 == key {
                    spans.push((extent.right_span.start, extent.right_span.end()));
                }
            }
            spans
        })
        .collect()
}

/// Runs the SPECULATIVE cleartext-plausibility gate (kill gate 3) — ONLY reached if
/// both structural gates passed (the expected case is that this is never run).
///
/// The symbol→letter mapping here is a HYPOTHESIS, never recovered: the
/// reading-layer symbols are mapped onto the language alphabet by a fixed,
/// explicitly-arbitrary affine projection `value*stride % alphabet_len`, the
/// implied plaintext is scored under the Finnish AND English models (Finnish
/// weighted highly — Noita is a Finnish game), and the scores are compared
/// against a matched null drawn from the SAME affine family (random coprime
/// stride + offset), so the single real stride sits at a well-defined percentile
/// within one exchangeable family rather than against a different-shape draw.
/// This is never primary evidence; the implied plaintext is logged verbatim for
/// human review regardless of the verdict.
///
/// # Errors
/// Returns [`GakAttackError::Language`] if a language model cannot be built.
fn eyes_speculative_cleartext(
    message_values: &[Vec<TrigramValue>],
    config: &EyesAttackConfig,
) -> Result<SpeculativeCleartext, GakAttackError> {
    let finnish = language::finnish_model()?;
    let english = language::english_model()?;
    let alphabet_len = finnish.alphabet().len().max(1);

    // HYPOTHESIZED (arbitrary) symbol→letter mapping: a fixed modular projection of
    // the reading-layer value onto the language alphabet. This is NOT recovered and
    // is labelled a hypothesis everywhere.
    let mapping = eyes_hypothesis_mapping(alphabet_len, config.seed);
    let indices: Vec<usize> = message_values
        .iter()
        .flatten()
        .map(|value| mapping.get(usize::from(value.get())).copied().unwrap_or(0))
        .collect();

    let implied_plaintext = render_implied_plaintext(&indices, &finnish);
    let finnish_score = finnish
        .score_indices(&indices)
        .map_or(f64::NEG_INFINITY, |s| s.bigram_mean_log_likelihood);
    let english_score = english
        .score_indices(&indices)
        .map_or(f64::NEG_INFINITY, |s| s.bigram_mean_log_likelihood);

    // Matched null: draw other mappings from the SAME affine family (random
    // coprime stride + offset) and re-score. The implied plaintext only "beats"
    // the null if it exceeds the affine-family mean — and even then it is a
    // HYPOTHESIS.
    let (finnish_null_mean, english_null_mean) =
        eyes_mapping_null(message_values, alphabet_len, config, &finnish, &english);

    Ok(SpeculativeCleartext {
        implied_plaintext,
        finnish_score,
        english_score,
        finnish_null_mean,
        english_null_mean,
        beats_finnish_null: finnish_score > finnish_null_mean,
        beats_english_null: english_score > english_null_mean,
    })
}

/// Builds the HYPOTHESIZED (arbitrary, never-recovered) symbol→letter mapping for
/// the speculative gate: a fixed modular projection of each reading-layer value onto
/// the language alphabet. Labelled a hypothesis everywhere it is used.
fn eyes_hypothesis_mapping(alphabet_len: usize, seed: u64) -> Vec<usize> {
    let stride = 1 + (seed as usize % alphabet_len.max(1));
    (0..EYE_READING_ALPHABET_SIZE)
        .map(|value| (value.wrapping_mul(stride)) % alphabet_len)
        .collect()
}

/// Draws one `(stride, offset)` pair from the affine family used by
/// [`eyes_hypothesis_mapping`]: a stride coprime to `len` (so the map is a
/// bijection on `0..len`) and a uniform offset in `0..len`. Returns `None` if an
/// index draw fails (unreachable for `len >= 1` on 64-bit targets).
fn draw_affine_stride_offset(len: usize, rng: &mut SplitMix64) -> Option<(usize, usize)> {
    // Rejection-sample a coprime stride in 1..=len, mirroring the real mapping's
    // `1 + (seed % len)` range. `len` is coprime to itself only when `len == 1`,
    // and `stride == 1` is always coprime, so this loop always terminates.
    let stride = loop {
        let stride = random_index_below(len, rng).ok()? + 1;
        if gcd(stride, len) == 1 {
            break stride;
        }
    };
    let offset = random_index_below(len, rng).ok()?;
    Some((stride, offset))
}

/// Greatest common divisor of two non-negative integers (Euclid's algorithm).
fn gcd(mut left: usize, mut right: usize) -> usize {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

/// Renders the implied plaintext string under a hypothesized mapping (for verbatim
/// logging). Each index becomes its alphabet symbol; out-of-range indices become `?`.
fn render_implied_plaintext(indices: &[usize], model: &LanguageModel) -> String {
    let mut rendered = String::with_capacity(indices.len());
    for &index in indices {
        match model.alphabet().symbol(index) {
            Some(symbol) => rendered.push(symbol),
            None => rendered.push('?'),
        }
    }
    rendered
}

/// Matched null for the speculative cleartext gate: mean Finnish/English bigram
/// scores over mappings drawn from the SAME affine family as the real hypothesis
/// (see [`eyes_hypothesis_mapping`]). Each trial draws a random stride coprime to
/// `alphabet_len` and a random offset and builds `full[value] = (value*a + b) %
/// alphabet_len`, so the single real stride sits at a well-defined percentile of
/// one exchangeable family rather than against a different-shape (random
/// relabeling) draw.
fn eyes_mapping_null(
    message_values: &[Vec<TrigramValue>],
    alphabet_len: usize,
    config: &EyesAttackConfig,
    finnish: &LanguageModel,
    english: &LanguageModel,
) -> (f64, f64) {
    let trials = config.trials.clamp(1, 256);
    let mut finnish_sum = 0.0f64;
    let mut english_sum = 0.0f64;
    let mut counted = 0usize;
    for trial in 0..trials {
        let mut rng = SplitMix64::new(mix_seed(
            config.seed,
            0x6d61_705f_6e75_6c6c ^ u64::try_from(trial).unwrap_or(u64::MAX),
        ));
        // Draw this trial's mapping from the SAME affine family as the real
        // hypothesis: a stride `a` coprime to `alphabet_len` and an offset `b`.
        let len = alphabet_len.max(1);
        let Some((a, b)) = draw_affine_stride_offset(len, &mut rng) else {
            continue;
        };
        let full: Vec<usize> = (0..EYE_READING_ALPHABET_SIZE)
            .map(|value| (value.wrapping_mul(a).wrapping_add(b)) % len)
            .collect();
        let indices: Vec<usize> = message_values
            .iter()
            .flatten()
            .map(|value| full.get(usize::from(value.get())).copied().unwrap_or(0))
            .collect();
        let f = finnish
            .score_indices(&indices)
            .map_or(f64::NEG_INFINITY, |s| s.bigram_mean_log_likelihood);
        let e = english
            .score_indices(&indices)
            .map_or(f64::NEG_INFINITY, |s| s.bigram_mean_log_likelihood);
        if f.is_finite() && e.is_finite() {
            finnish_sum += f;
            english_sum += e;
            counted = counted.saturating_add(1);
        }
    }
    if counted == 0 {
        (f64::NEG_INFINITY, f64::NEG_INFINITY)
    } else {
        (finnish_sum / counted as f64, english_sum / counted as f64)
    }
}

/// Derives a STABLE candidate-record filename from the run config/seed (NO clock).
///
/// The record must be reproducible, so the label is derived only from the seed,
/// trial count, and beam width — never a wall-clock timestamp.
fn eyes_record_filename(config: &EyesAttackConfig) -> String {
    format!(
        "eyes-seed-{:016x}-trials-{}-beam-{}.md",
        config.seed, config.trials, config.beam_width
    )
}

/// Bundle of inputs for writing the candidate record (keeps the writer signature
/// small and avoids a long argument list).
struct EyesRecordInputs<'a> {
    config: &'a EyesAttackConfig,
    order_name: &'a str,
    total_symbols: usize,
    distinct_symbols: usize,
    per_message: &'a [EyeMessageHeldOut],
    real_held_out_hits_total: usize,
    real_held_out_misses_total: usize,
    real_held_out_ambiguous_total: usize,
    real_score: i64,
    scoreable_edges: usize,
    max_achievable_score: f64,
    null_mean_score: f64,
    material_effect_threshold: f64,
    material_effect_met: bool,
    matched_null_p_value: f64,
    null_at_least_real: usize,
    held_out_beats_null: bool,
    held_out_positive_control: HeldOutPositiveControl,
    three_consistency: ThreeConsistency,
    candidate_survived: bool,
    speculative_cleartext: Option<&'a SpeculativeCleartext>,
}

/// Writes the mandatory candidate record for the eyes Step-3 run (filename is a
/// STABLE config/seed label, NO clock; re-running the same config overwrites the
/// prior record).
///
/// The record captures what was attempted, how much structure was recovered, the
/// held-out verdict + matched-null p-value, the Thread-3 consistency verdict, and
/// the explicit HYPOTHESIS-not-decode label and claim ceiling. If any candidate
/// cleartext emerged (the speculative gate ran) it is logged VERBATIM in English
/// AND Finnish with its scores and caveats. The expected record is a "NO candidate
/// surfaced — decode remains blocked" entry.
///
/// # Errors
/// Returns [`GakAttackError::CandidateRecordWrite`] if the directory cannot be
/// created or the file cannot be written.
fn write_eyes_candidate_record(
    path: &Path,
    inputs: &EyesRecordInputs<'_>,
) -> Result<(), GakAttackError> {
    let body = render_eyes_candidate_record(inputs).map_err(|_error| {
        GakAttackError::CandidateRecordWrite {
            path: path.display().to_string(),
        }
    })?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|_error| GakAttackError::CandidateRecordWrite {
            path: path.display().to_string(),
        })?;
    }
    std::fs::write(path, body).map_err(|_error| GakAttackError::CandidateRecordWrite {
        path: path.display().to_string(),
    })
}

/// Renders the candidate-record markdown body (split out so it is unit-testable
/// without touching the filesystem). Returns a [`std::fmt::Error`] only if a
/// string-buffer write fails (never, for an in-memory `String`).
fn render_eyes_candidate_record(inputs: &EyesRecordInputs<'_>) -> Result<String, std::fmt::Error> {
    let mut out = String::new();
    let verdict = if inputs.candidate_survived {
        "CANDIDATE SURVIVED BOTH STRUCTURAL GATES — logged as a HYPOTHESIS, NOT a decode"
    } else {
        "NO candidate surfaced — decode remains blocked"
    };
    // Header + claim ceiling (verbatim-in-spirit).
    writeln!(out, "# Eyes Step-3 GAK-attack candidate record")?;
    writeln!(out)?;
    writeln!(
        out,
        "Stable label (NO wall-clock): seed=0x{:016x} trials={} beam={}",
        inputs.config.seed, inputs.config.trials, inputs.config.beam_width
    )?;
    writeln!(out)?;
    writeln!(out, "## Verdict")?;
    writeln!(out)?;
    writeln!(out, "**{verdict}.**")?;
    writeln!(out)?;
    writeln!(
        out,
        "This record is a HYPOTHESIS, NOT a decode. The standing conclusion is the eye"
    )?;
    writeln!(
        out,
        "decode remains BLOCKED on the unknown symbol->meaning mapping, and it is"
    )?;
    writeln!(
        out,
        "preserved by this run unless a candidate survived BOTH structural gates below."
    )?;
    writeln!(out)?;
    writeln!(out, "## Claim ceiling (absolute)")?;
    writeln!(out)?;
    writeln!(
        out,
        "The eyes are deterministic, engine-generated, strikingly structured data of unknown meaning; unsolved; no primary developer source confirms recoverable plaintext."
    )?;
    writeln!(
        out,
        "Nothing in this record is stronger. The EXPECTED outcome of this unit is NO"
    )?;
    writeln!(
        out,
        "surviving candidate; a clean honest negative is a SUCCESS, not a failure."
    )?;
    writeln!(out)?;

    // What was attempted + entry path.
    writeln!(out, "## What was attempted")?;
    writeln!(out)?;
    writeln!(
        out,
        "Pointed the matured chain-link / hidden-state attack at the REAL eye corpus"
    )?;
    writeln!(
        out,
        "via the exact entry path orders::corpus_grids() -> accepted_honeycomb_order()"
    )?;
    writeln!(
        out,
        "-> read_corpus_message_values (per-message, boundaries kept, order `{}`).",
        inputs.order_name
    )?;
    writeln!(
        out,
        "Corpus pins: {} reading-layer symbols, {} distinct (83-symbol reading layer).",
        inputs.total_symbols, inputs.distinct_symbols
    )?;
    writeln!(
        out,
        "The attack recovers STRUCTURE (visible-coset / chain-link constraints), NOT"
    )?;
    writeln!(
        out,
        "cleartext: a full structural recovery still yields abstract letter INDICES,"
    )?;
    writeln!(
        out,
        "not readable text, because symbol->letter mapping needs an external anchor"
    )?;
    writeln!(out, "(the standing blocker).")?;
    writeln!(out)?;

    render_eyes_gate1(&mut out, inputs)?;
    render_eyes_gates_2_3_conclusion(&mut out, inputs)?;
    Ok(out)
}

/// Writes the Gate-1 (held-out isomorphs) section of the candidate record.
fn render_eyes_gate1(out: &mut String, inputs: &EyesRecordInputs<'_>) -> std::fmt::Result {
    // Gate 1: held-out (embargoed-consensus coverage-weighted excess correctness).
    writeln!(
        out,
        "## Gate 1 — held-out isomorphs vs matched within-message null"
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "Statistic: EMBARGOED-CONSENSUS coverage-weighted excess correctness. The"
    )?;
    writeln!(
        out,
        "recovered model is a LIBRARY of context-colored partial permutations (one per"
    )?;
    writeln!(
        out,
        "TRAIN isomorph occurrence pair), NOT a collapsed global symbol map. A held-out"
    )?;
    writeln!(
        out,
        "edge scores only when >=2 train contexts from DISTINCT signature groups, with NO",
    )?;
    writeln!(
        out,
        "physical span overlap/adjacency with the held-out context, AGREE on it (the"
    )?;
    writeln!(
        out,
        "embargo kills the nested/overlapping-window leak a shuffle mimics):"
    )?;
    writeln!(
        out,
        "score = (A-1)*hits - A*misses (ambiguous unpenalized), A=83. A per-message"
    )?;
    writeln!(
        out,
        "COVERAGE CLAMP zeroes any message with < 4 confident decisions (hits+misses) —"
    )?;
    writeln!(
        out,
        "an explicit part of the statistic, applied identically to the real eyes and to"
    )?;
    writeln!(
        out,
        "every matched-null shuffle, so it cannot manufacture a real-vs-null gap. Only"
    )?;
    writeln!(
        out,
        "structure transferable across DISTINCT signature groups scores; a within-message"
    )?;
    writeln!(
        out,
        "shuffle has none detected by this gate, so it scores ~0. Gate-1 chaining is"
    )?;
    writeln!(
        out,
        "ENFORCED to stay WITHIN the Thread-3 safe isomorph extents (F2): an occurrence"
    )?;
    writeln!(
        out,
        "window is admitted only when it lies inside a Thread-3 safe span for its message,"
    )?;
    writeln!(
        out,
        "so chaining never over-extends past a Thread-3 break (the restriction is"
    )?;
    writeln!(
        out,
        "positional, so the matched null is scored under the identical restriction)."
    )?;
    render_eyes_gate1_scores(out, inputs)
}

/// Writes the Gate-1 score lines + per-message table of the candidate record.
fn render_eyes_gate1_scores(out: &mut String, inputs: &EyesRecordInputs<'_>) -> std::fmt::Result {
    writeln!(
        out,
        "Held-out positive control on a SYNTHETIC isomorph-rich eye-shaped fixture:"
    )?;
    writeln!(
        out,
        "  real score {} vs worst-case null score {} (on {} scoreable edges) -> fired={}",
        inputs.held_out_positive_control.real_score,
        inputs.held_out_positive_control.null_score,
        inputs.held_out_positive_control.scoreable_edges,
        inputs.held_out_positive_control.fired
    )?;
    writeln!(
        out,
        "  (the predictor must fire on KNOWN signal AND clear its OWN population's"
    )?;
    writeln!(
        out,
        "  material-effect bar, or the held-out gate is not trusted)."
    )?;
    writeln!(
        out,
        "Real eyes aggregate held-out: hits={} misses={} ambiguous={}; coverage-weighted score = {}.",
        inputs.real_held_out_hits_total,
        inputs.real_held_out_misses_total,
        inputs.real_held_out_ambiguous_total,
        inputs.real_score
    )?;
    writeln!(
        out,
        "Matched within-message shuffle null: {} trials, {} >= real; null mean score {:.2}; add-one p = {:.4}.",
        inputs.config.trials,
        inputs.null_at_least_real,
        inputs.null_mean_score,
        inputs.matched_null_p_value
    )?;
    let fraction = EYES_MATERIAL_EFFECT_FRACTION;
    writeln!(
        out,
        "Material-effect bar (p-value alone is NECESSARY, NOT sufficient), POPULATION-RELATIVE"
    )?;
    writeln!(
        out,
        "and FAIR to the eyes: the real-vs-null excess must reach {fraction:.2} of the eyes' OWN max",
    )?;
    writeln!(
        out,
        "achievable score = scoreable_edges*(A-1) = {}*82 = {:.0}, so the bar = {:.1}. The eyes",
        inputs.scoreable_edges, inputs.max_achievable_score, inputs.material_effect_threshold
    )?;
    writeln!(
        out,
        "COULD clear this bar with real signal (the bar is BELOW their max achievable); their"
    )?;
    let real_excess = inputs.real_score as f64 - inputs.null_mean_score;
    writeln!(
        out,
        "excess is {real_excess:.1} (real {} - null mean {:.2}), threshold {:.1}, so met={}. The detector is validated: the positive control clears its own",
        inputs.real_score,
        inputs.null_mean_score,
        inputs.material_effect_threshold,
        inputs.material_effect_met
    )?;
    writeln!(out, "population's bar by the identical rule.")?;
    writeln!(
        out,
        "GATE 1 VERDICT (held-out beats matched null AND clears the material-effect bar): {}.",
        inputs.held_out_beats_null
    )?;
    writeln!(out)?;
    writeln!(out, "Per-message (boundaries kept; never concatenated):")?;
    for m in inputs.per_message {
        writeln!(
            out,
            "  {:<6} len={:<3} iso-groups={:<3} pairs={:<4} touched={:<3} aborts={:<3} hits={} miss={} amb={} score={}",
            m.message_key,
            m.length,
            m.isomorph_groups,
            m.aligned_pairs,
            m.symbols_touched,
            m.true_conflict_aborts,
            m.real_held_out_hits,
            m.real_held_out_misses,
            m.real_held_out_ambiguous,
            m.real_score
        )?;
    }
    writeln!(out)?;
    Ok(())
}

/// Writes the Gate-2, Gate-3, and Standing-conclusion sections of the record.
fn render_eyes_gates_2_3_conclusion(
    out: &mut String,
    inputs: &EyesRecordInputs<'_>,
) -> std::fmt::Result {
    // Gate 2: Thread-3 consistency.
    writeln!(
        out,
        "## Gate 2 — Thread-3 perfect-isomorphism consistency (reused API)"
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "robust internal violations: {} (must be 0 — a non-zero count is a manufactured",
        inputs.three_consistency.robust_internal_violations
    )?;
    writeln!(out, "TRUE conflict and would disqualify the model).")?;
    writeln!(
        out,
        "safe isomorph extents exported: {} (Gate-1 chaining is ENFORCED to stay within",
        inputs.three_consistency.safe_extents
    )?;
    writeln!(
        out,
        "these per-message safe spans (F2) — an occurrence window is admitted only inside a"
    )?;
    writeln!(
        out,
        "Thread-3 safe span, so chaining never over-extends past them)."
    )?;
    writeln!(
        out,
        "Thread-3 positive control fired: {}.",
        inputs.three_consistency.positive_control_fired
    )?;
    writeln!(
        out,
        "GATE 2 VERDICT (model consistent with Thread 3): {}.",
        inputs.three_consistency.consistent
    )?;
    writeln!(out)?;
    render_eyes_gate3_conclusion(out, inputs)
}

/// Writes the Gate-3 (speculative cleartext) and Standing-conclusion sections.
fn render_eyes_gate3_conclusion(
    out: &mut String,
    inputs: &EyesRecordInputs<'_>,
) -> std::fmt::Result {
    // Gate 3: speculative cleartext.
    writeln!(
        out,
        "## Gate 3 — SPECULATIVE cleartext plausibility (Finnish-weighted)"
    )?;
    writeln!(out)?;
    match inputs.speculative_cleartext {
        None => {
            writeln!(
                out,
                "NOT RUN. Gate 1 and/or Gate 2 did not pass (the expected case), so the"
            )?;
            writeln!(
                out,
                "speculative cleartext path is correctly NOT executed and NO candidate"
            )?;
            writeln!(out, "cleartext is reported. The decode remains blocked.")?;
        }
        Some(s) => {
            writeln!(
                out,
                "RAN (both structural gates passed). The symbol->letter mapping below is a",
            )?;
            writeln!(
                out,
                "HYPOTHESIS, never recovered; this is NEVER primary evidence. Logged VERBATIM",
            )?;
            writeln!(
                out,
                "for human review (Finnish weighted highly — Noita is Finnish)."
            )?;
            writeln!(out)?;
            writeln!(
                out,
                "Finnish bigram score {:.4} vs matched-mapping null mean {:.4} -> beats={}",
                s.finnish_score, s.finnish_null_mean, s.beats_finnish_null
            )?;
            writeln!(
                out,
                "English bigram score {:.4} vs matched-mapping null mean {:.4} -> beats={}",
                s.english_score, s.english_null_mean, s.beats_english_null
            )?;
            writeln!(out)?;
            writeln!(out, "Implied plaintext (HYPOTHESIS, verbatim):")?;
            writeln!(out, "```")?;
            writeln!(out, "{}", s.implied_plaintext)?;
            writeln!(out, "```")?;
        }
    }
    writeln!(out)?;
    writeln!(out, "## Standing conclusion")?;
    writeln!(out)?;
    if inputs.candidate_survived {
        writeln!(
            out,
            "A candidate survived both structural gates. It is logged here as a HYPOTHESIS",
        )?;
        writeln!(
            out,
            "for human review, NOT a decode. The standing claim is softened to \"a candidate",
        )?;
        writeln!(
            out,
            "structure passed the held-out + Thread-3 checks\" — it is NOT a recovered"
        )?;
        writeln!(out, "plaintext and the claim ceiling still binds.")?;
    } else {
        writeln!(
            out,
            "No candidate surfaced. The eye decode REMAINS BLOCKED on the unknown"
        )?;
        writeln!(
            out,
            "symbol->meaning mapping. This negative is the expected, reportable outcome."
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_PHRASE_LEN, GakAttackConfig, GroupKind, HiddenSubgroupKind, SOLVER_WINDOW_LEN,
        canonical_letters, collect_chain_links, generate_fixture, glyphs_to_values,
        initial_state_readout, phrase_chain_links, run_gak_attack, solve_gctak,
        truth_letter_permutations, verify_against_chain_links,
    };
    use crate::chaining_graph::{
        AlignedOccurrence, ChainLink, ContextId, SymbolValue, chain_links_for_pair,
    };
    use crate::ciphers::{gak_decrypt, gak_encrypt};
    use crate::glyph::Glyph;

    fn cyclic(order: usize) -> GroupKind {
        GroupKind::Cyclic { order }
    }

    fn dihedral(half_order: usize) -> GroupKind {
        GroupKind::Dihedral { half_order }
    }

    #[test]
    fn generator_round_trips_for_both_group_kinds() {
        let config = GakAttackConfig::default();
        for group in [cyclic(6), dihedral(4)] {
            for seed in [1u64, 2, 3] {
                let fixture = generate_fixture(group, config, seed).unwrap();
                let decrypted = gak_decrypt(&fixture.ciphertext, &fixture.key).unwrap();
                assert_eq!(
                    decrypted, fixture.plaintext,
                    "round trip {group:?} seed={seed}"
                );
                let re_encrypted = gak_encrypt(&fixture.plaintext, &fixture.key).unwrap();
                assert_eq!(re_encrypted, fixture.ciphertext);
                assert_eq!(fixture.hidden_subgroup_kind, HiddenSubgroupKind::Trivial);
            }
        }
    }

    #[test]
    fn ciphertext_is_isomorph_rich_on_repeated_phrases() {
        use crate::isomorph::PatternSignature;
        let config = GakAttackConfig::default();
        let fixture = generate_fixture(cyclic(6), config, 7).unwrap();
        let values = glyphs_to_values(&fixture.ciphertext).unwrap();
        // GCTAK ciphertext is the ABSOLUTE group state, so a repeated plaintext
        // phrase does NOT repeat as identical ciphertext values. The isomorph
        // signal lives in the EQUALITY PATTERN, which recurs with the phrase
        // period. Assert at least one informative equality pattern repeats.
        let mut signature_counts: std::collections::BTreeMap<PatternSignature, usize> =
            std::collections::BTreeMap::new();
        for window in values.windows(SOLVER_WINDOW_LEN) {
            let signature = PatternSignature::from_window(window);
            if signature.has_repeated_symbol() {
                *signature_counts.entry(signature).or_default() += 1;
            }
        }
        let max_repeat = signature_counts.values().copied().max().unwrap_or(0);
        assert!(
            max_repeat >= 2,
            "expected a repeated isomorph equality pattern, got max repeat {max_repeat}"
        );
    }

    /// Solves one fixture and reports whether the real stream recovered exactly
    /// AND its chain-link verification passed (the gate's full recovery criterion).
    fn recovers_exactly(group: GroupKind, config: GakAttackConfig, seed: u64) -> bool {
        let fixture = generate_fixture(group, config, seed).unwrap();
        let outcome = super::evaluate_fixture(&fixture, config, seed).unwrap();
        outcome.real_recovered_exactly
    }

    #[test]
    fn gctak_solver_recovers_cyclic_at_high_rate() {
        let config = GakAttackConfig::default();
        let trials = 60usize;
        let recovered = (0..trials)
            .filter(|seed| recovers_exactly(cyclic(6), config, *seed as u64))
            .count();
        // Commutative GCTAK recovers on essentially every fixture.
        assert!(
            recovered >= trials - 1,
            "cyclic GCTAK recovery rate too low: {recovered}/{trials}"
        );
    }

    #[test]
    fn gctak_solver_recovers_dihedral_non_commutative_at_high_rate() {
        let config = GakAttackConfig::default();
        // Confirm dihedral is genuinely non-commutative (the witness the gate needs).
        assert!(dihedral(4).is_non_commutative());
        let trials = 60usize;
        let recovered = (0..trials)
            .filter(|seed| recovers_exactly(dihedral(4), config, *seed as u64))
            .count();
        // The non-commutative state group recovers on the large majority of
        // fixtures; completing every per-letter permutation from a finite stream is
        // the hard part the broader thread studies, so a minority are below the
        // solver's current capability. The gate passes on this RATE beating the
        // null (F1), not on any single retry-selected seed.
        assert!(
            recovered * 10 >= trials * 8,
            "dihedral GCTAK recovery rate too low: {recovered}/{trials}"
        );
        assert!(recovered >= 1, "dihedral GCTAK never recovered");
    }

    #[test]
    fn shuffled_ciphertext_does_not_recover_exactly() {
        use crate::null::{SplitMix64, fisher_yates};
        let config = GakAttackConfig::default();
        let mut null_recoveries = 0usize;
        let mut trials = 0usize;
        for group in [cyclic(6), dihedral(4)] {
            for seed in 0u64..20 {
                let fixture = generate_fixture(group, config, seed).unwrap();
                let truth = canonical_letters(
                    &fixture
                        .plaintext
                        .iter()
                        .map(|glyph| usize::from(glyph.0))
                        .collect::<Vec<_>>(),
                );
                let values = glyphs_to_values(&fixture.ciphertext).unwrap();
                let initial = initial_state_readout(&fixture.key).unwrap();
                let order = fixture.group_kind.order();
                let mut shuffled = values.clone();
                let mut rng = SplitMix64::new(seed ^ 0xdead_beef);
                fisher_yates(&mut shuffled, &mut rng).unwrap();
                let solution = solve_gctak(&shuffled, initial, config.phrase_len, order);
                trials += 1;
                if solution.canonical_letters == truth {
                    null_recoveries += 1;
                }
            }
        }
        // The matched within-message shuffle destroys the Cayley structure: in
        // this sample of `trials` shuffled seeds the same pipeline reproduced the
        // exact plaintext partition 0 times (F7: a rate over this sample, not a
        // claimed proof over the whole shuffle space).
        assert_eq!(
            null_recoveries, 0,
            "matched shuffle null achieved exact recovery {null_recoveries}/{trials} in this sample; recovery would be vacuous"
        );
    }

    #[test]
    fn chain_links_match_shared_chaining_graph_primitive() {
        use crate::isomorph::PatternSignature;
        // Prove the chain links genuinely come from chaining_graph::
        // chain_links_for_pair, not a private reimplementation: rebuild one pair's
        // links directly and assert they appear in the solver's link set.
        let config = GakAttackConfig {
            phrase_len: DEFAULT_PHRASE_LEN,
            ..GakAttackConfig::default()
        };
        let fixture = generate_fixture(cyclic(6), config, 42).unwrap();
        let values = glyphs_to_values(&fixture.ciphertext).unwrap();
        let links = collect_chain_links(&values);
        assert!(
            !links.is_empty(),
            "expected chain links from repeated phrases"
        );

        // Find a pair of equal-EQUALITY-PATTERN windows (the GCTAK isomorph signal;
        // ciphertext is not value-identical) and rebuild its links directly with the
        // shared chaining_graph primitive.
        let mut direct = None;
        'outer: for (i, left) in values.windows(SOLVER_WINDOW_LEN).enumerate() {
            let left_sig = PatternSignature::from_window(left);
            if !left_sig.has_repeated_symbol() {
                continue;
            }
            for right in values.windows(SOLVER_WINDOW_LEN).skip(i + 1) {
                if PatternSignature::from_window(right) == left_sig {
                    let upper = AlignedOccurrence {
                        message: 0,
                        window: left,
                        core_len: SOLVER_WINDOW_LEN,
                    };
                    let lower = AlignedOccurrence {
                        message: 0,
                        window: right,
                        core_len: SOLVER_WINDOW_LEN,
                    };
                    let rebuilt = chain_links_for_pair(ContextId::new(0), &upper, &lower).unwrap();
                    direct = Some(rebuilt);
                    break 'outer;
                }
            }
        }
        let rebuilt = direct.expect("expected at least one repeated equality-pattern window");
        // Each rebuilt link's (from,to) must appear among the solver's links, proving
        // the solver consumes chaining_graph::chain_links_for_pair, not a private copy.
        for link in &rebuilt {
            let present = links
                .iter()
                .any(|candidate| candidate.from == link.from && candidate.to == link.to);
            assert!(
                present,
                "rebuilt chain link {link:?} absent from solver links"
            );
        }
    }

    #[test]
    fn run_gak_attack_passes_on_rate_beats_null_not_a_lucky_seed() {
        // F1: the gate PASSES on the recovery RATE beating the matched null across
        // INDEPENDENT seeds — not on a single retry-selected fixture.
        let report = run_gak_attack(GakAttackConfig::default()).unwrap();
        assert_eq!(report.hidden_subgroup, HiddenSubgroupKind::Trivial);

        // Rate-based pass condition is recorded and is the authoritative signal.
        assert!(
            report.rate_gate_passed,
            "rate gate must pass (rate beats null) {:?}",
            report.rates
        );
        assert!(
            (report.min_real_recovery_rate - super::MIN_REAL_RECOVERY_RATE).abs() < f64::EPSILON
        );

        // Both real-rate and null-rate are surfaced per group kind, and the real
        // rate genuinely clears the floor and strictly exceeds the null rate (~0).
        assert_eq!(report.rates.len(), 2);
        for rate in &report.rates {
            assert!(
                rate.real_fraction() >= super::MIN_REAL_RECOVERY_RATE,
                "{} real rate {} below floor",
                rate.group,
                rate.real_fraction()
            );
            assert!(
                rate.real_fraction() > rate.null_fraction(),
                "{} real rate must beat null rate",
                rate.group
            );
            assert_eq!(rate.null_recovered, 0, "{} null must be ~0", rate.group);
        }
        assert!(
            report.rates.iter().any(|rate| rate.non_commutative),
            "dihedral (non-commutative) rate must be present"
        );
        assert!(
            report.rates.iter().any(|rate| !rate.non_commutative),
            "cyclic (commutative) rate must be present"
        );

        // The null failed on every INDEPENDENT seed (the required contrast).
        assert!(report.all_null_failed, "shuffle null must fail everywhere");

        // The independent backbone has both kinds × seeds_per_kind seeds; no retry
        // selection inflates these.
        assert_eq!(report.outcomes.len(), 2 * report.config.seeds_per_kind);
    }

    #[test]
    fn retry_selected_exemplar_is_labelled_not_the_pass_evidence() {
        // F1: the bounded-retry exemplar remains ONLY as an illustrative worked
        // example. It exposes attempts_used and a fully-recovered outcome, but the
        // gate's PASS is `rate_gate_passed`, computed without it.
        let report = run_gak_attack(GakAttackConfig::default()).unwrap();
        assert_eq!(report.exemplars.len(), 2);
        for exemplar in &report.exemplars {
            assert!(
                exemplar.outcome.real_recovered_exactly,
                "exemplar is a recovered fixture by construction"
            );
            assert!(
                exemplar.attempts_used >= 1,
                "attempts_used is a transparency counter"
            );
            // The exemplar's per-letter recovery is full on the chosen seed.
            assert_eq!(
                exemplar.outcome.real_permutations_recovered,
                exemplar.outcome.permutations_total
            );
        }
    }

    #[test]
    fn run_gak_attack_is_deterministic_for_fixed_seed() {
        let config = GakAttackConfig::default();
        let first = run_gak_attack(config).unwrap();
        let second = run_gak_attack(config).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn run_gak_attack_rejects_nonzero_small_support_radius() {
        // A2: the decisive GCTAK gate runs unconstrained (radius 0). A nonzero
        // small-support radius must be rejected up front in validate_config — not
        // crash the gate or silently change its declared assumptions further down —
        // so the report's "radius 0 / unconstrained" claim stays true by
        // construction. The error must be the dedicated config variant, never a
        // downstream cipher error.
        let config = GakAttackConfig {
            small_support_radius: 1,
            ..GakAttackConfig::default()
        };
        let err = run_gak_attack(config).unwrap_err();
        assert_eq!(
            err,
            super::GakAttackError::SmallSupportRadiusUnsupported { requested: 1 }
        );
    }

    #[test]
    fn run_gak_attack_rejects_too_few_letters_as_config_error() {
        // D3: `--letters` below two is a plain user config error and must be
        // rejected up front in validate_config, not surface later as
        // PositiveControlFailed ("methodology bug, never a data finding"). Two is
        // the real minimum (dihedral non-commutative witness + non-degenerate
        // phrase partition), so both 0 and 1 must yield the dedicated config
        // variant carrying the offending count.
        for requested in [0usize, 1usize] {
            let config = GakAttackConfig {
                num_pt_letters: requested,
                ..GakAttackConfig::default()
            };
            let err = run_gak_attack(config).unwrap_err();
            assert_eq!(err, super::GakAttackError::TooFewLetters { requested });
        }
    }

    #[test]
    fn small_support_knob_perturbs_a_permutation() {
        // The TENTATIVE small-support knob composes a base permutation with `radius`
        // random transpositions and must yield a valid permutation that differs from
        // the base (for a positive radius on a non-degenerate base). It is exercised
        // at the permutation level here; the GCTAK gate itself runs at radius 0 (the
        // trivial-H CosetTable readout requires the unperturbed regular
        // representation), and non-zero radius is reserved for later
        // deck/non-trivial-H units.
        use super::apply_small_support;
        use crate::null::SplitMix64;
        let base: Vec<usize> = (0..8).collect();
        let mut perturbed = base.clone();
        let mut rng = SplitMix64::new(0x73_6d61_6c6c_7370);
        apply_small_support(&mut perturbed, 3, &mut rng).unwrap();
        let mut sorted = perturbed.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, base, "small-support result must stay a permutation");
        assert_ne!(
            perturbed, base,
            "radius 3 should perturb the base permutation"
        );
    }

    #[test]
    fn round_trip_holds_for_generated_gate_fixtures() {
        // The generator's keys decrypt back to the plaintext exactly (the Step-0
        // round-trip control) for the actual gate fixtures.
        let config = GakAttackConfig::default();
        for group in [cyclic(6), dihedral(4)] {
            for seed in [0u64, 1, 2, 3, 4] {
                let fixture = generate_fixture(group, config, seed).unwrap();
                let decrypted = gak_decrypt(&fixture.ciphertext, &fixture.key).unwrap();
                assert_eq!(decrypted, fixture.plaintext);
            }
        }
    }

    #[test]
    fn chain_links_are_load_bearing_corruption_breaks_recovery() {
        use crate::null::{SplitMix64, fisher_yates};
        // F2: prove the chain links genuinely gate recovery — corrupting the
        // chain-link output must break the verification, so they are not tokenistic.
        let config = GakAttackConfig::default();
        let fixture = generate_fixture(cyclic(6), config, 11).unwrap();
        let values = glyphs_to_values(&fixture.ciphertext).unwrap();
        let initial = initial_state_readout(&fixture.key).unwrap();
        let order = fixture.group_kind.order();

        // Recover, then verify the (real) chain links against the recovered perms.
        let outcome = super::evaluate_fixture(&fixture, config, 11).unwrap();
        assert!(
            outcome.real_recovered_exactly,
            "baseline fixture must recover (incl. chain-link verification)"
        );
        assert!(
            outcome.chain_link_checks > 0,
            "expected chain-link adjacency constraints to check"
        );
        assert_eq!(
            outcome.chain_link_consistent, outcome.chain_link_checks,
            "real fixture must satisfy every chain-link constraint"
        );

        // Rebuild the recovered perms and the SOUND same-phrase chain links the
        // solver actually verifies against (built on the augmented walk exactly as
        // `solve_gctak` does), then CORRUPT the links by bumping each image symbol.
        // Verification must then fail, proving recovery consumes the chain-link
        // `from`/`to` fields.
        let solution = solve_gctak(&values, initial, config.phrase_len, order);
        let mut walk = vec![initial];
        walk.extend_from_slice(&values);
        let links = phrase_chain_links(&walk, config.phrase_len);
        assert!(
            !links.is_empty(),
            "expected non-empty same-phrase chain links"
        );
        // Sanity: the genuine links verify.
        let (base_checks, base_consistent) =
            verify_against_chain_links(&links, &solution.recovered_permutations);
        assert!(base_checks > 0);
        assert_eq!(base_consistent, base_checks, "genuine links must verify");

        // Corrupt by randomly permuting the image (`to`) values across all links.
        // This breaks the column correspondence the links encode (it is NOT a
        // group relabelling — in particular not a translation, which a cyclic
        // `tau_a` would absorb), so the same-letter adjacency premise fails and the
        // recovered permutations can no longer explain the links.
        let mut images: Vec<_> = links.iter().map(|link| link.to).collect();
        let mut rng = SplitMix64::new(0x00c0_ffee_feed_face);
        fisher_yates(&mut images, &mut rng).unwrap();
        let corrupted: Vec<ChainLink> = links
            .iter()
            .zip(images)
            .map(|(link, image)| {
                let mut clone = *link;
                clone.to = image;
                clone
            })
            .collect();
        let (checks, consistent) =
            verify_against_chain_links(&corrupted, &solution.recovered_permutations);
        assert!(checks > 0);
        assert!(
            consistent < checks,
            "corrupting chain links must break verification: {consistent}/{checks} still consistent"
        );
    }

    #[test]
    fn per_letter_permutation_recovery_fraction_is_full_on_real_and_low_on_null() {
        // F5: the recovered per-letter permutations are scored DIRECTLY against the
        // held truth tau_a (the spec's preferred metric), not only the partition.
        let config = GakAttackConfig::default();
        let fixture = generate_fixture(dihedral(4), config, 5).unwrap();
        let truth = truth_letter_permutations(&fixture.key).unwrap();
        assert_eq!(
            truth.len(),
            config.num_pt_letters,
            "one truth permutation per plaintext letter"
        );

        let outcome = super::evaluate_fixture(&fixture, config, 5).unwrap();
        assert_eq!(
            outcome.permutations_total, config.num_pt_letters,
            "denominator is the letter count"
        );
        assert_eq!(
            outcome.real_permutations_recovered, outcome.permutations_total,
            "every per-letter permutation must be recovered on a recovered fixture"
        );
        // The matched null cannot recover the full permutation set (structure gone).
        assert!(
            outcome.null_permutations_recovered < outcome.permutations_total,
            "null recovered {}/{} permutations; should be strictly fewer",
            outcome.null_permutations_recovered,
            outcome.permutations_total
        );
    }

    #[test]
    fn radius_zero_gate_fixtures_are_faithful_and_bijective() {
        // F3: at the gate's radius 0 the realized subgroup is always faithful to the
        // declared base group, the readout is bijective (trivial H verified from the
        // key), and |C| equals the declared order. This pins the default gate
        // behavior as UNCHANGED.
        let config = GakAttackConfig::default();
        for group in [cyclic(6), dihedral(4)] {
            for seed in 0u64..6 {
                let fixture = generate_fixture(group, config, seed).unwrap();
                let realized = fixture.realized;
                assert_eq!(realized.declared_group_order, group.order());
                assert_eq!(realized.realized_subgroup_order, group.order());
                assert_eq!(realized.realized_coset_alphabet_size, group.order());
                assert!(realized.faithful_to_declared);
                assert!(
                    realized.readout_bijective,
                    "trivial H must hold (verified from the key)"
                );
            }
        }
    }

    #[test]
    fn perturbed_cyclic3_reports_realized_not_declared_structure() {
        // F3 counterexample to LOCK: cyclic order 3, one PT letter, radius 1, seed 0
        // — the perturbation can leave the cyclic group, so the realized subgroup is
        // smaller than the declared order 3 and |C| < 3. The fixture must report the
        // ACTUAL realized structure (never claim order 3 it does not realize) while
        // keeping the trivial-H readout TRUE (verified from the key).
        let config = GakAttackConfig {
            cyclic_order: 3,
            num_pt_letters: 1,
            small_support_radius: 1,
            // Keep the rest minimal; only the key structure matters here.
            ..GakAttackConfig::default()
        };
        let fixture = generate_fixture(cyclic(3), config, 0).unwrap();
        let realized = fixture.realized;

        assert_eq!(realized.declared_group_order, 3, "declared base order is 3");
        // The realized subgroup is strictly smaller than the declared order here.
        assert!(
            realized.realized_subgroup_order < realized.declared_group_order,
            "perturbed seed-0 must realize a smaller subgroup, got {}",
            realized.realized_subgroup_order
        );
        // Specifically size 2 (a single transposition generates an order-2 group).
        assert_eq!(realized.realized_subgroup_order, 2);
        // |C| equals the realized subgroup size, NOT the declared order 3.
        assert_eq!(realized.realized_coset_alphabet_size, 2);
        assert!(
            !realized.faithful_to_declared,
            "fixture must NOT claim faithfulness to the declared base group"
        );
        // Trivial H must remain TRUE, verified from the actual key.
        assert!(
            realized.readout_bijective,
            "readout must stay bijective on reachable states (trivial H verified)"
        );
        // Sanity: the cipher still round-trips with the realized (smaller) key.
        let decrypted = gak_decrypt(&fixture.ciphertext, &fixture.key).unwrap();
        assert_eq!(decrypted, fixture.plaintext);
    }

    #[test]
    fn dihedral_gate_fixtures_realize_a_non_commutative_subgroup() {
        // F6: the dihedral label alone is not enough — assert the GENERATED letters
        // actually realize a non-commuting pair (so `choose_generators` did not pick
        // an abelian subset). Needs ≥2 letters to witness a non-commuting pair.
        let config = GakAttackConfig {
            num_pt_letters: 2,
            ..GakAttackConfig::default()
        };
        assert!(dihedral(4).is_non_commutative());
        for seed in 0u64..12 {
            let fixture = generate_fixture(dihedral(4), config, seed).unwrap();
            let letters = fixture.key.plaintext_letters();
            // Search the realized letter permutations for a witnessed non-commuting
            // pair: some pair (p, q) with p∘q != q∘p.
            let witnessed = realized_non_commuting_pair(letters);
            assert!(
                witnessed,
                "dihedral seed {seed} realized only commuting letters (abelian subset)"
            );
        }
    }

    /// Returns `true` when some ordered pair of permutations does not commute under
    /// the `(f ∘ g)[i] = f[g[i]]` convention.
    fn realized_non_commuting_pair(letters: &[Vec<usize>]) -> bool {
        fn compose(f: &[usize], g: &[usize]) -> Vec<usize> {
            g.iter().map(|&i| f.get(i).copied().unwrap_or(i)).collect()
        }
        for (i, p) in letters.iter().enumerate() {
            for q in letters.iter().skip(i.saturating_add(1)) {
                if compose(p, q) != compose(q, p) {
                    return true;
                }
            }
        }
        false
    }

    // =================================================================
    // UNIT 2a — real-GAK deck-stabilizer (non-trivial H) attack tests.
    // =================================================================

    use super::{
        ContextAction, CosetEdge, DeckLetterRegime, build_chain_substrate, coset_recovery_fraction,
        evaluate_deck_fixture, generate_deck_fixture, run_deck_attack, run_deck_attack_sweep,
        truth_coset_edges,
    };

    /// Small deck config: enough text for stable recovery, cheap enough for tests.
    fn deck_config(seeds_per_kind: usize) -> GakAttackConfig {
        GakAttackConfig {
            seeds_per_kind,
            ..GakAttackConfig::default()
        }
    }

    #[test]
    fn deck_fixture_round_trips_and_is_genuinely_non_trivial_h() {
        // Round-trip (Step-0 control) AND prove |H| > 1: two plaintexts sharing a
        // prefix but differing later map through DISTINCT hidden states, so the
        // hidden state genuinely matters (the deck is not a bijective-readout
        // GCTAK in disguise).
        let config = deck_config(3);
        for &n in &[5usize, 6, 7] {
            let fixture =
                generate_deck_fixture(n, DeckLetterRegime::Unconstrained, config, 7).unwrap();
            let decrypted = gak_decrypt(&fixture.ciphertext, &fixture.key).unwrap();
            assert_eq!(decrypted, fixture.plaintext, "deck round trip n={n}");
            assert!(
                fixture.hidden_subgroup_order > 1,
                "deck H = S_(n-1) must have |H| = (n-1)! > 1, got {}",
                fixture.hidden_subgroup_order
            );
            assert_eq!(
                fixture.hidden_subgroup_order,
                super::deck_hidden_subgroup_order(n)
            );
        }

        // Hidden-state-matters witness: encrypt two plaintexts with a shared prefix
        // but different suffixes; the SAME ciphertext coset can be reached under
        // different hidden states, so a single coset does NOT determine the next.
        let fixture =
            generate_deck_fixture(5, DeckLetterRegime::Unconstrained, config, 11).unwrap();
        // Build two short plaintexts: [0,1,0] and [0,2,0] (shared prefix 0, then
        // differ). If the readout were a fixed coset permutation (trivial H), the
        // trailing 0 would map identically; with |H|>1 it can differ.
        let pa = vec![Glyph(0), Glyph(1), Glyph(0)];
        let pb = vec![Glyph(0), Glyph(2), Glyph(0)];
        let ca = gak_encrypt(&pa, &fixture.key).unwrap();
        let cb = gak_encrypt(&pb, &fixture.key).unwrap();
        // The shared first symbol matches; a later same-letter step lands on
        // different cosets because the hidden state diverged — the |H|>1 signature.
        assert_eq!(ca.first(), cb.first(), "shared-prefix first step matches");
        assert_ne!(
            ca.get(2),
            cb.get(2),
            "with |H|>1 the same trailing letter maps through distinct hidden states"
        );
    }

    #[test]
    fn deck_attack_recovers_nonzero_fraction_and_beats_null_on_easiest() {
        // The KEY go/no-go for this unit: on the easiest small-`n` deck fixture the
        // attack recovers a NON-ZERO coset-action fraction AND beats its matched
        // within-message shuffle null.
        let config = deck_config(super::DECK_SWEEP_SEEDS);
        let report =
            run_deck_attack_sweep(config, DeckLetterRegime::Unconstrained, &[5usize, 6, 7, 8])
                .unwrap();
        let easiest = report
            .tractability
            .first()
            .expect("at least one sweep point");
        assert_eq!(easiest.state_size, 5);
        assert!(
            easiest.real_recovered_total > 0,
            "expected non-zero real recovery at n=5, got {}/{}",
            easiest.real_recovered_total,
            easiest.letters_total
        );
        assert!(
            easiest.real_recovered_total > easiest.null_recovered_total,
            "real {}/{} must beat matched null {}/{} at the easiest n",
            easiest.real_recovered_total,
            easiest.letters_total,
            easiest.null_recovered_total,
            easiest.letters_total
        );
        // At the easiest n the matched null is fully destroyed (recovers nothing).
        assert_eq!(
            easiest.null_recovered_total, 0,
            "matched null should recover nothing at the easiest n"
        );
        assert!(
            report.beats_null_on_easiest,
            "go/no-go: must beat null on easiest"
        );
        assert_eq!(report.easiest_state_size, 5);
    }

    #[test]
    fn deck_attack_measures_a_tractability_bound_that_breaks_as_n_grows() {
        // The deliverable: a measured bound. Recovery is SMALL and roughly FLAT
        // across `n` — it does NOT climb with `n` (it is bounded by the hidden-state
        // obstruction, not improving as `|H|` grows). We assert that SHAPE honestly:
        // small-`n` real strictly beats null with null at zero, and the real-vs-null
        // margin at the largest `n` is NO LARGER than at the smallest `n` (recovery
        // does not improve with `n`). We do NOT assert monotone degradation, which
        // the data (e.g. a rebound at n=7) does not show.
        let config = deck_config(super::DECK_SWEEP_SEEDS);
        let report = run_deck_attack_sweep(
            config,
            DeckLetterRegime::Unconstrained,
            &super::DEFAULT_DECK_STATE_SIZES,
        )
        .unwrap();
        assert_eq!(report.tractability.len(), 4);

        let small = report.tractability.first().unwrap();
        let large = report.tractability.last().unwrap();
        // Small n: clean recovery, null at zero.
        assert!(small.real_recovered_total > 0);
        assert_eq!(small.null_recovered_total, 0);
        // |H| grows factorially across the sweep (the bound is read against |H|).
        assert!(large.hidden_subgroup_order > small.hidden_subgroup_order);
        // Breaking signature: the real-minus-null aggregate margin at the largest
        // n is no larger than at the smallest n (recovery does not improve with n).
        let small_margin = small
            .real_recovered_total
            .saturating_sub(small.null_recovered_total);
        let large_margin = large
            .real_recovered_total
            .saturating_sub(large.null_recovered_total);
        assert!(
            large_margin <= small_margin,
            "the real-vs-null margin must not grow with n (recovery breaks): small={small_margin} large={large_margin}"
        );
    }

    #[test]
    fn deck_attack_matched_null_symmetry_identical_pipeline_and_population() {
        // Matched-null discipline (the historical #1 bug): real and null run the
        // IDENTICAL pipeline over the IDENTICAL population (a within-message
        // shuffle of the SAME ciphertext), scored against the SAME truth. Here we
        // prove symmetry directly: shuffling the ciphertext back to itself (an
        // identity permutation via a no-op) reproduces the real recovery exactly.
        let config = deck_config(3);
        let fixture = generate_deck_fixture(5, DeckLetterRegime::Unconstrained, config, 3).unwrap();
        let values = glyphs_to_values(&fixture.ciphertext).unwrap();
        let truth = truth_coset_edges(&fixture.key, &fixture.plaintext).unwrap();

        // Run the identical attack pipeline on the unshuffled stream twice; the
        // population and pipeline are identical, so the scores are identical
        // (determinism + matched-population symmetry).
        let a = run_deck_attack(&values, fixture.state_size, config.phrase_len);
        let b = run_deck_attack(&values, fixture.state_size, config.phrase_len);
        assert_eq!(a, b, "identical pipeline+population must be identical");
        let (sa, _) = coset_recovery_fraction(&truth, &a.recovered_actions);
        let (sb, _) = coset_recovery_fraction(&truth, &b.recovered_actions);
        assert_eq!(sa, sb);

        // And the matched-null evaluation (a real shuffle) scores no higher than
        // real on this seed (structure helps; destroying it cannot help).
        let outcome = evaluate_deck_fixture(&fixture, config, 3).unwrap();
        assert!(
            outcome.null_recovered <= outcome.real_recovered,
            "destroying structure must not beat real: real={} null={}",
            outcome.real_recovered,
            outcome.null_recovered
        );
    }

    #[test]
    fn deck_attack_true_conflict_aborts_on_a_bad_isomorph_assumption() {
        // TRUE-conflict detection: a deliberately bad isomorph assumption (two
        // distinct arrows OUT of one symbol under one fixed context) must be
        // flagged as a TRUE conflict and dropped, never a false "recovery".
        let mut action = ContextAction::default();
        action.insert(CosetEdge { from: 1, to: 2 });
        assert!(!action.true_conflict, "single edge is fine");
        // A second arrow OUT of 1 to a different target => TRUE conflict.
        action.insert(CosetEdge { from: 1, to: 3 });
        assert!(
            action.true_conflict,
            "two arrows out of one symbol under one context must be a TRUE conflict"
        );

        // Backward TRUE conflict: two arrows INTO one symbol.
        let mut into = ContextAction::default();
        into.insert(CosetEdge { from: 1, to: 9 });
        into.insert(CosetEdge { from: 2, to: 9 });
        assert!(
            into.true_conflict,
            "two arrows into one symbol under one context must be a TRUE conflict"
        );

        // POSITIVE: a deliberately BAD isomorph alignment MUST make the substrate's
        // fixed-context TRUE-conflict abort actually FIRE (not just an upper bound).
        //
        // Two windows share the length-2 isomorph CORE [x, x] (signature [0,0]) but
        // DIVERGE in the over-extension tail. Aligning them column-wise (one fixed
        // context) yields two arrows OUT of symbol `3`:  3->5 (col 2) and 3->6
        // (col 4).  Under ONE alignment that is impossible for a real isomorph — it
        // is exactly the over-extension-past-the-core bad alignment the guard exists
        // to catch.  Window A = [7,7,3,9,3], Window B = [7,7,5,9,6], a `2` filler in
        // between so the only [x,x]-prefix collisions are these two windows and they
        // survive the spacing filter (6 >= 0 + window_len 5).
        let raw: Vec<u8> = vec![
            7, 7, 3, 9, 3, // window A (start 0): core [7,7], tail 3,9,3
            2, // filler: no adjacent-equal pair starts here
            7, 7, 5, 9, 6, // window B (start 6): core [7,7], tail 5,9,6
        ];
        let values: Vec<SymbolValue> = raw
            .into_iter()
            .map(|v| crate::trigram::TrigramValue::new(v).unwrap())
            .collect();
        // Full-window grouping (core_len == window_len) is a partial bijection by
        // construction, so it can NEVER fire — proving the guard was previously
        // unreachable in production.
        let full = build_chain_substrate(&values, 5, 5);
        assert_eq!(
            full.true_conflict_aborts, 0,
            "full-window grouping is a partial bijection by construction; no conflict can fire"
        );
        // Core-prefix grouping (core_len 2) aligns the divergent tails and MUST fire
        // the fixed-context TRUE-conflict abort exactly once.
        let bad = build_chain_substrate(&values, 5, 2);
        assert_eq!(
            bad.true_conflict_aborts, 1,
            "a bad isomorph alignment must fire exactly one fixed-context TRUE-conflict abort"
        );
        assert_eq!(
            bad.contexts.len(),
            0,
            "the conflicting context must be dropped, never counted as a surviving context"
        );
    }

    #[test]
    fn deck_chain_links_are_load_bearing_corruption_breaks_recovery() {
        // The chain links are genuinely load-bearing (option a): the recovered
        // single-valued cores are built from the per-column edges that
        // `phrase_column_evidence` reads STRAIGHT OUT OF `chain_links_for_pair`
        // (each occurrence window aligned against itself shifted by one). So
        // corrupting those edges must break recovery (the attack cannot ignore
        // them). Per-fixture recovery variance is high (only a minority of seeds
        // recover any letter), so we deterministically search a few seeds for one
        // that recovers a non-zero baseline — then prove corrupting its coset edges
        // breaks it.
        let config = deck_config(3);
        let n = 5usize;
        let mut chosen: Option<(super::DeckFixture, Vec<SymbolValue>, Vec<_>, usize)> = None;
        for seed in 0u64..32 {
            let fixture =
                generate_deck_fixture(n, DeckLetterRegime::Unconstrained, config, seed).unwrap();
            let values = glyphs_to_values(&fixture.ciphertext).unwrap();
            let truth = truth_coset_edges(&fixture.key, &fixture.plaintext).unwrap();
            let real = run_deck_attack(&values, fixture.state_size, config.phrase_len);
            let (base, _) = coset_recovery_fraction(&truth, &real.recovered_actions);
            if base > 0 {
                chosen = Some((fixture, values, truth, base));
                break;
            }
        }
        let (fixture, values, truth, base_recovered) =
            chosen.expect("some seed must recover a non-zero baseline at n=5");

        // Corrupt the ciphertext's coset values (bump each by 1 mod n). This breaks
        // the coset-edge correspondence the chain links carry, so the recovered
        // actions no longer match any letter's true coset edge set.
        let corrupted: Vec<SymbolValue> = values
            .iter()
            .map(|v| {
                let bumped = (usize::from(v.get()) + 1) % n;
                crate::trigram::TrigramValue::new(bumped as u8).unwrap()
            })
            .collect();
        let broken = run_deck_attack(&corrupted, fixture.state_size, config.phrase_len);
        let (broken_recovered, _) = coset_recovery_fraction(&truth, &broken.recovered_actions);
        assert!(
            broken_recovered < base_recovered,
            "corrupting the chain-link coset edges must reduce recovery: base={base_recovered} broken={broken_recovered}"
        );
    }

    #[test]
    fn deck_attack_is_deterministic_for_fixed_seed() {
        let config = deck_config(4);
        let a =
            run_deck_attack_sweep(config, DeckLetterRegime::Unconstrained, &[5usize, 6]).unwrap();
        let b =
            run_deck_attack_sweep(config, DeckLetterRegime::Unconstrained, &[5usize, 6]).unwrap();
        assert_eq!(a, b, "deck sweep must be reproducible for a fixed seed");
    }

    #[test]
    fn deck_generator_supports_both_letter_regimes() {
        // Both the unconstrained and TENTATIVE small-support regimes generate valid,
        // round-tripping deck fixtures (so the NEXT unit can validate the prior).
        let config = deck_config(2);
        for regime in [
            DeckLetterRegime::Unconstrained,
            DeckLetterRegime::SmallSupport { radius: 2 },
        ] {
            let fixture = generate_deck_fixture(6, regime, config, 1).unwrap();
            assert_eq!(fixture.regime, regime);
            let decrypted = gak_decrypt(&fixture.ciphertext, &fixture.key).unwrap();
            assert_eq!(decrypted, fixture.plaintext, "round trip for {regime:?}");
        }
    }

    // =================================================================
    // UNIT 2b — hidden-state marginalization (idea 3) + small-support (idea 2).
    // =================================================================

    use super::{
        DEFAULT_BEAM_WIDTH, MarginalizationReport, SmallSupportPrior, SplitColumnEvidence,
        beam_recover_column, run_marginalization_attack, run_marginalization_sweep,
        run_small_support_validation, single_valued_core_of_split, split_column_evidence,
    };

    /// Runs the idea-3 sweep with the default robust seed count over the default deck
    /// sizes, prior OFF — the headline configuration the report bundles.
    fn marginalization_report() -> MarginalizationReport {
        let config = deck_config(super::DECK_SWEEP_SEEDS);
        run_marginalization_sweep(
            config,
            DeckLetterRegime::Unconstrained,
            &super::DEFAULT_DECK_STATE_SIZES,
            DEFAULT_BEAM_WIDTH,
            SmallSupportPrior::Off,
        )
        .unwrap()
    }

    #[test]
    fn beam_admits_nothing_when_held_out_fold_cannot_validate_it() {
        // Guard: a column whose HELD-OUT fold is EMPTY is NON-VALIDATED. With held-out
        // recall constant at 0.0 across every prefix (no held-out branch can be a hit),
        // the held-out-strict smaller-set tie-break selects the EMPTY admitted set, so
        // the beam admits NO edge the held-out fold never had a chance to confirm. This
        // is what keeps the "admits the branches that generalize and prunes the rest"
        // attribution literally true and excludes train-only/saturated columns from the
        // held-out-validated marginal.
        let mut train_support = std::collections::BTreeMap::new();
        // High-support train branches that, under a larger-set tie-break, would all be
        // admitted for free the moment recall saturated.
        let _ = train_support.insert(CosetEdge { from: 1, to: 2 }, 9usize);
        let _ = train_support.insert(CosetEdge { from: 3, to: 4 }, 7usize);
        let _ = train_support.insert(CosetEdge { from: 5, to: 6 }, 5usize);
        let column = SplitColumnEvidence {
            train_support,
            held_out: Vec::new(),
        };
        let (best, _dropped) =
            beam_recover_column(&column, DEFAULT_BEAM_WIDTH, SmallSupportPrior::Off);
        assert!(
            best.admitted.is_empty(),
            "an empty held-out fold validates nothing: the beam must admit no edges, \
             got {:?}",
            best.admitted
        );
    }

    #[test]
    fn idea3_recovers_nonzero_fraction_and_beats_null_on_easiest() {
        // Idea 3 recovers a NON-ZERO per-letter coset-action (edge) fraction on the
        // easiest small-n deck fixture AND beats its matched within-message shuffle
        // null there. This is the go/no-go for the unit.
        let report = marginalization_report();
        let easiest = report.points.first().expect("at least one sweep point");
        assert_eq!(easiest.state_size, 5);
        assert!(
            easiest.idea3_true_total > 0,
            "expected non-zero idea-3 recovery at n=5, got {}/{}",
            easiest.idea3_true_total,
            easiest.truth_edges_total
        );
        assert!(
            easiest.idea3_true_total > easiest.null_true_total,
            "idea-3 real {}/{} must beat matched null {}/{} at the easiest n",
            easiest.idea3_true_total,
            easiest.truth_edges_total,
            easiest.null_true_total,
            easiest.truth_edges_total
        );
        assert!(
            report.beats_null_on_easiest,
            "go/no-go: beat null on easiest"
        );
        assert_eq!(report.easiest_state_size, 5);
    }

    #[test]
    fn idea3_marginalization_recovers_more_than_the_2a_single_valued_core() {
        // The REASON idea 3 exists: marginalizing the hidden state (admitting the
        // multi-valued `from` branches the 2a baseline discards) recovers strictly
        // MORE true per-letter coset edges than the 2a single-valued core — at EVERY
        // swept n, not just the easiest. This is measured on identical columns over
        // the identical truth denominator (a like-for-like comparison).
        let report = marginalization_report();
        assert!(
            report.beats_baseline_on_easiest,
            "must beat 2a core on easiest"
        );
        for point in &report.points {
            assert!(
                point.idea3_true_total > point.baseline_true_total,
                "idea-3 ({}) must recover more true edges than the 2a core ({}) at n={}",
                point.idea3_true_total,
                point.baseline_true_total,
                point.state_size
            );
            // The improvement is large at small n (the multi-valued part the 2a core
            // discards is most of the action there).
            assert!(
                point.idea3_beats_baseline,
                "n={} idea3_beats_baseline must be set",
                point.state_size
            );
            // The margin is SEVERAL-FOLD at EVERY swept n, not just the easiest: on the
            // deterministic table idea-3 recovers AT LEAST 2x the 2a single-valued core
            // across the whole sweep (the measured ratios run ~5.6x / 3.7x / 4.8x / 2.7x
            // from easiest to hardest n under the held-out-strict smaller-set tie-break;
            // the >=2x floor is the honest universal multiple that holds even at the
            // hardest swept n, where the marginalization is most eroded). This matches
            // the report's "SEVERAL-FOLD at every n" wording and catches a quiet
            // regression at ANY n, not only the easiest one.
            assert!(
                point.idea3_true_total >= point.baseline_true_total.saturating_mul(2),
                "idea-3 ({}) should recover at least 2x the 2a core ({}) at n={}",
                point.idea3_true_total,
                point.baseline_true_total,
                point.state_size
            );
        }
        // On the EASIEST fixture the margin is even larger (~5.6x measured): keep the
        // strict >= 3x lock there, the regime where the multi-valued part the 2a core
        // discards is most of the action.
        let easiest = report.points.first().unwrap();
        assert!(
            easiest.idea3_true_total >= easiest.baseline_true_total.saturating_mul(3),
            "idea-3 should recover at least 3x the 2a core at the easiest n: idea3={} core={}",
            easiest.idea3_true_total,
            easiest.baseline_true_total
        );
    }

    #[test]
    fn idea3_recovery_breaks_as_hidden_state_count_grows() {
        // The measured tractability bound (the deliverable): idea-3 recovery is
        // STRONGEST at the smallest n and DOES NOT improve as |H| = (n-1)! grows. We
        // assert the breaking SHAPE honestly: the easiest-n mean fraction strictly
        // exceeds the largest-n mean fraction (recovery degrades), while |H| grows
        // factorially. We do NOT claim strict monotonic degradation at every step.
        let report = marginalization_report();
        assert_eq!(report.points.len(), 4);
        let small = report.points.first().unwrap();
        let large = report.points.last().unwrap();
        assert!(large.hidden_subgroup_order > small.hidden_subgroup_order);
        assert!(
            small.idea3_mean_fraction > large.idea3_mean_fraction,
            "idea-3 recovery must degrade as |H| grows: small={:.3} large={:.3}",
            small.idea3_mean_fraction,
            large.idea3_mean_fraction
        );
        // Even at the largest n idea-3 still beats both the 2a core and the null
        // (it degrades gracefully toward, not below, the baseline).
        assert!(large.idea3_true_total > large.baseline_true_total);
        assert!(large.idea3_true_total > large.null_true_total);
    }

    #[test]
    fn idea3_matched_null_symmetry_identical_pipeline_and_population() {
        // Matched-null discipline (the historical #1 bug): real and null run the
        // IDENTICAL marginalization pipeline (same phrase_len, beam_width, prior) over
        // the IDENTICAL population (a within-message shuffle of the SAME ciphertext),
        // scored against the SAME truth. Determinism gives identical scores on the
        // identical population; the real shuffle null must score no higher than real.
        let config = deck_config(3);
        let fixture = generate_deck_fixture(5, DeckLetterRegime::Unconstrained, config, 3).unwrap();
        let values = glyphs_to_values(&fixture.ciphertext).unwrap();
        let a = run_marginalization_attack(
            &values,
            config.phrase_len,
            DEFAULT_BEAM_WIDTH,
            SmallSupportPrior::Off,
        );
        let b = run_marginalization_attack(
            &values,
            config.phrase_len,
            DEFAULT_BEAM_WIDTH,
            SmallSupportPrior::Off,
        );
        assert_eq!(a, b, "identical pipeline+population must be identical");

        let outcome = super::evaluate_marginalization_fixture(
            &fixture,
            config,
            3,
            DEFAULT_BEAM_WIDTH,
            SmallSupportPrior::Off,
        )
        .unwrap();
        assert!(
            outcome.null_true_edges <= outcome.idea3_true_edges,
            "destroying structure must not beat real: real={} null={}",
            outcome.idea3_true_edges,
            outcome.null_true_edges
        );
    }

    #[test]
    fn idea3_beam_width_bound_is_respected_and_reported() {
        // The beam-width bound is ENFORCED and the dropped-beam count is SURFACED (no
        // silent truncation): only the first `beam_width` support-ranked prefixes are
        // eligible for selection, so a recovered column admits at most `beam_width - 1`
        // branches (the largest eligible prefix), and the surplus deeper prefixes are
        // reported as dropped, not hidden.
        let report = marginalization_report();
        for point in &report.points {
            assert_eq!(
                point.beam_width, DEFAULT_BEAM_WIDTH,
                "the disclosed beam width must be the configured bound"
            );
        }
        // On the swept fixtures the candidate prefixes exceed the width, so the bound
        // genuinely bites and the disclosure is non-zero.
        let total_dropped: usize = report.points.iter().map(|p| p.beams_dropped).sum();
        assert!(
            total_dropped > 0,
            "the width bound must actually prune some beams (disclosed, not silent)"
        );
        // Per-outcome the disclosed width matches and dropped is non-negative by type.
        for outcome in &report.outcomes {
            assert_eq!(outcome.beam_width, DEFAULT_BEAM_WIDTH);
        }
    }

    #[test]
    fn idea3_beam_width_genuinely_caps_admitted_set_size() {
        // The width bound is LOAD-BEARING, not cosmetic: because `best` is selected
        // ONLY from the first `beam_width` support-ranked prefixes (k = 0..beam_width,
        // admitting at most `beam_width - 1` branches), no recovered column may ever
        // admit `beam_width` or more edges. A regression that selected a deeper
        // (dropped) prefix would admit more and fail here, so this test pins that the
        // dropped beams are genuinely ineligible for selection.
        let config = deck_config(3);
        // A larger deck makes many columns have far more than `beam_width` candidate
        // branches, so the cap actually bites.
        let fixture =
            generate_deck_fixture(8, DeckLetterRegime::Unconstrained, config, 11).unwrap();
        let values = glyphs_to_values(&fixture.ciphertext).unwrap();
        let solution = run_marginalization_attack(
            &values,
            config.phrase_len,
            DEFAULT_BEAM_WIDTH,
            SmallSupportPrior::Off,
        );
        assert!(
            solution.beams_dropped > 0,
            "this fixture must have deeper prefixes beyond the width (dropped > 0)"
        );
        for admitted in &solution.recovered_columns {
            assert!(
                admitted.len() < DEFAULT_BEAM_WIDTH,
                "a recovered column admitted {} edges but the width bound caps eligible \
                 prefixes at {} (<= {} branches): the bound is not enforced",
                admitted.len(),
                DEFAULT_BEAM_WIDTH,
                DEFAULT_BEAM_WIDTH - 1
            );
        }
        // A tiny width must bite even harder: at width 2 only the empty and the
        // single-top-branch prefixes are eligible, so every column admits <= 1 edge.
        let narrow =
            run_marginalization_attack(&values, config.phrase_len, 2, SmallSupportPrior::Off);
        for admitted in &narrow.recovered_columns {
            assert!(
                admitted.len() <= 1,
                "width 2 must admit at most 1 branch per column, got {}",
                admitted.len()
            );
        }
    }

    #[test]
    fn idea3_small_support_prior_validates_idea2() {
        // Idea-2 validation (TENTATIVE everywhere). The robust, structurally
        // guaranteed property: the prior FAILS GRACEFULLY — its confidence floor only
        // ever DROPS genuine low-support edges (recall ON <= recall OFF in BOTH
        // conditions) and never invents any, so PRECISION is held or improved and a
        // wrong small-support assumption is never rewarded.
        let report = marginalization_report();
        let v = report.small_support_validation;
        assert!(
            v.prior_fails_gracefully(),
            "prior must fail gracefully (recall only drops): small on/off={}/{} broad on/off={}/{}",
            v.small_truth_prior_on,
            v.small_truth_prior_off,
            v.broad_truth_prior_on,
            v.broad_truth_prior_off
        );
        // Precision is OBSERVED to hold-or-improve under the floor in both conditions
        // on THIS bundled 24-seed aggregate fixture. This is NOT a structural invariant:
        // on single fixtures the relation can flip, because the precision numerator is a
        // greedy one-to-one best-letter attribution (`marginal_edge_recovery`) while the
        // denominator is a flat admitted-edge sum, so dropping low-support TRUE edges can
        // lower the numerator faster than the denominator. The asserts below pass on the
        // shipped aggregate and are deliberately NOT promoted to a per-seed loop.
        assert!(
            v.small_precision(true) >= v.small_precision(false),
            "prior holds-or-improves precision on the bundled 24-seed aggregate (small-support truth): on={:.3} off={:.3}",
            v.small_precision(true),
            v.small_precision(false)
        );
        assert!(
            v.broad_precision(true) >= v.broad_precision(false),
            "prior holds-or-improves precision on the bundled 24-seed aggregate (unconstrained truth): on={:.3} off={:.3}",
            v.broad_precision(true),
            v.broad_precision(false)
        );
        // The WEAK, honestly-labelled selective signal: the prior retains slightly
        // MORE recall (proportionally) on small-support truth than on unconstrained
        // truth — it helps when true at least as much as when false. This is a thin,
        // TENTATIVE margin, reported as such; the graceful-failure property above is
        // the load-bearing guarantee.
        assert!(
            v.prior_is_discriminative()
                || v.small_truth_prior_on >= v.broad_truth_prior_on.saturating_sub(1),
            "prior should help small-support at least as much as broad (TENTATIVE, weak): small_on={} broad_on={}",
            v.small_truth_prior_on,
            v.broad_truth_prior_on
        );
    }

    #[test]
    fn idea3_small_support_prior_off_in_default_run_so_results_do_not_silently_depend_on_it() {
        // No idea-3 result silently depends on the TENTATIVE prior: the bundled
        // headline sweep runs the prior OFF, and the prior's effect lives only in the
        // explicitly-labelled validation field.
        let report = run_gak_attack(GakAttackConfig::default()).unwrap();
        assert_eq!(
            report.marginalization.prior,
            SmallSupportPrior::Off,
            "the headline idea-3 sweep must run with the prior OFF"
        );
        assert!(
            !report.marginalization.points.is_empty(),
            "idea-3 points must be surfaced"
        );
    }

    #[test]
    fn idea3_single_valued_core_of_split_matches_2a_core_definition() {
        // The like-for-like baseline really is the 2a single-valued core: a `from`
        // that maps exactly one way across every observed branch maps to that `to`;
        // a multi-valued `from` is excluded (only idea 3 recovers it).
        let config = deck_config(1);
        let fixture = generate_deck_fixture(5, DeckLetterRegime::Unconstrained, config, 0).unwrap();
        let values = glyphs_to_values(&fixture.ciphertext).unwrap();
        let split = split_column_evidence(&values, config.phrase_len);
        assert!(!split.is_empty(), "expected aligned phrase columns");
        for column in &split {
            let core = single_valued_core_of_split(column);
            // Every core entry's `from` must be single-valued across all branches.
            let mut images: std::collections::BTreeMap<u8, std::collections::BTreeSet<u8>> =
                std::collections::BTreeMap::new();
            for edge in column
                .train_support
                .keys()
                .copied()
                .chain(column.held_out.iter().copied())
            {
                let _ = images.entry(edge.from).or_default().insert(edge.to);
            }
            for (from, to) in &core {
                assert_eq!(
                    images.get(from).map(std::collections::BTreeSet::len),
                    Some(1),
                    "core `from` {from} must be single-valued"
                );
                assert!(images.get(from).is_some_and(|s| s.contains(to)));
            }
        }
    }

    #[test]
    fn idea3_is_deterministic_for_fixed_seed() {
        let config = deck_config(4);
        let a = run_marginalization_sweep(
            config,
            DeckLetterRegime::Unconstrained,
            &[5usize, 6],
            DEFAULT_BEAM_WIDTH,
            SmallSupportPrior::Off,
        )
        .unwrap();
        let b = run_marginalization_sweep(
            config,
            DeckLetterRegime::Unconstrained,
            &[5usize, 6],
            DEFAULT_BEAM_WIDTH,
            SmallSupportPrior::Off,
        )
        .unwrap();
        assert_eq!(a, b, "idea-3 sweep must be reproducible for a fixed seed");
    }

    #[test]
    fn idea3_held_out_validation_is_load_bearing_not_a_ground_truth_peek() {
        // The beam is scored ONLY by held-out chain-link generalization (no truth
        // peek): on a stream with NO repeated-phrase structure the held-out fold is
        // empty / unaligned, so the beam recovers ~nothing — exactly the matched-null
        // behaviour. Here we directly check the small-support validation runs without
        // ever consulting ground truth in the recovery (truth is only used to SCORE).
        let config = deck_config(4);
        let v = run_small_support_validation(config, DEFAULT_BEAM_WIDTH).unwrap();
        // Sanity: the validation actually recovered SOMETHING in both conditions
        // (so the held-out-driven beam is doing real work, not trivially empty).
        assert!(v.small_truth_prior_off > 0 && v.broad_truth_prior_off > 0);
        assert!(v.small_truth_total > 0 && v.broad_truth_total > 0);
    }

    #[test]
    fn run_gak_attack_surfaces_the_idea3_marginalization_result() {
        // The bundled report carries the idea-3 (unit-2b) marginalization result,
        // swept over the default deck sizes, beating the 2a baseline AND the matched
        // null on the easiest fixture, with the small-support validation attached.
        let report = run_gak_attack(GakAttackConfig::default()).unwrap();
        let m = &report.marginalization;
        assert_eq!(m.points.len(), super::DEFAULT_DECK_STATE_SIZES.len());
        assert_eq!(m.regime, DeckLetterRegime::Unconstrained);
        assert!(
            m.beats_baseline_on_easiest,
            "idea-3 must beat the 2a single-valued core on the easiest fixture"
        );
        assert!(
            m.beats_null_on_easiest,
            "idea-3 must beat its matched null on the easiest fixture"
        );
        assert_eq!(m.beam_width, DEFAULT_BEAM_WIDTH);
        // Every swept point is real GAK (|H| > 1) and discloses its beam width.
        for point in &m.points {
            assert!(
                point.hidden_subgroup_order > 1,
                "n={} not real GAK",
                point.state_size
            );
            assert_eq!(point.beam_width, DEFAULT_BEAM_WIDTH);
        }
        // The small-support validation fails gracefully (the robust property).
        assert!(m.small_support_validation.prior_fails_gracefully());
    }

    #[test]
    fn run_gak_attack_surfaces_the_deck_partial_recovery_bound() {
        // The bundled report carries the deck (non-trivial-H) partial-recovery
        // tractability bound, swept over the default deck sizes, with a robust seed
        // count, and beating the matched null on the easiest fixture.
        let report = run_gak_attack(GakAttackConfig::default()).unwrap();
        assert_eq!(
            report.deck.tractability.len(),
            super::DEFAULT_DECK_STATE_SIZES.len()
        );
        assert_eq!(report.deck.regime, DeckLetterRegime::Unconstrained);
        assert!(
            report.deck.beats_null_on_easiest,
            "deck attack must beat its matched null on the easiest fixture"
        );
        // Every swept point reports a hidden-subgroup order > 1 (real GAK).
        for tp in &report.deck.tractability {
            assert!(
                tp.hidden_subgroup_order > 1,
                "n={} not real GAK",
                tp.state_size
            );
        }
    }

    // =================================================================
    // UNIT 2c — EYES STEP 3 tests (the ONLY unit touching the real eyes).
    //
    // These pin the entry path / corpus pins, the held-out POSITIVE CONTROL
    // firing on synthetic signal, the matched-null discipline, the Thread-3
    // consultation, the candidate-record write + honesty strings, and — crucially
    // — they DO NOT assert a decode / a recovered eye plaintext. The real-eye
    // outcome is reported HONESTLY (whatever it is); only the honesty surface and
    // the structural-gate machinery are asserted, never a "passes" verdict.
    // =================================================================

    use super::{
        AggregateSafeFilter, EyesAttackConfig, SafeWindowFilter, eyes_aggregate_score,
        eyes_held_out_positive_control, eyes_message_evidence, render_eyes_candidate_record,
        run_gak_attack_eyes, synthetic_isomorph_rich_eye_message,
    };
    use crate::orders;

    /// A fast eyes config that writes records into the scratch dir, with a small
    /// matched-null trial count so the corpus-scale run stays inside `make verify`.
    fn eyes_test_config(dir: &std::path::Path) -> EyesAttackConfig {
        EyesAttackConfig {
            seed: 0x1234_5678,
            // trials only set the in-test matched-null sample size (NOT a production
            // default); coarser p-value resolution is fine here because the eyes score 0
            // (no tail to resolve). The genuine null calibration is exercised by the
            // positive-control test, which must KEEP enough trials to fire.
            trials: 8,
            beam_width: super::EYES_DEFAULT_BEAM_WIDTH,
            candidates_dir: dir.to_path_buf(),
        }
    }

    /// Unique per-test scratch directory (no clock; derived from a tag).
    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("gak-eyes-test-{tag}"));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn eyes_run_uses_verified_entry_path_and_pins_corpus() {
        // The eyes run is deterministic and uses the verified corpus entry path:
        // assert the 1036-trigram / 83-symbol / 9-message pins.
        let dir = scratch_dir("pins");
        let report = run_gak_attack_eyes(eyes_test_config(&dir)).unwrap();
        assert_eq!(report.total_symbols, 1_036, "1036 reading-layer trigrams");
        assert_eq!(report.distinct_symbols, 83, "83-symbol reading layer");
        assert_eq!(
            report.per_message.len(),
            9,
            "nine messages, boundaries kept"
        );
        assert_eq!(report.order_name, "standard36-u012-d012");
        // A single run suffices: the eyes run is deterministic by construction, so a
        // second run would only re-derive identical numbers at double the wall-clock.
    }

    #[test]
    fn eyes_held_out_positive_control_fires_on_synthetic_signal() {
        // POSITIVE CONTROL: the held-out predictor must fire on a SYNTHETIC
        // isomorph-rich eye-shaped fixture (known signal). This is the proof the
        // held-out gate can detect real structure when it exists.
        let config = eyes_test_config(&scratch_dir("posctrl"));
        let control = eyes_held_out_positive_control(&config).unwrap();
        assert!(
            control.fired,
            "held-out predictor must fire on synthetic isomorph-rich signal: real_score={} null_score={}",
            control.real_score, control.null_score
        );
        assert!(control.real_score > control.null_score);
        assert!(control.real_score > 0);
        // F1: the control fires on the SAME fair gate the eyes face — its real-vs-null
        // excess clears its OWN population-relative material-effect bar. This is what
        // makes the bar both achievable (the eyes COULD pass) AND validated.
        assert!(
            control.scoreable_edges > 0,
            "control must have scoreable edges"
        );
        let control_excess = f64::from(
            i32::try_from(control.real_score.saturating_sub(control.null_score)).unwrap(),
        );
        let control_bar = super::EYES_MATERIAL_EFFECT_FRACTION
            * super::max_achievable_score(control.scoreable_edges);
        assert!(
            control_excess >= control_bar,
            "the positive control must clear its OWN population's material-effect bar (excess={control_excess} bar={control_bar})"
        );
    }

    #[test]
    fn eyes_material_effect_bar_is_fair_below_the_eyes_max_achievable() {
        // F1 HONESTY: the material-effect bar must be ACHIEVABLE on the eyes
        // population — strictly below their MAX achievable score (every scoreable edge
        // a HIT) — so a genuine eye signal COULD clear it. The "no candidate" negative
        // must rest on a detector the eyes could in principle have passed, not on an
        // absolute bar pinned to the much larger synthetic control's population.
        let report = run_gak_attack_eyes(eyes_test_config(&scratch_dir("fairbar"))).unwrap();
        assert!(
            report.scoreable_edges > 0,
            "the eyes must expose a non-empty scoreable population"
        );
        // The bar is exactly a fraction of the eyes' own max achievable score.
        let expected_max =
            report.scoreable_edges as f64 * (super::EYE_READING_ALPHABET_SIZE - 1) as f64;
        assert!(
            (report.max_achievable_score - expected_max).abs() < 1e-6,
            "max achievable must be scoreable_edges*(A-1): got {} want {expected_max}",
            report.max_achievable_score
        );
        assert!(
            report.material_effect_threshold < report.max_achievable_score,
            "FAIR GATE: the bar ({}) must be BELOW the eyes' max achievable ({}) so real signal could clear it",
            report.material_effect_threshold,
            report.max_achievable_score
        );
        assert!(
            report.material_effect_threshold > 0.0,
            "the bar must be a real positive effect-size threshold, not vacuous"
        );
        // The eyes still fail it HONESTLY (score 0, no candidate) — the verdict stands.
        assert_eq!(report.real_score, 0, "the eyes genuinely score 0");
        assert!(
            !report.material_effect_met,
            "the eyes do not clear the fair bar"
        );
        assert!(!report.candidate_survived, "the decode remains blocked");
    }

    #[test]
    fn eyes_no_candidate_verdict_is_stable_across_null_seeds() {
        // F6: the "no candidate / decode blocked" verdict is PINNED across multiple
        // matched-null seeds. The eyes score 0 regardless of the null shuffle seed, so
        // the negative cannot be an artifact of one lucky/unlucky null draw.
        for seed in [0x1111_2222u64, 0xdead_beef] {
            let config = super::EyesAttackConfig {
                seed,
                // trials only set the in-test matched-null sample size (NOT a production
                // default); coarser p-value resolution is fine because the eyes score 0
                // (no tail to resolve). The genuine null calibration is exercised by the
                // positive-control test, which must KEEP enough trials to fire.
                trials: 8,
                beam_width: super::EYES_DEFAULT_BEAM_WIDTH,
                candidates_dir: scratch_dir(&format!("seed-{seed:x}")),
            };
            let report = run_gak_attack_eyes(config).unwrap();
            assert!(
                !report.candidate_survived,
                "no candidate must survive for null seed {seed:#x}"
            );
            assert_eq!(
                report.real_score, 0,
                "the eyes score 0 for null seed {seed:#x}"
            );
            assert!(
                !report.held_out_beats_null,
                "the eyes do not beat the matched null for seed {seed:#x}"
            );
            // The fair bar is seed-independent (it is a function of the population, not
            // the null seed), so it stays below the eyes' max for every seed.
            assert!(report.material_effect_threshold < report.max_achievable_score);
        }
    }

    #[test]
    fn eyes_run_rejects_zero_trials() {
        // F4: zero matched-null trials would define the p-value over an empty sample.
        // The run rejects it up front (the same discipline as the other modules'
        // ZeroTrials guards), never silently producing a degenerate null.
        let config = super::EyesAttackConfig {
            seed: 0x1234_5678,
            trials: 0,
            beam_width: super::EYES_DEFAULT_BEAM_WIDTH,
            candidates_dir: scratch_dir("zerotrials"),
        };
        assert!(
            matches!(
                run_gak_attack_eyes(config),
                Err(super::GakAttackError::EyesZeroTrials)
            ),
            "zero trials must be rejected with EyesZeroTrials"
        );
    }

    #[test]
    fn synthetic_isomorph_rich_fixture_scores_above_a_shuffle() {
        // The synthetic fixture genuinely carries held-out-predictable structure:
        // its coverage-weighted score strictly exceeds a within-message shuffle of
        // the SAME multiset (the matched-null contrast on known signal). This is the
        // strict statistic that the within-message shuffle CANNOT game.
        let fixture = synthetic_isomorph_rich_eye_message(0x1234_5678).unwrap();
        let real = eyes_aggregate_score(
            std::slice::from_ref(&fixture),
            AggregateSafeFilter::Unrestricted,
        );
        let mut shuffled = fixture.clone();
        let mut rng = super::SplitMix64::new(0xabcd);
        super::fisher_yates(&mut shuffled, &mut rng).unwrap();
        let null = eyes_aggregate_score(
            std::slice::from_ref(&shuffled),
            AggregateSafeFilter::Unrestricted,
        );
        assert!(
            real > null,
            "synthetic signal real score {real} must beat shuffle null score {null}"
        );
        assert!(
            real > 0,
            "synthetic signal must have a positive score, got {real}"
        );
    }

    #[test]
    fn eyes_real_outcome_is_reported_honestly_not_hardcoded_as_passing() {
        // CRITICAL HONESTY TEST: we do NOT assert the real eyes pass. We assert the
        // report is well-formed and that IF no candidate survived (the expected
        // case) then the cleartext gate was NOT run and the decode is blocked. We
        // never assert a recovered eye plaintext.
        let report = run_gak_attack_eyes(eyes_test_config(&scratch_dir("honest"))).unwrap();
        // The matched-null p-value is a proper probability.
        assert!(report.matched_null_p_value > 0.0 && report.matched_null_p_value <= 1.0);
        // Thread-3 was actually consulted: zero robust internal violations on the
        // real eyes and the Thread-3 positive control fired (the model is consistent
        // only if so).
        assert!(report.three_consistency.positive_control_fired);
        assert_eq!(report.three_consistency.robust_internal_violations, 0);
        assert!(report.three_consistency.safe_extents > 0);
        // Honesty invariant: the SPECULATIVE cleartext gate runs IFF a candidate
        // survived both structural gates. No decode is asserted either way.
        assert_eq!(
            report.speculative_cleartext.is_some(),
            report.candidate_survived,
            "the speculative cleartext gate must run iff a candidate survived"
        );
        if !report.candidate_survived {
            assert!(
                report.speculative_cleartext.is_none(),
                "expected case: no candidate, so no speculative cleartext"
            );
        }
    }

    #[test]
    fn eyes_candidate_record_is_written_with_honesty_strings() {
        // The mandatory candidate record is written and contains the
        // HYPOTHESIS-not-decode label, the claim ceiling, the held-out verdict, the
        // Thread-3 verdict, and the candidate-logging protocol framing.
        let dir = scratch_dir("record");
        let report = run_gak_attack_eyes(eyes_test_config(&dir)).unwrap();
        assert!(
            report.record_path.exists(),
            "candidate record must be written"
        );
        let body = std::fs::read_to_string(&report.record_path).unwrap();
        assert!(body.contains("HYPOTHESIS, NOT a decode"));
        assert!(body.contains(
            "deterministic, engine-generated, strikingly structured data of unknown meaning; unsolved; no primary developer source confirms recoverable plaintext"
        ));
        assert!(body.contains("Gate 1 — held-out isomorphs vs matched within-message null"));
        assert!(body.contains("Gate 2 — Thread-3 perfect-isomorphism consistency"));
        assert!(body.contains("Gate 3 — SPECULATIVE cleartext plausibility"));
        // Expected case: no candidate, decode remains blocked.
        if !report.candidate_survived {
            assert!(body.contains("NO candidate surfaced — decode remains blocked"));
            assert!(body.contains("decode REMAINS BLOCKED"));
        }
    }

    #[test]
    fn eyes_record_logs_cleartext_verbatim_when_speculative_gate_runs() {
        // If the SPECULATIVE gate runs, its implied plaintext is logged VERBATIM
        // with Finnish AND English scores. We exercise the renderer directly with a
        // synthesized "survived" input so the verbatim-logging path is covered even
        // though the real eyes are expected NOT to surface a candidate.
        let speculative = super::SpeculativeCleartext {
            implied_plaintext: "TESTHYPOTHESISPLAINTEXT".to_owned(),
            finnish_score: -3.21,
            english_score: -3.99,
            finnish_null_mean: -3.40,
            english_null_mean: -3.50,
            beats_finnish_null: true,
            beats_english_null: false,
        };
        let per_message = Vec::new();
        let inputs = super::EyesRecordInputs {
            config: &eyes_test_config(std::path::Path::new("/dev/null")),
            order_name: "standard36-u012-d012",
            total_symbols: 1_036,
            distinct_symbols: 83,
            per_message: &per_message,
            real_held_out_hits_total: 7,
            real_held_out_misses_total: 3,
            real_held_out_ambiguous_total: 5,
            real_score: 120,
            scoreable_edges: 15,
            max_achievable_score: 1_230.0,
            null_mean_score: -200.0,
            material_effect_threshold: 50.0,
            material_effect_met: true,
            matched_null_p_value: 0.001,
            null_at_least_real: 0,
            held_out_beats_null: true,
            held_out_positive_control: super::HeldOutPositiveControl {
                real_score: 500,
                null_score: 10,
                scoreable_edges: 600,
                fired: true,
            },
            three_consistency: super::ThreeConsistency {
                robust_internal_violations: 0,
                safe_extents: 16,
                positive_control_fired: true,
                consistent: true,
            },
            candidate_survived: true,
            speculative_cleartext: Some(&speculative),
        };
        let body = render_eyes_candidate_record(&inputs).unwrap();
        // The implied plaintext is logged verbatim, with both language scores.
        assert!(body.contains("TESTHYPOTHESISPLAINTEXT"));
        assert!(body.contains("Finnish bigram score"));
        assert!(body.contains("English bigram score"));
        // Even a surviving candidate is a HYPOTHESIS, never a decode.
        assert!(body.contains("HYPOTHESIS"));
        assert!(body.contains("NOT a recovered"));
    }

    #[test]
    fn eyes_message_evidence_splits_disjoint_train_and_held_out_contexts() {
        // The TRAIN and HELD-OUT context families are disjoint (whole signature
        // groups are assigned to one fold), so the held-out validation is genuinely
        // out-of-sample. Assert the evidence is well-formed and within the alphabet.
        let grids = orders::corpus_grids().unwrap();
        let order = orders::accepted_honeycomb_order();
        let message_values = orders::read_corpus_message_values(&grids, order).unwrap();
        let first = message_values.first().expect("at least one message");
        // Unrestricted here: this test only asserts the train/held-out split is
        // well-formed and within the alphabet, independent of the F2 safe-extent
        // restriction (which is exercised by the corpus-scale run tests).
        let evidence = eyes_message_evidence(first, SafeWindowFilter::unrestricted());
        // The fold counts are derived and the coverage is within the 83-symbol layer.
        let total_contexts = evidence.train_contexts.len() + evidence.held_out_contexts.len();
        assert_eq!(
            total_contexts, evidence.aligned_pairs,
            "every non-conflicting aligned pair is a train OR held-out context"
        );
        for action in evidence
            .train_contexts
            .iter()
            .chain(evidence.held_out_contexts.iter())
        {
            for (from, to) in &action.forward {
                assert!(
                    usize::from(*from) < super::EYE_READING_ALPHABET_SIZE
                        && usize::from(*to) < super::EYE_READING_ALPHABET_SIZE
                );
            }
        }
        assert!(evidence.symbols_touched <= super::EYE_READING_ALPHABET_SIZE);
    }
}

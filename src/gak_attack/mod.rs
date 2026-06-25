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
mod eyes;
// `generator`/`solver`/`marginalization` are `pub(crate)` so the solve pipeline
// (brief 04) can import the beam-search / fixture internals directly via
// `crate::gak_attack::{generator,solver,marginalization}::*`; this widens no
// external (`pub`) surface — the public path stays `crate::gak_attack::*` via the
// `pub use` block below.
pub(crate) mod generator;
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

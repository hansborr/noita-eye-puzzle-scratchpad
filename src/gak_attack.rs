//! Thread 4 GAK-attack spike: synthetic generator + GCTAK decisive gate.
//!
//! This module is the project's go/no-go gate for any attempt to attack the
//! Noita eye-glyph puzzle by pure cryptanalysis: **no GCTAK solve, no GAK
//! attempt.** It is **synthetic-only** — it never touches the eye corpus. The
//! eyes are a later unit (Step 3 of `research/gak-threads/specs/thread-4-spec.md`);
//! the strongest defensible statement about them is unchanged and stated here so
//! nothing downstream can drift past it:
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

use crate::chaining_graph::{
    AlignedOccurrence, ChainLink, ContextId, SymbolValue, chain_links_for_pair,
};
use crate::ciphers::{CipherError, CosetReadout, GakKey, GakKeyOptions, gak_encrypt};
use crate::glyph::Glyph;
use crate::isomorph::PatternSignature;
use crate::null::{SplitMix64, fisher_yates, mix_seed, random_index_below};
use crate::trigram::TrigramValue;

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

/// Which finite state group a synthetic GAK fixture realizes.
///
/// Both kinds are realized as permutation groups via the left regular
/// representation, so the solver code path is identical; the dihedral kind is the
/// **non-commutative** witness that the gate does not accidentally exploit
/// commutativity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupKind {
    /// Commutative cyclic group `C_m` of the configured order.
    Cyclic {
        /// Group order `m`.
        order: usize,
    },
    /// Non-commutative dihedral group `D_{2k}` (order `2k`) for `k ≥ 3`.
    Dihedral {
        /// Half-order `k`; the group order is `2k`.
        half_order: usize,
    },
}

impl GroupKind {
    /// Returns the abstract group order `|G|`.
    #[must_use]
    pub const fn order(self) -> usize {
        match self {
            Self::Cyclic { order } => order,
            Self::Dihedral { half_order } => half_order.saturating_mul(2),
        }
    }

    /// Returns a short report label for this group kind.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Cyclic { .. } => "cyclic",
            Self::Dihedral { .. } => "dihedral",
        }
    }

    /// Whether this group is non-commutative (dihedral with `k ≥ 3`).
    #[must_use]
    pub const fn is_non_commutative(self) -> bool {
        matches!(self, Self::Dihedral { half_order } if half_order >= 3)
    }
}

/// Which hidden subgroup `H` a fixture uses.
///
/// This unit only realizes the **trivial** hidden subgroup (GCTAK, bijective
/// readout `c`). The enum is left open so later units can add non-trivial `H`
/// without reshaping the surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiddenSubgroupKind {
    /// Trivial hidden subgroup `H = {e}`: the readout `c` is bijective and
    /// `|C| = |G|`. This is the GCTAK regime.
    Trivial,
}

impl HiddenSubgroupKind {
    /// Returns a short report label for this hidden-subgroup kind.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Trivial => "trivial-H (GCTAK)",
        }
    }
}

/// The structure a fixture's **constructed key actually realizes**, derived by
/// enumerating reachable states — never merely declared.
///
/// The declared `group_kind.order()` is the *base* group order. When the
/// TENTATIVE small-support knob (`small_support_radius > 0`) perturbs a letter
/// permutation it can leave the base group's regular representation, so the
/// subgroup the chosen letters actually generate (and hence the realized
/// ciphertext-coset alphabet `|C|`) may be **smaller** than the declared order.
/// Reporting this realized structure keeps a perturbed fixture from claiming a
/// structure its key lacks (review finding F3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RealizedStructure {
    /// Declared base group order `|G|` (before any small-support perturbation).
    pub declared_group_order: usize,
    /// Size of the subgroup the chosen letter permutations actually generate
    /// from the initial state — i.e. the number of reachable states.
    pub realized_subgroup_order: usize,
    /// Number of distinct ciphertext cosets `|C|` the realized states emit. With
    /// the bijective trivial-`H` readout this equals `realized_subgroup_order`.
    pub realized_coset_alphabet_size: usize,
    /// Whether the readout is **bijective on the reachable states** (i.e. the
    /// trivial hidden subgroup holds), *verified from the constructed key*, not
    /// assumed. The gate requires this to stay `true`.
    pub readout_bijective: bool,
    /// Whether the realized subgroup is faithful to the declared base group
    /// (`realized_subgroup_order == declared_group_order`). Always `true` for the
    /// `small_support_radius == 0` gate regime; can be `false` only under the
    /// TENTATIVE perturbation knob.
    pub faithful_to_declared: bool,
}

/// Held-back ground truth for one synthetic GAK fixture.
///
/// The attack always has this so every claim is checkable against truth.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntheticFixture {
    /// Plaintext letter stream (each [`Glyph`] is a letter index).
    pub plaintext: Vec<Glyph>,
    /// Ciphertext coset stream emitted by [`gak_encrypt`].
    pub ciphertext: Vec<Glyph>,
    /// The full key, held back for ground-truth checks.
    pub key: GakKey,
    /// The group kind this fixture realizes.
    pub group_kind: GroupKind,
    /// The hidden-subgroup kind this fixture realizes.
    pub hidden_subgroup_kind: HiddenSubgroupKind,
    /// The structure the constructed key **actually** realizes (derived from the
    /// key, not declared). See [`RealizedStructure`]; under the TENTATIVE
    /// small-support knob this can differ from `group_kind.order()`.
    pub realized: RealizedStructure,
}

/// Error returned by the GAK-attack harness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GakAttackError {
    /// A cipher primitive rejected a generated key or stream.
    Cipher(CipherError),
    /// A random-draw bound was zero or too large for the in-crate sampler.
    RandomBoundTooLarge {
        /// Requested exclusive upper bound.
        bound: usize,
    },
    /// At least one seed per group kind is required for the gate matrix.
    ZeroSeeds,
    /// A requested dihedral half-order was below `3` (not non-commutative).
    DihedralHalfOrderTooSmall {
        /// Requested half-order `k`.
        half_order: usize,
    },
    /// A requested cyclic order was below `2`.
    CyclicOrderTooSmall {
        /// Requested order `m`.
        order: usize,
    },
    /// More plaintext letters were requested than the group has non-identity
    /// generators to realize them distinctly.
    TooManyLetters {
        /// Requested letter count.
        requested: usize,
        /// Available non-identity group elements.
        available: usize,
    },
    /// A generated symbol could not be represented as a reading-layer value.
    SymbolOutOfRange {
        /// Offending numeric value.
        value: usize,
    },
    /// The generated plaintext template was empty.
    EmptyTemplate,
    /// The GCTAK positive-control solver did not recover a synthetic key whose
    /// ground truth we hold. This means the **methodology** is suspect, not the
    /// data; it is never a finding.
    PositiveControlFailed {
        /// Group kind of the fixture that failed.
        group: &'static str,
        /// Seed of the fixture that failed.
        seed: u64,
        /// Whether the real (unshuffled) pipeline recovered the plaintext.
        real_recovered: bool,
        /// Whether the matched shuffle-null pipeline recovered the plaintext
        /// (it must not, or the recovery is vacuous).
        null_recovered: bool,
    },
}

impl From<CipherError> for GakAttackError {
    fn from(value: CipherError) -> Self {
        Self::Cipher(value)
    }
}

impl From<crate::null::RandomBoundError> for GakAttackError {
    fn from(error: crate::null::RandomBoundError) -> Self {
        Self::RandomBoundTooLarge { bound: error.bound }
    }
}

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

    Ok(GakAttackReport {
        config,
        hidden_subgroup: HiddenSubgroupKind::Trivial,
        outcomes,
        rates,
        exemplars,
        min_real_recovery_rate: MIN_REAL_RECOVERY_RATE,
        rate_gate_passed,
        all_null_failed,
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
    if config.phrase_repeats == 0 || config.phrase_len == 0 {
        return Err(GakAttackError::EmptyTemplate);
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
// A. Synthetic generator driver (ground-truth fixtures).
// =====================================================================

/// Builds a synthetic GCTAK fixture with held-back ground truth.
///
/// `group_kind` selects the abstract state group (commutative cyclic or
/// non-commutative dihedral). Both are realized as permutation groups by the
/// **left regular representation**, so the solver code path is identical. The
/// hidden subgroup is trivial ([`HiddenSubgroupKind::Trivial`]) so the readout is
/// bijective (`|C| = |G|`), i.e. GCTAK.
///
/// `config.num_pt_letters` distinct non-identity group elements become the
/// plaintext letters' permutations. `config.small_support_radius` (TENTATIVE)
/// composes each letter permutation with `≤k` random transpositions; `0` is the
/// unconstrained regime the gate uses. The plaintext is a repeated-phrase
/// template so the ciphertext is isomorph-rich.
///
/// # Errors
/// Returns [`GakAttackError`] when the group is too small for the requested
/// letter count, when a generated permutation or key is rejected, or when a
/// generated symbol cannot be represented.
pub fn generate_fixture(
    group_kind: GroupKind,
    config: GakAttackConfig,
    seed: u64,
) -> Result<SyntheticFixture, GakAttackError> {
    let order = group_kind.order();
    if order < 2 {
        return Err(GakAttackError::CyclicOrderTooSmall { order });
    }

    // Group multiplication table over indices 0..order, with index 0 = identity.
    let table = group_table(group_kind)?;

    // Choose `num_pt_letters` distinct non-identity generators.
    let available = order.saturating_sub(1);
    if config.num_pt_letters == 0 || config.num_pt_letters > available {
        return Err(GakAttackError::TooManyLetters {
            requested: config.num_pt_letters,
            available,
        });
    }
    let mut rng = SplitMix64::new(seed);
    let generators = choose_generators(
        &table,
        config.num_pt_letters,
        group_kind.is_non_commutative(),
        &mut rng,
    )?;

    // Realize each generator as its left-regular permutation, then optionally
    // perturb by ≤k transpositions (TENTATIVE small-support knob). The perturbed
    // permutation is still a valid S_n element; GCTAK only needs a bijective
    // readout, which the CosetTable identity projection provides regardless.
    let mut plaintext_letters = Vec::with_capacity(config.num_pt_letters);
    for &generator in &generators {
        let mut permutation = left_regular_permutation(&table, generator)?;
        apply_small_support(&mut permutation, config.small_support_radius, &mut rng)?;
        plaintext_letters.push(permutation);
    }

    // Trivial H: bijective readout via an identity coset table over 0..order.
    let coset_of: Vec<usize> = (0..order).collect();
    let readout = CosetReadout::CosetTable {
        reference_value: 0,
        coset_of,
    };
    let initial_state: Vec<usize> = (0..order).collect();
    let key = GakKey::new(
        order,
        plaintext_letters,
        initial_state,
        readout,
        GakKeyOptions::default(),
    )?;

    let plaintext = repeated_phrase_template(config, config.num_pt_letters, &mut rng)?;
    if plaintext.is_empty() {
        return Err(GakAttackError::EmptyTemplate);
    }
    let ciphertext = gak_encrypt(&plaintext, &key)?;

    // F3: derive the structure the constructed key ACTUALLY realizes (do not
    // declare it). Under the TENTATIVE small-support knob the perturbed letters
    // may generate a smaller subgroup than the declared base order; report the
    // realized size honestly and verify (rather than assume) that the readout
    // stays bijective on reachable states (trivial hidden subgroup).
    let realized = realized_structure(&key, group_kind.order())?;

    Ok(SyntheticFixture {
        plaintext,
        ciphertext,
        key,
        group_kind,
        hidden_subgroup_kind: HiddenSubgroupKind::Trivial,
        realized,
    })
}

/// Derives the structure a constructed [`GakKey`] **actually realizes** by
/// enumerating the reachable states.
///
/// Starting from the key's initial state, this closes the set of states under
/// left-multiplication by every plaintext-letter permutation (the only states the
/// cipher can ever occupy), then reads off:
/// - the realized subgroup order (number of reachable states),
/// - the realized ciphertext-coset alphabet `|C|` (distinct readouts), and
/// - whether the readout is **bijective on those states** (trivial `H`,
///   *verified* not assumed).
///
/// For `small_support_radius == 0` the regular representation is faithful, so the
/// realized order equals `declared_group_order` and nothing changes for the gate.
///
/// # Errors
/// Returns [`GakAttackError`] if a reachable state's readout cannot be computed
/// or a generated symbol cannot be represented (both internal invariants here).
fn realized_structure(
    key: &GakKey,
    declared_group_order: usize,
) -> Result<RealizedStructure, GakAttackError> {
    let initial = key.initial_state().to_vec();
    let mut seen: BTreeSet<Vec<usize>> = BTreeSet::new();
    let _inserted = seen.insert(initial.clone());
    let mut frontier = vec![initial];
    while let Some(state) = frontier.pop() {
        for permutation in key.plaintext_letters() {
            let next = compose_state(permutation, &state)?;
            if seen.insert(next.clone()) {
                frontier.push(next);
            }
        }
    }

    // Readout of every reachable state; |C| and bijectivity follow.
    let mut readouts: Vec<usize> = Vec::with_capacity(seen.len());
    for state in &seen {
        readouts.push(readout_of_state(key, state)?);
    }
    let distinct_cosets: BTreeSet<usize> = readouts.iter().copied().collect();
    let realized_subgroup_order = seen.len();
    let realized_coset_alphabet_size = distinct_cosets.len();
    // Bijective on reachable states iff distinct states map to distinct cosets.
    let readout_bijective = realized_coset_alphabet_size == realized_subgroup_order;

    Ok(RealizedStructure {
        declared_group_order,
        realized_subgroup_order,
        realized_coset_alphabet_size,
        readout_bijective,
        faithful_to_declared: realized_subgroup_order == declared_group_order,
    })
}

/// The held ground-truth per-letter ciphertext-alphabet permutations `tau_a`.
///
/// For GCTAK the readout is bijective on reachable states, so each plaintext
/// letter `a` induces a fixed permutation `tau_a` of the ciphertext alphabet with
/// `c(p(a) ∘ g) = tau_a(c(g))` for every reachable state `g`. This enumerates the
/// reachable states and reads `tau_a` off directly from the key, giving the
/// ground truth the recovered permutations are scored against (review finding F5).
/// Each `tau_a` is returned as a `prev -> next` [`EdgeMap`] so it compares against
/// a recovered permutation by structural equality.
///
/// # Errors
/// Returns [`GakAttackError`] if a reachable state's readout cannot be computed or
/// a coset value exceeds the `u8` symbol range (internal invariants here).
fn truth_letter_permutations(key: &GakKey) -> Result<Vec<EdgeMap>, GakAttackError> {
    // Enumerate reachable states (the same closure used by `realized_structure`).
    let initial = key.initial_state().to_vec();
    let mut seen: BTreeSet<Vec<usize>> = BTreeSet::new();
    let _inserted = seen.insert(initial.clone());
    let mut frontier = vec![initial];
    while let Some(state) = frontier.pop() {
        for permutation in key.plaintext_letters() {
            let next = compose_state(permutation, &state)?;
            if seen.insert(next.clone()) {
                frontier.push(next);
            }
        }
    }

    let mut truths = Vec::with_capacity(key.plaintext_letters().len());
    for permutation in key.plaintext_letters() {
        let mut tau = EdgeMap::new();
        for state in &seen {
            let from = readout_of_state(key, state)?;
            let updated = compose_state(permutation, state)?;
            let to = readout_of_state(key, &updated)?;
            let from_value = u8::try_from(from)
                .map_err(|_error| GakAttackError::SymbolOutOfRange { value: from })?;
            let to_value = u8::try_from(to)
                .map_err(|_error| GakAttackError::SymbolOutOfRange { value: to })?;
            let _old = tau.insert(from_value, to_value);
        }
        truths.push(tau);
    }
    Ok(truths)
}

/// Scores recovered per-letter permutations against the held truth `tau_a`.
///
/// Returns `(matched, total)`: how many of the `total` truth permutations equal
/// some recovered permutation (one-to-one, up to the canonical relabelling of
/// letters that the edge-map representation already absorbs — a `tau_a` is the
/// same fixed bijection however the generator numbered letter `a`). This is the
/// spec's preferred success metric (per-letter permutation recovery), surfaced in
/// the report and asserted in tests (review finding F5).
fn permutation_recovery_fraction(truth: &[EdgeMap], recovered: &[EdgeMap]) -> (usize, usize) {
    let mut used = vec![false; recovered.len()];
    let mut matched = 0usize;
    for tau in truth {
        for (index, perm) in recovered.iter().enumerate() {
            let Some(slot) = used.get_mut(index) else {
                continue;
            };
            if !*slot && perm == tau {
                *slot = true;
                matched = matched.saturating_add(1);
                break;
            }
        }
    }
    (matched, truth.len())
}

/// Composes two `0..n` permutations in the `(f ∘ g)[i] = f[g[i]]` convention used
/// by [`gak_encrypt`] (the cipher's state-update convention).
fn compose_state(outer: &[usize], inner: &[usize]) -> Result<Vec<usize>, GakAttackError> {
    let mut composed = Vec::with_capacity(inner.len());
    for &image in inner {
        let mapped = outer
            .get(image)
            .copied()
            .ok_or(GakAttackError::SymbolOutOfRange { value: image })?;
        composed.push(mapped);
    }
    Ok(composed)
}

/// Computes the readout `c(state)` as a plain `usize`, mirroring the cipher's
/// [`CosetReadout`] projection (used by [`realized_structure`]).
fn readout_of_state(key: &GakKey, state: &[usize]) -> Result<usize, GakAttackError> {
    match key.coset_readout() {
        CosetReadout::TopCard { reference_value } => {
            inverse_image_position(state, *reference_value)
        }
        CosetReadout::CosetTable {
            reference_value,
            coset_of,
        } => {
            let position = inverse_image_position(state, *reference_value)?;
            coset_of
                .get(position)
                .copied()
                .ok_or(GakAttackError::SymbolOutOfRange { value: position })
        }
    }
}

/// The multiplication table `table[x][y] = index(x · y)` over `0..order`.
fn group_table(group_kind: GroupKind) -> Result<Vec<Vec<usize>>, GakAttackError> {
    match group_kind {
        GroupKind::Cyclic { order } => {
            if order < 2 {
                return Err(GakAttackError::CyclicOrderTooSmall { order });
            }
            let mut table = vec![vec![0usize; order]; order];
            for (x, row) in table.iter_mut().enumerate() {
                for (y, slot) in row.iter_mut().enumerate() {
                    *slot = (x + y) % order;
                }
            }
            Ok(table)
        }
        GroupKind::Dihedral { half_order } => dihedral_table(half_order),
    }
}

/// Multiplication table for `D_{2k}` (order `2k`).
///
/// Elements are indexed `0..k` for rotations `r^j` and `k..2k` for reflections
/// `s·r^j`. Products use the dihedral relations `r^a · r^b = r^{a+b}`,
/// `r^a · (s r^b) = s r^{b-a}`, `(s r^a) · r^b = s r^{a+b}`,
/// `(s r^a) · (s r^b) = r^{b-a}` (all exponents mod `k`). Index `0` is the
/// identity `r^0`.
fn dihedral_table(half_order: usize) -> Result<Vec<Vec<usize>>, GakAttackError> {
    if half_order < 3 {
        return Err(GakAttackError::DihedralHalfOrderTooSmall { half_order });
    }
    let order = half_order.saturating_mul(2);
    let mut table = vec![vec![0usize; order]; order];
    for (left, row) in table.iter_mut().enumerate() {
        for (right, slot) in row.iter_mut().enumerate() {
            *slot = dihedral_product(half_order, left, right);
        }
    }
    Ok(table)
}

fn dihedral_product(half_order: usize, left: usize, right: usize) -> usize {
    let k = half_order;
    let left_reflect = left >= k;
    let right_reflect = right >= k;
    let left_exp = left % k;
    let right_exp = right % k;
    match (left_reflect, right_reflect) {
        // r^a · r^b = r^{a+b}
        (false, false) => (left_exp + right_exp) % k,
        // r^a · (s r^b) = s r^{b-a}
        (false, true) => k + (right_exp + k - left_exp % k) % k,
        // (s r^a) · r^b = s r^{a+b}
        (true, false) => k + (left_exp + right_exp) % k,
        // (s r^a) · (s r^b) = r^{b-a}
        (true, true) => (right_exp + k - left_exp % k) % k,
    }
}

/// The left-regular permutation of a group element: `L(x)[i] = index(x · h_i)`.
fn left_regular_permutation(
    table: &[Vec<usize>],
    element: usize,
) -> Result<Vec<usize>, GakAttackError> {
    let Some(row) = table.get(element) else {
        return Err(GakAttackError::SymbolOutOfRange { value: element });
    };
    Ok(row.clone())
}

/// Chooses `count` distinct non-identity group elements as the plaintext letters.
///
/// For a **non-commutative** group with `count >= 2` the draw is rejected and
/// re-rolled (deterministically, bounded) until the chosen elements include at
/// least one non-commuting pair, so the generated dihedral fixture genuinely
/// realizes a non-commutative subgroup rather than accidentally an abelian subset
/// (review finding F6). For commutative groups (or `count < 2`) the first draw is
/// kept. If no non-commuting draw is found within the bound, the last draw is
/// returned (the caller's higher-level checks still hold); in practice a
/// non-commuting pair is found almost immediately for `D_{2k}`.
fn choose_generators(
    table: &[Vec<usize>],
    count: usize,
    require_non_commuting: bool,
    rng: &mut SplitMix64,
) -> Result<Vec<usize>, GakAttackError> {
    const MAX_DRAWS: usize = 64;
    let order = table.len();
    let mut last = Vec::new();
    for _draw in 0..MAX_DRAWS {
        // Non-identity elements are 1..order. Draw `count` distinct ones.
        let mut pool: Vec<usize> = (1..order).collect();
        fisher_yates(&mut pool, rng)?;
        pool.truncate(count);
        pool.sort_unstable();
        if !require_non_commuting || count < 2 || has_non_commuting_pair(table, &pool) {
            return Ok(pool);
        }
        last = pool;
    }
    Ok(last)
}

/// Returns `true` when some pair of elements in `elements` does not commute under
/// the group multiplication `table`.
fn has_non_commuting_pair(table: &[Vec<usize>], elements: &[usize]) -> bool {
    for (i, &x) in elements.iter().enumerate() {
        for &y in elements.iter().skip(i.saturating_add(1)) {
            let xy = table.get(x).and_then(|row| row.get(y)).copied();
            let yx = table.get(y).and_then(|row| row.get(x)).copied();
            if xy != yx {
                return true;
            }
        }
    }
    false
}

/// Composes `permutation` with `radius` random transpositions in place.
///
/// **TENTATIVE small-support heuristic** (`Deck-Cipher.md`): the result is still a
/// valid `S_n` permutation. The GCTAK gate runs with `radius == 0`.
fn apply_small_support(
    permutation: &mut [usize],
    radius: usize,
    rng: &mut SplitMix64,
) -> Result<(), GakAttackError> {
    let len = permutation.len();
    if len < 2 {
        return Ok(());
    }
    for _swap in 0..radius {
        let i = random_index_below(len, rng)?;
        let j = random_index_below(len, rng)?;
        permutation.swap(i, j);
    }
    Ok(())
}

/// Builds a repeated-phrase plaintext template over `num_letters` letter indices.
///
/// A single random phrase of `config.phrase_len` letters is repeated
/// `config.phrase_repeats` times, each repeat preceded by a fixed-length run of
/// **random** mixing letters. The mixing runs let the absolute group state drift
/// over the whole state group between repeats, so the same phrase occurrence is
/// seen from many different entry states; this is what lets the solver observe
/// each per-letter permutation across the full group (and thus merge same-letter
/// phrase columns exactly), and it works for non-commutative groups where a bare
/// repeat would only ever enter from a small orbit.
///
/// The GCTAK ciphertext is **not** periodic (the state accumulates); only the
/// equality/gap pattern of each phrase occurrence recurs, which is the
/// isomorph-rich signal the solver aligns on. The first two phrase positions are
/// forced to two different letters (when `num_letters ≥ 2`) so the partition is
/// non-degenerate.
fn repeated_phrase_template(
    config: GakAttackConfig,
    num_letters: usize,
    rng: &mut SplitMix64,
) -> Result<Vec<Glyph>, GakAttackError> {
    if num_letters == 0 {
        return Err(GakAttackError::EmptyTemplate);
    }
    let mut phrase = Vec::with_capacity(config.phrase_len);
    for index in 0..config.phrase_len {
        // The first `num_letters` positions are the distinct letters in order so
        // every fixture uses all letters and the phrase signature starts with a
        // distinctive all-distinct run; later positions are random.
        let letter = if index < num_letters {
            index
        } else {
            random_index_below(num_letters, rng)?
        };
        phrase.push(letter);
    }

    // A short random mixing run between repeats drifts the entry state.
    let mixing_len = MIXING_RUN_LEN;
    let mut letters = Vec::new();
    for repeat in 0..config.phrase_repeats {
        if repeat > 0 {
            for _index in 0..mixing_len {
                letters.push(random_index_below(num_letters, rng)?);
            }
        }
        letters.extend(phrase.iter().copied());
    }

    let mut plaintext = Vec::with_capacity(letters.len());
    for letter in letters {
        let glyph = u16::try_from(letter)
            .map_err(|_error| GakAttackError::SymbolOutOfRange { value: letter })?;
        plaintext.push(Glyph(glyph));
    }
    Ok(plaintext)
}

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
fn evaluate_fixture(
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
        letters_recovered: real.letter_count,
        real_permutations_recovered,
        permutations_total,
        null_permutations_recovered,
        chain_link_checks: real.chain_link_checks,
        chain_link_consistent: real.chain_link_consistent,
        real_recovered_exactly,
        null_recovered_exactly,
    })
}

/// Computes the readout `c(g_0)` of a key's initial state.
///
/// This is the ciphertext symbol the stream conceptually starts from (the state
/// entering the first plaintext letter). For the [`CosetReadout::CosetTable`]
/// readout used by the gate it is `coset_of[g_0^{-1}[reference]]`; for
/// [`CosetReadout::TopCard`] it is `g_0^{-1}[reference]`.
fn initial_state_readout(key: &GakKey) -> Result<SymbolValue, GakAttackError> {
    let state = key.initial_state();
    let readout_value = match key.coset_readout() {
        CosetReadout::TopCard { reference_value } => {
            inverse_image_position(state, *reference_value)?
        }
        CosetReadout::CosetTable {
            reference_value,
            coset_of,
        } => {
            let position = inverse_image_position(state, *reference_value)?;
            coset_of
                .get(position)
                .copied()
                .ok_or(GakAttackError::SymbolOutOfRange { value: position })?
        }
    };
    symbol_from_usize(readout_value)
}

/// Returns the position `j` with `state[j] == value` (`state^{-1}[value]`).
fn inverse_image_position(state: &[usize], value: usize) -> Result<usize, GakAttackError> {
    state
        .iter()
        .position(|&entry| entry == value)
        .ok_or(GakAttackError::SymbolOutOfRange { value })
}

fn symbol_from_usize(value: usize) -> Result<SymbolValue, GakAttackError> {
    let raw = u8::try_from(value).map_err(|_error| GakAttackError::SymbolOutOfRange { value })?;
    TrigramValue::new(raw).map_err(|bad| GakAttackError::SymbolOutOfRange {
        value: usize::from(bad),
    })
}

/// The recovered GCTAK structure from one ciphertext stream.
#[derive(Clone, Debug, PartialEq, Eq)]
struct GctakSolution {
    /// Recovered plaintext letter stream, canonicalized by first-occurrence
    /// order (so it is comparable to ground truth without depending on the
    /// generator's arbitrary letter numbering).
    canonical_letters: Vec<usize>,
    /// The recovered per-letter ciphertext-alphabet permutations `tau_a`, each as
    /// a `prev -> next` edge map. Held so the gate can score them directly against
    /// the held ground-truth permutations (review finding F5), not just compare
    /// the plaintext partition.
    recovered_permutations: Vec<EdgeMap>,
    /// Number of distinct letters the solver clustered.
    letter_count: usize,
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
fn solve_gctak(
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
    let letter_count = recovered.len();

    GctakSolution {
        canonical_letters,
        recovered_permutations: recovered,
        letter_count,
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
fn verify_against_chain_links(links: &[ChainLink], recovered: &[EdgeMap]) -> (usize, usize) {
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
fn collect_chain_links(ciphertext: &[SymbolValue]) -> Vec<ChainLink> {
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

/// One recovered per-letter permutation as a `prev -> next` edge map.
///
/// Stored as a sorted edge list so two permutations compare by structural
/// equality regardless of insertion order.
type EdgeMap = BTreeMap<u8, u8>;

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
fn phrase_chain_links(walk: &[SymbolValue], phrase_len: usize) -> Vec<ChainLink> {
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
fn canonical_letters(letters: &[usize]) -> Vec<usize> {
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

fn glyphs_to_values(glyphs: &[Glyph]) -> Result<Vec<SymbolValue>, GakAttackError> {
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

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_PHRASE_LEN, GakAttackConfig, GroupKind, HiddenSubgroupKind, SOLVER_WINDOW_LEN,
        canonical_letters, collect_chain_links, generate_fixture, glyphs_to_values,
        initial_state_readout, phrase_chain_links, run_gak_attack, solve_gctak,
        truth_letter_permutations, verify_against_chain_links,
    };
    use crate::chaining_graph::{AlignedOccurrence, ChainLink, ContextId, chain_links_for_pair};
    use crate::ciphers::{gak_decrypt, gak_encrypt};

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
}

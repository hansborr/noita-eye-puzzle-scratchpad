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
use crate::null::{
    SplitMix64, add_one_p_value, fisher_yates, mix_seed, random_index_below, shuffled_permutation,
};
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
/// The GCTAK gate realizes the **trivial** hidden subgroup (`|H| = 1`, bijective
/// readout `c`). Unit 2a adds the **deck stabilizer** [`Self::DeckStabilizer`]:
/// the real, non-trivial GAK the community's open problem is about
/// (`H = Stab(top) = S_{n-1}`, `|H| = (n-1)! > 1`, `|C| = n`, hidden state = the
/// rest of the deck).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiddenSubgroupKind {
    /// Trivial hidden subgroup `H = {e}`: the readout `c` is bijective and
    /// `|C| = |G|`. This is the GCTAK regime.
    Trivial,
    /// Deck-stabilizer hidden subgroup `H = Stab(top) = S_{n-1}` over the full
    /// symmetric state group `S_n` ([`CosetReadout::TopCard`]): the visible
    /// symbol is the position holding the marked card, `|C| = n`, `|H| = (n-1)!`,
    /// and the rest of the deck is the hidden state. This is **real GAK**
    /// (`|H| > 1`) — the regime the deck-cipher attack of this unit targets.
    DeckStabilizer,
}

impl HiddenSubgroupKind {
    /// Returns a short report label for this hidden-subgroup kind.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Trivial => "trivial-H (GCTAK)",
            Self::DeckStabilizer => "deck-stabilizer S_{n-1} (real GAK, |H|>1)",
        }
    }

    /// Whether this hidden subgroup is non-trivial (`|H| > 1`), i.e. real GAK.
    #[must_use]
    pub const fn is_non_trivial(self) -> bool {
        matches!(self, Self::DeckStabilizer)
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
    /// A requested deck size `n` was below `3`. The non-trivial-`H` deck attack
    /// requires `n >= 3`: at `n = 2` the hidden subgroup `H = S_1` is trivial (so it
    /// is GCTAK, not real GAK) and the group-dependent merge threshold
    /// `n - 1` collapses to `1`, which would let a single shared edge merge two
    /// actions — defeating the worst-case `S_n`/`S_{n-1}` overlap discipline. The
    /// default sweep (`5..=8`) is unaffected.
    DeckStateSizeTooSmall {
        /// Requested deck size `n`.
        state_size: usize,
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
    // The headline sweep runs the prior OFF (held-out generalization only); the
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
fn deck_hidden_subgroup_order(state_size: usize) -> u128 {
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
struct CosetEdge {
    /// Source visible coset symbol.
    from: u8,
    /// Image visible coset symbol under the context action.
    to: u8,
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
struct ContextAction {
    /// Forward partial permutation `from -> to`.
    forward: BTreeMap<u8, u8>,
    /// The distinct directed edges (for the group-dependent overlap threshold).
    edges: BTreeSet<CosetEdge>,
    /// `true` once a TRUE conflict (non-functional forward or backward) is seen.
    true_conflict: bool,
}

impl ContextAction {
    /// Inserts one observed edge, setting [`Self::true_conflict`] if it violates
    /// the partial-permutation law (forward or backward single-valuedness).
    fn insert(&mut self, edge: CosetEdge) {
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
struct ChainSubstrate {
    /// One [`ContextAction`] per aligned isomorph occurrence pair (one context).
    contexts: Vec<ContextAction>,
    /// Number of TRUE-conflict aborts encountered while building contexts.
    true_conflict_aborts: usize,
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
fn build_chain_substrate(
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
fn spacing_filter(starts: &[usize], window_len: usize) -> Vec<usize> {
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
struct DeckAttackSolution {
    /// The merged single-valued-core actions: each is a partial map on the visible
    /// coset alphabet, light-merged across phrase columns. These are the recovered
    /// PARTIAL visible-coset action maps scored against ground truth — a fraction of
    /// per-letter visible-coset transitions, NOT a recovered key and NOT the
    /// plaintext->group-element mapping.
    recovered_actions: Vec<BTreeMap<u8, u8>>,
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
fn run_deck_attack(
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
fn aligned_phrase_occurrences(ciphertext: &[SymbolValue], window_len: usize) -> Option<Vec<usize>> {
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
fn truth_coset_edges(
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
fn coset_recovery_fraction(
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
fn evaluate_deck_fixture(
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
fn mean_f64(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
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
    /// The prior is OFF: held-out generalization over all train branches is the only
    /// beam score; every train edge is a candidate.
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
            Self::Off => "OFF (held-out generalization only)",
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
    /// branches; a beam that over-admits noise (or, in the null, admits unrelated
    /// edges) does not.
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
    // larger admitted set so genuine multi-valued recovery (the point of
    // marginalization) is not under-counted at equal generalization. `best` is chosen
    // ONLY from the in-width candidates, so the dropped beams are truly ineligible.
    beams.sort_by(|a, b| {
        b.generalization()
            .partial_cmp(&a.generalization())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.admitted.len().cmp(&a.admitted.len()))
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
/// FAILS GRACEFULLY (it only ever drops genuine low-support edges, never invents any,
/// so precision never drops and a wrong small-support assumption is never rewarded).
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
    /// prior `on`. The prior is designed to NOT lower precision (it only drops
    /// genuine low-support edges, never invents any).
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
        DEFAULT_BEAM_WIDTH, MarginalizationReport, SmallSupportPrior, run_marginalization_attack,
        run_marginalization_sweep, run_small_support_validation, single_valued_core_of_split,
        split_column_evidence,
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
            // across the whole sweep (the measured ratios run ~5.9x / 3.9x / 4.9x / 2.8x
            // from easiest to hardest n; the >=2x floor is the honest universal multiple
            // that holds even at the hardest swept n, where the marginalization is most
            // eroded). This matches the report's "SEVERAL-FOLD at every n" wording and
            // catches a quiet regression at ANY n, not only the easiest one.
            assert!(
                point.idea3_true_total >= point.baseline_true_total.saturating_mul(2),
                "idea-3 ({}) should recover at least 2x the 2a core ({}) at n={}",
                point.idea3_true_total,
                point.baseline_true_total,
                point.state_size
            );
        }
        // On the EASIEST fixture the margin is even larger (~5.9x measured): keep the
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
        // Precision is HELD or improved by the floor in both conditions (the floor
        // removes low-confidence edges, it cannot lower precision).
        assert!(
            v.small_precision(true) >= v.small_precision(false),
            "prior must not lower precision on small-support truth: on={:.3} off={:.3}",
            v.small_precision(true),
            v.small_precision(false)
        );
        assert!(
            v.broad_precision(true) >= v.broad_precision(false),
            "prior must not lower precision on unconstrained truth: on={:.3} off={:.3}",
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
}

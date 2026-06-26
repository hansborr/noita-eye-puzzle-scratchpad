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
use std::fmt::{self, Write as _};
use std::path::{Path, PathBuf};

use crate::chaining_graph::{
    AlignedOccurrence, ChainLink, ContextId, SymbolValue, chain_links_for_pair,
};
use crate::ciphers::{
    CipherError, CosetReadout, GakKey, GakKeyOptions, compose_permutations, gak_encrypt,
};
use crate::glyph::Glyph;
use crate::isomorph::PatternSignature;
use crate::language::{self, LanguageModel};
use crate::null::{
    SplitMix64, add_one_p_value, fisher_yates, mix_seed, random_index_below, shuffled_permutation,
    stateless_splitmix,
};
use crate::orders::{self, GridError};
use crate::perfect_isomorphism::{self, PerfectIsomorphismError};
use crate::report::{self, Report};
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
#[derive(Clone, Debug, PartialEq)]
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
    /// Fewer than two plaintext letters were requested. This is a plain user
    /// config error, rejected up front so it never masquerades as a
    /// [`GakAttackError::PositiveControlFailed`] methodology failure. Two is the
    /// real minimum: the dihedral non-commutative witness needs `count >= 2` (at
    /// `count < 2` `choose_generators` short-circuits the non-commuting-pair check)
    /// and a non-degenerate repeated-phrase partition needs at least two distinct
    /// letters.
    TooFewLetters {
        /// Requested letter count.
        requested: usize,
    },
    /// A nonzero `small_support_radius` was requested for the GCTAK gate. The gate
    /// runs **unconstrained** (radius `0`) by construction so that the report's
    /// declared GCTAK assumptions stay true; the TENTATIVE small-support prior is
    /// exercised only by the deck / marginalization validation sweeps (via
    /// [`DeckLetterRegime::SmallSupport`] and [`SmallSupportPrior`]), never by the
    /// decisive gate. A nonzero radius here would silently change those assumptions,
    /// so it is rejected rather than honored.
    SmallSupportRadiusUnsupported {
        /// Requested (rejected) small-support radius.
        requested: usize,
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
    /// The verified eye corpus could not be reconstructed or read (Step 3 only).
    Grid(GridError),
    /// Thread 3's perfect-isomorphism scan failed to run (Step 3 consistency
    /// gate); the consistency verdict is unavailable, so no eye candidate may be
    /// named. This is a methodology/transcription failure, never a finding.
    PerfectIsomorphism(PerfectIsomorphismError),
    /// The held-out positive control did not fire on the synthetic isomorph-rich
    /// eye-shaped fixture (Step 3). The held-out predictor must beat its matched
    /// null on KNOWN signal or the held-out gate is not trustworthy; this is a
    /// methodology failure, never an eye finding.
    HeldOutPositiveControlFailed {
        /// Coverage-weighted held-out score the predictor achieved on the synthetic
        /// signal.
        real_score: i64,
        /// Coverage-weighted held-out score the matched null achieved (must be
        /// lower).
        null_score: i64,
    },
    /// A language model used by the SPECULATIVE cleartext gate could not be built
    /// (Step 3). The cleartext path is speculative and never primary, so this is
    /// surfaced rather than silently skipped.
    Language(language::LanguageError),
    /// Writing the mandatory candidate record to disk failed (Step 3). The record
    /// is a standing user directive, so a write failure is a hard error.
    CandidateRecordWrite {
        /// Path the record could not be written to.
        path: String,
    },
    /// The eyes Step-3 run was asked for zero matched-null trials (Step 3). The
    /// held-out gate's significance rests on the matched within-message shuffle
    /// null, so it must have at least one draw; zero trials would leave the
    /// p-value and null mean defined over an empty sample (the same discipline as
    /// [`crate::null::NullConfigError::ZeroTrials`]). This is a configuration
    /// error, never a finding.
    EyesZeroTrials,
}

impl fmt::Display for GakAttackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cipher(cipher_error) => write!(f, "GAK-attack cipher error: {cipher_error}"),
            Self::RandomBoundTooLarge { bound } => {
                write!(
                    f,
                    "random draw bound {bound} is too large for the in-crate sampler"
                )
            }
            Self::ZeroSeeds => {
                write!(
                    f,
                    "at least one seed per group kind is required for the gate matrix"
                )
            }
            Self::DihedralHalfOrderTooSmall { half_order } => {
                write!(
                    f,
                    "dihedral half-order {half_order} is below 3 (would not be non-commutative)"
                )
            }
            Self::CyclicOrderTooSmall { order } => write!(f, "cyclic order {order} is below 2"),
            Self::DeckStateSizeTooSmall { state_size } => write!(
                f,
                "deck size n={state_size} is below 3: the non-trivial-H deck attack requires n>=3 (n=2 is trivial-H GCTAK and collapses the merge threshold to 1)"
            ),
            Self::TooManyLetters {
                requested,
                available,
            } => write!(
                f,
                "requested {requested} plaintext letters but the group has only {available} non-identity generators"
            ),
            Self::TooFewLetters { requested } => write!(
                f,
                "requested {requested} plaintext letters but at least 2 are required (the dihedral non-commutative witness and a non-degenerate repeated-phrase partition both need >=2)"
            ),
            Self::SmallSupportRadiusUnsupported { requested } => write!(
                f,
                "small-support radius {requested} is rejected for the GCTAK gate, which runs unconstrained (radius 0); the small-support prior is exercised only by the deck/marginalization validation sweeps"
            ),
            Self::SymbolOutOfRange { value } => {
                write!(
                    f,
                    "generated symbol {value} cannot be represented as a reading-layer value"
                )
            }
            Self::EmptyTemplate => write!(f, "the generated plaintext template was empty"),
            Self::PositiveControlFailed {
                group,
                seed,
                real_recovered,
                null_recovered,
            } => write!(
                f,
                "positive control failed for {group} seed {seed}: real_recovered={real_recovered}, null_recovered={null_recovered} (methodology bug, never a data finding)"
            ),
            Self::Grid(grid_error) => write!(f, "eye corpus grid/order error: {grid_error:?}"),
            Self::PerfectIsomorphism(error) => {
                write!(
                    f,
                    "Thread-3 perfect-isomorphism consistency scan failed: {error}"
                )
            }
            Self::HeldOutPositiveControlFailed {
                real_score,
                null_score,
            } => write!(
                f,
                "held-out positive control did not fire on the synthetic isomorph-rich fixture (real score={real_score} <= worst-case null score={null_score}); the held-out gate is not trustworthy (methodology bug, never an eye finding)"
            ),
            Self::Language(error) => {
                write!(
                    f,
                    "language model for the SPECULATIVE cleartext gate could not be built: {error}"
                )
            }
            Self::CandidateRecordWrite { path } => {
                write!(
                    f,
                    "could not write the mandatory candidate record to {path}"
                )
            }
            Self::EyesZeroTrials => {
                write!(
                    f,
                    "the eyes Step-3 held-out gate needs at least one matched-null trial (zero trials would define the p-value over an empty sample)"
                )
            }
        }
    }
}

impl std::error::Error for GakAttackError {}

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

impl From<GridError> for GakAttackError {
    fn from(value: GridError) -> Self {
        Self::Grid(value)
    }
}

impl From<PerfectIsomorphismError> for GakAttackError {
    fn from(value: PerfectIsomorphismError) -> Self {
        Self::PerfectIsomorphism(value)
    }
}

impl From<language::LanguageError> for GakAttackError {
    fn from(value: language::LanguageError) -> Self {
        Self::Language(value)
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
///
/// Thin wrapper over [`compose_permutations`] that maps the shared helper's
/// contextless internal-invariant error into this module's error type. Inputs are
/// assumed validated, so an out-of-range image is an internal invariant rather
/// than expected input; the failing image is not surfaced by the shared helper.
fn compose_state(outer: &[usize], inner: &[usize]) -> Result<Vec<usize>, GakAttackError> {
    compose_permutations(outer, inner)
        .map_err(|_error| GakAttackError::SymbolOutOfRange { value: usize::MAX })
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

impl Report for EyesAttackReport {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(
            &mut out,
            "Thread 4 EYES Step 3 (the ONLY unit that touches the real eye corpus)"
        );
        report::appendln!(
            &mut out,
            "Claim ceiling: the eyes are deterministic, engine-generated, strikingly structured data of unknown meaning; unsolved; no primary developer source confirms recoverable plaintext. Nothing here is stronger."
        );
        report::appendln!(
            &mut out,
            "Expected outcome: NO surviving candidate. The standing conclusion is the eye decode remains BLOCKED on the unknown symbol->meaning mapping; a clean honest negative is a SUCCESS, not a failure."
        );
        report::appendln!(
            &mut out,
            "What is recovered: STRUCTURE (visible-coset / chain-link constraints), NOT cleartext. A full structural recovery still yields abstract plaintext-letter INDICES, not readable text, because symbol->letter mapping needs an external ANCHOR (the standing blocker). Any candidate is a HYPOTHESIS, never a decode."
        );
        report::appendln!(
            &mut out,
            "entry path (exact): orders::corpus_grids() -> accepted_honeycomb_order() -> read_corpus_message_values (per-message, boundaries kept, never concatenated, never re-ordered)"
        );
        report::appendln!(
            &mut out,
            "  reading order `{}`; {} reading-layer symbols; {} distinct (the 83-symbol reading layer); {} messages",
            self.order_name,
            self.total_symbols,
            self.distinct_symbols,
            self.per_message.len()
        );
        report::appendln!(&mut out);
        append_eyes_gate1(&mut out, self);
        report::appendln!(&mut out);
        append_eyes_gates_2_3_verdict(&mut out, self);
        out
    }
}

fn append_eyes_gate1(out: &mut String, eyes_report: &EyesAttackReport) {
    // GATE 1: held-out isomorphs (embargoed-consensus coverage-weighted score).
    report::appendln!(
        out,
        "GATE 1 -- held-out isomorphs vs matched within-message shuffle null"
    );
    report::appendln!(
        out,
        "  statistic: EMBARGOED-CONSENSUS coverage-weighted excess correctness. The recovered model is a LIBRARY of context-colored partial permutations (one per TRAIN isomorph occurrence pair), NOT a collapsed global symbol map. A held-out edge scores only when >=2 train contexts from DISTINCT signature groups -- with NO physical span overlap/adjacency with the held-out context -- AGREE on it; that embargo kills the nested/overlapping-window leak a within-message shuffle mimics, so only genuinely TRANSFERABLE structure scores. score = (A-1)*hits - A*misses (ambiguous unpenalized), A=83, with a per-message COVERAGE CLAMP that zeroes any message with < 4 confident decisions (an explicit part of the statistic, applied identically to real and null). Gate-1 chaining is ENFORCED to stay within the Thread-3 safe isomorph extents (F2). A shuffle has no transferable structure detected by this gate, so it scores ~0."
    );
    report::appendln!(
        out,
        "  held-out POSITIVE CONTROL on a synthetic isomorph-rich eye-shaped fixture: real score {} vs worst-case null score {} (on {} scoreable edges) -> fired={} (the predictor must fire on KNOWN signal AND clear its OWN population's material-effect bar, or the gate is not trusted)",
        eyes_report.held_out_positive_control.real_score,
        eyes_report.held_out_positive_control.null_score,
        eyes_report.held_out_positive_control.scoreable_edges,
        report::yes_no(eyes_report.held_out_positive_control.fired)
    );
    report::appendln!(
        out,
        "  real eyes aggregate held-out: hits={} misses={} ambiguous={}; coverage-weighted score = {}",
        eyes_report.real_held_out_hits_total,
        eyes_report.real_held_out_misses_total,
        eyes_report.real_held_out_ambiguous_total,
        eyes_report.real_score
    );
    report::appendln!(
        out,
        "  matched within-message shuffle null: {} trials, {} >= real; null mean score {:.2}; add-one p = {:.4}",
        eyes_report.trials,
        eyes_report.null_at_least_real,
        eyes_report.null_mean_score,
        eyes_report.matched_null_p_value
    );
    report::appendln!(
        out,
        "  material-effect bar (p-value is NECESSARY, NOT sufficient), POPULATION-RELATIVE and FAIR to the eyes: the real-vs-null excess must reach {:.0}% of the eyes' OWN max achievable score = scoreable_edges*(A-1) = {}*{} = {:.0}, so threshold = {:.1} (BELOW the eyes' max, so genuine signal COULD clear it); met={} (the detector is validated: the positive control clears its own population's bar by the identical rule)",
        EYES_MATERIAL_EFFECT_FRACTION * 100.0,
        eyes_report.scoreable_edges,
        EYE_READING_ALPHABET_SIZE - 1,
        eyes_report.max_achievable_score,
        eyes_report.material_effect_threshold,
        report::yes_no(eyes_report.material_effect_met)
    );
    report::appendln!(
        out,
        "  GATE 1 VERDICT (held-out beats matched null AND clears the calibrated material-effect bar): {}",
        report::yes_no(eyes_report.held_out_beats_null)
    );
    report::appendln!(out, "  per-message (boundaries kept; never concatenated):");
    report::appendln!(
        out,
        "    {:<6} {:>4} {:>10} {:>6} {:>8} {:>7} {:>5} {:>5} {:>5} {:>7}",
        "msg",
        "len",
        "iso-groups",
        "pairs",
        "touched",
        "aborts",
        "hits",
        "miss",
        "amb",
        "score"
    );
    for message in &eyes_report.per_message {
        report::appendln!(
            out,
            "    {:<6} {:>4} {:>10} {:>6} {:>8} {:>7} {:>5} {:>5} {:>5} {:>7}",
            message.message_key,
            message.length,
            message.isomorph_groups,
            message.aligned_pairs,
            message.symbols_touched,
            message.true_conflict_aborts,
            message.real_held_out_hits,
            message.real_held_out_misses,
            message.real_held_out_ambiguous,
            message.real_score
        );
    }
}

fn append_eyes_gates_2_3_verdict(out: &mut String, eyes_report: &EyesAttackReport) {
    // GATE 2: Thread-3 consistency.
    report::appendln!(
        out,
        "GATE 2 -- Thread-3 perfect-isomorphism consistency (Thread-3 API REUSED, never re-derived)"
    );
    report::appendln!(
        out,
        "  robust internal violations: {} (must be 0 -- a non-zero count is a manufactured TRUE conflict that would disqualify the model)",
        eyes_report.three_consistency.robust_internal_violations
    );
    report::appendln!(
        out,
        "  safe isomorph extents exported: {} (Gate-1 chaining is ENFORCED to stay within these per-message safe spans (F2): an occurrence window is admitted only inside a Thread-3 safe span, so chaining never over-extends past them)",
        eyes_report.three_consistency.safe_extents
    );
    report::appendln!(
        out,
        "  Thread-3 positive control fired: {}",
        report::yes_no(eyes_report.three_consistency.positive_control_fired)
    );
    report::appendln!(
        out,
        "  GATE 2 VERDICT (model consistent with Thread 3): {}",
        report::yes_no(eyes_report.three_consistency.consistent)
    );
    report::appendln!(out);

    // GATE 3: speculative cleartext.
    report::appendln!(
        out,
        "GATE 3 -- SPECULATIVE cleartext plausibility (LAST, Finnish-weighted, NEVER primary)"
    );
    match &eyes_report.speculative_cleartext {
        None => {
            report::appendln!(
                out,
                "  NOT RUN. Gate 1 and/or Gate 2 did not pass (the expected case), so the SPECULATIVE cleartext path is correctly NOT executed and NO candidate cleartext is reported."
            );
        }
        Some(cleartext) => {
            report::appendln!(
                out,
                "  RAN (both structural gates passed). The symbol->letter mapping is a HYPOTHESIS, never recovered; this is NEVER primary evidence. Implied plaintext logged VERBATIM to the candidate record for human review (Finnish weighted highly -- Noita is Finnish)."
            );
            report::appendln!(
                out,
                "  Finnish bigram {:.4} vs matched-mapping null {:.4} -> beats={}; English bigram {:.4} vs null {:.4} -> beats={}",
                cleartext.finnish_score,
                cleartext.finnish_null_mean,
                report::yes_no(cleartext.beats_finnish_null),
                cleartext.english_score,
                cleartext.english_null_mean,
                report::yes_no(cleartext.beats_english_null)
            );
        }
    }
    report::appendln!(out);

    // The verdict + interpretation (honesty lock).
    report::appendln!(
        out,
        "THE VERDICT: candidate survived BOTH structural gates: {}",
        report::yes_no(eyes_report.candidate_survived)
    );
    if eyes_report.candidate_survived {
        report::appendln!(
            out,
            "Interpretation: a candidate survived the held-out + Thread-3 checks. It is logged as a HYPOTHESIS for human review, NOT a decode. The claim ceiling still binds: this is NOT a recovered eye plaintext. FLAGGED LOUDLY for human review."
        );
    } else {
        report::appendln!(
            out,
            "Interpretation: no candidate surfaced. This is the EXPECTED, reportable outcome -- with a near-S_83 group and very little eye text, recovered structure does not predict held-out isomorphs above the matched null (no transferable structure DETECTED BY THIS GATE). The eye decode REMAINS BLOCKED on the unknown symbol->meaning mapping. This is a HYPOTHESIS-free honest negative, NOT a decode."
        );
    }
    report::appendln!(
        out,
        "Candidate-logging protocol: every eyes run writes a dated, clock-free record under research/gak-threads/candidates/ capturing the attempt, the recovered-structure amount, the held-out verdict + matched-null p-value, the Thread-3 verdict, and the explicit HYPOTHESIS-not-decode label; any candidate cleartext (English OR Finnish) is logged VERBATIM for human review. This run's record: {}",
        eyes_report.record_path.display()
    );
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

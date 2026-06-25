//! The GAK-attack harness error type and its `From` conversions.

use crate::ciphers::CipherError;
use crate::language;
use crate::orders::GridError;
use crate::perfect_isomorphism::PerfectIsomorphismError;

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
    /// [`crate::gak_attack::DeckLetterRegime::SmallSupport`] and
    /// [`crate::gak_attack::SmallSupportPrior`]), never by the
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

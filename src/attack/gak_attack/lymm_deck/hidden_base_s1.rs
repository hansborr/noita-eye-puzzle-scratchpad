//! Exhaustive known-plaintext recovery for hidden-base `s = 1` top-swap keys.
//!
//! The solver does not take the hidden base or per-letter mapping as input. It
//! enumerates candidate bases `B`, derives the only possible top swap `(0,k)` for
//! each first-seen plaintext letter under that base, and accepts a candidate only
//! when the resulting complete mapping re-encrypts the known plaintext exactly.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::ciphers::validate_permutation;

use super::hidden_base_s1_core::{S1Corpus, S1Search};
use super::{
    HiddenBaseSurfaceReport, KnownPlaintextPair, LymmDeckError, LymmDeckSpec,
    audit_hidden_base_mapping, lymm_default_ct_alphabet,
};

/// Generator family admitted by the hidden-base `s = 1` solver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiddenBaseS1GeneratorFamily {
    /// The top-card transposition family `{(0,k)}`.
    TopCardSwaps,
}

/// Search configuration for [`recover_hidden_base_s1_known_plaintext`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HiddenBaseS1SolverConfig {
    /// Deck size.
    pub n: usize,
    /// Plaintext alphabet in key order.
    pub pt_alphabet: String,
    /// Ciphertext alphabet indexed by emitted deck value.
    pub ct_alphabet: String,
    /// Generator family used for each per-letter perturbation.
    pub generator_family: HiddenBaseS1GeneratorFamily,
    /// Supported top-swap budget. This first rung requires `1`.
    pub swap_budget: usize,
    /// Optional cap on candidate hidden bases tested before returning
    /// [`HiddenBaseS1RecoveryState::SearchCapExceeded`].
    pub max_base_candidates: Option<usize>,
}

impl HiddenBaseS1SolverConfig {
    /// Builds the default top-card-swap configuration for this rung.
    #[must_use]
    pub fn top_card_swaps(n: usize, pt_alphabet: impl Into<String>) -> Self {
        Self {
            n,
            pt_alphabet: pt_alphabet.into(),
            ct_alphabet: lymm_default_ct_alphabet(n),
            generator_family: HiddenBaseS1GeneratorFamily::TopCardSwaps,
            swap_budget: 1,
            max_base_candidates: None,
        }
    }

    /// Replaces the ciphertext alphabet.
    #[must_use]
    pub fn with_ct_alphabet(mut self, ct_alphabet: impl Into<String>) -> Self {
        self.ct_alphabet = ct_alphabet.into();
        self
    }

    /// Replaces the candidate hidden-base cap.
    #[must_use]
    pub const fn with_max_base_candidates(mut self, max_base_candidates: Option<usize>) -> Self {
        self.max_base_candidates = max_base_candidates;
        self
    }
}

/// Final state of a hidden-base `s = 1` known-plaintext recovery run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiddenBaseS1RecoveryState {
    /// The planted base was supplied for post-search audit and was uniquely
    /// recovered by an exact re-encrypting candidate.
    RecoveredPlantedBase,
    /// At least one exact re-encrypting key was found, but the planted base was
    /// not uniquely identified or was not supplied for audit.
    RecoveredEquivalentKey,
    /// More than one exact hidden-base/key representative explains the stream.
    AmbiguousEquivalentClass,
    /// Exhaustive search completed and no exact re-encrypting candidate exists.
    NoCandidate,
    /// The candidate-base cap was reached before exhaustive classification.
    SearchCapExceeded,
}

impl HiddenBaseS1RecoveryState {
    /// Stable report label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::RecoveredPlantedBase => "recovered-planted-base",
            Self::RecoveredEquivalentKey => "recovered-equivalent-key",
            Self::AmbiguousEquivalentClass => "ambiguous-equivalent-class",
            Self::NoCandidate => "no-candidate",
            Self::SearchCapExceeded => "search-cap-exceeded",
        }
    }
}

/// One exact re-encrypting hidden-base/key representative.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HiddenBaseS1RecoveredKey {
    /// Candidate hidden base `B`.
    pub base: Vec<usize>,
    /// Complete per-letter mapping used for exact re-encryption.
    pub pt_mapping: BTreeMap<char, Vec<usize>>,
    /// One selected top-swap index `k` per plaintext letter.
    pub letter_swaps: BTreeMap<char, usize>,
}

/// Measurement and classification report for a hidden-base `s = 1` recovery run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HiddenBaseS1RecoveryReport {
    /// Final recovery state.
    pub state: HiddenBaseS1RecoveryState,
    /// Configuration used for the run.
    pub config: HiddenBaseS1SolverConfig,
    /// `n!` brute-force hidden-base count when it fits in `u128`.
    pub brute_force_base_count: Option<u128>,
    /// Candidate hidden bases tested by the solver.
    pub base_candidates_tested: usize,
    /// Exact re-encrypting base/key representatives found.
    pub exact_candidate_count: usize,
    /// Whether a planted base supplied for audit was one exact candidate.
    pub planted_base_recovered: Option<bool>,
    /// Observed plaintext letters in alphabet order.
    pub observed_letters: Vec<char>,
    /// Total known-plaintext alphabet events checked.
    pub event_count: usize,
    /// Wall-clock time spent in the exhaustive pass and post-search audit.
    pub elapsed: Duration,
    /// First exact re-encrypting representative, when one was found.
    pub representative_key: Option<HiddenBaseS1RecoveredKey>,
    /// Hidden-base decomposition audit for the representative exact mapping.
    pub representative_audit: Option<HiddenBaseSurfaceReport>,
}

impl HiddenBaseS1RecoveryReport {
    /// Returns true when the run found at least one exact key and did not stop at
    /// the search cap.
    #[must_use]
    pub const fn has_exact_recovery(&self) -> bool {
        matches!(
            self.state,
            HiddenBaseS1RecoveryState::RecoveredPlantedBase
                | HiddenBaseS1RecoveryState::RecoveredEquivalentKey
                | HiddenBaseS1RecoveryState::AmbiguousEquivalentClass
        )
    }
}

/// Recovers an exact hidden-base `s = 1` key from known plaintext/ciphertext
/// pairs without receiving the hidden base or planted per-letter mapping.
///
/// # Errors
/// Returns [`LymmDeckError`] if the configuration or corpus is malformed.
pub fn recover_hidden_base_s1_known_plaintext(
    config: &HiddenBaseS1SolverConfig,
    pairs: &[KnownPlaintextPair],
) -> Result<HiddenBaseS1RecoveryReport, LymmDeckError> {
    recover_hidden_base_s1_known_plaintext_inner(config, pairs, None)
}

/// Runs the same no-base solver, then uses an optional planted base only for
/// post-search classification on synthetic controls.
///
/// The planted base is never consulted while enumerating or pruning candidate
/// keys.
///
/// # Errors
/// Returns [`LymmDeckError`] if the configuration, corpus, or planted base is
/// malformed.
pub fn recover_hidden_base_s1_known_plaintext_with_audit(
    config: &HiddenBaseS1SolverConfig,
    pairs: &[KnownPlaintextPair],
    planted_base: Option<&[usize]>,
) -> Result<HiddenBaseS1RecoveryReport, LymmDeckError> {
    recover_hidden_base_s1_known_plaintext_inner(config, pairs, planted_base)
}

fn recover_hidden_base_s1_known_plaintext_inner(
    config: &HiddenBaseS1SolverConfig,
    pairs: &[KnownPlaintextPair],
    planted_base: Option<&[usize]>,
) -> Result<HiddenBaseS1RecoveryReport, LymmDeckError> {
    let started = Instant::now();
    validate_solver_config(config)?;
    if let Some(base) = planted_base {
        validate_permutation("hidden-base s1 planted base", base, config.n)?;
    }
    let spec = solver_spec(config)?;
    let corpus = S1Corpus::new(&spec, pairs)?;
    let brute_force_base_count = factorial_u128(config.n);
    let mut search = S1Search::new(config, &spec, &corpus, planted_base);
    search.run()?;
    let representative_audit = representative_audit(&spec, pairs, &search, planted_base)?;
    let state = classify_recovery(&search, representative_audit.as_ref());

    Ok(HiddenBaseS1RecoveryReport {
        state,
        config: config.clone(),
        brute_force_base_count,
        base_candidates_tested: search.base_candidates_tested,
        exact_candidate_count: search.exact_candidate_count,
        planted_base_recovered: search.planted_base_recovered,
        observed_letters: corpus.observed_letters(&spec),
        event_count: corpus.event_count,
        elapsed: started.elapsed(),
        representative_key: search.representative_key,
        representative_audit,
    })
}

fn validate_solver_config(config: &HiddenBaseS1SolverConfig) -> Result<(), LymmDeckError> {
    if config.n < 2 {
        return Err(LymmDeckError::DeckTooSmall { n: config.n });
    }
    if config.pt_alphabet.is_empty() {
        return Err(LymmDeckError::HiddenBaseConfig {
            reason: "plaintext alphabet must not be empty",
        });
    }
    if config.swap_budget != 1 {
        return Err(LymmDeckError::HiddenBaseConfig {
            reason: "hidden-base known-plaintext solver currently requires s=1",
        });
    }
    match config.generator_family {
        HiddenBaseS1GeneratorFamily::TopCardSwaps => {}
    }
    Ok(())
}

fn solver_spec(config: &HiddenBaseS1SolverConfig) -> Result<LymmDeckSpec, LymmDeckError> {
    let identity_base = (0..config.n).collect::<Vec<_>>();
    LymmDeckSpec::from_base(
        config.n,
        &config.pt_alphabet,
        &config.ct_alphabet,
        identity_base,
    )
}

fn representative_audit(
    spec: &LymmDeckSpec,
    pairs: &[KnownPlaintextPair],
    search: &S1Search<'_>,
    planted_base: Option<&[usize]>,
) -> Result<Option<HiddenBaseSurfaceReport>, LymmDeckError> {
    let Some(key) = &search.representative_key else {
        return Ok(None);
    };
    let audit_spec = LymmDeckSpec::from_base(
        spec.n,
        &spec.pt_alphabet.iter().collect::<String>(),
        &spec.ct_alphabet.iter().collect::<String>(),
        key.base.clone(),
    )?;
    audit_hidden_base_mapping(&audit_spec, pairs, &key.pt_mapping, 1, planted_base).map(Some)
}

fn classify_recovery(
    search: &S1Search<'_>,
    representative_audit: Option<&HiddenBaseSurfaceReport>,
) -> HiddenBaseS1RecoveryState {
    if search.search_cap_exceeded {
        return HiddenBaseS1RecoveryState::SearchCapExceeded;
    }
    if search.exact_candidate_count == 0 {
        return HiddenBaseS1RecoveryState::NoCandidate;
    }
    if search.exact_candidate_count > 1
        || representative_audit.is_some_and(|audit| audit.base_candidate_count > 1)
    {
        return HiddenBaseS1RecoveryState::AmbiguousEquivalentClass;
    }
    if search.planted_base_recovered == Some(true) {
        HiddenBaseS1RecoveryState::RecoveredPlantedBase
    } else {
        HiddenBaseS1RecoveryState::RecoveredEquivalentKey
    }
}

fn factorial_u128(n: usize) -> Option<u128> {
    let mut value = 1u128;
    for factor in 2..=n {
        value = value.checked_mul(u128::try_from(factor).ok()?)?;
    }
    Some(value)
}

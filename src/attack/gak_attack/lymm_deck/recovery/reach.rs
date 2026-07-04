//! Larger-group reach stress controls for generalized swap recovery.

use std::collections::BTreeMap;

use super::super::{
    KnownPlaintextPair, LymmDeckSpec, LymmGeneratorSet, encrypt_lymm_deck, lymm_default_ct_alphabet,
};
use super::selftest::classify_null_recovery;
use super::{
    LetterRecoveryVerdict, NullControlOutcome, RecoveryGeneratorSet, SwapRecoveryConfig,
    SwapRecoveryError, recover_known_plaintext_swaps,
};

/// Configuration for the generalized-reach stress self-test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GakSwapReachStressConfig {
    /// Residual candidate-model cap for solver calls.
    pub max_nodes: Option<usize>,
}

impl Default for GakSwapReachStressConfig {
    fn default() -> Self {
        Self {
            max_nodes: Some(50_000),
        }
    }
}

/// One measured reach stress case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GakSwapReachStressCase {
    /// Deck size.
    pub n: usize,
    /// Maximum generator-word budget.
    pub max_swaps: usize,
    /// Whether exact recovery succeeded and matched the planted permutations.
    pub exact_recovery: bool,
    /// Classified matched-null outcome; only [`NullControlOutcome::CleanFailure`]
    /// earns a passing null.
    pub matched_null_outcome: NullControlOutcome,
    /// Solver nodes reported by the matched-null run, when known.
    pub matched_null_nodes: Option<usize>,
    /// Number of observed plaintext letters.
    pub observed_letters: usize,
    /// Candidate permutations admitted after targeted domain construction.
    pub enumerated_candidates: usize,
    /// Residual solver candidate models checked.
    pub nodes: usize,
}

/// Aggregate measured reach report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GakSwapReachStressReport {
    /// Individual measured cases.
    pub cases: Vec<GakSwapReachStressCase>,
    /// Largest `(n, max_swaps)` pair in this bounded stress sweep that passed.
    pub measured_boundary: Option<(usize, usize)>,
}

impl GakSwapReachStressReport {
    /// Returns true when every measured case recovered exactly and its matched
    /// null failed cleanly.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.cases
            .iter()
            .all(|case| case.exact_recovery && case.matched_null_outcome.is_clean_failure())
    }
}

/// Runs a bounded larger-group stress self-test for explicit generator words.
///
/// This is a measured stress sweep, not a scaling claim: it plants full-support
/// rotation-generator mappings at two deck sizes and budgets `1..=3`, recovers
/// exactly, and records the largest passing `(n, max_swaps)` pair.
///
/// # Errors
/// Returns [`SwapRecoveryError`] if a positive stress case cannot be generated or
/// if recovery itself returns an unexpected plumbing error.
pub fn gak_swap_reach_stress_self_test(
    config: GakSwapReachStressConfig,
) -> Result<GakSwapReachStressReport, SwapRecoveryError> {
    let mut cases = Vec::new();
    for n in [11usize, 17usize] {
        for max_swaps in 1..=3 {
            cases.push(run_stress_case(n, max_swaps, config)?);
        }
    }
    let measured_boundary = cases
        .iter()
        .filter(|case| case.exact_recovery && case.matched_null_outcome.is_clean_failure())
        .map(|case| (case.n, case.max_swaps))
        .max();
    Ok(GakSwapReachStressReport {
        cases,
        measured_boundary,
    })
}

fn run_stress_case(
    n: usize,
    max_swaps: usize,
    config: GakSwapReachStressConfig,
) -> Result<GakSwapReachStressCase, SwapRecoveryError> {
    let alphabet = stress_alphabet(max_swaps.saturating_add(2));
    let spec =
        LymmDeckSpec::from_base(n, &alphabet, &lymm_default_ct_alphabet(n), (0..n).collect())?;
    let generator_set = rotation_generator_set(n, &[1, 2, 3])?;
    let planted = planted_rotation_mapping(&spec);
    let pairs = stress_pairs(&spec, &planted)?;
    let mut recovery_config = SwapRecoveryConfig::with_max_swaps(max_swaps)
        .with_generator_set(RecoveryGeneratorSet::Explicit(generator_set));
    recovery_config.max_nodes = config.max_nodes;
    let report = recover_known_plaintext_swaps(&spec, &pairs, recovery_config)?;
    let exact_recovery = report.round_trip.exact()
        && report
            .letters
            .iter()
            .filter(|letter| letter.occurrences > 0)
            .all(|letter| {
                letter.verdict == LetterRecoveryVerdict::RecoveredUnique
                    && letter.permutation.as_ref() == planted.get(&letter.letter)
            });

    let bad_generator_set = rotation_generator_set(n, &[1])?;
    let mut null_config = SwapRecoveryConfig::with_max_swaps(max_swaps)
        .with_generator_set(RecoveryGeneratorSet::Explicit(bad_generator_set));
    null_config.max_nodes = config.max_nodes;
    let (matched_null_outcome, matched_null_nodes) =
        classify_null_recovery(recover_known_plaintext_swaps(&spec, &pairs, null_config));

    Ok(GakSwapReachStressCase {
        n,
        max_swaps,
        exact_recovery,
        matched_null_outcome,
        matched_null_nodes,
        observed_letters: alphabet.chars().count(),
        enumerated_candidates: report.stats.enumerated_candidates,
        nodes: report.stats.nodes,
    })
}

fn stress_alphabet(len: usize) -> String {
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().take(len).collect()
}

fn rotation_generator_set(
    n: usize,
    shifts: &[usize],
) -> Result<LymmGeneratorSet, SwapRecoveryError> {
    LymmGeneratorSet::from_permutations(
        n,
        shifts
            .iter()
            .map(|&shift| rotation(n, shift))
            .collect::<Vec<_>>(),
    )
    .map_err(Into::into)
}

fn planted_rotation_mapping(spec: &LymmDeckSpec) -> BTreeMap<char, Vec<usize>> {
    spec.pt_alphabet
        .iter()
        .enumerate()
        .map(|(index, &letter)| (letter, rotation(spec.n, index.saturating_add(1))))
        .collect()
}

fn stress_pairs(
    spec: &LymmDeckSpec,
    mapping: &BTreeMap<char, Vec<usize>>,
) -> Result<Vec<KnownPlaintextPair>, SwapRecoveryError> {
    let letters = spec.pt_alphabet.iter().collect::<String>();
    let mut pairs = Vec::new();
    for offset in 0..spec.pt_alphabet.len() {
        let plaintext = letters
            .chars()
            .cycle()
            .skip(offset)
            .take(letters.len().saturating_mul(3))
            .collect::<String>();
        pairs.push(KnownPlaintextPair {
            label: format!("stress-{offset}"),
            ciphertext: encrypt_lymm_deck(spec, mapping, &plaintext)?,
            plaintext,
        });
    }
    Ok(pairs)
}

fn rotation(n: usize, shift: usize) -> Vec<usize> {
    (0..n).map(|index| (index + shift) % n).collect()
}

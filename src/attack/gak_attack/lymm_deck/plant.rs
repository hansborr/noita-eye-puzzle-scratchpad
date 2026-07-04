//! Seeded planted mappings for Lymm's top-swap deck family.
//!
//! The rejection-sampling invariant matches Lymm's Python reference generator
//! (`research/data/practice-puzzles/deck-swap/noita_test_cipher.py`,
//! `generate_random_pt_mapping`): each plaintext letter is sampled until
//! `perm[0]` is nonzero and no earlier plaintext letter used that target.

use std::collections::{BTreeMap, BTreeSet};

use crate::nulls::null::{SplitMix64, random_index_below};

use super::{LymmDeckError, LymmDeckSpec};

const MAX_PLANT_ATTEMPTS: usize = 1_000;

/// A planted per-letter mapping and the top-swap words used to produce it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlantedLymmMapping {
    /// Per-plaintext-letter deck permutations.
    pub pt_mapping: BTreeMap<char, Vec<usize>>,
    /// The sampled top-swap indices for each plaintext letter.
    pub pt_swaps: BTreeMap<char, Vec<usize>>,
}

/// Generates Lymm-style planted plaintext mappings from `spec.base`.
///
/// For each plaintext letter, this applies exactly `num_swaps` sampled top-card
/// transpositions `(0 k)` to the shared base permutation, rejecting samples whose
/// resulting top-card image is zero or duplicates an earlier letter. The random
/// stream is the in-crate [`SplitMix64`] sampler, not Python's or crates.io's RNG.
///
/// # Errors
/// Returns [`LymmDeckError`] if the alphabet is too large, a random draw is
/// invalid, or Lymm's 1000-attempt retry cap is exceeded for a letter.
pub fn generate_random_pt_mapping(
    spec: &LymmDeckSpec,
    num_swaps: usize,
    seed: u64,
) -> Result<PlantedLymmMapping, LymmDeckError> {
    if spec.pt_alphabet.len() > spec.n.saturating_sub(1) {
        return Err(LymmDeckError::TooManyPlaintextLetters {
            requested: spec.pt_alphabet.len(),
            available: spec.n.saturating_sub(1),
        });
    }

    let mut rng = SplitMix64::new(seed);
    let mut pt_mapping = BTreeMap::new();
    let mut pt_swaps = BTreeMap::new();
    let mut used = BTreeSet::new();
    for &letter in &spec.pt_alphabet {
        let mut attempts = 0usize;
        loop {
            attempts += 1;
            let mut perm = spec.base.clone();
            let mut swaps = Vec::with_capacity(num_swaps);
            for _ in 0..num_swaps {
                let swap_index = random_index_below(spec.n, &mut rng)?;
                perm.swap(0, swap_index);
                swaps.push(swap_index);
            }
            let target = perm.first().copied().unwrap_or(0);
            if target != 0 && used.insert(target) {
                let _old_perm = pt_mapping.insert(letter, perm);
                let _old_swaps = pt_swaps.insert(letter, swaps);
                break;
            }
            if attempts > MAX_PLANT_ATTEMPTS {
                return Err(LymmDeckError::PlantAttemptsExceeded { letter, attempts });
            }
        }
    }
    Ok(PlantedLymmMapping {
        pt_mapping,
        pt_swaps,
    })
}

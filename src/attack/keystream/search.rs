use crate::attack::quadgram::QuadgramModel;
use crate::nulls::null::{SplitMix64, fisher_yates, mix_seed};

use super::KeystreamSearchConfig;
use super::cipher::{KeystreamFamily, decrypt_into};

/// Deterministic tag mixed into the random-key null-stream seed so the random-key
/// null is decorrelated from the search stream while staying reproducible.
const NULL_SEED_TAG: u64 = 0x006e_756c_6c6b_7300;

/// Deterministic tag mixed into the matched-null shuffle/search seeds so the
/// matched null is decorrelated from both the search and the random-key null
/// streams while staying reproducible (the `SplitMix64` golden-ratio constant).
const MATCHED_NULL_SEED_TAG: u64 = 0x9e37_79b9_7f4a_7c15;

/// Draws a fresh random key of `len` residues `< n` from `rng`
/// (caller ensures `n >= 1`).
fn random_key(len: usize, n: usize, rng: &mut SplitMix64) -> Vec<u8> {
    (0..len)
        .map(|_position| (rng.next_u64() % n as u64) as u8)
        .collect()
}

/// Linear annealing temperature: `start` at iteration `0`, falling to `0` at the
/// final iteration. A non-positive `start` is a pure hill-climb.
fn temperature_at(start: f64, iteration: usize, iterations: usize) -> f64 {
    if start <= 0.0 {
        return 0.0;
    }
    if iterations <= 1 {
        return start;
    }
    let progress = iteration as f64 / (iterations - 1) as f64;
    (start * (1.0 - progress)).max(0.0)
}

/// Metropolis acceptance (mirrors [`crate::attack::solve`]): always accept a
/// non-worsening move; accept a worsening move of size `delta < 0` with
/// probability `exp(delta / temperature)`; at `temperature <= 0` reject it.
fn accept(delta: f64, temperature: f64, rng: &mut SplitMix64) -> bool {
    if delta >= 0.0 {
        return true;
    }
    if temperature <= 0.0 {
        return false;
    }
    let uniform = (rng.next_u64() >> 11) as f64 / ((1u64 << 53) as f64);
    (delta / temperature).exp() > uniform
}

/// Runs the annealed multi-restart key search, returning the global best
/// `(key, score)`. Caller ensures `l >= 1` and `n >= 1`. Deterministic in
/// `cfg.seed` (a fresh [`SplitMix64`] is seeded from it here).
pub(super) fn search(
    ciphertext: &[u8],
    family: KeystreamFamily,
    l: usize,
    n: usize,
    cfg: &KeystreamSearchConfig,
    model: &QuadgramModel,
) -> (Vec<u8>, f64) {
    let restarts = cfg.restarts.max(1);
    let mut rng = SplitMix64::new(cfg.seed);
    let mut buffer: Vec<usize> = Vec::with_capacity(ciphertext.len());
    let mut best_key: Vec<u8> = Vec::new();
    let mut best_score = f64::NEG_INFINITY;
    for _restart in 0..restarts {
        let mut key = random_key(l, n, &mut rng);
        decrypt_into(family, ciphertext, &key, n, &mut buffer);
        let mut current = model.score_indices(&buffer);
        if current > best_score {
            best_score = current;
            best_key.clone_from(&key);
        }
        for iteration in 0..cfg.iterations {
            let temperature = temperature_at(cfg.anneal_temp, iteration, cfg.iterations);
            let position = (rng.next_u64() % l as u64) as usize;
            let new_value = (rng.next_u64() % n as u64) as u8;
            let old_value = key.get(position).copied().unwrap_or(0);
            if let Some(slot) = key.get_mut(position) {
                *slot = new_value;
            }
            decrypt_into(family, ciphertext, &key, n, &mut buffer);
            let proposed = model.score_indices(&buffer);
            let delta = proposed - current;
            if accept(delta, temperature, &mut rng) {
                current = proposed;
                if current > best_score {
                    best_score = current;
                    best_key.clone_from(&key);
                }
            } else if let Some(slot) = key.get_mut(position) {
                *slot = old_value;
            }
        }
    }
    (best_key, best_score)
}

/// Builds the random-key null `(mean, std)` for a `(family, key length)`.
/// Caller ensures `l >= 1` and `n >= 1`.
pub(super) fn random_key_null(
    ciphertext: &[u8],
    family: KeystreamFamily,
    l: usize,
    n: usize,
    cfg: &KeystreamSearchConfig,
    model: &QuadgramModel,
    buffer: &mut Vec<usize>,
) -> (f64, f64) {
    if cfg.null_trials == 0 {
        return (0.0, 0.0);
    }
    let seed = mix_seed(cfg.seed, NULL_SEED_TAG ^ family_tag(family) ^ l as u64);
    let mut rng = SplitMix64::new(seed);
    let mut scores: Vec<f64> = Vec::with_capacity(cfg.null_trials);
    for _trial in 0..cfg.null_trials {
        let key = random_key(l, n, &mut rng);
        decrypt_into(family, ciphertext, &key, n, buffer);
        scores.push(model.score_indices(buffer));
    }
    mean_std(&scores)
}

/// Builds the matched null `(full_mean, full_std, heldout_mean)` for a `(family,
/// key length)`: the honest survival bar.
///
/// For each of `cfg.matched_null_trials` trials this Fisher-Yates **shuffles** a
/// copy of the ciphertext (preserving the exact letter multiset, so unigram
/// frequency is held fixed and only higher-order structure is destroyed) and
/// reruns the IDENTICAL annealed search (same `family`, `key_len`, `restarts`,
/// `iterations`, `anneal_temp`) on it, recording the search's best score AND the
/// odd-index held-out fold score of that best decrypt. The full mean/std capture
/// the search's own optimization power on structureless text (which the random-key
/// null cannot, since it never optimizes); the held-out mean is the apples-to-apples
/// baseline for the generalization gate (fold-vs-fold, never fold-vs-full-stream).
/// This calls the bare [`search`], never the gated [`crack`](super::crack), so the trials do not
/// recurse into matched-null computation. Caller ensures `l >= 1` and `n >= 1`;
/// returns `(0.0, 0.0, 0.0)` when `cfg.matched_null_trials == 0`.
pub(super) fn matched_null(
    ciphertext: &[u8],
    family: KeystreamFamily,
    l: usize,
    n: usize,
    cfg: &KeystreamSearchConfig,
    model: &QuadgramModel,
) -> (f64, f64, f64) {
    if cfg.matched_null_trials == 0 {
        return (0.0, 0.0, 0.0);
    }
    // Per-trial (full-stream best score, held-out odd-index fold score) pairs,
    // aggregated by the shared [`crate::nulls::heldout::matched_null_stats`].
    let mut trials: Vec<(f64, f64)> = Vec::with_capacity(cfg.matched_null_trials);
    let mut buffer: Vec<usize> = Vec::with_capacity(ciphertext.len());
    for trial in 0..cfg.matched_null_trials {
        // Per-trial shuffle seed (golden-ratio tag + family + key length + trial),
        // so each trial draws a distinct, reproducible permutation.
        let shuffle_seed =
            cfg.seed ^ MATCHED_NULL_SEED_TAG ^ family_tag(family) ^ (l as u64) ^ (trial as u64);
        let mut rng = SplitMix64::new(shuffle_seed);
        let mut shuffled = ciphertext.to_vec();
        if fisher_yates(&mut shuffled, &mut rng).is_err() {
            // Unreachable for an in-bounds slice on a 64-bit target; skip the
            // trial rather than panic (a dropped trial only shrinks the sample).
            continue;
        }
        // Per-trial search seed on a stream decorrelated from the shuffle stream,
        // distinct per trial so the matched null is not a single repeated search.
        let search_seed = mix_seed(
            cfg.seed,
            MATCHED_NULL_SEED_TAG
                ^ family_tag(family)
                ^ ((l as u64) << 16)
                ^ ((trial as u64) << 32),
        );
        let trial_cfg = KeystreamSearchConfig {
            seed: search_seed,
            ..*cfg
        };
        let (key, best) = search(&shuffled, family, l, n, &trial_cfg, model);
        // The held-out fold of THIS trial's best decrypt, computed with the same
        // odd-index fold the candidate uses (re-decrypt to recover the stream the
        // `best` score was taken on; `best` equals its full-stream score).
        decrypt_into(family, &shuffled, &key, n, &mut buffer);
        let heldout_score = model.score_indices(&crate::nulls::heldout::odd_index_fold(&buffer));
        trials.push((best, heldout_score));
    }
    let stats = crate::nulls::heldout::matched_null_stats(&trials);
    (stats.full_mean, stats.full_std, stats.heldout_mean)
}

/// Population mean and standard deviation (`(0.0, 0.0)` for an empty slice).
fn mean_std(samples: &[f64]) -> (f64, f64) {
    if samples.is_empty() {
        return (0.0, 0.0);
    }
    let count = samples.len() as f64;
    let mean = samples.iter().sum::<f64>() / count;
    let variance = samples
        .iter()
        .map(|value| {
            let delta = value - mean;
            delta * delta
        })
        .sum::<f64>()
        / count;
    (mean, variance.sqrt())
}

/// A stable per-family tag, decorrelating the per-family null streams.
const fn family_tag(family: KeystreamFamily) -> u64 {
    match family {
        KeystreamFamily::Vigenere => 0x5601,
        KeystreamFamily::Beaufort => 0xbe02,
        KeystreamFamily::PlaintextAutokey => 0xab03,
        KeystreamFamily::CiphertextAutokey => 0xac04,
    }
}

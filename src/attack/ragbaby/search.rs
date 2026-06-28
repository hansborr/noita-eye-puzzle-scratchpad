use crate::attack::quadgram::QuadgramModel;
use crate::nulls::null::{SplitMix64, fisher_yates};

use super::cipher::decrypt_into;
use super::{
    DEFAULT_BASIN_HOPS, DEFAULT_ITERATIONS, DEFAULT_MATCHED_NULL_TRIALS, DEFAULT_NULL_TRIALS,
    DEFAULT_RESTARTS, DEFAULT_SEED, DEFAULT_T0, DEFAULT_T1,
};

// ===========================================================================
// Simulated-annealing keyed-alphabet optimizer
// ===========================================================================

/// Configuration for the annealed multi-restart keyed-alphabet search and its two
/// nulls.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RagbabySearchConfig {
    /// Number of random restarts (each seeds a fresh random keyed alphabet).
    pub restarts: usize,
    /// Simulated-annealing iterations per restart's main anneal.
    pub iterations: usize,
    /// Basin-hopping perturbation rounds per restart (each re-anneals `iters/4`).
    pub basin_hops: usize,
    /// Annealing start temperature (nat scale).
    pub t0: f64,
    /// Annealing end temperature (nat scale).
    pub t1: f64,
    /// Deterministic PRNG seed for the search and both nulls.
    pub seed: u64,
    /// Random-keyed-alphabet null trials for the reported diagnostic.
    pub null_trials: usize,
    /// Matched-null trials (reruns of the full search on shuffled ciphertext) —
    /// the survival gate; `0` disables survival.
    pub matched_null_trials: usize,
}

impl Default for RagbabySearchConfig {
    fn default() -> Self {
        Self {
            restarts: DEFAULT_RESTARTS,
            iterations: DEFAULT_ITERATIONS,
            basin_hops: DEFAULT_BASIN_HOPS,
            t0: DEFAULT_T0,
            t1: DEFAULT_T1,
            seed: DEFAULT_SEED,
            null_trials: DEFAULT_NULL_TRIALS,
            matched_null_trials: DEFAULT_MATCHED_NULL_TRIALS,
        }
    }
}

/// A geometric annealing schedule `T = t0 * (t1 / t0)^(it / iters)`.
#[derive(Clone, Copy, Debug)]
struct AnnealSchedule {
    iters: usize,
    t0: f64,
    t1: f64,
}

impl AnnealSchedule {
    /// Temperature at iteration `it` (returns `t0` when `iters == 0`).
    fn temperature(&self, it: usize) -> f64 {
        if self.iters == 0 || self.t0 <= 0.0 {
            return self.t0.max(0.0);
        }
        let fraction = it as f64 / self.iters as f64;
        self.t0 * (self.t1 / self.t0).powf(fraction)
    }
}

/// A `[0, 1)` uniform draw from the high 53 bits of a `SplitMix64` output (mirrors
/// [`crate::attack::keystream`]'s Metropolis sampler).
fn uniform01(rng: &mut SplitMix64) -> f64 {
    (rng.next_u64() >> 11) as f64 / ((1u64 << 53) as f64)
}

/// Metropolis acceptance: always accept a non-worsening move; accept a worsening
/// move of size `delta < 0` with probability `exp(delta / temperature)`; reject it
/// at `temperature <= 0`.
fn accept(delta: f64, temperature: f64, rng: &mut SplitMix64) -> bool {
    if delta >= 0.0 {
        return true;
    }
    if temperature <= 0.0 {
        return false;
    }
    (delta / temperature).exp() > uniform01(rng)
}

/// Applies one in-place perturbation to `key`. `kind in {0, 1, 2}` is a
/// transposition swap, `3` is a slide (remove at `i`, reinsert at `j`), and any
/// other value is a segment reversal. Indices are drawn `< base == key.len()`, so
/// the `swap`/`remove`/`insert`/`get_mut` calls are always in bounds.
fn apply_move(key: &mut Vec<usize>, kind: u64, base: usize, rng: &mut SplitMix64) {
    if base == 0 {
        return;
    }
    let first = (rng.next_u64() % base as u64) as usize;
    let second = (rng.next_u64() % base as u64) as usize;
    match kind {
        0..=2 => key.swap(first, second),
        3 => {
            let value = key.remove(first);
            key.insert(second, value);
        }
        _ => {
            let (low, high) = if first <= second {
                (first, second)
            } else {
                (second, first)
            };
            if let Some(segment) = key.get_mut(low..=high) {
                segment.reverse();
            }
        }
    }
}

/// Returns a random keyed alphabet: a uniformly shuffled copy of `keep`.
pub(super) fn random_keyed_alphabet(keep: &[usize], rng: &mut SplitMix64) -> Vec<usize> {
    let mut key = keep.to_vec();
    // Unreachable for an in-bounds slice on a 64-bit target; an error only leaves
    // `key` unshuffled (a still-valid keyed alphabet), never panics.
    if fisher_yates(&mut key, rng).is_err() {
        return keep.to_vec();
    }
    key
}

/// The immutable problem data plus model reference for one `(base, sign)` anneal.
pub(super) struct RagbabySearch<'a> {
    pub(super) cipher: &'a [usize],
    pub(super) nums: &'a [usize],
    pub(super) base: usize,
    pub(super) sign: i64,
    pub(super) keep: &'a [usize],
    pub(super) model: &'a QuadgramModel,
}

impl RagbabySearch<'_> {
    /// Scores keyed alphabet `key` as the sum of quadgram log-probs of its
    /// decryption (the well-scaled SA objective), reusing `inv`/`out` buffers.
    fn score(&self, key: &[usize], inv: &mut [usize; 26], out: &mut Vec<usize>) -> f64 {
        decrypt_into(self.cipher, self.nums, key, self.sign, self.base, inv, out);
        self.model.score_indices_sum(out)
    }

    /// Anneals from `key`, returning the best keyed alphabet and its sum score.
    fn anneal(
        &self,
        key: &mut Vec<usize>,
        schedule: &AnnealSchedule,
        rng: &mut SplitMix64,
        inv: &mut [usize; 26],
        out: &mut Vec<usize>,
    ) -> (Vec<usize>, f64) {
        let mut current = self.score(key, inv, out);
        let mut best_key = key.clone();
        let mut best_score = current;
        for it in 0..schedule.iters {
            let temperature = schedule.temperature(it);
            let mut candidate = key.clone();
            apply_move(&mut candidate, rng.next_u64() % 5, self.base, rng);
            let proposed = self.score(&candidate, inv, out);
            if accept(proposed - current, temperature, rng) {
                *key = candidate;
                current = proposed;
                if proposed > best_score {
                    best_score = proposed;
                    best_key.clone_from(key);
                }
            }
        }
        (best_key, best_score)
    }

    /// Runs the multi-restart anneal with basin-hopping, returning the global best
    /// keyed alphabet and its sum score. Deterministic in the `rng` stream.
    fn run(&self, cfg: &RagbabySearchConfig, rng: &mut SplitMix64) -> (Vec<usize>, f64) {
        let mut inv = [0usize; 26];
        let mut out: Vec<usize> = Vec::with_capacity(self.cipher.len());
        let main = AnnealSchedule {
            iters: cfg.iterations,
            t0: cfg.t0,
            t1: cfg.t1,
        };
        let basin = AnnealSchedule {
            iters: cfg.iterations / 4,
            t0: cfg.t0 * 0.4,
            t1: cfg.t1,
        };
        let mut best_key: Vec<usize> = Vec::new();
        let mut best_score = f64::NEG_INFINITY;
        for _restart in 0..cfg.restarts.max(1) {
            let mut key = random_keyed_alphabet(self.keep, rng);
            let (mut local_key, mut local_score) =
                self.anneal(&mut key, &main, rng, &mut inv, &mut out);
            for _hop in 0..cfg.basin_hops {
                let mut perturbed = local_key.clone();
                let kicks = 2 + (rng.next_u64() % 4) as usize; // 2..=5 random swaps
                for _kick in 0..kicks {
                    apply_move(&mut perturbed, 0, self.base, rng);
                }
                let (hop_key, hop_score) =
                    self.anneal(&mut perturbed, &basin, rng, &mut inv, &mut out);
                if hop_score > local_score {
                    local_key = hop_key;
                    local_score = hop_score;
                }
            }
            if local_score > best_score {
                best_score = local_score;
                best_key = local_key;
            }
        }
        (best_key, best_score)
    }

    /// Decrypts under `key` into a fresh plaintext letter-index vector.
    pub(super) fn decrypt(&self, key: &[usize]) -> Vec<usize> {
        let mut inv = [0usize; 26];
        let mut out = Vec::with_capacity(self.cipher.len());
        decrypt_into(
            self.cipher,
            self.nums,
            key,
            self.sign,
            self.base,
            &mut inv,
            &mut out,
        );
        out
    }
}

/// Runs the anneal once from a fresh `SplitMix64` seeded by `cfg.seed` (mirrors
/// [`crate::attack::keystream`]'s `search`).
pub(super) fn search(ctx: &RagbabySearch, cfg: &RagbabySearchConfig) -> (Vec<usize>, f64) {
    let mut rng = SplitMix64::new(cfg.seed);
    ctx.run(cfg, &mut rng)
}

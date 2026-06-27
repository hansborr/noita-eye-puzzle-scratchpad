//! Polyalphabetic keystream cracker for the practice letter-puzzles.
//!
//! This module implements four keystream cipher families over `&[u8]` letter
//! indices (alphabet size `N`, default 26) and an annealed multi-restart key
//! search that maximizes the [`crate::attack::quadgram`] English model score of the
//! decryption. It is the letter-puzzle analogue of [`crate::attack::solve`]: it searches
//! and scores hypotheses, gates them against a matched null and a held-out fold,
//! and reports an explicit **honest negative** when nothing survives — which is
//! the expected outcome on the genuinely non-periodic-polyalphabetic practice
//! puzzles.
//!
//! # Cipher families
//!
//! Subtraction is computed as `(a + N - (b % N)) % N` to avoid `usize`
//! underflow. The primer/key is a `&[u8]` of length `L`, each value `< N`.
//!
//! - [`KeystreamFamily::Vigenere`]: `c_i = (p_i + k_{i mod L}) mod N`.
//! - [`KeystreamFamily::Beaufort`] (an involution): `c_i = (k_{i mod L} - p_i) mod N`.
//! - [`KeystreamFamily::PlaintextAutokey`]: keystream is `primer ++ plaintext`;
//!   `k_i = primer_i` for `i < L`, else `p_{i-L}`. Decryption is causal,
//!   recovering `p_{i-L}` left-to-right.
//! - [`KeystreamFamily::CiphertextAutokey`]: keystream is `primer ++ ciphertext`;
//!   `k_i = primer_i` for `i < L`, else `c_{i-L}`.
//!
//! # Survival gates: two complementary nulls
//!
//! Survival requires clearing **two** nulls, each policing a distinct failure
//! mode, plus a round-trip sanity check and a held-out fold.
//!
//! 1. **Matched null** (the gate this module's bug fix adds, mirroring the
//!    defence [`crate::attack::solve`] uses): rerun the IDENTICAL annealed search (same
//!    family, key length, restarts, iterations, temperature) on Fisher-Yates
//!    **shuffled** copies of the ciphertext. The shuffle preserves the exact
//!    letter multiset (unigram frequency held fixed) and destroys only
//!    higher-order structure, so the matched null measures *what the search
//!    itself extracts from noise*. The annealed key search has `L` free
//!    parameters and overfits short ciphertext: a weaker random-key null (which
//!    never pays for the search's optimization power) green-lights pure noise at
//!    high `L`; the matched null does not. A true cipher of real English decrypts
//!    to roughly `-10` nats while the matched null on shuffled ciphertext overfits
//!    only to roughly `-12`, so the true positive clears it but overfitting cannot.
//!
//! 2. **Random-key null** (retained, not demoted): score decryptions under random
//!    *keys* of the un-shuffled ciphertext. This is the only null that polices the
//!    [`KeystreamFamily::CiphertextAutokey`] **key-independence leak**
//!    (`p_i = c_i - c_{i-L}` for `i >= L`): on a long plaintext that decrypt is
//!    English *regardless of the key*, so a random key reads as English too and
//!    `best_score` cannot clear it. The matched null shuffles the ciphertext,
//!    which DESTROYS that leak, so it would (wrongly) promote ct-autokey on its
//!    own — only the random-key null keeps that honest.
//!
//! A candidate survives only when, against the matched null it clears the z-score
//! floor ([`Z_THRESHOLD`]) and the absolute nat floor ([`MIN_NAT_MARGIN`],
//! guarding tiny-`std` degeneracy) ([`beats_matched_null`]), against the
//! random-key null it clears the same pair ([`beats_null`]), AND a held-out fold
//! reads above the matched-null mean. Neither null alone is sufficient: the
//! matched null catches search overfitting, the random-key null catches the
//! key-independence leak.
//!
//! [`crate::attack::solve`] gates with `SEARCH_BEATS_NULL_MARGIN = 0.15` on the *bigram*
//! mean-log scale; that margin is far too lenient on the *quadgram* scale here
//! (English and random-key decryptions differ by roughly four nats), which is why
//! this module uses the z-score plus nat-floor pair above.
//!
//! [`beats_matched_null`]: KeystreamCandidate::beats_matched_null
//! [`beats_null`]: KeystreamCandidate::beats_null

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use crate::attack::quadgram::{QuadgramError, QuadgramModel};
use crate::nulls::null::{SplitMix64, fisher_yates, mix_seed};

/// Minimum z-score (best score above a null mean, in null standard deviations)
/// required to clear a null gate.
///
/// Applied to the matched null for [`KeystreamCandidate::beats_matched_null`] (the
/// survival gate) and to the random-key null for the
/// [`beats_null`](KeystreamCandidate::beats_null) diagnostic. Calibrated for the
/// quadgram mean-log scale, replacing [`crate::attack::solve::SEARCH_BEATS_NULL_MARGIN`]
/// (a bigram-scale bare margin that is far too lenient here).
pub const Z_THRESHOLD: f64 = 6.0;

/// Minimum absolute nat margin (`best_score - null_mean`) required to clear a null
/// gate, guarding the degenerate tiny-`std` case where a z-score alone would
/// explode. Applied to both [`KeystreamCandidate::beats_matched_null`] (survival)
/// and [`beats_null`](KeystreamCandidate::beats_null) (diagnostic).
pub const MIN_NAT_MARGIN: f64 = 1.0;

/// Default alphabet size used by [`KeystreamSearchConfig::default`].
pub const DEFAULT_ALPHABET_SIZE: usize = 26;

/// Default multi-restart count used by [`KeystreamSearchConfig::default`].
pub const DEFAULT_RESTARTS: usize = 12;

/// Default annealing iterations per restart used by
/// [`KeystreamSearchConfig::default`].
pub const DEFAULT_ITERATIONS: usize = 8_000;

/// Default annealing start temperature used by
/// [`KeystreamSearchConfig::default`].
pub const DEFAULT_ANNEAL_TEMP: f64 = 1.0;

/// Default deterministic seed used by [`KeystreamSearchConfig::default`].
pub const DEFAULT_SEED: u64 = 0x6b65_7973_7472_6d00;

/// Default random-key null-trial count used by
/// [`KeystreamSearchConfig::default`].
pub const DEFAULT_NULL_TRIALS: usize = 64;

/// Default matched-null trial count used by [`KeystreamSearchConfig::default`].
///
/// Mirrors [`crate::attack::solve::DEFAULT_NULL_TRIALS`]: each trial reruns the FULL
/// annealed search on a shuffled copy of the ciphertext, so this is the dominant
/// cost knob — keep it modest.
pub const DEFAULT_MATCHED_NULL_TRIALS: usize = 16;

/// Deterministic tag mixed into the random-key null-stream seed so the random-key
/// null is decorrelated from the search stream while staying reproducible.
const NULL_SEED_TAG: u64 = 0x006e_756c_6c6b_7300;

/// Deterministic tag mixed into the matched-null shuffle/search seeds so the
/// matched null is decorrelated from both the search and the random-key null
/// streams while staying reproducible (the `SplitMix64` golden-ratio constant).
const MATCHED_NULL_SEED_TAG: u64 = 0x9e37_79b9_7f4a_7c15;

/// Adds two reduced residues modulo `n` (caller ensures `n >= 1`).
const fn add_mod(a: usize, b: usize, n: usize) -> usize {
    (a + b) % n
}

/// Subtracts `b` from `a` modulo `n` without `usize` underflow
/// (caller ensures `n >= 1`).
const fn sub_mod(a: usize, b: usize, n: usize) -> usize {
    (a + n - (b % n)) % n
}

/// Reads `slice[idx]` as a residue modulo `n`, or `0` if out of range
/// (caller ensures `n >= 1`).
fn byte_at(slice: &[u8], idx: usize, n: usize) -> usize {
    usize::from(slice.get(idx).copied().unwrap_or(0)) % n
}

/// The keystream cipher families this module can encrypt, decrypt, and crack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeystreamFamily {
    /// Periodic additive keystream (`c_i = p_i + k_{i mod L}`).
    Vigenere,
    /// Periodic subtractive involution (`c_i = k_{i mod L} - p_i`).
    Beaufort,
    /// Autokey whose keystream is `primer ++ plaintext`.
    PlaintextAutokey,
    /// Autokey whose keystream is `primer ++ ciphertext`.
    CiphertextAutokey,
}

impl KeystreamFamily {
    /// All four families, in a stable order (the CLI default set).
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [
            Self::Vigenere,
            Self::Beaufort,
            Self::PlaintextAutokey,
            Self::CiphertextAutokey,
        ]
    }

    /// Stable lowercase name (used in tables and candidate-record filenames).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Vigenere => "vigenere",
            Self::Beaufort => "beaufort",
            Self::PlaintextAutokey => "autokey-pt",
            Self::CiphertextAutokey => "autokey-ct",
        }
    }
}

impl fmt::Display for KeystreamFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Combines a plaintext residue and keystream residue into a ciphertext residue
/// for `family` (caller ensures `n >= 1`).
fn encrypt_combine(family: KeystreamFamily, p: usize, k: usize, n: usize) -> usize {
    match family {
        KeystreamFamily::Beaufort => sub_mod(k, p, n),
        _ => add_mod(p, k, n),
    }
}

/// Combines a ciphertext residue and keystream residue into a plaintext residue
/// for `family` (caller ensures `n >= 1`).
fn decrypt_combine(family: KeystreamFamily, c: usize, k: usize, n: usize) -> usize {
    match family {
        KeystreamFamily::Beaufort => sub_mod(k, c, n),
        _ => sub_mod(c, k, n),
    }
}

/// The keystream residue at position `i` during encryption (caller ensures
/// `l >= 1` and `n >= 1`). Autokey families read the already-built prefix.
fn encrypt_key_value(
    family: KeystreamFamily,
    i: usize,
    l: usize,
    key: &[u8],
    plaintext: &[u8],
    cipher_so_far: &[u8],
    n: usize,
) -> usize {
    match family {
        KeystreamFamily::Vigenere | KeystreamFamily::Beaufort => byte_at(key, i % l, n),
        KeystreamFamily::PlaintextAutokey => {
            if i < l {
                byte_at(key, i, n)
            } else {
                byte_at(plaintext, i - l, n)
            }
        }
        KeystreamFamily::CiphertextAutokey => {
            if i < l {
                byte_at(key, i, n)
            } else {
                byte_at(cipher_so_far, i - l, n)
            }
        }
    }
}

/// The keystream residue at position `i` during decryption (caller ensures
/// `l >= 1` and `n >= 1`). Plaintext-autokey reads the already-recovered prefix.
fn decrypt_key_value(
    family: KeystreamFamily,
    i: usize,
    l: usize,
    key: &[u8],
    recovered: &[usize],
    ciphertext: &[u8],
    n: usize,
) -> usize {
    match family {
        KeystreamFamily::Vigenere | KeystreamFamily::Beaufort => byte_at(key, i % l, n),
        KeystreamFamily::PlaintextAutokey => {
            if i < l {
                byte_at(key, i, n)
            } else {
                recovered.get(i - l).copied().unwrap_or(0)
            }
        }
        KeystreamFamily::CiphertextAutokey => {
            if i < l {
                byte_at(key, i, n)
            } else {
                byte_at(ciphertext, i - l, n)
            }
        }
    }
}

/// Encrypts `plaintext` (letter indices `< N`) under `key` for `family`.
///
/// An empty `key` is treated as a no-op (the plaintext is returned reduced
/// modulo `N`), so a degenerate call never panics. `alphabet_size` is clamped to
/// at least `1`.
#[must_use]
pub fn encrypt(
    family: KeystreamFamily,
    plaintext: &[u8],
    key: &[u8],
    alphabet_size: usize,
) -> Vec<u8> {
    let n = alphabet_size.max(1);
    let l = key.len();
    let mut out: Vec<u8> = Vec::with_capacity(plaintext.len());
    if l == 0 {
        out.extend(plaintext.iter().map(|&p| (usize::from(p) % n) as u8));
        return out;
    }
    for i in 0..plaintext.len() {
        let p = byte_at(plaintext, i, n);
        let k = encrypt_key_value(family, i, l, key, plaintext, &out, n);
        out.push(encrypt_combine(family, p, k, n) as u8);
    }
    out
}

/// Decrypts `ciphertext` (letter indices `< N`) under `key` for `family`,
/// writing recovered residues into `out` (reused to avoid per-call allocation in
/// the search hot loop). Caller ensures `n >= 1`.
fn decrypt_into(
    family: KeystreamFamily,
    ciphertext: &[u8],
    key: &[u8],
    n: usize,
    out: &mut Vec<usize>,
) {
    out.clear();
    let l = key.len();
    if l == 0 {
        out.extend(ciphertext.iter().map(|&c| usize::from(c) % n));
        return;
    }
    for i in 0..ciphertext.len() {
        let c = byte_at(ciphertext, i, n);
        let k = decrypt_key_value(family, i, l, key, out, ciphertext, n);
        out.push(decrypt_combine(family, c, k, n));
    }
}

/// Decrypts `ciphertext` under `key` for `family`, returning letter indices.
///
/// An empty `key` is a no-op (mirroring [`encrypt`]); `alphabet_size` is clamped
/// to at least `1`. For any key, `encrypt(decrypt(c, k), k) == c` is an algebraic
/// identity (the round-trip gate), so the discriminating signal lives in the
/// matched-null and held-out gates, not the round trip.
#[must_use]
pub fn decrypt(
    family: KeystreamFamily,
    ciphertext: &[u8],
    key: &[u8],
    alphabet_size: usize,
) -> Vec<u8> {
    let n = alphabet_size.max(1);
    let mut out: Vec<usize> = Vec::with_capacity(ciphertext.len());
    decrypt_into(family, ciphertext, key, n, &mut out);
    out.iter().map(|&v| v as u8).collect()
}

/// Configuration for the annealed multi-restart key search.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct KeystreamSearchConfig {
    /// Alphabet size `N` (clamped to at least `1`).
    pub alphabet_size: usize,
    /// Number of random restarts (each seeds a fresh random key).
    pub restarts: usize,
    /// Annealing iterations per restart.
    pub iterations: usize,
    /// Annealing start temperature; falls linearly to `0`. A value of `0`
    /// (or less) is a pure hill-climb (worsening moves always rejected).
    pub anneal_temp: f64,
    /// Deterministic PRNG seed for the entire search and both nulls.
    pub seed: u64,
    /// Number of random-key null trials used for the reported DIAGNOSTIC
    /// (`null_mean`/`null_std`/`z`/`beats_null`), no longer the survival gate.
    pub null_trials: usize,
    /// Number of matched-null trials: reruns of the FULL search on Fisher-Yates
    /// shuffled ciphertext. This is the survival gate
    /// ([`KeystreamCandidate::beats_matched_null`]); `0` disables it (the
    /// candidate can never survive).
    pub matched_null_trials: usize,
}

impl Default for KeystreamSearchConfig {
    fn default() -> Self {
        Self {
            alphabet_size: DEFAULT_ALPHABET_SIZE,
            restarts: DEFAULT_RESTARTS,
            iterations: DEFAULT_ITERATIONS,
            anneal_temp: DEFAULT_ANNEAL_TEMP,
            seed: DEFAULT_SEED,
            null_trials: DEFAULT_NULL_TRIALS,
            matched_null_trials: DEFAULT_MATCHED_NULL_TRIALS,
        }
    }
}

/// One scored, gated keystream hypothesis for a single `(family, key length)`.
///
/// A surviving candidate is a HYPOTHESIS, never a confirmed decode.
#[derive(Clone, Debug, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the gate verdicts (round-trip, beats-matched-null, beats-null diagnostic, held-out, survives) are kept as separate fields and never collapsed, mirroring solve.rs's never-collapse gate discipline"
)]
pub struct KeystreamCandidate {
    /// Cipher family searched.
    pub family: KeystreamFamily,
    /// Key (primer) length searched.
    pub key_len: usize,
    /// Best key recovered by the search.
    pub key: Vec<u8>,
    /// Best (highest) quadgram mean-log score found over all restarts.
    pub best_score: f64,
    /// Mean quadgram score of the random-key null (DIAGNOSTIC; not the gate).
    pub null_mean: f64,
    /// Standard deviation of the random-key null (DIAGNOSTIC).
    pub null_std: f64,
    /// `(best_score - null_mean) / null_std` (or `0` when `null_std == 0`);
    /// the random-key-null z-score (DIAGNOSTIC).
    pub z: f64,
    /// Mean best score of the matched null (the same search rerun on shuffled
    /// ciphertext). This is the honest "what the search extracts from noise"
    /// baseline and drives the survival gate.
    pub matched_mean: f64,
    /// Standard deviation of the matched-null best scores.
    pub matched_std: f64,
    /// `(best_score - matched_mean) / matched_std` (or `0` when
    /// `matched_std == 0`); the matched-null z-score.
    pub matched_z: f64,
    /// Whether `encrypt(decrypt(c, key), key) == c` (always true; a sanity gate).
    pub round_trip_ok: bool,
    /// Quadgram score of the odd-indexed held-out fold of the best decrypt.
    pub heldout_score: f64,
    /// Mean held-out (odd-index) fold score across the matched-null reruns — the
    /// apples-to-apples baseline the candidate's `heldout_score` must beat.
    /// Comparing `heldout_score` to the full-stream `matched_mean` instead (the old
    /// bug) falsely failed a true decode, since a fold of English is not contiguous
    /// English and so scores below the full stream while the null pays no such
    /// penalty. `0.0` when `matched_null_trials == 0`.
    pub matched_heldout_mean: f64,
    /// Survival gate (random-key null): whether the candidate clears
    /// [`Z_THRESHOLD`] and [`MIN_NAT_MARGIN`] against the random-key null. This is
    /// the only gate that polices the [`KeystreamFamily::CiphertextAutokey`]
    /// key-independence leak (the matched null shuffles the ciphertext and so
    /// cannot).
    pub beats_null: bool,
    /// Survival gate (matched null): whether the candidate clears [`Z_THRESHOLD`]
    /// and [`MIN_NAT_MARGIN`] against the MATCHED null (and
    /// `matched_null_trials > 0`). Polices search overfitting at high key length.
    pub beats_matched_null: bool,
    /// Whether `heldout_score > matched_heldout_mean` (the held-out fold reads above
    /// the matched null's held-out fold — apples-to-apples). `false` when
    /// `matched_null_trials == 0`.
    pub heldout_ok: bool,
    /// `round_trip_ok && beats_matched_null && beats_null && heldout_ok` — both
    /// nulls must be cleared (each polices a distinct failure mode).
    pub survives: bool,
    /// The best decryption (letter indices).
    pub decrypt: Vec<u8>,
}

impl KeystreamCandidate {
    /// Renders the best decryption as `A..` letters (`0 -> 'A'`); indices outside
    /// `0..26` render as `'?'`.
    #[must_use]
    pub fn render_plaintext(&self) -> String {
        self.decrypt
            .iter()
            .map(|&v| if v < 26 { (b'A' + v) as char } else { '?' })
            .collect()
    }
}

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
fn search(
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
fn random_key_null(
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
/// This calls the bare [`search`], never the gated [`crack`], so the trials do not
/// recurse into matched-null computation. Caller ensures `l >= 1` and `n >= 1`;
/// returns `(0.0, 0.0, 0.0)` when `cfg.matched_null_trials == 0`.
fn matched_null(
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

/// Cracks `ciphertext` for one `(family, key_len)` against a prebuilt quadgram
/// `model`, returning a fully-gated [`KeystreamCandidate`].
///
/// Reuse this entry point when cracking many `(family, key length)` pairs so the
/// (expensive) quadgram model is built once. Deterministic in `cfg.seed`.
#[must_use]
pub fn crack_with_model(
    ciphertext: &[u8],
    family: KeystreamFamily,
    key_len: usize,
    cfg: &KeystreamSearchConfig,
    model: &QuadgramModel,
) -> KeystreamCandidate {
    let n = cfg.alphabet_size.max(1);
    let l = key_len.max(1);
    let mut buffer: Vec<usize> = Vec::with_capacity(ciphertext.len());

    let (key, _search_best) = search(ciphertext, family, l, n, cfg, model);

    // Recompute the best decryption (the buffer was last used by the search) and
    // derive the score, decrypt, and held-out fold from it.
    decrypt_into(family, ciphertext, &key, n, &mut buffer);
    let best_score = model.score_indices(&buffer);
    let decrypt_indices: Vec<u8> = buffer.iter().map(|&v| v as u8).collect();
    let heldout_score = model.score_indices(&crate::nulls::heldout::odd_index_fold(&buffer));

    // Random-key null: a DIAGNOSTIC only (too weak to gate — it never pays for
    // the search's optimization power, so it green-lights overfitting at high L).
    let (null_mean, null_std) = random_key_null(ciphertext, family, l, n, cfg, model, &mut buffer);
    let margin = best_score - null_mean;
    let z = if null_std > 0.0 {
        margin / null_std
    } else {
        0.0
    };

    // Matched null: the survival bar (same search rerun on shuffled ciphertext).
    let (matched_mean, matched_std, matched_heldout_mean) =
        matched_null(ciphertext, family, l, n, cfg, model);
    let matched_margin = best_score - matched_mean;
    let matched_z = if matched_std > 0.0 {
        matched_margin / matched_std
    } else {
        0.0
    };

    let round_trip_ok = encrypt(family, &decrypt_indices, &key, n) == ciphertext;
    // Random-key null gate: the defense against the [`KeystreamFamily::CiphertextAutokey`]
    // KEY-INDEPENDENCE leak (`p_i = c_i - c_{i-L}` for `i >= L`). The matched null
    // shuffles the ciphertext, which DESTROYS that leak, so it cannot police it —
    // only the random-key null can (a random key reproduces the same key-independent
    // English tail, so `best_score` cannot clear it). For the keyed families a true
    // recovery clears this comfortably.
    let beats_null = z >= Z_THRESHOLD && margin >= MIN_NAT_MARGIN;
    // Matched-null gate: the defense against SEARCH OVERFITTING at high key length
    // (the false-positive bug this gate fixes). The annealed search's optimization
    // power inflates `best_score` on short ciphertext; the matched null pays for
    // exactly that power on the shuffled (structureless) multiset, so overfitting
    // cannot clear it. `matched_null_trials == 0` never silently passes.
    let beats_matched_null =
        cfg.matched_null_trials > 0 && matched_z >= Z_THRESHOLD && matched_margin >= MIN_NAT_MARGIN;
    // Held-out fold judged against the matched null's HELD-OUT fold (apples-to-apples).
    // Comparing to the full-stream `matched_mean` instead falsely failed a true decode,
    // since a fold of English is not contiguous English and so scores below the full
    // stream while the null pays no such penalty.
    let heldout_ok = cfg.matched_null_trials > 0 && heldout_score > matched_heldout_mean;
    // Survival requires clearing BOTH nulls: the matched null (overfitting) AND the
    // random-key null (the ct-autokey key-independence leak). A true keyed recovery
    // clears both; overfitting fails the matched null; the ct-autokey leak fails the
    // random-key null. Each null polices a distinct failure mode, so neither alone
    // is sufficient — the matched null is the NEW gate, not a replacement.
    let survives = round_trip_ok && beats_matched_null && beats_null && heldout_ok;

    KeystreamCandidate {
        family,
        key_len: l,
        key,
        best_score,
        null_mean,
        null_std,
        z,
        matched_mean,
        matched_std,
        matched_z,
        round_trip_ok,
        heldout_score,
        matched_heldout_mean,
        beats_null,
        beats_matched_null,
        heldout_ok,
        survives,
        decrypt: decrypt_indices,
    }
}

/// Cracks `ciphertext` for one `(family, key_len)`, building the English
/// quadgram model internally.
///
/// Prefer [`crack_with_model`] when cracking many pairs (build the model once).
///
/// # Errors
/// Returns [`QuadgramError`] if the bundled English quadgram model cannot be
/// built (it should not be in a correct build).
pub fn crack(
    ciphertext: &[u8],
    family: KeystreamFamily,
    key_len: usize,
    cfg: &KeystreamSearchConfig,
) -> Result<KeystreamCandidate, QuadgramError> {
    let model = QuadgramModel::english()?;
    Ok(crack_with_model(ciphertext, family, key_len, cfg, &model))
}

/// Normalizes a puzzle string to letter indices: ASCII letters are kept and
/// uppercased to `0..=25`; every other character (spaces, punctuation, the
/// `seven` puzzle's `#` markers, newlines) is dropped.
#[must_use]
pub fn normalize_puzzle(text: &str) -> Vec<u8> {
    text.chars()
        .filter(char::is_ascii_alphabetic)
        .map(|ch| ch.to_ascii_uppercase() as u8 - b'A')
        .collect()
}

/// The bundled practice letter-puzzles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PracticePuzzle {
    /// Practice puzzle `three`.
    Three,
    /// Practice puzzle `four`.
    Four,
    /// Practice puzzle `five` (has the gap-40 `UXECHTINIT` 10-gram repeat).
    Five,
    /// Practice puzzle `seven` (uses `#` markers, stripped on normalization).
    Seven,
}

/// Returns the raw bundled text for a practice puzzle (committed under
/// `research/data/practice-puzzles/`).
#[must_use]
pub fn practice_puzzle_text(puzzle: PracticePuzzle) -> &'static str {
    match puzzle {
        PracticePuzzle::Three => include_str!("../../research/data/practice-puzzles/three"),
        PracticePuzzle::Four => include_str!("../../research/data/practice-puzzles/four"),
        PracticePuzzle::Five => include_str!("../../research/data/practice-puzzles/five"),
        PracticePuzzle::Seven => include_str!("../../research/data/practice-puzzles/seven"),
    }
}

/// Slugifies a label into a filename-safe lowercase token.
fn slugify(label: &str) -> String {
    label
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

/// Builds the stable, clock-free candidate-record filename.
fn record_filename(label: &str, candidate: &KeystreamCandidate, seed: u64) -> String {
    format!(
        "keystream-{}-{}-l{}-seed-{seed:016x}.md",
        slugify(label),
        candidate.family.name(),
        candidate.key_len
    )
}

/// Renders the candidate-record markdown body (pure; testable without the
/// filesystem). Reproduces [`crate::attack::solve::SOLVE_CLAIM_CEILING`] verbatim so no
/// record can make a stronger claim than the solve pipeline.
fn render_record(
    label: &str,
    seed: u64,
    candidate: &KeystreamCandidate,
) -> Result<String, fmt::Error> {
    use std::fmt::Write as _;
    let mut out = String::new();
    writeln!(out, "# Keystream candidate record: {label}")?;
    writeln!(out)?;
    writeln!(
        out,
        "Stable label (NO wall-clock): label={label} seed=0x{seed:016x} family={} key-len={}",
        candidate.family.name(),
        candidate.key_len
    )?;
    writeln!(out)?;
    writeln!(out, "## Verdict")?;
    writeln!(out)?;
    let verdict = if candidate.survives {
        "CANDIDATE SURVIVED ALL GATES (round-trip + matched-null + random-key-null + held-out) — logged as a HYPOTHESIS, NOT a decode"
    } else {
        "NO surviving candidate — decode remains blocked"
    };
    writeln!(out, "**{verdict}.**")?;
    writeln!(out)?;
    writeln!(out, "## Claim ceiling (absolute)")?;
    writeln!(out)?;
    writeln!(out, "{}", crate::attack::solve::SOLVE_CLAIM_CEILING)?;
    writeln!(
        out,
        "Nothing in this record is stronger. A clean honest negative is a SUCCESS."
    )?;
    writeln!(out)?;
    writeln!(out, "## Gates (never collapsed)")?;
    writeln!(out)?;
    writeln!(
        out,
        "Survival requires BOTH nulls plus round-trip and held-out. The MATCHED \
         null (the same annealed search rerun on Fisher-Yates shuffled ciphertext, \
         holding the unigram multiset fixed and destroying higher-order structure) \
         polices SEARCH OVERFITTING. The RANDOM-KEY null (random keys on the \
         un-shuffled ciphertext) polices the ciphertext-autokey KEY-INDEPENDENCE \
         leak, which the matched null cannot see. Neither alone is sufficient."
    )?;
    writeln!(out)?;
    writeln!(out, "- round_trip_ok: {}", candidate.round_trip_ok)?;
    writeln!(out, "- best_score: {:.6}", candidate.best_score)?;
    writeln!(
        out,
        "- matched_mean: {:.6}  matched_std: {:.6}  matched_z: {:.4}",
        candidate.matched_mean, candidate.matched_std, candidate.matched_z
    )?;
    writeln!(
        out,
        "- beats_matched_null [SURVIVAL GATE: overfitting] (z >= {Z_THRESHOLD} AND margin >= {MIN_NAT_MARGIN}): {}",
        candidate.beats_matched_null
    )?;
    writeln!(
        out,
        "- null_mean: {:.6}  null_std: {:.6}  z: {:.4}",
        candidate.null_mean, candidate.null_std, candidate.z
    )?;
    writeln!(
        out,
        "- beats_null [SURVIVAL GATE: key-independence leak] (z >= {Z_THRESHOLD} AND margin >= {MIN_NAT_MARGIN}): {}",
        candidate.beats_null
    )?;
    writeln!(
        out,
        "- heldout_score: {:.6}  matched_heldout_mean: {:.6}  heldout_ok (> matched_heldout_mean): {}",
        candidate.heldout_score, candidate.matched_heldout_mean, candidate.heldout_ok
    )?;
    writeln!(out)?;
    writeln!(out, "## Recovered key (letter indices)")?;
    writeln!(out)?;
    writeln!(out, "{:?}", candidate.key)?;
    writeln!(out)?;
    writeln!(out, "## Decrypt (HYPOTHESIS, NOT a decode)")?;
    writeln!(out)?;
    writeln!(out, "{}", candidate.render_plaintext())?;
    Ok(out)
}

/// Writes a candidate record (a labelled HYPOTHESIS, never a decode) to `dir`,
/// creating the directory if needed. The filename is stable (label + family +
/// key length + seed; no wall clock), so re-running overwrites the prior record.
///
/// Returns the path written.
///
/// # Errors
/// Returns an [`io::Error`] if the directory cannot be created or the file cannot
/// be written.
pub fn write_keystream_record(
    dir: &Path,
    label: &str,
    seed: u64,
    candidate: &KeystreamCandidate,
) -> io::Result<PathBuf> {
    let path = dir.join(record_filename(label, candidate, seed));
    let body = render_record(label, seed, candidate)
        .map_err(|_error| io::Error::other("record formatting failed"))?;
    std::fs::create_dir_all(dir)?;
    std::fs::write(&path, body)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::{
        KeystreamCandidate, KeystreamFamily, KeystreamSearchConfig, PracticePuzzle, crack,
        crack_with_model, decrypt, encrypt, normalize_puzzle, practice_puzzle_text,
        write_keystream_record,
    };
    use crate::attack::quadgram::QuadgramModel;
    use crate::nulls::null::SplitMix64;

    // ~265 letters of plain English (lots of common quadgrams), used as the
    // planted-recovery corpus. Real prose, not a slice of any committed corpus.
    const PLAINTEXT: &str = "the quick brown fox jumps over the lazy dog while the morning sun \
        rises slowly above the quiet little village near the river where children often play \
        together after school and the old baker prepares fresh bread for everyone who passes by \
        his small wooden shop on the corner of the street that leads down toward the harbor";

    fn random_residues(len: usize, n: usize, rng: &mut SplitMix64) -> Vec<u8> {
        (0..len)
            .map(|_| (rng.next_u64() % n as u64) as u8)
            .collect()
    }

    fn match_fraction(expected: &[u8], actual: &[u8]) -> f64 {
        let matches = expected
            .iter()
            .zip(actual)
            .filter(|(left, right)| left == right)
            .count();
        matches as f64 / expected.len().max(1) as f64
    }

    #[test]
    fn round_trip_each_family() {
        let mut rng = SplitMix64::new(0x_a11ce);
        for &n in &[5usize, 26, 29] {
            for l in 1..=6usize {
                let data = random_residues(120, n, &mut rng);
                let key = random_residues(l, n, &mut rng);
                for &family in &KeystreamFamily::all() {
                    let cipher = encrypt(family, &data, &key, n);
                    let plain = decrypt(family, &cipher, &key, n);
                    assert_eq!(
                        plain, data,
                        "decrypt(encrypt) failed: {family:?} n={n} l={l}"
                    );
                    // encrypt(decrypt(c)) == c for every key (the round-trip gate).
                    let recipher = encrypt(family, &plain, &key, n);
                    assert_eq!(
                        recipher, cipher,
                        "encrypt(decrypt) failed: {family:?} n={n} l={l}"
                    );
                }
            }
        }
    }

    #[test]
    fn empty_key_is_a_no_op() {
        let data = vec![1u8, 2, 3, 25, 0];
        for &family in &KeystreamFamily::all() {
            let cipher = encrypt(family, &data, &[], 26);
            assert_eq!(cipher, data);
            assert_eq!(decrypt(family, &cipher, &[], 26), data);
        }
    }

    #[test]
    fn planted_recovery_searchable_families() {
        let model = QuadgramModel::english().unwrap();
        let plain = normalize_puzzle(PLAINTEXT);
        assert!(
            plain.len() >= 250,
            "planted corpus too short: {}",
            plain.len()
        );
        let n = 26usize;
        let key = vec![3u8, 15, 8, 20, 13]; // L = 5, within 5..=8
        let cfg = KeystreamSearchConfig {
            alphabet_size: n,
            restarts: 20,
            iterations: 4_000,
            anneal_temp: 1.0,
            seed: 0x00C0_FFEE,
            null_trials: 40,
            // Small matched null: the true cipher still clears it (a true cipher
            // of real English decrypts to ~-10.x while the matched null overfits
            // shuffled ciphertext only to ~-12.x), and it keeps `make verify` fast.
            matched_null_trials: 4,
        };
        // CiphertextAutokey is excluded here: it is key-independent for i>=L, so a
        // long plaintext cannot beat a random-key null — see the dedicated test.
        for &family in &[
            KeystreamFamily::Vigenere,
            KeystreamFamily::Beaufort,
            KeystreamFamily::PlaintextAutokey,
        ] {
            let cipher = encrypt(family, &plain, &key, n);
            let candidate = crack_with_model(&cipher, family, key.len(), &cfg, &model);
            let fraction = match_fraction(&plain, &candidate.decrypt);
            assert!(
                fraction >= 0.95,
                "{family:?} recovered only {:.1}% (z={:.2})",
                fraction * 100.0,
                candidate.z
            );
            assert!(
                candidate.survives,
                "{family:?} did not survive the matched-null gate \
                 (matched_z={:.2} matched_margin={:.3} matched_mean={:.3} heldout={:.3} best={:.3})",
                candidate.matched_z,
                candidate.best_score - candidate.matched_mean,
                candidate.matched_mean,
                candidate.heldout_score,
                candidate.best_score
            );
        }
    }

    #[test]
    fn planted_decode_survives_full_gate() {
        // Regression for the held-out gate miscalibration (T1): the gate must compare
        // the candidate's odd-index held-out fold against the matched null's HELD-OUT
        // fold (`matched_heldout_mean`), not the full-stream `matched_mean`. A fold of
        // English is not contiguous English, so it scores below the full stream; the
        // old fold-vs-full-stream comparison could falsely fail a perfectly recovered
        // decode. A planted true decode MUST clear the corrected gate.
        let model = QuadgramModel::english().unwrap();
        let plain = normalize_puzzle(PLAINTEXT);
        assert!(
            plain.len() >= 250,
            "planted corpus too short: {}",
            plain.len()
        );
        let n = 26usize;
        let key = vec![3u8, 15, 8, 20, 13];
        let cfg = KeystreamSearchConfig {
            alphabet_size: n,
            restarts: 20,
            iterations: 4_000,
            anneal_temp: 1.0,
            seed: 0x00C0_FFEE,
            null_trials: 40,
            matched_null_trials: 4,
        };
        let cipher = encrypt(KeystreamFamily::Vigenere, &plain, &key, n);
        let candidate =
            crack_with_model(&cipher, KeystreamFamily::Vigenere, key.len(), &cfg, &model);
        assert!(
            candidate.round_trip_ok,
            "round-trip is an algebraic identity"
        );
        assert!(
            candidate.beats_matched_null,
            "planted decode failed matched-null (best={:.3} matched_mean={:.3} matched_z={:.2})",
            candidate.best_score, candidate.matched_mean, candidate.matched_z
        );
        // The corrected (fold-vs-fold) held-out comparison.
        assert!(
            candidate.heldout_score > candidate.matched_heldout_mean,
            "held-out fold must beat the matched null's held-out fold \
             (heldout={:.3} matched_heldout_mean={:.3})",
            candidate.heldout_score,
            candidate.matched_heldout_mean
        );
        assert!(
            candidate.heldout_ok,
            "planted decode failed held-out (heldout={:.3} matched_heldout_mean={:.3})",
            candidate.heldout_score, candidate.matched_heldout_mean
        );
        assert!(
            candidate.survives,
            "a recovered planted decode MUST survive the gate (else the gate is too strict)"
        );
    }

    #[test]
    fn ciphertext_autokey_recovers_bulk_but_honestly_does_not_survive() {
        // Ciphertext-autokey decryption is key-INDEPENDENT for i>=L
        // (p_i = c_i - c_{i-L}, the classic ciphertext-autokey leak). On a long
        // plaintext the bulk decrypts correctly regardless of the primer guess —
        // and for the same reason the RANDOM-KEY null also reads as English, so
        // best_score cannot clear MIN_NAT_MARGIN above it (beats_null == false).
        // The MATCHED null does NOT police this: it shuffles the ciphertext, which
        // destroys the leak, so it would (wrongly) promote ct-autokey on its own —
        // which is exactly why survival keeps requiring the random-key null too.
        // This PROVES the gate does not manufacture a survivor from a key-leaking
        // cipher.
        let model = QuadgramModel::english().unwrap();
        let plain = normalize_puzzle(PLAINTEXT);
        let n = 26usize;
        let key = vec![3u8, 15, 8, 20, 13];
        let cfg = KeystreamSearchConfig {
            alphabet_size: n,
            restarts: 20,
            iterations: 4_000,
            anneal_temp: 1.0,
            seed: 0x00C0_FFEE,
            null_trials: 40,
            // Small matched null: the true cipher still clears it (a true cipher
            // of real English decrypts to ~-10.x while the matched null overfits
            // shuffled ciphertext only to ~-12.x), and it keeps `make verify` fast.
            matched_null_trials: 4,
        };
        let cipher = encrypt(KeystreamFamily::CiphertextAutokey, &plain, &key, n);
        let candidate = crack_with_model(
            &cipher,
            KeystreamFamily::CiphertextAutokey,
            key.len(),
            &cfg,
            &model,
        );
        // The key-independent tail (>=95% of positions) is recovered for free.
        assert!(
            match_fraction(&plain, &candidate.decrypt) >= 0.95,
            "ct-autokey failed to recover the key-independent bulk"
        );
        assert!(candidate.round_trip_ok);
        assert!(
            !candidate.survives,
            "ct-autokey unexpectedly survived on a long plaintext \
             (matched_margin={:.3} matched_z={:.2})",
            candidate.best_score - candidate.matched_mean,
            candidate.matched_z
        );
    }

    #[test]
    fn random_ciphertext_yields_no_survivor() {
        let model = QuadgramModel::english().unwrap();
        let mut rng = SplitMix64::new(0x_dead_beef);
        let n = 26usize;
        let cipher = random_residues(220, n, &mut rng);
        let cfg = KeystreamSearchConfig {
            alphabet_size: n,
            restarts: 12,
            iterations: 3_000,
            anneal_temp: 1.0,
            seed: 0x0000_5151,
            null_trials: 40,
            matched_null_trials: 4,
        };
        for &family in &KeystreamFamily::all() {
            for key_len in [1usize, 3, 5] {
                let candidate = crack_with_model(&cipher, family, key_len, &cfg, &model);
                assert!(
                    !candidate.survives,
                    "noise survived: {family:?} l={key_len} (matched_z={:.2} matched_margin={:.3})",
                    candidate.matched_z,
                    candidate.best_score - candidate.matched_mean
                );
            }
        }
    }

    #[test]
    fn matched_null_rejects_overfitting_at_high_key_len() {
        // REGRESSION for the false-positive bug. At a high key length the annealed
        // search overfits short RANDOM ciphertext (many free key parameters),
        // reaching a best score whose z against the no-search random-key null
        // clears the gate — so the OLD (random-key-only) survival verdict promoted
        // PURE NOISE (beats_null == true below). The matched null reruns the SAME
        // search on shuffled copies of the same ciphertext, so it overfits just as
        // hard; the real result no longer clears it (beats_matched_null == false).
        // This test FAILS under the old gate and PASSES under the matched-null fix.
        let model = QuadgramModel::english().unwrap();
        let mut rng = SplitMix64::new(0x_0ddc_0ffe_e000_1234);
        let n = 26usize;
        let cipher = random_residues(274, n, &mut rng);
        let cfg = KeystreamSearchConfig {
            alphabet_size: n,
            restarts: 12,
            iterations: 8_000,
            anneal_temp: 1.0,
            seed: 0x00BA_DBED,
            null_trials: 16,
            matched_null_trials: 4,
        };
        let mut random_key_null_was_fooled = false;
        for key_len in [60usize, 80] {
            let candidate =
                crack_with_model(&cipher, KeystreamFamily::Vigenere, key_len, &cfg, &model);
            // The matched null (the fix) is NOT fooled: the search's best on real
            // random ciphertext is no higher than what the SAME search extracts
            // from the shuffled multiset, so it cannot clear the matched gate.
            assert!(
                !candidate.beats_matched_null,
                "overfit beat the matched null at L={key_len} \
                 (best={:.3} matched_mean={:.3} matched_z={:.2})",
                candidate.best_score, candidate.matched_mean, candidate.matched_z
            );
            assert!(
                !candidate.survives,
                "overfit survived at L={key_len} (matched_z={:.2} matched_margin={:.3})",
                candidate.matched_z,
                candidate.best_score - candidate.matched_mean
            );
            // The random-key null (the OLD gate) IS fooled on its headline z: pure
            // noise clears Z_THRESHOLD against it — the exact false positive the
            // matched null now catches.
            assert!(
                candidate.z >= super::Z_THRESHOLD,
                "expected the random-key null z to be fooled at L={key_len}, got z={:.2}",
                candidate.z
            );
            if candidate.beats_null {
                random_key_null_was_fooled = true;
            }
        }
        assert!(
            random_key_null_was_fooled,
            "expected the random-key null to FULLY pass on pure noise for at least \
             one high key length (the false positive the matched null fixes)"
        );
    }

    #[test]
    fn deterministic_for_fixed_seed() {
        let model = QuadgramModel::english().unwrap();
        let plain = normalize_puzzle(PLAINTEXT);
        let n = 26usize;
        let key = vec![1u8, 2, 3, 4];
        let cipher = encrypt(KeystreamFamily::Vigenere, &plain, &key, n);
        let cfg = KeystreamSearchConfig {
            alphabet_size: n,
            restarts: 5,
            iterations: 1_000,
            anneal_temp: 0.5,
            seed: 0x0000_0777,
            null_trials: 10,
            matched_null_trials: 4,
        };
        let first = crack_with_model(&cipher, KeystreamFamily::Vigenere, key.len(), &cfg, &model);
        let second = crack_with_model(&cipher, KeystreamFamily::Vigenere, key.len(), &cfg, &model);
        assert_eq!(first.key, second.key);
        assert_eq!(first.best_score.to_bits(), second.best_score.to_bits());
        assert_eq!(first.z.to_bits(), second.z.to_bits());
        // Matched-null stats (and the verdict they drive) are deterministic too.
        assert_eq!(first.matched_mean.to_bits(), second.matched_mean.to_bits());
        assert_eq!(first.matched_std.to_bits(), second.matched_std.to_bits());
        assert_eq!(
            first.matched_heldout_mean.to_bits(),
            second.matched_heldout_mean.to_bits()
        );
        assert_eq!(first.matched_z.to_bits(), second.matched_z.to_bits());
        assert_eq!(first.beats_matched_null, second.beats_matched_null);
        assert_eq!(first.survives, second.survives);
        assert_eq!(first.decrypt, second.decrypt);
    }

    #[test]
    fn practice_puzzles_normalize_to_letters() {
        for puzzle in [
            PracticePuzzle::Three,
            PracticePuzzle::Four,
            PracticePuzzle::Five,
            PracticePuzzle::Seven,
        ] {
            let indices = normalize_puzzle(practice_puzzle_text(puzzle));
            assert!(!indices.is_empty(), "{puzzle:?} parsed to no letters");
            assert!(
                indices.iter().all(|&v| v < 26),
                "{puzzle:?} produced a non-letter index"
            );
        }
        // The seven puzzle's `#` markers are dropped (not letters).
        assert!(
            !practice_puzzle_text(PracticePuzzle::Seven).contains('A')
                || normalize_puzzle("A#B") == vec![0u8, 1u8]
        );
    }

    #[test]
    fn crack_builds_model_and_renders_letters() {
        let plain = normalize_puzzle(PLAINTEXT);
        let key = vec![5u8, 9, 2];
        let cipher = encrypt(KeystreamFamily::Vigenere, &plain, &key, 26);
        let cfg = KeystreamSearchConfig {
            restarts: 3,
            iterations: 500,
            ..KeystreamSearchConfig::default()
        };
        let candidate = crack(&cipher, KeystreamFamily::Vigenere, key.len(), &cfg).unwrap();
        assert_eq!(candidate.family, KeystreamFamily::Vigenere);
        assert_eq!(candidate.key_len, 3);
        assert!(
            candidate
                .render_plaintext()
                .chars()
                .all(|ch| ch.is_ascii_uppercase())
        );
    }

    #[test]
    fn record_writer_emits_claim_ceiling() {
        let candidate = KeystreamCandidate {
            family: KeystreamFamily::Vigenere,
            key_len: 3,
            key: vec![1, 2, 3],
            best_score: -10.0,
            null_mean: -14.0,
            null_std: 0.2,
            z: 20.0,
            matched_mean: -12.0,
            matched_std: 0.2,
            matched_z: 10.0,
            round_trip_ok: true,
            heldout_score: -11.0,
            matched_heldout_mean: -12.5,
            beats_null: true,
            beats_matched_null: true,
            heldout_ok: true,
            survives: true,
            decrypt: vec![0, 1, 2],
        };
        let dir = std::env::temp_dir().join(format!("noita-keystream-rec-{}", std::process::id()));
        let _removed = std::fs::remove_dir_all(&dir);
        let path = write_keystream_record(&dir, "unit", 0x1234, &candidate).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains(crate::attack::solve::SOLVE_CLAIM_CEILING));
        assert!(body.contains("HYPOTHESIS, NOT a decode"));
        assert!(body.contains("vigenere"));
        let _cleanup = std::fs::remove_dir_all(&dir);
    }
}

//! General (non-keyword) Ragbaby cipher cracker for the practice letter-puzzles.
//!
//! The Ragbaby cipher is a polyalphabetic substitution over a single *keyed
//! alphabet* `K` (a permutation of the `base` letters). Each plaintext letter is
//! shifted along `K` by a position-dependent **key number** `N_i` derived from the
//! word structure of the text, then read back off `K`. The unknown this module
//! recovers is the keyed alphabet itself, found by a strong simulated-annealing
//! optimizer scored against the bundled [`crate::quadgram`] English model.
//!
//! It is the keyed-alphabet analogue of [`crate::keystream`]: it searches and
//! scores hypotheses, gates them against a matched null and a held-out fold, and
//! reports an explicit **honest negative** when nothing survives — the expected
//! outcome on the practice puzzles. Crucially it ships with a **positive control**
//! (a planted-recovery length sweep) so that a negative is only ever reported
//! alongside a demonstrated ability to recover a planted Ragbaby at that length.
//!
//! # Cipher definition
//!
//! Let `pos(x)` be the index of letter `x` in `K`. The plaintext is split into
//! words (maximal runs of letters); non-letters are separators. The per-letter key
//! number `N_i` depends on the numbering convention ([`Numbering`]):
//!
//! - [`Numbering::Std`] (ACA): the `k`-th letter (1-indexed) of word `w`
//!   (1-indexed) gets `N = w + (k - 1)`.
//! - [`Numbering::PerWord`]: each word is numbered `1, 2, 3, …` independently.
//! - [`Numbering::Continuous`]: the counter increments across the whole text and
//!   never resets (position-keyed).
//!
//! Encrypt: `c = K[(pos(p) + sign * N) mod base]`. Decrypt:
//! `p = K[(pos(c) - sign * N) mod base]`.
//!
//! ## Real-letter-index space
//!
//! `K` is a permutation whose **values are the real `A..Z` letter indices** of the
//! kept set, so the English quadgram model is meaningful at every base:
//!
//! - base 26: keep `[0..26]` (identity over `A..Z`).
//! - base 25: keep `[0..26]` minus `{9}` (J), folding `J -> I` before indexing.
//! - base 24: keep `[0..26]` minus `{9, 21}` (J, V), folding `J -> I`, `V -> U`.
//!
//! The kept letters are **not** relabelled into a contiguous `0..base` space: doing
//! so would shift every letter past `J` and the recovered plaintext would no longer
//! be English in scoring space (base-25/24 recovery would silently collapse). For
//! base 26 the path is the identity, so the base-26 case is unaffected.
//!
//! # Survival gate
//!
//! A candidate survives only when, against the **matched null** (the same annealed
//! search rerun on a Fisher-Yates shuffle of the ciphertext *letter* stream with
//! the key-number sequence `N_i` held fixed), it clears the z-score floor
//! ([`Z_THRESHOLD`]) and the absolute nat floor ([`MIN_NAT_MARGIN`]) on the
//! quadgram **mean** scale, AND `encrypt(decrypt) == ciphertext` (a round-trip
//! sanity gate), AND a held-out odd-index fold reads above the matched-null mean.
//! The matched null shares the search's degrees of freedom, so it measures exactly
//! what the keyed-alphabet search extracts from noise. A random-keyed-alphabet null
//! is reported as a diagnostic only — Ragbaby has no key-independence leak for it to
//! police (unlike ciphertext-autokey in [`crate::keystream`]).

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use crate::null::{SplitMix64, fisher_yates, mix_seed};
use crate::quadgram::{QuadgramError, QuadgramModel};

/// Minimum z-score (best score above the matched-null mean, in null standard
/// deviations) required to clear the survival gate, on the quadgram mean-log scale.
pub const Z_THRESHOLD: f64 = 6.0;

/// Minimum absolute nat margin (`best_score - matched_mean`, mean scale) required
/// to clear the survival gate, guarding the degenerate tiny-`std` case.
pub const MIN_NAT_MARGIN: f64 = 1.0;

/// Default multi-restart count (validated confirmatory default).
pub const DEFAULT_RESTARTS: usize = 40;

/// Default simulated-annealing iterations per restart (validated confirmatory
/// default).
pub const DEFAULT_ITERATIONS: usize = 20_000;

/// Default basin-hopping perturbation rounds per restart (validated confirmatory
/// default).
pub const DEFAULT_BASIN_HOPS: usize = 6;

/// Default annealing start temperature (nat scale).
pub const DEFAULT_T0: f64 = 12.0;

/// Default annealing end temperature (nat scale).
pub const DEFAULT_T1: f64 = 0.3;

/// Default deterministic seed for the search and both nulls.
pub const DEFAULT_SEED: u64 = 0x7261_6762_6162_7900;

/// Default random-keyed-alphabet null-trial count (the reported DIAGNOSTIC).
pub const DEFAULT_NULL_TRIALS: usize = 64;

/// Default matched-null trial count: reruns of the FULL search on a shuffled
/// ciphertext letter stream. Each trial is a full multi-restart anneal, so this is
/// the dominant cost knob — kept modest.
pub const DEFAULT_MATCHED_NULL_TRIALS: usize = 6;

/// Default planted-recovery trials per `(length, base)` cell in `--control`.
pub const DEFAULT_CONTROL_TRIALS: usize = 6;

/// Deterministic tag mixed into the random-keyed-alphabet null seed so that null is
/// decorrelated from the search stream while staying reproducible.
const NULL_SEED_TAG: u64 = 0x0072_6167_6e75_6c00;

/// Deterministic tag mixed into the matched-null shuffle/search seeds (the
/// `SplitMix64` golden-ratio constant) so the matched null is decorrelated from
/// both the search and the random-keyed-alphabet null streams.
const MATCHED_NULL_SEED_TAG: u64 = 0x9e37_79b9_7f4a_7c15;

/// Letter index of `J` (folded to `I` for bases ≤ 25).
const LETTER_J: usize = 9;

/// Letter index of `V` (folded to `U` for base 24).
const LETTER_V: usize = 21;

/// The ACA-family key-numbering convention for a Ragbaby cipher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Numbering {
    /// Standard ACA numbering: the `k`-th letter (1-indexed) of word `w`
    /// (1-indexed) gets `N = w + (k - 1)`.
    Std,
    /// Each word numbered `1, 2, 3, …` independently of its word index.
    PerWord,
    /// A single counter incrementing across the whole text, never reset.
    Continuous,
}

impl Numbering {
    /// All numbering conventions, in a stable order.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::Std, Self::PerWord, Self::Continuous]
    }

    /// Stable lowercase name (used in tables and candidate-record filenames).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Std => "std",
            Self::PerWord => "perword",
            Self::Continuous => "continuous",
        }
    }

    /// A stable per-numbering tag decorrelating the per-convention null streams.
    const fn tag(self) -> u64 {
        match self {
            Self::Std => 0x5354_4400,
            Self::PerWord => 0x5057_4400,
            Self::Continuous => 0x434f_4e00,
        }
    }
}

impl fmt::Display for Numbering {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The shift sign of a Ragbaby cipher (`+1` adds the key number, `-1` subtracts).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sign {
    /// `c = K[(pos(p) + N) mod base]`.
    Plus,
    /// `c = K[(pos(p) - N) mod base]`.
    Minus,
}

impl Sign {
    /// The numeric sign value (`+1` or `-1`).
    #[must_use]
    pub const fn value(self) -> i64 {
        match self {
            Self::Plus => 1,
            Self::Minus => -1,
        }
    }

    /// Stable lowercase name (used in candidate-record filenames).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Plus => "plus",
            Self::Minus => "minus",
        }
    }

    /// Compact signed label (`"+1"` / `"-1"`) for tables.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Plus => "+1",
            Self::Minus => "-1",
        }
    }

    /// A stable per-sign tag decorrelating the per-sign null streams.
    const fn tag(self) -> u64 {
        match self {
            Self::Plus => 0x2b31_0000,
            Self::Minus => 0x2d31_0000,
        }
    }
}

/// Returns the real `A..Z` letter indices that form the keyed alphabet for `base`.
///
/// Base 26 keeps all of `A..Z`; base 25 drops `J`; base 24 drops `J` and `V`. Any
/// other base falls back to the first `min(base, 26)` letters (never panics).
#[must_use]
pub fn keep_for_base(base: usize) -> Vec<usize> {
    match base {
        25 => (0..26).filter(|&i| i != LETTER_J).collect(),
        24 => (0..26)
            .filter(|&i| i != LETTER_J && i != LETTER_V)
            .collect(),
        b if b >= 26 => (0..26).collect(),
        b => (0..b).collect(),
    }
}

/// Folds a real letter index into the kept alphabet for `base` (`J -> I` for
/// bases ≤ 25, `V -> U` for base 24); all other letters pass through unchanged.
#[must_use]
pub fn fold_idx(letter: usize, base: usize) -> usize {
    if base <= 25 && letter == LETTER_J {
        return LETTER_J - 1; // J -> I
    }
    if base <= 24 && letter == LETTER_V {
        return LETTER_V - 1; // V -> U
    }
    letter
}

/// Computes the per-letter key numbers `N_i` for the letters of `text`, in letter
/// order, under `numbering`. Letters are maximal runs of ASCII alphabetic
/// characters; every other character is a word separator.
#[must_use]
pub fn key_numbers(text: &str, numbering: Numbering) -> Vec<usize> {
    let mut nums = Vec::new();
    let mut word_idx = 0usize;
    let mut within = 0usize;
    let mut continuous = 0usize;
    let mut in_word = false;
    for ch in text.chars() {
        if ch.is_ascii_alphabetic() {
            if !in_word {
                word_idx += 1;
                within = 0;
                in_word = true;
            }
            continuous += 1;
            let number = match numbering {
                Numbering::Std => word_idx + within,
                Numbering::PerWord => within + 1,
                Numbering::Continuous => continuous,
            };
            nums.push(number);
            within += 1;
        } else {
            in_word = false;
        }
    }
    nums
}

/// Prepares `text` for a Ragbaby attack at `base` under `numbering`, returning the
/// folded real-letter-index stream and the matching key-number stream (already
/// reduced modulo `base`). The two vectors have equal length (one entry per ASCII
/// letter); word structure is preserved by [`key_numbers`].
#[must_use]
pub fn prepare(text: &str, numbering: Numbering, base: usize) -> (Vec<usize>, Vec<usize>) {
    let divisor = base.max(1);
    let nums: Vec<usize> = key_numbers(text, numbering)
        .into_iter()
        .map(|number| number % divisor)
        .collect();
    let letters: Vec<usize> = text
        .chars()
        .filter(char::is_ascii_alphabetic)
        .map(|ch| fold_idx(usize::from(ch.to_ascii_uppercase() as u8 - b'A'), base))
        .collect();
    (letters, nums)
}

/// Adds two residues modulo `n` without overflow (returns `0` when `n == 0`).
fn add_mod(a: usize, b: usize, n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    (a % n + b % n) % n
}

/// Subtracts `b` from `a` modulo `n` without underflow (returns `0` when
/// `n == 0`).
fn sub_mod(a: usize, b: usize, n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    (a % n + n - b % n) % n
}

/// The shifted position for one letter: a forward shift (`forward == true`) adds
/// the key number along the keyed alphabet, a backward shift subtracts it.
fn shift_position(position: usize, number: usize, forward: bool, base: usize) -> usize {
    if forward {
        add_mod(position, number, base)
    } else {
        sub_mod(position, number, base)
    }
}

/// Builds the inverse map `inv[real_letter] = position in key` into `inv`
/// (size-26; entries for absent letters are left at `0`, never read for kept
/// letters).
fn fill_inverse(key: &[usize], inv: &mut [usize; 26]) {
    for slot in inv.iter_mut() {
        *slot = 0;
    }
    for (position, &letter) in key.iter().enumerate() {
        if let Some(slot) = inv.get_mut(letter) {
            *slot = position;
        }
    }
}

/// Encrypts a folded real-letter-index plaintext stream under keyed alphabet
/// `key`, returning the ciphertext letter-index stream.
///
/// `nums` are the per-letter key numbers (any residue; reduced internally). The
/// streams must be the same length; a short `nums` reads missing entries as `0`.
#[must_use]
pub fn encrypt_indices(
    plain: &[usize],
    nums: &[usize],
    key: &[usize],
    sign: i64,
    base: usize,
) -> Vec<usize> {
    let mut inv = [0usize; 26];
    fill_inverse(key, &mut inv);
    let mut out = Vec::with_capacity(plain.len());
    for (i, &letter) in plain.iter().enumerate() {
        let position = inv.get(letter).copied().unwrap_or(0);
        let number = nums.get(i).copied().unwrap_or(0);
        // Encrypt adds the key number for sign +1, subtracts it for sign -1.
        let cipher_pos = shift_position(position, number, sign >= 0, base);
        out.push(key.get(cipher_pos).copied().unwrap_or(0));
    }
    out
}

/// Decrypts a folded real-letter-index ciphertext stream under keyed alphabet
/// `key`, returning the plaintext letter-index stream (mirror of
/// [`encrypt_indices`]).
#[must_use]
pub fn decrypt_indices(
    cipher: &[usize],
    nums: &[usize],
    key: &[usize],
    sign: i64,
    base: usize,
) -> Vec<usize> {
    let mut inv = [0usize; 26];
    let mut out = Vec::with_capacity(cipher.len());
    decrypt_into(cipher, nums, key, sign, base, &mut inv, &mut out);
    out
}

/// Decrypts into reused buffers (the search hot path): fills `inv` from `key`,
/// clears `out`, and writes the recovered plaintext letter indices.
fn decrypt_into(
    cipher: &[usize],
    nums: &[usize],
    key: &[usize],
    sign: i64,
    base: usize,
    inv: &mut [usize; 26],
    out: &mut Vec<usize>,
) {
    fill_inverse(key, inv);
    out.clear();
    for (i, &letter) in cipher.iter().enumerate() {
        let position = inv.get(letter).copied().unwrap_or(0);
        let number = nums.get(i).copied().unwrap_or(0);
        // Decrypt subtracts the key number for sign +1, adds it for sign -1.
        let plain_pos = shift_position(position, number, sign < 0, base);
        out.push(key.get(plain_pos).copied().unwrap_or(0));
    }
}

/// Parses a keyed-alphabet string (ASCII letters) into its real-letter-index
/// permutation, or returns `None` on a non-letter character.
fn keyed_alphabet_indices(keyed_alphabet: &str) -> Option<Vec<usize>> {
    keyed_alphabet
        .chars()
        .map(|ch| {
            ch.is_ascii_alphabetic()
                .then(|| usize::from(ch.to_ascii_uppercase() as u8 - b'A'))
        })
        .collect()
}

/// Transcodes a full text (letters shifted, non-letters preserved) under keyed
/// alphabet `keyed_alphabet`, with `step` the signed position delta applied to
/// each letter's key number (encrypt uses `+sign`, decrypt uses `-sign`).
fn transcode_str(
    text: &str,
    keyed_alphabet: &str,
    numbering: Numbering,
    step: i64,
    base: usize,
) -> String {
    let Some(key) = keyed_alphabet_indices(keyed_alphabet) else {
        return text.to_owned();
    };
    let mut inv = [None; 26];
    for (position, &letter) in key.iter().enumerate() {
        if let Some(slot) = inv.get_mut(letter) {
            *slot = Some(position);
        }
    }
    let nums = key_numbers(text, numbering);
    let mut out = String::with_capacity(text.len());
    let mut letter_index = 0usize;
    for ch in text.chars() {
        if !ch.is_ascii_alphabetic() {
            out.push(ch);
            continue;
        }
        let folded = fold_idx(usize::from(ch.to_ascii_uppercase() as u8 - b'A'), base);
        let number = nums.get(letter_index).copied().unwrap_or(0);
        letter_index += 1;
        match inv.get(folded).copied().flatten() {
            Some(position) => {
                let shifted = shift_position(position, number, step >= 0, base);
                let letter = key.get(shifted).copied().unwrap_or(0);
                out.push((b'A' + letter as u8) as char);
            }
            None => out.push(ch),
        }
    }
    out
}

/// Encrypts `plaintext` (letters shifted, non-letters preserved) under the keyed
/// alphabet string `keyed_alphabet`. This is the string-form convention pinned by
/// the worked example (`"THE CAT"` → `"OJH YED"`).
#[must_use]
pub fn encrypt_str(
    plaintext: &str,
    keyed_alphabet: &str,
    numbering: Numbering,
    sign: Sign,
    base: usize,
) -> String {
    transcode_str(plaintext, keyed_alphabet, numbering, sign.value(), base)
}

/// Decrypts `ciphertext` under the keyed alphabet string `keyed_alphabet` (mirror
/// of [`encrypt_str`]).
#[must_use]
pub fn decrypt_str(
    ciphertext: &str,
    keyed_alphabet: &str,
    numbering: Numbering,
    sign: Sign,
    base: usize,
) -> String {
    transcode_str(ciphertext, keyed_alphabet, numbering, -sign.value(), base)
}

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
    /// Random-keyed-alphabet null trials for the reported DIAGNOSTIC.
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
/// [`crate::keystream`]'s Metropolis sampler).
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
fn random_keyed_alphabet(keep: &[usize], rng: &mut SplitMix64) -> Vec<usize> {
    let mut key = keep.to_vec();
    // Unreachable for an in-bounds slice on a 64-bit target; an error only leaves
    // `key` unshuffled (a still-valid keyed alphabet), never panics.
    if fisher_yates(&mut key, rng).is_err() {
        return keep.to_vec();
    }
    key
}

/// The immutable problem data plus model reference for one `(base, sign)` anneal.
struct RagbabySearch<'a> {
    cipher: &'a [usize],
    nums: &'a [usize],
    base: usize,
    sign: i64,
    keep: &'a [usize],
    model: &'a QuadgramModel,
}

impl RagbabySearch<'_> {
    /// Scores keyed alphabet `key` as the SUM of quadgram log-probs of its
    /// decryption (the well-scaled SA objective), reusing `inv`/`out` buffers.
    fn score(&self, key: &[usize], inv: &mut [usize; 26], out: &mut Vec<usize>) -> f64 {
        decrypt_into(self.cipher, self.nums, key, self.sign, self.base, inv, out);
        self.model.score_indices_sum(out)
    }

    /// Anneals from `key`, returning the best keyed alphabet and its SUM score.
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
    /// keyed alphabet and its SUM score. Deterministic in the `rng` stream.
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
    fn decrypt(&self, key: &[usize]) -> Vec<usize> {
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
/// [`crate::keystream`]'s `search`).
fn search(ctx: &RagbabySearch, cfg: &RagbabySearchConfig) -> (Vec<usize>, f64) {
    let mut rng = SplitMix64::new(cfg.seed);
    ctx.run(cfg, &mut rng)
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

/// Fraction of positions (over the shorter length) where `a` and `b` agree
/// (`0.0` for empty input).
#[must_use]
pub fn char_accuracy(a: &[usize], b: &[usize]) -> f64 {
    let n = a.len().min(b.len());
    if n == 0 {
        return 0.0;
    }
    let matches = a.iter().zip(b).take(n).filter(|(x, y)| x == y).count();
    matches as f64 / n as f64
}

/// A prepared Ragbaby ciphertext for one `(base, numbering, sign)` hypothesis.
///
/// The `cipher` and `nums` streams come from [`prepare`] and must be the same
/// length; `numbering` is carried for the candidate record and the null seed tags.
#[derive(Clone, Copy, Debug)]
pub struct RagbabyProblem<'a> {
    /// Folded real-letter-index ciphertext stream.
    pub cipher: &'a [usize],
    /// Per-letter key numbers (reduced modulo `base`), same length as `cipher`.
    pub nums: &'a [usize],
    /// Alphabet base (24, 25, or 26).
    pub base: usize,
    /// Shift sign.
    pub sign: Sign,
    /// Key-numbering convention.
    pub numbering: Numbering,
}

impl RagbabyProblem<'_> {
    /// A stable per-hypothesis tag decorrelating the per-`(base, numbering, sign)`
    /// null streams.
    fn tag(&self) -> u64 {
        (self.base as u64).wrapping_mul(0x0100_0000) ^ self.numbering.tag() ^ self.sign.tag()
    }
}

/// One scored, gated keyed-alphabet hypothesis for a single
/// `(base, numbering, sign)`.
///
/// A surviving candidate is a HYPOTHESIS, never a confirmed decode.
#[derive(Clone, Debug, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the gate verdicts (round-trip, beats-matched-null, beats-null diagnostic, held-out, survives) are kept as separate fields and never collapsed, mirroring keystream.rs's never-collapse gate discipline"
)]
pub struct RagbabyCandidate {
    /// Alphabet base searched.
    pub base: usize,
    /// Numbering convention searched.
    pub numbering: Numbering,
    /// Shift sign searched.
    pub sign: Sign,
    /// Best keyed alphabet recovered (real-letter-index permutation).
    pub key: Vec<usize>,
    /// Best quadgram MEAN-log score of the recovered plaintext (gate scale).
    pub best_score: f64,
    /// Mean quadgram score of the random-keyed-alphabet null (DIAGNOSTIC).
    pub null_mean: f64,
    /// Standard deviation of the random-keyed-alphabet null (DIAGNOSTIC).
    pub null_std: f64,
    /// `(best_score - null_mean) / null_std` (or `0`); the diagnostic z-score.
    pub z: f64,
    /// Mean best score of the matched null (the same search rerun on a shuffled
    /// ciphertext letter stream with `N_i` held fixed). Drives the survival gate.
    pub matched_mean: f64,
    /// Standard deviation of the matched-null best scores.
    pub matched_std: f64,
    /// `(best_score - matched_mean) / matched_std` (or `0`); the survival z-score.
    pub matched_z: f64,
    /// Whether `encrypt(decrypt) == ciphertext` (always true; a sanity gate).
    pub round_trip_ok: bool,
    /// Quadgram score of the odd-indexed held-out fold of the best decrypt.
    pub heldout_score: f64,
    /// Mean held-out (odd-index) fold score across the matched-null reruns — the
    /// apples-to-apples baseline the candidate's `heldout_score` must beat.
    pub matched_heldout_mean: f64,
    /// Diagnostic: clears [`Z_THRESHOLD`]/[`MIN_NAT_MARGIN`] vs the random-keyed
    /// null. Not part of survival — Ragbaby has no key-independence leak.
    pub beats_null: bool,
    /// Survival gate: clears [`Z_THRESHOLD`]/[`MIN_NAT_MARGIN`] vs the matched null
    /// (and `matched_null_trials > 0`). Polices search overfitting.
    pub beats_matched_null: bool,
    /// Whether `heldout_score > matched_heldout_mean`. `false` when
    /// `matched_null_trials == 0`.
    pub heldout_ok: bool,
    /// `round_trip_ok && beats_matched_null && heldout_ok`.
    pub survives: bool,
    /// The best decryption (plaintext letter indices).
    pub decrypt: Vec<usize>,
}

impl RagbabyCandidate {
    /// Renders the best decryption as `A..` letters (`0 -> 'A'`); indices outside
    /// `0..26` render as `'?'`.
    #[must_use]
    pub fn render_plaintext(&self) -> String {
        self.decrypt
            .iter()
            .map(|&v| {
                if v < 26 {
                    (b'A' + v as u8) as char
                } else {
                    '?'
                }
            })
            .collect()
    }
}

/// Builds the random-keyed-alphabet null `(mean, std)`: scores decryptions of the
/// real ciphertext under random keyed alphabets (no search). A DIAGNOSTIC only.
fn random_key_null(
    problem: &RagbabyProblem,
    keep: &[usize],
    cfg: &RagbabySearchConfig,
    model: &QuadgramModel,
) -> (f64, f64) {
    if cfg.null_trials == 0 {
        return (0.0, 0.0);
    }
    let ctx = RagbabySearch {
        cipher: problem.cipher,
        nums: problem.nums,
        base: problem.base,
        sign: problem.sign.value(),
        keep,
        model,
    };
    let mut rng = SplitMix64::new(mix_seed(cfg.seed, NULL_SEED_TAG ^ problem.tag()));
    let mut inv = [0usize; 26];
    let mut out: Vec<usize> = Vec::with_capacity(problem.cipher.len());
    let mut scores: Vec<f64> = Vec::with_capacity(cfg.null_trials);
    for _trial in 0..cfg.null_trials {
        let key = random_keyed_alphabet(keep, &mut rng);
        decrypt_into(
            problem.cipher,
            problem.nums,
            &key,
            ctx.sign,
            problem.base,
            &mut inv,
            &mut out,
        );
        scores.push(model.score_indices(&out));
    }
    mean_std(&scores)
}

/// Builds the matched null `(mean, std)` — the honest survival bar. Each trial
/// Fisher-Yates **shuffles** the ciphertext letter stream (holding `N_i` fixed, so
/// the search's degrees of freedom are identical) and reruns the IDENTICAL anneal,
/// recording the best decrypt's MEAN score. Returns `(0.0, 0.0)` when disabled.
/// Held-out fold of a decrypt: the odd-indexed letters scored as a stream.
///
/// This is only ever meaningful as a *relative* generalisation check — the
/// candidate's held-out fold is compared against the **matched null's** held-out
/// fold (apples-to-apples). Every-other-letter of English is NOT contiguous
/// English, so its absolute quadgram score is low; comparing it to the full-stream
/// mean (as an earlier version did) falsely fails even a perfect decode.
fn heldout_fold_score(decrypt: &[usize], model: &QuadgramModel) -> f64 {
    let fold: Vec<usize> = decrypt
        .iter()
        .copied()
        .enumerate()
        .filter_map(|(position, value)| (position % 2 == 1).then_some(value))
        .collect();
    model.score_indices(&fold)
}

/// Matched null: reruns the identical search on Fisher–Yates-shuffled cipher
/// letters (key-number sequence held fixed). Returns `(full_mean, full_std,
/// heldout_mean)` — the held-out mean is the baseline for the generalisation gate.
fn matched_null(
    problem: &RagbabyProblem,
    keep: &[usize],
    cfg: &RagbabySearchConfig,
    model: &QuadgramModel,
) -> (f64, f64, f64) {
    if cfg.matched_null_trials == 0 {
        return (0.0, 0.0, 0.0);
    }
    let mut scores: Vec<f64> = Vec::with_capacity(cfg.matched_null_trials);
    let mut heldouts: Vec<f64> = Vec::with_capacity(cfg.matched_null_trials);
    for trial in 0..cfg.matched_null_trials {
        let shuffle_seed = cfg.seed ^ MATCHED_NULL_SEED_TAG ^ problem.tag() ^ (trial as u64);
        let mut shuffle_rng = SplitMix64::new(shuffle_seed);
        let mut shuffled = problem.cipher.to_vec();
        if fisher_yates(&mut shuffled, &mut shuffle_rng).is_err() {
            // Unreachable for an in-bounds slice on a 64-bit target; skip the trial
            // rather than panic (a dropped trial only shrinks the sample).
            continue;
        }
        let search_seed = mix_seed(
            cfg.seed,
            MATCHED_NULL_SEED_TAG ^ problem.tag() ^ ((trial as u64) << 32),
        );
        let trial_cfg = RagbabySearchConfig {
            seed: search_seed,
            ..*cfg
        };
        let ctx = RagbabySearch {
            cipher: &shuffled,
            nums: problem.nums,
            base: problem.base,
            sign: problem.sign.value(),
            keep,
            model,
        };
        let (key, _sum) = search(&ctx, &trial_cfg);
        let decrypt = ctx.decrypt(&key);
        scores.push(model.score_indices(&decrypt));
        heldouts.push(heldout_fold_score(&decrypt, model));
    }
    let (mean, std) = mean_std(&scores);
    let (heldout_mean, _heldout_std) = mean_std(&heldouts);
    (mean, std, heldout_mean)
}

/// Cracks one prepared `(base, numbering, sign)` problem against a prebuilt
/// quadgram `model`, returning a fully-gated [`RagbabyCandidate`].
///
/// Reuse this entry point across many hypotheses so the (expensive) quadgram model
/// is built once. Deterministic in `cfg.seed`.
#[must_use]
pub fn crack_with_model(
    problem: &RagbabyProblem,
    cfg: &RagbabySearchConfig,
    model: &QuadgramModel,
) -> RagbabyCandidate {
    let keep = keep_for_base(problem.base);
    let ctx = RagbabySearch {
        cipher: problem.cipher,
        nums: problem.nums,
        base: problem.base,
        sign: problem.sign.value(),
        keep: &keep,
        model,
    };
    let (key, _best_sum) = search(&ctx, cfg);
    let decrypt = ctx.decrypt(&key);
    let best_score = model.score_indices(&decrypt);
    let heldout_score = heldout_fold_score(&decrypt, model);

    let (null_mean, null_std) = random_key_null(problem, &keep, cfg, model);
    let margin = best_score - null_mean;
    let z = if null_std > 0.0 {
        margin / null_std
    } else {
        0.0
    };

    let (matched_mean, matched_std, matched_heldout_mean) =
        matched_null(problem, &keep, cfg, model);
    let matched_margin = best_score - matched_mean;
    let matched_z = if matched_std > 0.0 {
        matched_margin / matched_std
    } else {
        0.0
    };

    let round_trip_ok =
        encrypt_indices(&decrypt, problem.nums, &key, ctx.sign, problem.base) == problem.cipher;
    let beats_null = z >= Z_THRESHOLD && margin >= MIN_NAT_MARGIN;
    let beats_matched_null =
        cfg.matched_null_trials > 0 && matched_z >= Z_THRESHOLD && matched_margin >= MIN_NAT_MARGIN;
    // Generalisation gate: the candidate's held-out (odd-index) fold must read more
    // English than the matched null's held-out fold (apples-to-apples). Comparing to
    // the full-stream `matched_mean` instead would falsely fail a true decode, since
    // every-other-letter of English is not itself contiguous English.
    let heldout_ok = cfg.matched_null_trials > 0 && heldout_score > matched_heldout_mean;
    // Survival is the matched null (overfitting) plus the round-trip and held-out
    // checks; the random-keyed-alphabet null is a diagnostic, since Ragbaby has no
    // key-independence leak for it to police.
    let survives = round_trip_ok && beats_matched_null && heldout_ok;

    RagbabyCandidate {
        base: problem.base,
        numbering: problem.numbering,
        sign: problem.sign,
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
        decrypt,
    }
}

/// Cracks one prepared problem, building the English quadgram model internally.
///
/// Prefer [`crack_with_model`] across many hypotheses (build the model once).
///
/// # Errors
/// Returns [`QuadgramError`] if the bundled English quadgram model cannot be built
/// (it should not be in a correct build).
pub fn crack(
    problem: &RagbabyProblem,
    cfg: &RagbabySearchConfig,
) -> Result<RagbabyCandidate, QuadgramError> {
    let model = QuadgramModel::english()?;
    Ok(crack_with_model(problem, cfg, &model))
}

/// Runs only the optimizer (no nulls) and returns the best decryption (plaintext
/// letter indices) for a prepared problem. Used by the planted-recovery control.
#[must_use]
pub fn best_decryption(
    problem: &RagbabyProblem,
    cfg: &RagbabySearchConfig,
    model: &QuadgramModel,
) -> Vec<usize> {
    let keep = keep_for_base(problem.base);
    let ctx = RagbabySearch {
        cipher: problem.cipher,
        nums: problem.nums,
        base: problem.base,
        sign: problem.sign.value(),
        keep: &keep,
        model,
    };
    let (key, _sum) = search(&ctx, cfg);
    ctx.decrypt(&key)
}

// ===========================================================================
// Positive control: planted-recovery length sweep
// ===========================================================================

/// Configuration for the planted-recovery control sweep.
#[derive(Clone, Debug)]
pub struct ControlConfig {
    /// Plaintext letter-lengths to sweep.
    pub lengths: Vec<usize>,
    /// Alphabet bases to sweep.
    pub bases: Vec<usize>,
    /// Planted-recovery trials per `(length, base)` cell.
    pub trials: usize,
    /// Numbering convention used for all planted ciphers.
    pub numbering: Numbering,
    /// Shift sign used for all planted ciphers.
    pub sign: Sign,
    /// Optimizer configuration (the seed seeds the whole sweep).
    pub search: RagbabySearchConfig,
}

/// One `(length, base)` cell of the planted-recovery control sweep.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ControlPoint {
    /// Target plaintext letter-length.
    pub length: usize,
    /// Alphabet base.
    pub base: usize,
    /// Number of planted-recovery trials run.
    pub trials: usize,
    /// Fraction of trials reaching ≥ 0.9 char accuracy versus the known plaintext.
    pub recovery_rate: f64,
    /// Median per-trial char accuracy.
    pub median_acc: f64,
    /// Mean per-trial char accuracy.
    pub mean_acc: f64,
}

/// Splits `corpus` into uppercased ASCII-letter words (runs of letters).
fn corpus_words(corpus: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    for ch in corpus.chars() {
        if ch.is_ascii_alphabetic() {
            current.push(ch.to_ascii_uppercase());
        } else if !current.is_empty() {
            words.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// Draws a contiguous run of `words` whose total letter count first reaches
/// `target_letters`, joined by single spaces (mirrors the Python control chunker).
fn sample_chunk(words: &[String], target_letters: usize, rng: &mut SplitMix64) -> String {
    if words.is_empty() {
        return String::new();
    }
    let upper = words.len().saturating_sub(80).max(1);
    let start = (rng.next_u64() % upper as u64) as usize;
    let mut accumulated: Vec<&str> = Vec::new();
    let mut total = 0usize;
    let mut index = start;
    while total < target_letters && index < words.len() {
        if let Some(word) = words.get(index) {
            total += word.len();
            accumulated.push(word.as_str());
        }
        index += 1;
    }
    accumulated.join(" ")
}

/// Summarizes the per-trial accuracies of one `(length, base)` cell.
fn summarize_control(length: usize, base: usize, accs: &[f64]) -> ControlPoint {
    let trials = accs.len();
    let recovered = accs.iter().filter(|&&acc| acc >= 0.9).count();
    let recovery_rate = if trials == 0 {
        0.0
    } else {
        recovered as f64 / trials as f64
    };
    let mut sorted = accs.to_vec();
    sorted.sort_by(f64::total_cmp);
    let median_acc = crate::null::median_f64(&sorted);
    let mean_acc = if trials == 0 {
        0.0
    } else {
        accs.iter().sum::<f64>() / trials as f64
    };
    ControlPoint {
        length,
        base,
        trials,
        recovery_rate,
        median_acc,
        mean_acc,
    }
}

/// Runs the planted-recovery control sweep: for each `(length, base)`, plant a
/// random-keyed-alphabet Ragbaby of an English excerpt of `corpus`, run the
/// optimizer, and report the recovery rate and accuracy. This is the POSITIVE
/// CONTROL that makes a negative on the real puzzles trustworthy. Deterministic in
/// `control.search.seed`.
#[must_use]
pub fn control_sweep(
    corpus: &str,
    control: &ControlConfig,
    model: &QuadgramModel,
) -> Vec<ControlPoint> {
    let words = corpus_words(corpus);
    let mut master = SplitMix64::new(control.search.seed);
    let mut points = Vec::new();
    for &length in &control.lengths {
        for &base in &control.bases {
            let keep = keep_for_base(base);
            let mut accs: Vec<f64> = Vec::with_capacity(control.trials);
            for _trial in 0..control.trials {
                let plaintext = sample_chunk(&words, length, &mut master);
                let (plain_idx, nums) = prepare(&plaintext, control.numbering, base);
                let planted = random_keyed_alphabet(&keep, &mut master);
                let cipher =
                    encrypt_indices(&plain_idx, &nums, &planted, control.sign.value(), base);
                let cfg = RagbabySearchConfig {
                    seed: master.next_u64(),
                    ..control.search
                };
                let problem = RagbabyProblem {
                    cipher: &cipher,
                    nums: &nums,
                    base,
                    sign: control.sign,
                    numbering: control.numbering,
                };
                let recovered = best_decryption(&problem, &cfg, model);
                accs.push(char_accuracy(&recovered, &plain_idx));
            }
            points.push(summarize_control(length, base, &accs));
        }
    }
    points
}

// ===========================================================================
// Candidate record writer (mirrors keystream::write_keystream_record)
// ===========================================================================

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
fn record_filename(label: &str, candidate: &RagbabyCandidate, seed: u64) -> String {
    format!(
        "ragbaby-{}-base{}-{}-{}-seed-{seed:016x}.md",
        slugify(label),
        candidate.base,
        candidate.numbering.name(),
        candidate.sign.name()
    )
}

/// Renders the candidate-record markdown body (pure; testable without the
/// filesystem). Reproduces [`crate::solve::SOLVE_CLAIM_CEILING`] verbatim so no
/// record can make a stronger claim than the solve pipeline.
fn render_record(
    label: &str,
    seed: u64,
    candidate: &RagbabyCandidate,
) -> Result<String, fmt::Error> {
    use std::fmt::Write as _;
    let mut out = String::new();
    writeln!(out, "# Ragbaby candidate record: {label}")?;
    writeln!(out)?;
    writeln!(
        out,
        "Stable label (NO wall-clock): label={label} seed=0x{seed:016x} base={} numbering={} sign={}",
        candidate.base,
        candidate.numbering.name(),
        candidate.sign.label()
    )?;
    writeln!(out)?;
    writeln!(out, "## Verdict")?;
    writeln!(out)?;
    let verdict = if candidate.survives {
        "CANDIDATE SURVIVED ALL GATES (round-trip + matched-null + held-out) — logged as a HYPOTHESIS, NOT a decode"
    } else {
        "NO surviving candidate — decode remains blocked"
    };
    writeln!(out, "**{verdict}.**")?;
    writeln!(out)?;
    writeln!(out, "## Claim ceiling (absolute)")?;
    writeln!(out)?;
    writeln!(out, "{}", crate::solve::SOLVE_CLAIM_CEILING)?;
    writeln!(
        out,
        "Nothing in this record is stronger. A clean honest negative is a SUCCESS."
    )?;
    writeln!(out)?;
    writeln!(out, "## Gates (never collapsed)")?;
    writeln!(out)?;
    writeln!(
        out,
        "Survival requires the MATCHED null (the same annealed keyed-alphabet search \
         rerun on a Fisher-Yates shuffle of the ciphertext LETTER stream, holding the \
         key-number sequence N_i fixed) plus round-trip and held-out. The matched \
         null shares the search's degrees of freedom, so it polices SEARCH \
         OVERFITTING. The random-keyed-alphabet null is reported as a DIAGNOSTIC only \
         (Ragbaby has no key-independence leak for it to police)."
    )?;
    writeln!(out)?;
    writeln!(out, "- round_trip_ok: {}", candidate.round_trip_ok)?;
    writeln!(out, "- best_score (mean): {:.6}", candidate.best_score)?;
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
        "- null_mean: {:.6}  null_std: {:.6}  z: {:.4}  beats_null [DIAGNOSTIC]: {}",
        candidate.null_mean, candidate.null_std, candidate.z, candidate.beats_null
    )?;
    writeln!(
        out,
        "- heldout_score: {:.6}  matched_heldout_mean: {:.6}  heldout_ok (>): {}",
        candidate.heldout_score, candidate.matched_heldout_mean, candidate.heldout_ok
    )?;
    writeln!(out)?;
    writeln!(out, "## Recovered keyed alphabet (real letter indices)")?;
    writeln!(out)?;
    writeln!(out, "{:?}", candidate.key)?;
    writeln!(out)?;
    writeln!(out, "## Decrypt (HYPOTHESIS, NOT a decode)")?;
    writeln!(out)?;
    writeln!(out, "{}", candidate.render_plaintext())?;
    Ok(out)
}

/// Writes a candidate record (a labelled HYPOTHESIS, never a decode) to `dir`,
/// creating the directory if needed. The filename is stable (label + base +
/// numbering + sign + seed; no wall clock), so re-running overwrites the prior
/// record. Returns the path written.
///
/// # Errors
/// Returns an [`io::Error`] if the directory cannot be created or the file cannot
/// be written.
pub fn write_ragbaby_record(
    dir: &Path,
    label: &str,
    seed: u64,
    candidate: &RagbabyCandidate,
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
        ControlConfig, Numbering, RagbabyCandidate, RagbabyProblem, RagbabySearchConfig, Sign,
        best_decryption, char_accuracy, control_sweep, crack_with_model, decrypt_indices,
        decrypt_str, encrypt_indices, encrypt_str, keep_for_base, key_numbers, prepare,
        random_keyed_alphabet, write_ragbaby_record,
    };
    use crate::null::SplitMix64;
    use crate::quadgram::QuadgramModel;

    // The worked-example keyed alphabet pinning the ACA std-numbering convention.
    const WORKED_KEY: &str = "CRYPTOABDEFGHIJKLMNQSUVWXZ";

    // ~270 letters of plain English prose (real prose, not a slice of the corpus),
    // used where recovery is NOT required (random-text null, determinism).
    const PLAINTEXT: &str = "the quick brown fox jumps over the lazy dog while the morning sun \
        rises slowly above the quiet little village near the river where children often play \
        together after school and the old baker prepares fresh bread for everyone who passes by \
        his small wooden shop on the corner of the street that leads down toward the harbor";

    // ~600 letters of plain English prose for the planted-recovery test. Keyed
    // alphabet recovery sharpens with length, so the longer excerpt recovers
    // reliably at a modest (debug-affordable) search budget.
    const LONG_PLAINTEXT: &str = "the quick brown fox jumps over the lazy dog while the morning \
        sun rises slowly above the quiet little village near the river where children often play \
        together after school and the old baker prepares fresh bread for everyone who passes by \
        his small wooden shop on the corner of the street that leads down toward the harbor where \
        fishing boats return each evening with their heavy nets and the salt wind carries the sound \
        of gulls across the water as families gather along the shore to share warm meals and quiet \
        stories before the early stars appear above the gentle hills that frame the sleepy town in \
        the fading golden light of another calm and ordinary autumn day beside the northern sea";

    #[test]
    fn worked_example_vector_and_round_trip() {
        let ciphertext = encrypt_str("THE CAT", WORKED_KEY, Numbering::Std, Sign::Plus, 26);
        assert_eq!(
            ciphertext, "OJH YED",
            "ACA std worked example must pin to OJH YED"
        );
        let back = decrypt_str(&ciphertext, WORKED_KEY, Numbering::Std, Sign::Plus, 26);
        assert_eq!(back, "THE CAT", "string-form decrypt must round-trip");
    }

    #[test]
    fn round_trip_all_bases() {
        let text = "THE QUICK BROWN FOX JUMPED OVER A VERY LAZY DOG NEAR JADED RIVERS";
        let mut rng = SplitMix64::new(0x00A9_0BA8);
        for &base in &[24usize, 25, 26] {
            let keep = keep_for_base(base);
            let key = random_keyed_alphabet(&keep, &mut rng);
            for &sign in &[Sign::Plus, Sign::Minus] {
                let (plain_idx, nums) = prepare(text, Numbering::Std, base);
                let cipher = encrypt_indices(&plain_idx, &nums, &key, sign.value(), base);
                let back = decrypt_indices(&cipher, &nums, &key, sign.value(), base);
                assert_eq!(
                    back,
                    plain_idx,
                    "index round-trip failed at base {base} sign {}",
                    sign.label()
                );
            }
        }
    }

    #[test]
    fn numbering_conventions_match_documented_sequences() {
        // Two words "THE" (len 3) and "CAT" (len 3).
        let text = "THE CAT";
        assert_eq!(
            key_numbers(text, Numbering::Std),
            vec![1, 2, 3, 2, 3, 4],
            "std: word w, k-th letter -> w + (k - 1)"
        );
        assert_eq!(
            key_numbers(text, Numbering::PerWord),
            vec![1, 2, 3, 1, 2, 3],
            "perword: each word numbered 1.."
        );
        assert_eq!(
            key_numbers(text, Numbering::Continuous),
            vec![1, 2, 3, 4, 5, 6],
            "continuous: 1.. across the whole text"
        );
    }

    #[test]
    fn planted_recovery_recovers_random_alphabet_base26() {
        let model = QuadgramModel::english().unwrap();
        let base = 26usize;
        let (plain_idx, nums) = prepare(LONG_PLAINTEXT, Numbering::Std, base);
        assert!(
            plain_idx.len() >= 200,
            "planted plaintext too short: {}",
            plain_idx.len()
        );
        let keep = keep_for_base(base);
        let mut rng = SplitMix64::new(0x_01A4_7ED0);
        let planted = random_keyed_alphabet(&keep, &mut rng);
        let cipher = encrypt_indices(&plain_idx, &nums, &planted, Sign::Plus.value(), base);
        // Recovery sharpens with length: a ~600-letter planted Ragbaby is recovered
        // by a low-restart anneal (debug-affordable). Nulls disabled — this is a
        // single multi-restart anneal.
        let cfg = RagbabySearchConfig {
            restarts: 8,
            iterations: 6_000,
            basin_hops: 2,
            seed: 0x00C0_FFEE,
            null_trials: 0,
            matched_null_trials: 0,
            ..RagbabySearchConfig::default()
        };
        let problem = RagbabyProblem {
            cipher: &cipher,
            nums: &nums,
            base,
            sign: Sign::Plus,
            numbering: Numbering::Std,
        };
        let recovered = best_decryption(&problem, &cfg, &model);
        let accuracy = char_accuracy(&recovered, &plain_idx);
        assert!(
            accuracy >= 0.9,
            "optimizer recovered only {:.1}% of a planted base-26 Ragbaby",
            accuracy * 100.0
        );
    }

    #[test]
    fn planted_recovery_recovers_reduced_bases() {
        // The base-24/25 real-letter-index path (J->I, V->U folding) is the
        // highest-risk arithmetic; a planted reduced-base Ragbaby must also recover.
        let model = QuadgramModel::english().unwrap();
        for base in [25usize, 24] {
            let (plain_idx, nums) = prepare(LONG_PLAINTEXT, Numbering::Std, base);
            let keep = keep_for_base(base);
            let mut rng = SplitMix64::new(0x_0BA5_E024 ^ base as u64);
            let planted = random_keyed_alphabet(&keep, &mut rng);
            let cipher = encrypt_indices(&plain_idx, &nums, &planted, Sign::Plus.value(), base);
            let cfg = RagbabySearchConfig {
                restarts: 8,
                iterations: 6_000,
                basin_hops: 2,
                seed: 0x00C0_FFEE,
                null_trials: 0,
                matched_null_trials: 0,
                ..RagbabySearchConfig::default()
            };
            let problem = RagbabyProblem {
                cipher: &cipher,
                nums: &nums,
                base,
                sign: Sign::Plus,
                numbering: Numbering::Std,
            };
            let recovered = best_decryption(&problem, &cfg, &model);
            let accuracy = char_accuracy(&recovered, &plain_idx);
            assert!(
                accuracy >= 0.9,
                "optimizer recovered only {:.1}% of a planted base-{base} Ragbaby",
                accuracy * 100.0
            );
        }
    }

    #[test]
    fn planted_decode_survives_full_gate() {
        // The positive control for the GATE itself (not just the optimizer): a
        // planted Ragbaby decode, recovered and run through the full survival gate,
        // MUST survive. Regression test for the held-out miscalibration — comparing
        // the odd-fold to the full-stream `matched_mean` (instead of the matched
        // null's odd-fold) falsely failed even a perfectly recovered decode.
        let model = QuadgramModel::english().unwrap();
        let base = 26usize;
        let (plain_idx, nums) = prepare(LONG_PLAINTEXT, Numbering::Std, base);
        let keep = keep_for_base(base);
        let mut rng = SplitMix64::new(0x_5EED_60D5);
        let planted = random_keyed_alphabet(&keep, &mut rng);
        let cipher = encrypt_indices(&plain_idx, &nums, &planted, Sign::Plus.value(), base);
        let cfg = RagbabySearchConfig {
            restarts: 8,
            iterations: 6_000,
            basin_hops: 2,
            seed: 0x00C0_FFEE,
            null_trials: 16,
            matched_null_trials: 4,
            ..RagbabySearchConfig::default()
        };
        let problem = RagbabyProblem {
            cipher: &cipher,
            nums: &nums,
            base,
            sign: Sign::Plus,
            numbering: Numbering::Std,
        };
        let candidate = crack_with_model(&problem, &cfg, &model);
        assert!(
            candidate.round_trip_ok,
            "round-trip is an algebraic identity"
        );
        assert!(
            candidate.beats_matched_null,
            "planted decode failed matched-null (best={:.3} matched_mean={:.3} matched_z={:.2})",
            candidate.best_score, candidate.matched_mean, candidate.matched_z
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
    fn matched_null_rejects_overfitting_on_random_text() {
        // Pure random ciphertext with real word structure: the search overfits, but
        // the matched null (the same search on a re-shuffled letter stream) overfits
        // just as hard, so the candidate cannot clear the gate.
        let model = QuadgramModel::english().unwrap();
        let base = 26usize;
        let nums = key_numbers(PLAINTEXT, Numbering::Std);
        let mut rng = SplitMix64::new(0x_0ddc_0ffe_e000_5151);
        let cipher: Vec<usize> = (0..nums.len())
            .map(|_| (rng.next_u64() % 26) as usize)
            .collect();
        let cfg = RagbabySearchConfig {
            restarts: 8,
            iterations: 6_000,
            basin_hops: 2,
            seed: 0x00BA_DBED,
            null_trials: 16,
            matched_null_trials: 4,
            ..RagbabySearchConfig::default()
        };
        let problem = RagbabyProblem {
            cipher: &cipher,
            nums: &nums,
            base,
            sign: Sign::Plus,
            numbering: Numbering::Std,
        };
        let candidate = crack_with_model(&problem, &cfg, &model);
        assert!(
            candidate.round_trip_ok,
            "round-trip is an algebraic identity"
        );
        assert!(
            !candidate.beats_matched_null,
            "overfit beat the matched null (best={:.3} matched_mean={:.3} matched_z={:.2})",
            candidate.best_score, candidate.matched_mean, candidate.matched_z
        );
        assert!(
            !candidate.survives,
            "random ciphertext produced a survivor (matched_z={:.2})",
            candidate.matched_z
        );
    }

    #[test]
    fn control_sweep_returns_well_formed_grid() {
        // Fast plumbing smoke: the sweep yields one point per (length, base) with
        // matching fields and accuracies in [0, 1]. Recovery is NOT asserted here
        // (a real recovery needs the heavier budget exercised by the ignored test
        // below); a tiny budget keeps `make verify` fast.
        let model = QuadgramModel::english().unwrap();
        let control = ControlConfig {
            lengths: vec![60, 90],
            bases: vec![26, 24],
            trials: 1,
            numbering: Numbering::Std,
            sign: Sign::Plus,
            search: RagbabySearchConfig {
                restarts: 2,
                iterations: 800,
                basin_hops: 1,
                seed: 0x5_eed,
                null_trials: 0,
                matched_null_trials: 0,
                ..RagbabySearchConfig::default()
            },
        };
        let points = control_sweep(crate::quadgram::ENGLISH_CORPUS_LARGE, &control, &model);
        assert_eq!(points.len(), 4, "one point per (length, base) cell");
        for point in &points {
            assert!(control.lengths.contains(&point.length));
            assert!(control.bases.contains(&point.base));
            assert_eq!(point.trials, 1);
            assert!((0.0..=1.0).contains(&point.recovery_rate));
            assert!((0.0..=1.0).contains(&point.median_acc));
            assert!((0.0..=1.0).contains(&point.mean_acc));
        }
    }

    #[test]
    #[ignore = "heavy positive-control reproduction (~10s); run with cargo test -- --ignored"]
    fn control_sweep_recovers_planted_english_heavy() {
        // The positive control proper: with the validated budget a planted base-26
        // Ragbaby of a real English excerpt is recovered with high accuracy
        // (Python gets 100% at L=274).
        let model = QuadgramModel::english().unwrap();
        let control = ControlConfig {
            lengths: vec![274],
            bases: vec![26],
            trials: 2,
            numbering: Numbering::Std,
            sign: Sign::Plus,
            search: RagbabySearchConfig {
                restarts: 20,
                iterations: 15_000,
                basin_hops: 4,
                seed: 0x5_eed,
                null_trials: 0,
                matched_null_trials: 0,
                ..RagbabySearchConfig::default()
            },
        };
        let points = control_sweep(crate::quadgram::ENGLISH_CORPUS_LARGE, &control, &model);
        let point = points.first().copied().unwrap();
        assert!(
            point.median_acc >= 0.9,
            "planted control median accuracy too low: {:.3}",
            point.median_acc
        );
    }

    #[test]
    fn deterministic_for_fixed_seed() {
        let model = QuadgramModel::english().unwrap();
        let base = 26usize;
        let (plain_idx, nums) = prepare(PLAINTEXT, Numbering::Std, base);
        let keep = keep_for_base(base);
        let mut rng = SplitMix64::new(0x_de7);
        let planted = random_keyed_alphabet(&keep, &mut rng);
        let cipher = encrypt_indices(&plain_idx, &nums, &planted, Sign::Plus.value(), base);
        let cfg = RagbabySearchConfig {
            restarts: 3,
            iterations: 1_500,
            basin_hops: 1,
            seed: 0x0000_0777,
            null_trials: 8,
            matched_null_trials: 2,
            ..RagbabySearchConfig::default()
        };
        let problem = RagbabyProblem {
            cipher: &cipher,
            nums: &nums,
            base,
            sign: Sign::Plus,
            numbering: Numbering::Std,
        };
        let first = crack_with_model(&problem, &cfg, &model);
        let second = crack_with_model(&problem, &cfg, &model);
        assert_eq!(first.key, second.key);
        assert_eq!(first.best_score.to_bits(), second.best_score.to_bits());
        assert_eq!(first.matched_mean.to_bits(), second.matched_mean.to_bits());
        assert_eq!(first.survives, second.survives);
        assert_eq!(first.decrypt, second.decrypt);
    }

    #[test]
    fn record_writer_emits_claim_ceiling() {
        let candidate = RagbabyCandidate {
            base: 26,
            numbering: Numbering::Std,
            sign: Sign::Plus,
            key: vec![0, 1, 2],
            best_score: -10.0,
            null_mean: -14.0,
            null_std: 0.2,
            z: 20.0,
            matched_mean: -12.0,
            matched_std: 0.2,
            matched_z: 10.0,
            round_trip_ok: true,
            heldout_score: -11.0,
            matched_heldout_mean: -13.0,
            beats_null: true,
            beats_matched_null: true,
            heldout_ok: true,
            survives: true,
            decrypt: vec![0, 1, 2],
        };
        let dir = std::env::temp_dir().join(format!("noita-ragbaby-rec-{}", std::process::id()));
        let _removed = std::fs::remove_dir_all(&dir);
        let path = write_ragbaby_record(&dir, "unit", 0x1234, &candidate).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains(crate::solve::SOLVE_CLAIM_CEILING));
        assert!(body.contains("HYPOTHESIS, NOT a decode"));
        assert!(body.contains("base=26"));
        let _cleanup = std::fs::remove_dir_all(&dir);
    }
}

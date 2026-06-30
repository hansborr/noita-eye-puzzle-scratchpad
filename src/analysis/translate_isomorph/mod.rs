//! Translate-isomorph (exact repeated-substring) scanner with a
//! transition-preserving null.
//!
//! A *translate-isomorph* is an exact repeated substring of a symbol stream —
//! the fingerprint a repeated plaintext span leaves in a ciphertext-autokey /
//! group-autokey (GAK) cipher, or directly in a transparent channel. Unlike the
//! gap-pattern signatures of [`crate::analysis::isomorph`] (which are invariant
//! under substitution), this finds *literal* repeats, optionally after a modular
//! finite-difference projection `d[i] = (v[i+1] - v[i]) mod m`. That projection
//! is mapping-independent (a global symbol offset cancels) and exposes the
//! repeats of an additive-walk / autokey plaintext: on practice puzzle `two`
//! (`A..L`, the `mod 3` rotor channel) the projected stream carries a length-68
//! exact repeat — about 34 repeated plaintext letters — that no
//! transition-preserving null reaches.
//!
//! ## Honesty discipline (binding — see `AGENTS.md`)
//!
//! A reported anchor is a **structural candidate, never a decode**. Its only
//! claim is "this span repeats more than the matched null explains"; it locates
//! *where* a message repeats, which can seed a crib / known-plaintext attack, but
//! it does not recover plaintext. The matched null is an **order-1 Markov
//! resample of the (projected) stream**, which preserves the first-order
//! transition law — so an anchor that clears it is repeat structure *beyond*
//! first-order chaining, not the transition law itself (the failure mode a
//! Fisher-Yates shuffle would miss). The bounded null states its trial count; it
//! does not prove the repeat is plaintext.

use std::collections::HashMap;
use std::fmt;

use crate::nulls::null::{RandomBoundError, SplitMix64, add_one_p_value, random_index_below};

#[cfg(test)]
mod tests;

/// Minimum projected-stream length the scanner accepts.
const MIN_STREAM_LEN: usize = 4;
/// Floor on the anchor-significance threshold, so a near-degenerate null floor
/// never lets length-1/2/3 coincidences be reported as anchors.
const MIN_ANCHOR_LEN: usize = 4;
/// Polynomial rolling-hash base (hash collisions are always verified by a direct
/// slice comparison, so the base only affects speed, never correctness).
const HASH_BASE: u64 = 1_000_003;

/// An error from the translate-isomorph scanner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IsoScanError {
    /// The (projected) stream is shorter than the minimum scannable length.
    StreamTooShort {
        /// Projected-stream length actually available.
        length: usize,
    },
    /// A difference modulus of zero was requested.
    ZeroModulus,
    /// A difference modulus larger than the alphabet was requested. Such a
    /// modulus adds no cyclic structure (the symbols never wrap) yet inflates the
    /// matched-null alphabet, so it is rejected rather than scanned.
    ModulusTooLarge {
        /// The requested difference modulus.
        modulus: usize,
        /// The alphabet size it may not exceed.
        alphabet_size: usize,
    },
    /// The declared alphabet size was zero.
    EmptyAlphabet,
    /// An in-crate random draw rejected its bound (unreachable for the bounds
    /// used here, which are validated non-zero before the draw).
    RandomDraw {
        /// The rejected draw bound.
        bound: usize,
    },
}

impl From<RandomBoundError> for IsoScanError {
    fn from(error: RandomBoundError) -> Self {
        Self::RandomDraw { bound: error.bound }
    }
}

impl fmt::Display for IsoScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StreamTooShort { length } => write!(
                f,
                "stream too short: need at least {MIN_STREAM_LEN} symbols after projection, have {length}"
            ),
            Self::ZeroModulus => write!(f, "difference modulus must be non-zero"),
            Self::ModulusTooLarge {
                modulus,
                alphabet_size,
            } => write!(
                f,
                "difference modulus {modulus} exceeds the alphabet size {alphabet_size}"
            ),
            Self::EmptyAlphabet => write!(f, "alphabet size must be non-zero"),
            Self::RandomDraw { bound } => write!(f, "random draw rejected bound {bound}"),
        }
    }
}

impl std::error::Error for IsoScanError {}

/// One exact repeated substring (translate-isomorph): the two start positions in
/// the projected stream and the repeat length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepeatAnchor {
    /// Repeat length, in projected-stream symbols.
    pub length: usize,
    /// First (smaller) start position in the projected stream.
    pub first: usize,
    /// Second (larger) start position in the projected stream.
    pub second: usize,
    /// Translation distance `second - first`.
    pub gap: usize,
}

/// Result of a translate-isomorph scan: the observed longest repeat, the
/// significant anchors, and the transition-preserving null calibration.
#[derive(Clone, Debug, PartialEq)]
pub struct IsoScanReport {
    /// Length of the input stream (before projection).
    pub input_len: usize,
    /// Declared input alphabet size.
    pub alphabet_size: usize,
    /// Difference modulus applied, if any (`None` = raw stream).
    pub delta_mod: Option<usize>,
    /// Length of the projected stream actually scanned.
    pub projected_len: usize,
    /// Alphabet size of the projected stream (`delta_mod` if projected).
    pub projected_alphabet: usize,
    /// Longest exact repeat length observed in the projected stream.
    pub observed_max: usize,
    /// Significant anchors (length strictly above the null ceiling), longest first.
    pub anchors: Vec<RepeatAnchor>,
    /// Number of matched-null trials run.
    pub null_trials: usize,
    /// Mean longest-repeat length across the null trials.
    pub null_max_mean: f64,
    /// Largest longest-repeat length any null trial reached (the significance
    /// ceiling anchors must clear).
    pub null_max_ceiling: usize,
    /// Add-one p-value: fraction of null trials whose longest repeat reached the
    /// observed maximum.
    pub p_value: f64,
    /// Whether the observed maximum clears every null trial (a structural
    /// candidate, not a decode).
    pub significant: bool,
}

/// Projects `values` to the scanned stream: the modular finite difference
/// `d[i] = (values[i+1] - values[i]) mod m` when `delta_mod` is `Some(m)`, else
/// the raw values widened to `u32`.
fn project(values: &[u16], delta_mod: Option<usize>) -> Result<Vec<u32>, IsoScanError> {
    match delta_mod {
        Some(0) => Err(IsoScanError::ZeroModulus),
        Some(m) => {
            // `u64` so `b + modulus` cannot overflow for any modulus that survives
            // the `iso_scan` bound check (the caller caps it at the alphabet size).
            let modulus = u64::try_from(m).unwrap_or(u64::MAX);
            let mut out = Vec::with_capacity(values.len().saturating_sub(1));
            for pair in values.windows(2) {
                if let [a, b] = pair {
                    let a = u64::from(*a) % modulus;
                    let b = u64::from(*b) % modulus;
                    let diff = (b + modulus - a) % modulus;
                    out.push(u32::try_from(diff).unwrap_or(0));
                }
            }
            Ok(out)
        }
        None => Ok(values.iter().map(|&v| u32::from(v)).collect()),
    }
}

/// Precomputed prefix hashes and base powers for `O(1)` window hashing.
struct RollingHash {
    prefix: Vec<u64>,
    power: Vec<u64>,
}

impl RollingHash {
    fn new(stream: &[u32]) -> Self {
        let mut prefix = Vec::with_capacity(stream.len() + 1);
        let mut power = Vec::with_capacity(stream.len() + 1);
        prefix.push(0u64);
        power.push(1u64);
        for &symbol in stream {
            let last_prefix = prefix.last().copied().unwrap_or(0);
            let last_power = power.last().copied().unwrap_or(1);
            // `+ 1` so a leading run of symbol 0 does not collapse to hash 0.
            prefix.push(
                last_prefix
                    .wrapping_mul(HASH_BASE)
                    .wrapping_add(u64::from(symbol) + 1),
            );
            power.push(last_power.wrapping_mul(HASH_BASE));
        }
        Self { prefix, power }
    }

    /// Hash of `stream[start..start + len]`.
    fn window(&self, start: usize, len: usize) -> u64 {
        let end = self.prefix.get(start + len).copied().unwrap_or(0);
        let begin = self.prefix.get(start).copied().unwrap_or(0);
        let power = self.power.get(len).copied().unwrap_or(0);
        end.wrapping_sub(begin.wrapping_mul(power))
    }
}

/// Returns `true` if some length-`len` substring of `stream` occurs at least
/// twice. Hash collisions are verified by a direct slice comparison.
fn has_repeat_of_len(stream: &[u32], hash: &RollingHash, len: usize) -> bool {
    if len == 0 || len > stream.len() {
        return false;
    }
    let mut seen: HashMap<u64, Vec<usize>> = HashMap::new();
    let last_start = stream.len() - len;
    for start in 0..=last_start {
        let key = hash.window(start, len);
        let current = stream.get(start..start + len);
        let bucket = seen.entry(key).or_default();
        if bucket
            .iter()
            .any(|&other| stream.get(other..other + len) == current)
        {
            return true;
        }
        bucket.push(start);
    }
    false
}

/// Longest exact repeated substring length, via binary search over the
/// repeat-existence predicate (monotone in length).
fn longest_repeat_len(stream: &[u32], hash: &RollingHash) -> usize {
    let mut lo = 0usize;
    let mut hi = stream.len();
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if has_repeat_of_len(stream, hash, mid) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

/// Finds the longest exact repeats of length `>= threshold`, longest first,
/// deduplicating nested sub-repeats (a shorter same-gap repeat contained inside a
/// longer one). Returns at most `top_k` anchors; `top_k == 0` suppresses anchor
/// enumeration entirely (the significance verdict still stands).
///
/// Exposed to the crate so the [`super::group_order`] element-order discriminator
/// can enumerate difference-channel anchors directly, on a length threshold,
/// without routing through [`iso_scan`]'s significance verdict (which is a
/// separate question the discriminator does not need answered).
pub(crate) fn find_anchors(stream: &[u32], threshold: usize, top_k: usize) -> Vec<RepeatAnchor> {
    if top_k == 0 || threshold == 0 || threshold > stream.len() {
        return Vec::new();
    }
    let n = stream.len();
    let mut suffixes: Vec<usize> = (0..n).collect();
    suffixes.sort_by(|&a, &b| stream.get(a..).cmp(&stream.get(b..)));
    let mut candidates: Vec<RepeatAnchor> = Vec::new();
    for pair in suffixes.windows(2) {
        let [a, b] = pair else { continue };
        let (a, b) = (*a, *b);
        let mut lcp = 0usize;
        while let (Some(x), Some(y)) = (stream.get(a + lcp), stream.get(b + lcp)) {
            if x != y {
                break;
            }
            lcp += 1;
        }
        if lcp >= threshold {
            let (first, second) = if a <= b { (a, b) } else { (b, a) };
            candidates.push(RepeatAnchor {
                length: lcp,
                first,
                second,
                gap: second - first,
            });
        }
    }
    candidates.sort_by(|x, y| y.length.cmp(&x.length).then_with(|| x.gap.cmp(&y.gap)));
    let mut kept: Vec<RepeatAnchor> = Vec::new();
    for cand in candidates {
        let nested = kept.iter().any(|k| {
            k.gap == cand.gap
                && k.first <= cand.first
                && cand.first + cand.length <= k.first + k.length
        });
        if !nested {
            kept.push(cand);
            if kept.len() >= top_k {
                break;
            }
        }
    }
    kept
}

/// Order-1 Markov resample of `stream` over `alphabet`: keeps the first symbol,
/// then draws each next symbol from the empirical `P(next | current)`. This
/// preserves the first-order transition law while destroying longer repeats — the
/// matched null an anchor must clear.
///
/// Exposed to the crate so [`super::key_difference`] can calibrate its gap-pattern
/// isomorph certificate against the very same order-1 Markov null the additive
/// difference channels use.
pub(crate) fn markov_resample(
    stream: &[u32],
    alphabet: usize,
    rng: &mut SplitMix64,
) -> Result<Vec<u32>, IsoScanError> {
    if alphabet == 0 {
        return Err(IsoScanError::EmptyAlphabet);
    }
    // counts[a] = successors observed after symbol `a`.
    let mut counts: Vec<Vec<u32>> = vec![Vec::new(); alphabet];
    for pair in stream.windows(2) {
        if let [cur, next] = pair
            && let Some(bucket) = counts.get_mut(*cur as usize)
        {
            bucket.push(*next);
        }
    }
    let mut out = Vec::with_capacity(stream.len());
    let first = stream.first().copied().unwrap_or(0);
    out.push(first);
    for _ in 1..stream.len() {
        let cur = out.last().copied().unwrap_or(first) as usize;
        let bucket = counts.get(cur).filter(|b| !b.is_empty());
        let next = match bucket {
            Some(succ) => {
                let pick = random_index_below(succ.len(), rng)?;
                succ.get(pick).copied().unwrap_or(first)
            }
            // A symbol seen only as the final element has no successor; fall back
            // to a uniform draw over the declared alphabet so the chain continues.
            None => u32::try_from(random_index_below(alphabet, rng)?).unwrap_or(0),
        };
        out.push(next);
    }
    Ok(out)
}

/// Default number of matched-null trials.
pub const DEFAULT_NULL_TRIALS: usize = 200;
/// Default maximum number of anchors reported.
pub const DEFAULT_TOP_K: usize = 8;
/// Default deterministic seed for the matched null.
pub const DEFAULT_SEED: u64 = 0x6973_6f73_6361_6e01;

/// Scans `values` for translate-isomorphs (exact repeats), optionally on the
/// `delta_mod` difference channel, and calibrates the longest repeat against an
/// order-1 Markov null.
///
/// `values` are alphabet indices (`0..alphabet_size`). The report's anchors are a
/// **structural candidate, never a decode** (see the module honesty note).
///
/// # Errors
/// Returns [`IsoScanError`] if `alphabet_size` is zero, `delta_mod` is `Some(0)`,
/// or the projected stream is shorter than the minimum scannable length.
pub fn iso_scan(
    values: &[u16],
    alphabet_size: usize,
    delta_mod: Option<usize>,
    top_k: usize,
    null_trials: usize,
    seed: u64,
) -> Result<IsoScanReport, IsoScanError> {
    if alphabet_size == 0 {
        return Err(IsoScanError::EmptyAlphabet);
    }
    if let Some(modulus) = delta_mod {
        if modulus == 0 {
            return Err(IsoScanError::ZeroModulus);
        }
        if modulus > alphabet_size {
            return Err(IsoScanError::ModulusTooLarge {
                modulus,
                alphabet_size,
            });
        }
    }
    let stream = project(values, delta_mod)?;
    if stream.len() < MIN_STREAM_LEN {
        return Err(IsoScanError::StreamTooShort {
            length: stream.len(),
        });
    }
    let projected_alphabet = delta_mod.unwrap_or(alphabet_size);
    let hash = RollingHash::new(&stream);
    let observed_max = longest_repeat_len(&stream, &hash);

    let mut rng = SplitMix64::new(seed);
    let mut null_sum = 0u64;
    let mut null_ceiling = 0usize;
    let mut reached = 0usize;
    for _ in 0..null_trials {
        let resampled = markov_resample(&stream, projected_alphabet, &mut rng)?;
        let resampled_hash = RollingHash::new(&resampled);
        let trial_max = longest_repeat_len(&resampled, &resampled_hash);
        null_sum += trial_max as u64;
        null_ceiling = null_ceiling.max(trial_max);
        if trial_max >= observed_max {
            reached += 1;
        }
    }
    let null_max_mean = if null_trials == 0 {
        0.0
    } else {
        null_sum as f64 / null_trials as f64
    };
    let p_value = add_one_p_value(reached, null_trials);
    let significant = null_trials > 0 && observed_max > null_ceiling;

    let threshold = (null_ceiling + 1).max(MIN_ANCHOR_LEN);
    let anchors = if significant {
        find_anchors(&stream, threshold, top_k)
    } else {
        Vec::new()
    };

    Ok(IsoScanReport {
        input_len: values.len(),
        alphabet_size,
        delta_mod,
        projected_len: stream.len(),
        projected_alphabet,
        observed_max,
        anchors,
        null_trials,
        null_max_mean,
        null_max_ceiling: null_ceiling,
        p_value,
        significant,
    })
}

/// Self-test outcome: a planted exact repeat must be recovered while the matched
/// null does not reach it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IsoScanSelfTest {
    /// Length of the planted exact repeat.
    pub planted_len: usize,
    /// Longest repeat the scanner recovered.
    pub recovered_len: usize,
    /// Largest repeat any null trial reached.
    pub null_max_ceiling: usize,
    /// Whether the planted repeat was recovered and clears the null ceiling.
    pub passed: bool,
}

/// Planted length for the self-test repeat.
const SELF_TEST_PLANT_LEN: usize = 30;
/// Base-stream length for the self-test.
const SELF_TEST_STREAM_LEN: usize = 400;
/// Base alphabet for the self-test stream.
const SELF_TEST_ALPHABET: usize = 4;

/// Runs the in-process positive control: build a random small-alphabet stream,
/// plant one fixed-length exact repeat, and confirm the scanner recovers a repeat
/// at least that long while the matched null stays below it. A `passed: false`
/// report is an instrument failure, never a finding.
///
/// # Errors
/// Returns [`IsoScanError`] if the underlying scan fails (it should not on the
/// constructed input).
pub fn iso_scan_self_test(seed: u64) -> Result<IsoScanSelfTest, IsoScanError> {
    let mut rng = SplitMix64::new(seed);
    let mut stream: Vec<u16> = Vec::with_capacity(SELF_TEST_STREAM_LEN);
    for _ in 0..SELF_TEST_STREAM_LEN {
        stream.push(u16::try_from(random_index_below(SELF_TEST_ALPHABET, &mut rng)?).unwrap_or(0));
    }
    // Plant an exact repeat: copy a block near the front to a location near the
    // back, far enough apart that the two copies do not overlap.
    let src = 20usize;
    let dst = SELF_TEST_STREAM_LEN - SELF_TEST_PLANT_LEN - 20;
    let block: Vec<u16> = stream
        .get(src..src + SELF_TEST_PLANT_LEN)
        .map(<[u16]>::to_vec)
        .unwrap_or_default();
    if let Some(slot) = stream.get_mut(dst..dst + SELF_TEST_PLANT_LEN) {
        slot.copy_from_slice(&block);
    }

    let report = iso_scan(
        &stream,
        SELF_TEST_ALPHABET,
        None,
        DEFAULT_TOP_K,
        DEFAULT_NULL_TRIALS,
        seed ^ 0x5a5a_5a5a_5a5a_5a5a,
    )?;
    let passed =
        report.observed_max >= SELF_TEST_PLANT_LEN && report.null_max_ceiling < SELF_TEST_PLANT_LEN;
    Ok(IsoScanSelfTest {
        planted_len: SELF_TEST_PLANT_LEN,
        recovered_len: report.observed_max,
        null_max_ceiling: report.null_max_ceiling,
        passed,
    })
}

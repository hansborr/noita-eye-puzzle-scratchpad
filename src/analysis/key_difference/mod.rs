//! Thread B: the isomorph **key-difference** discriminator.
//!
//! # What it measures
//!
//! `CodeWarrior0`'s isomorph theorem states that a relabelled ciphertext repeat
//! (an isomorph) appears between two occurrences of the same plaintext **iff**
//! the two occurrences' keystreams differ by a *constant* — the signature of
//! ciphertext-autokey / progressive-alphabet / Wadsworth ciphers. The
//! [`super::group_order`] discriminator (`groupscan`) recovers the relabelling
//! *permutation* `π` between aligned isomorph occurrences and classifies it by
//! cycle type. Thread B recovers the same relabelling's *additive realisation*
//! `Δ` and classifies it by **finite-difference order**.
//!
//! For two equal-length windows at starts `a`, `b`, the per-position key
//! difference is `Δ[j] = (c[b+j] − c[a+j]) mod m`. Its finite-difference order is
//! read off the difference channels of the whole stream, because:
//!
//! - `Δ ≡ 0` (identical key) ⟺ an **exact repeat on the raw stream** (order 0);
//! - `Δ` *constant* (classical autokey / Wadsworth / progressive) ⟺ an exact
//!   repeat on the **1st-difference channel** `d[i] = (c[i+1]−c[i]) mod m`
//!   (order 1), since a constant offset cancels under one differencing;
//! - `Δ` *linear* (accelerating progressive) ⟺ an exact repeat on the
//!   **2nd-difference channel** (order 2).
//!
//! So the verdict is the **lowest finite-difference order `k`** at which an exact
//! repeat fires *significantly* (clearing the order-1 Markov matched null — the
//! `isoscan` significance test, reused here, not eyeballed). When a relabelled
//! repeat demonstrably exists (a gap-pattern isomorph certificate from
//! [`detect_isomorphs`]) but **no** additive order fires up to the scanned ceiling,
//! the relabelling is non-additive — a deck / GAK / self-modifying keystream.
//!
//! Within the constant (`k = 1`) bucket, a secondary modular regression of the
//! per-pair additive offset `δ` on the translation gap `g` splits the autokey
//! family: a single shared slope `δ ≡ r·g (mod m)` across distinct gaps is
//! progressive-alphabet; a content-driven `δ` independent of `g` is classical
//! autokey.
//!
//! # Honesty ceiling (binding — see `AGENTS.md`)
//!
//! This is a **structural discriminator, not a decode**. It reports the additive
//! order of the keystream difference behind an isomorph; it never recovers
//! plaintext. Every order's firing is gated against the matched null, and the
//! `Irregular` verdict additionally requires the gap-pattern isomorph certificate
//! so an *absence* of additive structure is never reported as a positive deck
//! claim on a structureless stream.

use crate::analysis::isomorph::detect_isomorphs;
use crate::analysis::translate_isomorph::{IsoScanError, RepeatAnchor, iso_scan};
use crate::nulls::null::{RandomBoundError, mix_seed};

mod control;
#[cfg(test)]
mod tests;

/// Default highest finite-difference order scanned (orders `0..=MAX`).
pub const DEFAULT_MAX_ORDER: usize = 3;
/// Default minimum exact-repeat length (channel symbols) that counts as a firing.
pub const DEFAULT_MIN_ANCHOR_LEN: usize = 8;
/// Default maximum number of anchors enumerated per difference channel.
pub const DEFAULT_TOP_K: usize = 8;
/// Default order-1 Markov matched-null trial count per difference channel.
pub const DEFAULT_NULL_TRIALS: usize = 200;
/// Default deterministic seed (`"keydiff\u{1}"` little-endian-ish tag).
pub const DEFAULT_SEED: u64 = 0x6b65_7964_6966_6601;

/// Shortest channel the per-order scan will hand to [`iso_scan`] (its floor).
const MIN_CHANNEL_LEN: usize = 4;

/// Error returned by the key-difference discriminator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyDiffError {
    /// The declared alphabet size was zero.
    EmptyAlphabet,
    /// The input stream had fewer than two symbols (no difference channel).
    StreamTooShort {
        /// Number of input symbols available.
        length: usize,
    },
    /// A per-order [`iso_scan`] call failed.
    Channel(IsoScanError),
    /// A Monte-Carlo draw bound did not fit the PRNG helper (controls only).
    RandomBound {
        /// Requested exclusive upper bound.
        bound: usize,
    },
    /// A self-test control could not be constructed or scanned.
    SelfTestFailed,
}

impl From<IsoScanError> for KeyDiffError {
    fn from(error: IsoScanError) -> Self {
        Self::Channel(error)
    }
}

impl From<RandomBoundError> for KeyDiffError {
    fn from(error: RandomBoundError) -> Self {
        Self::RandomBound { bound: error.bound }
    }
}

impl std::fmt::Display for KeyDiffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyAlphabet => write!(f, "the declared alphabet is empty"),
            Self::StreamTooShort { length } => {
                write!(
                    f,
                    "input stream too short ({length} symbols); need at least 2"
                )
            }
            Self::Channel(error) => write!(f, "difference-channel scan failed: {error}"),
            Self::RandomBound { bound } => write!(f, "random draw bound {bound} is too large"),
            Self::SelfTestFailed => write!(f, "key-difference self-test failed"),
        }
    }
}

impl std::error::Error for KeyDiffError {}

/// The autokey family inside the constant-`Δ` (`k = 1`) bucket, decided by the
/// modular regression of the per-pair additive offset `δ` on the gap `g`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AutokeyFamily {
    /// A single shared slope `δ ≡ r·g (mod m)` fits every pair across at least two
    /// distinct gaps: the keystream advances by a fixed step per position
    /// (progressive-alphabet / Wadsworth).
    ProgressiveAlphabet {
        /// The recovered shared slope `r`.
        slope: usize,
    },
    /// The per-pair offset is content-driven — no single slope explains the
    /// observed `(g, δ)` pairs: classical (plaintext/ciphertext) autokey.
    ClassicalAutokey,
    /// Only one distinct gap was observed, so the slope is underdetermined and the
    /// family cannot be separated. Constant `Δ` is still established.
    SingleGap,
}

/// The discriminator verdict: the additive order of the keystream difference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyDiffVerdict {
    /// Order 0: a raw exact repeat — the two occurrences share the same key
    /// (`Δ ≡ 0`), e.g. Vigenère with the gap a period multiple.
    IdenticalKey,
    /// Order 1: a constant additive `Δ` — classical autokey / Wadsworth /
    /// progressive-alphabet, split further by `family`.
    ConstantAdditive {
        /// The autokey family from the `δ`-versus-gap regression.
        family: AutokeyFamily,
    },
    /// Order 2: a linear additive `Δ` — an accelerating progressive keystream.
    LinearAdditive,
    /// Order `k ≥ 3`: a higher-order polynomial additive `Δ`.
    HigherOrderAdditive {
        /// The lowest firing finite-difference order.
        order: usize,
    },
    /// A gap-pattern isomorph certificate exists (a relabelled repeat is present)
    /// but **no** additive order fired up to the scanned ceiling: the relabelling
    /// is non-additive — a deck / GAK / self-modifying keystream.
    Irregular,
    /// No additive order fired and no gap-pattern isomorph certificate was found:
    /// no relabelled-repeat structure to classify. Not evidence of any family.
    NoSignal,
}

/// One difference channel's firing record.
#[derive(Clone, Debug, PartialEq)]
pub struct OrderFiring {
    /// Finite-difference order of this channel (`0` = raw stream).
    pub order: usize,
    /// Length of the channel actually scanned.
    pub channel_len: usize,
    /// Longest exact repeat observed in the channel.
    pub observed_max: usize,
    /// Largest repeat any matched-null trial reached (the significance ceiling).
    pub null_ceiling: usize,
    /// Add-one p-value of the observed maximum versus the matched null.
    pub p_value: f64,
    /// Whether the observed maximum cleared every null trial.
    pub significant: bool,
    /// Whether this order fired: significant **and** long enough to count
    /// (`observed_max >= min_anchor_len`).
    pub fired: bool,
    /// Significant exact-repeat anchors enumerated in this channel, longest first.
    pub anchors: Vec<RepeatAnchor>,
}

/// The modular regression of the per-pair additive offset `δ` on the gap `g`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegressionFit {
    /// Number of `(gap, δ)` samples (one per constant-`Δ` anchor).
    pub pairs: usize,
    /// Number of distinct gap values among the samples.
    pub distinct_gaps: usize,
    /// The slope `r` that satisfies `δ ≡ r·g (mod m)` for the most samples.
    pub best_slope: usize,
    /// How many samples that best slope satisfies.
    pub consistent_pairs: usize,
}

/// Complete key-difference discriminator report.
#[derive(Clone, Debug, PartialEq)]
pub struct KeyDiffReport {
    /// Length of the input stream.
    pub input_len: usize,
    /// Declared alphabet size `m`.
    pub alphabet_size: usize,
    /// Highest finite-difference order scanned.
    pub max_order: usize,
    /// Minimum exact-repeat length that counts as a firing.
    pub min_anchor_len: usize,
    /// Per-order firing records (order 0 first).
    pub firings: Vec<OrderFiring>,
    /// The lowest finite-difference order that fired, if any.
    pub fired_order: Option<usize>,
    /// Whether a gap-pattern isomorph certificate was found on the raw stream.
    pub gap_isomorph_present: bool,
    /// The `δ`-versus-gap regression, present only for a constant-`Δ` verdict.
    pub regression: Option<RegressionFit>,
    /// The discriminator verdict.
    pub verdict: KeyDiffVerdict,
}

/// Outcome of the in-process self-test (planted controls + matched null).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "one independent pass/fail flag per control; a flat record is clearest"
)]
pub struct KeyDiffSelfTest {
    /// A ciphertext-autokey stream with a planted repeat classifies `k = 1`.
    pub ctak_constant: bool,
    /// A Vigenère stream with a period-multiple gap classifies `k = 0`.
    pub vigenere_identical: bool,
    /// A planted additive-progressive stream classifies `k = 1` and the regression
    /// reads it as progressive-alphabet.
    pub progressive_family: bool,
    /// A planted non-additive deck relabel (a fixed permutation applied to the
    /// second phrase occurrence) classifies `Irregular`.
    pub deck_irregular: bool,
    /// The matched null does not reach the constant-`Δ` controls, and the deck
    /// control exhibits no significant additive firing.
    pub null_agreement: bool,
    /// All checks passed.
    pub passed: bool,
}

/// Runs the finite-difference key-difference discriminator on a symbol stream.
///
/// `values` are alphabet indices (`0..alphabet_size`). For each order
/// `0..=max_order` the modular `k`-th finite-difference channel is scanned for an
/// exact repeat, gated by [`iso_scan`]'s order-1 Markov matched null; the verdict
/// is the lowest order that fires (`observed_max >= min_anchor_len` and
/// significant). With no additive firing the gap-pattern isomorph certificate
/// decides `Irregular` versus `NoSignal`.
///
/// # Errors
/// Returns [`KeyDiffError`] when the alphabet is empty, the stream is shorter than
/// two symbols, or a per-order [`iso_scan`] call fails.
pub fn key_difference_scan(
    values: &[u16],
    alphabet_size: usize,
    max_order: usize,
    min_anchor_len: usize,
    top_k: usize,
    null_trials: usize,
    seed: u64,
) -> Result<KeyDiffReport, KeyDiffError> {
    if alphabet_size == 0 {
        return Err(KeyDiffError::EmptyAlphabet);
    }
    if values.len() < 2 {
        return Err(KeyDiffError::StreamTooShort {
            length: values.len(),
        });
    }

    let raw: Vec<u16> = values
        .iter()
        .map(|&v| u16::try_from(usize::from(v) % alphabet_size).unwrap_or(0))
        .collect();

    let mut firings: Vec<OrderFiring> = Vec::with_capacity(max_order + 1);
    for order in 0..=max_order {
        let channel = difference_channel(&raw, alphabet_size, order);
        if channel.len() < MIN_CHANNEL_LEN {
            break;
        }
        let report = iso_scan(
            &channel,
            alphabet_size,
            None,
            top_k,
            null_trials,
            mix_seed(seed, order as u64),
        )?;
        let fired = report.significant && report.observed_max >= min_anchor_len;
        firings.push(OrderFiring {
            order,
            channel_len: report.projected_len,
            observed_max: report.observed_max,
            null_ceiling: report.null_max_ceiling,
            p_value: report.p_value,
            significant: report.significant,
            fired,
            anchors: report.anchors,
        });
    }

    let fired_order = lowest_fired_order(&firings);
    let regression = if fired_order == Some(1) {
        let order1_anchors = firings
            .iter()
            .find(|firing| firing.order == 1)
            .map_or(&[][..], |firing| firing.anchors.as_slice());
        Some(fit_regression(&raw, alphabet_size, order1_anchors))
    } else {
        None
    };
    let gap_isomorph_present = gap_pattern_certificate(&raw, min_anchor_len);
    let verdict = verdict_from(fired_order, regression.as_ref(), gap_isomorph_present);

    Ok(KeyDiffReport {
        input_len: values.len(),
        alphabet_size,
        max_order,
        min_anchor_len,
        firings,
        fired_order,
        gap_isomorph_present,
        regression,
        verdict,
    })
}

/// Runs the in-process self-test: planted ciphertext-autokey, Vigenère,
/// additive-progressive, and non-commutative dihedral GAK controls, each gated
/// against the matched null.
///
/// # Errors
/// Returns [`KeyDiffError`] if a control stream cannot be built or scanned.
pub fn key_difference_self_test(seed: u64) -> Result<KeyDiffSelfTest, KeyDiffError> {
    control::self_test(seed)
}

/// The modular `order`-th finite difference of `values` over `Z_modulus`.
///
/// Order 0 is the raw stream reduced modulo `modulus`; each subsequent order
/// applies `d[i] = (v[i+1] − v[i]) mod modulus`, shrinking the length by one. A
/// global additive offset cancels under one differencing, which is exactly why a
/// constant key difference surfaces as an exact repeat on the order-1 channel.
fn difference_channel(values: &[u16], modulus: usize, order: usize) -> Vec<u16> {
    let m = u32::try_from(modulus).unwrap_or(1).max(1);
    let mut channel: Vec<u32> = values.iter().map(|&v| u32::from(v) % m).collect();
    for _ in 0..order {
        let mut next = Vec::with_capacity(channel.len().saturating_sub(1));
        for pair in channel.windows(2) {
            if let [a, b] = pair {
                next.push((b + m - (a % m)) % m);
            }
        }
        channel = next;
    }
    channel
        .iter()
        .map(|&x| u16::try_from(x).unwrap_or(0))
        .collect()
}

/// The lowest order among `firings` that fired, if any.
fn lowest_fired_order(firings: &[OrderFiring]) -> Option<usize> {
    firings
        .iter()
        .filter(|firing| firing.fired)
        .map(|firing| firing.order)
        .min()
}

/// Fits the modular `δ ≡ r·g (mod m)` regression over the constant-`Δ` anchors.
///
/// For each order-1 anchor the constant offset is `δ = (c[second] − c[first]) mod
/// m` and the gap is `second − first`. The best slope is the `r ∈ 0..m`
/// satisfying the relation for the most samples (the alphabet is small, so the
/// brute-force search is cheap).
fn fit_regression(values: &[u16], modulus: usize, anchors: &[RepeatAnchor]) -> RegressionFit {
    let m = modulus.max(1);
    let mut samples: Vec<(usize, usize)> = Vec::new();
    for anchor in anchors {
        let (Some(&first), Some(&second)) = (values.get(anchor.first), values.get(anchor.second))
        else {
            continue;
        };
        let delta = (usize::from(second) + m - (usize::from(first) % m)) % m;
        samples.push((anchor.gap, delta));
    }
    let pairs = samples.len();
    let mut gaps: Vec<usize> = samples.iter().map(|(gap, _delta)| *gap).collect();
    gaps.sort_unstable();
    gaps.dedup();
    let distinct_gaps = gaps.len();

    let mut best_slope = 0usize;
    let mut consistent_pairs = 0usize;
    for r in 0..m {
        let consistent = samples
            .iter()
            .filter(|(gap, delta)| (r * gap) % m == delta % m)
            .count();
        if consistent > consistent_pairs {
            consistent_pairs = consistent;
            best_slope = r;
        }
    }
    RegressionFit {
        pairs,
        distinct_gaps,
        best_slope,
        consistent_pairs,
    }
}

/// Reads the autokey family from the regression fit.
fn autokey_family(fit: &RegressionFit) -> AutokeyFamily {
    if fit.pairs == 0 || fit.distinct_gaps < 2 {
        AutokeyFamily::SingleGap
    } else if fit.consistent_pairs == fit.pairs {
        AutokeyFamily::ProgressiveAlphabet {
            slope: fit.best_slope,
        }
    } else {
        AutokeyFamily::ClassicalAutokey
    }
}

/// Builds the verdict from the lowest firing order, the regression, and the
/// gap-pattern certificate.
fn verdict_from(
    fired_order: Option<usize>,
    regression: Option<&RegressionFit>,
    gap_isomorph_present: bool,
) -> KeyDiffVerdict {
    match fired_order {
        Some(0) => KeyDiffVerdict::IdenticalKey,
        Some(1) => KeyDiffVerdict::ConstantAdditive {
            family: regression.map_or(AutokeyFamily::SingleGap, autokey_family),
        },
        Some(2) => KeyDiffVerdict::LinearAdditive,
        Some(order) => KeyDiffVerdict::HigherOrderAdditive { order },
        None if gap_isomorph_present => KeyDiffVerdict::Irregular,
        None => KeyDiffVerdict::NoSignal,
    }
}

/// Whether a gap-pattern isomorph (a substitution-invariant repeated equality
/// pattern, the certificate that a relabelled repeat exists) is present on the
/// raw stream at the firing window length.
fn gap_pattern_certificate(values: &[u16], window: usize) -> bool {
    let effective = window.min(values.len());
    if effective == 0 {
        return false;
    }
    let max_period = values.len().saturating_sub(1).max(1);
    match detect_isomorphs(values, effective, 1, max_period) {
        Ok(detection) => !detection.groups.is_empty(),
        Err(_unscannable) => false,
    }
}

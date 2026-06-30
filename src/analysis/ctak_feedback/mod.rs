//! Ciphertext-autokey (feedback) deck discriminator for the `C3 × H`
//! hidden-state Group-Autokey reading of small-alphabet deck/rotor ciphers
//! (practice puzzle `two`).
//!
//! # The untested boundary this closes
//!
//! [`groupscan`](crate::analysis::group_order) and
//! [`keydiff`](crate::analysis::key_difference) both assume a **passive deck**:
//! between two occurrences of a repeated plaintext span the deck differs by one
//! *constant* group element `K`, which holds only for plaintext-autokey. Their
//! robust `NoDeckSignal` / additive-exclusion verdicts therefore leave one regime
//! untested — **ciphertext-autokey**, where the deck advance is keyed on the
//! *emitted ciphertext*, not the plaintext. There no readout exposes a constant
//! `K`, so the passive-deck instruments' positive-control premise collapses
//! (`CODEC-RESULTS.md` §"Readout convention and the autokey-family boundary").
//!
//! # Why feedback is attackable where passive autokey is not
//!
//! Under ciphertext-autokey the deck trajectory is **computable from the observed
//! ciphertext** plus the initial deck:
//!
//! ```text
//! D_i = D0 ∘ g(q_0) ∘ g(q_1) ∘ … ∘ g(q_{i-1}),   t_i = readout(D_i, q_i)
//! ```
//!
//! where `q_i = symbol / rotor_mod` is the observed deck channel and
//! `g: card-value -> S_deck` is the advance map. So the search collapses from the
//! plaintext-autokey `6^8` per-coset key space to the advance map `g` alone — a
//! few hundred thousand deterministic forward passes (`(deck!)^deck`). For the
//! canonical forward/right convention `D0` cancels from every crib equality
//! (`t_i = D0(P_i(q_i))`, `D0` a bijection), so the `g`-search is fully general.
//!
//! # The crib-anchored statistic (codec-free)
//!
//! `isoscan` locates rotor-difference-channel anchors — spans where the plaintext
//! **really repeats** (the `two` length-68 anchor clears a *period-2-preserving*
//! null, so it is a genuine ~34-letter repeated phrase, not a codec artifact). If
//! `two` is a feedback deck, the correct `g` must make the recovered deck channel
//! `t` **repeat at every anchor at once**. The gated statistic is the **joint
//! minimum** crib run across all anchors: a spurious `g` overfits one anchor but
//! cannot satisfy the minimum across all of them, and the matched null reruns the
//! entire `g`-search on a deck-channel surrogate, so the multiple-comparisons
//! inflation of an exhaustive search is absorbed by the null itself.
//!
//! # Honesty ceiling (binding)
//!
//! A verdict is a **structural discriminator over the feedback-deck family, never
//! a decode**. A positive `FeedbackDeckSignal` recovers the deck *mechanism* (an
//! advance map reproducing the crib), not plaintext — the digit→language codec is
//! a separate unknown. A `NoFeedbackSignal` strengthens the honest negative: with
//! passive-deck plaintext-autokey already excluded, no single-symbol-feedback deck
//! reproduces the real repeat either.

use std::fmt;

use crate::analysis::translate_isomorph::{RepeatAnchor, iso_scan};
use crate::nulls::null::{
    RandomBoundError, SplitMix64, add_one_p_value, mix_seed, random_index_below,
};

mod control;
pub mod model;
#[cfg(test)]
mod tests;

pub use model::{Convention, MAX_SEARCH_DECK, Readout, Side};
use model::{CribAnchor, Perms, search_best_map};

/// Default rotor modulus (the transparent `C3` factor of puzzle `two`).
pub const DEFAULT_ROTOR_MOD: usize = 3;
/// Default minimum rotor-difference-channel anchor length to seed a crib.
pub const DEFAULT_MIN_ANCHOR_LEN: usize = 8;
/// Default maximum number of crib anchors to use jointly.
pub const DEFAULT_TOP_K: usize = 8;
/// Default matched-null trial count (each trial reruns the full `g`-search, so
/// this trades runtime for p-value resolution; raise it for a publication run).
pub const DEFAULT_NULL_TRIALS: usize = 60;
/// Trial count for the rotor-anchor significance null (the `isoscan` gate that
/// keeps only genuine plaintext repeats, not chance repeats, as cribs).
const ANCHOR_NULL_TRIALS: usize = 200;
/// Default deterministic seed (`"ctakfdbk"` tag).
pub const DEFAULT_SEED: u64 = 0x6374_616b_6664_626b;
/// Per-convention matched-null significance threshold.
const SIGNIFICANCE_P: f64 = 0.05;

/// Error returned by the feedback-deck discriminator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CtakError {
    /// The declared alphabet size was zero.
    EmptyAlphabet,
    /// The rotor modulus was zero.
    ZeroRotorMod,
    /// The alphabet size is not a whole multiple of the rotor modulus.
    AlphabetNotDivisible {
        /// Declared alphabet size.
        alphabet_size: usize,
        /// Requested rotor modulus.
        rotor_mod: usize,
    },
    /// The implied deck size is below two (no permutation structure).
    DeckTooSmall {
        /// Implied deck size.
        deck_size: usize,
    },
    /// The implied deck size exceeds the exhaustive-search bound.
    DeckTooLarge {
        /// Implied deck size.
        deck_size: usize,
        /// The maximum the exhaustive `g`-search supports.
        max: usize,
    },
    /// A Monte-Carlo draw bound did not fit the PRNG helper.
    RandomBound {
        /// Requested exclusive upper bound.
        bound: usize,
    },
    /// The rotor-anchor significance scan (`isoscan`) failed.
    AnchorScanFailed {
        /// The underlying `isoscan` error rendered as text.
        detail: String,
    },
    /// The in-process self-test failed to recover a planted control signal.
    SelfTestFailed,
}

impl From<RandomBoundError> for CtakError {
    fn from(error: RandomBoundError) -> Self {
        Self::RandomBound { bound: error.bound }
    }
}

impl fmt::Display for CtakError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyAlphabet => write!(f, "the declared alphabet is empty"),
            Self::ZeroRotorMod => write!(f, "the rotor modulus must be positive"),
            Self::AlphabetNotDivisible {
                alphabet_size,
                rotor_mod,
            } => write!(
                f,
                "alphabet size {alphabet_size} is not a multiple of rotor modulus {rotor_mod}"
            ),
            Self::DeckTooSmall { deck_size } => {
                write!(f, "implied deck size {deck_size} is below two")
            }
            Self::DeckTooLarge { deck_size, max } => write!(
                f,
                "implied deck size {deck_size} exceeds the exhaustive-search bound {max}"
            ),
            Self::RandomBound { bound } => write!(f, "random draw bound {bound} is too large"),
            Self::AnchorScanFailed { detail } => {
                write!(f, "rotor-anchor significance scan failed: {detail}")
            }
            Self::SelfTestFailed => write!(f, "feedback-deck self-test failed"),
        }
    }
}

impl std::error::Error for CtakError {}

/// One convention's recovered-best advance map and its matched-null calibration.
#[derive(Clone, Debug, PartialEq)]
pub struct ConventionResult {
    /// The decode convention.
    pub convention: Convention,
    /// Whether `D0` provably cancels (so the `g`-search is fully general) or the
    /// search fixed `D0 = identity` (a representative slice).
    pub d0_cancels: bool,
    /// The recovered advance map (one permutation index per card value).
    pub best_g: Vec<usize>,
    /// Joint minimum crib run across all anchors for `best_g` (the gated statistic).
    pub min_run: usize,
    /// Per-anchor longest crib run for `best_g` (anchor order matches `anchors`).
    pub per_anchor_runs: Vec<usize>,
    /// Mean joint-minimum crib run across null trials.
    pub null_mean: f64,
    /// Largest joint-minimum crib run any null trial reached.
    pub null_ceiling: usize,
    /// Add-one p-value: fraction of null trials whose joint-minimum reaches the
    /// observed `min_run`.
    pub p_value: f64,
}

impl ConventionResult {
    /// Whether this convention fires: a significant joint minimum that also
    /// strictly clears the null ceiling (not merely a tie).
    #[must_use]
    pub fn fires(&self) -> bool {
        self.p_value < SIGNIFICANCE_P && self.min_run > self.null_ceiling
    }
}

/// The discriminator verdict.
#[derive(Clone, Debug, PartialEq)]
pub enum CtakVerdict {
    /// A feedback advance map reproduces the crib repeat across all anchors,
    /// significantly above the matched null. Recovers the deck *mechanism*, not
    /// plaintext.
    FeedbackDeckSignal {
        /// The firing convention.
        convention: Convention,
        /// The recovered advance map.
        g: Vec<usize>,
        /// Joint minimum crib run achieved.
        min_run: usize,
        /// Add-one p-value of the firing convention.
        p_value: f64,
    },
    /// No convention's advance map reproduces the crib above the matched null —
    /// ciphertext-autokey single-symbol-feedback deck is excluded too.
    NoFeedbackSignal,
}

/// Complete feedback-deck discriminator report.
#[derive(Clone, Debug, PartialEq)]
pub struct CtakReport {
    /// Length of the input stream.
    pub input_len: usize,
    /// Declared alphabet size.
    pub alphabet_size: usize,
    /// Rotor modulus (transparent channel).
    pub rotor_mod: usize,
    /// Implied deck size.
    pub deck_size: usize,
    /// Minimum rotor-difference-channel anchor length scanned.
    pub min_anchor_len: usize,
    /// Largest rotor-difference repeat any anchor-significance null trial reached
    /// (the cribs used all clear this ceiling — they are genuine plaintext
    /// repeats, not chance repeats).
    pub anchor_null_ceiling: usize,
    /// The crib anchors used (ciphertext coordinates), longest first.
    pub anchors: Vec<CribAnchor>,
    /// Per-convention results.
    pub conventions: Vec<ConventionResult>,
    /// Number of conventions examined (the multiple-comparisons family size).
    pub conventions_tested: usize,
    /// The discriminator verdict.
    pub verdict: CtakVerdict,
}

/// Outcome of the in-process self-test (planted positive + negative controls).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "one pass/fail flag per independent control; a flat record is clearest"
)]
pub struct CtakSelfTest {
    /// A planted feedback-deck stream (known `g`, planted repeated word) yields a
    /// `FeedbackDeckSignal` recovering a crib-consistent advance map.
    pub positive_recovered: bool,
    /// The recovered advance map reproduces the full planted repeat (joint minimum
    /// crib run reaches the planted word length).
    pub positive_full_repeat: bool,
    /// A no-feedback control (anchors present in the rotor channel, but the deck
    /// channel is order-1 Markov noise) yields `NoFeedbackSignal`.
    pub negative_rejected: bool,
    /// All checks passed.
    pub passed: bool,
}

/// Runs the ciphertext-autokey feedback-deck discriminator on a symbol stream.
///
/// `values` are alphabet indices (`0..alphabet_size`); `rotor_mod` selects the
/// transparent rotor channel and the deck channel `q = value / rotor_mod` over
/// `deck_size = alphabet_size / rotor_mod` card values. Rotor-difference-channel
/// anchors (length `>= min_anchor_len`, up to `top_k`) seed the joint crib; each
/// of the four `(side, readout)` conventions is searched exhaustively over the
/// advance map and calibrated against a deck-channel-resample order-1 Markov null.
///
/// # Errors
/// Returns [`CtakError`] when the alphabet/rotor configuration is invalid, the
/// deck is too large for an exhaustive search, or a Monte-Carlo bound fails.
pub fn ctak_scan(
    values: &[u16],
    alphabet_size: usize,
    rotor_mod: usize,
    min_anchor_len: usize,
    top_k: usize,
    null_trials: usize,
    seed: u64,
) -> Result<CtakReport, CtakError> {
    let deck_size = validate(alphabet_size, rotor_mod)?;
    let q: Vec<usize> = values.iter().map(|&v| usize::from(v) / rotor_mod).collect();

    // Cribs are the *significant* rotor-difference repeats (the `isoscan` gate),
    // so spurious chance repeats — which no advance map can satisfy and which
    // would collapse the joint minimum — are never used as anchors.
    let scan = iso_scan(
        values,
        alphabet_size,
        Some(rotor_mod),
        top_k,
        ANCHOR_NULL_TRIALS,
        seed,
    )
    .map_err(|error| CtakError::AnchorScanFailed {
        detail: error.to_string(),
    })?;
    let anchor_null_ceiling = scan.null_max_ceiling;
    let anchors = to_crib_anchors(&scan.anchors, values.len(), min_anchor_len);

    let perms = Perms::build(deck_size);
    let mut conventions = Vec::with_capacity(Convention::all().len());
    for convention in Convention::all() {
        let result = scan_convention(
            &perms,
            &q,
            deck_size,
            &anchors,
            convention,
            null_trials,
            seed,
        )?;
        conventions.push(result);
    }
    let verdict = verdict_from(&conventions);

    Ok(CtakReport {
        input_len: values.len(),
        alphabet_size,
        rotor_mod,
        deck_size,
        min_anchor_len,
        anchor_null_ceiling,
        anchors,
        conventions_tested: Convention::all().len(),
        conventions,
        verdict,
    })
}

/// Runs the in-process self-test (planted positive + no-feedback negative).
///
/// # Errors
/// Returns [`CtakError`] if a control stream cannot be built or scanned.
pub fn ctak_self_test(seed: u64) -> Result<CtakSelfTest, CtakError> {
    control::self_test(seed)
}

/// Validates the alphabet/rotor configuration and returns the implied deck size.
fn validate(alphabet_size: usize, rotor_mod: usize) -> Result<usize, CtakError> {
    if alphabet_size == 0 {
        return Err(CtakError::EmptyAlphabet);
    }
    if rotor_mod == 0 {
        return Err(CtakError::ZeroRotorMod);
    }
    if !alphabet_size.is_multiple_of(rotor_mod) {
        return Err(CtakError::AlphabetNotDivisible {
            alphabet_size,
            rotor_mod,
        });
    }
    let deck_size = alphabet_size / rotor_mod;
    if deck_size < 2 {
        return Err(CtakError::DeckTooSmall { deck_size });
    }
    if deck_size > MAX_SEARCH_DECK {
        return Err(CtakError::DeckTooLarge {
            deck_size,
            max: MAX_SEARCH_DECK,
        });
    }
    Ok(deck_size)
}

/// Scans one convention: exhaustive `g`-search + matched null.
fn scan_convention(
    perms: &Perms,
    q: &[usize],
    deck_size: usize,
    anchors: &[CribAnchor],
    convention: Convention,
    null_trials: usize,
    seed: u64,
) -> Result<ConventionResult, CtakError> {
    let best = search_best_map(perms, q, anchors, convention);
    let (best_g, min_run, per_anchor_runs) = match best {
        Some(b) => (b.g, b.min_run, b.per_anchor_runs),
        None => (vec![perms.identity(); deck_size], 0, Vec::new()),
    };

    let (null_mean, null_ceiling, p_value) = feedback_null(
        perms,
        q,
        deck_size,
        anchors,
        convention,
        min_run,
        null_trials,
        mix_seed(seed, convention_tag(convention)),
    )?;

    Ok(ConventionResult {
        convention,
        d0_cancels: convention.d0_cancels(),
        best_g,
        min_run,
        per_anchor_runs,
        null_mean,
        null_ceiling,
        p_value,
    })
}

/// The deck-channel-resample matched null: redraw `q` under its order-1 Markov law
/// (preserving the deck transition structure while breaking the cross-occurrence
/// alignment with the rotor anchors), rerun the full `g`-search, and calibrate the
/// observed joint minimum against the null joint-minimum distribution.
#[allow(clippy::too_many_arguments, reason = "an internal Monte-Carlo helper")]
fn feedback_null(
    perms: &Perms,
    q: &[usize],
    deck_size: usize,
    anchors: &[CribAnchor],
    convention: Convention,
    observed_min_run: usize,
    trials: usize,
    seed: u64,
) -> Result<(f64, usize, f64), CtakError> {
    if trials == 0 || anchors.is_empty() {
        return Ok((0.0, 0, add_one_p_value(0, trials)));
    }
    let table = markov_table(q, deck_size);
    let mut total = 0usize;
    let mut ceiling = 0usize;
    let mut at_least = 0usize;
    for trial in 0..trials {
        let mut rng = SplitMix64::new(mix_seed(seed, trial as u64));
        let resampled = markov_resample(q, deck_size, &table, &mut rng)?;
        let min_run =
            search_best_map(perms, &resampled, anchors, convention).map_or(0, |best| best.min_run);
        total += min_run;
        ceiling = ceiling.max(min_run);
        if min_run >= observed_min_run {
            at_least += 1;
        }
    }
    Ok((
        total as f64 / trials as f64,
        ceiling,
        add_one_p_value(at_least, trials),
    ))
}

/// Builds the verdict: the firing convention with the largest joint minimum, or
/// `NoFeedbackSignal` when none fires.
fn verdict_from(conventions: &[ConventionResult]) -> CtakVerdict {
    let best = conventions
        .iter()
        .filter(|c| c.fires())
        .max_by_key(|c| c.min_run);
    match best {
        Some(c) => CtakVerdict::FeedbackDeckSignal {
            convention: c.convention,
            g: c.best_g.clone(),
            min_run: c.min_run,
            p_value: c.p_value,
        },
        None => CtakVerdict::NoFeedbackSignal,
    }
}

/// A stable per-convention tag mixed into the null seed.
fn convention_tag(convention: Convention) -> u64 {
    let side = match convention.side {
        Side::Right => 0u64,
        Side::Left => 1,
    };
    let readout = match convention.readout {
        Readout::Forward => 0u64,
        Readout::Inverse => 2,
    };
    0x636f_6e76_0000_0000 ^ side ^ readout
}

/// Converts rotor-difference-channel anchors to ciphertext-coordinate crib
/// anchors. Difference index `j` is the transition `j -> j+1`, so a repeat over
/// difference indices `[first, first+len)` is a plaintext repeat over ciphertext
/// positions `[first+1, first+1+len)` (and likewise `second`). Anchors shorter
/// than `min_len` are dropped and the rest are clamped to stay within the stream.
fn to_crib_anchors(raw: &[RepeatAnchor], stream_len: usize, min_len: usize) -> Vec<CribAnchor> {
    raw.iter()
        .filter(|a| a.length >= min_len)
        .filter_map(|a| {
            let first = a.first + 1;
            let second = a.second + 1;
            let max_len = stream_len.saturating_sub(second);
            let length = a.length.min(max_len);
            (length > 0).then_some(CribAnchor {
                first,
                second,
                length,
            })
        })
        .collect()
}

/// Empirical successor multiset `P(next | current)` over the deck channel.
fn markov_table(q: &[usize], deck_size: usize) -> Vec<Vec<usize>> {
    let mut table = vec![Vec::new(); deck_size];
    for pair in q.windows(2) {
        let [a, b] = pair else { continue };
        if let Some(row) = table.get_mut(*a) {
            row.push(*b);
        }
    }
    table
}

/// Order-1 Markov resample of `q`: keep the first symbol, then draw each next from
/// the empirical successor multiset of the current symbol (uniform fallback for a
/// terminal-only symbol).
fn markov_resample(
    q: &[usize],
    deck_size: usize,
    table: &[Vec<usize>],
    rng: &mut SplitMix64,
) -> Result<Vec<usize>, CtakError> {
    let mut out = Vec::with_capacity(q.len());
    let Some(&first) = q.first() else {
        return Ok(out);
    };
    out.push(first);
    let mut current = first;
    for _ in 1..q.len() {
        let next = match table.get(current) {
            Some(row) if !row.is_empty() => {
                let idx = random_index_below(row.len(), rng)?;
                row.get(idx).copied().unwrap_or(current)
            }
            _ => random_index_below(deck_size, rng)?,
        };
        out.push(next);
        current = next;
    }
    Ok(out)
}

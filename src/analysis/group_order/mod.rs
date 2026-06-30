//! D4/A4/S4 hidden-group element-order discriminator for the `C3 × H`
//! hidden-state Group-Autokey reading of small-alphabet deck/rotor ciphers
//! (practice puzzle `two`).
//!
//! # What it discriminates
//!
//! `two` reads as a hidden-state GAK with state group `G = C3 × H`, where `C3`
//! is the transparent rotor (`r = symbol % rotor_mod`, fully visible) and
//! `H ⊆ S4` is the hidden group acting on a 4-card deck. The mod-3 rotor is
//! forced, but `H` is not: `D4` (order 8), `A4` (order 12), and `S4` (order 24)
//! all reproduce the mod-3 law and out-degree 8 identically. A smaller `H` means
//! less deck slack and less overfitting risk in any crib-anchored key recovery,
//! so this instrument constrains `H` *before* that recovery.
//!
//! # The discriminating fact (element orders)
//!
//! As subgroups of `S4`, the three candidates have distinct element-order
//! spectra: `D4` has elements of order `{1,2,4}` (**no** 3-cycle), `A4` of order
//! `{1,2,3}` (**no** 4-cycle), `S4` of `{1,2,3,4}` (both). So a single observed
//! **3-cycle rules out D4**, a single **4-cycle rules out A4**, and seeing both
//! forces **S4**.
//!
//! # How a cycle is observed (the `TopCard` gate)
//!
//! A repeated plaintext span at positions `a..a+L` and `b..b+L` relates the two
//! occurrences by one fixed group element (the "context" `C`). Under the
//! convention-B **top-card** readout (`q = symbol / rotor_mod` is the deck's top
//! card), the deck channel transforms functionally: `q[b+s] = C(q[a+s])`, where
//! the inducing permutation is the context's `H`-component, so its cycle type is
//! the order of one element of `H`. The instrument reads `q[a+s] -> q[b+s]`
//! across each rotor-difference-channel anchor; a **consistent bijection** is the
//! honesty gate — a genuine full-plaintext repeat under a top-card readout yields
//! one, while an eps-only (rotor-only) repeat or a non-TopCard readout is
//! generically not a clean group action. A finite consistency gate can still be
//! fooled by degenerate cases (a context that fixes the marked card, low coverage,
//! or chance consistency), so verdicts are gated against a matched null.
//!
//! # Honesty ceiling (binding)
//!
//! This is a **structural discriminator, not a decode**. It reports which hidden
//! group is consistent with the observed element-order spectrum and never claims
//! plaintext. An absence claim (D4 or A4) is reported only with a power statement
//! under an explicit "contexts ≈ uniform over `H`" model; the only certain
//! verdict is the positive S4 sighting of both a 3-cycle and a 4-cycle.

use std::fmt;

use crate::analysis::translate_isomorph::{RepeatAnchor, find_anchors};
use crate::core::math::gcd;
use crate::nulls::null::{RandomBoundError, SplitMix64, mix_seed, random_index_below};

mod control;
mod scan;
#[cfg(test)]
mod tests;

use scan::{cycle_lengths, read_context};

/// Default rotor modulus (the transparent `C3` factor of puzzle `two`).
pub const DEFAULT_ROTOR_MOD: usize = 3;
/// Default minimum difference-channel anchor length to read a context from.
pub const DEFAULT_MIN_ANCHOR_LEN: usize = 8;
/// Default maximum number of anchors (contexts) to examine.
pub const DEFAULT_TOP_K: usize = 16;
/// Default matched-null trial count for the deck-channel decoupling null.
pub const DEFAULT_NULL_TRIALS: usize = 200;
/// Default deterministic seed (`"grouporder"` little-endian-ish tag).
pub const DEFAULT_SEED: u64 = 0x6772_6f75_705f_6f31;
/// Matched-null p-value threshold required before emitting an exclusion verdict.
const SIGNIFICANCE_P: f64 = 0.05;

/// Error returned by the element-order discriminator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GroupScanError {
    /// The declared alphabet size was zero.
    EmptyAlphabet,
    /// The rotor modulus was zero (no transparent channel to project onto).
    ZeroRotorMod,
    /// The alphabet size is not a whole multiple of the rotor modulus, so the
    /// deck channel `q = symbol / rotor_mod` is not well defined.
    AlphabetNotDivisible {
        /// Declared alphabet size.
        alphabet_size: usize,
        /// Requested rotor modulus.
        rotor_mod: usize,
    },
    /// The implied deck size (`alphabet_size / rotor_mod`) is below two, so there
    /// is no permutation structure to read.
    DeckTooSmall {
        /// Implied deck size.
        deck_size: usize,
    },
    /// A Monte-Carlo draw bound did not fit the PRNG helper.
    RandomBound {
        /// Requested exclusive upper bound.
        bound: usize,
    },
    /// The in-process self-test failed to recover a planted control signal.
    SelfTestFailed,
}

impl From<RandomBoundError> for GroupScanError {
    fn from(error: RandomBoundError) -> Self {
        Self::RandomBound { bound: error.bound }
    }
}

impl fmt::Display for GroupScanError {
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
            Self::RandomBound { bound } => write!(f, "random draw bound {bound} is too large"),
            Self::SelfTestFailed => write!(f, "element-order self-test failed"),
        }
    }
}

impl std::error::Error for GroupScanError {}

/// One anchor's recovered deck-channel context (an element of the hidden group).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextReading {
    /// The difference-channel anchor this context was read from.
    pub anchor: RepeatAnchor,
    /// Distinct deck-channel values observed in the consistent prefix.
    pub coverage: usize,
    /// Length of the consistent prefix (aligned positions before the first
    /// collision or the anchor end). A context is trusted only when this clears
    /// the `min_anchor_len` floor.
    pub prefix_len: usize,
    /// The recovered inducing permutation, present only when the consistent
    /// prefix is long enough (`>= min_anchor_len`) and determines a permutation.
    pub permutation: Option<Vec<usize>>,
    /// Sorted cycle lengths of the recovered permutation, when determined.
    pub cycle_lengths: Option<Vec<usize>>,
    /// Element order (lcm of cycle lengths), when determined.
    pub element_order: Option<usize>,
}

/// The discriminator verdict.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum GroupVerdict {
    /// Both a 3-cycle and a 4-cycle were observed: the hidden group must be `S4`
    /// (only `S4` contains elements of both order 3 and order 4). Certain.
    S4,
    /// 4-cycle(s) observed, no 3-cycle: rules out `A4`. Remaining `D4` or `S4`.
    ExcludesA4 {
        /// Number of consistent determined contexts examined.
        contexts: usize,
        /// Under "contexts ≈ uniform over `H`", the chance of seeing no 3-cycle
        /// in `contexts` draws if the group were actually `S4` (`(2/3)^contexts`).
        s4_miss_prob: f64,
    },
    /// 3-cycle(s) observed, no 4-cycle: rules out `D4`. Remaining `A4` or `S4`.
    ExcludesD4 {
        /// Number of consistent determined contexts examined.
        contexts: usize,
        /// Under "contexts ≈ uniform over `H`", the chance of seeing no 4-cycle
        /// in `contexts` draws if the group were actually `S4` (`(3/4)^contexts`).
        s4_miss_prob: f64,
    },
    /// Only cycle lengths `<= 2` observed: inconclusive (consistent with any of
    /// `D4`/`A4`/`S4`).
    Inconclusive {
        /// Number of consistent determined contexts examined.
        contexts: usize,
    },
    /// No significant deck-channel signal was recovered versus the deck-decoupled
    /// null (eps-only repeats, a non-TopCard readout, too little coverage, or
    /// chance consistency). Not evidence of any particular group.
    NoDeckSignal,
}

/// Monte-Carlo band for the deck-channel-decoupling matched null.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NullBand {
    /// Number of null trials run.
    pub trials: usize,
    /// Mean number of consistent determined contexts under the null.
    pub mean_consistent: f64,
    /// Largest consistent-determined-context count any null trial reached.
    pub ceiling: usize,
    /// Add-one p-value: fraction of null trials whose consistent-determined
    /// context count reaches the observed real count, with +1 smoothing.
    pub p_value: f64,
}

/// Complete element-order discriminator report.
#[derive(Clone, Debug, PartialEq)]
pub struct GroupScanReport {
    /// Length of the input stream.
    pub input_len: usize,
    /// Declared alphabet size.
    pub alphabet_size: usize,
    /// Rotor modulus (transparent channel).
    pub rotor_mod: usize,
    /// Implied deck size (`alphabet_size / rotor_mod`).
    pub deck_size: usize,
    /// Minimum anchor length scanned.
    pub min_anchor_len: usize,
    /// Number of difference-channel anchors examined.
    pub anchors_examined: usize,
    /// Number of anchors yielding a consistent determined context.
    pub consistent_contexts: usize,
    /// Per-anchor readings (longest anchor first).
    pub readings: Vec<ContextReading>,
    /// Union of cycle lengths observed across consistent determined contexts.
    pub observed_cycle_lengths: Vec<usize>,
    /// Matched null (deck-channel decoupled under its order-1 Markov law).
    pub null: NullBand,
    /// The discriminator verdict.
    pub verdict: GroupVerdict,
}

/// Outcome of the in-process self-test (planted controls + matched null).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "one pass/fail flag per independent control; a flat record is clearest"
)]
pub struct GroupScanSelfTest {
    /// Every representative cycle type (1,2,2+2,3,4) recovered exactly.
    pub cycle_recovery_passed: bool,
    /// A planted `C3 × D4` stream yields a "rules out A4" verdict (4-cycle seen,
    /// no 3-cycle).
    pub d4_excludes_a4: bool,
    /// A planted `C3 × A4` stream yields a "rules out D4" verdict (3-cycle seen,
    /// no 4-cycle).
    pub a4_excludes_d4: bool,
    /// A planted `C3 × S4` stream yields an S4 verdict (both a 3- and 4-cycle).
    pub s4_verdict: bool,
    /// The eps-only matched null yields no consistent determined context.
    pub null_rejected: bool,
    /// All checks passed.
    pub passed: bool,
}

/// Runs the D4/A4/S4 element-order discriminator on an arbitrary symbol stream.
///
/// `values` are alphabet indices (`0..alphabet_size`); `rotor_mod` selects the
/// transparent rotor channel (`r = value % rotor_mod`) and the deck channel
/// (`q = value / rotor_mod`, over `deck_size = alphabet_size / rotor_mod`
/// values). Difference-channel anchors of length `>= min_anchor_len` (up to
/// `top_k`) seed the contexts; a deck-channel-decoupling order-1 Markov null over
/// `null_trials` trials calibrates the consistent-context count.
///
/// # Errors
/// Returns [`GroupScanError`] when the alphabet/rotor configuration is invalid or
/// a Monte-Carlo bound does not fit the PRNG helper.
pub fn group_scan(
    values: &[u16],
    alphabet_size: usize,
    rotor_mod: usize,
    min_anchor_len: usize,
    top_k: usize,
    null_trials: usize,
    seed: u64,
) -> Result<GroupScanReport, GroupScanError> {
    if alphabet_size == 0 {
        return Err(GroupScanError::EmptyAlphabet);
    }
    if rotor_mod == 0 {
        return Err(GroupScanError::ZeroRotorMod);
    }
    if !alphabet_size.is_multiple_of(rotor_mod) {
        return Err(GroupScanError::AlphabetNotDivisible {
            alphabet_size,
            rotor_mod,
        });
    }
    let deck_size = alphabet_size / rotor_mod;
    if deck_size < 2 {
        return Err(GroupScanError::DeckTooSmall { deck_size });
    }

    let q: Vec<usize> = values.iter().map(|&v| usize::from(v) / rotor_mod).collect();
    let diff = rotor_difference_channel(values, rotor_mod);
    let anchors = find_anchors(&diff, min_anchor_len, top_k);

    let readings: Vec<ContextReading> = anchors
        .iter()
        .map(|anchor| read_anchor(&q, deck_size, *anchor, min_anchor_len))
        .collect();

    let real_consistent = readings.iter().filter(|r| r.permutation.is_some()).count();
    let observed_cycle_lengths = union_cycle_lengths(&readings);
    let null = deck_decouple_null(
        &q,
        deck_size,
        &anchors,
        min_anchor_len,
        real_consistent,
        null_trials,
        seed,
    )?;
    let verdict = verdict_from(&observed_cycle_lengths, real_consistent, &null);

    Ok(GroupScanReport {
        input_len: values.len(),
        alphabet_size,
        rotor_mod,
        deck_size,
        min_anchor_len,
        anchors_examined: anchors.len(),
        consistent_contexts: real_consistent,
        readings,
        observed_cycle_lengths,
        null,
        verdict,
    })
}

/// Runs the in-process self-test: planted `C3 × {D4,A4,S4}` positive controls,
/// a representative-cycle-type recovery check, and an eps-only matched null.
///
/// # Errors
/// Returns [`GroupScanError`] if a control stream cannot be scanned.
pub fn group_scan_self_test(seed: u64) -> Result<GroupScanSelfTest, GroupScanError> {
    control::self_test(seed)
}

/// The rotor difference channel `d[i] = (v[i+1] - v[i]) mod rotor_mod`, widened to
/// `u32` for the anchor finder. A global symbol offset cancels, so a repeated
/// plaintext span leaves a literal exact repeat here.
fn rotor_difference_channel(values: &[u16], rotor_mod: usize) -> Vec<u32> {
    let modulus = rotor_mod as u64;
    let mut out = Vec::with_capacity(values.len().saturating_sub(1));
    for pair in values.windows(2) {
        if let [a, b] = pair {
            let a = u64::from(*a) % modulus;
            let b = u64::from(*b) % modulus;
            let diff = (b + modulus - a) % modulus;
            out.push(u32::try_from(diff).unwrap_or(0));
        }
    }
    out
}

/// Reads one anchor into a [`ContextReading`], trusting the recovered context
/// only when the consistent prefix clears the `min_anchor_len` floor.
fn read_anchor(
    q: &[usize],
    deck_size: usize,
    anchor: RepeatAnchor,
    min_anchor_len: usize,
) -> ContextReading {
    let outcome = read_context(q, deck_size, anchor.first, anchor.second, anchor.length);
    let permutation = if outcome.prefix_len >= min_anchor_len {
        outcome.permutation
    } else {
        None
    };
    let cycle_lengths = permutation.as_deref().map(cycle_lengths);
    let element_order = cycle_lengths.as_deref().map(lcm_all);
    ContextReading {
        anchor,
        coverage: outcome.coverage,
        prefix_len: outcome.prefix_len,
        permutation,
        cycle_lengths,
        element_order,
    }
}

/// Union of cycle lengths across all consistent determined contexts.
fn union_cycle_lengths(readings: &[ContextReading]) -> Vec<usize> {
    let mut lengths: Vec<usize> = Vec::new();
    for reading in readings {
        if let Some(cycles) = reading.cycle_lengths.as_deref() {
            for &len in cycles {
                if !lengths.contains(&len) {
                    lengths.push(len);
                }
            }
        }
    }
    lengths.sort_unstable();
    lengths
}

/// Least common multiple of a list of cycle lengths (the element order).
fn lcm_all(lengths: &[usize]) -> usize {
    lengths.iter().fold(1usize, |acc, &len| lcm(acc, len))
}

fn lcm(a: usize, b: usize) -> usize {
    if a == 0 || b == 0 {
        return 0;
    }
    a / gcd(a, b) * b
}

/// Builds the verdict from the observed cycle-length union, context count, and null.
fn verdict_from(
    observed_cycle_lengths: &[usize],
    contexts: usize,
    null: &NullBand,
) -> GroupVerdict {
    let significant = contexts > 0 && null.p_value < SIGNIFICANCE_P;
    if !significant {
        return GroupVerdict::NoDeckSignal;
    }
    let has_three = observed_cycle_lengths.contains(&3);
    let has_four = observed_cycle_lengths.contains(&4);
    match (has_three, has_four) {
        (true, true) => GroupVerdict::S4,
        (false, true) => GroupVerdict::ExcludesA4 {
            contexts,
            s4_miss_prob: powf(2.0 / 3.0, contexts),
        },
        (true, false) => GroupVerdict::ExcludesD4 {
            contexts,
            s4_miss_prob: powf(3.0 / 4.0, contexts),
        },
        (false, false) => GroupVerdict::Inconclusive { contexts },
    }
}

fn powf(base: f64, exp: usize) -> f64 {
    let mut acc = 1.0;
    for _ in 0..exp {
        acc *= base;
    }
    acc
}

/// The deck-channel-decoupling matched null: resample `q` under its order-1
/// Markov law (preserving the deck-channel transition structure while breaking
/// the cross-occurrence alignment) and recount consistent determined contexts at
/// the same anchors.
fn deck_decouple_null(
    q: &[usize],
    deck_size: usize,
    anchors: &[RepeatAnchor],
    min_anchor_len: usize,
    real_consistent: usize,
    trials: usize,
    seed: u64,
) -> Result<NullBand, GroupScanError> {
    if trials == 0 || anchors.is_empty() {
        let at_least_real = if real_consistent == 0 { trials } else { 0 };
        return Ok(NullBand {
            trials,
            mean_consistent: 0.0,
            ceiling: 0,
            p_value: crate::nulls::null::add_one_p_value(at_least_real, trials),
        });
    }
    let table = markov_table(q, deck_size);
    let mut total = 0usize;
    let mut ceiling = 0usize;
    let mut at_least_real = 0usize;
    for trial in 0..trials {
        let mut rng = SplitMix64::new(mix_seed(seed, trial as u64));
        let resampled = markov_resample(q, deck_size, &table, &mut rng)?;
        let mut consistent = 0usize;
        for anchor in anchors {
            let outcome = read_context(
                &resampled,
                deck_size,
                anchor.first,
                anchor.second,
                anchor.length,
            );
            if outcome.prefix_len >= min_anchor_len && outcome.permutation.is_some() {
                consistent += 1;
            }
        }
        total += consistent;
        ceiling = ceiling.max(consistent);
        if consistent >= real_consistent {
            at_least_real += 1;
        }
    }
    Ok(NullBand {
        trials,
        mean_consistent: total as f64 / trials as f64,
        ceiling,
        p_value: crate::nulls::null::add_one_p_value(at_least_real, trials),
    })
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

/// Order-1 Markov resample of `q`: keep the first symbol, then draw each next
/// from the empirical successor multiset of the current symbol (uniform fallback
/// for a terminal-only symbol).
fn markov_resample(
    q: &[usize],
    deck_size: usize,
    table: &[Vec<usize>],
    rng: &mut SplitMix64,
) -> Result<Vec<usize>, GroupScanError> {
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

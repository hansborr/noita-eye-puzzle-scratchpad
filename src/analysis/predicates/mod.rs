//! Thread C — the Toboter predicate battery + multiple-comparisons meta-analysis.
//!
//! Community analyst "Toboter" (and others) catalogued a handful of arithmetic
//! "surprising facts" about the 83-symbol eye messages, each with a self-reported
//! probability. This module **recomputes** each predicate's significance against
//! the repo's own `SplitMix64` matched nulls instead of trusting the reported
//! numbers, and — the real deliverable — runs a multiple-comparisons
//! meta-analysis: given how many predicates were tested, how many "hits" would we
//! expect by chance, and which survive a family-wise correction?
//!
//! # Honesty ceiling (binding — see `AGENTS.md`)
//!
//! - Every predicate is **conditional on the accepted honeycomb reading order**
//!   (`standard36-u012-d012`, alphabet size 83). State that caveat with any number.
//! - Predicates (b)-(e) are individually **weak**; none is ever reported as a
//!   finding on its own. The meta-analysis is the deliverable.
//! - Predicate (a), "only missing gap size is 1", is the one genuinely strong
//!   discriminant (it rules out the `(char + N·pos) mod 83` family), but it
//!   carries a mild **circularity**: the gap structure is the same property that
//!   selected the accepted reading order, so its significance is order- and
//!   plaintext-model-conditional (`research/03-confirmed-vs-speculation.md:161`).
//!
//! # Two null shapes (one per predicate family)
//!
//! - The gap/order predicate (a) uses a **within-message Fisher-Yates shuffle**
//!   ([`WithinMessageShuffle`](crate::nulls::null::WithinMessageShuffle)): it
//!   preserves each message's value multiset and destroys the gap structure — the
//!   correct surrogate for a gap predicate.
//! - The shuffle-**invariant** magnitude/sum predicates (b)-(e) use a
//!   **value-resample** null ([`ValueResample`]): each surrogate message is
//!   redrawn from the pooled empirical value multiset (lengths matched), so the
//!   per-message sums/values actually change and the claimed probabilities are
//!   recomputed against matched magnitudes.

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::fmt;

use crate::analysis::orders::{
    self, GridError, READING_LAYER_ALPHABET_SIZE, accepted_honeycomb_order,
    count_message_recurrence, read_corpus_message_values,
};
use crate::core::math::gcd;
use crate::core::trigram::TrigramValue;
use crate::nulls::null::{
    NullSampler, NullTestError, RandomBoundError, SplitMix64, random_index_below,
};

mod battery;
mod control;
#[cfg(test)]
mod tests;

pub use battery::{
    BatteryReport, MetaAnalysis, PredicateOutcome, bonferroni_adjusted, run_battery,
    run_corpus_battery, sidak_adjusted,
};
pub use control::{ControlCheck, SelfTestResult, predicate_self_test};

/// Reading-layer alphabet size for the eye corpus default (`0..=82`).
pub const DEFAULT_ALPHABET_SIZE: usize = READING_LAYER_ALPHABET_SIZE;

/// Threshold for predicate (b): every message's starting trigram value `> 26`.
pub const STARTING_TRIGRAM_THRESHOLD: u8 = 26;

/// Family-wise error rate the meta-analysis reports survivors against.
pub const FAMILY_ALPHA: f64 = 0.05;

/// Default Monte-Carlo trials for the within-message shuffle null (predicate a).
///
/// The shuffle null recomputes a full recurrence-distance sweep per draw, so this
/// is kept modest; it is the slow null. Override on the CLI for tighter tails.
pub const DEFAULT_SHUFFLE_TRIALS: usize = 1_000;

/// Default Monte-Carlo trials for the value-resample null (predicates b-e).
pub const DEFAULT_RESAMPLE_TRIALS: usize = 5_000;

/// Default deterministic PRNG seed (`b"predsca"` packed little-ish).
pub const DEFAULT_SEED: u64 = 0x7072_6564_7363_616e;

/// The two-digit primes used by predicate (d)'s trial-division factor helper.
pub const TWO_DIGIT_PRIMES: [u64; 21] = [
    11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
];

/// Which matched null a predicate is calibrated against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NullShape {
    /// Within-message Fisher-Yates shuffle (preserves the multiset, destroys order).
    WithinMessageShuffle,
    /// Pooled value-resample (lengths matched); for shuffle-invariant predicates.
    ValueResample,
}

impl NullShape {
    /// A short human label for the null shape.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::WithinMessageShuffle => "within-message shuffle",
            Self::ValueResample => "value-resample (pooled)",
        }
    }
}

/// One Toboter predicate in the battery.
///
/// Every predicate maps the per-message reading value streams to a single
/// `usize` *statistic* whose **upper tail is the surprising direction**, so a
/// single tail convention (more extreme ⇒ smaller empirical p) covers the whole
/// battery. For the "holds for all nine messages" predicates the statistic is the
/// count of satisfying messages and the community claim is `count == messages`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Predicate {
    /// (a) **(strong)** The only missing recurrence-gap size is 1 (no doubles, but
    /// every distance `2..=d_max` is realized). Rules out `(char + N·pos) mod 83`.
    OnlyMissingGapOne,
    /// (b) Every message's starting trigram value exceeds 26.
    StartingTrigramAbove,
    /// (c) Per-message decimal trigram-sum has an `abab` digit shape (e.g. 4040).
    AbabDecimalSum,
    /// (d) No per-message trigram-sum has a two-digit prime factor.
    NoTwoDigitPrimeFactorSum,
    /// (e) No message's first two trigram values are coprime (`gcd != 1`).
    FirstTwoNonCoprime,
}

impl Predicate {
    /// The battery in catalogue order `[a, b, c, d, e]`.
    pub const ALL: [Self; 5] = [
        Self::OnlyMissingGapOne,
        Self::StartingTrigramAbove,
        Self::AbabDecimalSum,
        Self::NoTwoDigitPrimeFactorSum,
        Self::FirstTwoNonCoprime,
    ];

    /// Stable short identifier (used in the meta-analysis survivor lists).
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::OnlyMissingGapOne => "a:missing-gap-1",
            Self::StartingTrigramAbove => "b:start>26",
            Self::AbabDecimalSum => "c:abab-sum",
            Self::NoTwoDigitPrimeFactorSum => "d:no-2dig-prime",
            Self::FirstTwoNonCoprime => "e:first2-gcd!=1",
        }
    }

    /// One-line human description of the predicate.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::OnlyMissingGapOne => "only missing recurrence-gap size is 1 [strong]",
            Self::StartingTrigramAbove => "all starting trigrams > 26",
            Self::AbabDecimalSum => "decimal trigram-sum has abab shape (4040/5656/4545)",
            Self::NoTwoDigitPrimeFactorSum => "no trigram-sum has a two-digit prime factor",
            Self::FirstTwoNonCoprime => "no message's first two trigrams have gcd 1",
        }
    }

    /// The community-reported probability/attribution, verbatim where known.
    #[must_use]
    pub const fn community_claim(self) -> &'static str {
        match self {
            Self::OnlyMissingGapOne => "load-bearing, [likely]; rules out (char+N*pos) mod 83",
            Self::StartingTrigramAbove => "stated as a regularity (Tyoskentely Juho)",
            Self::AbabDecimalSum => "3 of 9 messages, E1/E3/E5 (SaltyOutcome)",
            Self::NoTwoDigitPrimeFactorSum => "~0.4% by chance (Toboter)",
            Self::FirstTwoNonCoprime => "~6.5% by chance (Naugam)",
        }
    }

    /// The matched null this predicate is calibrated against.
    #[must_use]
    pub const fn null_shape(self) -> NullShape {
        match self {
            // A gap predicate's correct surrogate is exactly "shuffle the multiset".
            Self::OnlyMissingGapOne => NullShape::WithinMessageShuffle,
            // (b) is a value-magnitude claim; (c)/(d) are sum predicates that a
            // permutation leaves invariant; (e) is a first-pair coprimality claim.
            // All four are recomputed against matched value magnitudes by resampling.
            Self::StartingTrigramAbove
            | Self::AbabDecimalSum
            | Self::NoTwoDigitPrimeFactorSum
            | Self::FirstTwoNonCoprime => NullShape::ValueResample,
        }
    }

    /// The number of "units" the predicate aggregates over. For the gap predicate
    /// this is the largest geometrically-possible recurrence distance (the run's
    /// ceiling); for the others it is the message count, and the community claim is
    /// `statistic == unit_total`.
    #[must_use]
    pub fn unit_total(self, messages: &[Vec<TrigramValue>]) -> usize {
        match self {
            Self::OnlyMissingGapOne => messages
                .iter()
                .map(|message| message.len().saturating_sub(1))
                .max()
                .unwrap_or(0),
            _ => messages.len(),
        }
    }

    /// The predicate's `usize` statistic on a value-stream draw (upper tail is the
    /// surprising direction).
    ///
    /// For predicate (a) the statistic is the **only-1-missing run length** `M`:
    /// the largest `m` for which `missing_gap_sizes(.., m) == {1}` — i.e. distance
    /// 1 (a doubled trigram) is absent and every distance `2..=m` is realized. A
    /// longer run is more surprising, so the upper tail is again the surprising
    /// direction. (The full realized spectrum thins out at large distances, which
    /// is expected and is not part of the claim; see [`GapProfile`].)
    #[must_use]
    pub fn statistic(self, messages: &[Vec<TrigramValue>]) -> usize {
        match self {
            Self::OnlyMissingGapOne => only_one_missing_run(messages),
            Self::StartingTrigramAbove => messages
                .iter()
                .filter(|message| {
                    first_value(message).is_some_and(|first| first > STARTING_TRIGRAM_THRESHOLD)
                })
                .count(),
            Self::AbabDecimalSum => messages
                .iter()
                .filter(|message| is_abab_decimal(message_sum(message)))
                .count(),
            Self::NoTwoDigitPrimeFactorSum => messages
                .iter()
                .filter(|message| !has_two_digit_prime_factor(message_sum(message)))
                .count(),
            Self::FirstTwoNonCoprime => messages
                .iter()
                .filter(|message| first_two_non_coprime(message))
                .count(),
        }
    }

    /// Whether the community claim holds on `messages`.
    ///
    /// For (a) this is "only missing gap is 1"; for (c) it is "at least three
    /// `abab` messages"; for (b)/(d)/(e) it is "holds for every message".
    #[must_use]
    pub fn satisfied(self, messages: &[Vec<TrigramValue>]) -> bool {
        let observed = self.statistic(messages);
        match self {
            // A nontrivial only-1-missing run: distance 1 absent and at least
            // distance 2 realized (the magnitude/strength lives in the p-value).
            Self::OnlyMissingGapOne => observed >= 2,
            Self::AbabDecimalSum => observed >= 3,
            _ => observed == self.unit_total(messages),
        }
    }
}

/// The realized / missing recurrence-gap profile of a value-stream corpus.
///
/// "Realized" distances are those `d` for which some value recurs with its
/// immediately-previous occurrence exactly `d` positions earlier (the
/// [`count_message_recurrence`] convention), counted per message so artificial
/// joins between messages create no evidence.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GapProfile {
    /// Largest geometrically-possible recurrence distance (`max len - 1`).
    pub search_bound: usize,
    /// Distances `1..=search_bound` that are realized at least once.
    pub realized: BTreeSet<usize>,
    /// Largest realized distance, or 0 if none.
    pub max_realized: usize,
    /// Distances `1..=max_realized` that are never realized.
    pub missing: BTreeSet<usize>,
    /// The only-1-missing run length `M`: the largest `m` for which the only
    /// missing size in `1..=m` is 1 (distance 1 absent, `2..=m` all realized).
    pub only_one_missing_run: usize,
}

impl GapProfile {
    /// Computes the gap profile by sweeping [`count_message_recurrence`] over every
    /// distance up to the longest message length minus one — the same primitive
    /// the reading-order audit uses, but extended well past its `d <= 6` cap.
    #[must_use]
    pub fn of(messages: &[Vec<TrigramValue>]) -> Self {
        let search_bound = messages
            .iter()
            .map(|message| message.len().saturating_sub(1))
            .max()
            .unwrap_or(0);
        let realized: BTreeSet<usize> = (1..=search_bound)
            .filter(|&distance| count_message_recurrence(messages, distance) > 0)
            .collect();
        let max_realized = realized.iter().copied().max().unwrap_or(0);
        let missing = missing_gap_sizes(messages, max_realized);
        // The run extends to (first interior hole - 1); if 1 is not even missing
        // (a doubled trigram exists) there is no only-1-missing run at all.
        let only_one_missing_run = if missing.contains(&1) {
            missing
                .iter()
                .copied()
                .find(|&distance| distance >= 2)
                .map_or(max_realized, |hole| hole.saturating_sub(1))
        } else {
            0
        };
        Self {
            search_bound,
            realized,
            max_realized,
            missing,
            only_one_missing_run,
        }
    }

    /// Whether the only missing gap size over the **full** realized range
    /// (`1..=max_realized`) is exactly 1 — the strict, literal community claim.
    ///
    /// This is usually `false` on real data because large recurrence distances
    /// thin out; the testable discriminant is [`Self::only_one_missing_run`].
    #[must_use]
    pub fn only_missing_one(&self) -> bool {
        self.max_realized >= 2 && self.missing.len() == 1 && self.missing.contains(&1)
    }
}

/// The only-1-missing run length `M` (predicate (a)'s statistic).
///
/// Returns the largest `m` such that the only missing recurrence distance in
/// `1..=m` is 1: distance 1 (a doubled trigram) is absent and every distance
/// `2..=m` is realized. Returns 0 when distance 1 is itself realized (a doubled
/// trigram exists), so the claim cannot even begin.
///
/// This scans [`count_message_recurrence`] from the bottom and stops at the first
/// hole, so under a shuffle null that re-introduces a doubled trigram it returns
/// after a single distance — the cheap path that keeps the shuffle null fast.
#[must_use]
pub fn only_one_missing_run(messages: &[Vec<TrigramValue>]) -> usize {
    if messages.is_empty() || count_message_recurrence(messages, 1) > 0 {
        return 0;
    }
    let search_bound = messages
        .iter()
        .map(|message| message.len().saturating_sub(1))
        .max()
        .unwrap_or(0);
    let mut run = 1;
    for distance in 2..=search_bound {
        if count_message_recurrence(messages, distance) == 0 {
            break;
        }
        run = distance;
    }
    run
}

/// The set of recurrence distances in `1..=d_max` that never occur.
///
/// This is the shared gap primitive (a future `modscan`/Thread D consumes it):
/// it is built directly on top of [`count_message_recurrence`], extending the
/// distance range beyond the `OrderStats` `d <= 6` cap. A distance is *missing*
/// when no value's immediately-previous occurrence is exactly that far back, in
/// any message.
#[must_use]
pub fn missing_gap_sizes(messages: &[Vec<TrigramValue>], d_max: usize) -> BTreeSet<usize> {
    (1..=d_max)
        .filter(|&distance| count_message_recurrence(messages, distance) == 0)
        .collect()
}

/// The first reading value of a message, if it is non-empty.
#[must_use]
pub fn first_value(message: &[TrigramValue]) -> Option<u8> {
    message.first().map(|value| value.get())
}

/// The base-10 sum of a message's reading values.
#[must_use]
pub fn message_sum(message: &[TrigramValue]) -> u64 {
    message.iter().map(|value| u64::from(value.get())).sum()
}

/// Whether `value` is a four-digit base-10 number of `abab` digit shape.
///
/// Examples: 4040, 5656, 4545 hold; 1234, 999, 12345 do not. The check is on the
/// decimal string so it needs no digit arithmetic.
#[must_use]
pub fn is_abab_decimal(value: u64) -> bool {
    let text = value.to_string();
    let bytes = text.as_bytes();
    bytes.len() == 4 && bytes.first() == bytes.get(2) && bytes.get(1) == bytes.get(3)
}

/// Whether `value` is divisible by any two-digit prime (`11..=97`).
///
/// This is the trial-division factor helper for predicate (d). `0` is treated as
/// having no such factor (an empty message contributes no evidence).
#[must_use]
pub fn has_two_digit_prime_factor(value: u64) -> bool {
    value != 0
        && TWO_DIGIT_PRIMES
            .iter()
            .any(|&prime| value.is_multiple_of(prime))
}

/// Whether a message's first two reading values are *non*-coprime (`gcd != 1`).
///
/// A message with fewer than two trigrams is not non-coprime (undefined ⇒ false),
/// so it does not spuriously satisfy predicate (e).
#[must_use]
pub fn first_two_non_coprime(message: &[TrigramValue]) -> bool {
    match (message.first(), message.get(1)) {
        (Some(first), Some(second)) => {
            gcd(usize::from(first.get()), usize::from(second.get())) != 1
        }
        _ => false,
    }
}

/// Pooled value-resample null: each surrogate message is redrawn, with replacement,
/// from the pooled empirical value multiset, matching the per-message lengths.
///
/// This is the matched null for the shuffle-invariant magnitude/sum predicates:
/// it preserves the corpus's marginal value distribution (hence sum magnitudes)
/// while making each draw's per-message sums and first values genuinely random.
#[derive(Clone, Debug)]
pub struct ValueResample {
    lengths: Vec<usize>,
    pool: Vec<TrigramValue>,
}

impl ValueResample {
    /// Builds the resampler from the observed per-message value streams.
    #[must_use]
    pub fn new(messages: &[Vec<TrigramValue>]) -> Self {
        Self {
            lengths: messages.iter().map(Vec::len).collect(),
            pool: messages.iter().flatten().copied().collect(),
        }
    }
}

impl NullSampler for ValueResample {
    type Draw = Vec<Vec<TrigramValue>>;

    fn sample(&self, rng: &mut SplitMix64) -> Result<Self::Draw, RandomBoundError> {
        let pool_len = self.pool.len();
        let mut draw = Vec::with_capacity(self.lengths.len());
        for &length in &self.lengths {
            let mut message = Vec::with_capacity(length);
            for _cell in 0..length {
                let index = random_index_below(pool_len, rng)?;
                let value = self
                    .pool
                    .get(index)
                    .copied()
                    .ok_or(RandomBoundError { bound: pool_len })?;
                message.push(value);
            }
            draw.push(message);
        }
        Ok(draw)
    }
}

/// Error raised while running the predicate battery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PredicateError {
    /// The verified corpus grids could not be reconstructed or read.
    Grid(GridError),
    /// A bounded PRNG draw failed inside the value-resample sampler.
    Random(RandomBoundError),
    /// The input contained no messages, so no predicate can be evaluated.
    EmptyInput,
}

impl fmt::Display for PredicateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Grid(error) => write!(f, "grid/order error: {error:?}"),
            Self::Random(error) => write!(f, "random draw failed: bound {}", error.bound),
            Self::EmptyInput => write!(f, "input contained no messages"),
        }
    }
}

impl std::error::Error for PredicateError {}

impl From<GridError> for PredicateError {
    fn from(error: GridError) -> Self {
        Self::Grid(error)
    }
}

impl From<RandomBoundError> for PredicateError {
    fn from(error: RandomBoundError) -> Self {
        Self::Random(error)
    }
}

impl From<NullTestError<Infallible>> for PredicateError {
    fn from(error: NullTestError<Infallible>) -> Self {
        match error {
            NullTestError::Random(random) => Self::Random(random),
            // The statistic is infallible, so this arm is uninhabited.
            NullTestError::Statistic(never) => match never {},
        }
    }
}

/// Reads the eye corpus value streams under the accepted honeycomb reading order.
///
/// # Errors
/// Returns [`PredicateError::Grid`] if the verified corpus cannot be read.
pub fn corpus_message_values() -> Result<Vec<Vec<TrigramValue>>, PredicateError> {
    let grids = orders::corpus_grids()?;
    let messages = read_corpus_message_values(&grids, accepted_honeycomb_order())?;
    Ok(messages)
}

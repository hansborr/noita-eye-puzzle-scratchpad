//! In-process self-test: planted positive controls + matched non-satisfying
//! nulls for every predicate, covering **both** null shapes.
//!
//! For each predicate we construct an input that is FORCED to satisfy it and
//! confirm the matched null flags it at low empirical p, plus a matched
//! non-satisfying input that the detector must leave un-flagged (high p). The
//! controls call the very same library functions the CLI's battery calls
//! ([`Predicate::statistic`] / [`Predicate::satisfied`] and the shared samplers),
//! so a passing self-test exercises the production path, not a parallel one.

use std::convert::Infallible;

use crate::core::trigram::TrigramValue;
use crate::nulls::null::{WithinMessageShuffle, add_one_p_value, mix_seed, run_null_test};

use super::{NullShape, Predicate, ValueResample};

/// Monte-Carlo trials per control (small enough to stay in the test budget).
const SELF_TEST_TRIALS: usize = 1_000;

/// A planted positive control must reach at least this significance.
const POSITIVE_MAX_P: f64 = 0.05;

/// A matched non-satisfying control must stay at least this un-significant.
const NEGATIVE_MIN_P: f64 = 0.5;

/// 9 `abab`-shaped, two-digit-prime-free target sums (each `101 × {2,3,5,7}`-smooth).
const ABAB_SMOOTH_TARGETS: [u64; 9] = [3636, 4040, 4545, 4848, 5050, 5454, 5656, 6464, 7272];

/// One named control outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlCheck {
    /// What the control asserts.
    pub name: &'static str,
    /// Whether it held.
    pub passed: bool,
}

/// The full self-test result: every control plus the overall verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfTestResult {
    /// Per-control pass/fail in evaluation order.
    pub checks: Vec<ControlCheck>,
    /// Whether every control passed.
    pub passed: bool,
}

/// Runs every planted control and returns the aggregate verdict.
///
/// Deterministic in `seed`: each control draws from a `seed`-derived PRNG
/// sub-stream. Both null shapes are exercised (the gap predicate against a
/// within-message shuffle, the rest against a pooled value-resample).
#[must_use]
pub fn predicate_self_test(seed: u64) -> SelfTestResult {
    let gap_pos = plant_gap_positive();
    let gap_neg = plant_gap_negative();
    let start_pos = plant_start_positive();
    let start_neg = plant_start_negative();
    let sum_pos = plant_abab_prime_positive();
    let abab_neg = plant_non_abab(&[4000, 4100, 4200, 4300, 4700, 5100, 5300, 5900, 6100]);
    let prime_neg = plant_non_abab(&[4400, 4411, 4422, 4433, 4444, 4455, 4466, 4477, 4488]);
    let coprime_pos = plant_coprime_positive();
    let coprime_neg = plant_coprime_negative();

    let mut checks = Vec::new();
    let mut index = 0u64;
    let mut control = |name: &'static str,
                       predicate: Predicate,
                       positive: bool,
                       input: &[Vec<TrigramValue>],
                       checks: &mut Vec<ControlCheck>| {
        let p = predicate_p(predicate, input, mix_seed(seed, index), SELF_TEST_TRIALS);
        index += 1;
        let satisfied = predicate.satisfied(input);
        let passed = if positive {
            satisfied && p <= POSITIVE_MAX_P
        } else {
            !satisfied && p >= NEGATIVE_MIN_P
        };
        checks.push(ControlCheck { name, passed });
    };

    control(
        "a: planted only-missing-gap-1 detected (shuffle null)",
        Predicate::OnlyMissingGapOne,
        true,
        &gap_pos,
        &mut checks,
    );
    control(
        "a: gap-with-adjacency rejected",
        Predicate::OnlyMissingGapOne,
        false,
        &gap_neg,
        &mut checks,
    );
    control(
        "b: planted all-starts>26 detected (resample null)",
        Predicate::StartingTrigramAbove,
        true,
        &start_pos,
        &mut checks,
    );
    control(
        "b: low-start corpus rejected",
        Predicate::StartingTrigramAbove,
        false,
        &start_neg,
        &mut checks,
    );
    control(
        "c: planted abab-sums detected (resample null)",
        Predicate::AbabDecimalSum,
        true,
        &sum_pos,
        &mut checks,
    );
    control(
        "c: non-abab sums rejected",
        Predicate::AbabDecimalSum,
        false,
        &abab_neg,
        &mut checks,
    );
    control(
        "d: planted no-2-digit-prime sums detected",
        Predicate::NoTwoDigitPrimeFactorSum,
        true,
        &sum_pos,
        &mut checks,
    );
    control(
        "d: prime-factored sums rejected",
        Predicate::NoTwoDigitPrimeFactorSum,
        false,
        &prime_neg,
        &mut checks,
    );
    control(
        "e: planted non-coprime first-pairs detected",
        Predicate::FirstTwoNonCoprime,
        true,
        &coprime_pos,
        &mut checks,
    );
    control(
        "e: coprime first-pairs rejected",
        Predicate::FirstTwoNonCoprime,
        false,
        &coprime_neg,
        &mut checks,
    );

    let passed = checks.iter().all(|check| check.passed);
    SelfTestResult { checks, passed }
}

/// Empirical upper-tail p of `predicate` on `messages` against its matched null.
///
/// Mirrors the battery's `evaluate`, but standalone so the controls can score an
/// arbitrary planted input. On the (unreachable for in-bounds slices) sampler
/// error it returns the most-conservative `p = 1`, so a control can never pass by
/// accident.
fn predicate_p(
    predicate: Predicate,
    messages: &[Vec<TrigramValue>],
    seed: u64,
    trials: usize,
) -> f64 {
    let observed = predicate.statistic(messages);
    let statistic =
        |draw: &Vec<Vec<TrigramValue>>| Ok::<usize, Infallible>(predicate.statistic(draw));
    let hits = match predicate.null_shape() {
        NullShape::WithinMessageShuffle => run_null_test(
            statistic,
            observed,
            &WithinMessageShuffle { messages },
            trials,
            seed,
        )
        .map_or(trials, |result| result.upper_tail_count),
        NullShape::ValueResample => run_null_test(
            statistic,
            observed,
            &ValueResample::new(messages),
            trials,
            seed,
        )
        .map_or(trials, |result| result.upper_tail_count),
    };
    add_one_p_value(hits, trials)
}

/// Converts a `u8` value list to bounded trigram values (out-of-range values,
/// which the planted constructors never produce, are dropped rather than panic).
fn trigrams(raw: &[u8]) -> Vec<TrigramValue> {
    raw.iter()
        .filter_map(|&value| TrigramValue::new(value).ok())
        .collect()
}

/// A diverse base-10 value tail (`1..=70`, cycling) of the given length, used to
/// keep the value-resample pool from collapsing onto a few residues.
fn diverse_tail(length: usize) -> Vec<u8> {
    (0..length).map(|index| ((index % 70) + 1) as u8).collect()
}

/// A single message whose values sum to exactly `target`, drawn from a diverse
/// cycling base so the pooled-resample null does not concentrate.
fn message_summing_to(target: u64) -> Vec<u8> {
    let mut raw = Vec::new();
    let mut sum = 0u64;
    let mut next: u8 = 1;
    while sum + u64::from(next) <= target {
        raw.push(next);
        sum += u64::from(next);
        next = if next >= 70 { 1 } else { next + 1 };
    }
    let remainder = target - sum;
    if remainder > 0
        && let Ok(value) = u8::try_from(remainder)
    {
        raw.push(value);
    }
    raw
}

/// Single message realizing recurrence distances `2..=max_distance` exactly once
/// each, never distance 1, so the only missing gap size over `1..=max_distance`
/// is 1.
fn plant_gap_positive() -> Vec<Vec<TrigramValue>> {
    const MAX_DISTANCE: usize = 12;
    let mut raw: Vec<u8> = Vec::new();
    let mut filler: u8 = MAX_DISTANCE as u8; // fillers sit above the distinct X_d band
    for distance in 2..=MAX_DISTANCE {
        let echo = (distance - 2) as u8; // a distinct value per block
        raw.push(echo);
        for _intervening in 1..distance {
            raw.push(filler);
            filler = filler.wrapping_add(1);
        }
        raw.push(echo);
    }
    vec![trigrams(&raw)]
}

/// The gap-positive stream plus an adjacent-equal pair, so distance 1 is now
/// realized and the "only missing gap is 1" claim fails.
fn plant_gap_negative() -> Vec<Vec<TrigramValue>> {
    let mut message = plant_gap_positive();
    if let Some(first) = message.first_mut() {
        let adjacent = TrigramValue::new(80);
        if let Ok(value) = adjacent {
            first.push(value);
            first.push(value);
        }
    }
    message
}

/// Nine messages that each start with a high value (50) over a low-value body, so
/// every start exceeds 26 yet the pooled values rarely do.
fn plant_start_positive() -> Vec<Vec<TrigramValue>> {
    (0..9)
        .map(|_message| {
            let mut raw = vec![50u8];
            raw.extend(std::iter::repeat_n(5u8, 9));
            trigrams(&raw)
        })
        .collect()
}

/// Nine messages that all start with a low value (5), so no start exceeds 26.
fn plant_start_negative() -> Vec<Vec<TrigramValue>> {
    (0..9)
        .map(|_message| trigrams(&[5, 5, 5, 5, 5, 5]))
        .collect()
}

/// Nine messages whose decimal sums are all `abab`-shaped AND two-digit-prime-free
/// (shared by the (c) and (d) positive controls).
fn plant_abab_prime_positive() -> Vec<Vec<TrigramValue>> {
    ABAB_SMOOTH_TARGETS
        .iter()
        .map(|&target| trigrams(&message_summing_to(target)))
        .collect()
}

/// Nine messages summing to the given (non-`abab`) targets.
fn plant_non_abab(targets: &[u64]) -> Vec<Vec<TrigramValue>> {
    targets
        .iter()
        .map(|&target| trigrams(&message_summing_to(target)))
        .collect()
}

/// Nine messages whose first two values share a factor (6, 4), over a diverse tail.
fn plant_coprime_positive() -> Vec<Vec<TrigramValue>> {
    (0..9)
        .map(|_message| {
            let mut raw = vec![6u8, 4u8];
            raw.extend(diverse_tail(20));
            trigrams(&raw)
        })
        .collect()
}

/// Nine messages whose first two values are coprime (3, 5), over a diverse tail.
fn plant_coprime_negative() -> Vec<Vec<TrigramValue>> {
    (0..9)
        .map(|_message| {
            let mut raw = vec![3u8, 5u8];
            raw.extend(diverse_tail(20));
            trigrams(&raw)
        })
        .collect()
}

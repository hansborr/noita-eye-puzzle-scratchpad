//! Tests for the hidden-state (deck-stabilizer) GAK instruments.
//!
//! These exercise the **same library functions the `gak` CLI subcommand calls**
//! ([`super::run_self_test`], [`super::discriminate`], [`super::solve_candidate`]),
//! so the instrument and its regression cannot drift. Discipline (mirrors
//! `known_answer.rs` / `hidden_state.rs`):
//! 1. **Positive control** — the self-test's blind solver recovers a *synthetic*
//!    known-answer deck-stabilizer GAK plaintext to >=90% (must fire; failure is a
//!    methodology bug, never a finding).
//! 2. **Matched null** — a Fisher-Yates shuffle of that synthetic is rejected by
//!    the no-same-class precondition (or does not recover), so the recovery is the
//!    cipher structure, not an always-fits artifact.
//! 3. **Discriminator** — the Markov-excess statistic separates the hidden-state
//!    synthetic from a visible-state (convention A) synthetic, and the real puzzle
//!    `two` lands on the hidden-state side.
//! 4. **Honest negative on `two`** — the synthetic-validated solver runs on `two`
//!    but, with a generic English LM, produces no English-like candidate (it does
//!    not beat a matched no-English control). This is blocked on the unknown
//!    codec/convention; **no decode of `two` is claimed.**

use std::collections::BTreeMap;

use super::instrument::{build_ciphertext, english_eight_symbol};
use super::{
    DEFAULT_GENERATIONS, DEFAULT_POPULATION, DEFAULT_SEED, DeckConvention, HiddenVisibleVerdict,
    VISIBLE_ALPHABET, discriminate, run_self_test, solve_candidate,
};
use crate::attack::quadgram::ENGLISH_CORPUS_LARGE;

/// Length of the real `two` puzzle in 12-symbol values.
const TWO_LEN: usize = 698;
/// Deterministic key seed for the discriminator's synthetic fixtures.
const KEY_SEED: u64 = 0x6831_625f_7669_7401;

/// Parses the real `two` puzzle into 12-symbol values.
fn parse_two() -> Vec<u8> {
    let index: BTreeMap<char, u8> = "ABCDEFGHIJKL"
        .chars()
        .enumerate()
        .map(|(i, c)| (c, u8::try_from(i).expect("alphabet under 256")))
        .collect();
    include_str!("../../../../research/data/practice-puzzles/two")
        .chars()
        .filter_map(|c| index.get(&c).copied())
        .collect()
}

/// Positive control: the self-test's known-key decode and blind solve both recover
/// the synthetic known-answer plaintext. This **must** fire.
#[test]
fn self_test_positive_control_fires() {
    let report = run_self_test(DEFAULT_SEED).expect("self-test runs");
    assert!(
        report.known_key_accuracy >= 0.99,
        "known-key decode {:.3} must recover the plaintext (machinery sanity)",
        report.known_key_accuracy
    );
    assert!(
        report.blind_accuracy >= 0.90,
        "blind recovery {:.3} must be >= 0.90 (positive control; failure = methodology bug)",
        report.blind_accuracy
    );
    assert!(
        report.positive_control_passed,
        "the positive control must pass"
    );
}

/// Matched null: the self-test's Fisher-Yates shuffle of the synthetic ciphertext
/// does not recover. The shuffle destroys class-alternation, so the no-same-class
/// precondition rejects it outright — the recovery is provably the cipher
/// structure, not an always-fits artifact.
#[test]
fn self_test_matched_null_does_not_recover() {
    let report = run_self_test(DEFAULT_SEED).expect("self-test runs");
    assert!(
        report.null_rejected > 0,
        "the matched shuffle null must trip the no-same-class precondition at least once"
    );
    assert!(
        report.null_max_accuracy < 0.5,
        "a matched shuffle null that slipped past the precondition recovered {:.3}; it must stay well below the >=0.90 real recovery",
        report.null_max_accuracy
    );
    assert!(report.null_failed, "the matched null must fail to recover");
    assert!(report.passed, "the overall self-test must pass");
}

/// Discriminator: the Markov-excess statistic separates a hidden-state
/// (post-compose) synthetic from a visible-state (pre-compose) synthetic, and the
/// real `two` lands on the hidden-state side. The synthetics are generated at
/// `two`'s length so the finite-sample entropy bias is matched.
#[test]
fn markov_excess_separates_hidden_from_visible_and_two_is_hidden() {
    let plaintext = english_eight_symbol(8000, TWO_LEN);
    let hidden_ct = build_ciphertext(&plaintext, KEY_SEED, DeckConvention::HiddenState)
        .expect("hidden encrypt");
    let visible_ct = build_ciphertext(&plaintext, KEY_SEED, DeckConvention::VisibleState)
        .expect("visible encrypt");

    let hidden = discriminate(&hidden_ct, VISIBLE_ALPHABET).expect("hidden discriminate");
    let visible = discriminate(&visible_ct, VISIBLE_ALPHABET).expect("visible discriminate");
    assert!(
        hidden.excess > visible.excess + 0.15,
        "hidden-state drop {:.3} must exceed visible-state drop {:.3} by >0.15",
        hidden.excess,
        visible.excess
    );
    assert_eq!(
        hidden.verdict,
        HiddenVisibleVerdict::HiddenState,
        "hidden synthetic must be called hidden-state"
    );
    assert_ne!(
        visible.verdict,
        HiddenVisibleVerdict::HiddenState,
        "visible synthetic must not be called hidden-state"
    );

    let two = parse_two();
    assert_eq!(two.len(), TWO_LEN, "two is 698 symbols");
    let two_report = discriminate(&two, VISIBLE_ALPHABET).expect("two discriminate");
    assert!(
        two_report.excess > visible.excess + 0.15,
        "real two drop {:.3} must land on the hidden-state side of visible {:.3}",
        two_report.excess,
        visible.excess
    );
    assert_eq!(
        two_report.verdict,
        HiddenVisibleVerdict::HiddenState,
        "real two must be called hidden-state"
    );
}

/// Honest negative on `two`: the synthetic-validated solver runs on `two` but, with
/// a generic English LM, its best candidate is no more English-like than a matched
/// no-English control (a random-plaintext convention-B synthetic decoded by the
/// identical solver), and far below genuine English. There is no clean English
/// decode — recovery is blocked on the unknown codec/convention. **No decode of
/// `two` is claimed.**
#[test]
fn two_honest_negative_no_english_decode() {
    let two = parse_two();
    let candidate = solve_candidate(
        &two,
        ENGLISH_CORPUS_LARGE,
        DEFAULT_POPULATION,
        DEFAULT_GENERATIONS,
        DEFAULT_SEED,
    )
    .expect("solve_candidate runs on two");

    assert!(
        !candidate.plaintext.is_empty(),
        "the solver runs on two (it does not die at seeding the way solve_gctak does)"
    );
    assert!(
        candidate.candidate_fit <= candidate.control_fit + 0.05,
        "two candidate fit {:.4} must not exceed the matched no-English control {:.4}: no English recovered (blocked on the unknown codec/convention)",
        candidate.candidate_fit,
        candidate.control_fit
    );
    assert!(
        candidate.candidate_fit < candidate.english_ceiling - 0.2,
        "two candidate fit {:.4} must be far below the genuine-English ceiling {:.4}: not an English decode",
        candidate.candidate_fit,
        candidate.english_ceiling
    );
    assert!(
        !candidate.beats_control,
        "two candidate must not beat the matched no-English control"
    );
}

//! Tests for the hidden-state (deck-stabilizer) GAK solver and the
//! hidden-vs-visible Markov-excess discriminator.
//!
//! Discipline (mirrors `known_answer.rs` / `hidden_state.rs`):
//! 1. **Positive control** — the solver recovers a *synthetic* known-answer
//!    deck-stabilizer GAK plaintext to >=90% (must fire; failure is a methodology
//!    bug, never a finding).
//! 2. **Matched null** — a Fisher-Yates shuffle of that synthetic does not
//!    recover, so the recovery is the cipher structure, not an always-fits
//!    artifact.
//! 3. **Discriminator** — the Markov-excess statistic separates the hidden-state
//!    synthetic from a visible-state (convention A) synthetic, and the real
//!    puzzle `two` lands on the hidden-state side.
//! 4. **Honest negative on `two`** — the synthetic-validated solver runs on
//!    `two` but, with a generic English LM, produces no English-like decode. This
//!    is blocked on the unknown codec/convention; **no decode of `two` is
//!    claimed.**

use std::collections::BTreeMap;

use super::{
    BigramLm, DeckConvention, DeckTables, decode_with_key, draw_key, encrypt, markov_excess,
    solve_hidden_state_gak,
};
use crate::attack::quadgram::ENGLISH_CORPUS_LARGE;
use crate::nulls::null::{SplitMix64, fisher_yates, random_index_below};

// Shared fixture parameters: the synthetic is built from a 700-letter English
// slice mapped to 8 symbols by frequency rank, encrypted under a fixed key.
const PLAINTEXT_START: usize = 8000;
const PLAINTEXT_LEN: usize = 1500;
const KEY_SEED: u64 = 0x6831_625f_7669_7401;
const SOLVE_SEED: u64 = 0x00C0_FFEE_C0DE_0001;
const POPULATION: usize = 80;
const GENERATIONS: usize = 60;
const VISIBLE_ALPHABET: usize = 12;
const SMOOTHING: f64 = 0.3;

/// Maps a slice of the bundled English corpus to an 8-symbol stream by frequency
/// rank (`rank mod 8`) — a plausible expanding-codec analogue with English-like
/// bigram correlations (the validated Python uses the same reduction).
fn english_eight_symbol(start: usize, len: usize) -> Vec<usize> {
    let letters: Vec<char> = ENGLISH_CORPUS_LARGE
        .chars()
        .filter(char::is_ascii_alphabetic)
        .map(|c| c.to_ascii_uppercase())
        .skip(start)
        .take(len)
        .collect();
    let mut counts: BTreeMap<char, usize> = BTreeMap::new();
    for &c in &letters {
        *counts.entry(c).or_insert(0usize) += 1;
    }
    let mut order: Vec<(char, usize)> = counts.into_iter().collect();
    order.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut to_eight: BTreeMap<char, usize> = BTreeMap::new();
    for (rank, (c, _count)) in order.iter().enumerate() {
        let _previous = to_eight.insert(*c, rank % 8);
    }
    letters
        .iter()
        .map(|c| to_eight.get(c).copied().unwrap_or(0))
        .collect()
}

/// An i.i.d. uniform 8-symbol stream (the no-English baseline).
fn uniform_eight_symbol(len: usize, seed: u64) -> Vec<usize> {
    let mut rng = SplitMix64::new(seed);
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(random_index_below(8, &mut rng).expect("8 is a valid draw bound"));
    }
    out
}

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

/// Best plaintext-recovery accuracy under symbol relabeling: align decoded
/// symbols (positions `1..n`) to the held truth, relabel each decoded class to
/// its majority truth symbol, and score. This is how the validated Python
/// measures recovery.
fn relabel_accuracy(decoded: &[usize], truth_full: &[usize]) -> f64 {
    if decoded.is_empty() {
        return 0.0;
    }
    let truth_tail: Vec<usize> = truth_full.iter().skip(1).copied().collect();
    let mut groups: BTreeMap<usize, BTreeMap<usize, usize>> = BTreeMap::new();
    for (decoded_sym, truth_sym) in decoded.iter().zip(truth_tail.iter()) {
        *groups
            .entry(*decoded_sym)
            .or_default()
            .entry(*truth_sym)
            .or_insert(0usize) += 1;
    }
    let mut relabel: BTreeMap<usize, usize> = BTreeMap::new();
    for (decoded_sym, counter) in &groups {
        if let Some((truth_sym, _count)) = counter.iter().max_by_key(|entry| *entry.1) {
            let _previous = relabel.insert(*decoded_sym, *truth_sym);
        }
    }
    let correct = decoded
        .iter()
        .zip(truth_tail.iter())
        .filter(|(decoded_sym, truth_sym)| relabel.get(decoded_sym) == Some(*truth_sym))
        .count();
    correct as f64 / decoded.len() as f64
}

/// The shared synthetic hidden-state fixture: `(plaintext, ciphertext)`.
fn synthetic_fixture() -> (Vec<usize>, Vec<u8>) {
    let tables = DeckTables::build().expect("deck tables");
    let plaintext = english_eight_symbol(PLAINTEXT_START, PLAINTEXT_LEN);
    let key = draw_key(&tables, KEY_SEED).expect("key");
    let ciphertext =
        encrypt(&plaintext, &key, &tables, DeckConvention::HiddenState).expect("encrypt");
    (plaintext, ciphertext)
}

/// Positive control: the solver recovers the synthetic known-answer plaintext to
/// >=90% under symbol relabeling. This **must** fire.
#[test]
fn positive_control_recovers_synthetic_deck_stabilizer_plaintext() {
    let (plaintext, ciphertext) = synthetic_fixture();
    assert_eq!(ciphertext.len(), PLAINTEXT_LEN, "ciphertext length");

    // Observable signature: all 12 symbols, class (mod 3) always changes.
    let used: std::collections::BTreeSet<u8> = ciphertext.iter().copied().collect();
    assert_eq!(
        used.len(),
        VISIBLE_ALPHABET,
        "uses the full 12-symbol alphabet"
    );
    for window in ciphertext.windows(2) {
        if let [a, b] = window {
            assert_ne!(
                a % 3,
                b % 3,
                "consecutive symbols change class (eps in 1..3)"
            );
        }
    }

    let lm = BigramLm::from_symbols(&plaintext, 8, SMOOTHING).expect("plaintext LM");

    // Known-key sanity: decoding under the *actual* generator key recovers the
    // plaintext almost exactly — the deterministic decode machinery is correct,
    // so any shortfall below is a search miss, never a decode bug.
    let tables = DeckTables::build().expect("deck tables");
    let true_key = draw_key(&tables, KEY_SEED).expect("true key");
    let (_score, true_decode) =
        decode_with_key(&ciphertext, &lm, &true_key).expect("known-key decode");
    assert!(
        relabel_accuracy(&true_decode, &plaintext) >= 0.99,
        "known-key decode must recover the plaintext (machinery sanity)"
    );

    // The blind solve recovers the key/plaintext from ciphertext alone to >=90%.
    let recovery = solve_hidden_state_gak(&ciphertext, &lm, POPULATION, GENERATIONS, SOLVE_SEED)
        .expect("solve");
    let accuracy = relabel_accuracy(&recovery.plaintext, &plaintext);
    assert!(
        accuracy >= 0.90,
        "synthetic recovery accuracy {accuracy:.3} must be >= 0.90 (positive control; failure = methodology bug)"
    );
}

/// Matched null: the same pipeline on a Fisher-Yates shuffle of the synthetic
/// ciphertext does not recover (the shuffle destroys the class-alternation and
/// deck structure the convention-B decode relies on).
#[test]
fn matched_shuffle_null_does_not_recover() {
    let (plaintext, ciphertext) = synthetic_fixture();
    let lm = BigramLm::from_symbols(&plaintext, 8, SMOOTHING).expect("plaintext LM");

    let mut max_null = 0.0f64;
    for trial in 0u64..3 {
        let mut shuffled = ciphertext.clone();
        let mut rng = SplitMix64::new(0x6e75_6c6c_5f32_0000 ^ trial.wrapping_mul(0x9e37_79b9));
        fisher_yates(&mut shuffled, &mut rng).expect("non-empty shuffle");
        let recovery = solve_hidden_state_gak(&shuffled, &lm, POPULATION, GENERATIONS, SOLVE_SEED)
            .expect("solve");
        let accuracy = relabel_accuracy(&recovery.plaintext, &plaintext);
        if accuracy > max_null {
            max_null = accuracy;
        }
    }
    assert!(
        max_null < 0.5,
        "matched shuffle null recovered {max_null:.3}; it must stay well below the >=0.90 real recovery"
    );
}

/// Discriminator: the Markov-excess statistic separates a hidden-state
/// (post-compose) synthetic from a visible-state (pre-compose) synthetic, and the
/// real `two` lands on the hidden-state side. The synthetics are generated at
/// `two`'s length so the finite-sample entropy bias is matched.
#[test]
fn markov_excess_separates_hidden_from_visible_and_two_is_hidden() {
    let tables = DeckTables::build().expect("deck tables");
    let plaintext = english_eight_symbol(PLAINTEXT_START, 698);
    let key = draw_key(&tables, KEY_SEED).expect("key");
    let hidden =
        encrypt(&plaintext, &key, &tables, DeckConvention::HiddenState).expect("hidden encrypt");
    let visible =
        encrypt(&plaintext, &key, &tables, DeckConvention::VisibleState).expect("visible encrypt");

    let hidden_drop = markov_excess(&hidden, VISIBLE_ALPHABET).expect("hidden drop");
    let visible_drop = markov_excess(&visible, VISIBLE_ALPHABET).expect("visible drop");

    let two = parse_two();
    assert_eq!(two.len(), 698, "two is 698 symbols");
    let two_drop = markov_excess(&two, VISIBLE_ALPHABET).expect("two drop");

    assert!(
        hidden_drop > visible_drop + 0.15,
        "hidden-state drop {hidden_drop:.3} must exceed visible-state drop {visible_drop:.3} by >0.15"
    );
    assert!(
        two_drop > visible_drop + 0.15,
        "real two drop {two_drop:.3} must land on the hidden-state side of visible {visible_drop:.3}"
    );
}

/// Honest negative on `two`: the synthetic-validated solver runs on `two` (no
/// seeding death, unlike `solve_gctak`), but with a generic English LM its best
/// decode is no more English-like than a **matched no-English control** (a
/// random-plaintext convention-B synthetic run through the identical solver), and
/// far below genuine English. There is no clean <=26-symbol English decode —
/// recovery is blocked on the unknown codec/convention. **No decode of `two` is
/// claimed.**
#[test]
fn two_honest_negative_no_english_decode() {
    let tables = DeckTables::build().expect("deck tables");
    let two = parse_two();

    // A generic English 8-symbol bigram LM from a disjoint corpus slice, plus the
    // genuine-English fit floor under it.
    let generic_plaintext = english_eight_symbol(20_000, 20_000);
    let lm = BigramLm::from_symbols(&generic_plaintext, 8, SMOOTHING).expect("generic LM");
    let english_floor = lm
        .mean_bigram_log_prob(&generic_plaintext)
        .expect("english floor");

    // Matched no-English control: a convention-B synthetic of *random* plaintext,
    // same length as `two`, decoded by the *identical* solver. Its English-fit is
    // the noise floor the solver's overfitting can reach when no English exists
    // but the cipher structure is exactly right.
    let control_plaintext = uniform_eight_symbol(two.len(), 0x4e6f_456e_6700_0001);
    let control_key = draw_key(&tables, 0x6374_726c_0000_0001).expect("control key");
    let control_ciphertext = encrypt(
        &control_plaintext,
        &control_key,
        &tables,
        DeckConvention::HiddenState,
    )
    .expect("control encrypt");
    let control_fit = lm
        .mean_bigram_log_prob(
            &solve_hidden_state_gak(
                &control_ciphertext,
                &lm,
                POPULATION,
                GENERATIONS,
                SOLVE_SEED,
            )
            .expect("control solve")
            .plaintext,
        )
        .expect("control fit");

    // The solver runs on `two` (the convention-B structural precondition holds)...
    let recovery = solve_hidden_state_gak(&two, &lm, POPULATION, GENERATIONS, SOLVE_SEED)
        .expect("solve runs on two");
    assert!(
        !recovery.plaintext.is_empty(),
        "the solver runs on two (it does not die at seeding the way solve_gctak does)"
    );
    let two_fit = lm
        .mean_bigram_log_prob(&recovery.plaintext)
        .expect("two decode fit");

    // ...but its best decode is no more English-like than the no-English control
    // (matched-pipeline discipline) and far below genuine English. No English.
    assert!(
        two_fit <= control_fit + 0.05,
        "two decode English-fit {two_fit:.4} must not exceed the matched no-English control {control_fit:.4}: no English recovered (blocked on the unknown codec/convention)"
    );
    assert!(
        two_fit < english_floor - 0.2,
        "two decode English-fit {two_fit:.4} must be far below the genuine-English floor {english_floor:.4}: not an English decode"
    );
}

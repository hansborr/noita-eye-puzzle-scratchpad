//! Thread G1b — a hidden-state-capable GAK attack and its application to the
//! known-answer practice puzzle `two`.
//!
//! G1 showed the bijective-readout GCTAK solver
//! ([`solve_gctak`](crate::gak_attack::solver::solve_gctak)) **dies at seeding** on
//! `two` (every symbol has out-degree 8 — the many-valued hidden-subgroup signature).
//! This module attacks that regime with the hidden-state machinery (idea 3's
//! [`run_marginalization_attack`](crate::gak_attack::marginalization::run_marginalization_attack)),
//! which recovers, per plaintext letter, the **marginal** set of visible coset edges
//! over hidden states (a multi-valued action, not a fixed permutation).
//!
//! Binding honesty discipline (mirrors `known_answer.rs`):
//!
//! 1. **Positive control first.** A synthetic hidden-state GAK whose readout
//!    reproduces `two`'s signature exactly (12 symbols in 3 classes by index mod 3;
//!    consecutive symbols never share a class, so out-degree is exactly 8, not the
//!    bijective `= num_letters`). With a repeated-phrase plaintext recovery **fires**
//!    and a within-instance Fisher-Yates shuffle null recovers it **0/N**; the
//!    signature is asserted so the generator cannot have made recovery trivial.
//! 2. **The substrate is the lever, on ground truth.** The SAME cipher with a
//!    *realistic* (non-repeated-phrase) plaintext recovers several times fewer true
//!    edges — recoverability hinges on a dominant repeated phrase, which `two` lacks.
//! 3. **`two` itself: an honest negative.** The attack *runs* on `two` (no seeding
//!    death), but real text has no dominant repeated phrase, so the beam recovers
//!    only a few tiny column marginals covering a sliver of the stream — 76–83% of
//!    transitions stay undecidable, so there is no whole-stream keystream to feed the
//!    codec. No candidate text is logged (a score on the wrong structure is never a
//!    recovery).
//!
//! All `#[cfg(test)]` (a child of `known_answer`): no public surface; it drives the
//! existing `pub(crate)` recovery, reusing the codec/chain-link/beam primitives.

use crate::gak_attack::marginalization::{
    DEFAULT_BEAM_WIDTH, SmallSupportPrior, run_marginalization_attack,
};
use crate::gak_attack::solver::{CosetEdge, aligned_phrase_occurrences};
use crate::null::{SplitMix64, fisher_yates, random_index_below, shuffled_permutation};
use crate::trigram::TrigramValue;
use std::collections::{BTreeMap, BTreeSet};

// --- A. Synthetic hidden-state GAK matched to `two`'s signature. ---

/// Hidden deck size: the rank coordinate lives in `0..DECK_N`; the hidden state is
/// the rest of the deck, giving `|H| = (DECK_N - 1)!`.
const DECK_N: usize = 4;
/// The class coordinate is `0..CLASS_MOD`; matches `two`'s index-mod-3 class.
const CLASS_MOD: usize = 3;
/// The marked card whose deck position is the visible rank.
const MARKED: usize = 0;
/// Visible alphabet size: `CLASS_MOD * DECK_N = 12` (exactly `two`'s alphabet).
const ALPHABET: usize = CLASS_MOD * DECK_N;

/// One plaintext letter: a non-zero class shift (so the class always changes — the
/// no-same-class-successor constraint) and a deck permutation on the cards (the
/// hidden-state half).
#[derive(Clone, Debug)]
struct HiddenLetter {
    /// Class increment `mod CLASS_MOD`, in `1..CLASS_MOD` (never `0`).
    shift: usize,
    /// Permutation of cards `0..DECK_N` (`new_deck[i] = deck_perm[deck[i]]`).
    deck_perm: Vec<usize>,
}

/// Which plaintext the generator emits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Plaintext {
    /// One phrase repeated with short mixing runs — the recoverable isomorph
    /// substrate (positive control).
    RepeatedPhrase,
    /// i.i.d. random letters, no dominant repeated phrase — the analogue of `two`'s
    /// real text where one isomorph signature lumps many contexts.
    Realistic,
}

/// A synthetic hidden-state GAK fixture with held-back ground truth.
struct HiddenStateFixture {
    /// Visible ciphertext (symbols `0..ALPHABET`).
    ciphertext: Vec<TrigramValue>,
    /// Held ground-truth keystream: `keystream[i]` produced `ciphertext[i-1] ->
    /// ciphertext[i]` — the partition a full decode would have to recover.
    keystream: Vec<usize>,
    /// Held ground-truth per-letter coset-edge marginals (`truth_edges[a]` = every
    /// `(from, to)` letter `a` produced) — what the attack tries to recover.
    truth_edges: Vec<BTreeSet<CosetEdge>>,
    /// Number of plaintext letters.
    num_letters: usize,
}

fn symbol_of(class: usize, rank: usize) -> u8 {
    u8::try_from(class + CLASS_MOD * rank).expect("symbol < 12 fits u8")
}

fn rank_of(deck: &[usize]) -> usize {
    deck.iter()
        .position(|&card| card == MARKED)
        .expect("marked card is always in the deck")
}

/// Applies a letter to a `(class, deck)` state, returning the next state.
fn apply_letter(class: usize, deck: &[usize], letter: &HiddenLetter) -> (usize, Vec<usize>) {
    let next_class = (class + letter.shift) % CLASS_MOD;
    // new_deck[i] = perm[deck[i]]; the new rank (position of card 0) depends on the
    // WHOLE old deck, not just the old rank — that is the hidden state.
    let next_deck: Vec<usize> = deck
        .iter()
        .map(|&card| *letter.deck_perm.get(card).expect("perm covers all cards"))
        .collect();
    (next_class, next_deck)
}

/// Draws `num_letters` distinct letters: alternating class shift `1`/`2` (both
/// present), each a random non-identity deck permutation — enough to fill out-degree 8.
fn draw_letters(num_letters: usize, rng: &mut SplitMix64) -> Vec<HiddenLetter> {
    let identity: Vec<usize> = (0..DECK_N).collect();
    let mut letters: Vec<HiddenLetter> = Vec::with_capacity(num_letters);
    let mut index = 0usize;
    while letters.len() < num_letters {
        let shift = if index.is_multiple_of(2) { 1 } else { 2 };
        index += 1;
        let mut deck_perm = identity.clone();
        for _attempt in 0..64 {
            deck_perm = shuffled_permutation(DECK_N, rng).expect("deck perm");
            let distinct = deck_perm != identity
                && !letters
                    .iter()
                    .any(|l| l.shift == shift && l.deck_perm == deck_perm);
            if distinct {
                break;
            }
        }
        letters.push(HiddenLetter { shift, deck_perm });
    }
    letters
}

fn build_plaintext(
    plaintext: Plaintext,
    num_letters: usize,
    phrase_len: usize,
    phrase_repeats: usize,
    rng: &mut SplitMix64,
) -> Vec<usize> {
    match plaintext {
        Plaintext::RepeatedPhrase => {
            // One random phrase (first `num_letters` positions forced distinct),
            // repeated with one mixing letter between repeats.
            let mut phrase = Vec::with_capacity(phrase_len);
            for position in 0..phrase_len {
                let letter = if position < num_letters {
                    position
                } else {
                    random_index_below(num_letters, rng).expect("letter draw")
                };
                phrase.push(letter);
            }
            let mut stream = Vec::new();
            for repeat in 0..phrase_repeats {
                if repeat > 0 {
                    stream.push(random_index_below(num_letters, rng).expect("mix draw"));
                }
                stream.extend_from_slice(&phrase);
            }
            stream
        }
        Plaintext::Realistic => {
            // i.i.d. random letters: real-text-like, no dominant repeated phrase.
            let total = phrase_len * phrase_repeats;
            (0..total)
                .map(|_| random_index_below(num_letters, rng).expect("letter draw"))
                .collect()
        }
    }
}

fn generate_hidden_state_fixture(
    num_letters: usize,
    plaintext: Plaintext,
    phrase_len: usize,
    phrase_repeats: usize,
    seed: u64,
) -> HiddenStateFixture {
    let mut rng = SplitMix64::new(seed);
    let letters = draw_letters(num_letters, &mut rng);
    let plain = build_plaintext(plaintext, num_letters, phrase_len, phrase_repeats, &mut rng);

    // Encrypt: maintain (class, deck); emit the readout after each letter.
    let mut class = 0usize;
    let mut deck: Vec<usize> = (0..DECK_N).collect();
    let mut ciphertext: Vec<TrigramValue> = Vec::with_capacity(plain.len());
    let mut keystream: Vec<usize> = Vec::with_capacity(plain.len());
    for &letter_index in &plain {
        let letter = letters.get(letter_index).expect("letter in range");
        let (next_class, next_deck) = apply_letter(class, &deck, letter);
        class = next_class;
        deck = next_deck;
        ciphertext.push(TrigramValue::new(symbol_of(class, rank_of(&deck))).expect("symbol < 125"));
        keystream.push(letter_index);
    }

    // Held truth: per-letter edge marginal over observable consecutive transitions.
    let mut truth_edges: Vec<BTreeSet<CosetEdge>> = vec![BTreeSet::new(); num_letters];
    for i in 1..ciphertext.len() {
        let (from, to) = (
            ciphertext.get(i - 1).expect("prev").get(),
            ciphertext.get(i).expect("cur").get(),
        );
        let letter = *keystream.get(i).expect("keystream");
        if let Some(set) = truth_edges.get_mut(letter) {
            let _added = set.insert(CosetEdge { from, to });
        }
    }

    HiddenStateFixture {
        ciphertext,
        keystream,
        truth_edges,
        num_letters,
    }
}

// --- B. Signature + recovery-scoring helpers (the honesty instruments). ---

fn out_degrees(ciphertext: &[TrigramValue]) -> Vec<(u8, usize)> {
    let mut succ: Vec<BTreeSet<u8>> = vec![BTreeSet::new(); ALPHABET];
    for pair in ciphertext.windows(2) {
        if let [a, b] = pair
            && let Some(set) = succ.get_mut(usize::from(a.get()))
        {
            let _added = set.insert(b.get());
        }
    }
    succ.into_iter()
        .enumerate()
        .filter(|(_, set)| !set.is_empty())
        .map(|(s, set)| (u8::try_from(s).expect("symbol < 12"), set.len()))
        .collect()
}

fn max_out_degree(ciphertext: &[TrigramValue]) -> usize {
    out_degrees(ciphertext)
        .into_iter()
        .map(|(_, d)| d)
        .max()
        .unwrap_or(0)
}

/// Scores recovered per-column marginals against held truth at edge granularity (a
/// local copy of the marginalization sweep's private scorer): greedily attribute each
/// column to its best-matching letter (one-to-one) and count its genuinely-true edges.
fn score_marginal_edges(
    truth: &[BTreeSet<CosetEdge>],
    recovered: &[BTreeSet<CosetEdge>],
) -> (usize, usize) {
    let truth_total: usize = truth.iter().map(BTreeSet::len).sum();
    let mut used = vec![false; truth.len()];
    let mut recovered_true = 0usize;
    let mut order: Vec<usize> = (0..recovered.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(recovered.get(i).map_or(0, BTreeSet::len)));
    for column_index in order {
        let Some(column) = recovered.get(column_index) else {
            continue;
        };
        let mut best_letter: Option<usize> = None;
        let mut best_true = 0usize;
        for (letter_index, letter_edges) in truth.iter().enumerate() {
            if used.get(letter_index).copied().unwrap_or(true) {
                continue;
            }
            let true_count = column.iter().filter(|e| letter_edges.contains(e)).count();
            if true_count > best_true {
                best_true = true_count;
                best_letter = Some(letter_index);
            }
        }
        if let Some(letter_index) = best_letter {
            if let Some(slot) = used.get_mut(letter_index) {
                *slot = true;
            }
            recovered_true = recovered_true.saturating_add(best_true);
        }
    }
    (recovered_true, truth_total)
}

/// Runs the hidden-state recovery (idea-3 beam); returns per-letter coset marginals.
fn recover_marginals(ciphertext: &[TrigramValue], phrase_len: usize) -> Vec<BTreeSet<CosetEdge>> {
    run_marginalization_attack(
        ciphertext,
        phrase_len,
        DEFAULT_BEAM_WIDTH,
        SmallSupportPrior::Off,
    )
    .recovered_columns
}

fn frac(n: usize, d: usize) -> f64 {
    if d == 0 { 0.0 } else { n as f64 / d as f64 }
}

/// Per-transition decode coverage: each transition is covered by zero
/// (`undecidable`), one (`unique`), or several (`ambiguous`) marginals.
struct DecodeStats {
    unique: usize,
    ambiguous: usize,
    undecidable: usize,
    transitions: usize,
}

impl DecodeStats {
    fn unique_fraction(&self) -> f64 {
        frac(self.unique, self.transitions)
    }

    fn undecidable_fraction(&self) -> f64 {
        frac(self.undecidable, self.transitions)
    }
}

fn keystream_decode_stats(
    ciphertext: &[TrigramValue],
    marginals: &[BTreeSet<CosetEdge>],
) -> DecodeStats {
    let mut unique = 0usize;
    let mut ambiguous = 0usize;
    let mut undecidable = 0usize;
    let mut transitions = 0usize;
    for pair in ciphertext.windows(2) {
        if let [a, b] = pair {
            transitions += 1;
            let edge = CosetEdge {
                from: a.get(),
                to: b.get(),
            };
            let owners = marginals.iter().filter(|m| m.contains(&edge)).count();
            match owners {
                0 => undecidable += 1,
                1 => unique += 1,
                _ => ambiguous += 1,
            }
        }
    }
    DecodeStats {
        unique,
        ambiguous,
        undecidable,
        transitions,
    }
}

fn parse(text: &str, alphabet: &str) -> Vec<TrigramValue> {
    let index: BTreeMap<char, u8> = alphabet
        .chars()
        .enumerate()
        .map(|(i, c)| (c, u8::try_from(i).expect("alphabet under 256")))
        .collect();
    text.chars()
        .filter_map(|c| index.get(&c).copied())
        .map(|v| TrigramValue::new(v).expect("symbol in range"))
        .collect()
}

// Fixed test params: 5 letters => `two`'s exact out-degree-8 signature (4 gives 7).
const SYNTH_LETTERS: usize = 5;
const SYNTH_PHRASE_LEN: usize = 8;
const SYNTH_PHRASE_REPEATS: usize = 60;
const SYNTH_SEED: u64 = 0x6731_625f_6873_0001;
const TRIALS: usize = 8;

fn trial_seed(trial: usize) -> u64 {
    SYNTH_SEED
        ^ u64::try_from(trial)
            .expect("small trial")
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

fn synth(plaintext: Plaintext, seed: u64) -> HiddenStateFixture {
    generate_hidden_state_fixture(
        SYNTH_LETTERS,
        plaintext,
        SYNTH_PHRASE_LEN,
        SYNTH_PHRASE_REPEATS,
        seed,
    )
}

// --- C. Tests: positive control, the substrate lever, the `two` negative. ---

/// The synthetic generator reproduces `two`'s hidden-state signature: 12 symbols,
/// consecutive symbols never share a class (mod 3), out-degree exactly 8 on every
/// symbol (so `> num_letters` — many-valued, the non-trivial hidden subgroup), the
/// held truth is many-valued, and the held keystream is a genuine `num_letters`-way
/// partition. A generator that secretly made recovery trivial would fail this.
#[test]
fn synthetic_reproduces_two_hidden_state_signature() {
    let fixture = synth(Plaintext::RepeatedPhrase, SYNTH_SEED);

    // 12 symbols used, consecutive symbols never in the same class (mod 3).
    let used: BTreeSet<u8> = fixture.ciphertext.iter().map(|v| v.get()).collect();
    assert_eq!(used.len(), ALPHABET, "uses all 12 symbols");
    for pair in fixture.ciphertext.windows(2) {
        if let [a, b] = pair {
            assert_ne!(
                a.get() % 3,
                b.get() % 3,
                "consecutive symbols must change class (no same-class successor)"
            );
        }
    }

    // Many-valued readout: out-degree is exactly 8 on every realized symbol — the
    // same value `two` shows — and exceeds the letter count (the hidden-state
    // signature; a bijective GCTAK would have out-degree == num_letters).
    let degrees = out_degrees(&fixture.ciphertext);
    assert_eq!(degrees.len(), ALPHABET);
    assert!(
        degrees.iter().all(|&(_, d)| d == 8),
        "every symbol must have out-degree 8 (two's signature), got {degrees:?}"
    );
    assert!(
        max_out_degree(&fixture.ciphertext) > fixture.num_letters,
        "out-degree 8 must exceed num_letters {} (many-valued => hidden state)",
        fixture.num_letters,
    );

    // The held truth is itself many-valued: at least one letter sends one `from` to
    // several `to` (impossible for a bijective GCTAK readout — the |H|>1 signature).
    let multivalued_letters = fixture
        .truth_edges
        .iter()
        .filter(|edges| {
            let mut from_counts: BTreeMap<u8, usize> = BTreeMap::new();
            for e in *edges {
                *from_counts.entry(e.from).or_insert(0) += 1;
            }
            from_counts.values().any(|&c| c > 1)
        })
        .count();
    assert!(
        multivalued_letters > 0,
        "at least one letter must be many-valued (a from with several to)"
    );

    // The held keystream is a genuine num_letters-way partition (the ground-truth
    // structure a full decode would have to recover, and which `two` withholds).
    assert_eq!(fixture.keystream.len(), fixture.ciphertext.len());
    let distinct_letters: BTreeSet<usize> = fixture.keystream.iter().copied().collect();
    assert_eq!(
        distinct_letters.len(),
        SYNTH_LETTERS,
        "keystream uses all letters"
    );
}

/// THE binding positive control. On the repeated-phrase synthetic the recovery FIRES
/// (true per-letter coset edges, every trial) and a within-instance Fisher-Yates
/// shuffle null recovers it **0/N** — proving the recovery is the cipher structure.
#[test]
fn positive_control_hidden_state_recovery_fires_and_null_fails() {
    let mut real_fired = 0usize;
    let mut null_matched_real = 0usize;
    let mut real_total = 0usize;
    let mut null_total = 0usize;

    for trial in 0..TRIALS {
        let seed = trial_seed(trial);
        let fixture = synth(Plaintext::RepeatedPhrase, seed);

        // Real recovery.
        let recovered = recover_marginals(&fixture.ciphertext, SYNTH_PHRASE_LEN);
        let (real_true, truth_total) = score_marginal_edges(&fixture.truth_edges, &recovered);
        assert!(truth_total > 0, "fixture has truth edges");
        real_total += real_true;
        if real_true > 0 {
            real_fired += 1;
        }

        // Matched within-instance shuffle null: same pipeline, same truth.
        let mut shuffled = fixture.ciphertext.clone();
        let mut rng = SplitMix64::new(seed ^ 0x686e_756c_6c5f_3162);
        fisher_yates(&mut shuffled, &mut rng).expect("non-empty shuffle");
        let null_recovered = recover_marginals(&shuffled, SYNTH_PHRASE_LEN);
        let (null_true, _) = score_marginal_edges(&fixture.truth_edges, &null_recovered);
        null_total += null_true;
        // A "null recovery" would be the null reaching the real recovery; it must
        // not — the null only ever produces a few coincidental edges.
        if null_true >= real_true {
            null_matched_real += 1;
        }
        assert!(
            real_true > null_true,
            "trial {trial}: real {real_true} must beat null {null_true}"
        );
    }

    assert_eq!(
        real_fired, TRIALS,
        "recovery must FIRE on every trial ({real_fired}/{TRIALS}); real edges total {real_total}"
    );
    assert_eq!(
        null_matched_real, 0,
        "matched null must recover it 0/N (matched the real recovery {null_matched_real}/{TRIALS})"
    );
    // The null floor is a tiny fraction of the real recovery.
    assert!(
        real_total > null_total.saturating_mul(10),
        "real recovery {real_total} must dwarf the null floor {null_total}"
    );
}

/// The substrate is the lever, on ground truth. The SAME cipher recovers several
/// times more true coset edges from a repeated-phrase plaintext than from a realistic
/// (i.i.d.) one: the recoverable signal is the dominant repeated phrase (one isomorph
/// signature = one letter per column); without it (realistic text — and `two`) the
/// same signature lumps many letters and the beam recovers far less. Pins the `two`
/// obstruction where we hold the truth.
#[test]
fn repeated_phrase_substrate_drives_recovery_realistic_text_degrades_it() {
    let mut repeated_total = 0usize;
    let mut realistic_total = 0usize;

    for trial in 0..TRIALS {
        let seed = trial_seed(trial) ^ 0x5375_6273_7472_6174;
        let repeated = synth(Plaintext::RepeatedPhrase, seed);
        let realistic = synth(Plaintext::Realistic, seed);
        let (rep_true, _) = score_marginal_edges(
            &repeated.truth_edges,
            &recover_marginals(&repeated.ciphertext, SYNTH_PHRASE_LEN),
        );
        let (real_true, _) = score_marginal_edges(
            &realistic.truth_edges,
            &recover_marginals(&realistic.ciphertext, SYNTH_PHRASE_LEN),
        );
        repeated_total += rep_true;
        realistic_total += real_true;
    }

    assert!(repeated_total > 0, "repeated-phrase recovery must fire");
    assert!(
        repeated_total > realistic_total.saturating_mul(2),
        "repeated-phrase recovery ({repeated_total}) must be >2x the realistic-text recovery ({realistic_total})"
    );
}

/// `two` — the honest negative. The attack RUNS on `two` (no seeding death, unlike
/// `solve_gctak`): an isomorph pattern aligns and the beam emits a few column
/// marginals. But `two` is real text with no dominant repeated phrase, so those
/// marginals are tiny and cover only a sliver — 76–83% of the 697 transitions are
/// undecidable by any recovered marginal, so there is no whole-stream keystream to
/// feed the codec. No candidate text is logged. Same collapse as the substrate test,
/// now on the real sample.
#[test]
fn two_hidden_state_attack_honest_negative() {
    let vals = parse(
        include_str!("../../../research/data/practice-puzzles/two"),
        "ABCDEFGHIJKL",
    );
    assert_eq!(vals.len(), 698, "puzzle two is 698 symbols");

    // Re-pin the hidden-state signature (out-degree 8 on all 12 symbols).
    let degrees = out_degrees(&vals);
    assert_eq!(degrees.len(), ALPHABET, "two uses all 12 symbols");
    assert!(
        degrees.iter().all(|&(_, d)| d == 8),
        "two: every symbol has out-degree 8 (the hidden-state signature)"
    );

    for phrase_len in [4usize, 6, 8] {
        // The attack genuinely runs: an isomorph pattern aligns (real text repeats
        // equality patterns) — it does NOT die at seeding the way solve_gctak does.
        let occurrences =
            aligned_phrase_occurrences(&vals, phrase_len.max(2)).map_or(0, |starts| starts.len());
        assert!(
            occurrences >= 2,
            "phrase_len={phrase_len}: an isomorph pattern aligns ({occurrences} occurrences)"
        );

        // But the recovered marginals cover only a sliver of the stream: most
        // transitions are undecidable, so no whole-stream keystream exists.
        let recovered = recover_marginals(&vals, phrase_len);
        let stats = keystream_decode_stats(&vals, &recovered);
        assert_eq!(stats.transitions, 697);
        assert!(
            stats.undecidable_fraction() > 0.5,
            "phrase_len={phrase_len}: undecidable fraction {:.3} (unique {}, ambiguous {}, undecidable {}) — no whole-stream keystream to feed the codec",
            stats.undecidable_fraction(),
            stats.unique,
            stats.ambiguous,
            stats.undecidable
        );
        // The uniquely-decodable share is small (a few covered transitions, not a
        // decode).
        assert!(
            stats.unique_fraction() < 0.4,
            "phrase_len={phrase_len}: uniquely-decodable fraction {:.3} is not a decode",
            stats.unique_fraction()
        );
    }
}

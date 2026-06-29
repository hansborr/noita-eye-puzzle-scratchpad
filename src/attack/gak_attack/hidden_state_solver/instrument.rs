//! File-driven CLI instruments over the hidden-state (deck-stabilizer, convention
//! B) GAK: a structural hidden-vs-visible discriminator, an honest candidate
//! generator, and an in-process self-test (synthetic positive control + matched
//! null).
//!
//! These three functions ([`discriminate`], [`solve_candidate`], [`run_self_test`])
//! are exactly what the `gak` CLI subcommand calls, and the module's tests
//! exercise the same functions — so the instrument and its regression cannot
//! drift.
//!
//! ## Honesty discipline (binding — see `AGENTS.md`)
//!
//! - [`discriminate`] is **pure structural** (the Markov-excess statistic, no
//!   language model) and runs on any symbol stream; the hidden/visible verdict is
//!   a calibrated *heuristic*, reported alongside the matched same-length synthetic
//!   references so the call is transparent.
//! - [`solve_candidate`] emits a **candidate, never a decode**. The plaintext
//!   bigram fit is meaningful only relative to a **matched no-English control** (a
//!   random-plaintext convention-B synthetic decoded by the identical solver) and
//!   the genuine-English ceiling. The 6-fold deck slack lets a Viterbi decode
//!   manufacture English-looking text for a wrong key, so a high fit that does not
//!   clear the control floor is not a recovery. On real data the codec and
//!   composition convention are unknown, so the result is a candidate to verify
//!   externally, not a recovered plaintext.
//! - [`run_self_test`] is the precondition for trusting the instrument on real
//!   data: it must fire on a synthetic known answer (positive control) while the
//!   matched shuffle null does not (the [`super::GakAttackError::SameClassAdjacency`]
//!   precondition rejects it).

use std::collections::BTreeMap;

use crate::attack::quadgram::ENGLISH_CORPUS_LARGE;
use crate::nulls::null::{SplitMix64, fisher_yates, random_index_below};

use super::{
    BigramLm, DeckConvention, DeckTables, GakAttackError, decode_with_key, draw_key, encrypt,
    markov_excess, solve_hidden_state_gak,
};

/// Visible alphabet size of the C3×S4 hidden-state GAK (4 top cards × 3 classes).
/// The discriminator's synthetic calibration and the solver target this regime.
pub const VISIBLE_ALPHABET: usize = 12;
/// Plaintext symbol-alphabet size the bigram language model is trained over.
const PLAIN_ALPHABET: usize = 8;
/// Additive smoothing for the plaintext bigram language model.
const SMOOTHING: f64 = 0.3;

/// Default genetic-search population for the solver.
pub const DEFAULT_POPULATION: usize = 80;
/// Default genetic-search generations for the solver.
pub const DEFAULT_GENERATIONS: usize = 60;
/// Default deterministic seed for the genetic search and the self-test.
pub const DEFAULT_SEED: u64 = 0x00C0_FFEE_C0DE_0001;

/// Margin (in bits) by which the input Markov-excess must exceed the visible-state
/// reference to be called hidden-state. Matches the discriminator's validated
/// separation between the post-compose and pre-compose synthetics.
pub const HIDDEN_MARGIN: f64 = 0.15;
/// Margin (in nats/bigram) the candidate fit must clear above the matched
/// no-English control to be flagged English-like (still a candidate, not a decode).
pub const ENGLISH_MARGIN: f64 = 0.05;
/// Minimum blind recovery accuracy the self-test positive control must reach.
pub const SELF_TEST_MIN_RECOVERY: f64 = 0.90;
/// Minimum known-key decode accuracy (the machinery sanity floor).
pub const SELF_TEST_MIN_KNOWN_KEY: f64 = 0.99;
/// Maximum recovery accuracy any matched shuffle null may reach.
pub const SELF_TEST_MAX_NULL: f64 = 0.5;

// Internal fixture provenance (kept stable so the self-test and the discriminator
// references are reproducible). These mirror the validated test fixtures.
const REFERENCE_PLAINTEXT_START: usize = 8000;
const CALIBRATION_KEY_SEED: u64 = 0x6831_625f_7669_7401;
const CONTROL_PLAINTEXT_SEED: u64 = 0x4e6f_456e_6700_0001;
const CONTROL_KEY_SEED: u64 = 0x6374_726c_0000_0001;
const SELF_TEST_PLAINTEXT_START: usize = 8000;
const SELF_TEST_PLAINTEXT_LEN: usize = 1500;
const SELF_TEST_KEY_SEED: u64 = 0x6831_625f_7669_7401;
const SELF_TEST_NULL_SEED: u64 = 0x6e75_6c6c_5f32_0000;
const SELF_TEST_NULL_TRIALS: u64 = 3;

// =====================================================================
// Shared codec / scoring helpers (used by the instruments and the tests).
// =====================================================================

/// Frequency-rank reduction of `letters` to an 8-symbol stream (`rank mod 8`),
/// most-frequent letter first with ties broken by character order.
fn rank_reduce(letters: &[char]) -> Vec<usize> {
    let mut counts: BTreeMap<char, usize> = BTreeMap::new();
    for &c in letters {
        *counts.entry(c).or_insert(0usize) += 1;
    }
    let mut order: Vec<(char, usize)> = counts.into_iter().collect();
    order.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut to_eight: BTreeMap<char, usize> = BTreeMap::new();
    for (rank, (c, _count)) in order.iter().enumerate() {
        let _previous = to_eight.insert(*c, rank % PLAIN_ALPHABET);
    }
    letters
        .iter()
        .map(|c| to_eight.get(c).copied().unwrap_or(0))
        .collect()
}

/// Reduces arbitrary `text` to an 8-symbol plaintext stream by frequency rank over
/// its uppercased alphabetic characters.
///
/// This is the **assumed** expanding-codec analogue: an English-like 8-symbol
/// stream with realistic bigram correlations. It is a *modelled* codec, not a
/// recovered one — which is precisely why a solve on real data is a candidate, not
/// a decode.
pub(crate) fn reduce_alpha_to_eight(text: &str) -> Vec<usize> {
    let letters: Vec<char> = text
        .chars()
        .filter(char::is_ascii_alphabetic)
        .map(|c| c.to_ascii_uppercase())
        .collect();
    rank_reduce(&letters)
}

/// The bundled English corpus reduced to 8 symbols over the `[start, start + len)`
/// window of its uppercased alphabetic characters — the synthetic plaintext source
/// and the discriminator's calibration plaintext.
pub(crate) fn english_eight_symbol(start: usize, len: usize) -> Vec<usize> {
    let letters: Vec<char> = ENGLISH_CORPUS_LARGE
        .chars()
        .filter(char::is_ascii_alphabetic)
        .map(|c| c.to_ascii_uppercase())
        .skip(start)
        .take(len)
        .collect();
    rank_reduce(&letters)
}

/// An i.i.d. uniform 8-symbol stream (the no-English baseline plaintext).
///
/// # Errors
/// Returns [`GakAttackError`] if the in-crate sampler rejects the draw bound.
pub(crate) fn uniform_eight_symbol(len: usize, seed: u64) -> Result<Vec<usize>, GakAttackError> {
    let mut rng = SplitMix64::new(seed);
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(random_index_below(PLAIN_ALPHABET, &mut rng)?);
    }
    Ok(out)
}

/// Best plaintext-recovery accuracy under symbol relabeling: align decoded symbols
/// (positions `1..n`) to the held truth, relabel each decoded class to its majority
/// truth symbol, and score the fraction correct.
#[must_use]
pub(crate) fn relabel_accuracy(decoded: &[usize], truth_full: &[usize]) -> f64 {
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

/// Encrypts an 8-symbol `plaintext` into its 12-symbol convention-B ciphertext
/// under a key drawn deterministically from `key_seed` (the caller already holds
/// the plaintext as ground truth, so only the ciphertext is returned).
///
/// # Errors
/// Returns [`GakAttackError`] if the deck tables cannot be built or the encrypt
/// rejects a symbol.
pub(crate) fn build_ciphertext(
    plaintext: &[usize],
    key_seed: u64,
    convention: DeckConvention,
) -> Result<Vec<u8>, GakAttackError> {
    let tables = DeckTables::build()?;
    let key = draw_key(&tables, key_seed)?;
    encrypt(plaintext, &key, &tables, convention)
}

/// Validates that every symbol of `stream` is below the 12-symbol convention-B
/// visible alphabet (the solver and the calibration references are defined only on
/// that regime).
fn require_visible_alphabet(stream: &[u8]) -> Result<(), GakAttackError> {
    for &symbol in stream {
        if usize::from(symbol) >= VISIBLE_ALPHABET {
            return Err(GakAttackError::SymbolOutOfRange {
                value: usize::from(symbol),
            });
        }
    }
    Ok(())
}

// =====================================================================
// Instrument 1 — hidden-vs-visible discriminator.
// =====================================================================

/// Hidden-vs-visible verdict from the Markov-excess discriminator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HiddenVisibleVerdict {
    /// The excess lands on the hidden-state (post-compose) side: it clears the
    /// visible-state reference by [`HIDDEN_MARGIN`].
    HiddenState,
    /// The excess lands on the visible-state (pre-compose, low-memory) side: it is
    /// within half of [`HIDDEN_MARGIN`] of the visible-state reference.
    VisibleState,
    /// The excess sits in the gray band just above the visible-state reference
    /// (more than half [`HIDDEN_MARGIN`] above it, but less than a full margin) —
    /// no confident call. The verdict is taken relative to the visible-state
    /// reference; the hidden-state reference is reported for context only.
    Ambiguous,
    /// No calibration was available (alphabet size is not 12, where convention-B
    /// synthetics are undefined); only the raw excess is reported.
    Uncalibrated,
}

/// Result of the hidden-vs-visible structural discriminator.
#[derive(Clone, Debug, PartialEq)]
pub struct DiscriminateReport {
    /// Input stream length (symbols).
    pub length: usize,
    /// Declared alphabet size.
    pub alphabet_size: usize,
    /// The input's Markov-excess drop `H(s_t|s_{t-1}) - H(s_t|s_{t-2},s_{t-1})`.
    pub excess: f64,
    /// Matched same-length hidden-state synthetic reference drop (`None` when the
    /// alphabet is not 12, where convention-B synthetics are undefined).
    pub hidden_reference: Option<f64>,
    /// Matched same-length visible-state synthetic reference drop (`None` as above).
    pub visible_reference: Option<f64>,
    /// The verdict.
    pub verdict: HiddenVisibleVerdict,
}

/// Runs the hidden-vs-visible Markov-excess discriminator on `symbols`.
///
/// The statistic is purely structural (no language model). When the alphabet is
/// the 12-symbol convention-B visible alphabet, the input excess is calibrated
/// against a same-length hidden-state and visible-state synthetic so the verdict is
/// transparent; otherwise only the raw excess is reported
/// ([`HiddenVisibleVerdict::Uncalibrated`]). The verdict is a heuristic, not a
/// proof.
///
/// # Errors
/// Returns [`GakAttackError`] if `symbols` is shorter than 3, a symbol is not below
/// `alphabet_size`, or a calibration synthetic cannot be built.
pub fn discriminate(
    symbols: &[u8],
    alphabet_size: usize,
) -> Result<DiscriminateReport, GakAttackError> {
    let excess = markov_excess(symbols, alphabet_size)?;
    if alphabet_size != VISIBLE_ALPHABET {
        return Ok(DiscriminateReport {
            length: symbols.len(),
            alphabet_size,
            excess,
            hidden_reference: None,
            visible_reference: None,
            verdict: HiddenVisibleVerdict::Uncalibrated,
        });
    }
    // Calibrate against same-length convention-B synthetics built from the same
    // English plaintext under both conventions, so finite-sample entropy bias is
    // matched on both sides.
    let plaintext = english_eight_symbol(REFERENCE_PLAINTEXT_START, symbols.len());
    let hidden_ct = build_ciphertext(
        &plaintext,
        CALIBRATION_KEY_SEED,
        DeckConvention::HiddenState,
    )?;
    let visible_ct = build_ciphertext(
        &plaintext,
        CALIBRATION_KEY_SEED,
        DeckConvention::VisibleState,
    )?;
    let hidden_ref = markov_excess(&hidden_ct, VISIBLE_ALPHABET)?;
    let visible_ref = markov_excess(&visible_ct, VISIBLE_ALPHABET)?;
    let verdict = if excess >= visible_ref + HIDDEN_MARGIN {
        HiddenVisibleVerdict::HiddenState
    } else if excess <= visible_ref + HIDDEN_MARGIN / 2.0 {
        HiddenVisibleVerdict::VisibleState
    } else {
        HiddenVisibleVerdict::Ambiguous
    };
    Ok(DiscriminateReport {
        length: symbols.len(),
        alphabet_size,
        excess,
        hidden_reference: Some(hidden_ref),
        visible_reference: Some(visible_ref),
        verdict,
    })
}

// =====================================================================
// Instrument 2 — honest candidate generator.
// =====================================================================

/// An honest **candidate** from the hidden-state solver on a (possibly real)
/// ciphertext — never a decode.
///
/// The candidate's plaintext bigram fit is meaningful only relative to
/// [`Self::control_fit`] (the matched no-English floor) and [`Self::english_ceiling`]
/// (the genuine-English ceiling). [`Self::beats_control`] is the only honest signal
/// that the candidate carries more English structure than the solver's overfitting
/// can manufacture on noise — and even then it is a hypothesis to verify, not a
/// recovery.
#[derive(Clone, Debug, PartialEq)]
pub struct SolveCandidate {
    /// Recovered candidate plaintext symbols (positions `1..n`).
    pub plaintext: Vec<usize>,
    /// Mean per-bigram log-probability of the candidate under the language model.
    pub candidate_fit: f64,
    /// Mean per-bigram log-probability of a **matched no-English control** (a
    /// random-plaintext convention-B synthetic decoded by the identical solver):
    /// the noise floor overfitting reaches when no English exists but the cipher
    /// structure is exactly right.
    pub control_fit: f64,
    /// The language model's fit on its own training stream — the genuine-English
    /// ceiling the candidate would have to approach to be English.
    pub english_ceiling: f64,
    /// Whether the candidate fit clears the no-English control by [`ENGLISH_MARGIN`]
    /// (the only honest "more English than noise" flag; still a candidate to verify).
    pub beats_control: bool,
}

/// Runs the hidden-state solver on `ciphertext` against a bigram language model
/// trained from `lm_text` (reduced to 8 symbols by the assumed codec), and returns
/// an honest candidate gated by a matched no-English control.
///
/// `ciphertext` must be over the 12-symbol convention-B visible alphabet. The
/// search is bounded by `population`/`generations`/`seed`; a bounded search states
/// its limits — it does not exhaust the key space.
///
/// # Errors
/// Returns [`GakAttackError`] if a symbol is outside the 12-symbol alphabet, the
/// language model cannot be built, the no-English control cannot be drawn, or the
/// solver rejects the stream (e.g. [`super::GakAttackError::SameClassAdjacency`]).
pub fn solve_candidate(
    ciphertext: &[u8],
    lm_text: &str,
    population: usize,
    generations: usize,
    seed: u64,
) -> Result<SolveCandidate, GakAttackError> {
    require_visible_alphabet(ciphertext)?;
    let plaintext_model = reduce_alpha_to_eight(lm_text);
    let lm = BigramLm::from_symbols(&plaintext_model, PLAIN_ALPHABET, SMOOTHING)?;
    let english_ceiling = lm.mean_bigram_log_prob(&plaintext_model)?;

    // Matched no-English control: a random-plaintext convention-B synthetic of the
    // same length, decoded by the identical solver. Its fit is the floor the
    // solver's 6-fold deck slack can manufacture with no English present.
    let control_plaintext = uniform_eight_symbol(ciphertext.len(), CONTROL_PLAINTEXT_SEED)?;
    let control_ct = build_ciphertext(
        &control_plaintext,
        CONTROL_KEY_SEED,
        DeckConvention::HiddenState,
    )?;
    let control_recovery = solve_hidden_state_gak(&control_ct, &lm, population, generations, seed)?;
    let control_fit = lm.mean_bigram_log_prob(&control_recovery.plaintext)?;

    let recovery = solve_hidden_state_gak(ciphertext, &lm, population, generations, seed)?;
    let candidate_fit = lm.mean_bigram_log_prob(&recovery.plaintext)?;
    let beats_control = candidate_fit > control_fit + ENGLISH_MARGIN;

    Ok(SolveCandidate {
        plaintext: recovery.plaintext,
        candidate_fit,
        control_fit,
        english_ceiling,
        beats_control,
    })
}

// =====================================================================
// Instrument 3 — in-process self-test (positive control + matched null).
// =====================================================================

/// In-process self-test result: the synthetic positive control and the matched
/// shuffle null. [`Self::passed`] is the precondition for trusting the instrument
/// on real data — it fires on a known answer and the null does not.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SelfTestReport {
    /// Known-key decode recovery accuracy (the machinery sanity; should be ~1.0).
    pub known_key_accuracy: f64,
    /// Blind solver recovery accuracy on the synthetic (the positive control).
    pub blind_accuracy: f64,
    /// Whether the positive control passed (known-key and blind accuracies clear
    /// [`SELF_TEST_MIN_KNOWN_KEY`] / [`SELF_TEST_MIN_RECOVERY`]).
    pub positive_control_passed: bool,
    /// Number of matched shuffle-null trials rejected by the no-same-class
    /// precondition (the expected outcome — the shuffle breaks class-alternation).
    pub null_rejected: usize,
    /// Highest recovery accuracy any shuffle null that slipped past the precondition
    /// reached (must stay below [`SELF_TEST_MAX_NULL`]).
    pub null_max_accuracy: f64,
    /// Whether the matched null failed to recover (every trial rejected or below
    /// [`SELF_TEST_MAX_NULL`]).
    pub null_failed: bool,
    /// Number of shuffle-null trials run.
    pub null_trials: usize,
    /// Whether the overall self-test passed (positive control fired and null failed).
    pub passed: bool,
}

/// Runs the in-process self-test: a synthetic convention-B known answer (positive
/// control) plus a matched Fisher-Yates shuffle null, both through the same library
/// functions the CLI uses.
///
/// The blind solver must recover the synthetic plaintext, while the shuffle null is
/// rejected by the no-same-class precondition (or, for a freak valid shuffle, fails
/// to recover). A `passed: false` report is a methodology failure surfaced to the
/// user, never a data finding.
///
/// # Errors
/// Returns [`GakAttackError`] if the deck tables cannot be built, a draw/encrypt
/// fails, or the shuffle null returns an error other than
/// [`super::GakAttackError::SameClassAdjacency`].
pub fn run_self_test(seed: u64) -> Result<SelfTestReport, GakAttackError> {
    let plaintext = english_eight_symbol(SELF_TEST_PLAINTEXT_START, SELF_TEST_PLAINTEXT_LEN);
    let ciphertext = build_ciphertext(&plaintext, SELF_TEST_KEY_SEED, DeckConvention::HiddenState)?;
    let lm = BigramLm::from_symbols(&plaintext, PLAIN_ALPHABET, SMOOTHING)?;

    // Known-key sanity: decoding under the actual generator key recovers the
    // plaintext almost exactly, so any blind shortfall is a search miss, never a
    // decode bug.
    let tables = DeckTables::build()?;
    let true_key = draw_key(&tables, SELF_TEST_KEY_SEED)?;
    let (_score, known_decode) = decode_with_key(&ciphertext, &lm, &true_key)?;
    let known_key_accuracy = relabel_accuracy(&known_decode, &plaintext);

    // Blind solve from ciphertext alone.
    let recovery = solve_hidden_state_gak(
        &ciphertext,
        &lm,
        DEFAULT_POPULATION,
        DEFAULT_GENERATIONS,
        seed,
    )?;
    let blind_accuracy = relabel_accuracy(&recovery.plaintext, &plaintext);
    let positive_control_passed =
        known_key_accuracy >= SELF_TEST_MIN_KNOWN_KEY && blind_accuracy >= SELF_TEST_MIN_RECOVERY;

    // Matched shuffle null: the shuffle destroys class-alternation, so the
    // no-same-class precondition should reject it outright.
    let mut null_rejected = 0usize;
    let mut null_max_accuracy = 0.0f64;
    for trial in 0..SELF_TEST_NULL_TRIALS {
        let mut shuffled = ciphertext.clone();
        let mut rng =
            SplitMix64::new(SELF_TEST_NULL_SEED ^ trial.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        fisher_yates(&mut shuffled, &mut rng)?;
        match solve_hidden_state_gak(
            &shuffled,
            &lm,
            DEFAULT_POPULATION,
            DEFAULT_GENERATIONS,
            seed,
        ) {
            Err(GakAttackError::SameClassAdjacency { .. }) => null_rejected += 1,
            Ok(null_recovery) => {
                let accuracy = relabel_accuracy(&null_recovery.plaintext, &plaintext);
                if accuracy > null_max_accuracy {
                    null_max_accuracy = accuracy;
                }
            }
            Err(other) => return Err(other),
        }
    }
    let null_failed = null_max_accuracy < SELF_TEST_MAX_NULL;
    let passed = positive_control_passed && null_failed;

    Ok(SelfTestReport {
        known_key_accuracy,
        blind_accuracy,
        positive_control_passed,
        null_rejected,
        null_max_accuracy,
        null_failed,
        null_trials: usize::try_from(SELF_TEST_NULL_TRIALS).unwrap_or(0),
        passed,
    })
}

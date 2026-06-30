//! In-process self-test: a planted ciphertext-autokey feedback-deck positive
//! control and a no-feedback (deck-channel noise) negative control, both scanned
//! through the same [`super::ctak_scan`] the CLI calls.
//!
//! The positive control plants a repeated plaintext word so the rotor channel
//! carries a genuine isomorph anchor, encrypts the deck channel under a known
//! advance map (so the *literal* deck channel does **not** repeat — the deck state
//! differs at the two occurrences, exactly as real `two`), and asserts the search
//! recovers a crib-consistent advance map that reproduces the full repeat. The
//! negative control keeps the same anchor-bearing rotor channel but replaces the
//! deck channel with order-1 Markov noise, and asserts `NoFeedbackSignal`.
//!
//! The control uses a **3-card** deck (`S3`, `6^3 = 216` advance maps) rather than
//! the `two`-scale 4-card deck (`24^4 = 331_776`): the search/null/crib machinery
//! is deck-size-generic, so the small instance validates the full pipeline cheaply
//! while reaching `p < 0.05` with a real null. The `deck_size = 4` search itself is
//! covered by the fast `search_recovers_planted_single_anchor` unit test.

use super::model::{Convention, Perms, Readout, Side, encrypt_deck_channel, random_advance_map};
use super::{CtakError, CtakSelfTest, CtakVerdict, ctak_scan};
use crate::nulls::null::{SplitMix64, mix_seed, random_index_below};

/// Self-test configuration (small 3-card deck so the exhaustive search is cheap).
const ROTOR_MOD: usize = 3;
const DECK_SIZE: usize = 3;
const ALPHABET: usize = ROTOR_MOD * DECK_SIZE; // 9
const BASE_LEN: usize = 110;
const WORD_LEN: usize = 34;
const MIN_ANCHOR_LEN: usize = 8;
const TOP_K: usize = 6;
/// Enough trials that a perfect positive reaches `p = 1/(TRIALS+1) < 0.05`.
const NULL_TRIALS: usize = 30;

/// The convention the positive control is encrypted under (the canonical
/// `D0`-cancelling one, so the `D0 = identity` search is exact).
const PLANT_CONVENTION: Convention = Convention {
    side: Side::Right,
    readout: Readout::Forward,
};

/// Builds and scans the planted controls, returning the PASS/FAIL record.
pub(super) fn self_test(seed: u64) -> Result<CtakSelfTest, CtakError> {
    let perms = Perms::build(DECK_SIZE);

    // --- Positive control: a real feedback deck with a planted repeated word. ---
    let (plain, src, dst) = planted_plaintext(mix_seed(seed, 0x90));
    let t_channel: Vec<usize> = plain.iter().map(|&o| o % DECK_SIZE).collect();
    let mut rng = SplitMix64::new(mix_seed(seed, 0x91));
    let g = random_advance_map(&perms, &mut rng)?;
    let q = encrypt_deck_channel(&perms, &t_channel, &g, PLANT_CONVENTION);
    let class = rotor_walk(&plain);
    let positive_values = weave(&q, &class);

    let positive_report = ctak_scan(
        &positive_values,
        ALPHABET,
        ROTOR_MOD,
        MIN_ANCHOR_LEN,
        TOP_K,
        NULL_TRIALS,
        mix_seed(seed, 0xA1),
    )?;
    let (positive_recovered, positive_full_repeat) = match &positive_report.verdict {
        CtakVerdict::FeedbackDeckSignal { min_run, .. } => (true, *min_run >= WORD_LEN),
        CtakVerdict::NoFeedbackSignal => (false, false),
    };

    // --- Negative control: same rotor anchors, deck channel is Markov noise. ---
    let noise = markov_noise(q.len(), DECK_SIZE, mix_seed(seed, 0xB2));
    let negative_values = weave(&noise, &class);
    let negative_report = ctak_scan(
        &negative_values,
        ALPHABET,
        ROTOR_MOD,
        MIN_ANCHOR_LEN,
        TOP_K,
        NULL_TRIALS,
        mix_seed(seed, 0xB1),
    )?;
    let negative_rejected = matches!(negative_report.verdict, CtakVerdict::NoFeedbackSignal);

    // The anchor must actually exist for the controls to be meaningful.
    let anchors_present =
        !positive_report.anchors.is_empty() && !negative_report.anchors.is_empty();

    let passed = positive_recovered && positive_full_repeat && negative_rejected && anchors_present;
    let _ = (src, dst);
    Ok(CtakSelfTest {
        positive_recovered,
        positive_full_repeat,
        negative_rejected,
        passed,
    })
}

/// A random plaintext over `0..2*DECK_SIZE` of length `BASE_LEN` with a `WORD_LEN`
/// block copied from `src` to `dst`, planting a repeat in both the rotor channel
/// (`o / DECK_SIZE`) and the deck channel (`o % DECK_SIZE`). Returns
/// `(plain, src, dst)`.
fn planted_plaintext(seed: u64) -> (Vec<usize>, usize, usize) {
    let mut rng = SplitMix64::new(seed);
    let modulus = (2 * DECK_SIZE) as u64;
    let mut plain: Vec<usize> = (0..BASE_LEN)
        .map(|_| (rng.next_u64() % modulus) as usize)
        .collect();
    let src = 10usize;
    let dst = BASE_LEN - WORD_LEN - 5;
    let word: Vec<usize> = (0..WORD_LEN)
        .filter_map(|s| plain.get(src + s).copied())
        .collect();
    for (s, &v) in word.iter().enumerate() {
        if let Some(slot) = plain.get_mut(dst + s) {
            *slot = v;
        }
    }
    (plain, src, dst)
}

/// The rotor class walk: `class[i] = (class[i-1] + eps_i) mod rotor_mod`,
/// `eps_i = o_i/DECK_SIZE + 1 ∈ {1,2}`, so `class` always changes (the `two`
/// no-same-class law) and its difference channel reproduces the planted repeat.
fn rotor_walk(plain: &[usize]) -> Vec<usize> {
    let mut class = Vec::with_capacity(plain.len());
    let mut current = 0usize;
    for &o in plain {
        let eps = o / DECK_SIZE + 1; // 1 or 2
        current = (current + eps) % ROTOR_MOD;
        class.push(current);
    }
    class
}

/// Weaves deck channel `q` and rotor channel `class` into visible symbols
/// `value = q * rotor_mod + class`.
fn weave(q: &[usize], class: &[usize]) -> Vec<u16> {
    q.iter()
        .zip(class.iter())
        .map(|(&qi, &ci)| (qi * ROTOR_MOD + ci) as u16)
        .collect()
}

/// Uniform noise over `0..deck_size` (the negative control's deck channel: an
/// anchor-bearing rotor channel woven onto a structureless deck channel).
fn markov_noise(len: usize, deck_size: usize, seed: u64) -> Vec<usize> {
    let mut rng = SplitMix64::new(seed);
    (0..len)
        .map(|_| random_index_below(deck_size, &mut rng).unwrap_or(0))
        .collect()
}

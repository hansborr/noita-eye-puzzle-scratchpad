//! Planted positive controls and the matched-null agreement that validate the
//! key-difference discriminator end to end.
//!
//! Four controls span the family boundary, each reusing an existing generator:
//!
//! - **ciphertext-autokey** ([`crate::attack::keystream`]) with a planted
//!   plaintext repeat — a constant `Δ`, so it must classify order 1;
//! - **Vigenère** with the repeat planted at a period-multiple gap — `Δ ≡ 0`, so
//!   it must classify order 0;
//! - an **additive-progressive** synthetic (`k[i] = k0 + r·i`) with the same
//!   phrase planted at distinct gaps — a constant `Δ` whose offset is `r·g`, so it
//!   must classify order 1 *and* the regression must read it as progressive;
//! - a **non-additive deck relabel** — the same phrase planted twice with the
//!   second occurrence passed through a fixed non-additive permutation (a seeded
//!   [`fisher_yates`] shuffle of the alphabet, reusing the existing generator).
//!   The two occurrences share an equality pattern (a gap-pattern certificate)
//!   while the relabelling is a genuine permutation that is neither additive nor
//!   the identity, so no additive order fires and it must classify `Irregular`.
//!
//! (The spec's suggested deck control — a dihedral GCTAK fixture from
//! [`crate::attack::gak_attack`] — does not reproduce: its bijective trivial-`H`
//! readout makes the small-group ciphertext periodic, so repeated phrases collide
//! on entry states and produce identity relabellings that read as a raw repeat,
//! `IdenticalKey`, not `Irregular`; a group large enough to avoid the collisions
//! makes the difference-channel windows all-distinct, destroying the gap-pattern
//! certificate. The fixed-permutation relabel is the robust positive control for
//! the same non-additive class.)
//!
//! The matched null is [`super::iso_scan`]'s order-1 Markov resample, applied per
//! difference channel: the constant-`Δ` controls must clear it (their firing is
//! significant) while the deck control must not manufacture any additive firing.

use crate::attack::keystream::{KeystreamFamily, encrypt};
use crate::nulls::null::{SplitMix64, fisher_yates, mix_seed, random_index_below};

use super::{
    AutokeyFamily, KeyDiffError, KeyDiffReport, KeyDiffSelfTest, KeyDiffVerdict, OrderFiring,
    key_difference_scan,
};

/// Alphabet of the keystream controls (small, so the null ceiling is low).
const CONTROL_ALPHABET: usize = 10;
/// Base length of the keystream control plaintexts.
const CONTROL_LEN: usize = 320;
/// Length of the planted repeated block.
const PLANT_LEN: usize = 48;
/// Minimum firing length used when scanning controls.
const SELF_TEST_MIN_ANCHOR: usize = 8;
/// Maximum anchors enumerated per channel during the self-test.
const SELF_TEST_TOP_K: usize = 16;
/// Matched-null trial count used during the self-test (smaller, for speed).
const SELF_TEST_NULL_TRIALS: usize = 64;
/// Highest finite-difference order scanned during the self-test.
const SELF_TEST_MAX_ORDER: usize = 3;
/// Vigenère key period for the identical-key control.
const VIGENERE_PERIOD: usize = 5;

/// A random symbol stream of `len` letters over `alphabet`.
fn random_plaintext(
    len: usize,
    alphabet: usize,
    rng: &mut SplitMix64,
) -> Result<Vec<u8>, KeyDiffError> {
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(u8::try_from(random_index_below(alphabet, rng)?).unwrap_or(0));
    }
    Ok(out)
}

/// Copies the block at `src..src+len` over `dst..dst+len`, planting an exact
/// repeat (no-op if either window is out of range).
fn plant_repeat(stream: &mut [u8], src: usize, dst: usize, len: usize) {
    let block: Vec<u8> = stream
        .get(src..src + len)
        .map(<[u8]>::to_vec)
        .unwrap_or_default();
    if let Some(slot) = stream.get_mut(dst..dst + len)
        && slot.len() == block.len()
    {
        slot.copy_from_slice(&block);
    }
}

/// Scans a control byte stream with the self-test parameters.
fn scan_control(bytes: &[u8], alphabet: usize, seed: u64) -> Result<KeyDiffReport, KeyDiffError> {
    let values: Vec<u16> = bytes.iter().map(|&b| u16::from(b)).collect();
    key_difference_scan(
        &values,
        alphabet,
        SELF_TEST_MAX_ORDER,
        SELF_TEST_MIN_ANCHOR,
        SELF_TEST_TOP_K,
        SELF_TEST_NULL_TRIALS,
        seed,
    )
}

/// Ciphertext-autokey control: a planted plaintext repeat gives a constant `Δ`
/// (the 1st-difference channel of a length-1-primer ciphertext-autokey stream is
/// the plaintext itself), so it must classify order 1.
fn ctak_constant_control(seed: u64) -> Result<KeyDiffReport, KeyDiffError> {
    let mut rng = SplitMix64::new(mix_seed(seed, 1));
    let mut plaintext = random_plaintext(CONTROL_LEN, CONTROL_ALPHABET, &mut rng)?;
    plant_repeat(&mut plaintext, 24, CONTROL_LEN - PLANT_LEN - 24, PLANT_LEN);
    let primer = [u8::try_from(random_index_below(CONTROL_ALPHABET, &mut rng)?).unwrap_or(1)];
    let ciphertext = encrypt(
        KeystreamFamily::CiphertextAutokey,
        &plaintext,
        &primer,
        CONTROL_ALPHABET,
    );
    scan_control(&ciphertext, CONTROL_ALPHABET, mix_seed(seed, 2))
}

/// Vigenère control: the repeat is planted at a period-multiple gap, so the key
/// aligns and `Δ ≡ 0` — a raw exact repeat that must classify order 0.
fn vigenere_identical_control(seed: u64) -> Result<KeyDiffReport, KeyDiffError> {
    let mut rng = SplitMix64::new(mix_seed(seed, 3));
    let mut plaintext = random_plaintext(CONTROL_LEN, CONTROL_ALPHABET, &mut rng)?;
    let src = 20usize;
    let gap = VIGENERE_PERIOD * 12; // a multiple of the key period
    plant_repeat(&mut plaintext, src, src + gap, PLANT_LEN);
    let mut key = Vec::with_capacity(VIGENERE_PERIOD);
    for _ in 0..VIGENERE_PERIOD {
        key.push(u8::try_from(random_index_below(CONTROL_ALPHABET, &mut rng)?).unwrap_or(0));
    }
    let ciphertext = encrypt(
        KeystreamFamily::Vigenere,
        &plaintext,
        &key,
        CONTROL_ALPHABET,
    );
    scan_control(&ciphertext, CONTROL_ALPHABET, mix_seed(seed, 4))
}

/// Additive-progressive control: `c[i] = (p[i] + k0 + r·i) mod m` with one phrase
/// planted at three positions whose pairwise gaps are distinct and never a
/// multiple of `m` (so no pair degenerates to `Δ ≡ 0`). The constant offset is
/// `δ = r·g`, so it must classify order 1 with a progressive-alphabet family.
fn progressive_control(seed: u64) -> Result<KeyDiffReport, KeyDiffError> {
    const M: usize = 12;
    const SLOPE: usize = 5; // coprime to 12, so the recovered slope is unique
    const K0: usize = 3;
    const PHRASE_LEN: usize = 28;
    const LEN: usize = 360;
    // Gaps 111, 130, 241 — pairwise distinct, none ≡ 0 (mod 12).
    const POSITIONS: [usize; 3] = [10, 121, 251];

    let mut rng = SplitMix64::new(mix_seed(seed, 5));
    let mut plaintext = random_plaintext(LEN, M, &mut rng)?;
    let phrase = random_plaintext(PHRASE_LEN, M, &mut rng)?;
    for &pos in &POSITIONS {
        if let Some(slot) = plaintext.get_mut(pos..pos + PHRASE_LEN) {
            slot.copy_from_slice(&phrase);
        }
    }
    let ciphertext: Vec<u16> = plaintext
        .iter()
        .enumerate()
        .map(|(i, &p)| u16::try_from((usize::from(p) + K0 + SLOPE * i) % M).unwrap_or(0))
        .collect();
    key_difference_scan(
        &ciphertext,
        M,
        SELF_TEST_MAX_ORDER,
        SELF_TEST_MIN_ANCHOR,
        SELF_TEST_TOP_K,
        SELF_TEST_NULL_TRIALS,
        mix_seed(seed, 6),
    )
}

/// Copies `block` over `stream[pos..pos+block.len()]` (no-op if out of range).
fn plant_block(stream: &mut [u8], pos: usize, block: &[u8]) {
    if let Some(slot) = stream.get_mut(pos..pos + block.len()) {
        slot.copy_from_slice(block);
    }
}

/// Whether `perm` is a *non-additive* permutation — neither the identity nor a
/// pure translation `x -> (x + c) mod m`. A translation would leave the
/// difference channel an exact repeat (a constant `Δ`), which is exactly what the
/// deck control must avoid.
fn is_non_additive(perm: &[u8]) -> bool {
    let m = perm.len();
    let Some(&c0) = perm.first() else {
        return false;
    };
    let translation =
        (0..m).all(|x| perm.get(x).copied().map(usize::from) == Some((x + usize::from(c0)) % m));
    !translation
}

/// A fixed non-additive permutation of `0..m`, drawn by a seeded Fisher-Yates
/// shuffle and re-rolled until it is neither the identity nor a pure translation.
fn non_additive_permutation(m: usize, rng: &mut SplitMix64) -> Result<Vec<u8>, KeyDiffError> {
    for _ in 0..64 {
        let mut perm: Vec<u8> = (0..m).map(|v| u8::try_from(v).unwrap_or(0)).collect();
        fisher_yates(&mut perm, rng)?;
        if is_non_additive(&perm) {
            return Ok(perm);
        }
    }
    Err(KeyDiffError::SelfTestFailed)
}

/// Non-additive deck-relabel control: the same phrase planted twice with the
/// second occurrence passed through a fixed non-additive permutation. The two
/// occurrences share an equality pattern (gap-pattern certificate present) while
/// the relabelling is neither additive nor the identity, so no additive order
/// fires and it must classify `Irregular`.
fn deck_relabel_irregular_control(seed: u64) -> Result<KeyDiffReport, KeyDiffError> {
    const M: usize = 12;
    const LEN: usize = 360;
    const PHRASE_LEN: usize = 40;

    let mut rng = SplitMix64::new(mix_seed(seed, 8));
    let mut stream = random_plaintext(LEN, M, &mut rng)?;
    let phrase = random_plaintext(PHRASE_LEN, M, &mut rng)?;
    let perm = non_additive_permutation(M, &mut rng)?;
    let relabelled: Vec<u8> = phrase
        .iter()
        .map(|&p| perm.get(usize::from(p)).copied().unwrap_or(p))
        .collect();
    plant_block(&mut stream, 20, &phrase);
    plant_block(&mut stream, 200, &relabelled);
    scan_control(&stream, M, mix_seed(seed, 9))
}

/// Whether the firing at `order` was significant against the matched null.
fn order_is_significant(firings: &[OrderFiring], order: usize) -> bool {
    firings
        .iter()
        .find(|firing| firing.order == order)
        .is_some_and(|firing| firing.significant)
}

/// Runs the full self-test: the four planted controls and the matched-null
/// agreement.
pub(super) fn self_test(seed: u64) -> Result<KeyDiffSelfTest, KeyDiffError> {
    let ctak = ctak_constant_control(mix_seed(seed, 10))?;
    let ctak_constant = matches!(ctak.verdict, KeyDiffVerdict::ConstantAdditive { .. })
        && ctak.fired_order == Some(1);

    let vigenere = vigenere_identical_control(mix_seed(seed, 20))?;
    let vigenere_identical =
        matches!(vigenere.verdict, KeyDiffVerdict::IdenticalKey) && vigenere.fired_order == Some(0);

    let progressive = progressive_control(mix_seed(seed, 30))?;
    let progressive_family = matches!(
        progressive.verdict,
        KeyDiffVerdict::ConstantAdditive {
            family: AutokeyFamily::ProgressiveAlphabet { .. }
        }
    );

    let deck = deck_relabel_irregular_control(mix_seed(seed, 40))?;
    let deck_irregular =
        matches!(deck.verdict, KeyDiffVerdict::Irregular) && deck.fired_order.is_none();

    let constant_controls_significant =
        order_is_significant(&ctak.firings, 1) && order_is_significant(&progressive.firings, 1);
    let deck_no_additive = deck.firings.iter().all(|firing| !firing.fired);
    let null_agreement = constant_controls_significant && deck_no_additive;

    let passed = ctak_constant
        && vigenere_identical
        && progressive_family
        && deck_irregular
        && null_agreement;

    Ok(KeyDiffSelfTest {
        ctak_constant,
        vigenere_identical,
        progressive_family,
        deck_irregular,
        null_agreement,
        passed,
    })
}

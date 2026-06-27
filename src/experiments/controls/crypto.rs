//! Compute core for the Experiment 11 positive controls.
//!
//! Fixture builders, the deterministic substitution key, the polyalphabetic
//! encrypt routines, and the isomorph-detector adapter, split out of the
//! controls battery body.

use super::{
    ALPHABET_SIZE, ControlsError, FixtureReport, ISOMORPH_MAX_PERIOD, ISOMORPH_MIN_PERIOD,
    ISOMORPH_WINDOW, IsomorphFixtureReport, MAX_ABSENT_PERIOD_MATCHES, MIN_IOC_SEPARATION,
    MIN_PERIOD_MATCH_SEPARATION, MIN_PRESENT_PERIOD_MATCHES, U64_DRAW_DOMAIN,
};
use crate::analysis::analysis;
use crate::analysis::isomorph::{self, IsomorphError};
use crate::core::glyph::Glyph;
use crate::nulls::null::SplitMix64;

pub(super) fn build_fixture(
    label: &'static str,
    source_plaintext: &'static str,
    key: &SubstitutionKey,
) -> Result<FixtureReport, ControlsError> {
    let plaintext = normalize_plaintext(label, source_plaintext)?;
    let ciphertext = key.encrypt(label, &plaintext)?;
    let recovered = key.decrypt(label, &ciphertext)?;
    let frequency_multiset_preserved =
        sorted_frequency_counts(&plaintext) == sorted_frequency_counts(&ciphertext);
    let bigram_multiset_preserved =
        sorted_ngram_counts(&plaintext, 2) == sorted_ngram_counts(&ciphertext, 2);
    let known_key_recovered = recovered == plaintext;
    let plaintext_ioc = analysis::index_of_coincidence(&plaintext);
    let ciphertext_ioc = analysis::index_of_coincidence(&ciphertext);

    if plaintext_ioc.to_bits() != ciphertext_ioc.to_bits() {
        return Err(ControlsError::IocNotPreserved {
            label,
            plaintext_bits: plaintext_ioc.to_bits(),
            ciphertext_bits: ciphertext_ioc.to_bits(),
        });
    }
    if !frequency_multiset_preserved {
        return Err(ControlsError::FrequencyMultisetChanged { label });
    }
    if !bigram_multiset_preserved {
        return Err(ControlsError::BigramMultisetChanged { label });
    }
    if !known_key_recovered {
        return Err(ControlsError::KnownKeyRecoveryFailed { label });
    }

    Ok(FixtureReport {
        label,
        source_plaintext,
        normalized_plaintext: render_glyphs(label, &plaintext)?,
        ciphertext: render_glyphs(label, &ciphertext)?,
        recovered_plaintext: render_glyphs(label, &recovered)?,
        length: plaintext.len(),
        plaintext_entropy: analysis::shannon_entropy(&plaintext),
        ciphertext_entropy: analysis::shannon_entropy(&ciphertext),
        plaintext_ioc,
        ciphertext_ioc,
        frequency_multiset_preserved,
        bigram_multiset_preserved,
        known_key_recovered,
    })
}

pub(super) fn assert_regime_separation(
    fixture: &FixtureReport,
    flattened_ioc: f64,
    uniform_floor: f64,
) -> Result<(), ControlsError> {
    if fixture.plaintext_ioc <= uniform_floor
        || fixture.plaintext_ioc <= flattened_ioc + MIN_IOC_SEPARATION
        || flattened_ioc >= uniform_floor
    {
        return Err(ControlsError::RegimeSeparationFailed {
            label: fixture.label,
            plaintext_ioc: fixture.plaintext_ioc,
            flattened_ioc,
            uniform_floor,
        });
    }
    Ok(())
}

pub(super) fn build_isomorph_fixture(
    label: &'static str,
    cipher: &'static str,
    key_summary: String,
    plaintext: &[Glyph],
    ciphertext: &[Glyph],
    expected_period: usize,
) -> Result<IsomorphFixtureReport, ControlsError> {
    let analysis = detect_isomorphs(label, ciphertext, ISOMORPH_WINDOW)?;
    let expected_period_matches = analysis.period_matches(expected_period);
    let strongest_signatures = analysis.strongest_signatures(expected_period);
    let exact_repeated_windows = analysis::ngrams(ciphertext, ISOMORPH_WINDOW)
        .values()
        .filter(|count| **count > 1)
        .count();

    Ok(IsomorphFixtureReport {
        label,
        cipher,
        key_summary,
        plaintext: render_glyphs(label, plaintext)?,
        ciphertext: render_glyphs(label, ciphertext)?,
        length: ciphertext.len(),
        distinct_cipher_symbols: analysis::frequencies(ciphertext).len(),
        ciphertext_entropy: analysis::shannon_entropy(ciphertext),
        plaintext_ioc: analysis::index_of_coincidence(plaintext),
        ciphertext_ioc: analysis::index_of_coincidence(ciphertext),
        exact_repeated_windows,
        informative_windows: analysis.informative_windows,
        repeated_signature_kinds: analysis.repeated_signature_kinds(),
        expected_period,
        expected_period_matches,
        best_period: analysis.best_period(),
        strongest_signatures,
    })
}

pub(super) fn assert_isomorph_separation(
    vigenere: &IsomorphFixtureReport,
    autokey: &IsomorphFixtureReport,
    running_key: &IsomorphFixtureReport,
) -> Result<(), ControlsError> {
    if vigenere.expected_period_matches < MIN_PRESENT_PERIOD_MATCHES {
        return Err(ControlsError::IsomorphSignalMissing {
            label: vigenere.label,
            expected_period: vigenere.expected_period,
            observed_matches: vigenere.expected_period_matches,
            required_matches: MIN_PRESENT_PERIOD_MATCHES,
        });
    }

    let observed_best_period = vigenere.best_period.map(|signal| signal.period);
    if observed_best_period != Some(vigenere.expected_period) {
        return Err(ControlsError::IsomorphPeriodRecoveryFailed {
            label: vigenere.label,
            expected_period: vigenere.expected_period,
            observed_period: observed_best_period,
            observed_matches: vigenere.best_period.map_or(0, |signal| signal.matches),
        });
    }

    for absent in [autokey, running_key] {
        let absent_best = absent.best_period;
        let absent_best_matches = absent_best.map_or(0, |signal| signal.matches);
        if absent_best_matches > MAX_ABSENT_PERIOD_MATCHES {
            return Err(ControlsError::IsomorphFalsePositive {
                label: absent.label,
                observed_period: absent_best.map_or(absent.expected_period, |signal| signal.period),
                observed_matches: absent_best_matches,
                allowed_matches: MAX_ABSENT_PERIOD_MATCHES,
            });
        }

        if vigenere.expected_period_matches < absent_best_matches + MIN_PERIOD_MATCH_SEPARATION {
            return Err(ControlsError::IsomorphSeparationFailed {
                present_label: vigenere.label,
                absent_label: absent.label,
                present_matches: vigenere.expected_period_matches,
                absent_matches: absent_best_matches,
                required_gap: MIN_PERIOD_MATCH_SEPARATION,
            });
        }
    }

    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SubstitutionKey {
    seed: u64,
    forward: Vec<Glyph>,
    inverse: Vec<Glyph>,
}

impl SubstitutionKey {
    pub(super) fn from_seed(seed: u64, alphabet_size: usize) -> Result<Self, ControlsError> {
        let mut forward = identity_glyphs(alphabet_size)?;
        let mut rng = SplitMix64::new(seed);
        let mut unswapped = forward.len();
        while unswapped > 1 {
            let last = unswapped - 1;
            let partner = random_index_below(unswapped, &mut rng)?;
            forward.swap(last, partner);
            unswapped = last;
        }
        Self::from_forward(seed, forward)
    }

    fn from_forward(seed: u64, forward: Vec<Glyph>) -> Result<Self, ControlsError> {
        let alphabet_size = forward.len();
        let mut inverse_slots = vec![None; alphabet_size];
        for (plain_index, cipher) in forward.iter().copied().enumerate() {
            let Some(slot) = inverse_slots.get_mut(usize::from(cipher.0)) else {
                return Err(ControlsError::NonBijectiveKey {
                    seed,
                    alphabet_size,
                });
            };
            let plain = glyph_from_index(plain_index, alphabet_size)?;
            if slot.replace(plain).is_some() {
                return Err(ControlsError::NonBijectiveKey {
                    seed,
                    alphabet_size,
                });
            }
        }

        let mut inverse = Vec::with_capacity(alphabet_size);
        for slot in inverse_slots {
            let Some(glyph) = slot else {
                return Err(ControlsError::NonBijectiveKey {
                    seed,
                    alphabet_size,
                });
            };
            inverse.push(glyph);
        }

        Ok(Self {
            seed,
            forward,
            inverse,
        })
    }

    pub(super) fn encrypt(
        &self,
        label: &'static str,
        plaintext: &[Glyph],
    ) -> Result<Vec<Glyph>, ControlsError> {
        translate(label, plaintext, &self.forward)
    }

    pub(super) fn decrypt(
        &self,
        label: &'static str,
        ciphertext: &[Glyph],
    ) -> Result<Vec<Glyph>, ControlsError> {
        translate(label, ciphertext, &self.inverse)
    }

    pub(super) fn mapping_string(&self) -> Result<String, ControlsError> {
        let mut mappings = Vec::new();
        for (plain_index, cipher) in self.forward.iter().copied().enumerate() {
            let plain = char_from_index(plain_index, self.forward.len())?;
            let cipher = char_from_glyph("key mapping", cipher, self.forward.len())?;
            mappings.push(format!("{plain}->{cipher}"));
        }
        Ok(mappings.join(" "))
    }
}

fn translate(
    label: &'static str,
    input: &[Glyph],
    map: &[Glyph],
) -> Result<Vec<Glyph>, ControlsError> {
    let mut output = Vec::with_capacity(input.len());
    for glyph in input {
        output.push(map_glyph(label, *glyph, map)?);
    }
    Ok(output)
}

fn map_glyph(label: &'static str, glyph: Glyph, map: &[Glyph]) -> Result<Glyph, ControlsError> {
    map.get(usize::from(glyph.0))
        .copied()
        .ok_or(ControlsError::GlyphOutsideAlphabet {
            label,
            glyph,
            alphabet_size: map.len(),
        })
}

pub(super) fn normalize_plaintext(
    label: &'static str,
    plaintext: &'static str,
) -> Result<Vec<Glyph>, ControlsError> {
    let mut glyphs = Vec::new();
    for symbol in plaintext.chars() {
        if symbol.is_ascii_alphabetic() {
            let upper = symbol.to_ascii_uppercase();
            glyphs.push(Glyph(u16::from(upper as u8 - b'A')));
        } else if !(symbol.is_ascii_whitespace() || symbol.is_ascii_punctuation()) {
            return Err(ControlsError::UnsupportedPlaintextSymbol { label, symbol });
        }
    }
    if glyphs.is_empty() {
        return Err(ControlsError::EmptyPlaintext { label });
    }
    Ok(glyphs)
}

fn render_glyphs(label: &'static str, glyphs: &[Glyph]) -> Result<String, ControlsError> {
    let mut rendered = String::with_capacity(glyphs.len());
    for glyph in glyphs {
        rendered.push(char_from_glyph(label, *glyph, ALPHABET_SIZE)?);
    }
    Ok(rendered)
}

fn char_from_glyph(
    label: &'static str,
    glyph: Glyph,
    alphabet_size: usize,
) -> Result<char, ControlsError> {
    let index = glyph_index(label, glyph, alphabet_size)?;
    char_from_index(index, alphabet_size)
}

fn glyph_index(
    label: &'static str,
    glyph: Glyph,
    alphabet_size: usize,
) -> Result<usize, ControlsError> {
    let index = usize::from(glyph.0);
    if index >= alphabet_size {
        return Err(ControlsError::GlyphOutsideAlphabet {
            label,
            glyph,
            alphabet_size,
        });
    }
    Ok(index)
}

fn char_from_index(index: usize, alphabet_size: usize) -> Result<char, ControlsError> {
    if index >= alphabet_size || index >= ALPHABET_SIZE {
        return Err(ControlsError::AlphabetTooLarge { alphabet_size });
    }
    let index =
        u8::try_from(index).map_err(|_error| ControlsError::AlphabetTooLarge { alphabet_size })?;
    Ok(char::from(b'A' + index))
}

fn identity_glyphs(alphabet_size: usize) -> Result<Vec<Glyph>, ControlsError> {
    let mut glyphs = Vec::with_capacity(alphabet_size);
    for index in 0..alphabet_size {
        glyphs.push(glyph_from_index(index, alphabet_size)?);
    }
    Ok(glyphs)
}

fn glyph_from_index(index: usize, alphabet_size: usize) -> Result<Glyph, ControlsError> {
    if index > usize::from(u16::MAX) {
        return Err(ControlsError::AlphabetTooLarge { alphabet_size });
    }
    Ok(Glyph(index as u16))
}

fn random_index_below(bound: usize, rng: &mut SplitMix64) -> Result<usize, ControlsError> {
    let bound = u128::try_from(bound).map_err(|_error| ControlsError::AlphabetTooLarge {
        alphabet_size: bound,
    })?;
    if bound == 0 {
        return Err(ControlsError::AlphabetTooLarge { alphabet_size: 0 });
    }
    let acceptance_zone = (U64_DRAW_DOMAIN / bound) * bound;
    loop {
        let draw = u128::from(rng.next_u64());
        if draw < acceptance_zone {
            let index = draw % bound;
            return usize::try_from(index).map_err(|_error| ControlsError::AlphabetTooLarge {
                alphabet_size: usize::MAX,
            });
        }
    }
}

pub(super) fn balanced_uniform_sequence(
    alphabet_size: usize,
    length: usize,
) -> Result<Vec<Glyph>, ControlsError> {
    let mut glyphs = Vec::with_capacity(length);
    for index in 0..length {
        let symbol = index % alphabet_size;
        glyphs.push(glyph_from_index(symbol, alphabet_size)?);
    }
    Ok(glyphs)
}

pub(super) fn random_distinct_glyphs(
    label: &'static str,
    seed: u64,
    count: usize,
) -> Result<Vec<Glyph>, ControlsError> {
    let mut symbols = identity_glyphs(ALPHABET_SIZE)?;
    let mut rng = SplitMix64::new(seed);
    let mut unswapped = symbols.len();
    while unswapped > 1 {
        let last = unswapped - 1;
        let partner = random_index_below(unswapped, &mut rng)?;
        symbols.swap(last, partner);
        unswapped = last;
    }
    let glyphs = symbols.into_iter().take(count).collect::<Vec<_>>();
    if glyphs.len() != count {
        return Err(ControlsError::InvalidIsomorphWindow {
            label,
            window: count,
            sequence_len: glyphs.len(),
        });
    }
    Ok(glyphs)
}

pub(super) fn random_key_stream(
    label: &'static str,
    seed: u64,
    length: usize,
) -> Result<Vec<Glyph>, ControlsError> {
    let mut key = Vec::with_capacity(length);
    let mut rng = SplitMix64::new(seed);
    for _position in 0..length {
        key.push(glyph_from_index(
            random_index_below(ALPHABET_SIZE, &mut rng)?,
            ALPHABET_SIZE,
        )?);
    }
    if key.is_empty() {
        return Err(ControlsError::EmptyPlaintext { label });
    }
    Ok(key)
}

pub(super) fn encrypt_vigenere(
    label: &'static str,
    plaintext: &[Glyph],
    key: &[Glyph],
) -> Result<Vec<Glyph>, ControlsError> {
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    for (position, plain) in plaintext.iter().copied().enumerate() {
        let key_glyph = period_glyph_at(label, key, position)?;
        ciphertext.push(add_glyphs(label, plain, key_glyph)?);
    }
    Ok(ciphertext)
}

pub(super) fn encrypt_autokey(
    label: &'static str,
    plaintext: &[Glyph],
    seed_key: &[Glyph],
) -> Result<Vec<Glyph>, ControlsError> {
    if seed_key.is_empty() {
        return Err(ControlsError::EmptyPlaintext { label });
    }

    let mut ciphertext = Vec::with_capacity(plaintext.len());
    for (position, plain) in plaintext.iter().copied().enumerate() {
        let key = if position < seed_key.len() {
            period_glyph_at(label, seed_key, position)?
        } else {
            let Some(key) = plaintext.get(position - seed_key.len()).copied() else {
                return Err(ControlsError::InvalidIsomorphWindow {
                    label,
                    window: seed_key.len(),
                    sequence_len: plaintext.len(),
                });
            };
            key
        };
        ciphertext.push(add_glyphs(label, plain, key)?);
    }
    Ok(ciphertext)
}

pub(super) fn encrypt_key_stream(
    label: &'static str,
    plaintext: &[Glyph],
    key: &[Glyph],
) -> Result<Vec<Glyph>, ControlsError> {
    if plaintext.len() != key.len() {
        return Err(ControlsError::InvalidIsomorphWindow {
            label,
            window: key.len(),
            sequence_len: plaintext.len(),
        });
    }

    let mut ciphertext = Vec::with_capacity(plaintext.len());
    for (plain, key_glyph) in plaintext.iter().copied().zip(key.iter().copied()) {
        ciphertext.push(add_glyphs(label, plain, key_glyph)?);
    }
    Ok(ciphertext)
}

fn add_glyphs(label: &'static str, left: Glyph, right: Glyph) -> Result<Glyph, ControlsError> {
    let sum = glyph_index(label, left, ALPHABET_SIZE)? + glyph_index(label, right, ALPHABET_SIZE)?;
    glyph_from_index(sum % ALPHABET_SIZE, ALPHABET_SIZE)
}

fn period_glyph_at(
    label: &'static str,
    period: &[Glyph],
    position: usize,
) -> Result<Glyph, ControlsError> {
    if period.is_empty() {
        return Err(ControlsError::EmptyPlaintext { label });
    }
    let offset = position % period.len();
    period
        .get(offset)
        .copied()
        .ok_or(ControlsError::InvalidIsomorphWindow {
            label,
            window: offset,
            sequence_len: period.len(),
        })
}

pub(super) fn render_key(key: &[Glyph]) -> Result<String, ControlsError> {
    render_glyphs("key rendering", key)
}

pub(super) fn detect_isomorphs(
    label: &'static str,
    seq: &[Glyph],
    window: usize,
) -> Result<isomorph::IsomorphDetection, ControlsError> {
    isomorph::detect_isomorphs(seq, window, ISOMORPH_MIN_PERIOD, ISOMORPH_MAX_PERIOD).map_err(
        |error| match error {
            IsomorphError::InvalidWindow {
                window,
                sequence_len,
            } => ControlsError::InvalidIsomorphWindow {
                label,
                window,
                sequence_len,
            },
            IsomorphError::InvalidPeriodSearch {
                min_period,
                max_period,
            } => ControlsError::InvalidPeriodSearch {
                label,
                min_period,
                max_period,
            },
        },
    )
}

pub(super) fn sorted_frequency_counts(seq: &[Glyph]) -> Vec<usize> {
    let mut counts = analysis::frequencies(seq)
        .values()
        .copied()
        .collect::<Vec<_>>();
    counts.sort_unstable();
    counts
}

fn sorted_ngram_counts(seq: &[Glyph], n: usize) -> Vec<usize> {
    let mut counts = analysis::ngrams(seq, n)
        .values()
        .copied()
        .collect::<Vec<_>>();
    counts.sort_unstable();
    counts
}

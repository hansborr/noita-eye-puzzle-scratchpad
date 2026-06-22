//! Experiment 11 — positive controls for solved cipher types.
//!
//! This module calibrates the workbench against a cipher class whose behavior
//! is known in advance. The monoalphabetic control below is deliberately a
//! generated fixture: a known English-like plaintext is encrypted with a
//! deterministic one-to-one substitution key produced by the in-crate
//! [`crate::null::SplitMix64`] PRNG. That proves the frequency and substitution
//! tooling fires on a monoalphabetic cipher with ground truth.
//!
//! The documented Common Glyphs plaintexts are included only as named
//! round-trip vectors. Their upstream glyph-pixel mapping is not vendored here,
//! and the phrases are too short for honest frequency-only recovery claims.
//! Passing this control says nothing about whether the unsolved eye glyphs
//! encode a recoverable message.

use crate::analysis;
use crate::glyph::Glyph;
use crate::null::SplitMix64;

const ENGLISH_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ALPHABET_SIZE: usize = 26;
const DEFAULT_MONOALPHABETIC_SEED: u64 = 0x6d6f_6e6f_616c_7068;
const U64_DRAW_DOMAIN: u128 = 1u128 << 64;
const MIN_IOC_SEPARATION: f64 = 0.015;
const LONG_FIXTURE_LABEL: &str = "embedded English-like calibration plaintext";
const LONG_FIXTURE_TEXT: &str = "\
THE METHOD CHECKS THE KNOWN CIPHER BEFORE IT JUDGES THE UNKNOWN MESSAGE.
A SIMPLE SUBSTITUTION CHANGES LETTER NAMES BUT IT DOES NOT CHANGE HOW OFTEN
EACH LETTER OCCURS. THE SAME TOOL SHOULD NOTICE THAT THE CIPHER TEXT KEEPS
THE SAME COINCIDENCE RATE AND THE SAME BAG OF COUNTS. WHEN THE SAMPLE IS LONG
ENOUGH THE ENGLISH FREQUENCY SHAPE STANDS ABOVE A UNIFORM STREAM. THAT IS THE
ONLY CLAIM OF THIS CONTROL. IT CALIBRATES THE MEASUREMENT PATH AND IT DOES NOT
SAY THAT THE EYE GLYPHS CONTAIN A RECOVERABLE SENTENCE.";
const DOCUMENTED_COMMON_GLYPHS: [(&str, &str); 2] = [
    ("Common Glyphs / seek the end", "SEEK THE END"),
    (
        "Common Glyphs / bring the treasure here",
        "BRING THE TREASURE HERE",
    ),
];

/// Configuration for the monoalphabetic positive control.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MonoalphabeticControlConfig {
    /// Seed used to generate the deterministic one-to-one substitution key.
    pub seed: u64,
}

impl Default for MonoalphabeticControlConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_MONOALPHABETIC_SEED,
        }
    }
}

/// Error returned when a positive-control invariant cannot be established.
#[derive(Clone, Debug, PartialEq)]
pub enum ControlsError {
    /// A plaintext fixture contained no alphabetic symbols after normalization.
    EmptyPlaintext {
        /// Human-readable fixture label.
        label: &'static str,
    },
    /// A plaintext fixture used a character outside the accepted ASCII text
    /// notation.
    UnsupportedPlaintextSymbol {
        /// Human-readable fixture label.
        label: &'static str,
        /// The unsupported symbol.
        symbol: char,
    },
    /// A generated glyph index was outside the configured alphabet.
    GlyphOutsideAlphabet {
        /// Operation or fixture that encountered the bad glyph.
        label: &'static str,
        /// The glyph value that was out of range.
        glyph: Glyph,
        /// Number of symbols in the configured alphabet.
        alphabet_size: usize,
    },
    /// The configured alphabet cannot be represented by this control.
    AlphabetTooLarge {
        /// Number of symbols requested.
        alphabet_size: usize,
    },
    /// The generated key failed the one-to-one substitution invariant.
    NonBijectiveKey {
        /// Seed used to generate the key.
        seed: u64,
        /// Number of symbols in the configured alphabet.
        alphabet_size: usize,
    },
    /// Monoalphabetic substitution changed the index of coincidence.
    IocNotPreserved {
        /// Human-readable fixture label.
        label: &'static str,
        /// Exact bit pattern of the plaintext `IoC`.
        plaintext_bits: u64,
        /// Exact bit pattern of the ciphertext `IoC`.
        ciphertext_bits: u64,
    },
    /// Monoalphabetic substitution changed the sorted frequency counts.
    FrequencyMultisetChanged {
        /// Human-readable fixture label.
        label: &'static str,
    },
    /// Monoalphabetic substitution changed the sorted bigram count multiset.
    BigramMultisetChanged {
        /// Human-readable fixture label.
        label: &'static str,
    },
    /// Decrypting with the known inverse key did not recover the plaintext.
    KnownKeyRecoveryFailed {
        /// Human-readable fixture label.
        label: &'static str,
    },
    /// The long plaintext did not separate English-like `IoC` from a flattened
    /// uniform sample.
    RegimeSeparationFailed {
        /// Human-readable fixture label.
        label: &'static str,
        /// `IoC` of the plaintext fixture.
        plaintext_ioc: f64,
        /// `IoC` of the balanced uniform comparison sample.
        flattened_ioc: f64,
        /// Uniform with-replacement floor, `1 / alphabet_size`.
        uniform_floor: f64,
    },
}

/// Summary of one encrypted positive-control fixture.
#[derive(Clone, Debug, PartialEq)]
pub struct FixtureReport {
    /// Human-readable fixture label.
    pub label: &'static str,
    /// Source plaintext before normalization.
    pub source_plaintext: &'static str,
    /// Uppercase A-Z plaintext used by the substitution routine.
    pub normalized_plaintext: String,
    /// Ciphertext letters emitted by the generated one-to-one key.
    pub ciphertext: String,
    /// Plaintext recovered by applying the known inverse key.
    pub recovered_plaintext: String,
    /// Number of alphabetic symbols in the normalized plaintext.
    pub length: usize,
    /// Shannon entropy of the normalized plaintext.
    pub plaintext_entropy: f64,
    /// Shannon entropy of the ciphertext.
    pub ciphertext_entropy: f64,
    /// Index of coincidence of the normalized plaintext.
    pub plaintext_ioc: f64,
    /// Index of coincidence of the ciphertext.
    pub ciphertext_ioc: f64,
    /// Whether sorted symbol-frequency counts are exactly preserved.
    pub frequency_multiset_preserved: bool,
    /// Whether sorted bigram-count multisets are exactly preserved.
    pub bigram_multiset_preserved: bool,
    /// Whether the known inverse key recovered the normalized plaintext exactly.
    pub known_key_recovered: bool,
}

/// Complete monoalphabetic positive-control report.
#[derive(Clone, Debug, PartialEq)]
pub struct MonoalphabeticControlReport {
    /// Configuration used to build the control.
    pub config: MonoalphabeticControlConfig,
    /// Alphabet used by the generated substitution key.
    pub alphabet: &'static str,
    /// Number of symbols in the alphabet.
    pub alphabet_size: usize,
    /// Generated key rendered as `plain->cipher` pairs.
    pub key_mapping: String,
    /// The with-replacement uniform `IoC` floor, `1 / alphabet_size`.
    pub uniform_floor: f64,
    /// `IoC` of the balanced uniform comparison sample with the same length as
    /// the long fixture.
    pub flattened_ioc: f64,
    /// Shannon entropy of the balanced uniform comparison sample.
    pub flattened_entropy: f64,
    /// Long English-like fixture used for frequency and `IoC` separation.
    pub long_fixture: FixtureReport,
    /// Short documented Common Glyphs plaintexts, used only as known-key
    /// exactness vectors.
    pub documented_vectors: Vec<FixtureReport>,
}

/// Runs the monoalphabetic substitution positive control.
///
/// # Errors
/// Returns [`ControlsError`] if key generation fails or if any positive-control
/// invariant fails. Such an error means the calibration methodology is suspect.
pub fn run_monoalphabetic_control(
    config: MonoalphabeticControlConfig,
) -> Result<MonoalphabeticControlReport, ControlsError> {
    let key = SubstitutionKey::from_seed(config.seed, ALPHABET_SIZE)?;
    let long_fixture = build_fixture(LONG_FIXTURE_LABEL, LONG_FIXTURE_TEXT, &key)?;
    let flattened = balanced_uniform_sequence(ALPHABET_SIZE, long_fixture.length)?;
    let flattened_ioc = analysis::index_of_coincidence(&flattened);
    let flattened_entropy = analysis::shannon_entropy(&flattened);
    let uniform_floor = 1.0 / ALPHABET_SIZE as f64;
    assert_regime_separation(&long_fixture, flattened_ioc, uniform_floor)?;

    let mut documented_vectors = Vec::new();
    for (label, plaintext) in DOCUMENTED_COMMON_GLYPHS {
        documented_vectors.push(build_fixture(label, plaintext, &key)?);
    }

    Ok(MonoalphabeticControlReport {
        config,
        alphabet: ENGLISH_ALPHABET,
        alphabet_size: ALPHABET_SIZE,
        key_mapping: key.mapping_string()?,
        uniform_floor,
        flattened_ioc,
        flattened_entropy,
        long_fixture,
        documented_vectors,
    })
}

fn build_fixture(
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

fn assert_regime_separation(
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct SubstitutionKey {
    seed: u64,
    forward: Vec<Glyph>,
    inverse: Vec<Glyph>,
}

impl SubstitutionKey {
    fn from_seed(seed: u64, alphabet_size: usize) -> Result<Self, ControlsError> {
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

    fn encrypt(
        &self,
        label: &'static str,
        plaintext: &[Glyph],
    ) -> Result<Vec<Glyph>, ControlsError> {
        translate(label, plaintext, &self.forward)
    }

    fn decrypt(
        &self,
        label: &'static str,
        ciphertext: &[Glyph],
    ) -> Result<Vec<Glyph>, ControlsError> {
        translate(label, ciphertext, &self.inverse)
    }

    fn mapping_string(&self) -> Result<String, ControlsError> {
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

fn normalize_plaintext(
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
    let index = usize::from(glyph.0);
    if index >= alphabet_size {
        return Err(ControlsError::GlyphOutsideAlphabet {
            label,
            glyph,
            alphabet_size,
        });
    }
    char_from_index(index, alphabet_size)
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

fn balanced_uniform_sequence(
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

fn sorted_frequency_counts(seq: &[Glyph]) -> Vec<usize> {
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

#[cfg(test)]
mod tests {
    use super::{
        ALPHABET_SIZE, ControlsError, MonoalphabeticControlConfig, SubstitutionKey,
        balanced_uniform_sequence, normalize_plaintext, run_monoalphabetic_control,
        sorted_frequency_counts,
    };
    use crate::analysis;

    #[test]
    fn monoalphabetic_control_preserves_exact_statistics() {
        let report = run_monoalphabetic_control(MonoalphabeticControlConfig {
            seed: 0x1234_5678_9abc_def0,
        })
        .unwrap();

        assert_eq!(report.long_fixture.length, 420);
        assert_eq!(
            report.long_fixture.plaintext_ioc.to_bits(),
            report.long_fixture.ciphertext_ioc.to_bits()
        );
        assert!(
            (report.long_fixture.plaintext_entropy - report.long_fixture.ciphertext_entropy).abs()
                < 1e-12
        );
        assert!(report.long_fixture.frequency_multiset_preserved);
        assert!(report.long_fixture.bigram_multiset_preserved);
        assert!(report.long_fixture.known_key_recovered);
        assert_eq!(
            report.long_fixture.normalized_plaintext,
            report.long_fixture.recovered_plaintext
        );
    }

    #[test]
    fn monoalphabetic_control_separates_english_like_from_uniform() {
        let report =
            run_monoalphabetic_control(MonoalphabeticControlConfig { seed: 0xf00d }).unwrap();

        assert!(report.long_fixture.plaintext_ioc > report.uniform_floor);
        assert!(report.flattened_ioc < report.uniform_floor);
        assert!(report.long_fixture.plaintext_ioc - report.flattened_ioc > 0.03);
    }

    #[test]
    fn documented_common_glyph_plaintexts_are_known_key_vectors() {
        let report =
            run_monoalphabetic_control(MonoalphabeticControlConfig { seed: 0xbeef }).unwrap();
        let normalized = report
            .documented_vectors
            .iter()
            .map(|fixture| fixture.normalized_plaintext.as_str())
            .collect::<Vec<_>>();

        assert_eq!(normalized, vec!["SEEKTHEEND", "BRINGTHETREASUREHERE"]);
        for fixture in &report.documented_vectors {
            assert_eq!(
                fixture.plaintext_ioc.to_bits(),
                fixture.ciphertext_ioc.to_bits()
            );
            assert!(fixture.frequency_multiset_preserved);
            assert!(fixture.bigram_multiset_preserved);
            assert!(fixture.known_key_recovered);
            assert_eq!(fixture.normalized_plaintext, fixture.recovered_plaintext);
        }
    }

    #[test]
    fn generated_key_is_a_bijection() {
        let key = SubstitutionKey::from_seed(7, ALPHABET_SIZE).unwrap();
        let plaintext = normalize_plaintext("test", "ABCDEFGHIJKLMNOPQRSTUVWXYZ").unwrap();
        let ciphertext = key.encrypt("test", &plaintext).unwrap();
        let recovered = key.decrypt("test", &ciphertext).unwrap();

        assert_eq!(recovered, plaintext);
        assert_eq!(
            sorted_frequency_counts(&plaintext),
            sorted_frequency_counts(&ciphertext)
        );
    }

    #[test]
    fn balanced_uniform_comparison_sits_below_with_replacement_floor() {
        let sample = balanced_uniform_sequence(ALPHABET_SIZE, 420).unwrap();
        let ioc = analysis::index_of_coincidence(&sample);
        let uniform_floor = 1.0 / ALPHABET_SIZE as f64;

        assert!(ioc < uniform_floor);
    }

    #[test]
    fn unsupported_plaintext_symbols_are_rejected() {
        let error = normalize_plaintext("bad fixture", "SEEK 123").unwrap_err();

        assert_eq!(
            error,
            ControlsError::UnsupportedPlaintextSymbol {
                label: "bad fixture",
                symbol: '1'
            }
        );
    }
}

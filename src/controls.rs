//! Experiment 11 — positive controls for solved cipher types.
//!
//! This module calibrates the workbench against a cipher class whose behavior
//! is known in advance. The monoalphabetic control is deliberately a generated
//! fixture: a known English-like plaintext is encrypted with a deterministic
//! one-to-one substitution key produced by the in-crate [`crate::null::SplitMix64`]
//! PRNG. That proves the frequency and substitution tooling fires on a
//! monoalphabetic cipher with ground truth.
//!
//! The isomorph/polyalphabetic control is also generated: known plaintext is
//! encrypted with short-key Vigenere and autokey fixtures whose repeated
//! structure is intentional, then contrasted with a full-length running-key
//! fixture where that short-period structure is absent. That proves the
//! first-occurrence signature detector fires on known structure and stays quiet
//! on the matched absence case.
//!
//! The documented Common Glyphs plaintexts are included only as named
//! round-trip vectors. Their upstream glyph-pixel mapping is not vendored here,
//! and the phrases are too short for honest frequency-only recovery claims.
//! Passing this control says nothing about whether the unsolved eye glyphs
//! encode a recoverable message.

use std::collections::BTreeMap;

use crate::analysis;
use crate::glyph::Glyph;
use crate::null::SplitMix64;

const ENGLISH_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ALPHABET_SIZE: usize = 26;
const DEFAULT_MONOALPHABETIC_SEED: u64 = 0x6d6f_6e6f_616c_7068;
const DEFAULT_ISOMORPH_SEED: u64 = 0x6973_6f6d_6f72_7068;
const U64_DRAW_DOMAIN: u128 = 1u128 << 64;
const MIN_IOC_SEPARATION: f64 = 0.015;
const ISOMORPH_KEY_PERIOD: usize = 7;
const ISOMORPH_WINDOW: usize = 9;
const ISOMORPH_FIXTURE_LENGTH: usize = 280;
const ISOMORPH_MIN_PERIOD: usize = 2;
const ISOMORPH_MAX_PERIOD: usize = 16;
const MIN_PRESENT_PERIOD_MATCHES: usize = 180;
const MAX_ABSENT_PERIOD_MATCHES: usize = 32;
const MIN_PERIOD_MATCH_SEPARATION: usize = 120;
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

/// Configuration for the isomorph/polyalphabetic positive control.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IsomorphControlConfig {
    /// Seed used to generate deterministic known-key fixtures.
    pub seed: u64,
}

impl Default for IsomorphControlConfig {
    fn default() -> Self {
        Self {
            seed: DEFAULT_ISOMORPH_SEED,
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
    /// An isomorph detector window was incompatible with a fixture.
    InvalidIsomorphWindow {
        /// Human-readable fixture label.
        label: &'static str,
        /// Requested detector window length.
        window: usize,
        /// Number of glyphs available in the sequence.
        sequence_len: usize,
    },
    /// The isomorph detector period search bounds were invalid.
    InvalidPeriodSearch {
        /// Human-readable fixture label.
        label: &'static str,
        /// Lower inclusive period bound.
        min_period: usize,
        /// Upper inclusive period bound.
        max_period: usize,
    },
    /// A known-present fixture did not produce the expected period signal.
    IsomorphSignalMissing {
        /// Human-readable fixture label.
        label: &'static str,
        /// Ground-truth short period.
        expected_period: usize,
        /// Observed repeated-signature matches at that period.
        observed_matches: usize,
        /// Minimum matches required by the control.
        required_matches: usize,
    },
    /// A known-absent fixture produced too much short-period signal.
    IsomorphFalsePositive {
        /// Human-readable fixture label.
        label: &'static str,
        /// Ground-truth short period that should be absent.
        expected_period: usize,
        /// Observed repeated-signature matches at that period.
        observed_matches: usize,
        /// Maximum matches allowed by the control.
        allowed_matches: usize,
    },
    /// Known-present and known-absent isomorph fixtures did not separate.
    IsomorphSeparationFailed {
        /// Human-readable known-present fixture label.
        present_label: &'static str,
        /// Human-readable known-absent fixture label.
        absent_label: &'static str,
        /// Known-present matches at the expected period.
        present_matches: usize,
        /// Known-absent matches at the expected period.
        absent_matches: usize,
        /// Required gap between present and absent matches.
        required_gap: usize,
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

/// Repeated-signature period signal from the isomorph detector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeriodSignal {
    /// Candidate period measured in glyph positions.
    pub period: usize,
    /// Number of informative signature windows repeated exactly one period
    /// later.
    pub matches: usize,
    /// Number of distinct signature shapes contributing at least one match.
    pub signature_kinds: usize,
}

/// One repeated isomorph signature surfaced for CLI inspection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureSummary {
    /// First-occurrence pattern signature rendered as comma-separated ordinals.
    pub signature: String,
    /// Window start positions where this signature occurs.
    pub occurrences: Vec<usize>,
    /// Number of occurrence pairs separated by the ground-truth period.
    pub expected_period_matches: usize,
}

/// Summary of one generated isomorph-control fixture.
#[derive(Clone, Debug, PartialEq)]
pub struct IsomorphFixtureReport {
    /// Human-readable fixture label.
    pub label: &'static str,
    /// Cipher family used to generate the fixture.
    pub cipher: &'static str,
    /// Known-key description rendered for the CLI.
    pub key_summary: String,
    /// Known plaintext rendered as `A` through `Z`.
    pub plaintext: String,
    /// Generated ciphertext rendered as `A` through `Z`.
    pub ciphertext: String,
    /// Number of glyphs in the fixture.
    pub length: usize,
    /// Number of distinct ciphertext symbols.
    pub distinct_cipher_symbols: usize,
    /// Shannon entropy of the ciphertext.
    pub ciphertext_entropy: f64,
    /// Index of coincidence of the known plaintext.
    pub plaintext_ioc: f64,
    /// Index of coincidence of the generated ciphertext.
    pub ciphertext_ioc: f64,
    /// Number of exact repeated ciphertext n-grams at the detector window length.
    pub exact_repeated_windows: usize,
    /// Number of detector windows whose signature contains at least one repeated
    /// symbol.
    pub informative_windows: usize,
    /// Number of distinct informative signatures that repeat somewhere.
    pub repeated_signature_kinds: usize,
    /// Ground-truth period expected for known-present fixtures, and checked as
    /// absent in the contrast fixture.
    pub expected_period: usize,
    /// Repeated-signature matches observed at [`Self::expected_period`].
    pub expected_period_matches: usize,
    /// Strongest period found in the configured search range, if any.
    pub best_period: Option<PeriodSignal>,
    /// Strongest repeated signatures contributing to the expected-period signal.
    pub strongest_signatures: Vec<SignatureSummary>,
}

/// Complete isomorph/polyalphabetic positive-control report.
#[derive(Clone, Debug, PartialEq)]
pub struct IsomorphControlReport {
    /// Configuration used to build the control.
    pub config: IsomorphControlConfig,
    /// Alphabet used by the generated fixtures.
    pub alphabet: &'static str,
    /// Number of symbols in the alphabet.
    pub alphabet_size: usize,
    /// Isomorph detector window length.
    pub window: usize,
    /// Lower inclusive period searched by the detector.
    pub min_period: usize,
    /// Upper inclusive period searched by the detector.
    pub max_period: usize,
    /// Ground-truth short period encoded in the known-present fixtures.
    pub expected_period: usize,
    /// Minimum repeated-signature matches required for known-present fixtures.
    pub required_present_matches: usize,
    /// Maximum repeated-signature matches allowed for the known-absent fixture.
    pub allowed_absent_matches: usize,
    /// Known-present Vigenere fixture.
    pub vigenere: IsomorphFixtureReport,
    /// Known-present autokey fixture.
    pub autokey: IsomorphFixtureReport,
    /// Known-absent running-key contrast fixture.
    pub running_key: IsomorphFixtureReport,
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

/// Runs the isomorph/polyalphabetic positive control.
///
/// The known-present fixtures deliberately align repeated plaintext structure
/// with a short Vigenere key and an autokey seed. The contrast fixture encrypts
/// the same Vigenere plaintext with a full-length running key, removing the
/// short-period ground truth.
///
/// # Errors
/// Returns [`ControlsError`] if fixture generation fails or if the detector
/// cannot separate known-present from known-absent structure. Such an error
/// means the isomorph calibration methodology is suspect.
pub fn run_isomorph_control(
    config: IsomorphControlConfig,
) -> Result<IsomorphControlReport, ControlsError> {
    let target_period = target_cipher_period(config.seed)?;

    let vigenere_key = random_distinct_glyphs(
        "Vigenere short key",
        config.seed ^ 0x7669_6765_6e65_7265,
        ISOMORPH_KEY_PERIOD,
    )?;
    let vigenere_plain_period =
        derive_vigenere_plain_period("Vigenere plaintext period", &target_period, &vigenere_key)?;
    let vigenere_plaintext = repeat_period(&vigenere_plain_period, ISOMORPH_FIXTURE_LENGTH)?;
    let vigenere_ciphertext =
        encrypt_vigenere("Vigenere known-present", &vigenere_plaintext, &vigenere_key)?;
    let vigenere = build_isomorph_fixture(
        "known-present Vigenere short-key fixture",
        "Vigenere",
        format!(
            "period-{} key {}",
            vigenere_key.len(),
            render_key(&vigenere_key)?
        ),
        &vigenere_plaintext,
        &vigenere_ciphertext,
        ISOMORPH_KEY_PERIOD,
    )?;

    let autokey_seed = random_distinct_glyphs(
        "autokey seed",
        config.seed ^ 0x6175_746f_6b65_7921,
        ISOMORPH_KEY_PERIOD,
    )?;
    let autokey_plaintext = derive_autokey_plaintext(
        "autokey known-present",
        &target_period,
        &autokey_seed,
        ISOMORPH_FIXTURE_LENGTH,
    )?;
    let autokey_ciphertext =
        encrypt_autokey("autokey known-present", &autokey_plaintext, &autokey_seed)?;
    let autokey = build_isomorph_fixture(
        "known-present autokey short-seed fixture",
        "autokey",
        format!(
            "{}-symbol seed {}",
            autokey_seed.len(),
            render_key(&autokey_seed)?
        ),
        &autokey_plaintext,
        &autokey_ciphertext,
        ISOMORPH_KEY_PERIOD,
    )?;

    let running_key = random_key_stream(
        "running-key contrast key",
        config.seed ^ 0x7275_6e6e_696e_6721,
        ISOMORPH_FIXTURE_LENGTH,
    )?;
    let running_ciphertext = encrypt_key_stream(
        "running-key known-absent",
        &vigenere_plaintext,
        &running_key,
    )?;
    let running_key = build_isomorph_fixture(
        "known-absent full-length running-key fixture",
        "running key",
        format!("{}-symbol full-length key stream", running_ciphertext.len()),
        &vigenere_plaintext,
        &running_ciphertext,
        ISOMORPH_KEY_PERIOD,
    )?;

    assert_isomorph_separation(&vigenere, &autokey, &running_key)?;

    Ok(IsomorphControlReport {
        config,
        alphabet: ENGLISH_ALPHABET,
        alphabet_size: ALPHABET_SIZE,
        window: ISOMORPH_WINDOW,
        min_period: ISOMORPH_MIN_PERIOD,
        max_period: ISOMORPH_MAX_PERIOD,
        expected_period: ISOMORPH_KEY_PERIOD,
        required_present_matches: MIN_PRESENT_PERIOD_MATCHES,
        allowed_absent_matches: MAX_ABSENT_PERIOD_MATCHES,
        vigenere,
        autokey,
        running_key,
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

fn build_isomorph_fixture(
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

fn assert_isomorph_separation(
    vigenere: &IsomorphFixtureReport,
    autokey: &IsomorphFixtureReport,
    running_key: &IsomorphFixtureReport,
) -> Result<(), ControlsError> {
    for fixture in [vigenere, autokey] {
        if fixture.expected_period_matches < MIN_PRESENT_PERIOD_MATCHES {
            return Err(ControlsError::IsomorphSignalMissing {
                label: fixture.label,
                expected_period: fixture.expected_period,
                observed_matches: fixture.expected_period_matches,
                required_matches: MIN_PRESENT_PERIOD_MATCHES,
            });
        }
        if fixture.expected_period_matches
            < running_key.expected_period_matches + MIN_PERIOD_MATCH_SEPARATION
        {
            return Err(ControlsError::IsomorphSeparationFailed {
                present_label: fixture.label,
                absent_label: running_key.label,
                present_matches: fixture.expected_period_matches,
                absent_matches: running_key.expected_period_matches,
                required_gap: MIN_PERIOD_MATCH_SEPARATION,
            });
        }
    }

    if running_key.expected_period_matches > MAX_ABSENT_PERIOD_MATCHES {
        return Err(ControlsError::IsomorphFalsePositive {
            label: running_key.label,
            expected_period: running_key.expected_period,
            observed_matches: running_key.expected_period_matches,
            allowed_matches: MAX_ABSENT_PERIOD_MATCHES,
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

fn target_cipher_period(seed: u64) -> Result<Vec<Glyph>, ControlsError> {
    let symbols = random_distinct_glyphs("target isomorph period", seed ^ 0x7461_7267_6574, 5)?;
    let mut period = Vec::with_capacity(ISOMORPH_KEY_PERIOD);
    for offset in [0usize, 1, 2, 0, 3, 4, 0] {
        let Some(glyph) = symbols.get(offset).copied() else {
            return Err(ControlsError::AlphabetTooLarge {
                alphabet_size: ALPHABET_SIZE,
            });
        };
        period.push(glyph);
    }
    Ok(period)
}

fn random_distinct_glyphs(
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

fn random_key_stream(
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

fn derive_vigenere_plain_period(
    label: &'static str,
    target_period: &[Glyph],
    key: &[Glyph],
) -> Result<Vec<Glyph>, ControlsError> {
    if target_period.len() != key.len() {
        return Err(ControlsError::InvalidIsomorphWindow {
            label,
            window: key.len(),
            sequence_len: target_period.len(),
        });
    }

    let mut plaintext = Vec::with_capacity(target_period.len());
    for (cipher, key_glyph) in target_period.iter().copied().zip(key.iter().copied()) {
        plaintext.push(subtract_glyphs(label, cipher, key_glyph)?);
    }
    Ok(plaintext)
}

fn derive_autokey_plaintext(
    label: &'static str,
    target_period: &[Glyph],
    seed_key: &[Glyph],
    length: usize,
) -> Result<Vec<Glyph>, ControlsError> {
    if seed_key.is_empty() {
        return Err(ControlsError::EmptyPlaintext { label });
    }

    let mut plaintext = Vec::with_capacity(length);
    for position in 0..length {
        let cipher = period_glyph_at(label, target_period, position)?;
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
        plaintext.push(subtract_glyphs(label, cipher, key)?);
    }
    Ok(plaintext)
}

fn repeat_period(period: &[Glyph], length: usize) -> Result<Vec<Glyph>, ControlsError> {
    let mut output = Vec::with_capacity(length);
    for position in 0..length {
        output.push(period_glyph_at(
            "repeated plaintext period",
            period,
            position,
        )?);
    }
    Ok(output)
}

fn encrypt_vigenere(
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

fn encrypt_autokey(
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

fn encrypt_key_stream(
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

fn subtract_glyphs(label: &'static str, left: Glyph, right: Glyph) -> Result<Glyph, ControlsError> {
    let left = glyph_index(label, left, ALPHABET_SIZE)?;
    let right = glyph_index(label, right, ALPHABET_SIZE)?;
    glyph_from_index(
        (ALPHABET_SIZE + left - right) % ALPHABET_SIZE,
        ALPHABET_SIZE,
    )
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

fn render_key(key: &[Glyph]) -> Result<String, ControlsError> {
    render_glyphs("key rendering", key)
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct PatternSignature {
    values: Vec<usize>,
}

impl PatternSignature {
    fn from_window(window: &[Glyph]) -> Self {
        let mut assignments: Vec<(Glyph, usize)> = Vec::new();
        let mut values = Vec::with_capacity(window.len());
        let mut next = 0usize;

        for glyph in window {
            let known = assignments
                .iter()
                .find(|(assigned_glyph, _signature)| assigned_glyph == glyph)
                .map(|(_assigned_glyph, signature)| *signature);
            if let Some(signature) = known {
                values.push(signature);
            } else {
                assignments.push((*glyph, next));
                values.push(next);
                next += 1;
            }
        }

        Self { values }
    }

    fn has_repeated_symbol(&self) -> bool {
        let mut seen = Vec::new();
        for value in &self.values {
            if seen.contains(value) {
                return true;
            }
            seen.push(*value);
        }
        false
    }

    fn render(&self) -> String {
        self.values
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SignatureGroup {
    signature: PatternSignature,
    occurrences: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct IsomorphDetection {
    informative_windows: usize,
    groups: Vec<SignatureGroup>,
    period_signals: Vec<PeriodSignal>,
}

impl IsomorphDetection {
    fn repeated_signature_kinds(&self) -> usize {
        self.groups.len()
    }

    fn period_matches(&self, period: usize) -> usize {
        self.period_signals
            .iter()
            .find(|signal| signal.period == period)
            .map_or(0, |signal| signal.matches)
    }

    fn best_period(&self) -> Option<PeriodSignal> {
        self.period_signals
            .iter()
            .copied()
            .max_by_key(|signal| (signal.matches, signal.signature_kinds))
    }

    fn strongest_signatures(&self, expected_period: usize) -> Vec<SignatureSummary> {
        let mut groups = self
            .groups
            .iter()
            .map(|group| {
                (
                    signature_period_matches(group, expected_period),
                    group.occurrences.len(),
                    group,
                )
            })
            .filter(|(matches, _occurrences, _group)| *matches > 0)
            .collect::<Vec<_>>();
        groups.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| right.1.cmp(&left.1)));
        groups
            .into_iter()
            .take(3)
            .map(
                |(expected_period_matches, _occurrences, group)| SignatureSummary {
                    signature: group.signature.render(),
                    occurrences: group.occurrences.clone(),
                    expected_period_matches,
                },
            )
            .collect()
    }
}

fn detect_isomorphs(
    label: &'static str,
    seq: &[Glyph],
    window: usize,
) -> Result<IsomorphDetection, ControlsError> {
    if window == 0 || window > seq.len() {
        return Err(ControlsError::InvalidIsomorphWindow {
            label,
            window,
            sequence_len: seq.len(),
        });
    }
    if ISOMORPH_MIN_PERIOD > ISOMORPH_MAX_PERIOD {
        return Err(ControlsError::InvalidPeriodSearch {
            label,
            min_period: ISOMORPH_MIN_PERIOD,
            max_period: ISOMORPH_MAX_PERIOD,
        });
    }

    let mut signature_positions: BTreeMap<PatternSignature, Vec<usize>> = BTreeMap::new();
    let mut informative_windows = 0usize;
    for (position, glyph_window) in seq.windows(window).enumerate() {
        let signature = PatternSignature::from_window(glyph_window);
        if signature.has_repeated_symbol() {
            informative_windows += 1;
            signature_positions
                .entry(signature)
                .or_default()
                .push(position);
        }
    }

    let groups = signature_positions
        .into_iter()
        .filter(|(_signature, occurrences)| occurrences.len() > 1)
        .map(|(signature, occurrences)| SignatureGroup {
            signature,
            occurrences,
        })
        .collect::<Vec<_>>();
    let mut period_signals = Vec::new();
    for period in ISOMORPH_MIN_PERIOD..=ISOMORPH_MAX_PERIOD {
        let mut matches = 0usize;
        let mut signature_kinds = 0usize;
        for group in &groups {
            let group_matches = signature_period_matches(group, period);
            if group_matches > 0 {
                matches += group_matches;
                signature_kinds += 1;
            }
        }
        if matches > 0 {
            period_signals.push(PeriodSignal {
                period,
                matches,
                signature_kinds,
            });
        }
    }

    Ok(IsomorphDetection {
        informative_windows,
        groups,
        period_signals,
    })
}

fn signature_period_matches(group: &SignatureGroup, period: usize) -> usize {
    group
        .occurrences
        .iter()
        .filter(|position| {
            position
                .checked_add(period)
                .is_some_and(|target| group.occurrences.binary_search(&target).is_ok())
        })
        .count()
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
        ALPHABET_SIZE, ControlsError, ISOMORPH_KEY_PERIOD, IsomorphControlConfig,
        MAX_ABSENT_PERIOD_MATCHES, MIN_PERIOD_MATCH_SEPARATION, MIN_PRESENT_PERIOD_MATCHES,
        MonoalphabeticControlConfig, PatternSignature, SubstitutionKey, balanced_uniform_sequence,
        detect_isomorphs, normalize_plaintext, run_isomorph_control, run_monoalphabetic_control,
        sorted_frequency_counts,
    };
    use crate::analysis;
    use crate::glyph::Glyph;

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

    #[test]
    fn isomorph_control_separates_present_and_absent_structure() {
        let report = run_isomorph_control(IsomorphControlConfig {
            seed: 0x1234_5678_9abc_def0,
        })
        .unwrap();

        assert!(report.vigenere.expected_period_matches >= MIN_PRESENT_PERIOD_MATCHES);
        assert!(report.autokey.expected_period_matches >= MIN_PRESENT_PERIOD_MATCHES);
        assert!(report.running_key.expected_period_matches <= MAX_ABSENT_PERIOD_MATCHES);
        assert!(
            report.vigenere.expected_period_matches
                >= report.running_key.expected_period_matches + MIN_PERIOD_MATCH_SEPARATION
        );
        assert!(
            report.autokey.expected_period_matches
                >= report.running_key.expected_period_matches + MIN_PERIOD_MATCH_SEPARATION
        );
        assert_eq!(report.vigenere.expected_period, ISOMORPH_KEY_PERIOD);
        assert_eq!(report.autokey.expected_period, ISOMORPH_KEY_PERIOD);
    }

    #[test]
    fn isomorph_control_is_deterministic_for_seed() {
        let first = run_isomorph_control(IsomorphControlConfig { seed: 0xf00d }).unwrap();
        let second = run_isomorph_control(IsomorphControlConfig { seed: 0xf00d }).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn signature_detector_finds_repeated_relative_pattern_period() {
        let period = [0, 1, 2, 0, 3, 4, 0]
            .iter()
            .copied()
            .map(Glyph)
            .collect::<Vec<_>>();
        let mut seq = Vec::new();
        for index in 0..140 {
            seq.push(period.get(index % period.len()).copied().unwrap());
        }

        let detection = detect_isomorphs("test", &seq, 9).unwrap();

        assert_eq!(detection.period_matches(7), 125);
        assert_eq!(detection.period_matches(6), 0);
    }

    #[test]
    fn pattern_signature_uses_first_occurrence_shape() {
        let abcab =
            PatternSignature::from_window(&[Glyph(0), Glyph(1), Glyph(2), Glyph(0), Glyph(1)]);
        let xyzxy =
            PatternSignature::from_window(&[Glyph(23), Glyph(24), Glyph(25), Glyph(23), Glyph(24)]);

        assert_eq!(abcab, xyzxy);
        assert_eq!(abcab.render(), "0,1,2,0,1");
    }
}

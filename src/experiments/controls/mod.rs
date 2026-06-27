//! Experiment 11 — positive controls for solved cipher types.
//!
//! This module calibrates the workbench against a cipher class whose behavior
//! is known in advance. The monoalphabetic control is deliberately a generated
//! fixture: a known English-like plaintext is encrypted with a deterministic
//! one-to-one substitution key produced by the in-crate [`crate::nulls::null::SplitMix64`]
//! PRNG. That proves the frequency and substitution tooling fires on a
//! monoalphabetic cipher with ground truth.
//!
//! The isomorph/polyalphabetic control is also generated: English prose
//! containing a phrase repeated at offsets aligned to the Vigenere key period is
//! encrypted three ways. A short repeating-key Vigenere fixture is the
//! known-present period case, while autokey and full-length running-key fixtures
//! over the same plaintext are known-absent short-period contrasts. The planted
//! repeats are held constant, so the contrast tests whether the
//! first-occurrence signature detector recovers the period when period-aligned
//! repeats exist and stays quiet when the same repeats are encrypted without a
//! short repeating key.
//!
//! The documented Common Glyphs plaintexts are included only as named
//! round-trip vectors. Their upstream glyph-pixel mapping is not vendored here,
//! and the phrases are too short for honest frequency-only recovery claims.
//! Passing this control says nothing about whether the unsolved eye glyphs
//! encode a recoverable message.

use crate::analysis::analysis;

pub use crate::analysis::isomorph::{PeriodSignal, SignatureSummary};

mod crypto;
mod error;
mod report;
#[cfg(test)]
mod tests;

use crypto::{
    SubstitutionKey, assert_isomorph_separation, assert_regime_separation,
    balanced_uniform_sequence, build_fixture, build_isomorph_fixture, encrypt_autokey,
    encrypt_key_stream, encrypt_vigenere, normalize_plaintext, random_distinct_glyphs,
    random_key_stream, render_key,
};
#[cfg(test)]
use crypto::{detect_isomorphs, sorted_frequency_counts};
pub use error::ControlsError;

const ENGLISH_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ALPHABET_SIZE: usize = 26;
/// Default seed for the monoalphabetic positive-control fixture.
pub const DEFAULT_MONOALPHABETIC_SEED: u64 = 0x6d6f_6e6f_616c_7068;
/// Default seed for the isomorph/polyalphabetic positive-control fixtures.
pub const DEFAULT_ISOMORPH_SEED: u64 = 0x6973_6f6d_6f72_7068;
const U64_DRAW_DOMAIN: u128 = 1u128 << 64;
const MIN_IOC_SEPARATION: f64 = 0.015;
const ISOMORPH_KEY_PERIOD: usize = 7;
const ISOMORPH_AUTOKEY_SEED_LENGTH: usize = 43;
const ISOMORPH_WINDOW: usize = 16;
const ISOMORPH_MIN_PERIOD: usize = 2;
const ISOMORPH_MAX_PERIOD: usize = 16;
const MIN_PRESENT_PERIOD_MATCHES: usize = 850;
const MAX_ABSENT_PERIOD_MATCHES: usize = 64;
const MIN_PERIOD_MATCH_SEPARATION: usize = 800;
const LONG_FIXTURE_LABEL: &str = "embedded English-like calibration plaintext";
const LONG_FIXTURE_TEXT: &str = "\
THE METHOD CHECKS THE KNOWN CIPHER BEFORE IT JUDGES THE UNKNOWN MESSAGE.
A SIMPLE SUBSTITUTION CHANGES LETTER NAMES BUT IT DOES NOT CHANGE HOW OFTEN
EACH LETTER OCCURS. THE SAME TOOL SHOULD NOTICE THAT THE CIPHER TEXT KEEPS
THE SAME COINCIDENCE RATE AND THE SAME BAG OF COUNTS. WHEN THE SAMPLE IS LONG
ENOUGH THE ENGLISH FREQUENCY SHAPE STANDS ABOVE A UNIFORM STREAM. THAT IS THE
ONLY CLAIM OF THIS CONTROL. IT CALIBRATES THE MEASUREMENT PATH AND IT DOES NOT
SAY THAT THE EYE GLYPHS CONTAIN A RECOVERABLE SENTENCE.";
const ISOMORPH_FIXTURE_LABEL: &str = "English prose with period-aligned repeated phrase";
// The recurring phrase below starts only at normalized letter offsets that are
// multiples of the 7-symbol Vigenere period. That planted Kasiski signal is
// held constant across Vigenere/autokey/running-key fixtures, so the contrast
// isolates key structure rather than plaintext content.
const ISOMORPH_FIXTURE_TEXT: &str = "\
THE METHOD CHECKS THE KNOWN CIPHER BEFORE IT JUDGES THE UNKNOWN MESSAGE.
A SIMPLE SUBSTITUTION CHANGES LETTER NAMES BUT IT DOES NOT CHANGE HOW OFTEN
EACH LETTER OCCURS. THE SAME TOOL SHOULD NOTICE THAT THE CIPHER TEXT KEEPS
THE SAME COINCIDENCE RATE AND THE SAME BAG OF COUNTS. WHEN THE SAMPLE IS LONG
ENOUGH THE ENGLISH FREQUENCY SHAPE STANDS ABOVE A UNIFORM STREAM. THAT IS THE
ONLY CLAIM OF THIS CONTROL. IT CALIBRATES THE MEASUREMENT PATH AND IT DOES NOT
SAY THAT THE EYE GLYPHS CONTAIN A RECOVERABLE SENTENCE.

CAREFUL MEASUREMENT KEEPS THE RECORD HONEST. THE CLERK WRITES THE DATE AND
CHECKS THE MARGIN BEFORE THE NEXT LINE BEGINS TODAY.
CAREFUL MEASUREMENT KEEPS THE RECORD HONEST. A SECOND NOTE DESCRIBES THE
SOURCE, THE COPY, AND THE REASON FOR KEEPING BOTH TODAY.
CAREFUL MEASUREMENT KEEPS THE RECORD HONEST. NO SYMBOL IS TRUSTED UNTIL
ANOTHER READER HAS COMPARED IT WITH THE RECORD NEARBY.
CAREFUL MEASUREMENT KEEPS THE RECORD HONEST. THE TABLE BESIDE THE DESK HOLDS
PENS, PAPER, AND A SMALL LAMP FOR EVENING WORK TODAY.
CAREFUL MEASUREMENT KEEPS THE RECORD HONEST. THIS PARAGRAPH IS PLAIN ENGLISH
PROSE WITH UNEVEN WORDS AND ORDINARY CADENCE AS WRITTEN.
CAREFUL MEASUREMENT KEEPS THE RECORD HONEST. EVERY EXAMPLE IS MEANT TO BE
USEFUL, MODEST, AND EASY TO AUDIT LATER NEARBY.
CAREFUL MEASUREMENT KEEPS THE RECORD HONEST. THE SURROUNDING SENTENCES ARE NOT
REPEATED, AND THEY CARRY THE PASSAGE FORWARD STEADILY.
CAREFUL MEASUREMENT KEEPS THE RECORD HONEST. NOTHING IN THIS CONTROL CLAIMS
ANYTHING ABOUT A HIDDEN MESSAGE IN THE GLYPHS THROUGHOUT.
CAREFUL MEASUREMENT KEEPS THE RECORD HONEST.

THE FINAL SENTENCES CLOSE THE FIXTURE WITHOUT REPEATING THE CALIBRATION PHRASE
AGAIN. THEY REMIND THE READER THAT THE CONTRAST IS BETWEEN A REPEATING KEY AND
TWO APERIODIC KEYS, NOT BETWEEN SOLVED AND UNSOLVED GLYPH TEXT.";
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
    /// Short period checked for this fixture: present for Vigenere, absent for
    /// autokey and running-key contrasts.
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
    /// Ground-truth short period encoded in the known-present Vigenere fixture.
    pub expected_period: usize,
    /// Minimum repeated-signature matches required for the known-present
    /// Vigenere fixture.
    pub required_present_matches: usize,
    /// Maximum repeated-signature matches allowed for each known-absent fixture
    /// at any searched period.
    pub allowed_absent_matches: usize,
    /// Known-present Vigenere fixture.
    pub vigenere: IsomorphFixtureReport,
    /// Known-absent autokey fixture.
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
/// The known-present fixture encrypts English prose containing a phrase
/// repeated at offsets aligned to the 7-symbol key period with a short Vigenere
/// key. Known-absent contrast fixtures encrypt the same plaintext with autokey
/// and a full-length running key, removing the short repeating-key ground
/// truth while keeping the planted repeats unchanged. This tests period
/// recovery when Kasiski hooks exist, not detector sensitivity on arbitrary
/// prose.
///
/// # Errors
/// Returns [`ControlsError`] if fixture generation fails or if the detector
/// cannot separate known-present from known-absent structure. Such an error
/// means the isomorph calibration methodology is suspect.
pub fn run_isomorph_control(
    config: IsomorphControlConfig,
) -> Result<IsomorphControlReport, ControlsError> {
    let plaintext = normalize_plaintext(ISOMORPH_FIXTURE_LABEL, ISOMORPH_FIXTURE_TEXT)?;

    let vigenere_key = random_distinct_glyphs(
        "Vigenere short key",
        config.seed ^ 0x7669_6765_6e65_7265,
        ISOMORPH_KEY_PERIOD,
    )?;
    let vigenere_ciphertext =
        encrypt_vigenere("Vigenere known-present", &plaintext, &vigenere_key)?;
    let vigenere = build_isomorph_fixture(
        "known-present Vigenere repeating-key fixture",
        "Vigenere",
        format!(
            "period-{} key {}",
            vigenere_key.len(),
            render_key(&vigenere_key)?
        ),
        &plaintext,
        &vigenere_ciphertext,
        ISOMORPH_KEY_PERIOD,
    )?;

    let autokey_seed = random_key_stream(
        "autokey seed",
        config.seed ^ 0x6175_746f_6b65_7921,
        ISOMORPH_AUTOKEY_SEED_LENGTH,
    )?;
    let autokey_ciphertext = encrypt_autokey("autokey known-absent", &plaintext, &autokey_seed)?;
    let autokey = build_isomorph_fixture(
        "known-absent autokey short-seed fixture",
        "autokey",
        format!(
            "{}-symbol seed {}",
            autokey_seed.len(),
            render_key(&autokey_seed)?
        ),
        &plaintext,
        &autokey_ciphertext,
        ISOMORPH_KEY_PERIOD,
    )?;

    let running_key = random_key_stream(
        "running-key contrast key",
        config.seed ^ 0x7275_6e6e_696e_6721,
        plaintext.len(),
    )?;
    let running_ciphertext =
        encrypt_key_stream("running-key known-absent", &plaintext, &running_key)?;
    let running_key = build_isomorph_fixture(
        "known-absent full-length running-key fixture",
        "running key",
        format!("{}-symbol full-length key stream", running_ciphertext.len()),
        &plaintext,
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

//! Experiment 11 — positive controls for solved cipher types.
//!
//! This module calibrates the workbench against a cipher class whose behavior
//! is known in advance. The monoalphabetic control is deliberately a generated
//! fixture: a known English-like plaintext is encrypted with a deterministic
//! one-to-one substitution key produced by the in-crate [`crate::null::SplitMix64`]
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

use std::fmt;

use crate::analysis;
use crate::glyph::Glyph;
use crate::isomorph::{self, IsomorphError};
use crate::null::SplitMix64;
use crate::report::{self, Report};

pub use crate::isomorph::{PeriodSignal, SignatureSummary};

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
    /// A known-present fixture's strongest period was not the ground-truth
    /// key period.
    IsomorphPeriodRecoveryFailed {
        /// Human-readable fixture label.
        label: &'static str,
        /// Ground-truth short period.
        expected_period: usize,
        /// Strongest period observed by the detector.
        observed_period: Option<usize>,
        /// Repeated-signature matches for the strongest observed period.
        observed_matches: usize,
    },
    /// A known-absent fixture produced too much short-period signal.
    IsomorphFalsePositive {
        /// Human-readable fixture label.
        label: &'static str,
        /// Strongest short period observed by the detector.
        observed_period: usize,
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

impl fmt::Display for ControlsError {
    #[allow(
        clippy::too_many_lines,
        reason = "byte-identical Display for a large CLI error enum is clearest as one match"
    )]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPlaintext { label } => write!(f, "{label}: normalized plaintext is empty"),
            Self::UnsupportedPlaintextSymbol { label, symbol } => {
                write!(f, "{label}: unsupported plaintext symbol {symbol:?}")
            }
            Self::GlyphOutsideAlphabet {
                label,
                glyph,
                alphabet_size,
            } => write!(
                f,
                "{label}: glyph {glyph} is outside alphabet size {alphabet_size}"
            ),
            Self::AlphabetTooLarge { alphabet_size } => {
                write!(
                    f,
                    "alphabet size {alphabet_size} is too large for this control"
                )
            }
            Self::NonBijectiveKey {
                seed,
                alphabet_size,
            } => write!(
                f,
                "seed {seed} did not produce a bijection over alphabet size {alphabet_size}"
            ),
            Self::IocNotPreserved {
                label,
                plaintext_bits,
                ciphertext_bits,
            } => write!(
                f,
                "{label}: IoC changed across substitution ({plaintext_bits:#x} != {ciphertext_bits:#x})"
            ),
            Self::FrequencyMultisetChanged { label } => {
                write!(
                    f,
                    "{label}: frequency-count multiset changed across substitution"
                )
            }
            Self::BigramMultisetChanged { label } => {
                write!(
                    f,
                    "{label}: bigram-count multiset changed across substitution"
                )
            }
            Self::KnownKeyRecoveryFailed { label } => {
                write!(
                    f,
                    "{label}: known-key inverse did not recover the plaintext"
                )
            }
            Self::RegimeSeparationFailed {
                label,
                plaintext_ioc,
                flattened_ioc,
                uniform_floor,
            } => write!(
                f,
                "{label}: IoC did not separate regimes (plain {plaintext_ioc:.6}, balanced uniform {flattened_ioc:.6}, floor {uniform_floor:.6})"
            ),
            Self::InvalidIsomorphWindow {
                label,
                window,
                sequence_len,
            } => write!(
                f,
                "{label}: invalid isomorph window {window} for sequence length {sequence_len}"
            ),
            Self::InvalidPeriodSearch {
                label,
                min_period,
                max_period,
            } => write!(
                f,
                "{label}: invalid isomorph period search {min_period}..={max_period}"
            ),
            Self::IsomorphSignalMissing {
                label,
                expected_period,
                observed_matches,
                required_matches,
            } => write!(
                f,
                "{label}: expected period {expected_period} produced {observed_matches} signature matches, below required {required_matches}"
            ),
            Self::IsomorphPeriodRecoveryFailed {
                label,
                expected_period,
                observed_period,
                observed_matches,
            } => {
                let observed =
                    observed_period.map_or_else(|| "none".to_owned(), |period| period.to_string());
                write!(
                    f,
                    "{label}: strongest recovered period was {observed} with {observed_matches} signature matches, expected {expected_period}"
                )
            }
            Self::IsomorphFalsePositive {
                label,
                observed_period,
                observed_matches,
                allowed_matches,
            } => write!(
                f,
                "{label}: expected-absent period signal {observed_period} produced {observed_matches} signature matches, above allowed {allowed_matches}"
            ),
            Self::IsomorphSeparationFailed {
                present_label,
                absent_label,
                present_matches,
                absent_matches,
                required_gap,
            } => write!(
                f,
                "{present_label}: signature-period separation from {absent_label} was {present_matches} vs {absent_matches}, below required gap {required_gap}"
            ),
        }
    }
}

impl std::error::Error for ControlsError {}

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

impl Report for MonoalphabeticControlReport {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(&mut out, "Experiment 11 monoalphabetic positive control");
        report::appendln!(&mut out, "seed: {}", self.config.seed);
        report::appendln!(
            &mut out,
            "alphabet: {} symbols ({})",
            self.alphabet_size,
            self.alphabet
        );
        report::appendln!(&mut out, "generated key: {}", self.key_mapping);
        report::appendln!(&mut out);
        report::appendln!(
            &mut out,
            "long fixture: {} letters from {}",
            self.long_fixture.length,
            self.long_fixture.label
        );
        report::appendln!(
            &mut out,
            "plaintext:  {}",
            report::preview_text(&self.long_fixture.normalized_plaintext, 96)
        );
        report::appendln!(
            &mut out,
            "ciphertext: {}",
            report::preview_text(&self.long_fixture.ciphertext, 96)
        );
        report::appendln!(
            &mut out,
            "recovered:  {}",
            report::preview_text(&self.long_fixture.recovered_plaintext, 96)
        );
        report::appendln!(&mut out);
        report::appendln!(
            &mut out,
            "IoC plaintext/ciphertext: {:.6} / {:.6} (exactly preserved)",
            self.long_fixture.plaintext_ioc,
            self.long_fixture.ciphertext_ioc
        );
        report::appendln!(
            &mut out,
            "IoC balanced uniform: {:.6}; uniform floor 1/k: {:.6}",
            self.flattened_ioc,
            self.uniform_floor
        );
        report::appendln!(
            &mut out,
            "entropy plaintext/ciphertext/balanced uniform: {:.4} / {:.4} / {:.4} bits/symbol",
            self.long_fixture.plaintext_entropy,
            self.long_fixture.ciphertext_entropy,
            self.flattened_entropy
        );
        report::appendln!(
            &mut out,
            "frequency multiset preserved: {}",
            report::yes_no(self.long_fixture.frequency_multiset_preserved)
        );
        report::appendln!(
            &mut out,
            "bigram count multiset preserved: {}",
            report::yes_no(self.long_fixture.bigram_multiset_preserved)
        );
        report::appendln!(
            &mut out,
            "known-key recovery: {}",
            report::yes_no(self.long_fixture.known_key_recovered)
        );
        report::appendln!(&mut out);
        report::appendln!(
            &mut out,
            "documented Common Glyphs plaintext vectors (known-key exactness only):"
        );
        for fixture in &self.documented_vectors {
            report::appendln!(
                &mut out,
                "  {}: {:?} -> {} -> {}",
                fixture.label,
                fixture.source_plaintext,
                fixture.ciphertext,
                fixture.recovered_plaintext
            );
        }
        report::appendln!(&mut out);
        report::appendln!(
            &mut out,
            "Interpretation: this proves the frequency/substitution tooling is not systematically blind to a known monoalphabetic substitution fixture. It does not claim frequency-only recovery of the short Common Glyphs phrases, and it says nothing about whether the unsolved eye glyphs encode a message. If this control fails, the methodology is suspect."
        );
        out
    }
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

impl Report for IsomorphControlReport {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(
            &mut out,
            "Experiment 11 isomorph/polyalphabetic positive control"
        );
        report::appendln!(&mut out, "seed: {}", self.config.seed);
        report::appendln!(
            &mut out,
            "alphabet: {} symbols ({})",
            self.alphabet_size,
            self.alphabet
        );
        report::appendln!(
            &mut out,
            "detector: first-occurrence signatures over {}-glyph windows; periods {}..={}",
            self.window,
            self.min_period,
            self.max_period
        );
        report::appendln!(
            &mut out,
            "ground truth: plaintext has period-aligned planted repeats; Vigenere key period is {}; autokey and running-key have no short repeating key",
            self.expected_period
        );
        report::appendln!(
            &mut out,
            "invariant: Vigenere period matches >= {}; each absent fixture max period matches <= {}",
            self.required_present_matches,
            self.allowed_absent_matches
        );
        report::appendln!(&mut out);
        append_isomorph_fixture(&mut out, &self.vigenere);
        report::appendln!(&mut out);
        append_isomorph_fixture(&mut out, &self.autokey);
        report::appendln!(&mut out);
        append_isomorph_fixture(&mut out, &self.running_key);
        report::appendln!(&mut out);
        report::appendln!(
            &mut out,
            "Interpretation: this control shows the isomorph/period tooling recovers the repeating-key Vigenere period when English prose contains period-aligned planted repeats. The autokey and running-key fixtures use the same planted repeats but do not show a short period, so the contrast isolates key structure rather than plaintext content. It does not claim arbitrary natural text would produce this signal, and it says nothing about whether the unsolved eye glyphs encode a message. If this control fails, the methodology is suspect."
        );
        out
    }
}

fn append_isomorph_fixture(out: &mut String, fixture: &IsomorphFixtureReport) {
    report::appendln!(out, "{} ({})", fixture.label, fixture.cipher);
    report::appendln!(out, "key: {}", fixture.key_summary);
    report::appendln!(out, "length: {} glyphs", fixture.length);
    report::appendln!(
        out,
        "plaintext:  {}",
        report::preview_text(&fixture.plaintext, 84)
    );
    report::appendln!(
        out,
        "ciphertext: {}",
        report::preview_text(&fixture.ciphertext, 84)
    );
    report::appendln!(
        out,
        "cipher entropy/IoC/distinct: {:.4} bits / {:.6} / {}",
        fixture.ciphertext_entropy,
        fixture.ciphertext_ioc,
        fixture.distinct_cipher_symbols
    );
    report::appendln!(out, "plaintext IoC: {:.6}", fixture.plaintext_ioc);
    report::appendln!(
        out,
        "informative windows: {}; repeated signature kinds: {}; exact repeated windows: {}",
        fixture.informative_windows,
        fixture.repeated_signature_kinds,
        fixture.exact_repeated_windows
    );
    report::appendln!(
        out,
        "period-{} signature matches: {}",
        fixture.expected_period,
        fixture.expected_period_matches
    );
    match fixture.best_period {
        Some(signal) => report::appendln!(
            out,
            "best period: {} ({} matches across {} signatures)",
            signal.period,
            signal.matches,
            signal.signature_kinds
        ),
        None => report::appendln!(out, "best period: none"),
    }
    if !fixture.strongest_signatures.is_empty() {
        report::appendln!(out, "top period-{} signatures:", fixture.expected_period);
        for signature in &fixture.strongest_signatures {
            report::appendln!(
                out,
                "  [{}] at {} ({} period matches)",
                signature.signature,
                report::format_positions(&signature.occurrences),
                signature.expected_period_matches
            );
        }
    }
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

fn detect_isomorphs(
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
        MonoalphabeticControlConfig, SubstitutionKey, balanced_uniform_sequence, detect_isomorphs,
        normalize_plaintext, run_isomorph_control, run_monoalphabetic_control,
        sorted_frequency_counts,
    };
    use crate::analysis;
    use crate::glyph::Glyph;
    use crate::isomorph::PatternSignature;

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
        for seed in [0x6973_6f6d_6f72_7068, 0x1234_5678_9abc_def0, 0xf00d, 0] {
            let report = run_isomorph_control(IsomorphControlConfig { seed }).unwrap();

            assert_eq!(report.vigenere.length, 1496);
            assert!(report.vigenere.expected_period_matches >= MIN_PRESENT_PERIOD_MATCHES);
            assert_eq!(
                report.vigenere.best_period.map(|signal| signal.period),
                Some(ISOMORPH_KEY_PERIOD)
            );

            for absent in [&report.autokey, &report.running_key] {
                let absent_max_matches = absent.best_period.map_or(0, |signal| signal.matches);
                assert!(absent_max_matches <= MAX_ABSENT_PERIOD_MATCHES);
                assert!(
                    report.vigenere.expected_period_matches
                        >= absent_max_matches + MIN_PERIOD_MATCH_SEPARATION
                );
            }
        }
    }

    #[test]
    fn isomorph_control_is_deterministic_for_seed() {
        let first = run_isomorph_control(IsomorphControlConfig { seed: 0xf00d }).unwrap();
        let second = run_isomorph_control(IsomorphControlConfig { seed: 0xf00d }).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn isomorph_control_default_seed_numbers_are_anchored() {
        let report = run_isomorph_control(IsomorphControlConfig::default()).unwrap();

        assert_eq!(report.vigenere.informative_windows, 1480);
        assert_eq!(report.vigenere.repeated_signature_kinds, 49);
        assert_eq!(report.vigenere.exact_repeated_windows, 38);
        assert_eq!(report.vigenere.expected_period_matches, 923);
        assert_eq!(
            report.vigenere.best_period.map(|signal| signal.period),
            Some(7)
        );
        assert_eq!(
            report.vigenere.best_period.map(|signal| signal.matches),
            Some(923)
        );
        assert_eq!(
            report
                .vigenere
                .best_period
                .map(|signal| signal.signature_kinds),
            Some(44)
        );

        assert_eq!(report.autokey.informative_windows, 1479);
        assert_eq!(report.autokey.repeated_signature_kinds, 16);
        assert_eq!(report.autokey.exact_repeated_windows, 0);
        assert_eq!(report.autokey.expected_period_matches, 7);
        assert_eq!(
            report.autokey.best_period.map(|signal| signal.period),
            Some(2)
        );
        assert_eq!(
            report.autokey.best_period.map(|signal| signal.matches),
            Some(11)
        );
        assert_eq!(
            report
                .autokey
                .best_period
                .map(|signal| signal.signature_kinds),
            Some(7)
        );

        assert_eq!(report.running_key.informative_windows, 1479);
        assert_eq!(report.running_key.repeated_signature_kinds, 15);
        assert_eq!(report.running_key.exact_repeated_windows, 0);
        assert_eq!(report.running_key.expected_period_matches, 2);
        assert_eq!(
            report.running_key.best_period.map(|signal| signal.period),
            Some(2)
        );
        assert_eq!(
            report.running_key.best_period.map(|signal| signal.matches),
            Some(10)
        );
        assert_eq!(
            report
                .running_key
                .best_period
                .map(|signal| signal.signature_kinds),
            Some(10)
        );
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

        assert_eq!(detection.best_period().map(|signal| signal.period), Some(7));
        assert!(detection.period_matches(7) > detection.period_matches(6));
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

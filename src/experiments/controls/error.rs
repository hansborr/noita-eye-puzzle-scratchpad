//! Error type for the Experiment 11 positive controls.

use std::fmt;

use crate::core::glyph::Glyph;

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

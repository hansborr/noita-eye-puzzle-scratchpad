//! Error type for Lymm deck-cipher oracle and corpus plumbing.

use std::fmt;

use crate::ciphers::CipherError;

/// Error returned by Lymm deck-cipher helpers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LymmDeckError {
    /// A reused permutation validator rejected a permutation.
    Cipher(CipherError),
    /// The deck size was too small for a top-card deck cipher.
    DeckTooSmall {
        /// Requested deck size.
        n: usize,
    },
    /// An alphabet had the wrong length for its role.
    AlphabetLength {
        /// Alphabet name.
        alphabet: &'static str,
        /// Observed number of characters.
        len: usize,
        /// Required number of characters.
        expected: usize,
    },
    /// An alphabet repeated a character.
    DuplicateAlphabetChar {
        /// Alphabet name.
        alphabet: &'static str,
        /// Repeated character.
        ch: char,
    },
    /// The configured emit index was outside the deck.
    EmitIndexOutOfRange {
        /// Requested emit index.
        emit_index: usize,
        /// Deck size.
        n: usize,
    },
    /// A plaintext letter did not have a supplied permutation.
    MissingPlaintextMapping {
        /// Plaintext letter.
        letter: char,
    },
    /// The planted mapping cannot satisfy no-doubles with this alphabet/deck.
    TooManyPlaintextLetters {
        /// Requested plaintext alphabet length.
        requested: usize,
        /// Available nonzero top-card images.
        available: usize,
    },
    /// A planted letter exceeded the retry cap used by Lymm's generator.
    PlantAttemptsExceeded {
        /// Plaintext letter being generated.
        letter: char,
        /// Number of attempts tried.
        attempts: usize,
    },
    /// A random draw bound was zero or too large.
    RandomBoundTooLarge {
        /// Requested exclusive upper bound.
        bound: usize,
    },
    /// A labeled corpus line was malformed.
    CorpusLine {
        /// 1-based line number.
        line: usize,
        /// Short diagnostic.
        reason: &'static str,
    },
    /// The same label appeared more than once in one corpus file.
    DuplicateLabel {
        /// Repeated label.
        label: String,
    },
    /// A ciphertext label was absent from the plaintext file.
    UnexpectedCiphertextLabel {
        /// Extra ciphertext label.
        label: String,
    },
    /// A plaintext label did not have a matching ciphertext.
    MissingCiphertextLabel {
        /// Missing label.
        label: String,
    },
    /// A plaintext/ciphertext pair has different symbol counts.
    MessageLengthMismatch {
        /// Message label.
        label: String,
        /// Count of plaintext-alphabet characters.
        plaintext_alpha_chars: usize,
        /// Count of ciphertext characters.
        ciphertext_chars: usize,
    },
}

impl fmt::Display for LymmDeckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cipher(error) => write!(f, "Lymm deck permutation error: {error}"),
            Self::DeckTooSmall { n } => write!(f, "deck size n={n} is too small"),
            Self::AlphabetLength {
                alphabet,
                len,
                expected,
            } => write!(
                f,
                "{alphabet} alphabet has {len} characters, expected {expected}"
            ),
            Self::DuplicateAlphabetChar { alphabet, ch } => {
                write!(f, "{alphabet} alphabet repeats character {ch:?}")
            }
            Self::EmitIndexOutOfRange { emit_index, n } => {
                write!(f, "emit index {emit_index} is outside deck size {n}")
            }
            Self::MissingPlaintextMapping { letter } => {
                write!(f, "missing plaintext mapping for {letter:?}")
            }
            Self::TooManyPlaintextLetters {
                requested,
                available,
            } => write!(
                f,
                "requested {requested} plaintext letters but only {available} nonzero top-card images are available"
            ),
            Self::PlantAttemptsExceeded { letter, attempts } => write!(
                f,
                "failed to plant reversible mapping for {letter:?} after {attempts} attempts"
            ),
            Self::RandomBoundTooLarge { bound } => {
                write!(f, "random draw bound {bound} is invalid")
            }
            Self::CorpusLine { line, reason } => {
                write!(f, "malformed Lymm corpus line {line}: {reason}")
            }
            Self::DuplicateLabel { label } => write!(f, "duplicate corpus label {label:?}"),
            Self::UnexpectedCiphertextLabel { label } => {
                write!(f, "ciphertext has unexpected label {label:?}")
            }
            Self::MissingCiphertextLabel { label } => {
                write!(f, "plaintext label {label:?} has no ciphertext")
            }
            Self::MessageLengthMismatch {
                label,
                plaintext_alpha_chars,
                ciphertext_chars,
            } => write!(
                f,
                "message {label:?} has {plaintext_alpha_chars} plaintext alphabet characters but {ciphertext_chars} ciphertext characters"
            ),
        }
    }
}

impl std::error::Error for LymmDeckError {}

impl From<CipherError> for LymmDeckError {
    fn from(value: CipherError) -> Self {
        Self::Cipher(value)
    }
}

impl From<crate::nulls::null::RandomBoundError> for LymmDeckError {
    fn from(value: crate::nulls::null::RandomBoundError) -> Self {
        Self::RandomBoundTooLarge { bound: value.bound }
    }
}

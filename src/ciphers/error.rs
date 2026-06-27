//! Error taxonomy for candidate-cipher construction and translation.
//!
//! `CipherError` is the single error type returned by every cipher key
//! constructor and every free transform in this module's siblings.

use std::fmt;

use crate::core::glyph::Glyph;

/// Error returned by candidate-cipher construction and translation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CipherError {
    /// The alphabet size is outside the range supported by the cipher.
    InvalidAlphabetSize {
        /// Requested alphabet size.
        alphabet_size: usize,
        /// Minimum size accepted by this cipher.
        min: usize,
        /// Maximum size representable by [`Glyph`].
        max: usize,
    },
    /// A Vigenere key was empty, so no periodic shift can be selected.
    EmptyVigenereKey,
    /// A transposition period was empty, so no position block can be permuted.
    InvalidTranspositionPeriod {
        /// Requested block period.
        period: usize,
    },
    /// A plaintext or ciphertext symbol was outside the configured alphabet.
    SymbolOutsideAlphabet {
        /// Offending glyph value.
        symbol: Glyph,
        /// Configured alphabet size.
        alphabet_size: usize,
    },
    /// A permutation key had the wrong number of entries.
    PermutationLengthMismatch {
        /// Human-readable permutation name.
        label: &'static str,
        /// Number of entries supplied.
        len: usize,
        /// Configured alphabet size.
        alphabet_size: usize,
    },
    /// A permutation entry referred to a symbol outside the alphabet.
    PermutationSymbolOutsideAlphabet {
        /// Human-readable permutation name.
        label: &'static str,
        /// Offending symbol.
        symbol: usize,
        /// Configured alphabet size.
        alphabet_size: usize,
    },
    /// A permutation repeated a symbol.
    DuplicatePermutationSymbol {
        /// Human-readable permutation name.
        label: &'static str,
        /// Repeated symbol.
        symbol: usize,
        /// Position where the duplicate was encountered.
        duplicate_index: usize,
    },
    /// A permutation omitted a symbol.
    MissingPermutationSymbol {
        /// Human-readable permutation name.
        label: &'static str,
        /// Missing symbol.
        symbol: usize,
    },
    /// A deck-cipher control card was outside the configured alphabet.
    ControlSymbolOutsideAlphabet {
        /// Offending control symbol.
        symbol: usize,
        /// Configured alphabet size.
        alphabet_size: usize,
    },
    /// The deck-cipher control cards were not distinct.
    DuplicateControlSymbols {
        /// First control symbol.
        control_a: usize,
        /// Second control symbol.
        control_b: usize,
    },
    /// The AGL multiplier was not allowed modulo the prime alphabet size.
    NonUnitMultiplier {
        /// Offending multiplier.
        multiplier: usize,
        /// Prime modulus.
        modulus: usize,
    },
    /// The alphabet size for an AGL key was not prime.
    AlphabetNotPrime {
        /// Requested alphabet size.
        alphabet_size: usize,
    },
    /// The chosen multiplier subgroup was not supported for this alphabet.
    UnsupportedMultiplierSubgroup {
        /// Requested subgroup order.
        order: usize,
    },
    /// A GAK key requested a state size outside the supported range.
    InvalidGakStateSize {
        /// Requested permutation state size `n`.
        state_size: usize,
        /// Minimum size accepted by [`GakKey`](crate::ciphers::GakKey).
        min: usize,
        /// Maximum size representable by [`Glyph`].
        max: usize,
    },
    /// A GAK coset readout did not match the configured state size.
    GakReadoutSizeMismatch {
        /// Human-readable readout context.
        label: &'static str,
        /// Length the readout table actually had.
        len: usize,
        /// State size `n` the readout must cover.
        state_size: usize,
    },
    /// A GAK coset readout referenced a coset outside the ciphertext alphabet.
    GakReadoutCosetOutsideAlphabet {
        /// Offending coset label produced by the readout.
        coset: usize,
        /// Configured ciphertext alphabet size.
        ciphertext_alphabet_size: usize,
    },
    /// A GAK readout reference point was outside the state size.
    GakReferenceOutsideState {
        /// Offending reference point.
        reference_point: usize,
        /// State size `n`.
        state_size: usize,
    },
    /// A GAK key had no plaintext letters, so nothing can be enciphered.
    EmptyGakLetters,
    /// Two GAK plaintext letters land in the same hidden-subgroup coset from
    /// the initial state, so the cipher is not reversible.
    GakLettersShareCoset {
        /// Coset shared by two plaintext letters.
        coset: usize,
        /// Index of the later plaintext letter found in that coset.
        duplicate_index: usize,
    },
    /// A GAK plaintext-letter permutation left the readout coset unchanged from
    /// the initial state while `avoid_doubles` was requested.
    GakLetterFixesCoset {
        /// Index of the offending plaintext letter.
        letter_index: usize,
        /// Coset that was left unchanged.
        coset: usize,
    },
    /// A GAK plaintext-letter permutation violated the requested subgroup
    /// parity constraint (for example an odd permutation under `A_n`).
    GakLetterWrongParity {
        /// Index of the offending plaintext letter.
        letter_index: usize,
    },
    /// A GAK [`CosetReadout::CosetTable`](crate::ciphers::CosetReadout::CosetTable) key is not decrypt-invertible: from
    /// some reachable state two plaintext letters project to the same coset, so
    /// the ciphertext does not determine the plaintext letter.
    ///
    /// The identity-state injectivity check is *not* sufficient for an arbitrary
    /// supplied coset table (a coarser partition can merge points and break the
    /// state-independence the [`CosetReadout::TopCard`](crate::ciphers::CosetReadout::TopCard) proof relies on), so the
    /// constructor enumerates the reachable state set and verifies per-state
    /// injectivity directly.
    GakCosetTableNotInvertible {
        /// A reachable state from which two letters collide, in
        /// `(f ∘ g)[i] = f[g[i]]` form.
        state: Vec<usize>,
        /// The coset both colliding letters project to from that state.
        coset: usize,
        /// Index of the later plaintext letter found in that coset.
        duplicate_index: usize,
    },
    /// A GAK [`CosetReadout::CosetTable`](crate::ciphers::CosetReadout::CosetTable) key generates a state group larger than
    /// the supported enumeration cap, so decrypt-invertibility cannot be checked
    /// by bounded enumeration.
    ///
    /// `CosetTable` is documented as being for explicitly enumerated *small*
    /// groups; supply a smaller generating set or use
    /// [`CosetReadout::TopCard`](crate::ciphers::CosetReadout::TopCard) for the full deck realization instead.
    GakCosetTableGroupTooLarge {
        /// The enumeration cap that was exceeded.
        cap: usize,
    },
    /// A validated permutation state lost an invariant during translation.
    InternalInvariant {
        /// Human-readable invariant context.
        context: &'static str,
    },
}

impl fmt::Display for CipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAlphabetSize {
                alphabet_size,
                min,
                max,
            } => write!(
                f,
                "alphabet size {alphabet_size} is outside supported range {min}..={max}"
            ),
            Self::EmptyVigenereKey => write!(f, "Vigenere key must contain at least one shift"),
            Self::InvalidTranspositionPeriod { period } => {
                write!(f, "transposition period must be nonzero, got {period}")
            }
            Self::SymbolOutsideAlphabet {
                symbol,
                alphabet_size,
            } => write!(
                f,
                "symbol {symbol} is outside alphabet size {alphabet_size}"
            ),
            Self::PermutationLengthMismatch {
                label,
                len,
                alphabet_size,
            } => write!(
                f,
                "{label} permutation length {len} does not match alphabet size {alphabet_size}"
            ),
            Self::PermutationSymbolOutsideAlphabet {
                label,
                symbol,
                alphabet_size,
            } => write!(
                f,
                "{label} permutation symbol {symbol} is outside alphabet size {alphabet_size}"
            ),
            Self::DuplicatePermutationSymbol {
                label,
                symbol,
                duplicate_index,
            } => write!(
                f,
                "{label} permutation repeats symbol {symbol} at position {duplicate_index}"
            ),
            Self::MissingPermutationSymbol { label, symbol } => {
                write!(f, "{label} permutation omits symbol {symbol}")
            }
            Self::ControlSymbolOutsideAlphabet {
                symbol,
                alphabet_size,
            } => write!(
                f,
                "deck control symbol {symbol} is outside alphabet size {alphabet_size}"
            ),
            Self::DuplicateControlSymbols {
                control_a,
                control_b,
            } => write!(
                f,
                "deck control symbols must be distinct, got {control_a} and {control_b}"
            ),
            Self::NonUnitMultiplier {
                multiplier,
                modulus,
            } => write!(
                f,
                "AGL multiplier {multiplier} is not allowed modulo {modulus}"
            ),
            Self::AlphabetNotPrime { alphabet_size } => {
                write!(f, "AGL alphabet size {alphabet_size} is not prime")
            }
            Self::UnsupportedMultiplierSubgroup { order } => {
                write!(f, "AGL multiplier subgroup order {order} is not supported")
            }
            Self::InternalInvariant { context } => {
                write!(f, "internal cipher invariant failed: {context}")
            }
            other => other.fmt_gak(f),
        }
    }
}

impl CipherError {
    /// Formats the GAK-specific [`CipherError`] variants.
    ///
    /// Split out of [`fmt::Display`] so the main formatter stays within the
    /// crate's per-function line ceiling; non-GAK variants are unreachable here.
    fn fmt_gak(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGakStateSize {
                state_size,
                min,
                max,
            } => write!(
                f,
                "GAK state size {state_size} is outside supported range {min}..={max}"
            ),
            Self::GakReadoutSizeMismatch {
                label,
                len,
                state_size,
            } => write!(
                f,
                "{label} readout length {len} does not match GAK state size {state_size}"
            ),
            Self::GakReadoutCosetOutsideAlphabet {
                coset,
                ciphertext_alphabet_size,
            } => write!(
                f,
                "GAK readout coset {coset} is outside ciphertext alphabet size {ciphertext_alphabet_size}"
            ),
            Self::GakReferenceOutsideState {
                reference_point,
                state_size,
            } => write!(
                f,
                "GAK reference point {reference_point} is outside state size {state_size}"
            ),
            Self::EmptyGakLetters => {
                write!(f, "GAK key must contain at least one plaintext letter")
            }
            Self::GakLettersShareCoset {
                coset,
                duplicate_index,
            } => write!(
                f,
                "GAK plaintext letters are not injective on cosets: letter {duplicate_index} reuses coset {coset}"
            ),
            Self::GakLetterFixesCoset {
                letter_index,
                coset,
            } => write!(
                f,
                "GAK letter {letter_index} leaves readout coset {coset} unchanged but avoid_doubles is set"
            ),
            Self::GakLetterWrongParity { letter_index } => write!(
                f,
                "GAK letter {letter_index} violates the requested subgroup parity constraint"
            ),
            Self::GakCosetTableNotInvertible {
                state,
                coset,
                duplicate_index,
            } => write!(
                f,
                "GAK coset-table key is not invertible: from reachable state {state:?} letter {duplicate_index} collides on coset {coset}"
            ),
            Self::GakCosetTableGroupTooLarge { cap } => write!(
                f,
                "GAK coset-table state group exceeds the enumeration cap of {cap} elements"
            ),
            _ => write!(f, "internal cipher invariant failed: unexpected variant"),
        }
    }
}

impl std::error::Error for CipherError {}

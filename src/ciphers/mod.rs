//! Experiment 12 candidate-cipher primitives.
//!
//! The functions in this module operate on opaque [`Glyph`] values interpreted
//! as symbols `0..alphabet_size`. They are deliberately only primitives:
//! scoring, language models, null distributions, and attack harnesses belong to
//! separate experiment code.
//!
//! The additive ciphers combine plaintext and key material by addition modulo
//! `N`. Chaocipher follows the classic two-alphabet dynamic substitution step,
//! generalized from the 26-letter case by placing the nadir at `N / 2`. The
//! deck cipher is a documented `S_N` Solitaire-style simplification: the state
//! is exactly one permutation of the `N` alphabet symbols, with two in-alphabet
//! control cards replacing Pontifex's out-of-alphabet jokers.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::glyph::Glyph;

/// Alphabet size of the accepted eye reading layer, values `0..=82`.
pub const EYE_READING_ALPHABET_SIZE: usize = 83;

const MAX_ALPHABET_SIZE: usize = u16::MAX as usize + 1;

/// Maximum state-group order enumerated when validating a
/// [`CosetReadout::CosetTable`] GAK key for decrypt-invertibility.
///
/// `CosetTable` is for explicitly enumerated *small* groups, so this cap keeps
/// the bounded closure cheap and total; a key whose generated state group
/// exceeds it is rejected with [`CipherError::GakCosetTableGroupTooLarge`]
/// rather than accepted unvalidated or enumerated unboundedly.
const MAX_GAK_COSET_TABLE_GROUP: usize = 4_096;

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
        /// Minimum size accepted by [`GakKey`].
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
    /// A GAK [`CosetReadout::CosetTable`] key is not decrypt-invertible: from
    /// some reachable state two plaintext letters project to the same coset, so
    /// the ciphertext does not determine the plaintext letter.
    ///
    /// The identity-state injectivity check is *not* sufficient for an arbitrary
    /// supplied coset table (a coarser partition can merge points and break the
    /// state-independence the [`CosetReadout::TopCard`] proof relies on), so the
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
    /// A GAK [`CosetReadout::CosetTable`] key generates a state group larger than
    /// the supported enumeration cap, so decrypt-invertibility cannot be checked
    /// by bounded enumeration.
    ///
    /// `CosetTable` is documented as being for explicitly enumerated *small*
    /// groups; supply a smaller generating set or use
    /// [`CosetReadout::TopCard`] for the full deck realization instead.
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

/// Family marker for the no-key identity cipher.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Identity;

/// Key for a route/columnar transposition over positions.
///
/// The key partitions the stream into `period`-sized blocks and assigns each
/// plaintext column a permutation rank. Encryption emits each block's present
/// columns in ascending rank order; decryption places those columns back at
/// their original positions. This permutes positions only and never rewrites
/// symbol values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranspositionKey {
    period: usize,
    permutation: Vec<usize>,
}

impl TranspositionKey {
    /// Builds a transposition key from a period and column-rank permutation.
    ///
    /// # Errors
    /// Returns [`CipherError::InvalidTranspositionPeriod`] for `period == 0`,
    /// or a permutation error if `permutation` is not a permutation of
    /// `0..period`.
    pub fn new(period: usize, permutation: Vec<usize>) -> Result<Self, CipherError> {
        if period == 0 {
            return Err(CipherError::InvalidTranspositionPeriod { period });
        }
        validate_permutation("transposition", &permutation, period)?;
        Ok(Self {
            period,
            permutation,
        })
    }

    /// Returns the block period.
    #[must_use]
    pub const fn period(&self) -> usize {
        self.period
    }

    /// Returns the plaintext-column rank permutation.
    #[must_use]
    pub fn permutation(&self) -> &[usize] {
        &self.permutation
    }
}

/// Key for the Caesar additive shift cipher.
///
/// Encryption adds the single shift to every symbol modulo `N`; decryption
/// subtracts the same shift modulo `N`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaesarKey {
    alphabet_size: usize,
    shift: usize,
}

impl CaesarKey {
    /// Builds a Caesar key, reducing `shift` modulo `alphabet_size`.
    ///
    /// # Errors
    /// Returns [`CipherError::InvalidAlphabetSize`] when the alphabet is empty
    /// or cannot be represented by [`Glyph`].
    pub fn new(alphabet_size: usize, shift: usize) -> Result<Self, CipherError> {
        validate_alphabet_size(alphabet_size, 1)?;
        Ok(Self {
            alphabet_size,
            shift: shift % alphabet_size,
        })
    }

    /// Returns the configured alphabet size.
    #[must_use]
    pub const fn alphabet_size(self) -> usize {
        self.alphabet_size
    }

    /// Returns the normalized additive shift.
    #[must_use]
    pub const fn shift(self) -> usize {
        self.shift
    }
}

/// Key for the periodic additive Vigenere cipher.
///
/// Encryption adds `shifts[i % period]` to symbol `i` modulo `N`; decryption
/// subtracts the same periodic shift.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VigenereKey {
    alphabet_size: usize,
    shifts: Vec<usize>,
}

impl VigenereKey {
    /// Builds a Vigenere key, reducing every shift modulo `alphabet_size`.
    ///
    /// # Errors
    /// Returns [`CipherError::InvalidAlphabetSize`] for an invalid alphabet or
    /// [`CipherError::EmptyVigenereKey`] when no shifts are supplied.
    pub fn new(alphabet_size: usize, shifts: Vec<usize>) -> Result<Self, CipherError> {
        validate_alphabet_size(alphabet_size, 1)?;
        if shifts.is_empty() {
            return Err(CipherError::EmptyVigenereKey);
        }
        Ok(Self {
            alphabet_size,
            shifts: normalize_shifts(shifts, alphabet_size),
        })
    }

    /// Returns the configured alphabet size.
    #[must_use]
    pub const fn alphabet_size(&self) -> usize {
        self.alphabet_size
    }

    /// Returns the normalized periodic shifts.
    #[must_use]
    pub fn shifts(&self) -> &[usize] {
        &self.shifts
    }
}

/// Key for the additive-progressive incrementing-wheel cipher.
///
/// This implements the direct additive-progressive interpretation of
/// ngraham20's "outer ring plus inner ring rotating one step per character"
/// model:
///
/// `cipher[i] = (plain[i] + start + i * step) mod N`.
///
/// The gapped-inner-ring variant is intentionally out of scope for this
/// primitive because it needs an explicit plaintext alphabet and gap pattern,
/// which belongs in an attack harness rather than in a total sequence
/// transform.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IncrementingWheelKey {
    alphabet_size: usize,
    start: usize,
    step: usize,
}

impl IncrementingWheelKey {
    /// Builds an incrementing-wheel key, reducing `start` and `step` modulo
    /// `alphabet_size`.
    ///
    /// # Errors
    /// Returns [`CipherError::InvalidAlphabetSize`] when the alphabet is empty
    /// or cannot be represented by [`Glyph`].
    pub fn new(alphabet_size: usize, start: usize, step: usize) -> Result<Self, CipherError> {
        validate_alphabet_size(alphabet_size, 1)?;
        Ok(Self {
            alphabet_size,
            start: start % alphabet_size,
            step: step % alphabet_size,
        })
    }

    /// Returns the configured alphabet size.
    #[must_use]
    pub const fn alphabet_size(self) -> usize {
        self.alphabet_size
    }

    /// Returns the normalized initial shift.
    #[must_use]
    pub const fn start(self) -> usize {
        self.start
    }

    /// Returns the normalized shift increment per symbol.
    #[must_use]
    pub const fn step(self) -> usize {
        self.step
    }
}

/// Key for the classic two-alphabet Chaocipher transform.
///
/// `left` is the ciphertext alphabet and `right` is the plaintext alphabet.
/// For encryption, the plaintext symbol is found in `right` and the symbol at
/// the same position in `left` is emitted. For decryption, the ciphertext
/// symbol is found in `left` and the symbol at the same position in `right` is
/// emitted. After every character both alphabets are permuted using the
/// standard Chaocipher step; for non-26 alphabets the nadir is generalized to
/// index `N / 2`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChaocipherKey {
    alphabet_size: usize,
    left: Vec<usize>,
    right: Vec<usize>,
}

impl ChaocipherKey {
    /// Builds a Chaocipher key from explicit left and right alphabets.
    ///
    /// # Errors
    /// Returns [`CipherError`] if the alphabet is smaller than three symbols,
    /// too large for [`Glyph`], or either alphabet is not a permutation of
    /// `0..alphabet_size`.
    pub fn new(
        alphabet_size: usize,
        left: Vec<usize>,
        right: Vec<usize>,
    ) -> Result<Self, CipherError> {
        validate_alphabet_size(alphabet_size, 3)?;
        validate_permutation("Chaocipher left", &left, alphabet_size)?;
        validate_permutation("Chaocipher right", &right, alphabet_size)?;
        Ok(Self {
            alphabet_size,
            left,
            right,
        })
    }

    /// Builds a Chaocipher key with identity left and right alphabets.
    ///
    /// # Errors
    /// Returns [`CipherError::InvalidAlphabetSize`] if the alphabet is smaller
    /// than three symbols or too large for [`Glyph`].
    pub fn identity(alphabet_size: usize) -> Result<Self, CipherError> {
        Self::new(
            alphabet_size,
            identity_permutation(alphabet_size, 3)?,
            identity_permutation(alphabet_size, 3)?,
        )
    }

    /// Returns the configured alphabet size.
    #[must_use]
    pub const fn alphabet_size(&self) -> usize {
        self.alphabet_size
    }

    /// Returns the initial left ciphertext alphabet.
    #[must_use]
    pub fn left_alphabet(&self) -> &[usize] {
        &self.left
    }

    /// Returns the initial right plaintext alphabet.
    #[must_use]
    pub fn right_alphabet(&self) -> &[usize] {
        &self.right
    }
}

/// Key for the generalized `S_N` deck-keystream cipher.
///
/// This is a Solitaire/Pontifex-style stream generator over exactly one
/// permutation of `N` alphabet cards. Each keystream step moves two configured
/// in-alphabet control cards, performs a triple cut, performs a bottom-card
/// count cut, and emits the card selected by the top-card count. The emitted
/// card is used directly as a value modulo `N`, including when it is one of the
/// control cards.
///
/// This is the module's explicit simplification: classic Pontifex uses two
/// out-of-alphabet jokers and discards joker outputs. Those rules would make
/// the state a permutation of `N + 2` cards rather than `S_N`; this variant
/// keeps the state in `S_N` so an 83-symbol eye alphabet uses an 83-card deck.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeckCipherKey {
    alphabet_size: usize,
    deck: Vec<usize>,
    control_a: usize,
    control_b: usize,
}

impl DeckCipherKey {
    /// Builds a deck-cipher key from a deck permutation and two control cards.
    ///
    /// # Errors
    /// Returns [`CipherError`] if the alphabet is smaller than three symbols,
    /// the deck is not a permutation of `0..alphabet_size`, or the control
    /// cards are outside the alphabet or not distinct.
    pub fn new(
        alphabet_size: usize,
        deck: Vec<usize>,
        control_a: usize,
        control_b: usize,
    ) -> Result<Self, CipherError> {
        validate_alphabet_size(alphabet_size, 3)?;
        validate_permutation("deck", &deck, alphabet_size)?;
        validate_control_cards(alphabet_size, control_a, control_b)?;
        Ok(Self {
            alphabet_size,
            deck,
            control_a,
            control_b,
        })
    }

    /// Builds an identity deck using symbols `N - 2` and `N - 1` as controls.
    ///
    /// # Errors
    /// Returns [`CipherError::InvalidAlphabetSize`] if the alphabet is smaller
    /// than three symbols or too large for [`Glyph`].
    pub fn identity(alphabet_size: usize) -> Result<Self, CipherError> {
        validate_alphabet_size(alphabet_size, 3)?;
        Self::new(
            alphabet_size,
            identity_permutation(alphabet_size, 3)?,
            alphabet_size - 2,
            alphabet_size - 1,
        )
    }

    /// Returns the configured alphabet size.
    #[must_use]
    pub const fn alphabet_size(&self) -> usize {
        self.alphabet_size
    }

    /// Returns the initial deck permutation.
    #[must_use]
    pub fn deck(&self) -> &[usize] {
        &self.deck
    }

    /// Returns the first moving control card.
    #[must_use]
    pub const fn control_a(&self) -> usize {
        self.control_a
    }

    /// Returns the second moving control card.
    #[must_use]
    pub const fn control_b(&self) -> usize {
        self.control_b
    }
}

/// Which multiplicative subgroup the AGL multiplier `a` ranges over.
///
/// [`AglMultiplierSubgroup::Full`] is `C83:C82` for the eye alphabet, and
/// [`AglMultiplierSubgroup::QuadraticResidues`] is the index-2 subgroup
/// `C83:C41`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AglMultiplierSubgroup {
    /// All nonzero units modulo the prime alphabet size.
    Full,
    /// The quadratic-residue subgroup of the units modulo the prime alphabet.
    QuadraticResidues,
}

/// Key for an AGL(1,n)-GAK stream cipher in the verified convention.
///
/// State is an affine map `(a,b): x -> a*x + b (mod n)`. Each plaintext letter
/// right-multiplies the state by its configured group element, and the emitted
/// ciphertext is the updated state's image of the fixed reference point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AglGakKey {
    alphabet_size: usize,
    subgroup: AglMultiplierSubgroup,
    reference_point: usize,
    initial_state: (usize, usize),
    letter_elements: Vec<(usize, usize)>,
}

impl AglGakKey {
    /// Builds an AGL(1,n)-GAK key from explicit state and letter elements.
    ///
    /// # Errors
    /// Returns [`CipherError`] if the alphabet is not a supported prime, if a
    /// state element is outside the selected AGL subgroup, or if two plaintext
    /// letters occupy the same point-stabilizer coset.
    pub fn new(
        alphabet_size: usize,
        subgroup: AglMultiplierSubgroup,
        reference_point: usize,
        initial_state: (usize, usize),
        letter_elements: Vec<(usize, usize)>,
    ) -> Result<Self, CipherError> {
        validate_agl_alphabet(alphabet_size)?;
        if reference_point >= alphabet_size {
            return Err(CipherError::PermutationSymbolOutsideAlphabet {
                label: "AGL reference point",
                symbol: reference_point,
                alphabet_size,
            });
        }
        validate_agl_element(initial_state, alphabet_size, subgroup, "AGL initial state")?;
        validate_agl_letter_elements(&letter_elements, alphabet_size, subgroup, reference_point)?;
        Ok(Self {
            alphabet_size,
            subgroup,
            reference_point,
            initial_state,
            letter_elements,
        })
    }

    /// Builds an identity-state key with one translation representative per coset.
    ///
    /// # Errors
    /// Returns [`CipherError`] if the alphabet is not a supported prime.
    pub fn identity(
        alphabet_size: usize,
        subgroup: AglMultiplierSubgroup,
    ) -> Result<Self, CipherError> {
        validate_agl_alphabet(alphabet_size)?;
        let letter_elements = (0..alphabet_size).map(|symbol| (1, symbol)).collect();
        Self::new(alphabet_size, subgroup, 0, (1, 0), letter_elements)
    }

    /// Returns the configured ciphertext alphabet size.
    #[must_use]
    pub const fn alphabet_size(&self) -> usize {
        self.alphabet_size
    }

    /// Returns the configured multiplier subgroup.
    #[must_use]
    pub const fn subgroup(&self) -> AglMultiplierSubgroup {
        self.subgroup
    }

    /// Returns the fixed reference point `x0`.
    #[must_use]
    pub const fn reference_point(&self) -> usize {
        self.reference_point
    }

    /// Returns the initial affine state `(a,b)`.
    #[must_use]
    pub const fn initial_state(&self) -> (usize, usize) {
        self.initial_state
    }

    /// Returns plaintext-letter group elements in letter-index order.
    #[must_use]
    pub fn letter_elements(&self) -> &[(usize, usize)] {
        &self.letter_elements
    }
}

/// Hidden-subgroup coset readout `c: G -> C` for a [`GakKey`].
///
/// The readout must be constant on the right cosets `Hg` of the hidden subgroup
/// `H` — the `Group-Autokey-(GAK).md` requirement — paired with the spec's
/// left-multiplication state update `g_{i+1} = p(a_i) ∘ g_i` in the
/// `(f ∘ g)[i] = f[g[i]]` convention. Concretely the visible symbol is read off
/// `g^{-1}` (the *position* a marked card occupies): `c(g) = g^{-1}[reference]`.
/// This is the **intentional dual** of the literal deck/GAK spec's
/// `g[top_index]` readout, *not* that literal expression. The dual is forced by
/// the convention: under the left update `g ← p(a) ∘ g`, the function constant
/// on right cosets `Hg` (and hence invertible from any reachable state for
/// arbitrary `p(a)`) is `g^{-1}[reference]`, whereas `g[index]` is constant on
/// *left* cosets and would not be reversible here. Both variants realize the
/// abstract group `G` as a permutation group on `0..n` (`Deck-Cipher.md`: every
/// finite group is a permutation group, so one representation covers the deck
/// case and explicitly enumerated small groups alike).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CosetReadout {
    /// Deck realization (`S_n` over the stabilizer `H = S_{n-1}` of one card):
    /// the visible ciphertext symbol is the *position* currently holding the
    /// marked card `reference_value`, i.e. `c(g) = g^{-1}[reference_value]`,
    /// with `|C| = n`. This is the deck cipher's "where is the top card"
    /// reading, the right-coset-constant dual of `g[index]` under left-update.
    TopCard {
        /// The marked card whose position is the visible ciphertext symbol.
        reference_value: usize,
    },
    /// Explicit coset projection for an enumerated small group: read the
    /// position of `reference_value` under `g` (i.e. `g^{-1}[reference_value]`,
    /// a value in `0..n`) and project it through `coset_of` to a coset label in
    /// `0..ciphertext_alphabet_size`.
    ///
    /// The caller is responsible for supplying a `(G, H)` pair whose right
    /// cosets `Hg` are exactly the fibers of
    /// `g -> coset_of[g^{-1}[reference_value]]` (document the pair and its
    /// source rather than re-deriving irreducibility of `H` in code).
    CosetTable {
        /// The marked card whose position indexes the projection table.
        reference_value: usize,
        /// Projection from card-position (`0..n`) to coset label
        /// (`0..ciphertext_alphabet_size`); length must equal the state size.
        coset_of: Vec<usize>,
    },
}

impl CosetReadout {
    /// Projects a state permutation to its visible ciphertext coset.
    ///
    /// The permutation is taken in the `(f ∘ g)[i] = f[g[i]]` convention used by
    /// [`gak_encrypt`]; the readout reads `g^{-1}[reference_value]` so that it
    /// is constant on right cosets under the left-multiplication update.
    fn coset_of(&self, state: &[usize]) -> Result<usize, CipherError> {
        match self {
            Self::TopCard { reference_value } => inverse_image(state, *reference_value),
            Self::CosetTable {
                reference_value,
                coset_of,
            } => {
                let position = inverse_image(state, *reference_value)?;
                coset_of
                    .get(position)
                    .copied()
                    .ok_or(CipherError::InternalInvariant {
                        context: "GAK coset-table projection",
                    })
            }
        }
    }

    /// Number of distinct cosets `|C|` this readout can emit over `0..state_size`.
    fn ciphertext_alphabet_size(&self, state_size: usize) -> usize {
        match self {
            Self::TopCard { .. } => state_size,
            Self::CosetTable { coset_of, .. } => coset_of
                .iter()
                .copied()
                .max()
                .map_or(0, |max| max.saturating_add(1)),
        }
    }

    /// Validates the readout against the state size, returning `|C|`.
    fn validate(&self, state_size: usize) -> Result<usize, CipherError> {
        match self {
            Self::TopCard { reference_value } => {
                if *reference_value >= state_size {
                    return Err(CipherError::GakReferenceOutsideState {
                        reference_point: *reference_value,
                        state_size,
                    });
                }
                Ok(state_size)
            }
            Self::CosetTable {
                reference_value,
                coset_of,
            } => {
                if *reference_value >= state_size {
                    return Err(CipherError::GakReferenceOutsideState {
                        reference_point: *reference_value,
                        state_size,
                    });
                }
                if coset_of.len() != state_size {
                    return Err(CipherError::GakReadoutSizeMismatch {
                        label: "GAK coset table",
                        len: coset_of.len(),
                        state_size,
                    });
                }
                // Cap the ciphertext alphabet at the largest size a `Glyph` can
                // encode. Without this an unbounded coset label (e.g.
                // `usize::MAX - 1`) would pass the trivially-true `coset <
                // max(coset_of) + 1` check, then either trigger an impossible
                // `vec![false; alphabet_size]` allocation in `GakKey::new` or
                // emit a coset too large to represent as a `Glyph`.
                let alphabet_size = self.ciphertext_alphabet_size(state_size);
                if alphabet_size > MAX_ALPHABET_SIZE {
                    let coset = coset_of.iter().copied().max().unwrap_or(0);
                    return Err(CipherError::GakReadoutCosetOutsideAlphabet {
                        coset,
                        ciphertext_alphabet_size: MAX_ALPHABET_SIZE,
                    });
                }
                for &coset in coset_of {
                    if coset >= alphabet_size {
                        return Err(CipherError::GakReadoutCosetOutsideAlphabet {
                            coset,
                            ciphertext_alphabet_size: alphabet_size,
                        });
                    }
                }
                Ok(alphabet_size)
            }
        }
    }
}

/// Returns the position `j` with `state[j] == value`, i.e. `state^{-1}[value]`.
fn inverse_image(state: &[usize], value: usize) -> Result<usize, CipherError> {
    state
        .iter()
        .position(|&entry| entry == value)
        .ok_or(CipherError::InternalInvariant {
            context: "GAK inverse-image readout",
        })
}

/// Optional subgroup-parity constraint on a [`GakKey`]'s plaintext-letter
/// permutations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GakSubgroupConstraint {
    /// No constraint: each `p(a)` may be any permutation of `0..n` (`S_n`).
    SymmetricGroup,
    /// Alternating group `A_n`: every `p(a)` must be an even permutation.
    AlternatingGroup,
}

/// Options applied while constructing a [`GakKey`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GakKeyOptions {
    /// Reject any plaintext letter whose permutation leaves the readout coset
    /// unchanged from the initial state.
    ///
    /// This realizes `Deck-Cipher.md`'s "don't pick from the identity coset"
    /// rule. For the `TopCard` readout (and any readout where `c(p∘g) == c(g)` is
    /// state-independent, i.e. equivalent to `p` fixing the reference value)
    /// this guarantees no adjacent-equal ciphertext symbols. For an arbitrary
    /// `CosetTable` readout the check is performed only against the initial
    /// state, so it forbids initial-state doubles but does NOT guarantee the
    /// absence of adjacent-equal symbols from later reachable states.
    pub avoid_doubles: bool,
    /// Subgroup-parity constraint the plaintext-letter permutations must obey.
    pub subgroup: GakSubgroupConstraint,
}

impl Default for GakKeyOptions {
    fn default() -> Self {
        Self {
            avoid_doubles: false,
            subgroup: GakSubgroupConstraint::SymmetricGroup,
        }
    }
}

/// Key for a general Group-Autokey (GAK) cipher realized as a permutation group.
///
/// This is the abstract GAK of `Group-Autokey-(GAK).md`: a state group `G`
/// (here a permutation group on `0..n`) with a hidden subgroup `H`, a plaintext
/// map `p: P -> G`, and a ciphertext map `c: G -> C` constant on right cosets
/// `Hg`. The state updates by cumulative left-multiplication
/// `g_{i+1} = p(a_i) ∘ g_i` and the emitted symbol is `c(g_{i+1})`, with
/// `|C| = |G| / |H|`. With a trivial hidden subgroup (`c` bijective) it reduces
/// to GCTAK.
///
/// `S_n` / `A_n` / `D_{2n}` / `AGL(1,p)` and the candidate 83-symbol groups all
/// fit this one type by choosing the per-letter permutations and the
/// [`CosetReadout`]. The small-support / `≤k`-swaps (`≤k`-transpositions) prior
/// used by the generator drivers is a **TENTATIVE** search heuristic, not a
/// property of this key, and is not encoded here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GakKey {
    ciphertext_alphabet_size: usize,
    state_size: usize,
    plaintext_letters: Vec<Vec<usize>>,
    initial_state: Vec<usize>,
    coset_readout: CosetReadout,
}

impl GakKey {
    /// Builds a GAK key from explicit per-letter permutations and a readout.
    ///
    /// Each entry of `plaintext_letters` is the permutation `p(a)` for one
    /// plaintext letter, in the `(f ∘ g)[i] = f[g[i]]` convention. The
    /// well-formedness rules of `Group-Autokey-(GAK).md` are enforced.
    ///
    /// # Errors
    /// Returns [`CipherError`] if the state size is out of range; if
    /// `initial_state` or any `p(a)` is not a permutation of `0..n`; if the
    /// readout is malformed for the state size; if no plaintext letters are
    /// supplied; if two plaintext letters land in the same readout coset from
    /// the initial state (not injective on cosets, hence not reversible); if
    /// `avoid_doubles` is set and some `p(a)` fixes the readout coset; or if a
    /// requested subgroup-parity constraint is violated.
    pub fn new(
        state_size: usize,
        plaintext_letters: Vec<Vec<usize>>,
        initial_state: Vec<usize>,
        coset_readout: CosetReadout,
        options: GakKeyOptions,
    ) -> Result<Self, CipherError> {
        validate_gak_state_size(state_size)?;
        validate_permutation("GAK initial state", &initial_state, state_size)?;
        let ciphertext_alphabet_size = coset_readout.validate(state_size)?;
        if plaintext_letters.is_empty() {
            return Err(CipherError::EmptyGakLetters);
        }

        let base_coset = coset_readout.coset_of(&initial_state)?;
        let mut seen_cosets = vec![false; ciphertext_alphabet_size];
        for (letter_index, permutation) in plaintext_letters.iter().enumerate() {
            validate_permutation("GAK plaintext letter", permutation, state_size)?;
            validate_gak_letter_parity(permutation, options.subgroup, letter_index)?;

            let updated = compose_permutations(permutation, &initial_state)?;
            let coset = coset_readout.coset_of(&updated)?;
            if options.avoid_doubles && coset == base_coset {
                return Err(CipherError::GakLetterFixesCoset {
                    letter_index,
                    coset,
                });
            }
            let Some(slot) = seen_cosets.get_mut(coset) else {
                return Err(CipherError::InternalInvariant {
                    context: "GAK coset seen lookup",
                });
            };
            if *slot {
                return Err(CipherError::GakLettersShareCoset {
                    coset,
                    duplicate_index: letter_index,
                });
            }
            *slot = true;
        }

        // The identity-state injectivity check above is PROVEN sufficient for
        // the TopCard deck readout (its readout is itself the right-coset
        // projection, so per-state injectivity follows from the identity case).
        // It is NOT sufficient for an arbitrary supplied coset table, so those
        // require full reachable-state enumeration; see
        // `validate_coset_table_invertible`.
        if matches!(coset_readout, CosetReadout::CosetTable { .. }) {
            validate_coset_table_invertible(&plaintext_letters, &initial_state, &coset_readout)?;
        }

        Ok(Self {
            ciphertext_alphabet_size,
            state_size,
            plaintext_letters,
            initial_state,
            coset_readout,
        })
    }

    /// Builds a deck-realization GAK key (`S_n`, hidden subgroup `S_{n-1}`).
    ///
    /// Uses the identity initial state and [`CosetReadout::TopCard`] tracking
    /// the marked card `0`. The plaintext letters must already be permutations
    /// of `0..n`; see [`GakKey::new`] for the validation rules.
    ///
    /// # Errors
    /// Returns [`CipherError`] under the same conditions as [`GakKey::new`].
    pub fn deck(
        state_size: usize,
        plaintext_letters: Vec<Vec<usize>>,
        options: GakKeyOptions,
    ) -> Result<Self, CipherError> {
        let initial_state = identity_gak_permutation(state_size)?;
        Self::new(
            state_size,
            plaintext_letters,
            initial_state,
            CosetReadout::TopCard { reference_value: 0 },
            options,
        )
    }

    /// Returns the ciphertext alphabet size `|C| = |G| / |H|`.
    #[must_use]
    pub const fn ciphertext_alphabet_size(&self) -> usize {
        self.ciphertext_alphabet_size
    }

    /// Returns the permutation state size `n` (permutations act on `0..n`).
    #[must_use]
    pub const fn state_size(&self) -> usize {
        self.state_size
    }

    /// Returns the per-letter permutations `p(a)` in plaintext-letter order.
    #[must_use]
    pub fn plaintext_letters(&self) -> &[Vec<usize>] {
        &self.plaintext_letters
    }

    /// Returns the initial state permutation `g_0`.
    #[must_use]
    pub fn initial_state(&self) -> &[usize] {
        &self.initial_state
    }

    /// Returns the hidden-subgroup coset readout `c: G -> C`.
    #[must_use]
    pub const fn coset_readout(&self) -> &CosetReadout {
        &self.coset_readout
    }
}

/// Encrypts with the no-key identity cipher.
///
/// # Errors
/// This transform is total and currently cannot fail.
pub fn identity_encrypt(plaintext: &[Glyph]) -> Result<Vec<Glyph>, CipherError> {
    Ok(plaintext.to_vec())
}

/// Decrypts with the no-key identity cipher.
///
/// # Errors
/// This transform is total and currently cannot fail.
pub fn identity_decrypt(ciphertext: &[Glyph]) -> Result<Vec<Glyph>, CipherError> {
    Ok(ciphertext.to_vec())
}

/// Encrypts with a route/columnar transposition over positions.
///
/// Symbol values are never changed. Each block is emitted in the key's column
/// rank order; a final partial block is permuted by the same rank restriction
/// over the positions that are present.
///
/// # Errors
/// Returns [`CipherError::InternalInvariant`] if a validated key loses its
/// position permutation invariant.
pub fn transposition_encrypt(
    plaintext: &[Glyph],
    key: &TranspositionKey,
) -> Result<Vec<Glyph>, CipherError> {
    let mut output = Vec::with_capacity(plaintext.len());
    for block in plaintext.chunks(key.period) {
        for column in transposition_order(key, block.len())? {
            let Some(&glyph) = block.get(column) else {
                return Err(CipherError::InternalInvariant {
                    context: "transposition encrypt column lookup",
                });
            };
            output.push(glyph);
        }
    }
    Ok(output)
}

/// Decrypts with a route/columnar transposition over positions.
///
/// # Errors
/// Returns [`CipherError::InternalInvariant`] if a validated key loses its
/// position permutation invariant.
pub fn transposition_decrypt(
    ciphertext: &[Glyph],
    key: &TranspositionKey,
) -> Result<Vec<Glyph>, CipherError> {
    let mut output = Vec::with_capacity(ciphertext.len());
    for block in ciphertext.chunks(key.period) {
        let order = transposition_order(key, block.len())?;
        let mut restored = vec![Glyph(0); block.len()];
        for (cipher_column, plain_column) in order.into_iter().enumerate() {
            let Some(&glyph) = block.get(cipher_column) else {
                return Err(CipherError::InternalInvariant {
                    context: "transposition decrypt column lookup",
                });
            };
            let Some(slot) = restored.get_mut(plain_column) else {
                return Err(CipherError::InternalInvariant {
                    context: "transposition decrypt restore slot",
                });
            };
            *slot = glyph;
        }
        output.extend(restored);
    }
    Ok(output)
}

/// Encrypts with the Caesar additive shift cipher.
///
/// Each plaintext symbol `p` is transformed to `(p + shift) mod N`.
///
/// # Errors
/// Returns [`CipherError::SymbolOutsideAlphabet`] if the plaintext contains a
/// symbol outside the key alphabet.
pub fn caesar_encrypt(plaintext: &[Glyph], key: &CaesarKey) -> Result<Vec<Glyph>, CipherError> {
    translate_additive(
        plaintext,
        key.alphabet_size,
        |_position| Ok(key.shift),
        Direction::Encrypt,
    )
}

/// Decrypts with the Caesar additive shift cipher.
///
/// Each ciphertext symbol `c` is transformed to `(c - shift) mod N`.
///
/// # Errors
/// Returns [`CipherError::SymbolOutsideAlphabet`] if the ciphertext contains a
/// symbol outside the key alphabet.
pub fn caesar_decrypt(ciphertext: &[Glyph], key: &CaesarKey) -> Result<Vec<Glyph>, CipherError> {
    translate_additive(
        ciphertext,
        key.alphabet_size,
        |_position| Ok(key.shift),
        Direction::Decrypt,
    )
}

/// Encrypts with the periodic additive Vigenere cipher.
///
/// At position `i`, the plaintext symbol `p` is transformed to
/// `(p + key[i % period]) mod N`.
///
/// # Errors
/// Returns [`CipherError::SymbolOutsideAlphabet`] if the plaintext contains a
/// symbol outside the key alphabet.
pub fn vigenere_encrypt(plaintext: &[Glyph], key: &VigenereKey) -> Result<Vec<Glyph>, CipherError> {
    translate_additive(
        plaintext,
        key.alphabet_size,
        |position| periodic_shift_at(&key.shifts, position),
        Direction::Encrypt,
    )
}

/// Decrypts with the periodic additive Vigenere cipher.
///
/// At position `i`, the ciphertext symbol `c` is transformed to
/// `(c - key[i % period]) mod N`.
///
/// # Errors
/// Returns [`CipherError::SymbolOutsideAlphabet`] if the ciphertext contains a
/// symbol outside the key alphabet.
pub fn vigenere_decrypt(
    ciphertext: &[Glyph],
    key: &VigenereKey,
) -> Result<Vec<Glyph>, CipherError> {
    translate_additive(
        ciphertext,
        key.alphabet_size,
        |position| periodic_shift_at(&key.shifts, position),
        Direction::Decrypt,
    )
}

/// Encrypts with the additive-progressive incrementing-wheel cipher.
///
/// At position `i`, the plaintext symbol `p` is transformed to
/// `(p + start + i * step) mod N`.
///
/// # Errors
/// Returns [`CipherError::SymbolOutsideAlphabet`] if the plaintext contains a
/// symbol outside the key alphabet.
pub fn incrementing_wheel_encrypt(
    plaintext: &[Glyph],
    key: &IncrementingWheelKey,
) -> Result<Vec<Glyph>, CipherError> {
    translate_additive(
        plaintext,
        key.alphabet_size,
        |position| Ok(progressive_shift_at(key, position)),
        Direction::Encrypt,
    )
}

/// Decrypts with the additive-progressive incrementing-wheel cipher.
///
/// At position `i`, the ciphertext symbol `c` is transformed to
/// `(c - start - i * step) mod N`.
///
/// # Errors
/// Returns [`CipherError::SymbolOutsideAlphabet`] if the ciphertext contains a
/// symbol outside the key alphabet.
pub fn incrementing_wheel_decrypt(
    ciphertext: &[Glyph],
    key: &IncrementingWheelKey,
) -> Result<Vec<Glyph>, CipherError> {
    translate_additive(
        ciphertext,
        key.alphabet_size,
        |position| Ok(progressive_shift_at(key, position)),
        Direction::Decrypt,
    )
}

/// Encrypts with the generalized Chaocipher transform.
///
/// The plaintext symbol is located in the right alphabet, the aligned symbol
/// in the left alphabet is emitted, and both dynamic alphabets are then
/// permuted using the standard Chaocipher step.
///
/// # Errors
/// Returns [`CipherError::SymbolOutsideAlphabet`] if the plaintext contains a
/// symbol outside the key alphabet, or [`CipherError::InternalInvariant`] if a
/// validated dynamic alphabet loses permutation state.
pub fn chaocipher_encrypt(
    plaintext: &[Glyph],
    key: &ChaocipherKey,
) -> Result<Vec<Glyph>, CipherError> {
    translate_chaocipher(plaintext, key, Direction::Encrypt)
}

/// Decrypts with the generalized Chaocipher transform.
///
/// The ciphertext symbol is located in the left alphabet, the aligned symbol
/// in the right alphabet is emitted, and both dynamic alphabets are then
/// permuted exactly as in encryption.
///
/// # Errors
/// Returns [`CipherError::SymbolOutsideAlphabet`] if the ciphertext contains a
/// symbol outside the key alphabet, or [`CipherError::InternalInvariant`] if a
/// validated dynamic alphabet loses permutation state.
pub fn chaocipher_decrypt(
    ciphertext: &[Glyph],
    key: &ChaocipherKey,
) -> Result<Vec<Glyph>, CipherError> {
    translate_chaocipher(ciphertext, key, Direction::Decrypt)
}

/// Encrypts with the generalized `S_N` deck-keystream cipher.
///
/// A deterministic deck keystream is generated from the key state and added to
/// the plaintext modulo `N`.
///
/// # Errors
/// Returns [`CipherError::SymbolOutsideAlphabet`] if the plaintext contains a
/// symbol outside the key alphabet, or [`CipherError::InternalInvariant`] if a
/// validated deck loses permutation state.
pub fn deck_cipher_encrypt(
    plaintext: &[Glyph],
    key: &DeckCipherKey,
) -> Result<Vec<Glyph>, CipherError> {
    translate_deck_cipher(plaintext, key, Direction::Encrypt)
}

/// Decrypts with the generalized `S_N` deck-keystream cipher.
///
/// The same deterministic deck keystream is generated from the key state and
/// subtracted from the ciphertext modulo `N`.
///
/// # Errors
/// Returns [`CipherError::SymbolOutsideAlphabet`] if the ciphertext contains a
/// symbol outside the key alphabet, or [`CipherError::InternalInvariant`] if a
/// validated deck loses permutation state.
pub fn deck_cipher_decrypt(
    ciphertext: &[Glyph],
    key: &DeckCipherKey,
) -> Result<Vec<Glyph>, CipherError> {
    translate_deck_cipher(ciphertext, key, Direction::Decrypt)
}

/// Encrypts with the AGL(1,n)-GAK stream cipher.
///
/// Starting from the key's initial state, each plaintext letter
/// right-multiplies the state by its configured affine element. The ciphertext
/// symbol is the updated state's image of the reference point.
///
/// # Errors
/// Returns [`CipherError::SymbolOutsideAlphabet`] for an out-of-range
/// plaintext letter, or [`CipherError::InternalInvariant`] if a validated group
/// element loses its invariant.
pub fn agl_gak_encrypt(plaintext: &[Glyph], key: &AglGakKey) -> Result<Vec<Glyph>, CipherError> {
    let mut state = key.initial_state;
    let mut output = Vec::with_capacity(plaintext.len());
    for glyph in plaintext.iter().copied() {
        let letter = symbol_from_glyph(glyph, key.letter_elements.len())?;
        let Some(element) = key.letter_elements.get(letter).copied() else {
            return Err(CipherError::InternalInvariant {
                context: "AGL letter element lookup",
            });
        };
        state = agl_compose(state, element, key.alphabet_size);
        let symbol = agl_coset_symbol(state, key.reference_point, key.alphabet_size);
        output.push(glyph_from_symbol(symbol, key.alphabet_size)?);
    }
    Ok(output)
}

/// Decrypts an AGL(1,n)-GAK ciphertext back to plaintext.
///
/// The current state makes the next ciphertext symbol a lookup over the
/// configured letter cosets. The key constructor enforces that this lookup is
/// injective for every state.
///
/// # Errors
/// Returns [`CipherError::SymbolOutsideAlphabet`] for an out-of-range
/// ciphertext symbol, or [`CipherError::InternalInvariant`] if no configured
/// letter matches the observed coset.
pub fn agl_gak_decrypt(ciphertext: &[Glyph], key: &AglGakKey) -> Result<Vec<Glyph>, CipherError> {
    let mut state = key.initial_state;
    let mut output = Vec::with_capacity(ciphertext.len());
    for glyph in ciphertext.iter().copied() {
        let observed = symbol_from_glyph(glyph, key.alphabet_size)?;
        let lookup = agl_step_lookup(state, key)?;
        let Some(letter) = lookup.get(&observed).copied() else {
            return Err(CipherError::InternalInvariant {
                context: "AGL ciphertext coset lookup",
            });
        };
        let Some(element) = key.letter_elements.get(letter).copied() else {
            return Err(CipherError::InternalInvariant {
                context: "AGL decrypt letter element lookup",
            });
        };
        output.push(glyph_from_symbol(letter, key.letter_elements.len())?);
        state = agl_compose(state, element, key.alphabet_size);
    }
    Ok(output)
}

/// Encrypts with the general permutation-group GAK cipher.
///
/// Starting from `g_0`, each plaintext letter `a` updates the state by
/// cumulative left-multiplication `g ← p(a) ∘ g` (in the
/// `(f ∘ g)[i] = f[g[i]]` convention) and the emitted ciphertext symbol is the
/// hidden-subgroup coset readout `c(g)`.
///
/// # Errors
/// Returns [`CipherError::SymbolOutsideAlphabet`] if a plaintext letter is not a
/// configured letter index, or [`CipherError::InternalInvariant`] if a validated
/// permutation loses its invariant during composition or readout.
pub fn gak_encrypt(plaintext: &[Glyph], key: &GakKey) -> Result<Vec<Glyph>, CipherError> {
    let mut state = key.initial_state.clone();
    let mut output = Vec::with_capacity(plaintext.len());
    for glyph in plaintext.iter().copied() {
        let letter = symbol_from_glyph(glyph, key.plaintext_letters.len())?;
        let Some(permutation) = key.plaintext_letters.get(letter) else {
            return Err(CipherError::InternalInvariant {
                context: "GAK encrypt letter lookup",
            });
        };
        // State update: left-multiplication g_{i+1} = p(a_i) ∘ g_i.
        state = compose_permutations(permutation, &state)?;
        let coset = key.coset_readout.coset_of(&state)?;
        output.push(glyph_from_symbol(coset, key.ciphertext_alphabet_size)?);
    }
    Ok(output)
}

/// Decrypts a general permutation-group GAK ciphertext back to plaintext.
///
/// The cumulative state is replayed exactly as in encryption. At each step the
/// constructor's guarantee that the plaintext letters are injective on cosets
/// makes the next ciphertext coset identify a unique plaintext letter, which is
/// emitted before the state is advanced by that letter's permutation. Decrypt
/// therefore legitimately requires the key.
///
/// # Errors
/// Returns [`CipherError::SymbolOutsideAlphabet`] for an out-of-range ciphertext
/// symbol, or [`CipherError::InternalInvariant`] if no configured letter matches
/// the observed coset or a validated permutation loses its invariant.
pub fn gak_decrypt(ciphertext: &[Glyph], key: &GakKey) -> Result<Vec<Glyph>, CipherError> {
    let mut state = key.initial_state.clone();
    let mut output = Vec::with_capacity(ciphertext.len());
    for glyph in ciphertext.iter().copied() {
        let observed = symbol_from_glyph(glyph, key.ciphertext_alphabet_size)?;
        let lookup = gak_step_lookup(&state, key)?;
        let Some(letter) = lookup.get(&observed).copied() else {
            return Err(CipherError::InternalInvariant {
                context: "GAK ciphertext coset lookup",
            });
        };
        let Some(permutation) = key.plaintext_letters.get(letter) else {
            return Err(CipherError::InternalInvariant {
                context: "GAK decrypt letter lookup",
            });
        };
        output.push(glyph_from_symbol(letter, key.plaintext_letters.len())?);
        state = compose_permutations(permutation, &state)?;
    }
    Ok(output)
}

/// A cipher family: encrypts/decrypts [`Glyph`] sequences under a family-specific key.
///
/// Implementors are zero-sized family markers; per-instance configuration lives
/// in [`Cipher::Key`]. The canonical transforms remain this module's free
/// functions, which these methods delegate to byte-for-byte.
pub trait Cipher {
    /// Family-specific key type, such as [`CaesarKey`].
    type Key;

    /// Encrypts `plaintext` under `key`.
    ///
    /// # Errors
    /// Propagates the underlying [`CipherError`] unchanged.
    fn encrypt(&self, key: &Self::Key, plaintext: &[Glyph]) -> Result<Vec<Glyph>, CipherError>;

    /// Decrypts `ciphertext` under `key`.
    ///
    /// # Errors
    /// Propagates the underlying [`CipherError`] unchanged.
    fn decrypt(&self, key: &Self::Key, ciphertext: &[Glyph]) -> Result<Vec<Glyph>, CipherError>;

    /// Returns a short, stable display-only family name.
    #[must_use]
    fn name(&self) -> &'static str;
}

/// Trait implementation for the no-key identity cipher marker.
impl Cipher for Identity {
    type Key = ();

    fn encrypt(&self, _key: &(), plaintext: &[Glyph]) -> Result<Vec<Glyph>, CipherError> {
        identity_encrypt(plaintext)
    }

    fn decrypt(&self, _key: &(), ciphertext: &[Glyph]) -> Result<Vec<Glyph>, CipherError> {
        identity_decrypt(ciphertext)
    }

    fn name(&self) -> &'static str {
        "identity"
    }
}

/// Family marker for the route/columnar transposition cipher.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Transposition;

impl Cipher for Transposition {
    type Key = TranspositionKey;

    fn encrypt(
        &self,
        key: &TranspositionKey,
        plaintext: &[Glyph],
    ) -> Result<Vec<Glyph>, CipherError> {
        transposition_encrypt(plaintext, key)
    }

    fn decrypt(
        &self,
        key: &TranspositionKey,
        ciphertext: &[Glyph],
    ) -> Result<Vec<Glyph>, CipherError> {
        transposition_decrypt(ciphertext, key)
    }

    fn name(&self) -> &'static str {
        "transposition"
    }
}

/// Family marker for the Caesar additive shift cipher.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Caesar;

impl Cipher for Caesar {
    type Key = CaesarKey;

    fn encrypt(&self, key: &CaesarKey, plaintext: &[Glyph]) -> Result<Vec<Glyph>, CipherError> {
        // Free functions take (sequence, key); trait methods take (key, sequence).
        caesar_encrypt(plaintext, key)
    }

    fn decrypt(&self, key: &CaesarKey, ciphertext: &[Glyph]) -> Result<Vec<Glyph>, CipherError> {
        // Free functions take (sequence, key); trait methods take (key, sequence).
        caesar_decrypt(ciphertext, key)
    }

    fn name(&self) -> &'static str {
        "Caesar"
    }
}

/// Family marker for the periodic additive Vigenere cipher.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Vigenere;

impl Cipher for Vigenere {
    type Key = VigenereKey;

    fn encrypt(&self, key: &VigenereKey, plaintext: &[Glyph]) -> Result<Vec<Glyph>, CipherError> {
        // Free functions take (sequence, key); trait methods take (key, sequence).
        vigenere_encrypt(plaintext, key)
    }

    fn decrypt(&self, key: &VigenereKey, ciphertext: &[Glyph]) -> Result<Vec<Glyph>, CipherError> {
        // Free functions take (sequence, key); trait methods take (key, sequence).
        vigenere_decrypt(ciphertext, key)
    }

    fn name(&self) -> &'static str {
        "Vigenere"
    }
}

/// Family marker for the additive-progressive incrementing-wheel cipher.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IncrementingWheel;

impl Cipher for IncrementingWheel {
    type Key = IncrementingWheelKey;

    fn encrypt(
        &self,
        key: &IncrementingWheelKey,
        plaintext: &[Glyph],
    ) -> Result<Vec<Glyph>, CipherError> {
        // Free functions take (sequence, key); trait methods take (key, sequence).
        incrementing_wheel_encrypt(plaintext, key)
    }

    fn decrypt(
        &self,
        key: &IncrementingWheelKey,
        ciphertext: &[Glyph],
    ) -> Result<Vec<Glyph>, CipherError> {
        // Free functions take (sequence, key); trait methods take (key, sequence).
        incrementing_wheel_decrypt(ciphertext, key)
    }

    fn name(&self) -> &'static str {
        "incrementing-wheel"
    }
}

/// Family marker for the generalized two-alphabet Chaocipher.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Chaocipher;

impl Cipher for Chaocipher {
    type Key = ChaocipherKey;

    fn encrypt(&self, key: &ChaocipherKey, plaintext: &[Glyph]) -> Result<Vec<Glyph>, CipherError> {
        // Free functions take (sequence, key); trait methods take (key, sequence).
        chaocipher_encrypt(plaintext, key)
    }

    fn decrypt(
        &self,
        key: &ChaocipherKey,
        ciphertext: &[Glyph],
    ) -> Result<Vec<Glyph>, CipherError> {
        // Free functions take (sequence, key); trait methods take (key, sequence).
        chaocipher_decrypt(ciphertext, key)
    }

    fn name(&self) -> &'static str {
        "Chaocipher"
    }
}

/// Family marker for the generalized `S_N` deck-keystream cipher.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeckCipher;

impl Cipher for DeckCipher {
    type Key = DeckCipherKey;

    fn encrypt(&self, key: &DeckCipherKey, plaintext: &[Glyph]) -> Result<Vec<Glyph>, CipherError> {
        // Free functions take (sequence, key); trait methods take (key, sequence).
        deck_cipher_encrypt(plaintext, key)
    }

    fn decrypt(
        &self,
        key: &DeckCipherKey,
        ciphertext: &[Glyph],
    ) -> Result<Vec<Glyph>, CipherError> {
        // Free functions take (sequence, key); trait methods take (key, sequence).
        deck_cipher_decrypt(ciphertext, key)
    }

    fn name(&self) -> &'static str {
        "deck"
    }
}

/// Family marker for the AGL(1,n)-GAK stream cipher.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AglGak;

impl Cipher for AglGak {
    type Key = AglGakKey;

    fn encrypt(&self, key: &AglGakKey, plaintext: &[Glyph]) -> Result<Vec<Glyph>, CipherError> {
        // Free functions take (sequence, key); trait methods take (key, sequence).
        agl_gak_encrypt(plaintext, key)
    }

    fn decrypt(&self, key: &AglGakKey, ciphertext: &[Glyph]) -> Result<Vec<Glyph>, CipherError> {
        // Free functions take (sequence, key); trait methods take (key, sequence).
        agl_gak_decrypt(ciphertext, key)
    }

    fn name(&self) -> &'static str {
        "AGL-GAK"
    }
}

/// Family marker for the general permutation-group GAK cipher.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gak;

impl Cipher for Gak {
    type Key = GakKey;

    fn encrypt(&self, key: &GakKey, plaintext: &[Glyph]) -> Result<Vec<Glyph>, CipherError> {
        // Free functions take (sequence, key); trait methods take (key, sequence).
        gak_encrypt(plaintext, key)
    }

    fn decrypt(&self, key: &GakKey, ciphertext: &[Glyph]) -> Result<Vec<Glyph>, CipherError> {
        // Free functions take (sequence, key); trait methods take (key, sequence).
        gak_decrypt(ciphertext, key)
    }

    fn name(&self) -> &'static str {
        "GAK"
    }
}

/// A cipher family together with its key, for heterogeneous search.
///
/// [`Cipher`] has an associated [`Cipher::Key`] type. A trait object for it
/// must bind that type, so it can carry only one family's key and gives no
/// heterogeneous dispatch across the seven families. This enum
/// recovers runtime polymorphism instead: each variant pairs a family with its
/// concrete key, and the inherent methods dispatch over the closed set of
/// existing cipher families.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnyCipher {
    /// No-key passthrough cipher.
    Identity,
    /// Route/columnar position transposition, with its key.
    Transposition(TranspositionKey),
    /// Caesar additive shift, with its key.
    Caesar(CaesarKey),
    /// Periodic additive Vigenere, with its key.
    Vigenere(VigenereKey),
    /// Additive-progressive incrementing wheel, with its key.
    IncrementingWheel(IncrementingWheelKey),
    /// Generalized two-alphabet Chaocipher, with its key.
    Chaocipher(ChaocipherKey),
    /// Generalized `S_N` deck-keystream cipher, with its key.
    DeckCipher(DeckCipherKey),
    /// AGL(1,n)-GAK stream cipher, with its key.
    AglGak(AglGakKey),
    /// General permutation-group GAK cipher, with its key.
    Gak(GakKey),
}

impl AnyCipher {
    /// Encrypts `plaintext` with the contained family/key.
    ///
    /// # Errors
    /// Propagates the underlying [`CipherError`] unchanged.
    pub fn encrypt(&self, plaintext: &[Glyph]) -> Result<Vec<Glyph>, CipherError> {
        match self {
            Self::Identity => identity_encrypt(plaintext),
            Self::Transposition(key) => transposition_encrypt(plaintext, key),
            Self::Caesar(key) => caesar_encrypt(plaintext, key),
            Self::Vigenere(key) => vigenere_encrypt(plaintext, key),
            Self::IncrementingWheel(key) => incrementing_wheel_encrypt(plaintext, key),
            Self::Chaocipher(key) => chaocipher_encrypt(plaintext, key),
            Self::DeckCipher(key) => deck_cipher_encrypt(plaintext, key),
            Self::AglGak(key) => agl_gak_encrypt(plaintext, key),
            Self::Gak(key) => gak_encrypt(plaintext, key),
        }
    }

    /// Decrypts `ciphertext` with the contained family/key.
    ///
    /// # Errors
    /// Propagates the underlying [`CipherError`] unchanged.
    pub fn decrypt(&self, ciphertext: &[Glyph]) -> Result<Vec<Glyph>, CipherError> {
        match self {
            Self::Identity => identity_decrypt(ciphertext),
            Self::Transposition(key) => transposition_decrypt(ciphertext, key),
            Self::Caesar(key) => caesar_decrypt(ciphertext, key),
            Self::Vigenere(key) => vigenere_decrypt(ciphertext, key),
            Self::IncrementingWheel(key) => incrementing_wheel_decrypt(ciphertext, key),
            Self::Chaocipher(key) => chaocipher_decrypt(ciphertext, key),
            Self::DeckCipher(key) => deck_cipher_decrypt(ciphertext, key),
            Self::AglGak(key) => agl_gak_decrypt(ciphertext, key),
            Self::Gak(key) => gak_decrypt(ciphertext, key),
        }
    }

    /// Returns a short, stable display-only family name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Identity => Identity.name(),
            Self::Transposition(_) => Transposition.name(),
            Self::Caesar(_) => Caesar.name(),
            Self::Vigenere(_) => Vigenere.name(),
            Self::IncrementingWheel(_) => IncrementingWheel.name(),
            Self::Chaocipher(_) => Chaocipher.name(),
            Self::DeckCipher(_) => DeckCipher.name(),
            Self::AglGak(_) => AglGak.name(),
            Self::Gak(_) => Gak.name(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direction {
    Encrypt,
    Decrypt,
}

fn validate_alphabet_size(alphabet_size: usize, min: usize) -> Result<(), CipherError> {
    if alphabet_size < min || alphabet_size > MAX_ALPHABET_SIZE {
        return Err(CipherError::InvalidAlphabetSize {
            alphabet_size,
            min,
            max: MAX_ALPHABET_SIZE,
        });
    }
    Ok(())
}

fn validate_agl_alphabet(alphabet_size: usize) -> Result<(), CipherError> {
    validate_alphabet_size(alphabet_size, 3)?;
    if !is_prime(alphabet_size) {
        return Err(CipherError::AlphabetNotPrime { alphabet_size });
    }
    let subgroup_order = quadratic_residues_mod(alphabet_size).len();
    if subgroup_order == 0 {
        return Err(CipherError::UnsupportedMultiplierSubgroup {
            order: subgroup_order,
        });
    }
    Ok(())
}

fn normalize_shifts(shifts: Vec<usize>, alphabet_size: usize) -> Vec<usize> {
    shifts
        .into_iter()
        .map(|shift| shift % alphabet_size)
        .collect()
}

fn identity_permutation(alphabet_size: usize, min: usize) -> Result<Vec<usize>, CipherError> {
    validate_alphabet_size(alphabet_size, min)?;
    Ok((0..alphabet_size).collect())
}

fn validate_gak_state_size(state_size: usize) -> Result<(), CipherError> {
    if !(2..=MAX_ALPHABET_SIZE).contains(&state_size) {
        return Err(CipherError::InvalidGakStateSize {
            state_size,
            min: 2,
            max: MAX_ALPHABET_SIZE,
        });
    }
    Ok(())
}

fn identity_gak_permutation(state_size: usize) -> Result<Vec<usize>, CipherError> {
    validate_gak_state_size(state_size)?;
    Ok((0..state_size).collect())
}

/// Composes two permutations of `0..n` in the `(f ∘ g)[i] = f[g[i]]` convention.
///
/// `outer` and `inner` are assumed validated; an out-of-range image is reported
/// as an internal invariant rather than panicking.
pub(crate) fn compose_permutations(
    outer: &[usize],
    inner: &[usize],
) -> Result<Vec<usize>, CipherError> {
    let mut composed = Vec::with_capacity(inner.len());
    for &image in inner {
        let mapped = outer
            .get(image)
            .copied()
            .ok_or(CipherError::InternalInvariant {
                context: "GAK permutation composition index",
            })?;
        composed.push(mapped);
    }
    Ok(composed)
}

fn validate_gak_letter_parity(
    permutation: &[usize],
    subgroup: GakSubgroupConstraint,
    letter_index: usize,
) -> Result<(), CipherError> {
    match subgroup {
        GakSubgroupConstraint::SymmetricGroup => Ok(()),
        GakSubgroupConstraint::AlternatingGroup => {
            if permutation_parity_is_even(permutation)? {
                Ok(())
            } else {
                Err(CipherError::GakLetterWrongParity { letter_index })
            }
        }
    }
}

/// Returns `true` when a validated permutation of `0..n` is even.
///
/// Parity is the parity of `n` minus the number of disjoint cycles.
fn permutation_parity_is_even(permutation: &[usize]) -> Result<bool, CipherError> {
    let len = permutation.len();
    let mut visited = vec![false; len];
    let mut transpositions = 0usize;
    for start in 0..len {
        let Some(seen) = visited.get(start).copied() else {
            return Err(CipherError::InternalInvariant {
                context: "GAK parity visited lookup",
            });
        };
        if seen {
            continue;
        }
        let mut cursor = start;
        let mut cycle_len = 0usize;
        loop {
            let Some(slot) = visited.get_mut(cursor) else {
                return Err(CipherError::InternalInvariant {
                    context: "GAK parity cursor lookup",
                });
            };
            if *slot {
                break;
            }
            *slot = true;
            cycle_len += 1;
            cursor = permutation
                .get(cursor)
                .copied()
                .ok_or(CipherError::InternalInvariant {
                    context: "GAK parity image lookup",
                })?;
        }
        transpositions += cycle_len.saturating_sub(1);
    }
    Ok(transpositions.is_multiple_of(2))
}

fn gak_step_lookup(state: &[usize], key: &GakKey) -> Result<BTreeMap<usize, usize>, CipherError> {
    let mut lookup = BTreeMap::new();
    for (letter, permutation) in key.plaintext_letters.iter().enumerate() {
        let next_state = compose_permutations(permutation, state)?;
        let coset = key.coset_readout.coset_of(&next_state)?;
        if lookup.insert(coset, letter).is_some() {
            return Err(CipherError::InternalInvariant {
                context: "GAK step lookup duplicate coset",
            });
        }
    }
    Ok(lookup)
}

/// Verifies a [`CosetReadout::CosetTable`] GAK key is decrypt-invertible by
/// bounded enumeration of its reachable state set.
///
/// The identity-state injectivity check that suffices for
/// [`CosetReadout::TopCard`] is *not* sufficient for an arbitrary supplied coset
/// table: a coarser partition can merge points so two letters that separate from
/// the identity state collide from another reachable state. The reachable states
/// are `{ w ∘ initial_state : w ∈ ⟨p(a)⟩ }` where `⟨p(a)⟩` is the subgroup of
/// `S_n` generated by the per-letter permutations. This enumerates that group by
/// closure under composition (worklist from the identity plus the generators),
/// then for each reachable state checks the per-letter readout `a ↦ c(p(a) ∘ g)`
/// is injective.
///
/// Enumeration is capped at [`MAX_GAK_COSET_TABLE_GROUP`]; exceeding the cap
/// yields [`CipherError::GakCosetTableGroupTooLarge`] rather than an unbounded
/// loop or an unvalidated key.
///
/// # Errors
/// [`CipherError::GakCosetTableNotInvertible`] when some reachable state admits a
/// two-letter coset collision; [`CipherError::GakCosetTableGroupTooLarge`] when
/// the generated state group exceeds the cap.
fn validate_coset_table_invertible(
    plaintext_letters: &[Vec<usize>],
    initial_state: &[usize],
    coset_readout: &CosetReadout,
) -> Result<(), CipherError> {
    let state_size = initial_state.len();
    let identity: Vec<usize> = (0..state_size).collect();
    let mut group: BTreeSet<Vec<usize>> = BTreeSet::new();
    let mut worklist: Vec<Vec<usize>> = Vec::new();
    if group.insert(identity.clone()) {
        worklist.push(identity);
    }
    // BFS closure of ⟨p(a)⟩: pop an element, left-multiply by every generator,
    // enqueue any newly discovered element until the group is closed.
    while let Some(element) = worklist.pop() {
        for generator in plaintext_letters {
            let product = compose_permutations(generator, &element)?;
            if group.insert(product.clone()) {
                if group.len() > MAX_GAK_COSET_TABLE_GROUP {
                    return Err(CipherError::GakCosetTableGroupTooLarge {
                        cap: MAX_GAK_COSET_TABLE_GROUP,
                    });
                }
                worklist.push(product);
            }
        }
    }
    // Every reachable state is w ∘ initial_state for w in the generated group;
    // require per-letter readout injectivity from each.
    for element in &group {
        let state = compose_permutations(element, initial_state)?;
        let mut seen: BTreeMap<usize, usize> = BTreeMap::new();
        for (letter_index, permutation) in plaintext_letters.iter().enumerate() {
            let updated = compose_permutations(permutation, &state)?;
            let coset = coset_readout.coset_of(&updated)?;
            if seen.insert(coset, letter_index).is_some() {
                return Err(CipherError::GakCosetTableNotInvertible {
                    state: state.clone(),
                    coset,
                    duplicate_index: letter_index,
                });
            }
        }
    }
    Ok(())
}

fn validate_permutation(
    label: &'static str,
    symbols: &[usize],
    alphabet_size: usize,
) -> Result<(), CipherError> {
    if symbols.len() != alphabet_size {
        return Err(CipherError::PermutationLengthMismatch {
            label,
            len: symbols.len(),
            alphabet_size,
        });
    }

    let mut seen = vec![false; alphabet_size];
    for (index, &symbol) in symbols.iter().enumerate() {
        if symbol >= alphabet_size {
            return Err(CipherError::PermutationSymbolOutsideAlphabet {
                label,
                symbol,
                alphabet_size,
            });
        }
        let Some(slot) = seen.get_mut(symbol) else {
            return Err(CipherError::InternalInvariant {
                context: "permutation slot lookup",
            });
        };
        if *slot {
            return Err(CipherError::DuplicatePermutationSymbol {
                label,
                symbol,
                duplicate_index: index,
            });
        }
        *slot = true;
    }

    for (symbol, present) in seen.iter().copied().enumerate() {
        if !present {
            return Err(CipherError::MissingPermutationSymbol { label, symbol });
        }
    }
    Ok(())
}

fn transposition_order(
    key: &TranspositionKey,
    block_len: usize,
) -> Result<Vec<usize>, CipherError> {
    if block_len > key.period {
        return Err(CipherError::InternalInvariant {
            context: "transposition block longer than period",
        });
    }
    let mut columns = key
        .permutation
        .iter()
        .copied()
        .enumerate()
        .filter(|(column, _rank)| *column < block_len)
        .collect::<Vec<_>>();
    columns.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
    Ok(columns.into_iter().map(|(column, _rank)| column).collect())
}

fn validate_control_cards(
    alphabet_size: usize,
    control_a: usize,
    control_b: usize,
) -> Result<(), CipherError> {
    if control_a >= alphabet_size {
        return Err(CipherError::ControlSymbolOutsideAlphabet {
            symbol: control_a,
            alphabet_size,
        });
    }
    if control_b >= alphabet_size {
        return Err(CipherError::ControlSymbolOutsideAlphabet {
            symbol: control_b,
            alphabet_size,
        });
    }
    if control_a == control_b {
        return Err(CipherError::DuplicateControlSymbols {
            control_a,
            control_b,
        });
    }
    Ok(())
}

fn validate_agl_letter_elements(
    elements: &[(usize, usize)],
    alphabet_size: usize,
    subgroup: AglMultiplierSubgroup,
    reference_point: usize,
) -> Result<(), CipherError> {
    let mut seen_cosets = vec![false; alphabet_size];
    for (index, &element) in elements.iter().enumerate() {
        validate_agl_element(element, alphabet_size, subgroup, "AGL letter element")?;
        let symbol = agl_coset_symbol(element, reference_point, alphabet_size);
        let Some(seen) = seen_cosets.get_mut(symbol) else {
            return Err(CipherError::InternalInvariant {
                context: "AGL coset seen lookup",
            });
        };
        if *seen {
            return Err(CipherError::DuplicatePermutationSymbol {
                label: "AGL letter coset",
                symbol,
                duplicate_index: index,
            });
        }
        *seen = true;
    }
    Ok(())
}

fn validate_agl_element(
    element: (usize, usize),
    alphabet_size: usize,
    subgroup: AglMultiplierSubgroup,
    label: &'static str,
) -> Result<(), CipherError> {
    let (multiplier, translation) = element;
    if translation >= alphabet_size {
        return Err(CipherError::PermutationSymbolOutsideAlphabet {
            label,
            symbol: translation,
            alphabet_size,
        });
    }
    if !agl_multiplier_allowed(multiplier, alphabet_size, subgroup) {
        return Err(CipherError::NonUnitMultiplier {
            multiplier,
            modulus: alphabet_size,
        });
    }
    Ok(())
}

fn agl_multiplier_allowed(
    multiplier: usize,
    alphabet_size: usize,
    subgroup: AglMultiplierSubgroup,
) -> bool {
    if multiplier == 0 || multiplier >= alphabet_size {
        return false;
    }
    match subgroup {
        AglMultiplierSubgroup::Full => true,
        AglMultiplierSubgroup::QuadraticResidues => {
            is_quadratic_residue_mod(multiplier, alphabet_size)
        }
    }
}

fn symbol_from_glyph(glyph: Glyph, alphabet_size: usize) -> Result<usize, CipherError> {
    let symbol = usize::from(glyph.0);
    if symbol >= alphabet_size {
        return Err(CipherError::SymbolOutsideAlphabet {
            symbol: glyph,
            alphabet_size,
        });
    }
    Ok(symbol)
}

fn glyph_from_symbol(symbol: usize, alphabet_size: usize) -> Result<Glyph, CipherError> {
    let glyph = u16::try_from(symbol).map_err(|_error| CipherError::InvalidAlphabetSize {
        alphabet_size,
        min: 1,
        max: MAX_ALPHABET_SIZE,
    })?;
    Ok(Glyph(glyph))
}

fn translate_additive(
    values: &[Glyph],
    alphabet_size: usize,
    mut shift_at: impl FnMut(usize) -> Result<usize, CipherError>,
    direction: Direction,
) -> Result<Vec<Glyph>, CipherError> {
    let mut output = Vec::with_capacity(values.len());
    for (position, glyph) in values.iter().copied().enumerate() {
        let symbol = symbol_from_glyph(glyph, alphabet_size)?;
        let shift = shift_at(position)? % alphabet_size;
        output.push(glyph_from_symbol(
            combine_additive(symbol, shift, alphabet_size, direction),
            alphabet_size,
        )?);
    }
    Ok(output)
}

fn periodic_shift_at(shifts: &[usize], position: usize) -> Result<usize, CipherError> {
    if shifts.is_empty() {
        return Err(CipherError::InternalInvariant {
            context: "empty periodic shift lookup",
        });
    }
    let offset = position % shifts.len();
    shifts
        .get(offset)
        .copied()
        .ok_or(CipherError::InternalInvariant {
            context: "periodic shift lookup",
        })
}

fn progressive_shift_at(key: &IncrementingWheelKey, position: usize) -> usize {
    let position_mod = position % key.alphabet_size;
    let stepped = (position_mod * key.step) % key.alphabet_size;
    (key.start + stepped) % key.alphabet_size
}

fn combine_additive(
    symbol: usize,
    shift: usize,
    alphabet_size: usize,
    direction: Direction,
) -> usize {
    match direction {
        Direction::Encrypt => (symbol + shift) % alphabet_size,
        Direction::Decrypt => (symbol + alphabet_size - shift) % alphabet_size,
    }
}

pub(crate) fn agl_compose(g: (usize, usize), h: (usize, usize), n: usize) -> (usize, usize) {
    let g_a = g.0 % n;
    let g_b = g.1 % n;
    let h_a = h.0 % n;
    let h_b = h.1 % n;
    ((g_a * h_a) % n, (((g_a * h_b) % n) + g_b) % n)
}

pub(crate) fn agl_inverse(g: (usize, usize), n: usize) -> Option<(usize, usize)> {
    let a_inv = mul_inverse_mod(g.0, n)?;
    Some((a_inv, neg_mod((a_inv * (g.1 % n)) % n, n)))
}

pub(crate) fn agl_apply(g: (usize, usize), x: usize, n: usize) -> usize {
    (((g.0 % n) * (x % n)) % n + (g.1 % n)) % n
}

pub(crate) fn agl_coset_symbol(g: (usize, usize), x0: usize, n: usize) -> usize {
    agl_apply(g, x0, n)
}

pub(crate) fn mul_inverse_mod(a: usize, n: usize) -> Option<usize> {
    if n < 2 || a.is_multiple_of(n) {
        return None;
    }
    Some(pow_mod(a % n, n - 2, n))
}

pub(crate) fn sub_mod(a: usize, b: usize, n: usize) -> usize {
    ((a % n) + n - (b % n)) % n
}

pub(crate) fn neg_mod(t: usize, n: usize) -> usize {
    (n - (t % n)) % n
}

pub(crate) fn quadratic_residues_mod(n: usize) -> Vec<usize> {
    let mut residues = Vec::new();
    let mut seen = vec![false; n];
    for value in 1..n {
        let residue = (value * value) % n;
        if let Some(seen_residue) = seen.get_mut(residue)
            && !*seen_residue
        {
            *seen_residue = true;
            residues.push(residue);
        }
    }
    residues.sort_unstable();
    residues
}

fn agl_step_lookup(
    state: (usize, usize),
    key: &AglGakKey,
) -> Result<BTreeMap<usize, usize>, CipherError> {
    let mut lookup = BTreeMap::new();
    for (letter, &element) in key.letter_elements.iter().enumerate() {
        let next_state = agl_compose(state, element, key.alphabet_size);
        let symbol = agl_coset_symbol(next_state, key.reference_point, key.alphabet_size);
        if lookup.insert(symbol, letter).is_some() {
            return Err(CipherError::InternalInvariant {
                context: "AGL step lookup duplicate coset",
            });
        }
    }
    Ok(lookup)
}

fn pow_mod(mut base: usize, mut exponent: usize, n: usize) -> usize {
    let mut acc = 1 % n;
    base %= n;
    while exponent > 0 {
        if exponent % 2 == 1 {
            acc = (acc * base) % n;
        }
        base = (base * base) % n;
        exponent /= 2;
    }
    acc
}

fn is_quadratic_residue_mod(multiplier: usize, n: usize) -> bool {
    quadratic_residues_mod(n).contains(&multiplier)
}

fn is_prime(n: usize) -> bool {
    if n < 2 {
        return false;
    }
    if n == 2 {
        return true;
    }
    if n.is_multiple_of(2) {
        return false;
    }
    let mut divisor = 3usize;
    while divisor <= n / divisor {
        if n.is_multiple_of(divisor) {
            return false;
        }
        divisor += 2;
    }
    true
}

fn translate_chaocipher(
    values: &[Glyph],
    key: &ChaocipherKey,
    direction: Direction,
) -> Result<Vec<Glyph>, CipherError> {
    let mut left = key.left.clone();
    let mut right = key.right.clone();
    let mut output = Vec::with_capacity(values.len());

    for glyph in values.iter().copied() {
        let input = symbol_from_glyph(glyph, key.alphabet_size)?;
        let (cipher_symbol, plain_symbol, output_symbol) = match direction {
            Direction::Encrypt => {
                let position = symbol_position(&right, input, "Chaocipher right")?;
                let cipher = symbol_at(&left, position, "Chaocipher left")?;
                (cipher, input, cipher)
            }
            Direction::Decrypt => {
                let position = symbol_position(&left, input, "Chaocipher left")?;
                let plain = symbol_at(&right, position, "Chaocipher right")?;
                (input, plain, plain)
            }
        };
        output.push(glyph_from_symbol(output_symbol, key.alphabet_size)?);
        permute_chaocipher_alphabets(
            &mut left,
            &mut right,
            cipher_symbol,
            plain_symbol,
            key.alphabet_size,
        )?;
    }

    Ok(output)
}

fn symbol_position(
    values: &[usize],
    symbol: usize,
    label: &'static str,
) -> Result<usize, CipherError> {
    values
        .iter()
        .position(|&candidate| candidate == symbol)
        .ok_or(CipherError::InternalInvariant { context: label })
}

fn symbol_at(values: &[usize], position: usize, label: &'static str) -> Result<usize, CipherError> {
    values
        .get(position)
        .copied()
        .ok_or(CipherError::InternalInvariant { context: label })
}

fn permute_chaocipher_alphabets(
    left: &mut Vec<usize>,
    right: &mut Vec<usize>,
    cipher_symbol: usize,
    plain_symbol: usize,
    alphabet_size: usize,
) -> Result<(), CipherError> {
    let nadir = alphabet_size / 2;

    rotate_symbol_to_front(left, cipher_symbol, "Chaocipher left rotate")?;
    move_position(left, 1, nadir, "Chaocipher left tab")?;

    rotate_symbol_to_front(right, plain_symbol, "Chaocipher right rotate")?;
    rotate_left_one(right, "Chaocipher right extra rotate")?;
    move_position(right, 2, nadir, "Chaocipher right tab")?;

    Ok(())
}

fn rotate_symbol_to_front(
    values: &mut [usize],
    symbol: usize,
    label: &'static str,
) -> Result<(), CipherError> {
    let position = symbol_position(values, symbol, label)?;
    values.rotate_left(position);
    Ok(())
}

fn rotate_left_one(values: &mut [usize], label: &'static str) -> Result<(), CipherError> {
    if values.is_empty() {
        return Err(CipherError::InternalInvariant { context: label });
    }
    values.rotate_left(1);
    Ok(())
}

fn move_position(
    values: &mut Vec<usize>,
    from: usize,
    to: usize,
    label: &'static str,
) -> Result<(), CipherError> {
    if from >= values.len() {
        return Err(CipherError::InternalInvariant { context: label });
    }
    let value = values.remove(from);
    if to > values.len() {
        return Err(CipherError::InternalInvariant { context: label });
    }
    values.insert(to, value);
    Ok(())
}

fn translate_deck_cipher(
    values: &[Glyph],
    key: &DeckCipherKey,
    direction: Direction,
) -> Result<Vec<Glyph>, CipherError> {
    let mut deck = key.deck.clone();
    let mut output = Vec::with_capacity(values.len());

    for glyph in values.iter().copied() {
        let symbol = symbol_from_glyph(glyph, key.alphabet_size)?;
        let shift = next_deck_keystream(&mut deck, key)?;
        output.push(glyph_from_symbol(
            combine_additive(symbol, shift, key.alphabet_size, direction),
            key.alphabet_size,
        )?);
    }

    Ok(output)
}

fn next_deck_keystream(deck: &mut Vec<usize>, key: &DeckCipherKey) -> Result<usize, CipherError> {
    move_card_down(deck, key.control_a, 1, "deck control A move")?;
    move_card_down(deck, key.control_b, 2, "deck control B move")?;
    triple_cut(deck, key.control_a, key.control_b)?;
    count_cut(deck, key)?;

    let top = top_card(deck)?;
    let count = deck_count_value(top, key);
    let selected = symbol_at(deck, count, "deck output lookup")?;
    Ok(selected % key.alphabet_size)
}

fn move_card_down(
    deck: &mut Vec<usize>,
    card: usize,
    steps: usize,
    label: &'static str,
) -> Result<(), CipherError> {
    if deck.len() < 2 {
        return Err(CipherError::InternalInvariant { context: label });
    }
    let Some(position) = deck.iter().position(|&candidate| candidate == card) else {
        return Err(CipherError::InternalInvariant { context: label });
    };
    let value = deck.remove(position);
    let len_after_remove = deck.len();
    let target = wrapped_down_position(position, steps, len_after_remove)?;
    if target > deck.len() {
        return Err(CipherError::InternalInvariant { context: label });
    }
    deck.insert(target, value);
    Ok(())
}

fn wrapped_down_position(
    position: usize,
    steps: usize,
    len_after_remove: usize,
) -> Result<usize, CipherError> {
    if len_after_remove == 0 {
        return Err(CipherError::InternalInvariant {
            context: "deck move in empty deck",
        });
    }
    if steps == 0 {
        return Ok(position);
    }
    let shifted = position
        .checked_add(steps)
        .and_then(|value| value.checked_sub(1))
        .ok_or(CipherError::InternalInvariant {
            context: "deck move offset",
        })?;
    Ok(1 + shifted % len_after_remove)
}

fn triple_cut(
    deck: &mut Vec<usize>,
    control_a: usize,
    control_b: usize,
) -> Result<(), CipherError> {
    let first_control = symbol_position(deck, control_a, "deck triple cut A")?;
    let second_control = symbol_position(deck, control_b, "deck triple cut B")?;
    let first = first_control.min(second_control);
    let second = first_control.max(second_control);

    let mut before = Vec::new();
    let mut middle = Vec::new();
    let mut after = Vec::new();
    for (index, card) in deck.iter().copied().enumerate() {
        if index < first {
            before.push(card);
        } else if index <= second {
            middle.push(card);
        } else {
            after.push(card);
        }
    }

    let mut permuted = Vec::with_capacity(deck.len());
    permuted.extend(after);
    permuted.extend(middle);
    permuted.extend(before);
    *deck = permuted;
    Ok(())
}

fn count_cut(deck: &mut Vec<usize>, key: &DeckCipherKey) -> Result<(), CipherError> {
    let bottom = bottom_card(deck)?;
    let count = deck_count_value(bottom, key);
    if count == 0 || count >= deck.len().saturating_sub(1) {
        return Ok(());
    }

    let bottom_index = deck.len().saturating_sub(1);
    let mut top = Vec::new();
    let mut middle = Vec::new();
    let mut bottom_card = None;
    for (index, card) in deck.iter().copied().enumerate() {
        if index < count {
            top.push(card);
        } else if index < bottom_index {
            middle.push(card);
        } else {
            bottom_card = Some(card);
        }
    }

    let Some(bottom) = bottom_card else {
        return Err(CipherError::InternalInvariant {
            context: "deck count-cut bottom",
        });
    };
    let mut cut = Vec::with_capacity(deck.len());
    cut.extend(middle);
    cut.extend(top);
    cut.push(bottom);
    *deck = cut;
    Ok(())
}

fn top_card(deck: &[usize]) -> Result<usize, CipherError> {
    deck.first().copied().ok_or(CipherError::InternalInvariant {
        context: "deck top card",
    })
}

fn bottom_card(deck: &[usize]) -> Result<usize, CipherError> {
    deck.last().copied().ok_or(CipherError::InternalInvariant {
        context: "deck bottom card",
    })
}

fn deck_count_value(card: usize, key: &DeckCipherKey) -> usize {
    if card == key.control_a || card == key.control_b {
        key.alphabet_size - 1
    } else {
        (card % (key.alphabet_size - 1)) + 1
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AglGak, AglGakKey, AglMultiplierSubgroup, AnyCipher, Caesar, CaesarKey, Chaocipher,
        ChaocipherKey, Cipher, CipherError, CosetReadout, DeckCipher, DeckCipherKey,
        EYE_READING_ALPHABET_SIZE, Gak, GakKey, GakKeyOptions, GakSubgroupConstraint, Identity,
        IncrementingWheel, IncrementingWheelKey, Transposition, TranspositionKey, Vigenere,
        VigenereKey, agl_apply, agl_compose, agl_gak_decrypt, agl_gak_encrypt, caesar_decrypt,
        caesar_encrypt, chaocipher_decrypt, chaocipher_encrypt, deck_cipher_decrypt,
        deck_cipher_encrypt, gak_decrypt, gak_encrypt, identity_decrypt, identity_encrypt,
        incrementing_wheel_decrypt, incrementing_wheel_encrypt, transposition_decrypt,
        transposition_encrypt, vigenere_decrypt, vigenere_encrypt,
    };
    use crate::glyph::Glyph;
    use crate::isomorph::PatternSignature;
    use crate::null::SplitMix64;

    #[test]
    fn identity_cipher_passes_through_and_trait_matches_free_functions() {
        let cipher = Identity;
        let plaintext = glyphs(&[4, 1, 3, 1, 0]);
        let ciphertext = identity_encrypt(&plaintext).unwrap();

        assert_eq!(cipher.name(), "identity");
        assert_eq!(ciphertext, plaintext);
        assert_eq!(cipher.encrypt(&(), &plaintext).unwrap(), ciphertext);
        assert_eq!(
            cipher.decrypt(&(), &ciphertext).unwrap(),
            identity_decrypt(&ciphertext).unwrap()
        );
    }

    #[test]
    fn transposition_known_tiny_vector_and_trait_matches_free_functions() {
        let cipher = Transposition;
        let key = TranspositionKey::new(4, vec![2, 0, 3, 1]).unwrap();
        let plaintext = glyphs(&[0, 1, 2, 3, 4, 5, 6]);
        let ciphertext = transposition_encrypt(&plaintext, &key).unwrap();

        assert_eq!(values(&ciphertext), vec![1, 3, 0, 2, 5, 4, 6]);
        assert_eq!(transposition_decrypt(&ciphertext, &key).unwrap(), plaintext);
        assert_eq!(cipher.name(), "transposition");
        assert_eq!(cipher.encrypt(&key, &plaintext).unwrap(), ciphertext);
        assert_eq!(
            cipher.decrypt(&key, &ciphertext).unwrap(),
            transposition_decrypt(&ciphertext, &key).unwrap()
        );
    }

    #[test]
    fn caesar_known_tiny_vector() {
        let key = CaesarKey::new(5, 2).unwrap();
        let plaintext = glyphs(&[0, 1, 4]);
        let ciphertext = caesar_encrypt(&plaintext, &key).unwrap();
        assert_eq!(values(&ciphertext), vec![2, 3, 1]);
        assert_eq!(caesar_decrypt(&ciphertext, &key).unwrap(), plaintext);
    }

    #[test]
    fn caesar_trait_matches_free_functions() {
        let cipher = Caesar;
        let key = CaesarKey::new(5, 2).unwrap();
        let plaintext = glyphs(&[0, 1, 4]);
        let ciphertext = caesar_encrypt(&plaintext, &key).unwrap();

        assert_eq!(cipher.name(), "Caesar");
        assert_eq!(cipher.encrypt(&key, &plaintext).unwrap(), ciphertext);
        assert_eq!(
            cipher.decrypt(&key, &ciphertext).unwrap(),
            caesar_decrypt(&ciphertext, &key).unwrap()
        );
    }

    #[test]
    fn vigenere_known_tiny_vector() {
        let key = VigenereKey::new(5, vec![1, 0, 3]).unwrap();
        let plaintext = glyphs(&[0, 4, 2, 3]);
        let ciphertext = vigenere_encrypt(&plaintext, &key).unwrap();
        assert_eq!(values(&ciphertext), vec![1, 4, 0, 4]);
        assert_eq!(vigenere_decrypt(&ciphertext, &key).unwrap(), plaintext);
    }

    #[test]
    fn vigenere_trait_matches_free_functions() {
        let cipher = Vigenere;
        let key = VigenereKey::new(5, vec![1, 0, 3]).unwrap();
        let plaintext = glyphs(&[0, 4, 2, 3]);
        let ciphertext = vigenere_encrypt(&plaintext, &key).unwrap();

        assert_eq!(cipher.name(), "Vigenere");
        assert_eq!(cipher.encrypt(&key, &plaintext).unwrap(), ciphertext);
        assert_eq!(
            cipher.decrypt(&key, &ciphertext).unwrap(),
            vigenere_decrypt(&ciphertext, &key).unwrap()
        );
    }

    #[test]
    fn incrementing_wheel_known_tiny_vector() {
        let key = IncrementingWheelKey::new(5, 1, 2).unwrap();
        let plaintext = glyphs(&[0, 1, 2, 3]);
        let ciphertext = incrementing_wheel_encrypt(&plaintext, &key).unwrap();
        assert_eq!(values(&ciphertext), vec![1, 4, 2, 0]);
        assert_eq!(
            incrementing_wheel_decrypt(&ciphertext, &key).unwrap(),
            plaintext
        );
    }

    #[test]
    fn incrementing_wheel_trait_matches_free_functions() {
        let cipher = IncrementingWheel;
        let key = IncrementingWheelKey::new(5, 1, 2).unwrap();
        let plaintext = glyphs(&[0, 1, 2, 3]);
        let ciphertext = incrementing_wheel_encrypt(&plaintext, &key).unwrap();

        assert_eq!(cipher.name(), "incrementing-wheel");
        assert_eq!(cipher.encrypt(&key, &plaintext).unwrap(), ciphertext);
        assert_eq!(
            cipher.decrypt(&key, &ciphertext).unwrap(),
            incrementing_wheel_decrypt(&ciphertext, &key).unwrap()
        );
    }

    #[test]
    fn chaocipher_known_tiny_vector() {
        let key = ChaocipherKey::identity(7).unwrap();
        let plaintext = glyphs(&[0, 2, 4, 6]);
        let ciphertext = chaocipher_encrypt(&plaintext, &key).unwrap();
        assert_eq!(values(&ciphertext), vec![0, 2, 2, 4]);
        assert_eq!(chaocipher_decrypt(&ciphertext, &key).unwrap(), plaintext);
    }

    #[test]
    fn chaocipher_trait_matches_free_functions() {
        let cipher = Chaocipher;
        let key = ChaocipherKey::identity(7).unwrap();
        let plaintext = glyphs(&[0, 2, 4, 6]);
        let ciphertext = chaocipher_encrypt(&plaintext, &key).unwrap();

        assert_eq!(cipher.name(), "Chaocipher");
        assert_eq!(cipher.encrypt(&key, &plaintext).unwrap(), ciphertext);
        assert_eq!(
            cipher.decrypt(&key, &ciphertext).unwrap(),
            chaocipher_decrypt(&ciphertext, &key).unwrap()
        );
    }

    #[test]
    fn chaocipher_matches_classic_published_vector() {
        let left = alphabet("HXUCZVAMDSLKPEFJRIGTWOBNYQ");
        let right = alphabet("PTLNBQDEOYSFAVZKGJRIHWXUMC");
        let key = ChaocipherKey::new(26, left, right).unwrap();
        let plaintext = alphabet("WELLDONEISBETTERTHANWELLSAID");
        let ciphertext = chaocipher_encrypt(&glyphs_from_usize(&plaintext), &key).unwrap();
        assert_eq!(letters(&ciphertext), "OAHQHCNYNXTSZJRRHJBYHQKSOUJY");
        assert_eq!(
            chaocipher_decrypt(&ciphertext, &key).unwrap(),
            glyphs_from_usize(&plaintext)
        );
    }

    #[test]
    fn deck_cipher_known_tiny_vector() {
        let key = DeckCipherKey::identity(5).unwrap();
        let plaintext = glyphs(&[0, 0, 0, 0]);
        let ciphertext = deck_cipher_encrypt(&plaintext, &key).unwrap();
        assert_eq!(values(&ciphertext), vec![3, 0, 3, 0]);
        assert_eq!(deck_cipher_decrypt(&ciphertext, &key).unwrap(), plaintext);
    }

    #[test]
    fn deck_cipher_trait_matches_free_functions() {
        let cipher = DeckCipher;
        let key = DeckCipherKey::identity(5).unwrap();
        let plaintext = glyphs(&[0, 0, 0, 0]);
        let ciphertext = deck_cipher_encrypt(&plaintext, &key).unwrap();

        assert_eq!(cipher.name(), "deck");
        assert_eq!(cipher.encrypt(&key, &plaintext).unwrap(), ciphertext);
        assert_eq!(
            cipher.decrypt(&key, &ciphertext).unwrap(),
            deck_cipher_decrypt(&ciphertext, &key).unwrap()
        );
    }

    #[test]
    fn agl_gak_matches_hand_computed_n5() {
        let key = AglGakKey::new(
            5,
            AglMultiplierSubgroup::Full,
            0,
            (1, 0),
            vec![(1, 1), (1, 2), (2, 0)],
        )
        .unwrap();

        let first_plaintext = glyphs(&[0, 0]);
        let first_ciphertext = agl_gak_encrypt(&first_plaintext, &key).unwrap();
        assert_eq!(values(&first_ciphertext), vec![1, 2]);
        assert_eq!(
            agl_gak_decrypt(&first_ciphertext, &key).unwrap(),
            first_plaintext
        );

        let second_plaintext = glyphs(&[2, 0]);
        let second_ciphertext = agl_gak_encrypt(&second_plaintext, &key).unwrap();
        assert_eq!(values(&second_ciphertext), vec![0, 2]);
        assert_eq!(
            agl_gak_decrypt(&second_ciphertext, &key).unwrap(),
            second_plaintext
        );
    }

    #[test]
    fn agl_gak_trait_matches_free_functions() {
        let cipher = AglGak;
        let key = AglGakKey::new(
            5,
            AglMultiplierSubgroup::Full,
            0,
            (1, 0),
            vec![(1, 1), (1, 2), (2, 0)],
        )
        .unwrap();
        let plaintext = glyphs(&[2, 0]);
        let ciphertext = agl_gak_encrypt(&plaintext, &key).unwrap();

        assert_eq!(cipher.name(), "AGL-GAK");
        assert_eq!(cipher.encrypt(&key, &plaintext).unwrap(), ciphertext);
        assert_eq!(
            cipher.decrypt(&key, &ciphertext).unwrap(),
            agl_gak_decrypt(&ciphertext, &key).unwrap()
        );
    }

    #[test]
    fn agl_gak_wrong_left_update_convention_differs() {
        let key = AglGakKey::new(
            5,
            AglMultiplierSubgroup::Full,
            0,
            (1, 0),
            vec![(1, 1), (1, 2), (2, 0)],
        )
        .unwrap();
        let plaintext = glyphs(&[2, 0]);
        let right_update = agl_gak_encrypt(&plaintext, &key).unwrap();
        let wrong_left_update = wrong_left_update_encrypt(&plaintext, &key);
        assert_eq!(values(&right_update), vec![0, 2]);
        assert_eq!(wrong_left_update, vec![0, 1]);
        assert_ne!(values(&right_update), wrong_left_update);
    }

    #[test]
    fn caesar_round_trips_random_plaintexts() {
        let small_keys = [
            CaesarKey::new(7, 0).unwrap(),
            CaesarKey::new(7, 19).unwrap(),
        ];
        let eye_keys = [
            CaesarKey::new(EYE_READING_ALPHABET_SIZE, 1).unwrap(),
            CaesarKey::new(EYE_READING_ALPHABET_SIZE, 82).unwrap(),
        ];
        for (index, key) in small_keys.iter().chain(eye_keys.iter()).enumerate() {
            let plaintext =
                random_plaintext(0x6361_6573_6172 ^ index as u64, 257, key.alphabet_size());
            let ciphertext = caesar_encrypt(&plaintext, key).unwrap();
            assert_eq!(caesar_decrypt(&ciphertext, key).unwrap(), plaintext);
        }
    }

    #[test]
    fn transposition_round_trips_random_plaintexts() {
        let keys = [
            TranspositionKey::new(1, vec![0]).unwrap(),
            TranspositionKey::new(4, vec![2, 0, 3, 1]).unwrap(),
            TranspositionKey::new(7, vec![3, 0, 6, 1, 5, 2, 4]).unwrap(),
        ];
        for (index, key) in keys.iter().enumerate() {
            let plaintext = random_plaintext(0x7472_616e_7370 ^ index as u64, 263, 11);
            let ciphertext = transposition_encrypt(&plaintext, key).unwrap();
            assert_eq!(transposition_decrypt(&ciphertext, key).unwrap(), plaintext);
        }
    }

    #[test]
    fn vigenere_round_trips_random_plaintexts() {
        let small_keys = [
            VigenereKey::new(7, vec![0]).unwrap(),
            VigenereKey::new(7, vec![1, 3, 6, 2]).unwrap(),
        ];
        let eye_keys = [
            VigenereKey::new(EYE_READING_ALPHABET_SIZE, vec![0, 1, 82]).unwrap(),
            VigenereKey::new(EYE_READING_ALPHABET_SIZE, vec![5, 17, 29, 41, 80]).unwrap(),
        ];
        for (index, key) in small_keys.iter().chain(eye_keys.iter()).enumerate() {
            let plaintext =
                random_plaintext(0x7669_6765_6e65 ^ index as u64, 313, key.alphabet_size());
            let ciphertext = vigenere_encrypt(&plaintext, key).unwrap();
            assert_eq!(vigenere_decrypt(&ciphertext, key).unwrap(), plaintext);
        }
    }

    #[test]
    fn incrementing_wheel_round_trips_random_plaintexts() {
        let small_keys = [
            IncrementingWheelKey::new(7, 0, 1).unwrap(),
            IncrementingWheelKey::new(7, 3, 5).unwrap(),
        ];
        let eye_keys = [
            IncrementingWheelKey::new(EYE_READING_ALPHABET_SIZE, 0, 1).unwrap(),
            IncrementingWheelKey::new(EYE_READING_ALPHABET_SIZE, 19, 37).unwrap(),
        ];
        for (index, key) in small_keys.iter().chain(eye_keys.iter()).enumerate() {
            let plaintext =
                random_plaintext(0x7768_6565_6c21 ^ index as u64, 331, key.alphabet_size());
            let ciphertext = incrementing_wheel_encrypt(&plaintext, key).unwrap();
            assert_eq!(
                incrementing_wheel_decrypt(&ciphertext, key).unwrap(),
                plaintext
            );
        }
    }

    #[test]
    fn chaocipher_round_trips_random_plaintexts() {
        let small_keys = [
            ChaocipherKey::identity(7).unwrap(),
            ChaocipherKey::new(7, vec![3, 1, 6, 0, 5, 2, 4], vec![2, 4, 0, 6, 1, 5, 3]).unwrap(),
        ];
        let eye_keys = [
            ChaocipherKey::identity(EYE_READING_ALPHABET_SIZE).unwrap(),
            ChaocipherKey::new(
                EYE_READING_ALPHABET_SIZE,
                shuffled_permutation(EYE_READING_ALPHABET_SIZE, 0x0063_6861_6f6c),
                shuffled_permutation(EYE_READING_ALPHABET_SIZE, 0x0063_6861_6f72),
            )
            .unwrap(),
        ];
        for (index, key) in small_keys.iter().chain(eye_keys.iter()).enumerate() {
            let plaintext =
                random_plaintext(0x6368_616f_2121 ^ index as u64, 211, key.alphabet_size());
            let ciphertext = chaocipher_encrypt(&plaintext, key).unwrap();
            assert_eq!(chaocipher_decrypt(&ciphertext, key).unwrap(), plaintext);
        }
    }

    #[test]
    fn deck_cipher_round_trips_random_plaintexts() {
        let small_keys = [
            DeckCipherKey::identity(7).unwrap(),
            DeckCipherKey::new(7, vec![3, 1, 6, 0, 5, 2, 4], 5, 2).unwrap(),
        ];
        let eye_keys = [
            DeckCipherKey::identity(EYE_READING_ALPHABET_SIZE).unwrap(),
            DeckCipherKey::new(
                EYE_READING_ALPHABET_SIZE,
                shuffled_permutation(EYE_READING_ALPHABET_SIZE, 0x0064_6563_6b83),
                17,
                80,
            )
            .unwrap(),
        ];
        for (index, key) in small_keys.iter().chain(eye_keys.iter()).enumerate() {
            let plaintext =
                random_plaintext(0x6465_636b_2121 ^ index as u64, 233, key.alphabet_size());
            let ciphertext = deck_cipher_encrypt(&plaintext, key).unwrap();
            assert_eq!(deck_cipher_decrypt(&ciphertext, key).unwrap(), plaintext);
        }
    }

    #[test]
    fn agl_gak_round_trips_random_plaintexts() {
        let keys = [
            AglGakKey::identity(7, AglMultiplierSubgroup::Full).unwrap(),
            AglGakKey::identity(7, AglMultiplierSubgroup::QuadraticResidues).unwrap(),
            AglGakKey::new(
                7,
                AglMultiplierSubgroup::Full,
                0,
                (3, 4),
                vec![(1, 0), (2, 1), (3, 2), (4, 3), (5, 4), (6, 5), (1, 6)],
            )
            .unwrap(),
            AglGakKey::identity(EYE_READING_ALPHABET_SIZE, AglMultiplierSubgroup::Full).unwrap(),
            AglGakKey::identity(
                EYE_READING_ALPHABET_SIZE,
                AglMultiplierSubgroup::QuadraticResidues,
            )
            .unwrap(),
        ];
        for (index, key) in keys.iter().enumerate() {
            let plaintext = random_plaintext(
                0x6167_6c5f_6761_6b21 ^ index as u64,
                271,
                key.letter_elements().len(),
            );
            let ciphertext = agl_gak_encrypt(&plaintext, key).unwrap();
            assert_eq!(agl_gak_decrypt(&ciphertext, key).unwrap(), plaintext);
        }
    }

    #[test]
    fn gak_round_trips_random_plaintexts_small_and_eye() {
        // Deck-realization (S_n, hidden subgroup S_{n-1}) GAK keys: one random
        // small permutation per plaintext letter, then the full 83-symbol size.
        let small_letters = random_distinct_coset_letters(7, 7, 0x6761_6b5f_736d);
        let eye_letters = random_distinct_coset_letters(
            EYE_READING_ALPHABET_SIZE,
            EYE_READING_ALPHABET_SIZE,
            0x6761_6b5f_6579,
        );
        let keys = [
            GakKey::deck(7, small_letters, GakKeyOptions::default()).unwrap(),
            GakKey::deck(
                EYE_READING_ALPHABET_SIZE,
                eye_letters,
                GakKeyOptions::default(),
            )
            .unwrap(),
        ];
        for (index, key) in keys.iter().enumerate() {
            let plaintext = random_plaintext(
                0x6761_6b5f_7274 ^ index as u64,
                277,
                key.plaintext_letters().len(),
            );
            let ciphertext = gak_encrypt(&plaintext, key).unwrap();
            assert_eq!(gak_decrypt(&ciphertext, key).unwrap(), plaintext);
        }
    }

    #[test]
    fn gak_trait_matches_free_functions() {
        let cipher = Gak;
        let n = 5usize;
        let letters = (0..n).map(|shift| rotation_permutation(n, shift)).collect();
        let key = GakKey::deck(n, letters, GakKeyOptions::default()).unwrap();
        let plaintext = glyphs(&[0, 1, 4, 2]);
        let ciphertext = gak_encrypt(&plaintext, &key).unwrap();

        assert_eq!(cipher.name(), "GAK");
        assert_eq!(cipher.encrypt(&key, &plaintext).unwrap(), ciphertext);
        assert_eq!(
            cipher.decrypt(&key, &ciphertext).unwrap(),
            gak_decrypt(&ciphertext, &key).unwrap()
        );
    }

    #[test]
    fn any_cipher_caesar_matches_free_functions_and_round_trips() {
        let key = CaesarKey::new(5, 2).unwrap();
        let plaintext = glyphs(&[0, 1, 4]);
        let expected = caesar_encrypt(&plaintext, &key).unwrap();
        let cipher = AnyCipher::Caesar(key);

        let ciphertext = cipher.encrypt(&plaintext).unwrap();
        assert_eq!(cipher.name(), "Caesar");
        assert_eq!(ciphertext, expected);
        assert_eq!(cipher.decrypt(&ciphertext).unwrap(), plaintext);
    }

    #[test]
    fn any_cipher_identity_matches_free_functions_and_round_trips() {
        let plaintext = glyphs(&[0, 4, 2, 3]);
        let expected = identity_encrypt(&plaintext).unwrap();
        let cipher = AnyCipher::Identity;

        let ciphertext = cipher.encrypt(&plaintext).unwrap();
        assert_eq!(cipher.name(), "identity");
        assert_eq!(ciphertext, expected);
        assert_eq!(cipher.decrypt(&ciphertext).unwrap(), plaintext);
    }

    #[test]
    fn any_cipher_transposition_matches_free_functions_and_round_trips() {
        let key = TranspositionKey::new(3, vec![1, 2, 0]).unwrap();
        let plaintext = glyphs(&[0, 1, 2, 3, 4]);
        let expected = transposition_encrypt(&plaintext, &key).unwrap();
        let cipher = AnyCipher::Transposition(key);

        let ciphertext = cipher.encrypt(&plaintext).unwrap();
        assert_eq!(cipher.name(), "transposition");
        assert_eq!(ciphertext, expected);
        assert_eq!(cipher.decrypt(&ciphertext).unwrap(), plaintext);
    }

    #[test]
    fn any_cipher_vigenere_matches_free_functions_and_round_trips() {
        let key = VigenereKey::new(5, vec![1, 0, 3]).unwrap();
        let plaintext = glyphs(&[0, 4, 2, 3]);
        let expected = vigenere_encrypt(&plaintext, &key).unwrap();
        let cipher = AnyCipher::Vigenere(key);

        let ciphertext = cipher.encrypt(&plaintext).unwrap();
        assert_eq!(cipher.name(), "Vigenere");
        assert_eq!(ciphertext, expected);
        assert_eq!(cipher.decrypt(&ciphertext).unwrap(), plaintext);
    }

    #[test]
    fn any_cipher_incrementing_wheel_matches_free_functions_and_round_trips() {
        let key = IncrementingWheelKey::new(5, 1, 2).unwrap();
        let plaintext = glyphs(&[0, 1, 2, 3]);
        let expected = incrementing_wheel_encrypt(&plaintext, &key).unwrap();
        let cipher = AnyCipher::IncrementingWheel(key);

        let ciphertext = cipher.encrypt(&plaintext).unwrap();
        assert_eq!(cipher.name(), "incrementing-wheel");
        assert_eq!(ciphertext, expected);
        assert_eq!(cipher.decrypt(&ciphertext).unwrap(), plaintext);
    }

    #[test]
    fn any_cipher_chaocipher_matches_free_functions_and_round_trips() {
        let key = ChaocipherKey::identity(7).unwrap();
        let plaintext = glyphs(&[0, 2, 4, 6]);
        let expected = chaocipher_encrypt(&plaintext, &key).unwrap();
        let cipher = AnyCipher::Chaocipher(key);

        let ciphertext = cipher.encrypt(&plaintext).unwrap();
        assert_eq!(cipher.name(), "Chaocipher");
        assert_eq!(ciphertext, expected);
        assert_eq!(cipher.decrypt(&ciphertext).unwrap(), plaintext);
    }

    #[test]
    fn any_cipher_deck_cipher_matches_free_functions_and_round_trips() {
        let key = DeckCipherKey::identity(5).unwrap();
        let plaintext = glyphs(&[0, 0, 0, 0]);
        let expected = deck_cipher_encrypt(&plaintext, &key).unwrap();
        let cipher = AnyCipher::DeckCipher(key);

        let ciphertext = cipher.encrypt(&plaintext).unwrap();
        assert_eq!(cipher.name(), "deck");
        assert_eq!(ciphertext, expected);
        assert_eq!(cipher.decrypt(&ciphertext).unwrap(), plaintext);
    }

    #[test]
    fn any_cipher_agl_gak_matches_free_functions_and_round_trips() {
        let key = AglGakKey::new(
            5,
            AglMultiplierSubgroup::Full,
            0,
            (1, 0),
            vec![(1, 1), (1, 2), (2, 0)],
        )
        .unwrap();
        let plaintext = glyphs(&[2, 0]);
        let expected = agl_gak_encrypt(&plaintext, &key).unwrap();
        let cipher = AnyCipher::AglGak(key);

        let ciphertext = cipher.encrypt(&plaintext).unwrap();
        assert_eq!(cipher.name(), "AGL-GAK");
        assert_eq!(ciphertext, expected);
        assert_eq!(cipher.decrypt(&ciphertext).unwrap(), plaintext);
    }

    #[test]
    fn any_cipher_gak_matches_free_functions_and_round_trips() {
        let n = 5usize;
        let letters: Vec<Vec<usize>> = (0..n).map(|shift| rotation_permutation(n, shift)).collect();
        let key = GakKey::deck(n, letters, GakKeyOptions::default()).unwrap();
        let plaintext = glyphs(&[0, 1, 4, 2]);
        let expected = gak_encrypt(&plaintext, &key).unwrap();
        let cipher = AnyCipher::Gak(key);

        let ciphertext = cipher.encrypt(&plaintext).unwrap();
        assert_eq!(cipher.name(), "GAK");
        assert_eq!(ciphertext, expected);
        assert_eq!(cipher.decrypt(&ciphertext).unwrap(), plaintext);
    }

    #[test]
    fn gak_reduces_to_gctak_when_hidden_subgroup_trivial() {
        // Cyclic state group C_n realized as rotation permutations on 0..n with a
        // bijective TopCard readout: H is trivial, so GAK must equal GCTAK. The
        // independent reference is the cumulative-shift autokey on the rotation
        // amounts.
        let n = 11usize;
        let shifts = [0usize, 1, 3, 5, 7, 9, 2, 4, 6, 8, 10];
        let letters: Vec<Vec<usize>> = shifts.iter().map(|&s| rotation_permutation(n, s)).collect();
        let key = GakKey::deck(n, letters, GakKeyOptions::default()).unwrap();

        let plaintext = random_plaintext(0x6763_7461_6b21, 191, shifts.len());
        let ciphertext = gak_encrypt(&plaintext, &key).unwrap();
        let reference = gctak_rotation_reference(&plaintext, &shifts, n);
        assert_eq!(values(&ciphertext), reference);
        assert_eq!(gak_decrypt(&ciphertext, &key).unwrap(), plaintext);
    }

    #[test]
    fn gak_preserves_isomorph_pattern_on_repeated_phrase() {
        // A plaintext with a repeated phrase must produce ciphertext windows
        // whose first-occurrence equality patterns are identical at the repeats:
        // the perfect-isomorph signal the attack needs to bite on.
        let letters = random_distinct_coset_letters(7, 7, 0x6973_6f5f_6761);
        let key = GakKey::deck(7, letters, GakKeyOptions::default()).unwrap();

        let phrase = [1usize, 4, 1, 0, 3, 4];
        let mut plaintext_values = Vec::new();
        plaintext_values.extend_from_slice(&phrase);
        plaintext_values.extend_from_slice(&[2, 5, 0]);
        let first_start = plaintext_values.len();
        plaintext_values.extend_from_slice(&phrase);
        let plaintext = glyphs_from_usize(&plaintext_values);

        let ciphertext = gak_encrypt(&plaintext, &key).unwrap();
        let ct_owned = values_usize(&ciphertext);
        let ct_values: &[usize] = &ct_owned;

        // Both occurrences have length `phrase.len()`; fetch each via the
        // windows iterator so no range indexing is needed.
        let mut windows = ct_values.windows(phrase.len());
        let first_window = windows.next().unwrap();
        let first_signature = PatternSignature::from_window(first_window);
        let second_window = windows.nth(first_start - 1).unwrap();
        let second_signature = PatternSignature::from_window(second_window);
        assert_eq!(first_signature, second_signature);
        // Proving the *ciphertext* reproduces the isomorph: the CT window's own
        // first-occurrence pattern must be non-trivial (have a repeated symbol),
        // otherwise two all-distinct CT windows would also pass the equality
        // above without any isomorph being carried into the ciphertext. The
        // first/second signatures are equal, so checking either suffices.
        assert!(
            first_signature.has_repeated_symbol(),
            "ciphertext window {first_window:?} is all-distinct, so no isomorph is reproduced"
        );
    }

    #[test]
    fn gak_avoid_doubles_forbids_adjacent_equal_ciphertext() {
        // Surviving letters (rotations by 1..n, none in the identity coset)
        // never repeat a ciphertext symbol back-to-back under avoid_doubles.
        let n = 7usize;
        let letters: Vec<Vec<usize>> = (1..n).map(|s| rotation_permutation(n, s)).collect();
        let key = GakKey::deck(n, letters, avoid_doubles_options()).unwrap();

        let plaintext = random_plaintext(0x6e6f_5f64_626c, 211, key.plaintext_letters().len());
        let ciphertext = gak_encrypt(&plaintext, &key).unwrap();
        let ct_values = values_usize(&ciphertext);
        for pair in ct_values.windows(2) {
            if let [a, b] = pair {
                assert_ne!(a, b, "avoid_doubles produced adjacent-equal ciphertext");
            }
        }
        assert_eq!(gak_decrypt(&ciphertext, &key).unwrap(), plaintext);
    }

    #[test]
    fn gak_avoid_doubles_rejects_letter_in_identity_coset() {
        // The identity permutation (rotation by 0) fixes the readout coset of
        // the identity initial state, so avoid_doubles must reject it at
        // construction rather than silently allowing adjacent-equal ciphertext.
        let n = 7usize;
        // Pair the identity letter with a non-identity rotation so the only
        // failure cause is the identity-coset rule, not coset collision.
        let letters = vec![rotation_permutation(n, 0), rotation_permutation(n, 3)];
        let error = GakKey::deck(n, letters, avoid_doubles_options()).unwrap_err();
        // rotation(7,0) is the identity; its TopCard readout p^{-1}[0] = 0,
        // the base coset, so letter 0 is the offender.
        assert!(matches!(
            error,
            CipherError::GakLetterFixesCoset {
                letter_index: 0,
                coset: 0,
            }
        ));
    }

    #[test]
    fn gak_rejects_letters_sharing_a_coset() {
        // Two DISTINCT plaintext letters whose TopCard image (the position of
        // card 0) coincides collide on the same coset from the identity state,
        // so construction must fail (no panic). Both place card 0 at index 2 but
        // differ elsewhere, so this is a genuine coset collision, not equality.
        let n = 5usize;
        let letter_a = vec![1usize, 3, 0, 4, 2];
        let letter_b = vec![4usize, 1, 0, 2, 3];
        assert_ne!(letter_a, letter_b, "letters must be distinct permutations");
        let letters = vec![letter_a, letter_b];
        let error = GakKey::deck(n, letters, GakKeyOptions::default()).unwrap_err();
        // Under left-update p ∘ identity = p, the readout p^{-1}[0] = 2 for both.
        assert!(matches!(
            error,
            CipherError::GakLettersShareCoset {
                coset: 2,
                duplicate_index: 1,
            }
        ));
    }

    #[test]
    fn gak_rejects_non_permutation_letter() {
        // A malformed letter (repeats symbol 0, omits 4) is caught by the shared
        // validate_permutation helper rather than silently accepted.
        let n = 5usize;
        let letters = vec![vec![0usize, 1, 2, 3, 0]];
        let error = GakKey::deck(n, letters, GakKeyOptions::default()).unwrap_err();
        assert!(matches!(
            error,
            CipherError::DuplicatePermutationSymbol {
                label: "GAK plaintext letter",
                symbol: 0,
                ..
            }
        ));
    }

    #[test]
    fn gak_alternating_subgroup_rejects_odd_permutation() {
        // A single transposition is odd, so the A_n parity constraint rejects it.
        let n = 5usize;
        let mut odd = identity_usize(n);
        odd.swap(0, 1);
        let options = GakKeyOptions {
            avoid_doubles: false,
            subgroup: GakSubgroupConstraint::AlternatingGroup,
        };
        let error = GakKey::deck(n, vec![odd], options).unwrap_err();
        assert!(matches!(
            error,
            CipherError::GakLetterWrongParity { letter_index: 0 }
        ));
    }

    #[test]
    fn gak_round_trips_accepted_coset_table_key() {
        // A genuine, *coarser* right-coset projection of the Klein four-group
        // V_4 = {id, a, b, ab} on 0..4, hidden subgroup H = {id, a}. The cosets
        // are H (card-0 positions 0,1) and Hb (positions 2,3), so the projection
        // coset_of = [0,0,1,1] merges pairs and emits only |C| = 2 symbols. This
        // is a valid key the new reachable-state validator must accept and that
        // must round-trip exactly.
        let n = 4usize;
        let a = vec![1usize, 0, 3, 2]; // (0 1)(2 3)
        let b = vec![2usize, 3, 0, 1]; // (0 2)(1 3)
        let readout = CosetReadout::CosetTable {
            reference_value: 0,
            coset_of: vec![0usize, 0, 1, 1],
        };
        let key = GakKey::new(
            n,
            vec![a, b],
            identity_usize(n),
            readout,
            GakKeyOptions::default(),
        )
        .unwrap();
        assert_eq!(key.ciphertext_alphabet_size(), 2);

        let plaintext = random_plaintext(0x636f_7365_7421, 233, key.plaintext_letters().len());
        let ciphertext = gak_encrypt(&plaintext, &key).unwrap();
        assert_eq!(gak_decrypt(&ciphertext, &key).unwrap(), plaintext);
    }

    #[test]
    fn gak_round_trips_non_identity_initial_state() {
        // Non-identity initial state g_0 = rot(5,2) with rotation letters whose
        // readouts from g_0 are distinct; decrypt replays the same g_0.
        let n = 5usize;
        let initial = rotation_permutation(n, 2);
        let letters: Vec<Vec<usize>> = (1..n).map(|s| rotation_permutation(n, s)).collect();
        let key = GakKey::new(
            n,
            letters,
            initial,
            CosetReadout::TopCard { reference_value: 0 },
            GakKeyOptions::default(),
        )
        .unwrap();

        let plaintext = random_plaintext(0x6e6f_6e69_6432, 199, key.plaintext_letters().len());
        let ciphertext = gak_encrypt(&plaintext, &key).unwrap();
        assert_eq!(gak_decrypt(&ciphertext, &key).unwrap(), plaintext);
    }

    #[test]
    fn gak_round_trips_alternating_subgroup_key() {
        // Four even permutations of 0..4 (A_4) with distinct card-0 positions, so
        // the parity constraint accepts them and the coset readouts are distinct.
        let n = 4usize;
        let letters = vec![
            identity_usize(n),
            vec![1usize, 0, 3, 2],
            vec![1usize, 2, 0, 3],
            vec![1usize, 3, 2, 0],
        ];
        let options = GakKeyOptions {
            avoid_doubles: false,
            subgroup: GakSubgroupConstraint::AlternatingGroup,
        };
        let key = GakKey::deck(n, letters, options).unwrap();

        let plaintext = random_plaintext(0x615f_6e5f_6b65_7921, 223, key.plaintext_letters().len());
        let ciphertext = gak_encrypt(&plaintext, &key).unwrap();
        assert_eq!(gak_decrypt(&ciphertext, &key).unwrap(), plaintext);
    }

    #[test]
    fn gak_rejects_non_invertible_coset_table() {
        // P0 regression. n=3, CosetTable{ref 0, coset_of [0,1,1]}, letters
        // id=[0,1,2] and q=[2,0,1]. From the identity state the two letters land
        // in distinct cosets (0 and 1), so the cheap identity-only check passes;
        // but plaintexts [1,0] and [1,1] both encrypt to [1,1], so the key is NOT
        // invertible. The reachable-state validator must reject it: from state
        // [2,0,1] both letters project to coset 1.
        let n = 3usize;
        let letters = vec![vec![0usize, 1, 2], vec![2usize, 0, 1]];
        let readout = CosetReadout::CosetTable {
            reference_value: 0,
            coset_of: vec![0usize, 1, 1],
        };
        let error = GakKey::new(
            n,
            letters,
            identity_usize(n),
            readout,
            GakKeyOptions::default(),
        )
        .unwrap_err();
        assert!(
            matches!(
                error,
                CipherError::GakCosetTableNotInvertible {
                    coset: 1,
                    duplicate_index: 1,
                    ..
                }
            ),
            "expected GakCosetTableNotInvertible, got {error:?}"
        );
    }

    #[test]
    fn gak_rejects_oversize_coset_table() {
        // P1 regression. A coset label too large to encode as a Glyph (and to
        // allocate a seen-cosets table for) must be rejected at construction,
        // not allowed to reach an impossible allocation or a non-encodable
        // emitted symbol.
        let n = 3usize;
        let readout = CosetReadout::CosetTable {
            reference_value: 0,
            coset_of: vec![0usize, 1, usize::MAX - 1],
        };
        let error = GakKey::new(
            n,
            vec![identity_usize(n)],
            identity_usize(n),
            readout,
            GakKeyOptions::default(),
        )
        .unwrap_err();
        assert!(
            matches!(error, CipherError::GakReadoutCosetOutsideAlphabet { .. }),
            "expected GakReadoutCosetOutsideAlphabet, got {error:?}"
        );
    }

    fn rotation_permutation(n: usize, shift: usize) -> Vec<usize> {
        (0..n).map(|i| (i + shift) % n).collect()
    }

    fn identity_usize(n: usize) -> Vec<usize> {
        (0..n).collect()
    }

    fn avoid_doubles_options() -> GakKeyOptions {
        GakKeyOptions {
            avoid_doubles: true,
            subgroup: GakSubgroupConstraint::SymmetricGroup,
        }
    }

    fn gctak_rotation_reference(plaintext: &[Glyph], shifts: &[usize], n: usize) -> Vec<u16> {
        // Independent reference: under left-update g <- rot(s) o g from identity,
        // the cumulative state is rot(S) with S the running shift-sum, and the
        // inverse-image readout g^{-1}[0] is the position holding card 0, i.e.
        // (n - S) mod n. This is a bijection of S, so it is a valid GCTAK output.
        let mut cumulative = 0usize;
        let mut output = Vec::with_capacity(plaintext.len());
        for glyph in plaintext {
            let letter = usize::from(glyph.0);
            let shift = shifts.get(letter).copied().unwrap();
            cumulative = (cumulative + shift) % n;
            output.push(((n - cumulative) % n) as u16);
        }
        output
    }

    /// Draws `count` random permutations of `0..n` whose inverse-image readouts
    /// (the position holding card 0, `p^{-1}[0]`) are all distinct, so the
    /// deck-realization coset-injectivity rule holds. Requires `count <= n`.
    fn random_distinct_coset_letters(n: usize, count: usize, seed: u64) -> Vec<Vec<usize>> {
        let mut rng = SplitMix64::new(seed);
        let mut letters: Vec<Vec<usize>> = Vec::with_capacity(count);
        let mut used_position = vec![false; n];
        let mut produced = 0usize;
        while produced < count {
            let mut perm = (0..n).collect::<Vec<_>>();
            let mut unswapped = perm.len();
            while unswapped > 1 {
                let last = unswapped - 1;
                let partner = random_index_below(unswapped, &mut rng);
                perm.swap(last, partner);
                unswapped = last;
            }
            let zero_position = perm.iter().position(|&entry| entry == 0).unwrap();
            let slot: &mut bool = used_position.as_mut_slice().get_mut(zero_position).unwrap();
            if !*slot {
                *slot = true;
                letters.push(perm);
                produced += 1;
            }
        }
        letters
    }

    fn values_usize(glyphs: &[Glyph]) -> Vec<usize> {
        glyphs.iter().map(|glyph| usize::from(glyph.0)).collect()
    }

    fn wrong_left_update_encrypt(plaintext: &[Glyph], key: &AglGakKey) -> Vec<u16> {
        let mut state = key.initial_state();
        let mut output = Vec::new();
        for glyph in plaintext {
            let element = *key.letter_elements().get(usize::from(glyph.0)).unwrap();
            state = agl_compose(element, state, key.alphabet_size());
            output.push(agl_apply(state, key.reference_point(), key.alphabet_size()) as u16);
        }
        output
    }

    fn random_plaintext(seed: u64, len: usize, alphabet_size: usize) -> Vec<Glyph> {
        let mut rng = SplitMix64::new(seed);
        let mut plaintext = Vec::with_capacity(len);
        let bound = alphabet_size as u64;
        for _position in 0..len {
            let value = rng.next_u64() % bound;
            plaintext.push(Glyph(value as u16));
        }
        plaintext
    }

    fn shuffled_permutation(alphabet_size: usize, seed: u64) -> Vec<usize> {
        let mut values = (0..alphabet_size).collect::<Vec<_>>();
        let mut rng = SplitMix64::new(seed);
        let mut unswapped = values.len();
        while unswapped > 1 {
            let last = unswapped - 1;
            let partner = random_index_below(unswapped, &mut rng);
            values.swap(last, partner);
            unswapped = last;
        }
        values
    }

    fn random_index_below(bound: usize, rng: &mut SplitMix64) -> usize {
        let bound = bound as u64;
        loop {
            let draw = rng.next_u64();
            let threshold = u64::MAX - (u64::MAX % bound);
            if draw < threshold {
                return (draw % bound) as usize;
            }
        }
    }

    fn glyphs(values: &[u16]) -> Vec<Glyph> {
        values.iter().copied().map(Glyph).collect()
    }

    fn glyphs_from_usize(values: &[usize]) -> Vec<Glyph> {
        values
            .iter()
            .copied()
            .map(|value| Glyph(value as u16))
            .collect()
    }

    fn values(glyphs: &[Glyph]) -> Vec<u16> {
        glyphs.iter().map(|glyph| glyph.0).collect()
    }

    fn alphabet(letters: &str) -> Vec<usize> {
        letters
            .bytes()
            .map(|byte| usize::from(byte - b'A'))
            .collect()
    }

    fn letters(glyphs: &[Glyph]) -> String {
        glyphs
            .iter()
            .map(|glyph| char::from(b'A' + glyph.0 as u8))
            .collect()
    }
}

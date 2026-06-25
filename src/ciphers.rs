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

use std::collections::BTreeMap;
use std::fmt;

use crate::glyph::Glyph;

/// Alphabet size of the accepted eye reading layer, values `0..=82`.
pub const EYE_READING_ALPHABET_SIZE: usize = 83;

const MAX_ALPHABET_SIZE: usize = u16::MAX as usize + 1;

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
        }
    }
}

impl std::error::Error for CipherError {}

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
        AglGakKey, AglMultiplierSubgroup, CaesarKey, ChaocipherKey, DeckCipherKey,
        EYE_READING_ALPHABET_SIZE, IncrementingWheelKey, VigenereKey, agl_apply, agl_compose,
        agl_gak_decrypt, agl_gak_encrypt, caesar_decrypt, caesar_encrypt, chaocipher_decrypt,
        chaocipher_encrypt, deck_cipher_decrypt, deck_cipher_encrypt, incrementing_wheel_decrypt,
        incrementing_wheel_encrypt, vigenere_decrypt, vigenere_encrypt,
    };
    use crate::glyph::Glyph;
    use crate::null::SplitMix64;

    #[test]
    fn caesar_known_tiny_vector() {
        let key = CaesarKey::new(5, 2).unwrap();
        let plaintext = glyphs(&[0, 1, 4]);
        let ciphertext = caesar_encrypt(&plaintext, &key).unwrap();
        assert_eq!(values(&ciphertext), vec![2, 3, 1]);
        assert_eq!(caesar_decrypt(&ciphertext, &key).unwrap(), plaintext);
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
    fn chaocipher_known_tiny_vector() {
        let key = ChaocipherKey::identity(7).unwrap();
        let plaintext = glyphs(&[0, 2, 4, 6]);
        let ciphertext = chaocipher_encrypt(&plaintext, &key).unwrap();
        assert_eq!(values(&ciphertext), vec![0, 2, 2, 4]);
        assert_eq!(chaocipher_decrypt(&ciphertext, &key).unwrap(), plaintext);
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

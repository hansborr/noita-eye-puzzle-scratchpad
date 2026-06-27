//! Key types for the simple (non-GAK) candidate ciphers.
//!
//! Each key validates its parameters at construction and exposes read-only
//! accessors; the transforms that consume the (crate-visible) fields live in
//! the `transforms` and `mechanics` siblings.

use crate::ciphers::error::CipherError;
use crate::ciphers::validation::{
    identity_permutation, normalize_shifts, validate_alphabet_size, validate_control_cards,
    validate_permutation,
};

/// Key for a route/columnar transposition over positions.
///
/// The key partitions the stream into `period`-sized blocks and assigns each
/// plaintext column a permutation rank. Encryption emits each block's present
/// columns in ascending rank order; decryption places those columns back at
/// their original positions. This permutes positions only and never rewrites
/// symbol values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranspositionKey {
    pub(crate) period: usize,
    pub(crate) permutation: Vec<usize>,
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
    pub(crate) alphabet_size: usize,
    pub(crate) shift: usize,
}

impl CaesarKey {
    /// Builds a Caesar key, reducing `shift` modulo `alphabet_size`.
    ///
    /// # Errors
    /// Returns [`CipherError::InvalidAlphabetSize`] when the alphabet is empty
    /// or cannot be represented by [`Glyph`](crate::core::glyph::Glyph).
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
    pub(crate) alphabet_size: usize,
    pub(crate) shifts: Vec<usize>,
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
    pub(crate) alphabet_size: usize,
    pub(crate) start: usize,
    pub(crate) step: usize,
}

impl IncrementingWheelKey {
    /// Builds an incrementing-wheel key, reducing `start` and `step` modulo
    /// `alphabet_size`.
    ///
    /// # Errors
    /// Returns [`CipherError::InvalidAlphabetSize`] when the alphabet is empty
    /// or cannot be represented by [`Glyph`](crate::core::glyph::Glyph).
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
    pub(crate) alphabet_size: usize,
    pub(crate) left: Vec<usize>,
    pub(crate) right: Vec<usize>,
}

impl ChaocipherKey {
    /// Builds a Chaocipher key from explicit left and right alphabets.
    ///
    /// # Errors
    /// Returns [`CipherError`] if the alphabet is smaller than three symbols,
    /// too large for [`Glyph`](crate::core::glyph::Glyph), or either alphabet is not a permutation of
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
    /// than three symbols or too large for [`Glyph`](crate::core::glyph::Glyph).
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
    pub(crate) alphabet_size: usize,
    pub(crate) deck: Vec<usize>,
    pub(crate) control_a: usize,
    pub(crate) control_b: usize,
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
    /// than three symbols or too large for [`Glyph`](crate::core::glyph::Glyph).
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

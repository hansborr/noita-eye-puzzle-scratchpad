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

use crate::core::glyph::Glyph;

mod error;
mod keys_gak;
mod keys_simple;
mod mechanics;
mod transforms;
mod validation;

pub use error::CipherError;
pub use keys_gak::{
    AglGakKey, AglMultiplierSubgroup, CosetReadout, GakKey, GakKeyOptions, GakSubgroupConstraint,
};
pub use keys_simple::{
    CaesarKey, ChaocipherKey, DeckCipherKey, IncrementingWheelKey, TranspositionKey, VigenereKey,
};
pub(crate) use mechanics::{
    agl_apply, agl_compose, agl_coset_symbol, agl_inverse, mul_inverse_mod, quadratic_residues_mod,
    sub_mod,
};
pub use transforms::{
    agl_gak_decrypt, agl_gak_encrypt, caesar_decrypt, caesar_encrypt, chaocipher_decrypt,
    chaocipher_encrypt, deck_cipher_decrypt, deck_cipher_encrypt, gak_decrypt, gak_encrypt,
    identity_decrypt, identity_encrypt, incrementing_wheel_decrypt, incrementing_wheel_encrypt,
    transposition_decrypt, transposition_encrypt, vigenere_decrypt, vigenere_encrypt,
};
pub(crate) use validation::compose_permutations;

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

/// Family marker for the no-key identity cipher.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Identity;

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

#[cfg(test)]
mod tests;

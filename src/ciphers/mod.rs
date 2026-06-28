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

/// Generates the [`Cipher`] impl for a zero-sized family marker by delegating to
/// this module's canonical free transforms.
///
/// The free transforms take their arguments as `(sequence, key)`, whereas the
/// [`Cipher`] trait methods take them as `(key, sequence)`; each generated method
/// bridges that argument-order difference in one place. The `keyless` arm is for
/// [`Identity`], whose free transforms take only the sequence and whose key type
/// is `()`.
macro_rules! impl_cipher {
    ($marker:ty, key = $key:ty, name = $name:literal, encrypt = $encrypt:path, decrypt = $decrypt:path) => {
        impl Cipher for $marker {
            type Key = $key;

            fn encrypt(
                &self,
                key: &Self::Key,
                plaintext: &[Glyph],
            ) -> Result<Vec<Glyph>, CipherError> {
                $encrypt(plaintext, key)
            }

            fn decrypt(
                &self,
                key: &Self::Key,
                ciphertext: &[Glyph],
            ) -> Result<Vec<Glyph>, CipherError> {
                $decrypt(ciphertext, key)
            }

            fn name(&self) -> &'static str {
                $name
            }
        }
    };
    ($marker:ty, keyless, name = $name:literal, encrypt = $encrypt:path, decrypt = $decrypt:path) => {
        impl Cipher for $marker {
            type Key = ();

            fn encrypt(&self, _key: &(), plaintext: &[Glyph]) -> Result<Vec<Glyph>, CipherError> {
                $encrypt(plaintext)
            }

            fn decrypt(&self, _key: &(), ciphertext: &[Glyph]) -> Result<Vec<Glyph>, CipherError> {
                $decrypt(ciphertext)
            }

            fn name(&self) -> &'static str {
                $name
            }
        }
    };
}

impl_cipher!(
    Identity,
    keyless,
    name = "identity",
    encrypt = identity_encrypt,
    decrypt = identity_decrypt
);

/// Family marker for the route/columnar transposition cipher.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Transposition;

impl_cipher!(
    Transposition,
    key = TranspositionKey,
    name = "transposition",
    encrypt = transposition_encrypt,
    decrypt = transposition_decrypt
);

/// Family marker for the Caesar additive shift cipher.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Caesar;

impl_cipher!(
    Caesar,
    key = CaesarKey,
    name = "Caesar",
    encrypt = caesar_encrypt,
    decrypt = caesar_decrypt
);

/// Family marker for the periodic additive Vigenere cipher.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Vigenere;

impl_cipher!(
    Vigenere,
    key = VigenereKey,
    name = "Vigenere",
    encrypt = vigenere_encrypt,
    decrypt = vigenere_decrypt
);

/// Family marker for the additive-progressive incrementing-wheel cipher.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IncrementingWheel;

impl_cipher!(
    IncrementingWheel,
    key = IncrementingWheelKey,
    name = "incrementing-wheel",
    encrypt = incrementing_wheel_encrypt,
    decrypt = incrementing_wheel_decrypt
);

/// Family marker for the generalized two-alphabet Chaocipher.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Chaocipher;

impl_cipher!(
    Chaocipher,
    key = ChaocipherKey,
    name = "Chaocipher",
    encrypt = chaocipher_encrypt,
    decrypt = chaocipher_decrypt
);

/// Family marker for the generalized `S_N` deck-keystream cipher.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeckCipher;

impl_cipher!(
    DeckCipher,
    key = DeckCipherKey,
    name = "deck",
    encrypt = deck_cipher_encrypt,
    decrypt = deck_cipher_decrypt
);

/// Family marker for the AGL(1,n)-GAK stream cipher.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AglGak;

impl_cipher!(
    AglGak,
    key = AglGakKey,
    name = "AGL-GAK",
    encrypt = agl_gak_encrypt,
    decrypt = agl_gak_decrypt
);

/// Family marker for the general permutation-group GAK cipher.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gak;

impl_cipher!(
    Gak,
    key = GakKey,
    name = "GAK",
    encrypt = gak_encrypt,
    decrypt = gak_decrypt
);

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

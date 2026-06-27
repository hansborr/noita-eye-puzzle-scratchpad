//! Free encrypt/decrypt transforms for the candidate-cipher families.
//!
//! These are the canonical primitives; the `Cipher` trait impls in the parent
//! module delegate to them byte-for-byte.

use crate::ciphers::error::CipherError;
use crate::ciphers::keys_gak::{AglGakKey, GakKey};
use crate::ciphers::keys_simple::{
    CaesarKey, ChaocipherKey, DeckCipherKey, IncrementingWheelKey, TranspositionKey, VigenereKey,
};
use crate::ciphers::mechanics::{
    Direction, agl_compose, agl_coset_symbol, agl_step_lookup, glyph_from_symbol,
    periodic_shift_at, progressive_shift_at, symbol_from_glyph, translate_additive,
    translate_chaocipher, translate_deck_cipher,
};
use crate::ciphers::validation::{compose_permutations, gak_step_lookup, transposition_order};
use crate::core::glyph::Glyph;

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

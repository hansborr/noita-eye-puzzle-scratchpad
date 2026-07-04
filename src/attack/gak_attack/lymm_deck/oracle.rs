//! Exact encryption oracle for Lymm's deck-cipher convention.

use std::collections::BTreeMap;

use crate::ciphers::{CipherError, compose_permutations, validate_permutation};

use super::{LymmComposeDirection, LymmDeckError, LymmDeckSpec};

/// Encrypts `plaintext` under Lymm's deck-cipher convention.
///
/// Characters outside `spec.pt_alphabet` pass through verbatim and do not advance
/// the deck state. Plaintext letters apply their mapped permutation, then emit
/// `spec.ct_alphabet[state[spec.emit_index]]`.
///
/// # Errors
/// Returns [`LymmDeckError`] if the mapping is incomplete, any mapped
/// permutation is invalid, or the configured state update leaves the deck.
pub fn encrypt_lymm_deck(
    spec: &LymmDeckSpec,
    pt_mapping: &BTreeMap<char, Vec<usize>>,
    plaintext: &str,
) -> Result<String, LymmDeckError> {
    validate_mapping(spec, pt_mapping)?;
    let mut state = spec.initial_state.clone();
    let mut ciphertext = String::with_capacity(plaintext.len());
    for ch in plaintext.chars() {
        if !spec.is_plaintext_char(ch) {
            ciphertext.push(ch);
            continue;
        }
        let perm = pt_mapping
            .get(&ch)
            .ok_or(LymmDeckError::MissingPlaintextMapping { letter: ch })?;
        state = match spec.compose_dir {
            LymmComposeDirection::Left => compose_lymm(perm, &state)?,
            LymmComposeDirection::Right => compose_lymm(&state, perm)?,
        };
        let deck_value =
            state
                .get(spec.emit_index)
                .copied()
                .ok_or(LymmDeckError::EmitIndexOutOfRange {
                    emit_index: spec.emit_index,
                    n: spec.n,
                })?;
        let emitted = spec.ct_alphabet.get(deck_value).copied().ok_or(
            LymmDeckError::EmitIndexOutOfRange {
                emit_index: deck_value,
                n: spec.ct_alphabet.len(),
            },
        )?;
        ciphertext.push(emitted);
    }
    Ok(ciphertext)
}

pub(crate) fn validate_mapping(
    spec: &LymmDeckSpec,
    pt_mapping: &BTreeMap<char, Vec<usize>>,
) -> Result<(), LymmDeckError> {
    for &letter in &spec.pt_alphabet {
        let perm = pt_mapping
            .get(&letter)
            .ok_or(LymmDeckError::MissingPlaintextMapping { letter })?;
        validate_permutation("Lymm plaintext mapping", perm, spec.n)?;
    }
    Ok(())
}

pub(crate) fn compose_lymm(p1: &[usize], p2: &[usize]) -> Result<Vec<usize>, CipherError> {
    compose_permutations(p2, p1)
}

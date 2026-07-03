//! Parameter bundle for Lymm's deck-cipher convention.

use std::collections::BTreeSet;

use crate::ciphers::{identity_gak_permutation, validate_permutation};

use super::{LymmDeckError, compose_lymm};

/// Default deck size of Lymm's supplied practice corpus.
pub const LYMM_DEFAULT_N: usize = 83;
/// Default plaintext alphabet of Lymm's supplied practice corpus.
pub const LYMM_DEFAULT_PT_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
/// Default rotation shift used to build Lymm's base permutation.
pub const LYMM_DEFAULT_SHIFT: usize = 26;
/// Default decimation used to build Lymm's base permutation.
pub const LYMM_DEFAULT_DECIMATION: usize = 3;

/// State-update convention for the parameterized oracle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LymmComposeDirection {
    /// Lymm's generator convention: `state = compose(perm, state)`, so
    /// `new[i] = state[perm[i]]`.
    Left,
    /// The alternate right-compose convention: `state = compose(state, perm)`, so
    /// `new[i] = perm[state[i]]`.
    Right,
}

/// Complete parameter set for Lymm's deck-cipher oracle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LymmDeckSpec {
    /// Deck size.
    pub n: usize,
    /// Plaintext alphabet; characters outside this set pass through.
    pub pt_alphabet: Vec<char>,
    /// Ciphertext alphabet, indexed by the emitted deck value.
    pub ct_alphabet: Vec<char>,
    /// Public base permutation used by the top-swap mapping generator.
    pub base: Vec<usize>,
    /// Initial state for each independent encryption.
    pub initial_state: Vec<usize>,
    /// State-update convention.
    pub compose_dir: LymmComposeDirection,
    /// Deck position read after each state update.
    pub emit_index: usize,
}

impl LymmDeckSpec {
    /// Builds the exact parameter set used by the vendored `deck-swap` corpus.
    ///
    /// # Errors
    /// Returns [`LymmDeckError`] if the generated base or alphabets are invalid.
    pub fn lymm_default() -> Result<Self, LymmDeckError> {
        Self::from_shift_decimation(
            LYMM_DEFAULT_N,
            LYMM_DEFAULT_PT_ALPHABET,
            &lymm_default_ct_alphabet(LYMM_DEFAULT_N),
            LYMM_DEFAULT_SHIFT,
            LYMM_DEFAULT_DECIMATION,
        )
    }

    /// Builds a spec from Lymm's `rotation[shift]` and `decimation[decimation]`
    /// base construction.
    ///
    /// The base matches the Python expression
    /// `compose(rotations[shift], decimations[decimation])`.
    ///
    /// # Errors
    /// Returns [`LymmDeckError`] if the alphabets or resulting base are invalid.
    pub fn from_shift_decimation(
        n: usize,
        pt_alphabet: &str,
        ct_alphabet: &str,
        shift: usize,
        decimation: usize,
    ) -> Result<Self, LymmDeckError> {
        if n < 2 {
            return Err(LymmDeckError::DeckTooSmall { n });
        }
        let rotation = rotation_permutation(n, shift);
        let decimation_perm = decimation_permutation(n, decimation);
        let base = compose_lymm(&rotation, &decimation_perm)?;
        Self::from_base(n, pt_alphabet, ct_alphabet, base)
    }

    /// Builds a spec from an explicit base permutation and identity initial state.
    ///
    /// # Errors
    /// Returns [`LymmDeckError`] if the alphabets, base, or identity state are
    /// invalid.
    pub fn from_base(
        n: usize,
        pt_alphabet: &str,
        ct_alphabet: &str,
        base: Vec<usize>,
    ) -> Result<Self, LymmDeckError> {
        if n < 2 {
            return Err(LymmDeckError::DeckTooSmall { n });
        }
        let initial_state = identity_gak_permutation(n)?;
        let spec = Self {
            n,
            pt_alphabet: alphabet_chars("plaintext", pt_alphabet, None)?,
            ct_alphabet: alphabet_chars("ciphertext", ct_alphabet, Some(n))?,
            base,
            initial_state,
            compose_dir: LymmComposeDirection::Left,
            emit_index: 0,
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Replaces the initial state.
    ///
    /// # Errors
    /// Returns [`LymmDeckError`] if `initial_state` is not a permutation of the
    /// deck.
    pub fn with_initial_state(mut self, initial_state: Vec<usize>) -> Result<Self, LymmDeckError> {
        self.initial_state = initial_state;
        self.validate()?;
        Ok(self)
    }

    /// Replaces the composition direction.
    #[must_use]
    pub fn with_compose_dir(mut self, compose_dir: LymmComposeDirection) -> Self {
        self.compose_dir = compose_dir;
        self
    }

    /// Replaces the readout index.
    ///
    /// # Errors
    /// Returns [`LymmDeckError`] if `emit_index` is outside the deck.
    pub fn with_emit_index(mut self, emit_index: usize) -> Result<Self, LymmDeckError> {
        self.emit_index = emit_index;
        self.validate()?;
        Ok(self)
    }

    /// Returns true when `ch` is in the plaintext alphabet.
    #[must_use]
    pub fn is_plaintext_char(&self, ch: char) -> bool {
        self.pt_alphabet.contains(&ch)
    }

    fn validate(&self) -> Result<(), LymmDeckError> {
        validate_permutation("Lymm base", &self.base, self.n)?;
        validate_permutation("Lymm initial state", &self.initial_state, self.n)?;
        if self.emit_index >= self.n {
            return Err(LymmDeckError::EmitIndexOutOfRange {
                emit_index: self.emit_index,
                n: self.n,
            });
        }
        Ok(())
    }
}

/// Returns the ASCII `chr(33 + i)` ciphertext alphabet used by Lymm's generator.
#[must_use]
pub fn lymm_default_ct_alphabet(n: usize) -> String {
    (0..n)
        .filter_map(|i| u32::try_from(33usize.saturating_add(i)).ok())
        .filter_map(char::from_u32)
        .collect()
}

fn alphabet_chars(
    alphabet: &'static str,
    raw: &str,
    expected_len: Option<usize>,
) -> Result<Vec<char>, LymmDeckError> {
    let chars = raw.chars().collect::<Vec<_>>();
    if let Some(expected) = expected_len
        && chars.len() != expected
    {
        return Err(LymmDeckError::AlphabetLength {
            alphabet,
            len: chars.len(),
            expected,
        });
    }
    let mut seen = BTreeSet::new();
    for &ch in &chars {
        if !seen.insert(ch) {
            return Err(LymmDeckError::DuplicateAlphabetChar { alphabet, ch });
        }
    }
    Ok(chars)
}

fn rotation_permutation(n: usize, shift: usize) -> Vec<usize> {
    (0..n).map(|i| (i + shift) % n).collect()
}

fn decimation_permutation(n: usize, decimation: usize) -> Vec<usize> {
    (0..n).map(|i| (i * decimation) % n).collect()
}

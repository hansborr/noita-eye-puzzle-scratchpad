//! Language-scoring primitives for candidate plaintexts.
//!
//! This module is calibration tooling for later cipher experiments. It builds
//! unigram and bigram language models from known public-domain text samples and
//! scores candidate plaintexts by mean natural-log likelihood per symbol. The
//! default alphabet is shared by the bundled English and Finnish models so the
//! scores can be compared directly.
//!
//! The model uses additive smoothing: every unigram and bigram count receives
//! the configured positive `alpha` before probabilities are computed. With the
//! default [`DEFAULT_SMOOTHING`] value of `1.0`, this is standard Laplace
//! smoothing and unseen n-grams remain finite rather than becoming negative
//! infinity.
//!
//! These scores make no claim about the eye-glyph corpus. They only calibrate a
//! reusable "does this look like English or Finnish?" primitive for future
//! Caesar, Vigenere, and candidate-cipher searches.

use std::collections::BTreeMap;
use std::fmt;

/// Shared alphabet for the bundled English and Finnish language models.
///
/// The alphabet is normalized uppercase `A..Z` plus `ÅÄÖ`. English samples use
/// the same alphabet with zero observed counts for the Finnish-only letters.
pub const DEFAULT_LANGUAGE_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZÅÄÖ";

/// Default additive smoothing used by bundled models.
///
/// `1.0` is Laplace smoothing: each possible symbol or conditional bigram is
/// treated as if it had been observed once before the training sample.
pub const DEFAULT_SMOOTHING: f64 = 1.0;

/// Bundled public-domain English training sample.
pub const ENGLISH_SAMPLE: &str = include_str!("../../../research/data/lang/english.txt");

/// Bundled public-domain Finnish training sample.
pub const FINNISH_SAMPLE: &str = include_str!("../../../research/data/lang/finnish.txt");

/// Error returned when a language model or candidate text is malformed.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LanguageError {
    /// The alphabet contained no supported symbols.
    EmptyAlphabet,
    /// The same normalized alphabet symbol appeared more than once.
    DuplicateAlphabetSymbol {
        /// The duplicated normalized symbol.
        symbol: char,
    },
    /// A text or alphabet symbol is alphabetic but outside the supported
    /// normalization inventory.
    UnsupportedSymbol {
        /// The unsupported input character.
        symbol: char,
    },
    /// The smoothing value was not finite and positive.
    InvalidSmoothing {
        /// The invalid smoothing value.
        smoothing: f64,
    },
    /// The alphabet was too large to allocate the bigram table safely.
    AlphabetTooLarge {
        /// Number of symbols in the alphabet.
        alphabet_len: usize,
    },
    /// The training sample had no symbols after normalization.
    EmptyTrainingText,
    /// The candidate had no symbols after normalization.
    EmptyCandidate,
    /// A candidate symbol index was outside the model alphabet.
    IndexOutsideAlphabet {
        /// The unsupported candidate index.
        index: usize,
        /// Number of symbols in the model alphabet.
        alphabet_len: usize,
    },
}

impl fmt::Display for LanguageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::EmptyAlphabet => write!(f, "language alphabet is empty"),
            Self::DuplicateAlphabetSymbol { symbol } => {
                write!(f, "duplicate language alphabet symbol {symbol:?}")
            }
            Self::UnsupportedSymbol { symbol } => {
                write!(f, "unsupported language symbol {symbol:?}")
            }
            Self::InvalidSmoothing { smoothing } => {
                write!(
                    f,
                    "language smoothing must be finite and positive, got {smoothing}"
                )
            }
            Self::AlphabetTooLarge { alphabet_len } => {
                write!(
                    f,
                    "language alphabet of {alphabet_len} symbols is too large"
                )
            }
            Self::EmptyTrainingText => write!(f, "language training text is empty"),
            Self::EmptyCandidate => write!(f, "language candidate text is empty"),
            Self::IndexOutsideAlphabet {
                index,
                alphabet_len,
            } => write!(
                f,
                "language candidate index {index} is outside alphabet length {alphabet_len}"
            ),
        }
    }
}

impl std::error::Error for LanguageError {}

/// A normalized language alphabet for text scoring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LanguageAlphabet {
    symbols: Vec<char>,
    indices: BTreeMap<char, usize>,
}

impl LanguageAlphabet {
    /// Builds an alphabet from distinct supported letters.
    ///
    /// Letters are normalized to uppercase ASCII plus `ÅÄÖ`, so `a` and `A`
    /// collide.
    ///
    /// # Errors
    /// Returns [`LanguageError::EmptyAlphabet`] for an empty alphabet,
    /// [`LanguageError::UnsupportedSymbol`] for a non-supported alphabet
    /// character, or [`LanguageError::DuplicateAlphabetSymbol`] after
    /// normalization.
    pub fn from_chars(chars: &str) -> Result<Self, LanguageError> {
        let mut symbols = Vec::new();
        let mut indices = BTreeMap::new();
        for raw in chars.chars() {
            let Some(symbol) = normalize_letter(raw)? else {
                return Err(LanguageError::UnsupportedSymbol { symbol: raw });
            };
            if indices.insert(symbol, symbols.len()).is_some() {
                return Err(LanguageError::DuplicateAlphabetSymbol { symbol });
            }
            symbols.push(symbol);
        }
        if symbols.is_empty() {
            return Err(LanguageError::EmptyAlphabet);
        }
        Ok(Self { symbols, indices })
    }

    /// Number of symbols in the alphabet.
    #[must_use]
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Returns `true` if the alphabet has no symbols.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Returns the normalized symbol at `index`, if it exists.
    #[must_use]
    pub fn symbol(&self, index: usize) -> Option<char> {
        self.symbols.get(index).copied()
    }

    /// Returns the index of `symbol` after normalization, if it is in the
    /// alphabet.
    #[must_use]
    pub fn index(&self, symbol: char) -> Option<usize> {
        match normalize_letter(symbol) {
            Ok(Some(normalized)) => self.indices.get(&normalized).copied(),
            Ok(None) | Err(_) => None,
        }
    }

    /// Returns the normalized symbol inventory in index order.
    #[must_use]
    pub fn symbols(&self) -> &[char] {
        &self.symbols
    }

    /// Normalizes text into alphabet indices, ignoring whitespace,
    /// punctuation, and digits.
    ///
    /// # Errors
    /// Returns [`LanguageError::UnsupportedSymbol`] if the text contains an
    /// alphabetic character that cannot be normalized into this alphabet.
    pub fn normalize_text(&self, text: &str) -> Result<Vec<usize>, LanguageError> {
        let mut indices = Vec::new();
        self.normalize_text_into(text, &mut indices)?;
        Ok(indices)
    }

    fn normalize_text_into(
        &self,
        text: &str,
        output: &mut Vec<usize>,
    ) -> Result<(), LanguageError> {
        for raw in text.chars() {
            let Some(symbol) = normalize_letter(raw)? else {
                continue;
            };
            let Some(&index) = self.indices.get(&symbol) else {
                return Err(LanguageError::UnsupportedSymbol { symbol: raw });
            };
            output.push(index);
        }
        Ok(())
    }
}

/// Mean per-symbol language scores for a candidate.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LanguageScore {
    /// Number of normalized symbols scored.
    pub symbols: usize,
    /// Mean natural-log likelihood per symbol under the unigram model.
    pub unigram_mean_log_likelihood: f64,
    /// Mean natural-log likelihood per symbol under the bigram model.
    ///
    /// The first symbol is scored with the unigram model and every following
    /// symbol is scored conditionally on its predecessor.
    pub bigram_mean_log_likelihood: f64,
}

/// Additively-smoothed unigram and bigram language model.
#[derive(Clone, Debug)]
pub struct LanguageModel {
    alphabet: LanguageAlphabet,
    smoothing: f64,
    unigram_counts: Vec<usize>,
    context_counts: Vec<usize>,
    bigram_counts: Vec<usize>,
    symbol_count: usize,
}

impl LanguageModel {
    /// Builds a unigram+bigram model from sample text.
    ///
    /// Lines whose first non-whitespace character is `#` are treated as
    /// provenance comments and skipped. All other non-alphabetic characters are
    /// ignored during normalization.
    ///
    /// # Errors
    /// Returns [`LanguageError`] if the alphabet or smoothing value is invalid,
    /// if the sample has no normalized symbols, or if the sample contains an
    /// unsupported alphabetic character.
    pub fn from_sample(
        sample: &str,
        alphabet: LanguageAlphabet,
        smoothing: f64,
    ) -> Result<Self, LanguageError> {
        validate_smoothing(smoothing)?;
        let symbols = normalize_training_sample(sample, &alphabet)?;
        Self::from_indices(&symbols, alphabet, smoothing)
    }

    /// Scores normalized alphabet indices directly.
    ///
    /// This is the API later brute-force experiments can use after mapping a
    /// candidate cipher alphabet onto the model alphabet.
    ///
    /// # Errors
    /// Returns [`LanguageError::EmptyCandidate`] for an empty sequence or
    /// [`LanguageError::IndexOutsideAlphabet`] if an index is not in the model
    /// alphabet.
    pub fn score_indices(&self, indices: &[usize]) -> Result<LanguageScore, LanguageError> {
        if indices.is_empty() {
            return Err(LanguageError::EmptyCandidate);
        }

        let mut unigram_log_likelihood = 0.0;
        for &index in indices {
            unigram_log_likelihood += self.unigram_log_probability(index)?;
        }

        let mut bigram_log_likelihood = 0.0;
        if let Some(&first) = indices.first() {
            bigram_log_likelihood += self.unigram_log_probability(first)?;
        }
        for pair in indices.windows(2) {
            if let [left, right] = pair {
                bigram_log_likelihood += self.bigram_log_probability(*left, *right)?;
            }
        }

        let symbols = indices.len();
        let symbols_f64 = symbols as f64;
        Ok(LanguageScore {
            symbols,
            unigram_mean_log_likelihood: unigram_log_likelihood / symbols_f64,
            bigram_mean_log_likelihood: bigram_log_likelihood / symbols_f64,
        })
    }

    /// Normalizes and scores candidate text.
    ///
    /// Whitespace, punctuation, and digits are ignored. Unsupported alphabetic
    /// characters are rejected so accidental transcription or alphabet mistakes
    /// do not silently disappear.
    ///
    /// # Errors
    /// Returns [`LanguageError`] if normalization fails or if the candidate has
    /// no normalized symbols.
    pub fn score_text(&self, text: &str) -> Result<LanguageScore, LanguageError> {
        let indices = self.alphabet.normalize_text(text)?;
        self.score_indices(&indices)
    }

    /// Returns the model alphabet.
    #[must_use]
    pub fn alphabet(&self) -> &LanguageAlphabet {
        &self.alphabet
    }

    /// Returns the additive smoothing parameter.
    #[must_use]
    pub const fn smoothing(&self) -> f64 {
        self.smoothing
    }

    /// Returns the number of normalized symbols used for training.
    #[must_use]
    pub const fn symbol_count(&self) -> usize {
        self.symbol_count
    }

    /// Returns the observed unigram count for an alphabet index.
    ///
    /// # Errors
    /// Returns [`LanguageError::IndexOutsideAlphabet`] if `index` is not in the
    /// model alphabet.
    pub fn unigram_count(&self, index: usize) -> Result<usize, LanguageError> {
        self.count_at(&self.unigram_counts, index)
    }

    /// Returns the observed bigram count for two alphabet indices.
    ///
    /// # Errors
    /// Returns [`LanguageError::IndexOutsideAlphabet`] if either index is not
    /// in the model alphabet.
    pub fn bigram_count(&self, left: usize, right: usize) -> Result<usize, LanguageError> {
        let offset = bigram_offset(left, right, self.alphabet.len())?;
        self.count_at(&self.bigram_counts, offset)
    }

    fn from_indices(
        symbols: &[usize],
        alphabet: LanguageAlphabet,
        smoothing: f64,
    ) -> Result<Self, LanguageError> {
        if symbols.is_empty() {
            return Err(LanguageError::EmptyTrainingText);
        }
        let alphabet_len = alphabet.len();
        let bigram_len = alphabet_len
            .checked_mul(alphabet_len)
            .ok_or(LanguageError::AlphabetTooLarge { alphabet_len })?;
        let mut model = Self {
            alphabet,
            smoothing,
            unigram_counts: vec![0; alphabet_len],
            context_counts: vec![0; alphabet_len],
            bigram_counts: vec![0; bigram_len],
            symbol_count: symbols.len(),
        };

        for &symbol in symbols {
            increment_count(&mut model.unigram_counts, symbol, alphabet_len)?;
        }
        for pair in symbols.windows(2) {
            if let [left, right] = pair {
                increment_count(&mut model.context_counts, *left, alphabet_len)?;
                let offset = bigram_offset(*left, *right, alphabet_len)?;
                increment_count(&mut model.bigram_counts, offset, bigram_len)?;
            }
        }

        Ok(model)
    }

    fn unigram_log_probability(&self, index: usize) -> Result<f64, LanguageError> {
        let count = self.count_at(&self.unigram_counts, index)? as f64;
        let denominator = self.symbol_count as f64 + self.smoothing * self.alphabet.len() as f64;
        Ok(((count + self.smoothing) / denominator).ln())
    }

    fn bigram_log_probability(&self, left: usize, right: usize) -> Result<f64, LanguageError> {
        let alphabet_len = self.alphabet.len();
        let offset = bigram_offset(left, right, alphabet_len)?;
        let bigram_count = self.count_at(&self.bigram_counts, offset)? as f64;
        let context_count = self.count_at(&self.context_counts, left)? as f64;
        let denominator = context_count + self.smoothing * alphabet_len as f64;
        Ok(((bigram_count + self.smoothing) / denominator).ln())
    }

    fn count_at(&self, counts: &[usize], index: usize) -> Result<usize, LanguageError> {
        counts
            .get(index)
            .copied()
            .ok_or(LanguageError::IndexOutsideAlphabet {
                index,
                alphabet_len: self.alphabet.len(),
            })
    }
}

/// Builds the default `A..ZÅÄÖ` language alphabet.
///
/// # Errors
/// Returns [`LanguageError`] if the built-in alphabet constant is malformed.
pub fn default_alphabet() -> Result<LanguageAlphabet, LanguageError> {
    LanguageAlphabet::from_chars(DEFAULT_LANGUAGE_ALPHABET)
}

/// Builds the bundled English language model.
///
/// # Errors
/// Returns [`LanguageError`] if the built-in alphabet or sample is malformed.
pub fn english_model() -> Result<LanguageModel, LanguageError> {
    LanguageModel::from_sample(ENGLISH_SAMPLE, default_alphabet()?, DEFAULT_SMOOTHING)
}

/// Builds the bundled Finnish language model.
///
/// # Errors
/// Returns [`LanguageError`] if the built-in alphabet or sample is malformed.
pub fn finnish_model() -> Result<LanguageModel, LanguageError> {
    LanguageModel::from_sample(FINNISH_SAMPLE, default_alphabet()?, DEFAULT_SMOOTHING)
}

fn validate_smoothing(smoothing: f64) -> Result<(), LanguageError> {
    if !smoothing.is_finite() || smoothing <= 0.0 {
        return Err(LanguageError::InvalidSmoothing { smoothing });
    }
    Ok(())
}

fn normalize_training_sample(
    sample: &str,
    alphabet: &LanguageAlphabet,
) -> Result<Vec<usize>, LanguageError> {
    let mut indices = Vec::new();
    for line in sample.lines() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        alphabet.normalize_text_into(line, &mut indices)?;
    }
    Ok(indices)
}

fn normalize_letter(symbol: char) -> Result<Option<char>, LanguageError> {
    match symbol {
        'A'..='Z' => Ok(Some(symbol)),
        'a'..='z' => Ok(Some(symbol.to_ascii_uppercase())),
        'Å' | 'å' => Ok(Some('Å')),
        'Ä' | 'ä' => Ok(Some('Ä')),
        'Ö' | 'ö' => Ok(Some('Ö')),
        _ if symbol.is_alphabetic() => Err(LanguageError::UnsupportedSymbol { symbol }),
        _ => Ok(None),
    }
}

fn increment_count(
    counts: &mut [usize],
    index: usize,
    alphabet_len: usize,
) -> Result<(), LanguageError> {
    let Some(count) = counts.get_mut(index) else {
        return Err(LanguageError::IndexOutsideAlphabet {
            index,
            alphabet_len,
        });
    };
    *count += 1;
    Ok(())
}

fn bigram_offset(left: usize, right: usize, alphabet_len: usize) -> Result<usize, LanguageError> {
    if left >= alphabet_len {
        return Err(LanguageError::IndexOutsideAlphabet {
            index: left,
            alphabet_len,
        });
    }
    if right >= alphabet_len {
        return Err(LanguageError::IndexOutsideAlphabet {
            index: right,
            alphabet_len,
        });
    }
    left.checked_mul(alphabet_len)
        .and_then(|base| base.checked_add(right))
        .ok_or(LanguageError::AlphabetTooLarge { alphabet_len })
}

#[cfg(test)]
mod tests;

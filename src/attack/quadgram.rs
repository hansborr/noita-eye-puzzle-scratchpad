//! Quadgram English language model for scoring candidate plaintexts.
//!
//! This module is calibration tooling for the polyalphabetic key search. The
//! bigram model in [`crate::attack::language`] is intentionally simple and trained on a
//! tiny sample; it is too weak to separate near-English candidates from noise
//! during a large key search. This module builds a fixed `A..Z` *quadgram*
//! (4-gram) model from a large, committed public-domain corpus and precomputes a
//! dense log-probability table so each scoring call is `O(n)` table lookups with
//! no per-call probability arithmetic.
//!
//! The model uses additive (Laplace-style) smoothing: every one of the `26^4`
//! possible quadgrams receives the configured positive `smoothing` mass before
//! probabilities are computed, so unseen quadgrams keep a finite floor
//! log-probability rather than `-inf`.
//!
//! Scores are the mean natural-log probability per length-4 window, so longer
//! and shorter candidates are directly comparable. The scorer makes no claim
//! about the eye-glyph corpus; it only answers "does this look like English?"
//! well enough to rank decryptions.

use std::fmt;

/// Number of letters in the fixed model alphabet (`A..Z`).
pub const ALPHABET_LEN: usize = 26;

/// Number of distinct quadgrams: `ALPHABET_LEN.pow(4)` = `456_976`.
pub const TABLE_LEN: usize = ALPHABET_LEN.pow(4);

/// Default additive smoothing used by [`QuadgramModel::english`].
///
/// `0.5` (Jeffreys / Krichevsky–Trofimov prior) is a conventional sub-Laplace
/// choice for high-dimensional n-gram tables: with `26^4` cells and roughly a
/// million observed quadgrams, full Laplace (`1.0`) would over-smooth and flatten
/// the contrast between common and rare quadgrams, while a smaller value keeps
/// unseen quadgrams penalized without driving their floor to `-inf`.
pub const DEFAULT_SMOOTHING: f64 = 0.5;

/// Bundled large public-domain English training corpus.
///
/// This is the `~1.5 MB` corpus committed under `research/data/lang/`, distinct
/// from the small [`crate::attack::language::ENGLISH_SAMPLE`] used by the bigram model.
pub const ENGLISH_CORPUS_LARGE: &str =
    include_str!("../../research/data/lang/english-corpus-large.txt");

/// Error returned when a quadgram model cannot be built.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum QuadgramError {
    /// The training sample held fewer than four letters after normalization, so
    /// not a single quadgram window could be formed.
    SampleTooSmall {
        /// Number of `A..Z` letters found after normalization.
        letters: usize,
    },
    /// The smoothing value was not finite and positive.
    InvalidSmoothing {
        /// The invalid smoothing value.
        smoothing: f64,
    },
}

impl fmt::Display for QuadgramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::SampleTooSmall { letters } => write!(
                f,
                "quadgram training sample has {letters} letters, need at least 4"
            ),
            Self::InvalidSmoothing { smoothing } => write!(
                f,
                "quadgram smoothing must be finite and positive, got {smoothing}"
            ),
        }
    }
}

impl std::error::Error for QuadgramError {}

/// An additively-smoothed `A..Z` quadgram language model.
///
/// The model owns a dense `logprob` table of length [`TABLE_LEN`] holding the
/// natural-log probability of every quadgram, so scoring is a flat sequence of
/// table lookups. Unseen quadgrams resolve to a single shared floor
/// log-probability.
#[derive(Clone, Debug)]
pub struct QuadgramModel {
    logprob: Vec<f32>,
    floor_logprob: f32,
    total_quadgrams: u64,
    smoothing: f64,
}

impl QuadgramModel {
    /// Builds a quadgram model from sample text.
    ///
    /// Normalization keeps ASCII alphabetic characters, uppercases them, and maps
    /// `A..Z` onto `0..=25`; every other character (whitespace, punctuation,
    /// digits, non-ASCII) is dropped. Quadgrams are counted over the resulting
    /// index stream and additive smoothing is applied before the log-probability
    /// table is precomputed.
    ///
    /// # Errors
    /// Returns [`QuadgramError::InvalidSmoothing`] if `smoothing` is not finite
    /// and positive, or [`QuadgramError::SampleTooSmall`] if fewer than four
    /// letters remain after normalization (no quadgram window can be formed).
    pub fn from_sample(sample: &str, smoothing: f64) -> Result<Self, QuadgramError> {
        if !smoothing.is_finite() || smoothing <= 0.0 {
            return Err(QuadgramError::InvalidSmoothing { smoothing });
        }
        let indices = normalize_to_indices(sample);
        if indices.len() < 4 {
            return Err(QuadgramError::SampleTooSmall {
                letters: indices.len(),
            });
        }

        let mut counts = vec![0u32; TABLE_LEN];
        let mut total_quadgrams: u64 = 0;
        for window in indices.windows(4) {
            if let &[a, b, c, d] = window {
                let quadgram = quadgram_index(a, b, c, d);
                if let Some(slot) = counts.get_mut(quadgram) {
                    *slot = slot.saturating_add(1);
                    total_quadgrams += 1;
                }
            }
        }

        let denominator = total_quadgrams as f64 + smoothing * TABLE_LEN as f64;
        let floor_logprob = (smoothing / denominator).ln() as f32;
        let logprob = counts
            .iter()
            .map(|&count| ((f64::from(count) + smoothing) / denominator).ln() as f32)
            .collect();

        Ok(Self {
            logprob,
            floor_logprob,
            total_quadgrams,
            smoothing,
        })
    }

    /// Builds the bundled English quadgram model from [`ENGLISH_CORPUS_LARGE`]
    /// with [`DEFAULT_SMOOTHING`].
    ///
    /// # Errors
    /// Returns [`QuadgramError`] if the bundled corpus or default smoothing is
    /// somehow invalid (it should not be in a correct build).
    pub fn english() -> Result<Self, QuadgramError> {
        Self::from_sample(ENGLISH_CORPUS_LARGE, DEFAULT_SMOOTHING)
    }

    /// Scores normalized `A..Z` indices as the mean log-probability per quadgram.
    ///
    /// Every length-4 window contributes one log-probability and the mean over
    /// all `n - 3` windows is returned. Two edge cases are handled without
    /// panicking:
    ///
    /// - **Fewer than four indices** (`n < 4`): no window exists, so the shared
    ///   floor log-probability is returned (the same value an unseen quadgram
    ///   would receive).
    /// - **Out-of-range indices** (any value `>= ALPHABET_LEN`): the offending
    ///   window is scored at the floor log-probability rather than indexed, so a
    ///   stray index never panics and never masquerades as a real quadgram.
    #[must_use]
    pub fn score_indices(&self, indices: &[usize]) -> f64 {
        let window_count = match indices.len().checked_sub(3) {
            Some(count) if count >= 1 => count,
            _ => return f64::from(self.floor_logprob),
        };
        let mut sum = 0.0_f64;
        for window in indices.windows(4) {
            if let &[a, b, c, d] = window {
                sum += f64::from(self.window_logprob(a, b, c, d));
            }
        }
        sum / window_count as f64
    }

    /// Scores normalized `A..Z` indices as the **sum** of log-probability over
    /// every length-4 window (not the mean).
    ///
    /// This is the well-scaled objective for a permutation-key simulated anneal:
    /// the per-window mean ([`Self::score_indices`]) makes single-move score
    /// deltas vanishingly small (≈0.01 nats), so any sane temperature degenerates
    /// to a random walk; the sum keeps deltas at the ≈1–100 nat scale the
    /// Metropolis schedule needs. Because the scored stream has a fixed length
    /// during a search, the sum and the mean are monotonically related
    /// (`sum = mean * window_count`), so they rank permutations identically — the
    /// sum is used only to recover usable temperature scaling.
    ///
    /// Edge cases mirror [`Self::score_indices`]: fewer than four indices returns
    /// the shared floor log-probability, and any out-of-range window is scored at
    /// the floor rather than indexed (never panics).
    #[must_use]
    pub fn score_indices_sum(&self, indices: &[usize]) -> f64 {
        if indices.len() < 4 {
            return f64::from(self.floor_logprob);
        }
        let mut sum = 0.0_f64;
        for window in indices.windows(4) {
            if let &[a, b, c, d] = window {
                sum += f64::from(self.window_logprob(a, b, c, d));
            }
        }
        sum
    }

    /// Normalizes `text` to `A..Z` indices and scores it via [`Self::score_indices`].
    ///
    /// Normalization follows the same rules as [`Self::from_sample`]: ASCII
    /// letters are kept and uppercased, everything else is dropped.
    #[must_use]
    pub fn score_letters(&self, text: &str) -> f64 {
        let indices = normalize_to_indices(text);
        self.score_indices(&indices)
    }

    /// Returns the total number of quadgram windows observed during training.
    #[must_use]
    pub const fn total_quadgrams(&self) -> u64 {
        self.total_quadgrams
    }

    /// Returns the additive smoothing parameter used to build the model.
    #[must_use]
    pub const fn smoothing(&self) -> f64 {
        self.smoothing
    }

    /// Returns the floor log-probability assigned to unseen or out-of-range
    /// quadgrams.
    #[must_use]
    pub fn floor_logprob(&self) -> f64 {
        f64::from(self.floor_logprob)
    }

    fn window_logprob(&self, a: usize, b: usize, c: usize, d: usize) -> f32 {
        if a >= ALPHABET_LEN || b >= ALPHABET_LEN || c >= ALPHABET_LEN || d >= ALPHABET_LEN {
            return self.floor_logprob;
        }
        let quadgram = quadgram_index(a, b, c, d);
        self.logprob
            .get(quadgram)
            .copied()
            .unwrap_or(self.floor_logprob)
    }
}

/// Normalizes text to `A..Z` indices, keeping ASCII letters and dropping the rest.
fn normalize_to_indices(text: &str) -> Vec<usize> {
    text.chars()
        .filter(char::is_ascii_alphabetic)
        .map(|ch| usize::from(ch.to_ascii_uppercase() as u8 - b'A'))
        .collect()
}

/// Maps four `0..=25` letter indices to a `0..TABLE_LEN` quadgram offset.
const fn quadgram_index(a: usize, b: usize, c: usize, d: usize) -> usize {
    ((a * ALPHABET_LEN + b) * ALPHABET_LEN + c) * ALPHABET_LEN + d
}

#[cfg(test)]
mod tests {
    use super::{ALPHABET_LEN, QuadgramError, QuadgramModel, TABLE_LEN};

    const ENGLISH_SENTENCE: &str =
        "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG AND THEN RETURNS HOME";

    // A fixed consonant-heavy scramble of similar length with no English
    // quadgram structure.
    const RANDOM_LETTERS: &str = "ZQXJKVWBPFMGYHQZJXKVWPFBMGYHCLZQXJKVWBPFMGYHQZJXKVWPFBMGY";

    fn caesar_shift(text: &str, shift: u8) -> String {
        text.chars()
            .map(|c| {
                if c.is_ascii_uppercase() {
                    let idx = (c as u8 - b'A' + shift) % 26;
                    (b'A' + idx) as char
                } else {
                    c
                }
            })
            .collect()
    }

    #[test]
    fn table_len_is_26_to_the_fourth() {
        assert_eq!(TABLE_LEN, 456_976);
        assert_eq!(ALPHABET_LEN, 26);
    }

    #[test]
    fn english_model_builds() {
        let model = QuadgramModel::english();
        assert!(model.is_ok(), "english model failed to build: {model:?}");
        let model = model.unwrap();
        assert!(model.total_quadgrams() > 1_000_000);
        assert!(model.floor_logprob().is_finite());
    }

    #[test]
    fn english_scores_above_random() {
        let model = QuadgramModel::english().unwrap();
        let english = model.score_letters(ENGLISH_SENTENCE);
        let random = model.score_letters(RANDOM_LETTERS);
        println!(
            "english={english:.6} random={random:.6} margin={:.6}",
            english - random
        );
        assert!(
            english > random,
            "english {english} should beat random {random}"
        );
    }

    #[test]
    fn plaintext_beats_caesar_shift() {
        let model = QuadgramModel::english().unwrap();
        let plaintext = model.score_letters(ENGLISH_SENTENCE);
        let shifted = model.score_letters(&caesar_shift(ENGLISH_SENTENCE, 3));
        println!(
            "plaintext={plaintext:.6} caesar3={shifted:.6} margin={:.6}",
            plaintext - shifted
        );
        assert!(
            plaintext > shifted,
            "plaintext {plaintext} should beat caesar-3 {shifted}"
        );
    }

    #[test]
    fn deterministic() {
        let model = QuadgramModel::english().unwrap();
        let first = model.score_letters(ENGLISH_SENTENCE);
        let second = model.score_letters(ENGLISH_SENTENCE);
        assert_eq!(first.to_bits(), second.to_bits());
    }

    #[test]
    fn tiny_sample_errors_or_floors() {
        // Documented contract: fewer than 4 letters is an error (no quadgram
        // window can be formed).
        let error = QuadgramModel::from_sample("ABC", 0.5).unwrap_err();
        assert_eq!(error, QuadgramError::SampleTooSmall { letters: 3 });
    }

    #[test]
    fn rejects_bad_smoothing() {
        assert_eq!(
            QuadgramModel::from_sample("ABCDEF", 0.0).unwrap_err(),
            QuadgramError::InvalidSmoothing { smoothing: 0.0 }
        );
        assert!(matches!(
            QuadgramModel::from_sample("ABCDEF", -1.0),
            Err(QuadgramError::InvalidSmoothing { .. })
        ));
        assert!(matches!(
            QuadgramModel::from_sample("ABCDEF", f64::NAN),
            Err(QuadgramError::InvalidSmoothing { .. })
        ));
    }

    #[test]
    fn short_input_returns_floor_without_panicking() {
        let model = QuadgramModel::english().unwrap();
        let floor = model.floor_logprob();
        assert_eq!(model.score_indices(&[0, 1, 2]).to_bits(), floor.to_bits());
        assert_eq!(model.score_indices(&[]).to_bits(), floor.to_bits());
    }

    #[test]
    fn out_of_range_indices_do_not_panic() {
        let model = QuadgramModel::english().unwrap();
        // Every window contains an out-of-range index, so the mean is the floor.
        let score = model.score_indices(&[99, 100, 101, 102, 103]);
        assert!(score.is_finite());
        assert!(score <= model.floor_logprob() + 1e-9);
    }
}

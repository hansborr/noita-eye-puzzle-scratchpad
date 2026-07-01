//! Rank-code encoder and decoder.

use super::predictor::{LETTERS, RankPredictor};

/// Encodes plaintext letters as 1-based predictor ranks.
///
/// For each plaintext letter, the predictor is queried with the decoded-so-far
/// context, the letter's rank is emitted, and the letter is appended to the
/// context. Ranks can be as large as 26; `one`'s carrier can only represent the
/// subset whose ranks are at most its maximum magnitude.
#[must_use]
pub fn rank_encode(pred: &RankPredictor, letters: &[usize]) -> Vec<usize> {
    let mut context = Vec::with_capacity(letters.len());
    let mut ranks = Vec::with_capacity(letters.len());
    for &letter in letters {
        let rank = pred.rank_of(&context, letter);
        ranks.push(rank);
        if letter < LETTERS {
            context.push(letter);
        }
    }
    ranks
}

/// Decodes 1-based predictor ranks into `A=0..Z=25` letters.
///
/// Rank values outside `1..=26` are clamped to that range so malformed external
/// carriers produce a deterministic candidate instead of panicking.
#[must_use]
pub fn rank_decode(pred: &RankPredictor, magnitudes: &[usize]) -> Vec<usize> {
    let mut context = Vec::with_capacity(magnitudes.len());
    let mut letters = Vec::with_capacity(magnitudes.len());
    for &rank in magnitudes {
        let ranked = pred.ranked(&context);
        let index = rank.clamp(1, LETTERS) - 1;
        let letter = ranked.get(index).copied().unwrap_or(0);
        letters.push(letter);
        context.push(letter);
    }
    letters
}

//! Planted positive control for the `mag-pairs` tokenizer.

use std::collections::HashMap;

use crate::core::glyph::Glyph;

use super::derive::StreamKind;

/// English text used by the bigramcodec planted positive control.
///
/// The letter inventory is deliberately restricted so the injective
/// substitution search has enough repeated structure to recover readable text at
/// a modest deterministic budget.
pub const BIGRAM_PLANT_TEXT: &str = "THERAINONTHEROADANDTHEWINDINTHETREESHIDTHELOSTRIDERSINTOTHEOLDNORTHLANDS\
WHERENOONEHADSAILEDORTRADEDINTENSLOWSEASONSANDTHESTONEWALLSHELDTHESILENTDEAD\
WHILETHETIREDRIDERSRODEONINTOTHERAINANDTHEWINDANDTHELONESHADEANDTHEOLDROAD";

/// Positive-control stream family.
pub const BIGRAM_PLANT_STREAM: StreamKind = StreamKind::MagPairs;

/// Converts ASCII text to `A=0..Z=25` letters, dropping non-letters.
#[must_use]
pub fn english_letters(text: &str) -> Vec<usize> {
    text.bytes()
        .filter(u8::is_ascii_alphabetic)
        .map(|byte| usize::from(byte.to_ascii_uppercase() - b'A'))
        .collect()
}

/// Builds base-5 walk digits whose `mag-pairs` token stream is a substitution of
/// the built-in positive-control text.
#[must_use]
pub fn planted_magpair_walk() -> Vec<Glyph> {
    let letters = english_letters(BIGRAM_PLANT_TEXT);
    let magnitudes = encode_mag_pairs(&letters, 5);
    crate::attack::rlcodec::synthesize_walk(&magnitudes, 5)
}

fn encode_mag_pairs(letters: &[usize], base: usize) -> Vec<usize> {
    let mut rank_of: HashMap<usize, usize> = HashMap::new();
    let mut magnitudes = Vec::with_capacity(letters.len() * 2);
    for &letter in letters {
        let next_rank = rank_of.len();
        let rank = *rank_of.entry(letter).or_insert(next_rank);
        let first = rank / base;
        let second = rank % base;
        magnitudes.push(first + 1);
        magnitudes.push(second + 1);
    }
    magnitudes
}

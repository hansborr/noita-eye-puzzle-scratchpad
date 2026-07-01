//! Reusable planted-codec encoders for the run-length carrier instruments.
//!
//! The comma encoder is the constructive inverse of [`super::RlCodec::Comma`]:
//! it maps each first-seen plaintext letter to a distinct tuple over magnitude
//! values `{1, 2, 3}`, separates letters with a reserved separator magnitude,
//! then realizes those magnitudes as a synthetic `±1` walk.

use std::collections::HashMap;

use crate::core::glyph::Glyph;

use super::derive::synthesize_walk;

/// Separator magnitude used by the standard planted comma code.
pub const DEFAULT_COMMA_SEP: usize = 4;
/// Base of the standard synthetic `±1` walk.
pub const DEFAULT_PLANT_BASE: usize = 5;

/// A genuine, long English plaintext for planted positive controls.
///
/// Restricted to a 12-letter alphabet (`A D E H I L N O R S T W`) so the planted
/// stream's substitution search converges reliably at a modest budget. The power
/// harness can reuse this as its built-in English source when no file is supplied.
pub const PLANT_PLAINTEXT: &str = "THERAINONTHEROADANDTHEWINDINTHETREESHIDTHELOSTRIDERS\
INTOTHEOLDNORTHLANDSWHERENOONEHADSAILEDORTRADEDINTENSLOWSEASONSANDTHESTONEWALLSHELD\
THESILENTDEADWHILETHETIREDRIDERSRODEONINTOTHERAINANDTHEWINDANDTHELONESHADEANDTHEOLD\
ROADSTILLLEDTHERIDERSINTOTHENORTHWHERETHEHEARTLANDSLIEDROWNEDINRAIN";

/// Converts ASCII English text to `A=0..Z=25` letter indices, dropping
/// non-letters and uppercasing lowercase letters.
#[must_use]
pub fn english_letters(text: &str) -> Vec<usize> {
    text.bytes()
        .filter(u8::is_ascii_alphabetic)
        .map(|byte| usize::from(byte.to_ascii_uppercase() - b'A'))
        .collect()
}

/// Maps each distinct value to a dense id by first appearance.
#[must_use]
pub fn partition_of(values: &[usize]) -> Vec<usize> {
    let mut ids: HashMap<usize, usize> = HashMap::new();
    let mut out = Vec::with_capacity(values.len());
    for &value in values {
        let next = ids.len();
        out.push(*ids.entry(value).or_insert(next));
    }
    out
}

/// Comma-encodes an English letter sequence into a synthetic `±1` walk.
///
/// Each distinct letter receives a distinct tuple over magnitude values
/// `{1, 2, 3}` in first-appearance order. Tuples are separated by `sep`, then
/// the internal walk synthesizer realizes the magnitude stream over the given
/// `base`.
/// Returns an empty walk if `base < 2`, because no valid cycle walk exists.
#[must_use]
pub fn encode_comma(letters: &[usize], sep: usize, base: usize) -> Vec<Glyph> {
    if base < 2 {
        return Vec::new();
    }

    let mut rank_of: HashMap<usize, usize> = HashMap::new();
    let mut magnitudes: Vec<usize> = Vec::new();
    for (position, &letter) in letters.iter().enumerate() {
        if position > 0 {
            magnitudes.push(sep);
        }
        let next_rank = rank_of.len();
        let rank = *rank_of.entry(letter).or_insert(next_rank);
        magnitudes.extend(tuple_for_rank(rank));
    }
    synthesize_walk(&magnitudes, base)
}

/// The `rank`-th distinct tuple over `{1, 2, 3}`, enumerated by increasing length
/// then lexicographically. Injective in `rank`, so distinct letters get distinct
/// tuples.
fn tuple_for_rank(rank: usize) -> Vec<usize> {
    let symbols = [1usize, 2, 3];
    let mut remaining = rank;
    let mut length = 1usize;
    loop {
        let count = symbols.len().pow(u32::try_from(length).unwrap_or(1));
        if remaining < count {
            let mut digits = Vec::with_capacity(length);
            let mut value = remaining;
            for _ in 0..length {
                let digit = value % symbols.len();
                value /= symbols.len();
                digits.push(*symbols.get(digit).unwrap_or(&1));
            }
            digits.reverse();
            return digits;
        }
        remaining -= count;
        length += 1;
    }
}

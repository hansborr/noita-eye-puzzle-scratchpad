//! Shared two-q-symbol pair extraction for shadow-finish instruments.

use super::tables::strict_language_byte;
use super::{DigitOrder, PairPhase, ShadowFinishTable};

pub(super) fn decode_pattern(
    pattern: &[u16],
    phase: PairPhase,
    order: DigitOrder,
    permutation: [u8; 8],
    table: &ShadowFinishTable,
) -> Option<(Vec<u8>, bool)> {
    let values = pair_values(pattern, phase, order, permutation)?;
    let mut out = Vec::with_capacity(values.len());
    let mut strict = true;
    for value in values {
        let byte = table.decode(value)?;
        strict &= strict_language_byte(byte);
        out.push(byte);
    }
    Some((out, strict))
}

pub(super) fn pair_values(
    pattern: &[u16],
    phase: PairPhase,
    order: DigitOrder,
    permutation: [u8; 8],
) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(pattern.len() / 2);
    for (left, right) in pair_iter(pattern, phase) {
        let left = *permutation.get(usize::from(left))?;
        let right = *permutation.get(usize::from(right))?;
        let value = match order {
            DigitOrder::HighLow => left * 8 + right,
            DigitOrder::LowHigh => right * 8 + left,
        };
        out.push(value);
    }
    Some(out)
}

fn pair_iter(pattern: &[u16], phase: PairPhase) -> impl Iterator<Item = (u16, u16)> + '_ {
    let start = match phase {
        PairPhase::Phase0 => 0,
        PairPhase::Phase1 => 1,
    };
    pattern
        .get(start..)
        .unwrap_or(&[])
        .chunks_exact(2)
        .filter_map(|chunk| match *chunk {
            [left, right] => Some((left, right)),
            _ => None,
        })
}

//! Direction-bit derivation (the `±1`-walk gate) and the readout-grid sweep.

use crate::core::glyph::Glyph;

use super::{
    BitOrder, CellParams, CellReadout, MaskError, MaskKind, NotAWalkDetail, Polarity, ReadDirection,
};

/// Outcome of the walk gate: direction bits, or the first `±1` violation.
pub(super) enum Derivation {
    /// Every transition was `±1 mod base`; the up (`+1`) bits.
    Walk(Vec<bool>),
    /// The first violating transition.
    NotAWalk(NotAWalkDetail),
}

/// Derives the direction bits of a `±1` walk (`true` = the `+1`/up move).
pub(super) fn derive_direction_bits(
    digits: &[Glyph],
    base: usize,
) -> Result<Derivation, MaskError> {
    let mut bits = Vec::with_capacity(digits.len().saturating_sub(1));
    for (position, pair) in digits.windows(2).enumerate() {
        let [a, b] = pair else { continue };
        let from = usize::from(a.0);
        let to = usize::from(b.0);
        if from >= base {
            return Err(MaskError::SymbolOutOfRange { value: from, base });
        }
        if to >= base {
            return Err(MaskError::SymbolOutOfRange { value: to, base });
        }
        let diff = (to + base - from) % base;
        if diff == 1 {
            bits.push(true);
        } else if diff == base - 1 {
            bits.push(false);
        } else {
            return Ok(Derivation::NotAWalk(NotAWalkDetail {
                position,
                from,
                to,
                diff,
                base,
            }));
        }
    }
    Ok(Derivation::Walk(bits))
}

/// Enumerates every cell of the sweep grid for the given widths.
pub(super) fn enumerate_cells(widths: &[usize]) -> Vec<CellParams> {
    let mut cells = Vec::new();
    for &width in widths {
        for mask in [MaskKind::Static, MaskKind::Alternating] {
            for offset in 0..width {
                for order in [BitOrder::MsbFirst, BitOrder::LsbFirst] {
                    for polarity in [Polarity::Plain, Polarity::Complemented] {
                        for direction in [ReadDirection::Forward, ReadDirection::Reversed] {
                            cells.push(CellParams {
                                mask,
                                width,
                                offset,
                                order,
                                polarity,
                                direction,
                            });
                        }
                    }
                }
            }
        }
    }
    cells
}

/// Applies direction, mask, and polarity: `p[i] = o'[i] ^ b_i ^ pol`, where
/// `o'` is the (possibly reversed) direction-bit stream.
pub(super) fn masked_stream(bits: &[bool], params: &CellParams) -> Vec<bool> {
    let polarity = matches!(params.polarity, Polarity::Complemented);
    let stream: Vec<bool> = match params.direction {
        ReadDirection::Forward => bits.to_vec(),
        ReadDirection::Reversed => bits.iter().rev().copied().collect(),
    };
    stream
        .iter()
        .enumerate()
        .map(|(index, &bit)| bit ^ params.mask.bit(index) ^ polarity)
        .collect()
}

/// Assembles one chunk's value under the given bit order.
pub(super) fn chunk_value(chunk: &[bool], order: BitOrder) -> u32 {
    let fold = |acc: u32, bit: &bool| (acc << 1) | u32::from(*bit);
    match order {
        BitOrder::MsbFirst => chunk.iter().fold(0, fold),
        BitOrder::LsbFirst => chunk.iter().rev().fold(0, fold),
    }
}

/// `true` for ASCII letters `A-Z`/`a-z` and space.
pub(super) const fn is_letter_or_space(value: u32) -> bool {
    value == 0x20 || (value >= 0x41 && value <= 0x5a) || (value >= 0x61 && value <= 0x7a)
}

/// `true` for printable ASCII (`0x20..=0x7E`).
pub(super) const fn is_printable(value: u32) -> bool {
    value >= 0x20 && value <= 0x7e
}

/// The display character for a chunk value (`.` for non-printables).
pub(super) fn render_value(value: u32) -> char {
    if is_printable(value) {
        char::from_u32(value).unwrap_or('.')
    } else {
        '.'
    }
}

/// Reads one cell: mask the stream, skip `offset` bits, chunk, classify.
pub(super) fn read_cell(bits: &[bool], params: &CellParams) -> CellReadout {
    let masked = masked_stream(bits, params);
    let body = masked.get(params.offset..).unwrap_or(&[]);
    let n_chunks = body.len() / params.width;
    let tail_bits = body.len() % params.width;
    let mut n_letters = 0usize;
    let mut n_printable = 0usize;
    let mut rendered = String::with_capacity(n_chunks);
    for chunk in body.chunks_exact(params.width) {
        let value = chunk_value(chunk, params.order);
        if is_letter_or_space(value) {
            n_letters += 1;
        }
        if is_printable(value) {
            n_printable += 1;
        }
        rendered.push(render_value(value));
    }
    CellReadout {
        params: *params,
        n_chunks,
        n_letters,
        n_printable,
        head_bits: params.offset.min(masked.len()),
        tail_bits,
        rendered,
    }
}

/// Ranks readouts by letter fraction, then printable fraction (both
/// descending), then the canonical parameter key (ascending).
pub(super) fn rank_readouts(readouts: &mut [CellReadout]) {
    readouts.sort_by(|a, b| {
        b.letter_fraction()
            .total_cmp(&a.letter_fraction())
            .then_with(|| b.printable_fraction().total_cmp(&a.printable_fraction()))
            .then_with(|| a.params.canonical_key().cmp(&b.params.canonical_key()))
    });
}

//! Head/tail completion enumeration and the decisive exact round-trip
//! re-encode that separates a candidate readout from a verified decode.

use crate::core::glyph::Glyph;

use super::sweep::{chunk_value, is_letter_or_space, masked_stream, render_value};
use super::{
    BitOrder, CandidateCell, CellParams, CellReadout, Completion, MIN_BASE, MaskError, Polarity,
    ReadDirection, validate_width,
};

/// Encodes `text` as a `±1` walk on `C_base` under `params`, starting from
/// digit `start`, with every message bit carried by the walk.
///
/// This is the planted-control encoder: it is the exact inverse of a
/// chunk-aligned (`offset = 0`, no partial tail) readout at the same cell.
///
/// # Errors
/// Returns [`MaskError`] if the width is out of range, the base is below
/// [`MIN_BASE`], the starting digit is not below the base, or a character does
/// not fit the chunk width.
pub fn mask_encode(
    text: &str,
    params: &CellParams,
    base: usize,
    start: usize,
) -> Result<Vec<Glyph>, MaskError> {
    mask_encode_trimmed(text, params, base, start, 0, 0)
}

/// Round-trip encoder with head/tail trim: encodes `text` under `params` but
/// drops the first `head_skip` and last `tail_skip` message bits before
/// walking from `start`.
///
/// A readout at chunk offset `o > 0` misses the first `width - o` message bits
/// (they precede the ciphertext) and a partial tail of `t` observed bits
/// misses the last `width - t`; those are exactly the skips this re-encoder
/// drops, so a verified completion reproduces the ciphertext digits exactly.
///
/// # Errors
/// Returns [`MaskError`] under the same conditions as [`mask_encode`].
pub fn mask_encode_trimmed(
    text: &str,
    params: &CellParams,
    base: usize,
    start: usize,
    head_skip: usize,
    tail_skip: usize,
) -> Result<Vec<Glyph>, MaskError> {
    validate_width(params.width)?;
    if base < MIN_BASE {
        return Err(MaskError::InvalidBase { base });
    }
    if start >= base {
        return Err(MaskError::InvalidStartDigit { start, base });
    }
    let mut message_bits = Vec::with_capacity(text.len() * params.width);
    for ch in text.chars() {
        let value = char_value(ch, params.width)?;
        message_bits.extend(char_stream_bits(value, params.width, params.order));
    }
    let end = message_bits.len().saturating_sub(tail_skip);
    let carried = message_bits.get(head_skip..end).unwrap_or(&[]);
    let polarity = matches!(params.polarity, Polarity::Complemented);
    let masked: Vec<bool> = carried
        .iter()
        .enumerate()
        .map(|(index, &bit)| bit ^ params.mask.bit(index) ^ polarity)
        .collect();
    let directions: Vec<bool> = match params.direction {
        ReadDirection::Forward => masked,
        ReadDirection::Reversed => masked.into_iter().rev().collect(),
    };
    Ok(walk_digits(start, &directions, base))
}

fn char_value(ch: char, width: usize) -> Result<u32, MaskError> {
    let value = u32::from(ch);
    let capacity = 1u32 << width.min(31);
    if width < 32 && value >= capacity {
        return Err(MaskError::UnencodableChar { ch, width });
    }
    Ok(value)
}

/// The `width` stream-order bits of `value` under the given bit order.
pub(super) fn char_stream_bits(value: u32, width: usize, order: BitOrder) -> Vec<bool> {
    (0..width)
        .map(|position| {
            let shift = match order {
                BitOrder::MsbFirst => width - 1 - position,
                BitOrder::LsbFirst => position,
            };
            (value >> shift) & 1 == 1
        })
        .collect()
}

/// Walks from `start` on `C_base`, `+1` for each `true` bit, `-1` otherwise.
pub(super) fn walk_digits(start: usize, directions: &[bool], base: usize) -> Vec<Glyph> {
    let mut digits = Vec::with_capacity(directions.len() + 1);
    let mut current = start % base.max(1);
    digits.push(Glyph(u16::try_from(current).unwrap_or(0)));
    for &up in directions {
        current = if up {
            (current + 1) % base
        } else {
            (current + base - 1) % base
        };
        digits.push(Glyph(u16::try_from(current).unwrap_or(0)));
    }
    digits
}

#[derive(Clone, Copy)]
enum Side {
    Head,
    Tail,
}

/// Enumerates the `2^missing` completions of a partial chunk and keeps those
/// whose value is an ASCII letter or space.
fn letter_completions(observed: &[bool], width: usize, order: BitOrder, side: Side) -> Vec<char> {
    let missing = width.saturating_sub(observed.len());
    let variants = 1u32 << missing.min(31);
    let mut out = Vec::new();
    for pattern in 0..variants {
        let missing_bits: Vec<bool> = (0..missing)
            .map(|position| (pattern >> (missing - 1 - position)) & 1 == 1)
            .collect();
        let stream: Vec<bool> = match side {
            Side::Head => missing_bits
                .iter()
                .chain(observed.iter())
                .copied()
                .collect(),
            Side::Tail => observed
                .iter()
                .chain(missing_bits.iter())
                .copied()
                .collect(),
        };
        let value = chunk_value(&stream, order);
        if is_letter_or_space(value)
            && let Some(ch) = char::from_u32(value)
        {
            out.push(ch);
        }
    }
    out
}

/// Verifies one full-letter readout: enumerate letter/space head/tail
/// completions, re-encode each completed text under the same cell from the
/// observed starting digit, and count reproduced digits.
pub(super) fn verify_candidate(
    readout: &CellReadout,
    bits: &[bool],
    digits: &[Glyph],
    base: usize,
) -> CandidateCell {
    let params = readout.params;
    let width = params.width;
    let masked = masked_stream(bits, &params);
    let body = masked.get(params.offset..).unwrap_or(&[]);
    let n_chunks = body.len() / width;
    let tail_len = body.len() % width;
    let core: String = body
        .chunks_exact(width)
        .map(|chunk| render_value(chunk_value(chunk, params.order)))
        .collect();

    let head_observed = masked.get(..params.offset.min(masked.len())).unwrap_or(&[]);
    let head_options = if params.offset == 0 {
        Vec::new()
    } else {
        letter_completions(head_observed, width, params.order, Side::Head)
    };
    let tail_observed = body.get(n_chunks * width..).unwrap_or(&[]);
    let tail_options = if tail_len == 0 {
        Vec::new()
    } else {
        letter_completions(tail_observed, width, params.order, Side::Tail)
    };
    let head_missing_bits = if params.offset == 0 {
        0
    } else {
        width - params.offset
    };
    let tail_missing_bits = if tail_len == 0 { 0 } else { width - tail_len };

    let head_choices: Vec<Option<char>> = if params.offset == 0 {
        vec![None]
    } else {
        head_options.iter().copied().map(Some).collect()
    };
    let tail_choices: Vec<Option<char>> = if tail_len == 0 {
        vec![None]
    } else {
        tail_options.iter().copied().map(Some).collect()
    };

    let start = digits.first().map_or(0, |glyph| usize::from(glyph.0));
    let mut completions = Vec::new();
    for &head in &head_choices {
        for &tail in &tail_choices {
            let mut text = String::with_capacity(core.len() + 2);
            if let Some(ch) = head {
                text.push(ch);
            }
            text.push_str(&core);
            if let Some(ch) = tail {
                text.push(ch);
            }
            let matched = match mask_encode_trimmed(
                &text,
                &params,
                base,
                start,
                head_missing_bits,
                tail_missing_bits,
            ) {
                Ok(encoded) if encoded.len() == digits.len() => encoded
                    .iter()
                    .zip(digits.iter())
                    .filter(|(a, b)| a == b)
                    .count(),
                Ok(_) | Err(_) => 0,
            };
            completions.push(Completion {
                text,
                head_char: head,
                tail_char: tail,
                matched,
                total: digits.len(),
            });
        }
    }

    CandidateCell {
        readout: readout.clone(),
        head_missing_bits,
        tail_missing_bits,
        head_options,
        tail_options,
        completions,
    }
}

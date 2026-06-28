//! Codec transduction mechanics: forward grouping/delta transduction, the
//! round-trip + alphabet-size sanity gates, and the inverse (ungroup /
//! re-integrate) the round-trip uses.
//!
//! Split out of [`super`] (the codec layer) to keep `mod.rs` within the
//! file-size budget. Every item keeps its original visibility and the public
//! ones are re-exported from [`super`], so external paths
//! (`crate::attack::codec::*`) are unchanged.

use crate::core::glyph::Glyph;

use super::{AnyCodec, Codec, CodecError, DeltaCodec, DigitOrder, GroupingCodec};

/// Resolves a codec's output alphabet size given the input cipher alphabet size.
///
/// [`AnyCodec::Identity`] inherits the input cipher alphabet (its bare
/// [`Codec::output_alphabet_size`] returns a `0` sentinel); widening codecs report
/// their intrinsic size. This is the size a mapping's domain must cover.
#[must_use]
pub fn resolved_output_alphabet_size(codec: &AnyCodec, cipher_alphabet_size: usize) -> usize {
    match codec {
        AnyCodec::Identity => cipher_alphabet_size,
        AnyCodec::FixedGrouping(codec) => grouping_output_alphabet_size(codec),
        AnyCodec::Delta(codec) => resolved_output_alphabet_size(&codec.then, codec.base),
    }
}

pub(super) fn grouping_output_alphabet_size(codec: &GroupingCodec) -> usize {
    saturating_pow(codec.base, codec.group_len)
}

/// `base.pow(exp)` saturating to [`usize::MAX`] instead of overflowing.
fn saturating_pow(base: usize, exp: usize) -> usize {
    let Ok(exp) = u32::try_from(exp) else {
        return usize::MAX;
    };
    base.checked_pow(exp).unwrap_or(usize::MAX)
}

/// Forward `FixedGrouping`: combine each group of `group_len` digits (stepping by
/// `stride`) into one value. Errors on a non-multiple length so a trailing partial
/// group is never silently dropped.
pub(super) fn group_symbols(
    codec: &GroupingCodec,
    symbols: &[Glyph],
) -> Result<Vec<Glyph>, CodecError> {
    let group_len = codec.group_len;
    let len = symbols.len();
    if group_len == 0 || codec.base == 0 {
        return Err(CodecError::LengthNotGroupMultiple { len, group_len });
    }
    if !len.is_multiple_of(group_len) {
        return Err(CodecError::LengthNotGroupMultiple { len, group_len });
    }
    let stride = codec.stride.max(1);
    let mut out = Vec::with_capacity(len / group_len);
    let mut start = 0usize;
    while start + group_len <= len {
        let group = symbols
            .get(start..start + group_len)
            .ok_or(CodecError::LengthNotGroupMultiple { len, group_len })?;
        out.push(combine_digits(group, codec.base, codec.order)?);
        start += stride;
    }
    Ok(out)
}

/// Combines `group` base-`base` digits into a single value in [`DigitOrder`]
/// order. `Msb` makes the first digit most-significant (matches `src/trigram.rs`).
fn combine_digits(group: &[Glyph], base: usize, order: DigitOrder) -> Result<Glyph, CodecError> {
    let mut value = 0usize;
    match order {
        DigitOrder::Msb => {
            for glyph in group {
                value = horner_step(value, *glyph, base)?;
            }
        }
        DigitOrder::Lsb => {
            for glyph in group.iter().rev() {
                value = horner_step(value, *glyph, base)?;
            }
        }
    }
    if value > usize::from(u16::MAX) {
        return Err(CodecError::OutputValueTooWide { value });
    }
    Ok(Glyph(value as u16))
}

/// One Horner step `value * base + digit`, validating `digit < base`.
///
/// Uses checked arithmetic (mirroring the `saturating_pow` discipline in
/// [`grouping_output_alphabet_size`]) so a pathological grouping config (e.g.
/// `base = 2` with a large `group_len`) cannot overflow `usize` mid-loop — which
/// would panic in debug and silently wrap in release. On overflow it reports the
/// pre-overflow accumulator via [`CodecError::OutputValueTooWide`]; the distinct
/// glyph-width ceiling (`value > u16::MAX`) still runs after the loop in
/// [`combine_digits`].
fn horner_step(value: usize, glyph: Glyph, base: usize) -> Result<usize, CodecError> {
    let digit = usize::from(glyph.0);
    if digit >= base {
        return Err(CodecError::ValueOutsideBase { value: digit, base });
    }
    value
        .checked_mul(base)
        .and_then(|shifted| shifted.checked_add(digit))
        .ok_or(CodecError::OutputValueTooWide { value })
}

/// Forward Delta: first-difference (mod `base`) into a move stream, then transduce
/// the moves through the inner codec. The seed (first symbol) is *not* in the
/// output — re-integration recovers it from the original stream (see
/// [`codec_round_trip_ok`]).
pub(super) fn delta_transduce(
    codec: &DeltaCodec,
    symbols: &[Glyph],
) -> Result<Vec<Glyph>, CodecError> {
    if symbols.is_empty() {
        return Err(CodecError::EmptyInput);
    }
    let base = codec.base;
    if base == 0 {
        return Err(CodecError::ValueOutsideBase { value: 0, base });
    }
    for glyph in symbols {
        let value = usize::from(glyph.0);
        if value >= base {
            return Err(CodecError::ValueOutsideBase { value, base });
        }
    }
    let mut moves = Vec::with_capacity(symbols.len().saturating_sub(1));
    for pair in symbols.windows(2) {
        let [previous, current] = pair else { continue };
        let previous = usize::from(previous.0);
        let current = usize::from(current.0);
        // (current - previous) mod base, kept in 0..base without underflow.
        let difference = (current + base - previous) % base;
        moves.push(Glyph(difference as u16));
    }
    codec.then.transduce(&moves)
}

// ---------------------------------------------------------------------------
// Codec round-trip + alphabet-size sanity gates.
// ---------------------------------------------------------------------------

/// The default language alphabet size (29: 26 Latin letters plus the Finnish
/// vowels Å, Ä, Ö), mirroring `crate::attack::language::DEFAULT_LANGUAGE_ALPHABET`. A codec
/// whose resolved output alphabet is below this cannot host the default language
/// under a symbol->letter mapping.
pub const DEFAULT_LANGUAGE_ALPHABET_SIZE: usize = 29;

/// Codec round-trip consistency check (the fourth structural gate, alongside the
/// cipher round-trip).
///
/// Where the codec [`is_invertible`](Codec::is_invertible), transduce then
/// re-expand (ungroup digits / re-integrate a delta from its seed symbol) and
/// compare to `symbols` byte-for-byte. Returns an honest `false` for a lossy input
/// (e.g. a trailing partial group that makes `transduce` error, or a stride that
/// does not partition the stream). Like the cipher round-trip, a passing codec
/// round-trip proves only codec/cipher consistency — it says nothing about whether
/// the mapping decodes anything.
#[must_use]
pub fn codec_round_trip_ok(codec: &AnyCodec, symbols: &[Glyph]) -> bool {
    if !codec.is_invertible() {
        return false;
    }
    let Ok(transduced) = codec.transduce(symbols) else {
        return false;
    };
    let Ok(expanded) = re_expand(codec, &transduced, symbols) else {
        return false;
    };
    expanded == symbols
}

/// Alphabet-size sanity predicate: can the codec's resolved output alphabet host a
/// language of `language_alphabet_size` symbols?
///
/// `true` iff
/// `resolved_output_alphabet_size(codec, cipher_alphabet_size) >= language_alphabet_size`.
/// This formalizes "5 < 26, 12 < 26 => you need a codec": [`AnyCodec::Identity`]
/// over a 5- or 12-symbol cipher alphabet fails for 29-letter English, while
/// `Identity` over the 83-symbol eyes passes. For the default language pass
/// [`DEFAULT_LANGUAGE_ALPHABET_SIZE`].
///
/// # Phase boundary (not an oversight that this has no live call site yet)
/// This predicate is the **Phase 1** deliverable — predicate + unit tests only.
/// Its **enforcement as a pruning filter** is wired in
/// **Phase 2** under [`CodecStrategy::Search`](super::CodecStrategy::Search): each enumerated
/// codec is pruned by this predicate and any skip is `log()`-ed (no silent
/// truncation). The [`CodecStrategy::Fixed`](super::CodecStrategy::Fixed) path intentionally does **not** reject
/// on this predicate — `Fixed` codecs are user-declared and round-tripped + scored
/// only (no search), so e.g. a `Fixed` [`AnyCodec::Identity`] over a 26-letter
/// Latin alphabet must still solve: 26 hosts English, and the `29` threshold here
/// is the Finnish-inclusive [`DEFAULT_LANGUAGE_ALPHABET_SIZE`], not a floor for
/// English.
#[must_use]
pub fn output_alphabet_hosts_language(
    codec: &AnyCodec,
    cipher_alphabet_size: usize,
    language_alphabet_size: usize,
) -> bool {
    resolved_output_alphabet_size(codec, cipher_alphabet_size) >= language_alphabet_size
}

/// Flags a codec whose transduced output leaves the accepted alphabet
/// `0..accepted_alphabet_size`.
///
/// The honeycomb accept policy keeps trigram values `0..=82`
/// (`accepted_alphabet_size = 83`) and rejects raw `83..=124`; that accept filter
/// is a consumer-side policy, **not** part of grouping. Returns `true` when any
/// transduced value is `>= accepted_alphabet_size` (the codec emits out-of-alphabet
/// symbols for that consumer, exactly as `cipher_attack`/`solve` reject value
/// `>= 83`).
///
/// # Errors
/// Returns [`CodecError`] if the codec cannot transduce `symbols`.
pub fn output_exceeds_accepted_alphabet(
    codec: &AnyCodec,
    symbols: &[Glyph],
    accepted_alphabet_size: usize,
) -> Result<bool, CodecError> {
    let transduced = codec.transduce(symbols)?;
    Ok(transduced
        .iter()
        .any(|glyph| usize::from(glyph.0) >= accepted_alphabet_size))
}

/// Re-expands a transduced stream back to cipher symbols (the inverse used by
/// [`codec_round_trip_ok`]). `original` supplies the [`AnyCodec::Delta`] seed (its
/// first symbol); it is unused for [`AnyCodec::Identity`]/[`AnyCodec::FixedGrouping`].
fn re_expand(
    codec: &AnyCodec,
    transduced: &[Glyph],
    original: &[Glyph],
) -> Result<Vec<Glyph>, CodecError> {
    match codec {
        AnyCodec::Identity => Ok(transduced.to_vec()),
        AnyCodec::FixedGrouping(codec) => ungroup(codec, transduced),
        AnyCodec::Delta(codec) => {
            let moves = re_expand(&codec.then, transduced, original)?;
            let Some(seed) = original.first().copied() else {
                return Err(CodecError::EmptyInput);
            };
            integrate(codec.base, seed, &moves)
        }
    }
}

/// Splits each grouped value back into `group_len` base-`base` digits in
/// [`DigitOrder`] order — the inverse of [`group_symbols`] on the non-overlapping
/// (`stride == group_len`) configuration.
fn ungroup(codec: &GroupingCodec, transduced: &[Glyph]) -> Result<Vec<Glyph>, CodecError> {
    let group_len = codec.group_len;
    let base = codec.base;
    if group_len == 0 || base == 0 {
        return Err(CodecError::NonInvertible);
    }
    let mut out = Vec::with_capacity(transduced.len().saturating_mul(group_len));
    for glyph in transduced {
        let mut value = usize::from(glyph.0);
        // Extract least-significant digit first into the trailing slot, leaving
        // `digits` most-significant-first.
        let mut digits = vec![0u16; group_len];
        for slot in (0..group_len).rev() {
            let digit = value % base;
            value /= base;
            if let Some(cell) = digits.get_mut(slot) {
                *cell = digit as u16;
            }
        }
        match codec.order {
            DigitOrder::Msb => out.extend(digits.iter().copied().map(Glyph)),
            DigitOrder::Lsb => out.extend(digits.iter().rev().copied().map(Glyph)),
        }
    }
    Ok(out)
}

/// Re-integrates a [`AnyCodec::Delta`] move stream from its seed: cumulative sum
/// mod `base`. The inverse of the first-difference in [`delta_transduce`].
fn integrate(base: usize, seed: Glyph, moves: &[Glyph]) -> Result<Vec<Glyph>, CodecError> {
    if base == 0 {
        return Err(CodecError::ValueOutsideBase { value: 0, base });
    }
    let mut accumulator = usize::from(seed.0);
    if accumulator >= base {
        return Err(CodecError::ValueOutsideBase {
            value: accumulator,
            base,
        });
    }
    let mut out = Vec::with_capacity(moves.len().saturating_add(1));
    out.push(seed);
    for step in moves {
        let step = usize::from(step.0);
        if step >= base {
            return Err(CodecError::ValueOutsideBase { value: step, base });
        }
        accumulator = (accumulator + step) % base;
        out.push(Glyph(accumulator as u16));
    }
    Ok(out)
}

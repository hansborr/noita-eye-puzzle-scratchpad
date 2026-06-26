//! Codec / transduction layer.
//!
//! A codec regroups/transduces a **decrypted** cipher-symbol stream into a
//! (usually larger) value alphabet, *before* a symbol->letter mapping runs, so a
//! small cipher alphabet can carry a natural-language alphabet. A direct
//! symbol->letter substitution presupposes cipher-alphabet >= language-alphabet,
//! which is well-posed for the 83-symbol eye reading layer but structurally
//! impossible for a 5- or 12-symbol cipher alphabet (5 < 26, 12 < 26). The codec
//! is the layer that first *widens* the alphabet: `decrypt -> codec -> mapping ->
//! text`.
//!
//! The canonical real-world instance already lives in this crate: the eye
//! honeycomb reading layer groups base-5 orientation digits into trigrams with
//! raw value `0..=124` (`src/trigram.rs`), of which the contiguous `0..=82` are
//! the accepted reading-layer alphabet (`src/orders.rs`). [`AnyCodec::Identity`]
//! covers the eyes (83 >= 29, no widening needed); [`GroupingCodec`] generalizes
//! the honeycomb (`group_len` consecutive base-`base` digits -> one value); and
//! [`DeltaCodec`] captures the +/-1 walk structure observed in practice puzzle
//! `one` (`research/data/practice-puzzles/one`).
//!
//! This module is a peer of [`crate::solve`]; it supplies the codec types the
//! solve pipeline threads between `decrypt` and `mapping`. The accept-`0..=82`
//! filter is **not** part of grouping — it is a consumer-side alphabet policy
//! (see `output_exceeds_accepted_alphabet`).

use std::fmt;

use crate::glyph::Glyph;

/// Transduces a decrypted cipher-symbol stream into an output value alphabet, so
/// a symbol->letter mapping can span a natural-language alphabet.
pub trait Codec {
    /// Transduce decrypted symbols into the output value alphabet.
    ///
    /// # Errors
    /// Returns [`CodecError`] when the stream cannot be transduced — for example a
    /// non-multiple length for a grouping codec ([`CodecError::LengthNotGroupMultiple`]),
    /// a digit outside the declared base ([`CodecError::ValueOutsideBase`]), or an
    /// empty stream for a codec that needs a seed ([`CodecError::EmptyInput`]).
    fn transduce(&self, symbols: &[Glyph]) -> Result<Vec<Glyph>, CodecError>;

    /// Output value-alphabet size (the mapping's domain).
    ///
    /// For [`AnyCodec::Identity`] the output alphabet equals the input cipher
    /// alphabet, which a unit variant cannot know; it therefore returns `0` as a
    /// passthrough sentinel. Resolve it against the cipher alphabet size with
    /// [`resolved_output_alphabet_size`].
    fn output_alphabet_size(&self) -> usize;

    /// Stable family name for candidate reports.
    fn name(&self) -> &'static str;

    /// Whether [`transduce`](Codec::transduce) is invertible (enables a codec
    /// round-trip check via `codec_round_trip_ok`). This is a property of the
    /// codec *type*; a specific lossy input (e.g. a trailing partial group) still
    /// yields an honest `false` from `codec_round_trip_ok`.
    fn is_invertible(&self) -> bool;
}

/// Heterogeneous dispatch enum over the closed codec family set (the same pattern
/// [`crate::ciphers::AnyCipher`] uses for ciphers).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnyCodec {
    /// Pass-through: output alphabet == input cipher alphabet. Used when the
    /// cipher alphabet already spans the language alphabet (e.g. the 83-symbol
    /// eyes).
    Identity,
    /// Group `group_len` consecutive base-`base` digits into one value in
    /// `0..base.pow(group_len)` (the honeycomb generalization). Invertible on
    /// full-length multiples.
    FixedGrouping(GroupingCodec),
    /// First-difference (mod `base`) of the stream, then an inner codec (usually
    /// [`AnyCodec::Identity`] or [`AnyCodec::FixedGrouping`]). Captures the
    /// +/-1-walk structure of practice puzzle `one`. Invertible given the seed
    /// symbol (the first input symbol).
    Delta(DeltaCodec),
}

/// A fixed-grouping codec: `group_len` consecutive base-`base` digits in
/// [`DigitOrder`] order, advancing by `stride`, combine into one value in
/// `0..base.pow(group_len)`.
///
/// The canonical/invertible configuration is non-overlapping (`stride ==
/// group_len`), which reproduces the honeycomb base-5 trigram grouping with
/// `group_len = 3`, `base = 5`, `order = Msb`, `stride = 3`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupingCodec {
    /// Number of consecutive digits combined into one output value.
    pub group_len: usize,
    /// Radix of each input digit (each digit must be in `0..base`).
    pub base: usize,
    /// Whether the first digit of a group is the most- or least-significant.
    pub order: DigitOrder,
    /// Step between successive group starts; `stride == group_len` is
    /// non-overlapping (the invertible configuration).
    pub stride: usize,
}

/// A delta codec: first-difference (mod `base`) the stream into a move stream,
/// then transduce the moves through the inner `then` codec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeltaCodec {
    /// Radix the first differences are reduced modulo.
    pub base: usize,
    /// Inner codec applied to the move stream (usually [`AnyCodec::Identity`]).
    pub then: Box<AnyCodec>,
}

/// Digit significance order within a [`GroupingCodec`] group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigitOrder {
    /// The first digit of a group is the most-significant (matches the honeycomb
    /// trigram convention in `src/trigram.rs`: `first*base^2 + .. + last`).
    Msb,
    /// The first digit of a group is the least-significant.
    Lsb,
}

/// Error returned by the codec layer. Hand-written `Display` + [`std::error::Error`]
/// (mirrors [`crate::ciphers::CipherError`]); no `thiserror`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodecError {
    /// A codec that needs a seed (e.g. [`AnyCodec::Delta`]) received an empty
    /// stream.
    EmptyInput,
    /// A grouping codec was given a stream whose length is not a multiple of the
    /// group length (a trailing partial group would be a silent loss).
    LengthNotGroupMultiple {
        /// Stream length.
        len: usize,
        /// Group length the stream must be a multiple of.
        group_len: usize,
    },
    /// A digit was outside the declared base `0..base`.
    ValueOutsideBase {
        /// Offending digit value.
        value: usize,
        /// Declared base.
        base: usize,
    },
    /// A codec round-trip was attempted on a non-invertible codec.
    NonInvertible,
    /// A grouped value exceeded the [`Glyph`] index width (`u16`); the codec is
    /// too wide to encode into a glyph stream.
    OutputValueTooWide {
        /// Offending grouped value.
        value: usize,
    },
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => f.write_str("codec received an empty symbol stream"),
            Self::LengthNotGroupMultiple { len, group_len } => write!(
                f,
                "stream length {len} is not a multiple of group length {group_len}"
            ),
            Self::ValueOutsideBase { value, base } => {
                write!(f, "digit {value} is outside base {base}")
            }
            Self::NonInvertible => {
                f.write_str("codec is not invertible; no round-trip is available")
            }
            Self::OutputValueTooWide { value } => {
                write!(f, "grouped value {value} exceeds the glyph index width")
            }
        }
    }
}

impl std::error::Error for CodecError {}

impl Codec for AnyCodec {
    fn transduce(&self, symbols: &[Glyph]) -> Result<Vec<Glyph>, CodecError> {
        match self {
            Self::Identity => Ok(symbols.to_vec()),
            Self::FixedGrouping(codec) => group_symbols(codec, symbols),
            Self::Delta(codec) => delta_transduce(codec, symbols),
        }
    }

    fn output_alphabet_size(&self) -> usize {
        match self {
            // Passthrough sentinel: resolve with `resolved_output_alphabet_size`.
            Self::Identity => 0,
            Self::FixedGrouping(codec) => grouping_output_alphabet_size(codec),
            Self::Delta(codec) => resolved_output_alphabet_size(&codec.then, codec.base),
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::FixedGrouping(_) => "fixed-grouping",
            Self::Delta(_) => "delta",
        }
    }

    fn is_invertible(&self) -> bool {
        // Identity is trivially invertible; FixedGrouping is invertible on a
        // full-length multiple (a trailing partial group is the only loss, caught
        // by `codec_round_trip_ok`); Delta is invertible given its seed symbol.
        true
    }
}

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

fn grouping_output_alphabet_size(codec: &GroupingCodec) -> usize {
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
fn group_symbols(codec: &GroupingCodec, symbols: &[Glyph]) -> Result<Vec<Glyph>, CodecError> {
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
fn horner_step(value: usize, glyph: Glyph, base: usize) -> Result<usize, CodecError> {
    let digit = usize::from(glyph.0);
    if digit >= base {
        return Err(CodecError::ValueOutsideBase { value: digit, base });
    }
    Ok(value * base + digit)
}

/// Forward Delta: first-difference (mod `base`) into a move stream, then transduce
/// the moves through the inner codec. The seed (first symbol) is *not* in the
/// output — re-integration recovers it from the original stream (see
/// [`codec_round_trip_ok`]).
fn delta_transduce(codec: &DeltaCodec, symbols: &[Glyph]) -> Result<Vec<Glyph>, CodecError> {
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

#[cfg(test)]
mod tests {
    use super::{AnyCodec, Codec, CodecError, DigitOrder, GroupingCodec};
    use crate::glyph::{Glyph, Orientation};
    use crate::trigram::ReadingTrigram;

    fn glyphs(values: &[u16]) -> Vec<Glyph> {
        values.iter().copied().map(Glyph).collect()
    }

    fn honeycomb_grouping() -> GroupingCodec {
        GroupingCodec {
            group_len: 3,
            base: 5,
            order: DigitOrder::Msb,
            stride: 3,
        }
    }

    /// The honeycomb base-5 trigram value for three rendered orientation digits,
    /// taken straight from `src/trigram.rs` (the convention the codec must match).
    fn trigram_value(first: u8, second: u8, third: u8) -> u16 {
        let orientation = |digit: u8| Orientation::from_digit(digit).unwrap();
        u16::from(
            ReadingTrigram::new(orientation(first), orientation(second), orientation(third))
                .value()
                .get(),
        )
    }

    #[test]
    fn identity_is_the_identity() {
        let input = glyphs(&[3, 1, 4, 1, 0, 2]);
        assert_eq!(AnyCodec::Identity.transduce(&input).unwrap(), input);
        assert!(AnyCodec::Identity.is_invertible());
        assert_eq!(AnyCodec::Identity.name(), "identity");
    }

    #[test]
    fn fixed_grouping_matches_honeycomb_trigram_values() {
        let codec = AnyCodec::FixedGrouping(honeycomb_grouping());
        // Hand values cross-checked against ReadingTrigram::value (MSB convention):
        //   [4,4,4] -> 4*25 + 4*5 + 4 = 124 (the raw-trigram maximum)
        //   [1,2,3] -> 1*25 + 2*5 + 3 = 38
        //   [2,0,0] -> 2*25          = 50
        assert_eq!(trigram_value(4, 4, 4), 124);
        assert_eq!(trigram_value(1, 2, 3), 38);
        assert_eq!(trigram_value(2, 0, 0), 50);

        let input = glyphs(&[4, 4, 4, 1, 2, 3, 2, 0, 0]);
        let out = codec.transduce(&input).unwrap();
        assert_eq!(out, glyphs(&[124, 38, 50]));
        // And each output equals the independent trigram computation.
        assert_eq!(
            out,
            glyphs(&[
                trigram_value(4, 4, 4),
                trigram_value(1, 2, 3),
                trigram_value(2, 0, 0),
            ])
        );
    }

    #[test]
    fn fixed_grouping_lsb_reverses_significance() {
        let codec = AnyCodec::FixedGrouping(GroupingCodec {
            group_len: 3,
            base: 5,
            order: DigitOrder::Lsb,
            stride: 3,
        });
        // LSB: first digit least-significant -> 1 + 2*5 + 3*25 = 86.
        let out = codec.transduce(&glyphs(&[1, 2, 3])).unwrap();
        assert_eq!(out, glyphs(&[86]));
    }

    #[test]
    fn fixed_grouping_output_alphabet_size_is_base_pow_group_len() {
        assert_eq!(
            AnyCodec::FixedGrouping(honeycomb_grouping()).output_alphabet_size(),
            125
        );
        assert_eq!(
            AnyCodec::FixedGrouping(GroupingCodec {
                group_len: 2,
                base: 6,
                order: DigitOrder::Msb,
                stride: 2,
            })
            .output_alphabet_size(),
            36
        );
    }

    #[test]
    fn fixed_grouping_non_multiple_length_errors() {
        let codec = AnyCodec::FixedGrouping(honeycomb_grouping());
        let error = codec.transduce(&glyphs(&[0, 1, 2, 3])).unwrap_err();
        assert_eq!(
            error,
            CodecError::LengthNotGroupMultiple {
                len: 4,
                group_len: 3,
            }
        );
    }

    #[test]
    fn fixed_grouping_digit_outside_base_errors() {
        let codec = AnyCodec::FixedGrouping(honeycomb_grouping());
        let error = codec.transduce(&glyphs(&[0, 5, 1])).unwrap_err();
        assert_eq!(error, CodecError::ValueOutsideBase { value: 5, base: 5 });
    }

    #[test]
    fn fixed_grouping_empty_input_is_empty_output() {
        let codec = AnyCodec::FixedGrouping(honeycomb_grouping());
        assert_eq!(codec.transduce(&[]).unwrap(), Vec::<Glyph>::new());
    }
}

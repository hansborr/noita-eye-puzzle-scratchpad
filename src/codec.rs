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
//! (see [`output_exceeds_accepted_alphabet`]).

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
    ///
    /// # Do NOT use this for alphabet-size sanity / search pruning
    /// Because this bare method returns the `0` passthrough sentinel for
    /// [`AnyCodec::Identity`], the obvious pruning idiom
    /// `codec.output_alphabet_size() >= N` would WRONGLY reject `Identity` over ANY
    /// cipher alphabet — including `Identity`-over-the-83-symbol-eyes, the one path
    /// that must always survive (`0 >= 29` is false). Always resolve the true
    /// mapping domain via
    /// [`resolved_output_alphabet_size(codec, cipher_alphabet_size)`](resolved_output_alphabet_size)
    /// (or [`output_alphabet_hosts_language`]) before any sanity check or prune.
    fn output_alphabet_size(&self) -> usize;

    /// Stable family name for candidate reports.
    fn name(&self) -> &'static str;

    /// Whether [`transduce`](Codec::transduce) is invertible (enables a codec
    /// round-trip check via [`codec_round_trip_ok`]). This is a property of the
    /// codec *configuration*: it is now configuration-honest for the decidable
    /// overlapping-stride case — an [`AnyCodec::FixedGrouping`] with a non-partition
    /// stride (`stride != group_len`) is structurally non-invertible and returns
    /// `false` here. The remaining, input-dependent loss (a trailing partial group
    /// on an otherwise `stride == group_len` stream) is not decidable from the
    /// configuration alone and still yields an honest `false` at runtime from
    /// [`codec_round_trip_ok`].
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

/// Codec strategy for a solve request: which codecs sit between the cipher's
/// decrypted symbols and the symbol->letter mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodecStrategy {
    /// Phase 1: a declared set of codecs, each round-tripped + scored (no search).
    /// The behavior-preserving default is a single [`AnyCodec::Identity`].
    Fixed(Vec<AnyCodec>),
    /// Phase 2 seam: enumerate codec parameters and run the mapping search on each
    /// transduced stream, ranked by held-out + matched-null. **Not implemented in
    /// Phase 1** — the solve pipeline returns a clear phase-2-unavailable error.
    Search(CodecSearch),
}

/// Phase-2 codec-search configuration (a seam in Phase 1; the enumeration is not
/// implemented yet). `base` is fixed to the cipher alphabet size, not searched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodecSearch {
    /// `group_len` is enumerated over `1..=max_group_len`.
    pub max_group_len: usize,
    /// Whether to enumerate the delta codec in `{off, on}`.
    pub try_delta: bool,
    /// Digit orders to enumerate (a subset of `{Msb, Lsb}`).
    pub orders: Vec<DigitOrder>,
    /// Deterministic seed for the enumeration (drives `SplitMix64`); same seed =>
    /// same enumeration.
    pub seed: u64,
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
            // Passthrough sentinel `0`: NOT a real alphabet size. Never compare it
            // against a language/prune threshold (`0 >= N` wrongly rejects Identity,
            // including Identity-over-the-83-symbol-eyes). Resolve the true domain
            // with `resolved_output_alphabet_size` / `output_alphabet_hosts_language`.
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
        match self {
            // Identity is trivially invertible; Delta is invertible given its seed
            // symbol.
            Self::Identity | Self::Delta(_) => true,
            // FixedGrouping inverts via `ungroup`, which assumes the non-overlapping
            // `stride == group_len` partition. An overlapping/gapped stride
            // (`stride != group_len`) is structurally non-invertible, so report it
            // honestly here. On a non-overlapping stride it is invertible on a
            // full-length multiple (a trailing partial group is the only remaining
            // loss, caught at runtime by `codec_round_trip_ok`).
            Self::FixedGrouping(codec) => codec.stride == codec.group_len,
        }
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

// ---------------------------------------------------------------------------
// Step 3 — codec round-trip + alphabet-size sanity gates.
// ---------------------------------------------------------------------------

/// The default language alphabet size (29: 26 Latin letters plus the Finnish
/// vowels Å, Ä, Ö), mirroring `crate::language::DEFAULT_LANGUAGE_ALPHABET`. A codec
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
/// over a 5- or 12-symbol cipher alphabet FAILS for 29-letter English, while
/// `Identity` over the 83-symbol eyes passes. For the default language pass
/// [`DEFAULT_LANGUAGE_ALPHABET_SIZE`].
///
/// # Phase boundary (not an oversight that this has no live call site yet)
/// This predicate is the **Phase 1** deliverable — predicate + unit tests only
/// (brief 04a step 3). Its **enforcement as a pruning filter** is wired in
/// **Phase 2** under [`CodecStrategy::Search`] (brief 04a step 5): each enumerated
/// codec is pruned by this predicate and any skip is `log()`-ed (no silent
/// truncation). The [`CodecStrategy::Fixed`] path intentionally does **not** reject
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

#[cfg(test)]
mod tests {
    use super::{
        AnyCodec, Codec, CodecError, DEFAULT_LANGUAGE_ALPHABET_SIZE, DeltaCodec, DigitOrder,
        GroupingCodec, codec_round_trip_ok, output_alphabet_hosts_language,
        output_exceeds_accepted_alphabet,
    };
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

    // The +/-1-C5 hint (practice puzzle `one`, research/data/practice-puzzles/one):
    // every transition of that 5-symbol sample is +/-1 mod 5 — a walk on the
    // pentagon C5. Differencing collapses it to the MOVE stream over {+1,-1} = {1,4}
    // mod 5; re-integrating from the seed reproduces the walk. This is an OBSERVED
    // ciphertext property and a search hint (Delta is the natural first codec),
    // never a claim of "no message".
    #[test]
    fn delta_differences_c5_walk_and_reintegrates_from_seed() {
        let codec = AnyCodec::Delta(DeltaCodec {
            base: 5,
            then: Box::new(AnyCodec::Identity),
        });
        // A +/-1 walk on C5 (each step differs from the last by +/-1 mod 5).
        let walk = glyphs(&[2, 3, 4, 0, 4, 3, 2, 1, 0, 1, 2]);
        let moves = codec.transduce(&walk).unwrap();

        // Differencing collapses the alphabet to the two moves {+1, -1} = {1, 4}.
        assert_eq!(moves.len(), walk.len() - 1);
        assert!(moves.iter().all(|step| step.0 == 1 || step.0 == 4));

        // Re-integration from the seed (the first symbol) reproduces the original
        // walk exactly: cumulative sum of the moves mod base, starting at the seed.
        let seed = walk.first().copied().unwrap();
        let mut accumulator = usize::from(seed.0);
        let mut reintegrated = vec![seed];
        for step in &moves {
            accumulator = (accumulator + usize::from(step.0)) % 5;
            reintegrated.push(Glyph(accumulator as u16));
        }
        assert_eq!(reintegrated, walk);

        // Inner Identity over the differenced base-5 alphabet keeps the output at 5.
        assert_eq!(codec.output_alphabet_size(), 5);
        assert_eq!(codec.name(), "delta");
        assert!(codec.is_invertible());
    }

    #[test]
    fn delta_empty_input_errors() {
        let codec = AnyCodec::Delta(DeltaCodec {
            base: 5,
            then: Box::new(AnyCodec::Identity),
        });
        assert_eq!(codec.transduce(&[]).unwrap_err(), CodecError::EmptyInput);
    }

    #[test]
    fn delta_digit_outside_base_errors() {
        let codec = AnyCodec::Delta(DeltaCodec {
            base: 5,
            then: Box::new(AnyCodec::Identity),
        });
        let error = codec.transduce(&glyphs(&[0, 1, 7])).unwrap_err();
        assert_eq!(error, CodecError::ValueOutsideBase { value: 7, base: 5 });
    }

    #[test]
    fn identity_round_trips() {
        assert!(codec_round_trip_ok(
            &AnyCodec::Identity,
            &glyphs(&[3, 1, 4, 1, 0])
        ));
    }

    #[test]
    fn fixed_grouping_round_trips_on_full_multiple() {
        let codec = AnyCodec::FixedGrouping(honeycomb_grouping());
        assert!(codec_round_trip_ok(&codec, &glyphs(&[4, 4, 4, 1, 2, 3])));
        // LSB ungroup must also reproduce its input.
        let lsb = AnyCodec::FixedGrouping(GroupingCodec {
            group_len: 3,
            base: 5,
            order: DigitOrder::Lsb,
            stride: 3,
        });
        assert!(codec_round_trip_ok(&lsb, &glyphs(&[1, 2, 3, 0, 4, 2])));
    }

    #[test]
    fn fixed_grouping_partial_group_is_honest_false() {
        // A trailing partial group makes transduce error, so the round-trip is an
        // honest false (the codec is lossy on this input).
        let codec = AnyCodec::FixedGrouping(honeycomb_grouping());
        assert!(!codec_round_trip_ok(&codec, &glyphs(&[4, 4, 4, 1, 2])));
    }

    #[test]
    fn delta_round_trips_on_c5_walk() {
        let codec = AnyCodec::Delta(DeltaCodec {
            base: 5,
            then: Box::new(AnyCodec::Identity),
        });
        assert!(codec_round_trip_ok(
            &codec,
            &glyphs(&[2, 3, 4, 0, 4, 3, 2, 1, 0, 1, 2])
        ));
    }

    #[test]
    fn delta_then_fixed_grouping_round_trips() {
        // Delta differences then groups the move stream; re-expand ungroups then
        // re-integrates from the seed. Length of the move stream (walk.len()-1)
        // must be a multiple of group_len for the grouping to be lossless.
        let codec = AnyCodec::Delta(DeltaCodec {
            base: 5,
            then: Box::new(AnyCodec::FixedGrouping(GroupingCodec {
                group_len: 2,
                base: 5,
                order: DigitOrder::Msb,
                stride: 2,
            })),
        });
        // 11-symbol walk -> 10 moves -> 5 grouped values (even); round-trips.
        assert!(codec_round_trip_ok(
            &codec,
            &glyphs(&[2, 3, 4, 0, 4, 3, 2, 1, 0, 1, 2])
        ));
    }

    #[test]
    fn alphabet_size_sanity_rejects_small_identity_and_accepts_wide_grouping() {
        // Identity over 5 or 12 symbols cannot host 29-letter English.
        assert!(!output_alphabet_hosts_language(
            &AnyCodec::Identity,
            5,
            DEFAULT_LANGUAGE_ALPHABET_SIZE
        ));
        assert!(!output_alphabet_hosts_language(
            &AnyCodec::Identity,
            12,
            DEFAULT_LANGUAGE_ALPHABET_SIZE
        ));
        // Identity over the 83-symbol eyes is already wide enough.
        assert!(output_alphabet_hosts_language(
            &AnyCodec::Identity,
            83,
            DEFAULT_LANGUAGE_ALPHABET_SIZE
        ));
        // A base-6 pair grouping (6^2 = 36 >= 29) can host the language.
        let grouping = AnyCodec::FixedGrouping(GroupingCodec {
            group_len: 2,
            base: 6,
            order: DigitOrder::Msb,
            stride: 2,
        });
        assert!(output_alphabet_hosts_language(
            &grouping,
            6,
            DEFAULT_LANGUAGE_ALPHABET_SIZE
        ));
    }

    #[test]
    fn fixed_grouping_emitting_above_82_is_flagged_for_eye_consumer() {
        let codec = AnyCodec::FixedGrouping(honeycomb_grouping());
        // [3,1,2] -> 82 (accepted); [4,4,4] -> 124 (raw, rejected by the 0..=82 policy).
        let accepted = crate::ciphers::EYE_READING_ALPHABET_SIZE; // 83
        assert!(!output_exceeds_accepted_alphabet(&codec, &glyphs(&[3, 1, 2]), accepted).unwrap());
        assert!(
            output_exceeds_accepted_alphabet(&codec, &glyphs(&[3, 1, 2, 4, 4, 4]), accepted)
                .unwrap()
        );
    }

    #[test]
    fn horner_usize_overflow_is_output_value_too_wide_not_panic() {
        // base 2 over a 70-digit group doubles the accumulator ~70 times, overflowing
        // usize around step 64. The checked Horner step must surface this as an
        // `OutputValueTooWide` error — never a debug panic or a silent release wrap.
        let codec = AnyCodec::FixedGrouping(GroupingCodec {
            group_len: 70,
            base: 2,
            order: DigitOrder::Msb,
            stride: 70,
        });
        let input = glyphs(&[1; 70]);
        let error = codec.transduce(&input).unwrap_err();
        assert!(
            matches!(error, CodecError::OutputValueTooWide { .. }),
            "expected OutputValueTooWide, got {error:?}"
        );
    }

    #[test]
    fn overlapping_stride_is_not_invertible_and_does_not_round_trip() {
        // stride (2) != group_len (3): an overlapping partition that `ungroup`
        // cannot invert. `is_invertible` now reports this honestly from the config,
        // and `codec_round_trip_ok` short-circuits to false on it.
        let overlapping = AnyCodec::FixedGrouping(GroupingCodec {
            group_len: 3,
            base: 5,
            order: DigitOrder::Msb,
            stride: 2,
        });
        assert!(!overlapping.is_invertible());
        assert!(!codec_round_trip_ok(
            &overlapping,
            &glyphs(&[1, 2, 3, 0, 4, 2])
        ));

        // A non-overlapping (`stride == group_len`) grouping stays invertible.
        assert!(AnyCodec::FixedGrouping(honeycomb_grouping()).is_invertible());
    }
}

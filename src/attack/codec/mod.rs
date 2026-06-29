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
//! This module is a peer of [`crate::attack::solve`]; it supplies the codec types the
//! solve pipeline threads between `decrypt` and `mapping`. The accept-`0..=82`
//! filter is **not** part of grouping — it is a consumer-side alphabet policy
//! (see [`output_exceeds_accepted_alphabet`]).

use std::fmt;

use crate::core::glyph::Glyph;

mod mechanics;
#[cfg(test)]
mod tests;

pub use mechanics::{
    DEFAULT_LANGUAGE_ALPHABET_SIZE, codec_round_trip_ok, output_alphabet_hosts_language,
    output_exceeds_accepted_alphabet, resolved_output_alphabet_size,
};
use mechanics::{delta_transduce, group_symbols, grouping_output_alphabet_size, project_transduce};

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
    /// # Do not use this for alphabet-size sanity / search pruning
    /// Because this bare method returns the `0` passthrough sentinel for
    /// [`AnyCodec::Identity`], the obvious pruning idiom
    /// `codec.output_alphabet_size() >= N` would wrongly reject `Identity` over any
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
    /// symbol (the first input symbol) **iff** its inner codec is.
    Delta(DeltaCodec),
    /// Per-symbol projection onto a residue ([`ProjectionOp::Modulo`]) or quotient
    /// ([`ProjectionOp::Div`]) channel, declaring the channel's base, then an inner
    /// codec. Length-preserving and **lossy** (it discards the complementary
    /// channel), so it is never invertible. It unifies two readings a single
    /// symbol->letter mapping cannot otherwise reach: the *binary-move* reading
    /// (`Delta -> Project{Modulo 2} -> FixedGrouping{base 2}`, the up/down bit
    /// stream of a +/-1 walk widened to letters) and small-alphabet *fractionation*
    /// (project a composite base onto a `base = d x (base/d)` channel). The
    /// projection is total on every in-base symbol so the matched null can rerun it
    /// on any shuffle (see [`enumerate_codecs`]).
    Project(ProjectCodec),
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

/// A projection codec: reduce each input symbol onto a residue or quotient channel
/// (declaring the channel base), then transduce that channel through `then`.
///
/// The per-symbol map is total on every symbol in `0..input_base`, so a codec built
/// from it transduces a shuffled stream iff it transduces the original — the
/// content-independence the matched-null enumeration relies on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectCodec {
    /// Radix each input symbol must lie within (`symbol < input_base`).
    pub input_base: usize,
    /// Declared base of the projected channel (the inner codec's input alphabet).
    pub output_base: usize,
    /// Which channel to keep (residue or quotient).
    pub op: ProjectionOp,
    /// Inner codec applied to the projected channel.
    pub then: Box<AnyCodec>,
}

/// Which channel a [`ProjectCodec`] keeps from each symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectionOp {
    /// Keep the residue `v % output_base` (always within the declared base).
    Modulo,
    /// Keep the quotient `v / divisor`, validated to be within the declared base.
    Div {
        /// Divisor whose quotient is kept.
        divisor: usize,
    },
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
    /// Phase 2: enumerate codec parameters ([`enumerate_codecs`]) and run the
    /// mapping search on each transduced stream, ranked by held-out + matched-null.
    /// Every enumerated codec that is pruned before its mapping search runs is
    /// surfaced as a [`SkippedCodec`] (no silent truncation).
    Search(CodecSearch),
}

/// Phase-2 codec-search configuration. `base` is fixed to the cipher alphabet
/// size, not searched. The enumeration is realized by [`enumerate_codecs`]; the
/// solve pipeline prunes each enumerated codec (alphabet-size sanity +
/// [`MAX_SEARCH_OUTPUT_ALPHABET`] ceiling) and runs the mapping search on every
/// survivor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodecSearch {
    /// `group_len` is enumerated over `1..=max_group_len`.
    pub max_group_len: usize,
    /// Whether to enumerate the delta codec in `{off, on}`.
    pub try_delta: bool,
    /// Whether to append the binary-move reading: `Delta -> Project{Modulo 2} ->
    /// FixedGrouping{base 2}` over [`BINARY_MOVE_GROUP_LENS`] — the up/down bit
    /// stream of a +/-1 walk (puzzle `one`) widened to a letter alphabet.
    pub try_binary_move: bool,
    /// Whether to append small-alphabet fractionation: for each proper divisor `d`
    /// of the cipher alphabet, project onto the residue (base `d`) and quotient
    /// (base `base/d`) channels, then group each like the top level.
    pub try_fractionation: bool,
    /// Digit orders to enumerate (a subset of `{Msb, Lsb}`).
    pub orders: Vec<DigitOrder>,
    /// Deterministic seed for the enumeration (drives `SplitMix64`); same seed =>
    /// same enumeration.
    pub seed: u64,
}

/// Default `max_group_len` for the CLI codec search (`solve --codec-search`).
///
/// Group lengths `1..=3` cover every grouping the practice corpus needs while
/// staying under [`MAX_SEARCH_OUTPUT_ALPHABET`]: base-5 trigrams (`5³ = 125`),
/// base-6 pairs/triples (`6² = 36`, `6³ = 216`) and base-12 pairs (`12² = 144`);
/// `12³ = 1728` and `5⁴ = 625` are pruned by the ceiling.
pub const DEFAULT_CODEC_SEARCH_MAX_GROUP_LEN: usize = 3;

/// Base-2 group lengths the binary-move reading enumerates: `2.pow(g)` for `g` in
/// `5..=8` is `32..=256` — at/above the 29-letter language floor and at/below
/// [`MAX_SEARCH_OUTPUT_ALPHABET`]. A 4-bit group (16) is below the floor and would be
/// pruned, so 5 is the smallest useful length.
pub const BINARY_MOVE_GROUP_LENS: [usize; 4] = [5, 6, 7, 8];

/// The default codec-search configuration the CLI `--codec-search` flag selects:
/// group lengths `1..=`[`DEFAULT_CODEC_SEARCH_MAX_GROUP_LEN`], both digit orders,
/// the delta codec enabled (the motivated `±1`-`C5` hint for puzzle `one`), and the
/// binary-move reading (which makes puzzle `one`'s C5-walk testable). `seed` threads
/// the caller's deterministic seed through the enumeration.
///
/// `try_fractionation` is deliberately **off** in this default. Fractionating a
/// cipher that carries a first-order *transition law* (e.g. puzzle `two`'s
/// `s[i+1] mod 3 != s[i] mod 3`) projects that law onto a channel, where a
/// many-to-one mapping search reads it as a high bigram score that the
/// Fisher-Yates matched null — which destroys the transition law — cannot match. A
/// bigram objective cannot distinguish a first-order transition law from
/// first-order language signal (a first-order Markov null that *preserves* the law
/// is not beaten even by genuine English), so an on-by-default fractionation search
/// would report a gibberish "survivor" for `two`. The capability is retained for
/// explicit, caveated use; see `research/data/practice-puzzles/CODEC-RESULTS.md`.
#[must_use]
pub fn default_codec_search(seed: u64) -> CodecSearch {
    CodecSearch {
        max_group_len: DEFAULT_CODEC_SEARCH_MAX_GROUP_LEN,
        try_delta: true,
        try_binary_move: true,
        try_fractionation: false,
        orders: vec![DigitOrder::Msb, DigitOrder::Lsb],
        seed,
    }
}

/// The eye **honeycomb** codec the CLI `--codec honeycomb` selector declares: the
/// canonical base-5 trigram grouping (`group_len = 3`, `base = 5`, MSB,
/// non-overlapping) whose raw value range is `0..=124` (`src/trigram.rs`). It is a
/// declared [`CodecStrategy::Fixed`] codec, so it only transduces a base-5 digit
/// stream; on any other alphabet [`Codec::transduce`] errors honestly.
#[must_use]
pub fn honeycomb_codec() -> AnyCodec {
    AnyCodec::FixedGrouping(GroupingCodec {
        group_len: 3,
        base: 5,
        order: DigitOrder::Msb,
        stride: 3,
    })
}

/// Documented output-alphabet ceiling for the codec search: an enumerated codec
/// whose resolved output alphabet exceeds this is skipped (and logged) as too wide
/// to map honestly onto a ~29-letter language.
///
/// A symbol->letter mapping over an `N`-symbol domain is increasingly many-to-one
/// as `N` grows past the ~29-letter language alphabet; far past it the mapping is
/// almost all collapse and the search both explodes and stops being honestly
/// interpretable. `256` (~9x the language alphabet) is generous enough to admit
/// every grouping the practice corpus needs — the honeycomb base-5 trigram raw
/// range (`5^3 = 125`), base-6 digit pairs (`6^2 = 36`) and triples (`6^3 = 216`),
/// and base-12 letter pairs (`12^2 = 144`) — while pruning the genuinely explosive
/// configurations (`5^4 = 625`, `6^4 = 1296`, `12^3 = 1728`).
pub const MAX_SEARCH_OUTPUT_ALPHABET: usize = 256;

/// Why an enumerated codec was pruned from the codec search before any mapping
/// search ran. Surfaced as data (never `println`/silently dropped) so the caller
/// can render the full enumeration trace: every cap is documented and every skip
/// is logged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodecSkipReason {
    /// The resolved output alphabet is smaller than the language alphabet, so the
    /// codec cannot host the language under any symbol->letter mapping (the formal
    /// "5 < 26, 12 < 26 => you need a codec" prune).
    SanityTooSmall {
        /// Resolved output alphabet size of the skipped codec.
        resolved: usize,
        /// Language alphabet size it failed to reach.
        language: usize,
    },
    /// The resolved output alphabet exceeds [`MAX_SEARCH_OUTPUT_ALPHABET`]: too
    /// wide to map honestly.
    CeilingTooWide {
        /// Resolved output alphabet size of the skipped codec.
        resolved: usize,
        /// The ceiling it exceeded.
        ceiling: usize,
    },
    /// The codec cannot transduce the ciphertext stream as given (e.g. a grouping
    /// whose `group_len` does not divide the stream length). Logged-and-skipped so
    /// an ill-fitting config never silently truncates the stream nor aborts the
    /// whole search.
    Untransducible,
    /// The resolved output alphabet exceeds the domain of the declared
    /// [`MappingStrategy::Fixed`](crate::attack::solve::MappingStrategy::Fixed) mapping, so
    /// that mapping cannot host the widened stream. Logged-and-skipped
    /// (defense-in-depth) rather than hard-erroring with
    /// [`SolveError::MappingSymbolOutsideTable`](crate::attack::solve::SolveError::MappingSymbolOutsideTable):
    /// a [`CodecStrategy::Search`] paired with an explicit fixed mapping skips the
    /// codecs the mapping is too small to host instead of aborting the whole
    /// search. (The CLI never reaches this path — it auto-enables the mapping
    /// search under `--codec-search`.)
    MappingDomainMismatch {
        /// Resolved output alphabet size of the skipped codec.
        resolved: usize,
        /// Domain (table length) of the smallest declared fixed mapping.
        mapping_domain: usize,
    },
}

/// An enumerated codec that the search pruned, paired with the reason. Returned as
/// a structured trace from the codec search so no skip is silent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkippedCodec {
    /// The pruned codec configuration.
    pub codec: AnyCodec,
    /// Why it was pruned.
    pub reason: CodecSkipReason,
}

/// Enumerates the codec configurations a [`CodecStrategy::Search`] explores for a
/// fixed cipher alphabet size (`base`, not searched).
///
/// For each `group_len` in `1..=max_group_len` and each `order` in
/// `search.orders`, a non-overlapping (`stride == group_len`) [`GroupingCodec`] is
/// emitted; `group_len == 1` reduces to [`AnyCodec::Identity`] and is
/// order-agnostic, so only one copy is emitted for it. When `search.try_delta` is
/// set, each of those is also wrapped in a [`DeltaCodec`] over the same `base`.
///
/// The delta wrapping is the motivated search hint for the **+/-1-`C5`** structure
/// observed in practice puzzle `one` (`research/data/practice-puzzles/one`): every
/// one of that 5-symbol sample's transitions is +/-1 mod 5 — a walk on the
/// pentagon `C5`. Differencing collapses the walk to its move stream, so a
/// `Delta` codec is the natural first attempt. This is an observed ciphertext
/// property and a search hint, never a claim of triviality or "no message".
///
/// The order is deterministic. Pruning (alphabet-size sanity, the
/// [`MAX_SEARCH_OUTPUT_ALPHABET`] ceiling, transduce feasibility) and the
/// structured [`SkippedCodec`] log are the caller's (solve's) job; this function
/// just lists the candidate codecs.
#[must_use]
pub fn enumerate_codecs(search: &CodecSearch, cipher_alphabet_size: usize) -> Vec<AnyCodec> {
    let base = cipher_alphabet_size;
    let deltas: &[bool] = if search.try_delta {
        &[false, true]
    } else {
        &[false]
    };
    let mut codecs = Vec::new();
    // Top-level enumeration over the bare cipher alphabet (unchanged): groupings
    // `1..=max_group_len`, both orders, optionally Delta-wrapped.
    for &delta in deltas {
        for group_len in 1..=search.max_group_len {
            for &order in &search.orders {
                // A 1-digit group is order-agnostic; skip the redundant Lsb copy so
                // the enumeration has no duplicate Identity / Delta-of-Identity.
                if group_len == 1 && order == DigitOrder::Lsb {
                    continue;
                }
                let inner = grouping_inner(group_len, base, order);
                codecs.push(if delta {
                    AnyCodec::Delta(DeltaCodec {
                        base,
                        then: Box::new(inner),
                    })
                } else {
                    inner
                });
            }
        }
    }
    // Appended (deterministic): binary-move reading — the +/-1-walk hint generalized
    // to its up/down bit stream. Delta differences the walk, Project mod 2 collapses
    // each move to a bit, and a base-2 group of `g` bits forms one symbol. This is
    // the path that makes puzzle `one` (a C5 walk; 265 moves = 5 x 53) testable.
    if search.try_binary_move {
        for group_len in BINARY_MOVE_GROUP_LENS {
            codecs.push(binary_move_codec(base, group_len));
        }
    }
    // Appended (deterministic): small-alphabet fractionation — project onto each
    // proper-divisor residue (`Modulo`) and quotient (`Div`) channel, then group that
    // channel like the top level. A composite base (12 = 4 x 3, 6 = 2 x 3) thereby
    // splits into channels a single symbol->letter mapping cannot otherwise reach.
    if search.try_fractionation {
        for divisor in proper_divisors(base) {
            for (output_base, op) in [
                (divisor, ProjectionOp::Modulo),
                (base / divisor, ProjectionOp::Div { divisor }),
            ] {
                if output_base < 2 {
                    continue;
                }
                for group_len in 1..=search.max_group_len {
                    for &order in &search.orders {
                        if group_len == 1 && order == DigitOrder::Lsb {
                            continue;
                        }
                        codecs.push(AnyCodec::Project(ProjectCodec {
                            input_base: base,
                            output_base,
                            op,
                            then: Box::new(grouping_inner(group_len, output_base, order)),
                        }));
                    }
                }
            }
        }
    }
    codecs
}

/// One grouping codec over `base` in the canonical non-overlapping (`stride ==
/// group_len`) configuration, or an order-agnostic [`AnyCodec::Identity`] for
/// `group_len == 1`. Shared by the top-level and fractionation enumerations so both
/// build identical inner groupings.
fn grouping_inner(group_len: usize, base: usize, order: DigitOrder) -> AnyCodec {
    if group_len == 1 {
        AnyCodec::Identity
    } else {
        AnyCodec::FixedGrouping(GroupingCodec {
            group_len,
            base,
            order,
            stride: group_len,
        })
    }
}

/// The binary-move codec for `base`: `Delta -> Project{Modulo 2} ->
/// FixedGrouping{base 2, group_len}`. Differencing yields the move stream, the mod-2
/// projection collapses each move to an up/down bit, and the base-2 grouping widens
/// `group_len` bits into one of `2.pow(group_len)` symbols.
fn binary_move_codec(base: usize, group_len: usize) -> AnyCodec {
    AnyCodec::Delta(DeltaCodec {
        base,
        then: Box::new(AnyCodec::Project(ProjectCodec {
            input_base: base,
            output_base: 2,
            op: ProjectionOp::Modulo,
            then: Box::new(AnyCodec::FixedGrouping(GroupingCodec {
                group_len,
                base: 2,
                order: DigitOrder::Msb,
                stride: group_len,
            })),
        })),
    })
}

/// Proper divisors `d` of `n` with `1 < d < n`, ascending (deterministic).
fn proper_divisors(n: usize) -> Vec<usize> {
    (2..n)
        .filter(|divisor| n.is_multiple_of(*divisor))
        .collect()
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
            Self::Project(codec) => project_transduce(codec, symbols),
        }
    }

    fn output_alphabet_size(&self) -> usize {
        match self {
            // Passthrough sentinel `0`: not a real alphabet size. Never compare it
            // against a language/prune threshold (`0 >= N` wrongly rejects Identity,
            // including Identity-over-the-83-symbol-eyes). Resolve the true domain
            // with `resolved_output_alphabet_size` / `output_alphabet_hosts_language`.
            Self::Identity => 0,
            Self::FixedGrouping(codec) => grouping_output_alphabet_size(codec),
            Self::Delta(codec) => resolved_output_alphabet_size(&codec.then, codec.base),
            Self::Project(codec) => resolved_output_alphabet_size(&codec.then, codec.output_base),
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::FixedGrouping(_) => "fixed-grouping",
            Self::Delta(_) => "delta",
            Self::Project(_) => "project",
        }
    }

    fn is_invertible(&self) -> bool {
        match self {
            // Identity is trivially invertible.
            Self::Identity => true,
            // Delta is invertible from its seed symbol *iff* its inner codec is, so a
            // Delta wrapping a lossy Project (the binary-move reading) is honestly
            // non-invertible — `codec_round_trip_ok` then short-circuits to false.
            Self::Delta(codec) => codec.then.is_invertible(),
            // FixedGrouping inverts via `ungroup`, which assumes the non-overlapping
            // `stride == group_len` partition. An overlapping/gapped stride
            // (`stride != group_len`) is structurally non-invertible, so report it
            // honestly here. On a non-overlapping stride it is invertible on a
            // full-length multiple (a trailing partial group is the only remaining
            // loss, caught at runtime by `codec_round_trip_ok`).
            Self::FixedGrouping(codec) => codec.stride == codec.group_len,
            // Project discards the complementary channel (residue or quotient), so it
            // is lossy and never invertible.
            Self::Project(_) => false,
        }
    }
}

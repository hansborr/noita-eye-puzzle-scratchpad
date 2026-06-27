//! External-ciphertext ingest: the missing front door.
//!
//! [`parse_sequence`] is a **pure** parser (no I/O) that turns an external
//! ciphertext string into the crate's [`Glyph`] sequence
//! under a chosen [`SequenceLayer`]; [`load_sequence`] is a thin I/O wrapper
//! that reads a path (or forwards a string) and delegates to it. The library
//! never reads global stdin — reading stdin is the CLI's job (`main.rs` slurps
//! it into a `String`, then calls [`parse_sequence`]).
//!
//! Three layers are supported: the two **eye layers** ([`RenderedOrientation`]
//! orientation digits `0..=4`, dropping the `5` row delimiter; and
//! [`HoneycombReading`] accepted eye-reading values `0..=82`) plus an
//! **additive** general [`CipherAlphabet`] path for the external practice
//! corpus, which passes spaces/punctuation through as transparent symbols.
//!
//! [`RenderedOrientation`]: SequenceLayer::RenderedOrientation
//! [`HoneycombReading`]: SequenceLayer::HoneycombReading
//! [`CipherAlphabet`]: SequenceLayer::CipherAlphabet

use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::path::Path;

use crate::ciphers::EYE_READING_ALPHABET_SIZE;
use crate::core::glyph::{Alphabet, Glyph, Orientation};

/// Where an external ciphertext is read from. There is **no `Stdin` variant** —
/// reading stdin is the CLI's job (`main.rs` reads it to a `String`, then calls
/// [`parse_sequence`]); the library never touches global stdin.
#[derive(Clone, Copy, Debug)]
pub enum Input<'a> {
    /// An in-memory string (e.g. a CLI argument).
    Str(&'a str),
    /// A filesystem path read in full.
    Path(&'a Path),
}

/// The configured set of **transparent symbols** for the [`CipherAlphabet`]
/// path: chars that are passed through (their positions recorded) rather than
/// treated as cipher symbols. Default membership: space, `.`, `,`, `?`, `!`,
/// `#`, and newline. These are *plumbing* (word boundaries / punctuation), never
/// a decode; the 29-letter [`crate::attack::language`] bigram model scores letters only
/// (`normalize_text` strips non-letters), so transparent symbols are skipped for
/// scoring but kept for readability.
///
/// **Caveat — `#` is plumbing by default, but may be a cipher symbol.** `#` is
/// included by default as punctuation plumbing, yet the practice corpus README
/// (`research/data/practice-puzzles/README.md`) hypothesizes `#` may be a
/// *cipher* symbol (a rare letter/space) in puzzle `seven`, so a `seven` run
/// must override the transparent set to **exclude** `#` (build one with
/// [`TransparentSet::from_chars`]); the engine surfaces, rather than silently
/// strips, any defaulted-transparent char that could be a cipher symbol.
///
/// [`CipherAlphabet`]: SequenceLayer::CipherAlphabet
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransparentSet {
    chars: BTreeSet<char>,
}

impl TransparentSet {
    /// The default transparent chars: space, `.`, `,`, `?`, `!`, `#`, newline.
    const DEFAULT_CHARS: &'static str = " .,?!#\n";

    /// Builds a transparent set from an explicit list of pass-through chars.
    ///
    /// Use this to override the default — e.g. exclude `#` for puzzle `seven`,
    /// where `#` is hypothesized to be a cipher symbol rather than punctuation.
    #[must_use]
    pub fn from_chars(chars: &str) -> Self {
        Self {
            chars: chars.chars().collect(),
        }
    }

    /// Returns `true` if `ch` is a configured transparent (pass-through) char.
    #[must_use]
    pub fn contains(&self, ch: char) -> bool {
        self.chars.contains(&ch)
    }
}

impl Default for TransparentSet {
    fn default() -> Self {
        Self::from_chars(Self::DEFAULT_CHARS)
    }
}

/// One transparent (pass-through) char and the position it occupied in the
/// original input, recorded **separately from the cipher-symbol stream** so the
/// pipeline (brief 04) can reinsert it into `rendered_text` at its position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransparentMark {
    /// The verbatim char (e.g. `' '`, `'.'`, `'\n'`).
    pub ch: char,
    /// Its 0-based index in the original char stream (for position-faithful
    /// reinsert).
    pub position: usize,
}

/// Which glyph layer the external tokens are expressed in.
///
/// The first two variants are the **eye layers** and stay exactly as the
/// round-2 fix left them (rendered digits `0..=4`; accepted honeycomb reading
/// `0..=82`). [`CipherAlphabet`](SequenceLayer::CipherAlphabet) is the
/// **additive** general path for the external practice corpus — it does not
/// touch the eye layers.
#[derive(Clone, Copy, Debug)]
pub enum SequenceLayer<'a> {
    /// Rendered orientation digits `0..=4`; digit `5` is the row delimiter and
    /// is dropped. Maps digit `d` to `Glyph(d)`. (Eye layer — e.g. puzzle `one`,
    /// `research/data/practice-puzzles/one`, the loadable 5-digit demo.)
    RenderedOrientation,
    /// Whitespace/comma-separated **accepted eye-reading-layer** symbols
    /// `0..=82` — the same alphabet `cipher_attack`/`solve` consume
    /// (`EYE_READING_ALPHABET_SIZE = 83`). Maps value `v` to `Glyph(v)`. This
    /// loads *accepted* reading-layer symbols, **not** the raw base-5 trigram
    /// range `0..=124`: values `83..=124` are rejected, exactly as
    /// `cipher_attack` rejects them. (Eye layer.)
    HoneycombReading,
    /// **General cipher-alphabet path (additive; for the practice corpus, not
    /// the eyes).** Ingests an arbitrary cipher alphabet, mapping each cipher
    /// char to its `Glyph(i)` index. A configured set of transparent symbols
    /// (space, `.`, `,`, `?`, `!`, `#`, newline by default) is treated as
    /// **pass-through**: such chars are *not* cipher symbols and *never* an
    /// invalid token — their positions are recorded in
    /// [`ParsedSequence::transparent`] and they are excluded from the returned
    /// cipher-symbol stream. Any char that is neither in `alphabet` nor in
    /// `transparent` is an [`IngestError::InvalidToken`]. (e.g. puzzle `three`,
    /// `research/data/practice-puzzles/three`, a letter+space sample.)
    CipherAlphabet {
        /// The cipher alphabet (e.g. `"ABCDEFGHIJKLMNOPQRSTUVWXYZ"`), built by
        /// [`Alphabet::from_chars`].
        alphabet: &'a Alphabet,
        /// Chars passed through verbatim (positions recorded, not cipher
        /// symbols): by default space, `.`, `,`, `?`, `!`, `#`, and newline.
        transparent: &'a TransparentSet,
    },
}

/// A parsed external ciphertext: the cipher-symbol stream and (for the
/// [`CipherAlphabet`](SequenceLayer::CipherAlphabet) path) the transparent
/// symbols recorded **separately**.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedSequence {
    /// The cipher symbols, in order — the stream the cipher/codec/mapping and
    /// the language scorer operate on. Transparent symbols are **not** here.
    pub glyphs: Vec<Glyph>,
    /// Transparent (pass-through) chars with their original positions, kept
    /// apart from `glyphs` so the pipeline (brief 04) can reinsert them into
    /// `rendered_text` at their positions. Empty for the two eye layers.
    pub transparent: Vec<TransparentMark>,
}

/// Owned discriminant of [`SequenceLayer`] for error reporting (no borrow).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayerKind {
    /// The [`SequenceLayer::RenderedOrientation`] eye layer.
    RenderedOrientation,
    /// The [`SequenceLayer::HoneycombReading`] eye layer.
    HoneycombReading,
    /// The [`SequenceLayer::CipherAlphabet`] general path.
    CipherAlphabet,
}

impl LayerKind {
    /// A short, human-readable label for the layer.
    fn label(self) -> &'static str {
        match self {
            Self::RenderedOrientation => "rendered orientation",
            Self::HoneycombReading => "honeycomb reading",
            Self::CipherAlphabet => "cipher alphabet",
        }
    }

    /// A layer-specific hint describing what a valid token looks like.
    fn token_hint(self) -> &'static str {
        match self {
            Self::RenderedOrientation => {
                "digits 0-4 are orientations and 5 is the dropped row delimiter"
            }
            Self::HoneycombReading => "expected an accepted eye-reading value 0-82",
            Self::CipherAlphabet => {
                "expected a cipher-alphabet symbol or a transparent space/punctuation character"
            }
        }
    }
}

impl fmt::Display for LayerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Failure to ingest an external ciphertext into a glyph sequence.
#[derive(Debug)]
pub enum IngestError {
    /// Reading the path failed (`load_sequence(Input::Path(..))` only; the
    /// library has no stdin path, so this is the sole I/O source).
    Io(io::Error),
    /// A token was not valid for the requested layer (records a layer label,
    /// the offending token text, and its 0-based index). The label is an owned
    /// discriminant, not a borrowed [`SequenceLayer`], so `IngestError` carries
    /// no lifetime.
    InvalidToken {
        /// The layer under which parsing failed.
        layer: LayerKind,
        /// The offending token text (a single char for the rendered / cipher
        /// layers, a whitespace/comma-delimited token for the honeycomb layer).
        token: String,
        /// The 0-based index of the offending token: the char index for the
        /// char-oriented layers, the token index for the whitespace/comma-split
        /// honeycomb layer.
        index: usize,
    },
    /// The input yielded no **cipher** glyphs after parsing (an all-transparent
    /// [`CipherAlphabet`](SequenceLayer::CipherAlphabet) input, or empty /
    /// all-whitespace for the eye layers).
    Empty,
}

impl fmt::Display for IngestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "failed to read external ciphertext: {error}"),
            Self::InvalidToken {
                layer,
                token,
                index,
            } => write!(
                f,
                "invalid token {token:?} at {layer} index {index}: {hint}",
                hint = layer.token_hint()
            ),
            Self::Empty => {
                f.write_str("input produced no cipher glyphs (empty or all-transparent)")
            }
        }
    }
}

impl std::error::Error for IngestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidToken { .. } | Self::Empty => None,
        }
    }
}

/// Parses an external ciphertext string under the given layer. **Pure —
/// performs no I/O.** This is the unit-testable core; every parsing test targets
/// this function.
///
/// [`RenderedOrientation`](SequenceLayer::RenderedOrientation) ignores ASCII /
/// Unicode whitespace and drops digit `5`;
/// [`HoneycombReading`](SequenceLayer::HoneycombReading) splits on whitespace
/// and commas and parses **accepted eye-reading-layer** symbols `0..=82` (the
/// alphabet `cipher_attack`/`solve` consume), rejecting `83..=124` and
/// non-numeric tokens; [`CipherAlphabet`](SequenceLayer::CipherAlphabet) maps
/// each char through `alphabet`, **passes through** the configured transparent
/// symbols (recording their positions in [`ParsedSequence::transparent`]), and
/// rejects any other char. The two eye layers return an empty `transparent` vec.
///
/// # Errors
/// Returns [`IngestError::InvalidToken`] on an out-of-range / non-numeric /
/// unknown token, or [`IngestError::Empty`] when the input yields no cipher
/// glyphs. Never returns [`IngestError::Io`] (no I/O).
pub fn parse_sequence(text: &str, layer: SequenceLayer<'_>) -> Result<ParsedSequence, IngestError> {
    match layer {
        SequenceLayer::RenderedOrientation => parse_rendered(text),
        SequenceLayer::HoneycombReading => parse_honeycomb(text),
        SequenceLayer::CipherAlphabet {
            alphabet,
            transparent,
        } => parse_cipher_alphabet(text, alphabet, transparent),
    }
}

/// Loads an external ciphertext under the given layer.
///
/// I/O wrapper around [`parse_sequence`]: [`Input::Path`] reads the file in full
/// (I/O errors → [`IngestError::Io`]) then parses; [`Input::Str`] forwards to
/// [`parse_sequence`] directly. The library reads no stdin — the CLI reads stdin
/// to a `String` and calls [`parse_sequence`] itself.
///
/// # Errors
/// Returns [`IngestError`] on path-read I/O failure ([`IngestError::Io`]), an
/// out-of-range / non-numeric / unknown token ([`IngestError::InvalidToken`]),
/// or an input that yields no cipher glyphs ([`IngestError::Empty`]).
pub fn load_sequence(
    input: Input<'_>,
    layer: SequenceLayer<'_>,
) -> Result<ParsedSequence, IngestError> {
    match input {
        Input::Str(text) => parse_sequence(text, layer),
        Input::Path(path) => {
            let text = std::fs::read_to_string(path).map_err(IngestError::Io)?;
            parse_sequence(&text, layer)
        }
    }
}

fn parse_rendered(text: &str) -> Result<ParsedSequence, IngestError> {
    let mut glyphs = Vec::new();
    for (index, ch) in text.chars().enumerate() {
        if ch.is_whitespace() || ch == '5' {
            continue;
        }
        let orientation = ch
            .to_digit(10)
            .and_then(|digit| u8::try_from(digit).ok())
            .and_then(|digit| Orientation::from_digit(digit).ok());
        match orientation {
            Some(orientation) => glyphs.push(orientation.glyph()),
            None => {
                return Err(IngestError::InvalidToken {
                    layer: LayerKind::RenderedOrientation,
                    token: ch.to_string(),
                    index,
                });
            }
        }
    }
    finish(glyphs, Vec::new())
}

fn parse_honeycomb(text: &str) -> Result<ParsedSequence, IngestError> {
    let mut glyphs = Vec::new();
    let tokens = text
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|token| !token.is_empty());
    for (index, token) in tokens.enumerate() {
        let value = token
            .parse::<u8>()
            .ok()
            .filter(|value| usize::from(*value) < EYE_READING_ALPHABET_SIZE);
        match value {
            Some(value) => glyphs.push(Glyph(u16::from(value))),
            None => {
                return Err(IngestError::InvalidToken {
                    layer: LayerKind::HoneycombReading,
                    token: token.to_string(),
                    index,
                });
            }
        }
    }
    finish(glyphs, Vec::new())
}

fn parse_cipher_alphabet(
    text: &str,
    alphabet: &Alphabet,
    transparent: &TransparentSet,
) -> Result<ParsedSequence, IngestError> {
    let mut glyphs = Vec::new();
    let mut marks = Vec::new();
    for (position, ch) in text.chars().enumerate() {
        if transparent.contains(ch) {
            marks.push(TransparentMark { ch, position });
            continue;
        }
        match alphabet.glyph(ch) {
            Some(glyph) => glyphs.push(glyph),
            None => {
                return Err(IngestError::InvalidToken {
                    layer: LayerKind::CipherAlphabet,
                    token: ch.to_string(),
                    index: position,
                });
            }
        }
    }
    finish(glyphs, marks)
}

/// Builds the final [`ParsedSequence`], rejecting an empty cipher-glyph stream.
fn finish(
    glyphs: Vec<Glyph>,
    transparent: Vec<TransparentMark>,
) -> Result<ParsedSequence, IngestError> {
    if glyphs.is_empty() {
        return Err(IngestError::Empty);
    }
    Ok(ParsedSequence {
        glyphs,
        transparent,
    })
}

#[cfg(test)]
mod tests;

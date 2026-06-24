//! The eye-glyph alphabet and transcribed glyph sequences.
//!
//! The complete inventory for rendered eye-message orientations is now narrow:
//! five displayed orientation digits (`0` through `4`) plus `5` as a
//! non-rendered row delimiter. The broader cryptanalysis alphabet is still
//! modelled as an opaque [`Glyph`] index into an [`Alphabet`], because later
//! layers also need to represent engine-storage symbols, trigram values, and
//! candidate cipher alphabets without pretending those are the same thing.

use std::collections::BTreeMap;
use std::fmt;

/// A parse error for a rendered eye-message symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SymbolError {
    /// The invalid symbol value.
    pub value: i16,
}

/// One of the five rendered orientation digits in the eye-message corpus.
///
/// These variants intentionally encode only the verified digit identity
/// (`0` through `4`). They do not assign pixel-direction names such as "up" or
/// "left", because that mapping is not established by the text sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Orientation {
    /// Rendered orientation digit `0`.
    Zero = 0,
    /// Rendered orientation digit `1`.
    One = 1,
    /// Rendered orientation digit `2`.
    Two = 2,
    /// Rendered orientation digit `3`.
    Three = 3,
    /// Rendered orientation digit `4`.
    Four = 4,
}

impl Orientation {
    /// Converts a verified orientation digit into an orientation.
    ///
    /// # Errors
    /// Returns [`SymbolError`] when `value` is outside `0..=4`.
    pub const fn from_digit(value: u8) -> Result<Self, SymbolError> {
        match value {
            0 => Ok(Self::Zero),
            1 => Ok(Self::One),
            2 => Ok(Self::Two),
            3 => Ok(Self::Three),
            4 => Ok(Self::Four),
            _ => Err(SymbolError {
                value: value as i16,
            }),
        }
    }

    /// Returns the canonical corpus digit for this orientation.
    #[must_use]
    pub const fn digit(self) -> u8 {
        self as u8
    }

    /// Returns the generic glyph index matching this orientation digit.
    #[must_use]
    pub const fn glyph(self) -> Glyph {
        Glyph(self as u16)
    }
}

/// A rendered corpus symbol: either an orientation or the non-rendered row
/// delimiter encoded as digit `5`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RenderedSymbol {
    /// A displayed eye orientation.
    Orientation(Orientation),
    /// The row delimiter encoded as digit `5`.
    RowDelimiter,
}

impl RenderedSymbol {
    /// Converts a rendered corpus digit into a symbol.
    ///
    /// # Errors
    /// Returns [`SymbolError`] when `value` is outside `0..=5`.
    pub const fn from_digit(value: u8) -> Result<Self, SymbolError> {
        match value {
            0 => Ok(Self::Orientation(Orientation::Zero)),
            1 => Ok(Self::Orientation(Orientation::One)),
            2 => Ok(Self::Orientation(Orientation::Two)),
            3 => Ok(Self::Orientation(Orientation::Three)),
            4 => Ok(Self::Orientation(Orientation::Four)),
            5 => Ok(Self::RowDelimiter),
            _ => Err(SymbolError {
                value: value as i16,
            }),
        }
    }
}

/// A symbol emitted by the engine-storage base-7 decode layer.
///
/// The storage decoder emits values in `-1..=5`. In the verified corpus only
/// `0..=5` appear, where `5` is a row delimiter. Keeping this distinct from
/// [`RenderedSymbol`] prevents accidentally treating the base-7 storage layer
/// as the base-5 reading layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageSymbol {
    /// Engine value `-1`, not present in the verified nine-message corpus.
    NegativeOne,
    /// A rendered orientation digit `0..=4`.
    Orientation(Orientation),
    /// The engine row delimiter value `5`.
    RowDelimiter,
}

impl StorageSymbol {
    /// Converts an engine-storage value into a symbol.
    ///
    /// # Errors
    /// Returns [`SymbolError`] when `value` is outside `-1..=5`.
    pub const fn from_value(value: i8) -> Result<Self, SymbolError> {
        match value {
            -1 => Ok(Self::NegativeOne),
            0 => Ok(Self::Orientation(Orientation::Zero)),
            1 => Ok(Self::Orientation(Orientation::One)),
            2 => Ok(Self::Orientation(Orientation::Two)),
            3 => Ok(Self::Orientation(Orientation::Three)),
            4 => Ok(Self::Orientation(Orientation::Four)),
            5 => Ok(Self::RowDelimiter),
            _ => Err(SymbolError {
                value: value as i16,
            }),
        }
    }
}

/// A single eye glyph, identified by its index within an [`Alphabet`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Glyph(pub u16);

impl fmt::Display for Glyph {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "g{}", self.0)
    }
}

/// A mapping between glyph indices and the single characters used to
/// transcribe them in plain-text corpora.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Alphabet {
    to_char: Vec<char>,
    from_char: BTreeMap<char, Glyph>,
}

impl Alphabet {
    /// Builds an alphabet from a string of distinct transcription characters.
    ///
    /// The character at position `i` becomes `Glyph(i)`.
    ///
    /// # Errors
    /// Returns the offending character if the same one appears twice, or if more
    /// than 65536 distinct characters are supplied (the index would exceed
    /// [`u16::MAX`]).
    pub fn from_chars(chars: &str) -> Result<Self, char> {
        let mut to_char = Vec::new();
        let mut from_char = BTreeMap::new();
        for (i, c) in chars.chars().enumerate() {
            if i > usize::from(u16::MAX) {
                return Err(c);
            }
            let glyph = Glyph(i as u16);
            if from_char.insert(c, glyph).is_some() {
                return Err(c);
            }
            to_char.push(c);
        }
        Ok(Self { to_char, from_char })
    }

    /// Number of distinct glyphs in the alphabet.
    #[must_use]
    pub fn len(&self) -> usize {
        self.to_char.len()
    }

    /// Returns `true` if the alphabet has no glyphs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.to_char.is_empty()
    }

    /// Looks up the glyph transcribed by `c`, if any.
    #[must_use]
    pub fn glyph(&self, c: char) -> Option<Glyph> {
        self.from_char.get(&c).copied()
    }

    /// Returns the transcription character for `glyph`, if it is in range.
    #[must_use]
    pub fn char(&self, glyph: Glyph) -> Option<char> {
        self.to_char.get(glyph.0 as usize).copied()
    }
}

/// An ordered sequence of glyphs — one transcribed eye message.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Sequence {
    /// The glyphs, in reading order.
    pub glyphs: Vec<Glyph>,
}

impl Sequence {
    /// Parses a sequence from text, skipping ASCII/Unicode whitespace.
    ///
    /// # Errors
    /// Returns the first non-whitespace character that is not present in
    /// `alphabet`.
    pub fn parse(text: &str, alphabet: &Alphabet) -> Result<Self, char> {
        let mut glyphs = Vec::new();
        for c in text.chars() {
            if c.is_whitespace() {
                continue;
            }
            match alphabet.glyph(c) {
                Some(g) => glyphs.push(g),
                None => return Err(c),
            }
        }
        Ok(Self { glyphs })
    }

    /// Number of glyphs in the sequence.
    #[must_use]
    pub fn len(&self) -> usize {
        self.glyphs.len()
    }

    /// Returns `true` if the sequence contains no glyphs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.glyphs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{Alphabet, Glyph, Sequence};

    #[test]
    fn rejects_duplicate_alphabet_chars() {
        assert_eq!(Alphabet::from_chars("aba"), Err('a'));
    }

    #[test]
    fn round_trips_chars_and_glyphs() {
        let alphabet = Alphabet::from_chars("xyz").unwrap();
        assert_eq!(alphabet.glyph('y'), Some(Glyph(1)));
        assert_eq!(alphabet.char(Glyph(1)), Some('y'));
        assert_eq!(alphabet.char(Glyph(9)), None);
    }

    #[test]
    fn parse_skips_whitespace_and_reports_unknown() {
        let alphabet = Alphabet::from_chars("ab").unwrap();
        let seq = Sequence::parse("a b\na", &alphabet).unwrap();
        assert_eq!(seq.len(), 3);
        assert_eq!(Sequence::parse("a?b", &alphabet), Err('?'));
    }
}

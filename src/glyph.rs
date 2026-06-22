//! The eye-glyph alphabet and transcribed glyph sequences.
//!
//! The complete inventory of distinct Noita eye glyphs is itself part of what
//! the puzzle community is still pinning down, so a [`Glyph`] is modelled as an
//! opaque index into an [`Alphabet`] rather than a closed `enum`. Once the
//! inventory is settled this can be promoted to an exhaustive enum to get
//! compile-time coverage checking — a deliberate, documented trade-off.

use std::collections::BTreeMap;
use std::fmt;

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
    /// Returns the offending character if the same one appears twice.
    pub fn from_chars(chars: &str) -> Result<Self, char> {
        let mut to_char = Vec::new();
        let mut from_char = BTreeMap::new();
        for (i, c) in chars.chars().enumerate() {
            let glyph = Glyph(u16::try_from(i).expect("alphabet larger than u16::MAX"));
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

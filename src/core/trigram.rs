//! Base-5 trigram reading-layer types.
//!
//! The eye-message reading layer groups rendered orientation digits (`0..=4`)
//! into base-5 trigrams. This is separate from the engine-storage layer, which
//! is base-7 over 64-bit integer chunks and can emit control values.

use crate::core::glyph::Orientation;

/// One base-5 trigram formed from three rendered orientation digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReadingTrigram {
    first: Orientation,
    second: Orientation,
    third: Orientation,
}

impl ReadingTrigram {
    /// Builds a trigram from three rendered orientation digits.
    #[must_use]
    pub const fn new(first: Orientation, second: Orientation, third: Orientation) -> Self {
        Self {
            first,
            second,
            third,
        }
    }

    /// Returns the base-5 value in `0..=124`.
    #[must_use]
    pub const fn value(self) -> TrigramValue {
        let value = self.first.digit() * 25 + self.second.digit() * 5 + self.third.digit();
        TrigramValue(value)
    }

    /// Returns the three orientations in reading order.
    #[must_use]
    pub const fn orientations(self) -> [Orientation; 3] {
        [self.first, self.second, self.third]
    }
}

/// A base-5 trigram value in `0..=124`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrigramValue(u8);

impl TrigramValue {
    /// Constructs a trigram value when it is in the base-5 trigram range.
    ///
    /// # Errors
    /// Returns `value` unchanged when it is greater than `124`.
    pub const fn new(value: u8) -> Result<Self, u8> {
        if value <= 124 {
            Ok(Self(value))
        } else {
            Err(value)
        }
    }

    /// Returns the numeric value in `0..=124`.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl From<ReadingTrigram> for TrigramValue {
    fn from(value: ReadingTrigram) -> Self {
        value.value()
    }
}

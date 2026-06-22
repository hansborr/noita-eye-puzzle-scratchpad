//! Transcribed eye-message data.
//!
//! **The sequences below are placeholders** that only illustrate the expected
//! shape of the data and let the analysis code run end to end. The real eye
//! messages still need to be transcribed from the game (and the community's
//! catalogues) into this module before any decoding attempt is meaningful.
//!
//! See `README.md` for the sources to transcribe from and the transcription
//! conventions to follow.

use crate::glyph::{Alphabet, Sequence};

/// A placeholder transcription alphabet (`a`, `b`, `c`, ...) used by the demo.
///
/// Replace this with the real glyph inventory once it is settled.
#[must_use]
pub fn placeholder_alphabet() -> Alphabet {
    Alphabet::from_chars("abcdefghij").expect("placeholder chars are distinct")
}

/// A made-up sample sequence used purely to exercise the analysis code.
///
/// This is **not** real puzzle data.
#[must_use]
pub fn sample() -> Sequence {
    let alphabet = placeholder_alphabet();
    Sequence::parse("abcabc abac aabbcc deadbeef", &alphabet).expect("sample uses alphabet chars")
}

#[cfg(test)]
mod tests {
    use super::sample;

    #[test]
    fn sample_is_parseable_and_nonempty() {
        assert!(!sample().is_empty());
    }
}

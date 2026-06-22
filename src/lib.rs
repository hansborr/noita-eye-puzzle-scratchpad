//! Toolkit for analyzing and attempting to decode the Noita eye-glyph puzzle.
//!
//! The crate is organized in three layers:
//!
//! - [`glyph`]: the alphabet and sequence types used to represent transcribed
//!   eye messages, including the verified rendered orientation symbols.
//! - [`trigram`]: the base-5 reading layer over rendered orientations.
//! - [`analysis`]: encoding-agnostic cryptanalysis statistics (frequencies,
//!   entropy, index of coincidence, n-grams).
//! - [`corpus`]: the verified transcribed message data.
//!
//! Nothing here commits to a particular theory of how the glyphs encode
//! meaning; the goal is to provide trustworthy primitives that constrain the
//! hypothesis space.

pub mod analysis;
pub mod corpus;
pub mod glyph;
pub mod trigram;

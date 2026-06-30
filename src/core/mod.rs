//! Core representation: the alphabet and reading layer plus ciphertext ingest.
//!
//! These foundational types underpin the rest of the crate:
//!
//! - [`glyph`]: the alphabet and sequence types used to represent transcribed
//!   eye messages, including the verified rendered orientation symbols.
//! - [`trigram`]: the base-5 reading layer over rendered orientations.
//! - [`ingest`]: external-ciphertext ingest — a pure `parse_sequence` plus a
//!   thin `load_sequence` I/O wrapper that loads arbitrary glyph sequences
//!   (rendered orientation, accepted honeycomb reading, or a general cipher
//!   alphabet) without the library ever touching global stdin.

pub mod glyph;
pub mod ingest;
pub mod math;
pub mod trigram;

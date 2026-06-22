//! Toolkit for analyzing and attempting to decode the Noita eye-glyph puzzle.
//!
//! The crate is organized in three layers:
//!
//! - [`glyph`]: the alphabet and sequence types used to represent transcribed
//!   eye messages, including the verified rendered orientation symbols.
//! - [`isomorph`]: first-occurrence repeated-pattern detection used by the
//!   isomorph experiments and controls.
//! - [`isomorph_null`]: Experiment 7A repeated-pattern analysis against a
//!   within-message shuffle null.
//! - [`trigram`]: the base-5 reading layer over rendered orientations.
//! - [`analysis`]: encoding-agnostic cryptanalysis statistics (frequencies,
//!   entropy, index of coincidence, chi-square goodness of fit, n-grams).
//! - [`controls`]: positive-control fixtures for solved cipher classes.
//! - [`corpus`]: the verified transcribed message data.
//! - [`generator`]: the engine storage-layer base-7 decoder and vendored input
//!   blocks used for corpus cross-checks.
//! - [`language`]: English/Finnish n-gram language models for scoring
//!   candidate plaintexts.
//! - [`null`]: deterministic null distributions for fixed reading-order
//!   families.
//! - [`periodicity`]: Experiment 5A periodicity, autocorrelation, and Kasiski
//!   tests against same-shape random null streams.
//! - [`pipeline_null`]: Experiment 2 nulls for testing whether the base-7
//!   generation pipeline manufactures reading-layer statistics.
//!
//! Nothing here commits to a particular theory of how the glyphs encode
//! meaning; the goal is to provide trustworthy primitives that constrain the
//! hypothesis space.

pub mod analysis;
pub mod controls;
pub mod corpus;
pub mod generator;
pub mod glyph;
pub mod isomorph;
pub mod isomorph_null;
pub mod language;
pub mod null;
pub mod orders;
pub mod periodicity;
pub mod pipeline_null;
pub mod trigram;

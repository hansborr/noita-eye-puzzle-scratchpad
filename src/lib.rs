//! Toolkit for analyzing and attempting to decode the Noita eye-glyph puzzle.
//!
//! This crate is a CLI **workbench** with a thin library backing, not a
//! general-purpose library: nearly all of its public surface exists to serve
//! the in-repo binary and the golden-master tests rather than as a designed,
//! curated API. Treat the library API as internal and offered **without a
//! stability guarantee** — paths and signatures may change between commits.
//!
//! The code is organized into the following module groups:
//!
//! - [`crate::core`]: the alphabet and sequence types, the base-5 reading
//!   layer, and the external-ciphertext ingest front door.
//! - [`data`]: the verified transcribed corpus and the engine storage-layer
//!   base-7 decoder/generator.
//! - [`analysis`]: encoding-agnostic cryptanalysis statistics and the
//!   structural analyses and audits.
//! - [`nulls`]: matched-null distributions and the DoF-calibrated null drivers.
//! - [`ciphers`]: Experiment 12 candidate-cipher primitives and exact
//!   round-trip controls.
//! - [`attack`]: cipher attacks, language models, and the solve/keystream
//!   pipelines.
//! - [`experiments`]: the structural-battery experiment drivers.
//! - [`report`]: CLI report rendering and domain error formatting.
//!
//! Each group module documents its individual leaf modules. Nothing here
//! commits to a particular theory of how the glyphs encode meaning; the goal is
//! to provide trustworthy primitives that constrain the hypothesis space.

pub mod analysis;
pub mod attack;
pub mod ciphers;
pub mod core;
pub mod data;
pub mod experiments;
pub mod nulls;
pub mod report;

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
//! - [`chaining`]: Experiment 7B alphabet-chaining structural signatures with
//!   generated known-succeed and known-fail calibration controls.
//! - [`cipher_attack`]: Experiment 12 attack/null harness that scores named
//!   candidate ciphers only under declared, unverified symbol-to-letter
//!   mappings.
//! - [`ciphers`]: Experiment 12 candidate-cipher primitives and exact
//!   round-trip controls.
//! - [`controls`]: positive-control fixtures for solved cipher classes.
//! - [`corpus`]: the verified transcribed message data.
//! - [`dof_null`]: calibrated adaptive null for researcher degrees of freedom
//!   across traversal, grouping, and headline-statistic choice.
//! - [`generator`]: the engine storage-layer base-7 decoder and vendored input
//!   blocks used for corpus cross-checks.
//! - [`grouping`]: Experiment 8 base-N grouping comparison and independent
//!   collision-based state-count calibration.
//! - [`honeycomb`]: fixed-order two-dimensional honeycomb lattice structure
//!   test over physical row-pair coordinates.
//! - [`language`]: English/Finnish n-gram language models for scoring
//!   candidate plaintexts.
//! - [`modular_diff`]: modular finite-difference structural fingerprinting
//!   with generated cipher-family controls.
//! - [`null`]: deterministic null distributions for fixed reading-order
//!   families.
//! - [`orientation_homogeneity`]: order-independent cross-message
//!   homogeneity test over engine-fixed single-orientation frequencies.
//! - [`periodicity`]: Experiment 5A periodicity, autocorrelation, and Kasiski
//!   tests against same-shape random null streams.
//! - [`perseus`]: Experiment 7C Perseus shared-region recurrence statistic and
//!   within-message shuffle null.
//! - [`pipeline_null`]: Experiment 2 nulls for testing whether the base-7
//!   generation pipeline manufactures reading-layer statistics.
//! - [`report`]: CLI report rendering and domain error formatting.
//! - [`zero_adjacency_null`]: Experiment 7D zero-adjacency
//!   forbidden-successor null against within-message multiset shuffles.
//!
//! Nothing here commits to a particular theory of how the glyphs encode
//! meaning; the goal is to provide trustworthy primitives that constrain the
//! hypothesis space.

pub mod analysis;
pub mod chaining;
pub mod cipher_attack;
pub mod ciphers;
pub mod controls;
pub mod corpus;
pub mod dof_null;
pub mod generator;
pub mod glyph;
pub mod grouping;
pub mod honeycomb;
pub mod isomorph;
pub mod isomorph_null;
pub mod language;
pub mod modular_diff;
pub mod null;
pub mod orders;
pub mod orientation_homogeneity;
pub mod periodicity;
pub mod perseus;
pub mod pipeline_null;
pub mod report;
pub mod trigram;
pub mod zero_adjacency_null;

//! Toolkit for analyzing and attempting to decode the Noita eye-glyph puzzle.
//!
//! The crate is organized into the following modules:
//!
//! - [`glyph`]: the alphabet and sequence types used to represent transcribed
//!   eye messages, including the verified rendered orientation symbols.
//! - [`isomorph`]: first-occurrence repeated-pattern detection used by the
//!   isomorph experiments and controls.
//! - [`isomorph_null`]: Experiment 7A repeated-pattern analysis against a
//!   within-message shuffle null.
//! - [`keystream`]: polyalphabetic keystream cracker (Vigenere/Beaufort/autokey)
//!   with an annealed key search, quadgram scoring, and z-score/held-out gates.
//! - [`trigram`]: the base-5 reading layer over rendered orientations.
//! - [`analysis`]: encoding-agnostic cryptanalysis statistics (frequencies,
//!   entropy, index of coincidence, chi-square goodness of fit, n-grams).
//! - [`agl_gak`]: Thread 2 AGL(1,83)-GAK structural stress test and exclusion
//!   audit.
//! - [`chaining`]: Experiment 7B alphabet-chaining structural signatures with
//!   generated known-succeed and known-fail calibration controls.
//! - [`chaining_graph`]: graph-chaining conflict and coverage audit over
//!   aligned isomorph occurrences.
//! - [`cipher_attack`]: Experiment 12 attack/null harness that scores named
//!   candidate ciphers only under declared, unverified symbol-to-letter
//!   mappings.
//! - [`ciphers`]: Experiment 12 candidate-cipher primitives and exact
//!   round-trip controls.
//! - [`controls`]: positive-control fixtures for solved cipher classes.
//! - [`conditional_structure`]: first-order transition-matrix and
//!   successor-graph analysis against within-message shuffle nulls.
//! - [`corpus`]: the verified transcribed message data.
//! - [`dof_null`]: calibrated adaptive null for researcher degrees of freedom
//!   across traversal, grouping, and headline-statistic choice.
//! - [`gak_attack`]: Thread 4 synthetic GAK generator and the decisive GCTAK
//!   solver gate, validated against held-back ground truth (synthetic-only).
//! - [`generator`]: the engine storage-layer base-7 decoder and vendored input
//!   blocks used for corpus cross-checks.
//! - [`grouping`]: Experiment 8 base-N grouping comparison and independent
//!   collision-based state-count calibration.
//! - [`honeycomb`]: fixed-order two-dimensional honeycomb lattice structure
//!   test over physical row-pair coordinates.
//! - [`ingest`]: external-ciphertext ingest — a pure `parse_sequence` plus a
//!   thin `load_sequence` I/O wrapper that loads arbitrary glyph sequences
//!   (rendered orientation, accepted honeycomb reading, or a general cipher
//!   alphabet) without the library ever touching global stdin.
//! - [`language`]: English/Finnish n-gram language models for scoring
//!   candidate plaintexts.
//! - [`modular_diff`]: modular finite-difference structural fingerprinting
//!   with generated cipher-family controls.
//! - [`null`]: deterministic null distributions for fixed reading-order
//!   families.
//! - [`orders`]: reading-order experiments that reconstruct the rendered 2D
//!   glyph grids (splitting on the `5` row delimiter) and read them under
//!   documented order families.
//! - [`orientation_homogeneity`]: order-independent cross-message
//!   homogeneity test over engine-fixed single-orientation frequencies.
//! - [`perfect_isomorphism`]: Thread 3 perfect-isomorphism and allomorph
//!   consistency scan over cross-message gap-pattern isomorphs.
//! - [`periodicity`]: Experiment 5A periodicity, autocorrelation, and Kasiski
//!   tests against same-shape random null streams.
//! - [`perseus`]: Experiment 7C Perseus shared-region recurrence statistic and
//!   within-message shuffle null.
//! - [`pipeline_null`]: Experiment 2 nulls for testing whether the base-7
//!   generation pipeline manufactures reading-layer statistics.
//! - [`pyry_conditions`]: capstone structural falsification harness encoding
//!   Pyry's nine-condition checklist across generated cipher-family fixtures.
//! - [`quadgram`]: large-corpus `A..Z` quadgram English language model for
//!   scoring candidate plaintexts during polyalphabetic key search.
//! - [`report`]: CLI report rendering and domain error formatting.
//! - [`solve`]: unified search-and-score solve pipeline for candidate
//!   hypotheses, with round-trip, held-out, and matched-null gates.
//! - [`zero_adjacency_null`]: Experiment 7D zero-adjacency
//!   forbidden-successor null against within-message multiset shuffles.
//! - [`tree_residual`]: tree-residual cross-tail n-gram sharing after the
//!   Experiment 7C shared-region mask, against a within-tail shuffle null.
//! - [`transitivity`]: conditional D166 dihedral-exclusion audit using
//!   graph-chaining links and the order-83 forcing argument.
//!
//! Nothing here commits to a particular theory of how the glyphs encode
//! meaning; the goal is to provide trustworthy primitives that constrain the
//! hypothesis space.

// core: alphabet, base-5 reading layer, and external-ciphertext ingest.
#[path = "core/glyph.rs"]
pub mod glyph;
#[path = "core/trigram.rs"]
pub mod trigram;
// role: external-ciphertext front door (brief 03 core/sequence territory).
#[path = "core/ingest.rs"]
pub mod ingest;

// data: the verified corpus and the engine base-7 decoder/generator.
#[path = "data/corpus.rs"]
pub mod corpus;
#[path = "data/generator.rs"]
pub mod generator;

// analysis: encoding-agnostic statistics and structural analyses.
#[path = "analysis/analysis.rs"]
pub mod analysis;
#[path = "analysis/chaining.rs"]
pub mod chaining;
#[path = "analysis/chaining_graph.rs"]
pub mod chaining_graph;
#[path = "analysis/grouping.rs"]
pub mod grouping;
#[path = "analysis/honeycomb.rs"]
pub mod honeycomb;
#[path = "analysis/isomorph.rs"]
pub mod isomorph;
#[path = "analysis/orders.rs"]
pub mod orders;
#[path = "analysis/perfect_isomorphism.rs"]
pub mod perfect_isomorphism;

pub mod agl_gak;
pub mod cipher_attack;
pub mod ciphers;
pub mod codec;
pub mod conditional_structure;
pub mod controls;
pub mod dof_null;
pub mod gak_attack;
pub mod isomorph_null;
pub mod keystream;
pub mod language;
pub mod modular_diff;
pub mod null;
pub mod orientation_homogeneity;
pub mod periodicity;
pub mod perseus;
pub mod pipeline_null;
pub mod pyry_conditions;
pub mod quadgram;
pub mod report;
pub mod solve;
pub mod transitivity;
pub mod tree_residual;
pub mod zero_adjacency_null;

//! Encoding-agnostic statistics and the structural analyses.
//!
//! The [`analysis`] leaf holds the general cryptanalysis
//! statistics; the remaining modules are the structural experiments and audits
//! that constrain the hypothesis space without committing to any encoding
//! theory:
//!
//! - [`analysis`]: encoding-agnostic cryptanalysis statistics
//!   (frequencies, entropy, index of coincidence, chi-square goodness of fit,
//!   n-grams).
//! - [`chaining`]: Experiment 7B alphabet-chaining structural signatures with
//!   generated known-succeed and known-fail calibration controls.
//! - [`crc_scan`]: file-driven stored-`u32` CRC/hash word scanner with analytic
//!   and `SplitMix64` empirical false-alarm calibration.
//! - [`chaining_graph`]: graph-chaining conflict and coverage audit over
//!   aligned isomorph occurrences.
//! - [`first_trigram`]: first-trigram "message start" tabulation in both the
//!   storage-order base-5 and honeycomb reading-layer representations, with
//!   index/checksum/last-character/base-5 digit-structure hypothesis verdicts.
//! - [`group_order`]: D4/A4/S4 hidden-group element-order discriminator for the
//!   `C3 × H` hidden-state GAK reading — reads the deck channel's induced
//!   permutation across difference-channel anchors and reports which hidden group
//!   the observed cycle-length spectrum is consistent with.
//! - [`grouping`]: Experiment 8 base-N grouping comparison and independent
//!   collision-based state-count calibration.
//! - [`honeycomb`]: fixed-order two-dimensional honeycomb lattice structure
//!   test over physical row-pair coordinates.
//! - [`isomorph`]: first-occurrence repeated-pattern detection used by the
//!   isomorph experiments and controls.
//! - [`key_difference`]: Thread B isomorph key-difference discriminator — recovers
//!   the additive realisation `Δ` of the isomorph relabelling and classifies it by
//!   finite-difference order (identical / constant-additive / linear / irregular).
//! - [`isomorph_imperfection`]: Thread G2 forward isomorph-imperfection
//!   disproof — extended-window violation push, loose-candidate-class matched
//!   null, word-boundary discount, and a generative imperfectly-isomorphic
//!   cipher family for the fit comparison.
//! - [`leak_ceiling`]: Thread G3 isomorph-leak information ceiling — measured
//!   leak supply vs analytic chaining-recovery demand, with a G1b `two`
//!   coverage-model calibration and a coset-count scaling sweep.
//! - [`orders`]: reading-order experiments that reconstruct the rendered 2D
//!   glyph grids (splitting on the `5` row delimiter) and read them under
//!   documented order families.
//! - [`perfect_isomorphism`]: Thread 3 perfect-isomorphism and allomorph
//!   consistency scan over cross-message gap-pattern isomorphs.

#[allow(
    clippy::module_inception,
    reason = "the statistics leaf keeps its `analysis` name; de-stuttering it is a tracked follow-up, out of scope for the module-tree conversion"
)]
pub mod analysis;
pub mod chaining;
pub mod chaining_graph;
pub mod crc_scan;
pub mod ctak_feedback;
pub mod first_trigram;
pub mod group_order;
pub mod grouping;
pub mod honeycomb;
pub mod isomorph;
pub mod isomorph_imperfection;
pub mod key_difference;
pub mod leak_ceiling;
pub mod orders;
pub mod perfect_isomorphism;
pub mod predicates;
pub mod translate_isomorph;

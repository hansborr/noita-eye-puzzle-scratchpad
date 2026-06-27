//! The structural-battery experiment drivers.
//!
//! - [`conditional_structure`]: first-order transition-matrix and
//!   successor-graph analysis against within-message shuffle nulls.
//! - [`controls`]: positive-control fixtures for solved cipher classes.
//! - [`modular_diff`]: modular finite-difference structural fingerprinting with
//!   generated cipher-family controls.
//! - [`orientation_homogeneity`]: order-independent cross-message homogeneity
//!   test over engine-fixed single-orientation frequencies.
//! - [`periodicity`]: Experiment 5A periodicity, autocorrelation, and Kasiski
//!   tests against same-shape random null streams.
//! - [`pyry_conditions`]: capstone structural falsification harness encoding
//!   Pyry's nine-condition checklist across generated cipher-family fixtures.
//! - [`transitivity`]: conditional D166 dihedral-exclusion audit using
//!   graph-chaining links and the order-83 forcing argument.

pub mod conditional_structure;
pub mod controls;
pub mod modular_diff;
pub mod orientation_homogeneity;
pub mod periodicity;
pub mod pyry_conditions;
pub mod transitivity;

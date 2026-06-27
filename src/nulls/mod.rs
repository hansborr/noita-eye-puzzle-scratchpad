//! Matched-null distributions and DoF-calibrated null drivers.
//!
//! [`null`] is the shared matched-null harness core; the other drivers build
//! their experiment-specific null models on top of it:
//!
//! - [`dof_null`]: calibrated adaptive null for researcher degrees of freedom
//!   across traversal, grouping, and headline-statistic choice.
//! - [`heldout`]: shared held-out-fold helpers for the survival gates (the
//!   alternating fold extraction plus matched-null full/held-out statistics).
//! - [`isomorph_null`]: Experiment 7A repeated-pattern analysis against a
//!   within-message shuffle null.
//! - [`null`]: deterministic null distributions for fixed reading-order
//!   families.
//! - [`perseus`]: Experiment 7C Perseus shared-region recurrence statistic and
//!   within-message shuffle null.
//! - [`pipeline_null`]: Experiment 2 nulls for testing whether the base-7
//!   generation pipeline manufactures reading-layer statistics.
//! - [`tree_residual`]: tree-residual cross-tail n-gram sharing after the
//!   Experiment 7C shared-region mask, against a within-tail shuffle null.
//! - [`zero_adjacency_null`]: Experiment 7D zero-adjacency forbidden-successor
//!   null against within-message multiset shuffles.

pub mod dof_null;
pub mod heldout;
pub mod isomorph_null;
pub mod null;
pub mod perseus;
pub mod pipeline_null;
pub mod tree_residual;
pub mod zero_adjacency_null;

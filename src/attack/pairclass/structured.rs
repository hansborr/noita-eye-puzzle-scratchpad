//! Structured-coloring enumeration plus fully pinned oracle decode.
//!
//! This module implements Avenue A for the `pairclass` instrument: enumerate a
//! curated family of deterministic 26-to-4 letter colorings, collapse only the
//! class-label symmetry with a generous marginal filter, and run the existing
//! solver with each survivor passed as `SolveInput::seed_coloring`.

mod confirm;
mod enumerate;
mod families;
mod nulls;
mod pipeline;
mod random;

pub use confirm::{StructuredConfirmRender, confirm_structured_top_candidates};
pub use enumerate::{
    DEFAULT_STRUCTURED_RANK_BEAM, StructuredCandidateMeta, StructuredFamilyProfile,
    StructuredGenerationReport, StructuredRunCfg, StructuredStream, generate_structured_candidates,
};
pub use pipeline::{
    StructuredDecodedCandidate, StructuredNegativeReport, StructuredNullCfg, StructuredNullGate,
    StructuredPlantOutcome, StructuredPowerReport, StructuredRunReport, measure_structured_power,
    measure_structured_random_negative, run_structured_oracle_decode, structured_null_gate,
    structured_null_gate_streams,
};

#[cfg(test)]
pub(crate) use random::draw_out_of_family_random_plant;

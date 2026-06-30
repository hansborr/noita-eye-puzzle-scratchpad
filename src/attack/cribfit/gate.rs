//! The language gate: for each crib-consistent + English-viable candidate, run
//! `rlcodec`'s substitution search against the **same** matched null the codec
//! battery uses ([`gate_symbol_stream`]).
//!
//! This is a thin adapter — all null/search/verdict logic lives in `rlcodec`, so
//! `cribfit` and `rlcodec` cannot drift apart. A high quadgram score here is **not**
//! a decode: a candidate is a survivor only if its real score beats the matched
//! null at `p < SURVIVOR_ALPHA`, exactly as in the codec battery.

use crate::attack::quadgram::QuadgramModel;
use crate::attack::rlcodec::{BatteryCfg, CodecVerdict, gate_symbol_stream, name_seed_tag};

use super::CribfitError;
use super::families::CribCandidate;

/// Gates every gateable candidate (crib-consistent and English-viable) and returns
/// the matched-null verdicts in candidate order.
///
/// Each candidate's random streams are separated by a name-derived seed tag (the
/// same scheme `rlcodec` uses per codec), so the gate is deterministic in
/// `cfg.seed` and independent across candidates.
///
/// # Errors
/// Returns [`CribfitError`] if a matched null or substitution search fails.
pub fn gate_candidates(
    candidates: &[CribCandidate],
    model: &QuadgramModel,
    cfg: &BatteryCfg,
) -> Result<Vec<CodecVerdict>, CribfitError> {
    let mut verdicts = Vec::new();
    for candidate in candidates.iter().filter(|c| c.gateable()) {
        verdicts.push(gate_symbol_stream(
            candidate.name.clone(),
            &candidate.symbols,
            name_seed_tag(&candidate.name),
            model,
            cfg,
        )?);
    }
    Ok(verdicts)
}

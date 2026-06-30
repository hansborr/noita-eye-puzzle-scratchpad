//! Crib-anchored consistency filter for the *codec-with-memory* regime of practice
//! puzzle `one`.
//!
//! `rlcodec` settled that `one`'s carrier is the direction-blind run-length
//! magnitude sequence `M` and excluded every *memoryless* codec as an honest
//! negative; the live regime is a codec **with memory / a keyed or stateful
//! reading** of `M`. This instrument operationalizes the lever that regime leaves
//! open: `M` has census-significant exact repeats (the *cribs*), and a repeat in a
//! carrier almost certainly marks a repeated *plaintext* span — so for **any codec
//! whose tokens align to the crib (plaintext-token) boundaries, every occurrence
//! must decode identically.**
//!
//! That is a **language-free necessary condition**, with an explicit precondition:
//! the repeated carrier span must line up with the codec's token boundaries. When a
//! tokenization's boundaries do *not* align across the cribs (a chunk straddles a
//! window edge, or a dropped separator leaves a gap), the test is **inapplicable** —
//! the crib is *set aside*, never treated as an exclusion. Every candidate is thus in
//! one of three states: **applicable + consistent** (survives the filter),
//! **applicable + inconsistent** (excluded), or **inapplicable** (set aside). For
//! aligned codecs the condition is a hard filter that excludes most of the space
//! *and derives the admissible state/key period* from the cribs' geometry:
//!
//! - a **run-periodic** key (advances once per run) is consistent ⟺ its period
//!   divides every **run-gap** ⟺ it divides `gcd(run-gaps)`;
//! - a **bit-periodic** key (advances once per carrier bit) and a
//!   **cumulative-sum-mod-`n`** code are consistent ⟺ their period / modulus
//!   divides every **bit-gap** ⟺ it divides `gcd(bit-gaps)`;
//! - a **move-to-front** (evolving-table) code is checked directly by
//!   occurrence-equality across the cribs, where its tokenization aligns.
//!
//! ## Honesty discipline (binding — see `AGENTS.md`)
//!
//! A crib-consistent candidate is still only a **hypothesis**: any crib-consistent,
//! English-viable symbol stream is handed to `rlcodec`'s substitution search and the
//! **same matched null** the codec battery uses ([`gate_symbol_stream`]); a high
//! quadgram score that does not beat that null is a substitution-freedom artifact,
//! never a decode. The expected verdict on real `one` is an **honest negative**
//! (no English survivor) plus the *derived structural constraint*: the only
//! English-viable bit-periodic/cumsum periods divide `gcd(bit-gaps)`, and no
//! nontrivial run-periodic key is admissible (`gcd(run-gaps) = 1`).
//!
//! [`gate_symbol_stream`]: crate::attack::rlcodec::gate_symbol_stream

use crate::attack::quadgram::QuadgramModel;
use crate::attack::rlcodec::{BatteryCfg, CensusReport, CodecVerdict, RlError, derive_magnitudes};
use crate::core::glyph::Glyph;
use crate::nulls::null::mix_seed;

mod crib;
mod families;
mod gate;
mod selftest;

#[cfg(test)]
mod tests;

pub use crib::{AnchorPair, CribGeometry, crib_geometry, derive_crib_geometry};
pub use families::{
    AnchorConsistency, ConsistencyVerdict, CribCandidate, Tokenization, cumsum_candidate,
    mtf_candidate,
};
pub use gate::gate_candidates;
pub use selftest::{CribfitSelfTest, cribfit_self_test};

/// `cribfit`'s error type is `rlcodec`'s — every fallible step (derive, census,
/// matched-null gate) routes through `rlcodec` library functions.
pub type CribfitError = RlError;

/// Seed tag separating `cribfit`'s census null stream from the candidate gates.
const CENSUS_TAG: u64 = 0x0c41_b817_0000_0001;

/// A summary of the carrier derivation for the report header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CarrierSummary {
    /// Number of input digits.
    pub n_digits: usize,
    /// The base the walk lives on.
    pub base: usize,
    /// Number of `±1` move bits.
    pub n_bits: usize,
    /// Number of run-length magnitudes (`|M|`).
    pub n_magnitudes: usize,
    /// Sum of the magnitudes (`= n_bits`).
    pub sum: usize,
    /// Magnitude distribution as sorted `(value, count)` pairs.
    pub distribution: Vec<(usize, usize)>,
}

/// The whole `cribfit` run: carrier header, crib geometry (Section A), the per-family
/// candidates (Section B), and the gated survivors with the honest verdict
/// (Section C).
#[derive(Clone, Debug, PartialEq)]
pub struct CribfitReport {
    /// Carrier-derivation summary.
    pub carrier: CarrierSummary,
    /// Crib geometry and the divisibility lattice (Section A).
    pub geometry: CribGeometry,
    /// Census calibration of the cribs' longest repeat (the cribs' significance).
    pub census: CensusReport,
    /// `CumulativeSumMod(n)` candidates, one per admissible modulus (Section B).
    pub cumsum: Vec<CribCandidate>,
    /// `EvolvingTableMtf` candidates, one per tokenization (Section B).
    pub mtf: Vec<CribCandidate>,
    /// Matched-null verdicts for the crib-consistent + English-viable candidates
    /// (Section C).
    pub gated: Vec<CodecVerdict>,
    /// `true` iff some gated candidate beat its matched null (expected `false` on
    /// real `one`: the honest negative).
    pub overall_survivor: bool,
}

impl CribfitReport {
    /// `true` when the geometry found at least one census-significant crib (the
    /// filter is inapplicable without one).
    #[must_use]
    pub fn has_cribs(&self) -> bool {
        !self.geometry.anchors.is_empty()
    }
}

/// Builds the carrier-derivation summary.
fn summarise(n_digits: usize, base: usize, magnitudes: &[usize], n_bits: usize) -> CarrierSummary {
    let mut counts: std::collections::BTreeMap<usize, usize> = std::collections::BTreeMap::new();
    for &m in magnitudes {
        *counts.entry(m).or_insert(0) += 1;
    }
    CarrierSummary {
        n_digits,
        base,
        n_bits,
        n_magnitudes: magnitudes.len(),
        sum: magnitudes.iter().sum(),
        distribution: counts.into_iter().collect(),
    }
}

/// Runs the whole crib-consistency filter: derive `M`, census its cribs, compute the
/// geometry, enumerate the family candidates with their crib-consistency verdicts,
/// and gate the crib-consistent + English-viable ones against the matched null.
///
/// # Errors
/// Returns [`CribfitError`] if the input is not a clean `±1` walk, if the English
/// quadgram model fails to build, or if a census / matched-null / search step fails.
pub fn run_cribfit(
    digits: &[Glyph],
    base: usize,
    cfg: &BatteryCfg,
) -> Result<CribfitReport, CribfitError> {
    let derivation = derive_magnitudes(digits, base)?;
    if derivation.magnitudes.is_empty() {
        return Err(RlError::EmptyMagnitudes);
    }
    let magnitudes = &derivation.magnitudes;
    let (geometry, census) = derive_crib_geometry(
        magnitudes,
        cfg.top_k,
        cfg.census_null_trials,
        mix_seed(cfg.seed, CENSUS_TAG),
    )?;
    let model = QuadgramModel::english()?;

    let cumsum: Vec<CribCandidate> = geometry
        .bit_periods
        .iter()
        .map(|&n| cumsum_candidate(magnitudes, n, &geometry.anchors))
        .collect();
    let mtf: Vec<CribCandidate> = Tokenization::all()
        .into_iter()
        .map(|tok| mtf_candidate(magnitudes, tok, &geometry.anchors))
        .collect();

    let mut all = cumsum.clone();
    all.extend(mtf.clone());
    let gated = gate_candidates(&all, &model, cfg)?;
    let overall_survivor = gated.iter().any(|verdict| verdict.survivor);

    Ok(CribfitReport {
        carrier: summarise(digits.len(), base, magnitudes, derivation.n_bits),
        geometry,
        census,
        cumsum,
        mtf,
        gated,
        overall_survivor,
    })
}

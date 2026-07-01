//! Planted controls for `mdlcodec --self-test`.

use std::collections::HashMap;

use crate::attack::cribfit::derive_crib_geometry;
use crate::attack::quadgram::QuadgramModel;
use crate::attack::rlcodec::{
    PLANT_PLAINTEXT, RlError, derive_magnitudes, english_letters, one_practice_digits,
};
use crate::nulls::null::{SplitMix64, random_index_below};

use super::eval::analyze_magnitudes;
use super::grid::{AffineCell, crib_consistent};
use super::{MdlCfg, MdlError, carrier_summary};

/// Outcome of the `mdlcodec` self-test.
#[derive(Clone, Debug, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "self-test report DTO: each bool is an independent control verdict printed by the CLI"
)]
pub struct MdlSelfTest {
    /// The planted affine cell passed the modular crib check.
    pub planted_cell_crib_consistent: bool,
    /// The planted cell's best substitution exactly recovered the plant text.
    pub planted_recovered: bool,
    /// The planted cell beat the post-selection matched null.
    pub planted_survivor: bool,
    /// The planted cell was at or near the global MDL-like winner.
    pub planted_near_winner: bool,
    /// Planted cell `MDL - mean(null best MDL)`, in bits.
    pub planted_delta_mdl_bits: f64,
    /// Fifth percentile of the planted run's post-selection best-null MDL values.
    pub planted_null_p05_bits: f64,
    /// The random repeated-block control did not beat its post-selection null.
    pub null_non_survivor: bool,
    /// The random repeated-block control had more than one near-tied cell.
    pub null_underdetermined: bool,
    /// Near-tie count measured on the random repeated-block control.
    pub null_underdetermination_count: usize,
    /// The `a=1,b=0` modular check agrees with cribfit's admissible `R` set and
    /// includes `R=21` on real `one`.
    pub cribfit_r21_crosscheck: bool,
}

impl MdlSelfTest {
    /// `true` iff every planted/control leg passed.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.planted_cell_crib_consistent
            && self.planted_recovered
            && self.planted_survivor
            && self.planted_near_winner
            && self.null_non_survivor
            && self.null_underdetermined
            && self.cribfit_r21_crosscheck
    }
}

/// Runs the planted positive, matched null control, and cribfit cross-check.
///
/// # Errors
/// Returns [`MdlError`] if a shared derivation, census, search, or null step
/// fails.
pub fn mdlcodec_self_test(seed: u64) -> Result<MdlSelfTest, MdlError> {
    let model = QuadgramModel::english().map_err(RlError::from)?;
    let planted = planted_positive(&model, seed)?;
    let null = random_null_control(&model, seed)?;
    let cribfit_r21_crosscheck = cribfit_crosscheck(seed)?;
    Ok(MdlSelfTest {
        planted_cell_crib_consistent: planted.cell_crib_consistent,
        planted_recovered: planted.recovered,
        planted_survivor: planted.survivor,
        planted_near_winner: planted.near_winner,
        planted_delta_mdl_bits: planted.delta_mdl_bits,
        planted_null_p05_bits: planted.null_p05_bits,
        null_non_survivor: null.non_survivor,
        null_underdetermined: null.underdetermined,
        null_underdetermination_count: null.underdetermination_count,
        cribfit_r21_crosscheck,
    })
}

#[allow(
    clippy::struct_excessive_bools,
    reason = "internal self-test DTO mirrors the independent planted-control checks"
)]
struct PlantedOutcome {
    cell_crib_consistent: bool,
    recovered: bool,
    survivor: bool,
    near_winner: bool,
    delta_mdl_bits: f64,
    null_p05_bits: f64,
}

struct NullOutcome {
    non_survivor: bool,
    underdetermined: bool,
    underdetermination_count: usize,
}

fn planted_positive(model: &QuadgramModel, seed: u64) -> Result<PlantedOutcome, MdlError> {
    let plant_text = positive_plaintext();
    let magnitudes = affine_english_magnitudes(&plant_text, 17);
    let cfg = positive_cfg(seed);
    let carrier = carrier_summary(
        magnitudes.iter().sum::<usize>() + 1,
        5,
        magnitudes.iter().sum(),
        &magnitudes,
    );
    let report = analyze_magnitudes(carrier, &magnitudes, &cfg, model)?;
    let planted_cell = AffineCell {
        ring: 17,
        a: 1,
        b: 0,
    };
    let planted_cell_crib_consistent = crib_consistent(&report.geometry.anchors, planted_cell);
    let planted_row = report.top_cells.iter().find(|row| row.cell == planted_cell);
    let planted_recovered = planted_row.is_some_and(|row| row.candidate == plant_text);
    let planted_survivor = planted_row.is_some_and(|row| row.survivor);
    let planted_near_winner =
        planted_row.is_some_and(|row| row.mdl_bits <= report.winner.mdl_bits + cfg.epsilon_bits);
    let planted_delta_mdl_bits = planted_row.map_or(f64::NAN, |row| row.delta_mdl_bits);
    Ok(PlantedOutcome {
        cell_crib_consistent: planted_cell_crib_consistent,
        recovered: planted_recovered,
        survivor: planted_survivor,
        near_winner: planted_near_winner,
        delta_mdl_bits: planted_delta_mdl_bits,
        null_p05_bits: report.null.p05_mdl_bits,
    })
}

fn random_null_control(model: &QuadgramModel, seed: u64) -> Result<NullOutcome, MdlError> {
    let magnitudes = random_repeated_magnitudes(seed)?;
    let cfg = null_cfg(seed);
    let carrier = carrier_summary(
        magnitudes.iter().sum::<usize>() + 1,
        5,
        magnitudes.iter().sum(),
        &magnitudes,
    );
    let report = analyze_magnitudes(carrier, &magnitudes, &cfg, model)?;
    Ok(NullOutcome {
        non_survivor: !report.winner.survivor,
        underdetermined: report.underdetermination_count >= 2,
        underdetermination_count: report.underdetermination_count,
    })
}

fn cribfit_crosscheck(seed: u64) -> Result<bool, MdlError> {
    let one = one_practice_digits()?;
    let derivation = derive_magnitudes(&one, 5)?;
    let (geometry, _census) = derive_crib_geometry(&derivation.magnitudes, 8, 40, seed)?;
    let mdl_admissible = (1usize..=26)
        .filter(|&ring| crib_consistent(&geometry.anchors, AffineCell { ring, a: 1, b: 0 }))
        .collect::<Vec<_>>();
    let cribfit_admissible = geometry
        .bit_periods
        .iter()
        .copied()
        .filter(|period| (1..=26).contains(period))
        .collect::<Vec<_>>();
    Ok(mdl_admissible == cribfit_admissible && mdl_admissible.contains(&21))
}

fn positive_cfg(seed: u64) -> MdlCfg {
    MdlCfg {
        ring_sizes: vec![17],
        coeff_max: 1,
        epsilon_bits: 2.0,
        top: 512,
        null_trials: 80,
        restarts: 12,
        iters: 3_000,
        top_k: 1,
        census_null_trials: 40,
        seed,
        min_effective_alphabet: 8,
    }
}

fn null_cfg(seed: u64) -> MdlCfg {
    MdlCfg {
        ring_sizes: (10..=20).collect(),
        coeff_max: 5,
        epsilon_bits: 100.0,
        top: 128,
        null_trials: 12,
        restarts: 4,
        iters: 700,
        top_k: 8,
        census_null_trials: 32,
        seed: seed ^ 0x9e37_79b9_7f4a_7c15,
        min_effective_alphabet: 8,
    }
}

fn affine_english_magnitudes(text: &str, ring: usize) -> Vec<usize> {
    let symbols = first_seen_symbols(&english_letters(text));
    let mut magnitudes = Vec::with_capacity(symbols.len());
    for pair in symbols.windows(2) {
        let [current, next] = pair else { continue };
        let diff = (*next + ring - *current) % ring;
        magnitudes.push(if diff == 0 { ring } else { diff });
    }
    magnitudes.push(1);
    magnitudes
}

fn positive_plaintext() -> String {
    format!(
        "{}{}",
        PLANT_PLAINTEXT,
        "THENORTHWINDROSEANDTHEOLDSTONEWALLSHELDTHERAINALONGTHEROAD\
THERIDERSWENTONINSILENTSLOWSTEPSANDTHEHIDDENLANDSLEANEDTOWARDTHESEA\
WHILETHETREESSTOODINTHEDARKANDTHEROADLEDONANDLEDTHEMINTOLONELIERHILLS"
    )
}

fn first_seen_symbols(letters: &[usize]) -> Vec<usize> {
    let mut ids = HashMap::new();
    let mut out = Vec::with_capacity(letters.len());
    for &letter in letters {
        let next = ids.len();
        out.push(*ids.entry(letter).or_insert(next));
    }
    out
}

fn random_repeated_magnitudes(seed: u64) -> Result<Vec<usize>, MdlError> {
    let mut rng = SplitMix64::new(seed ^ 0x6d64_6c63_5eed_0001);
    let mut magnitudes = (0..160)
        .map(|_index| random_index_below(5, &mut rng).map(|value| value + 1))
        .collect::<Result<Vec<_>, _>>()
        .map_err(RlError::from)?;
    let first = 20usize;
    let second = 95usize;
    let length = 30usize;
    for offset in 0..length {
        let value = magnitudes.get(first + offset).copied().unwrap_or(1);
        if let Some(slot) = magnitudes.get_mut(second + offset) {
            *slot = value;
        }
    }
    Ok(magnitudes)
}

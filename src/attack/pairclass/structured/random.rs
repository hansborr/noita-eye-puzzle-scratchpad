//! Random-coloring helpers for structured negative controls.

use std::collections::BTreeSet;

use crate::attack::pairclass::PairclassError;
use crate::attack::pairclass::plant::{Plant, PlantSpec, plant_from_text};

const RANDOM_NEGATIVE_REDRAW_LIMIT: usize = 256;

pub(crate) fn draw_out_of_family_random_plant(
    text: &str,
    spec: &PlantSpec,
    base_seed: u64,
    plant_index: usize,
    forbidden: &BTreeSet<[u8; 26]>,
) -> Result<(Plant, usize), PairclassError> {
    for redraws in 0..RANDOM_NEGATIVE_REDRAW_LIMIT {
        let seed = redraw_seed(base_seed, plant_index, redraws);
        let plant = plant_from_text(text, spec, seed)?;
        if !forbidden.contains(&plant.coloring) {
            return Ok((plant, redraws));
        }
    }
    Err(PairclassError::NullModel(format!(
        "failed to draw random coloring outside structured family after {RANDOM_NEGATIVE_REDRAW_LIMIT} attempts"
    )))
}

fn redraw_seed(base_seed: u64, plant_index: usize, redraws: usize) -> u64 {
    base_seed
        .wrapping_add(plant_index as u64)
        .wrapping_add((redraws as u64) << 32)
}

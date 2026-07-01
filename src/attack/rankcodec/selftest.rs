//! Planted controls for the `rankcodec` CLI self-test.

use crate::attack::cribfit::AnchorPair;
use crate::attack::quadgram::QuadgramModel;
use crate::attack::rlcodec::{
    BatteryCfg, CodecVerdict, PLANT_PLAINTEXT, english_letters, gate_symbol_stream_with_nulls,
    name_seed_tag,
};

use super::{
    DEFAULT_MAX_MAGNITUDE, RankCribStatus, RankError, RankPredictor, crib_summary,
    matched_null_decodes, rank_decode, rank_encode,
};

/// Positive-control legs in `rankcodec --self-test`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RankPositiveSelfTest {
    /// Planted positive decoded back to the constructed plant.
    pub recovered: bool,
    /// Planted repeated windows locked after the predictor transient.
    pub crib_consistent: bool,
    /// Planted positive cleared the tertiary gate.
    pub survivor: bool,
}

/// Outcome of `rankcodec --self-test`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RankSelfTest {
    /// Round-trip law held on the built-in passage.
    pub round_trip: bool,
    /// Planted positive-control results.
    pub positive: RankPositiveSelfTest,
    /// Deliberately mismatched repeated windows were excluded.
    pub inconsistent_excluded: bool,
}

impl RankSelfTest {
    /// `true` iff every self-test leg passed.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.round_trip
            && self.positive.recovered
            && self.positive.crib_consistent
            && self.positive.survivor
            && self.inconsistent_excluded
    }
}

/// Runs fast planted controls for `rankcodec`.
///
/// # Errors
/// Returns [`RankError`] if a shared gate/search step fails.
pub fn rankcodec_self_test(seed: u64) -> Result<RankSelfTest, RankError> {
    let source = english_letters(PLANT_PLAINTEXT);
    let pred = RankPredictor::train(&source, 3);
    let encoded = rank_encode(&pred, &source);
    let round_trip = rank_decode(&pred, &encoded) == source;

    let (plant, plant_magnitudes, anchor) = build_positive_plant(&pred);
    let recovered = rank_decode(&pred, &plant_magnitudes);
    let positive_recovered = recovered == plant;
    let positive_crib = crib_summary(&recovered, &[anchor], pred.order());
    let positive_crib_consistent = positive_crib.status == RankCribStatus::Consistent;
    let positive_survivor = positive_gate(&pred, &plant_magnitudes, &[anchor], seed)?.survivor;

    let (inconsistent_m, inconsistent_anchor) = build_inconsistent_carrier();
    let inconsistent_decoded = rank_decode(&pred, &inconsistent_m);
    let inconsistent = crib_summary(&inconsistent_decoded, &[inconsistent_anchor], pred.order());

    Ok(RankSelfTest {
        round_trip,
        positive: RankPositiveSelfTest {
            recovered: positive_recovered,
            crib_consistent: positive_crib_consistent,
            survivor: positive_survivor,
        },
        inconsistent_excluded: inconsistent.status == RankCribStatus::Excluded,
    })
}

pub(super) fn build_positive_plant(pred: &RankPredictor) -> (Vec<usize>, Vec<usize>, AnchorPair) {
    let source = english_letters(PLANT_PLAINTEXT);
    let source_ranks = rank_encode(pred, &source)
        .into_iter()
        .map(|rank| rank.min(DEFAULT_MAX_MAGNITUDE))
        .collect::<Vec<_>>();
    let sync_len = 140usize;
    let block_start = 20usize;
    let block_len = 48usize;
    let filler_len = 80usize;

    let mut magnitudes = vec![1usize; sync_len];
    let first = magnitudes.len();
    let block_end = block_start + block_len;
    magnitudes.extend(
        source_ranks
            .get(block_start..block_end)
            .unwrap_or(&[])
            .iter()
            .copied(),
    );
    magnitudes.extend(
        source_ranks
            .get(block_end..(block_end + filler_len).min(source_ranks.len()))
            .unwrap_or(&[])
            .iter()
            .copied(),
    );
    magnitudes.extend(vec![1usize; sync_len]);
    let second = magnitudes.len();
    magnitudes.extend(
        source_ranks
            .get(block_start..block_end)
            .unwrap_or(&[])
            .iter()
            .copied(),
    );
    magnitudes.extend(
        source_ranks
            .get((block_end + filler_len).min(source_ranks.len())..)
            .unwrap_or(&[])
            .iter()
            .copied(),
    );
    let plant = rank_decode(pred, &magnitudes);
    let anchor = AnchorPair {
        length: block_len,
        first,
        second,
        run_gap: second - first,
        bit_gap: magnitudes
            .get(first..second)
            .unwrap_or(&[])
            .iter()
            .sum::<usize>(),
    };
    (plant, magnitudes, anchor)
}

pub(super) fn build_inconsistent_carrier() -> (Vec<usize>, AnchorPair) {
    let mut magnitudes = vec![1usize; 12];
    let block = [1usize, 2, 1, 3, 1, 2, 1, 4, 1, 2, 1, 3];
    let first = magnitudes.len();
    magnitudes.extend(block);
    magnitudes.extend([1usize; 8]);
    let second = magnitudes.len();
    magnitudes.extend(block);
    let anchor = AnchorPair {
        length: block.len(),
        first,
        second,
        run_gap: second - first,
        bit_gap: magnitudes
            .get(first..second)
            .unwrap_or(&[])
            .iter()
            .sum::<usize>(),
    };
    (magnitudes, anchor)
}

pub(super) fn positive_gate(
    pred: &RankPredictor,
    magnitudes: &[usize],
    anchors: &[AnchorPair],
    seed: u64,
) -> Result<CodecVerdict, RankError> {
    let cfg = BatteryCfg {
        null_trials: 24,
        restarts: 12,
        iters: 3_000,
        top_k: 0,
        census_null_trials: 0,
        seed,
    };
    let model = QuadgramModel::english().map_err(crate::attack::rlcodec::RlError::from)?;
    let decoded = rank_decode(pred, magnitudes);
    let nulls = matched_null_decodes(pred, magnitudes, anchors, DEFAULT_MAX_MAGNITUDE, &cfg, 3)?;
    let name = "RankCodecSelfTest{k=3}".to_owned();
    Ok(gate_symbol_stream_with_nulls(
        name.clone(),
        &decoded,
        &nulls,
        name_seed_tag(&name),
        &model,
        &cfg,
    )?)
}

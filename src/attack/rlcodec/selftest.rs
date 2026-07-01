//! The in-process self-test: a planted positive control that *must* fire and the
//! real-`one` honest negative that *must not*.

use crate::attack::quadgram::QuadgramModel;
use crate::core::glyph::Glyph;

use super::battery::{evaluate_codec, run_battery};
use super::codecs::RlCodec;
use super::derive::{derive_magnitudes, one_practice_digits};
use super::plant::{
    DEFAULT_COMMA_SEP, DEFAULT_PLANT_BASE, PLANT_PLAINTEXT, encode_comma, english_letters,
    partition_of,
};
use super::{BatteryCfg, RlError};

/// Positive-control matched-null trials. With `ge == 0` the add-one p-value is
/// `1/(trials+1)`, so `>= 20` trials are needed for `p < 0.05`.
const POSITIVE_NULL_TRIALS: usize = 24;
/// Positive-control search restarts (the long planted stream needs enough
/// restarts for the anneal to reliably find its English optimum).
const POSITIVE_RESTARTS: usize = 12;
/// Positive-control search proposals per restart.
const POSITIVE_ITERS: usize = 3_000;

/// Negative-control (real `one`) matched-null trials. The honest negative is
/// robust to budget — every codec scores below its null regardless — so a small
/// budget keeps `make verify` fast.
const NEGATIVE_NULL_TRIALS: usize = 20;
/// Negative-control search restarts.
const NEGATIVE_RESTARTS: usize = 6;
/// Negative-control search proposals per restart.
const NEGATIVE_ITERS: usize = 1_800;
/// Self-test census matched-null trials.
const SELFTEST_CENSUS_TRIALS: usize = 60;
/// Self-test census top-k anchors.
const SELFTEST_TOP_K: usize = 6;

/// Outcome of the self-test.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfTestReport {
    /// The codec the positive control plants through (`Comma{sep=4}`).
    pub positive_codec: String,
    /// Whether that codec was flagged a survivor on the planted walk.
    pub positive_survivor: bool,
    /// Whether the decoded symbol stream exactly recovered the planted partition.
    pub positive_partition_recovered: bool,
    /// Whether the real-`one` battery produced any survivor (must be `false`).
    pub negative_overall_survivor: bool,
}

impl SelfTestReport {
    /// `true` only if the positive control fired, recovered the planted partition,
    /// and the real-`one` negative produced no survivor.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.positive_survivor
            && self.positive_partition_recovered
            && !self.negative_overall_survivor
    }
}

/// The decoded symbol stream of the planted English-via-`Comma{sep=4}` positive
/// control (the partition the codec recovers).
///
/// Exposed so a sibling instrument (`cribfit`) can drive the *same* matched-null
/// gate ([`super::gate_symbol_stream`]) on a control known to fire — proving the
/// gate fires inside `cribfit` without re-deriving the English plant.
pub(crate) fn planted_positive_symbols() -> Vec<usize> {
    build_plant().1
}

/// The positive-control budget (a single planted codec, so it can afford the
/// larger search the long stream needs).
fn positive_cfg(seed: u64) -> BatteryCfg {
    BatteryCfg {
        null_trials: POSITIVE_NULL_TRIALS,
        restarts: POSITIVE_RESTARTS,
        iters: POSITIVE_ITERS,
        top_k: SELFTEST_TOP_K,
        census_null_trials: SELFTEST_CENSUS_TRIALS,
        seed,
    }
}

/// The negative-control budget (the whole real-`one` battery, kept small).
fn negative_cfg(seed: u64) -> BatteryCfg {
    BatteryCfg {
        null_trials: NEGATIVE_NULL_TRIALS,
        restarts: NEGATIVE_RESTARTS,
        iters: NEGATIVE_ITERS,
        top_k: SELFTEST_TOP_K,
        census_null_trials: SELFTEST_CENSUS_TRIALS,
        seed,
    }
}

/// Builds the planted positive control: the synthetic walk digits and the planted
/// symbol partition the `Comma{sep=4}` codec must recover.
fn build_plant() -> (Vec<Glyph>, Vec<usize>) {
    let letters = english_letters(PLANT_PLAINTEXT);
    let digits = encode_comma(&letters, DEFAULT_COMMA_SEP, DEFAULT_PLANT_BASE);
    let planted_partition = partition_of(&letters);
    (digits, planted_partition)
}

/// Runs the planted positive control and the real-`one` honest negative, returning
/// PASS only if the gate fires on the plant (and recovers it) and stays silent on
/// real `one`.
///
/// # Errors
/// Returns [`RlError`] if the embedded fixtures fail to derive or the battery
/// fails (it should not in a correct build).
pub fn rlcodec_self_test(seed: u64) -> Result<SelfTestReport, RlError> {
    let model = QuadgramModel::english()?;
    let comma = RlCodec::Comma {
        sep: DEFAULT_COMMA_SEP,
    };
    let positive_codec = comma.name();

    // POSITIVE: the planted English-via-Comma walk must fire and be recovered.
    // Only the planted codec is evaluated (the gate it fires through), so the long
    // stream can afford the larger search its reliable English recovery needs.
    let (plant_digits, planted_partition) = build_plant();
    let plant_magnitudes = derive_magnitudes(&plant_digits, DEFAULT_PLANT_BASE)?;
    let verdict = evaluate_codec(
        &plant_magnitudes.magnitudes,
        &comma,
        &model,
        &positive_cfg(seed),
    )?;
    let positive_survivor = verdict.survivor;

    let decoded = comma.decode(&plant_magnitudes.magnitudes);
    let positive_partition_recovered = decoded.as_deref() == Some(planted_partition.as_slice());

    // NEGATIVE: the real `one` magnitude sequence must produce no survivor across
    // the whole battery.
    let one_digits = one_practice_digits()?;
    let one_report = run_battery(&one_digits, DEFAULT_PLANT_BASE, &negative_cfg(seed))?;
    let negative_overall_survivor = one_report.overall_survivor;

    Ok(SelfTestReport {
        positive_codec,
        positive_survivor,
        positive_partition_recovered,
        negative_overall_survivor,
    })
}

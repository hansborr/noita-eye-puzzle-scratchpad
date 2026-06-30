//! The in-process self-test: a planted positive control that *must* fire and the
//! real-`one` honest negative that *must not*.

use std::collections::HashMap;

use crate::attack::quadgram::QuadgramModel;
use crate::core::glyph::Glyph;

use super::battery::{evaluate_codec, run_battery};
use super::codecs::RlCodec;
use super::derive::{derive_magnitudes, one_practice_digits, synthesize_walk};
use super::{BatteryCfg, RlError};

/// Separator magnitude used by the planted comma code (never appears inside a
/// letter tuple, which are drawn from `{1, 2, 3}`).
const PLANT_SEP: usize = 4;
/// Base of the synthetic `±1` walk.
const PLANT_BASE: usize = 5;

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

/// A genuine, long English plaintext for the planted positive control.
///
/// Restricted to a 12-letter alphabet (`A D E H I L N O R S T W`) so the planted
/// stream's substitution search converges reliably at a modest budget — the
/// English quadgram structure beyond bigrams is what beats the matched null, and
/// keeping the alphabet small keeps that recovery deterministic (a 22-letter plant
/// needs a far larger search budget to find its global optimum). It is genuine
/// English prose throughout.
const PLANT_PLAINTEXT: &str = "THERAINONTHEROADANDTHEWINDINTHETREESHIDTHELOSTRIDERS\
INTOTHEOLDNORTHLANDSWHERENOONEHADSAILEDORTRADEDINTENSLOWSEASONSANDTHESTONEWALLSHELD\
THESILENTDEADWHILETHETIREDRIDERSRODEONINTOTHERAINANDTHEWINDANDTHELONESHADEANDTHEOLD\
ROADSTILLLEDTHERIDERSINTOTHENORTHWHERETHEHEARTLANDSLIEDROWNEDINRAIN";

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

/// Maps each distinct value to a dense id by first appearance (the planted
/// partition's canonical form).
fn partition_of(values: &[usize]) -> Vec<usize> {
    let mut ids: HashMap<usize, usize> = HashMap::new();
    let mut out = Vec::with_capacity(values.len());
    for &value in values {
        let next = ids.len();
        out.push(*ids.entry(value).or_insert(next));
    }
    out
}

/// The `rank`-th distinct tuple over `{1, 2, 3}`, enumerated by increasing length
/// then lexicographically. Injective in `rank`, so distinct letters get distinct
/// tuples.
fn tuple_for_rank(rank: usize) -> Vec<usize> {
    let symbols = [1usize, 2, 3];
    let mut remaining = rank;
    let mut length = 1usize;
    loop {
        let count = symbols.len().pow(u32::try_from(length).unwrap_or(1));
        if remaining < count {
            let mut digits = Vec::with_capacity(length);
            let mut value = remaining;
            for _ in 0..length {
                let digit = value % symbols.len();
                value /= symbols.len();
                digits.push(*symbols.get(digit).unwrap_or(&1));
            }
            digits.reverse();
            return digits;
        }
        remaining -= count;
        length += 1;
    }
}

/// Builds the planted positive control: the synthetic walk digits and the planted
/// symbol partition the `Comma{sep=4}` codec must recover.
fn build_plant() -> (Vec<Glyph>, Vec<usize>) {
    let letters: Vec<usize> = PLANT_PLAINTEXT
        .bytes()
        .filter(u8::is_ascii_uppercase)
        .map(|byte| usize::from(byte - b'A'))
        .collect();

    let mut rank_of: HashMap<usize, usize> = HashMap::new();
    let mut magnitudes: Vec<usize> = Vec::new();
    for (position, &letter) in letters.iter().enumerate() {
        if position > 0 {
            magnitudes.push(PLANT_SEP);
        }
        let next_rank = rank_of.len();
        let rank = *rank_of.entry(letter).or_insert(next_rank);
        magnitudes.extend(tuple_for_rank(rank));
    }

    let digits = synthesize_walk(&magnitudes, PLANT_BASE);
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
    let comma = RlCodec::Comma { sep: PLANT_SEP };
    let positive_codec = comma.name();

    // POSITIVE: the planted English-via-Comma walk must fire and be recovered.
    // Only the planted codec is evaluated (the gate it fires through), so the long
    // stream can afford the larger search its reliable English recovery needs.
    let (plant_digits, planted_partition) = build_plant();
    let plant_magnitudes = derive_magnitudes(&plant_digits, PLANT_BASE)?;
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
    let one_report = run_battery(&one_digits, PLANT_BASE, &negative_cfg(seed))?;
    let negative_overall_survivor = one_report.overall_survivor;

    Ok(SelfTestReport {
        positive_codec,
        positive_survivor,
        positive_partition_recovered,
        negative_overall_survivor,
    })
}

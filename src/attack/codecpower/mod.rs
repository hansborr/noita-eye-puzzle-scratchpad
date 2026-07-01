//! Detection-power calibration for `rlcodec`'s comma-code gate.
//!
//! This instrument plants English letter windows through the same comma encoder
//! used by `rlcodec`'s positive control, decodes the resulting carrier with
//! [`crate::attack::rlcodec::RlCodec::Comma`], and gates the decoded symbol stream
//! through [`crate::attack::rlcodec::gate_symbol_stream`]. The reported power is
//! therefore the power of the actual matched-null gate, not a parallel score.

use crate::attack::quadgram::QuadgramModel;
use crate::attack::rlcodec::{
    BatteryCfg, CodecVerdict, DEFAULT_COMMA_SEP, DEFAULT_PLANT_BASE, PLANT_PLAINTEXT, RlCodec,
    RlError, derive_magnitudes, encode_comma, english_letters, gate_symbol_stream, name_seed_tag,
};
use crate::nulls::null::{SplitMix64, mix_seed, random_index_below};

#[cfg(test)]
mod tests;

/// Practice puzzle `one`'s direction-blind run-length carrier size.
pub const ONE_CARRIER_BUDGET: usize = 135;
/// Default plaintext lengths swept by the CLI.
pub const DEFAULT_LENGTHS: &[usize] = &[8, 12, 16, 24, 32, 48, 64];
/// Default number of English and non-English plants per swept length.
pub const DEFAULT_TRIALS: usize = 8;
/// Default detection-power threshold used for the detectable-length floor.
pub const DEFAULT_POWER_THRESHOLD: f64 = 0.8;
/// Short planted length used by `codecpower --self-test`.
pub const SELFTEST_SHORT_LENGTH: usize = 8;
/// Long planted length used by `codecpower --self-test`.
pub const SELFTEST_LONG_LENGTH: usize = 285;

/// Configuration for one `codecpower` run.
#[derive(Clone, Debug, PartialEq)]
pub struct PowerCfg {
    /// English source letters (`A=0..Z=25`) sampled as windows. If empty, the
    /// built-in planted-control passage is used.
    pub source_letters: Vec<usize>,
    /// Plaintext lengths to sweep.
    pub lengths: Vec<usize>,
    /// Number of English plants and matched non-English controls per length.
    pub trials: usize,
    /// Comma-code separator magnitude.
    pub sep: usize,
    /// Base of the synthetic `±1` walk.
    pub base: usize,
    /// Power threshold used to report the detectable-length floor.
    pub power_threshold: f64,
    /// Matched-null gate/search budget reused from `rlcodec`.
    pub gate: BatteryCfg,
}

impl PowerCfg {
    /// Returns the default CLI configuration for a seed and gate budget.
    #[must_use]
    pub fn defaults(gate: BatteryCfg) -> Self {
        Self {
            source_letters: english_letters(PLANT_PLAINTEXT),
            lengths: DEFAULT_LENGTHS.to_vec(),
            trials: DEFAULT_TRIALS,
            sep: DEFAULT_COMMA_SEP,
            base: DEFAULT_PLANT_BASE,
            power_threshold: DEFAULT_POWER_THRESHOLD,
            gate,
        }
    }
}

/// One row of the power curve.
#[derive(Clone, Debug, PartialEq)]
pub struct PowerRow {
    /// Planted plaintext length in letters.
    pub length: usize,
    /// Number of English plants evaluated.
    pub trials: usize,
    /// Mean direction-blind carrier length `|M|` after comma encoding.
    pub mean_carrier: f64,
    /// Number of English plants that survived the gate.
    pub detections: usize,
    /// Detection power (`detections / trials`) for English plants.
    pub power: f64,
    /// Mean z-score across English plants.
    pub mean_z: f64,
    /// Mean add-one p-value across English plants.
    pub mean_p: f64,
    /// Number of non-English control plants that survived the same gate.
    pub control_detections: usize,
    /// Detection rate on uniform-letter non-English controls for this length.
    pub control_rate: f64,
}

/// The row closest to `one`'s carrier budget.
#[derive(Clone, Debug, PartialEq)]
pub struct OperatingPoint {
    /// Planted plaintext length in letters.
    pub length: usize,
    /// Mean carrier length for that row.
    pub mean_carrier: f64,
    /// English detection power for that row.
    pub power: f64,
}

/// Full detection-power report.
#[derive(Clone, Debug, PartialEq)]
pub struct PowerReport {
    /// Codec under calibration.
    pub codec_name: String,
    /// Practice puzzle `one`'s comparison budget (`|M| = 135`).
    pub one_carrier_budget: usize,
    /// Per-length power rows.
    pub rows: Vec<PowerRow>,
    /// Aggregate non-English false-positive detections across all control plants.
    pub false_positive_detections: usize,
    /// Aggregate number of non-English control plants.
    pub false_positive_trials: usize,
    /// Aggregate non-English false-positive rate.
    pub false_positive_rate: f64,
    /// Row closest to `one`'s carrier budget.
    pub operating_point: Option<OperatingPoint>,
    /// Smallest swept length whose power clears the configured threshold.
    pub detectable_floor: Option<OperatingPoint>,
    /// Power threshold used for `detectable_floor`.
    pub power_threshold: f64,
}

/// Outcome of `codecpower --self-test`.
#[derive(Clone, Debug, PartialEq)]
pub struct CodecpowerSelfTest {
    /// Power at the short planted length.
    pub short_power: f64,
    /// Power at the long planted length.
    pub long_power: f64,
    /// Aggregate non-English false-positive rate.
    pub false_positive_rate: f64,
}

impl CodecpowerSelfTest {
    /// Returns `true` when the directional power and size controls pass.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.long_power >= DEFAULT_POWER_THRESHOLD
            && self.long_power > self.short_power
            && self.false_positive_rate <= 2.0 * crate::attack::rlcodec::SURVIVOR_ALPHA
    }
}

#[derive(Clone, Copy, Debug)]
struct TrialStats {
    carrier_len: usize,
    survivor: bool,
    z: f64,
    p: f64,
}

const ENGLISH_SAMPLE_TAG: u64 = 0xc0de_c001_e000_0001;
const CONTROL_SAMPLE_TAG: u64 = 0xc0de_c001_c000_0001;
const ENGLISH_GATE_TAG: u64 = 0xc0de_c001_e000_0101;
const CONTROL_GATE_TAG: u64 = 0xc0de_c001_c000_0101;

/// Measures detection power for the configured comma-code sweep.
///
/// # Errors
/// Returns [`RlError`] if a planted walk cannot be derived, a PRNG index draw
/// fails, the quadgram model cannot be built, or the matched-null gate fails.
pub fn measure_power(cfg: &PowerCfg) -> Result<PowerReport, RlError> {
    let model = QuadgramModel::english()?;
    let codec = RlCodec::Comma { sep: cfg.sep };
    let codec_name = codec.name();
    let codec_seed_tag = name_seed_tag(&codec_name);
    let source = source_letters(cfg);
    let mut english_rng = SplitMix64::new(mix_seed(cfg.gate.seed, ENGLISH_SAMPLE_TAG));
    let mut control_rng = SplitMix64::new(mix_seed(cfg.gate.seed, CONTROL_SAMPLE_TAG));

    let mut rows = Vec::new();
    let mut fp_detections = 0usize;
    let mut fp_trials = 0usize;
    for &length in &cfg.lengths {
        let mut english_trials = Vec::with_capacity(cfg.trials);
        let mut control_trials = Vec::with_capacity(cfg.trials);
        for trial in 0..cfg.trials {
            let english = sample_english_window(&source, length, &mut english_rng)?;
            let english_seed = trial_seed(cfg.gate.seed, length, trial, ENGLISH_GATE_TAG);
            english_trials.push(run_trial(
                &english,
                cfg,
                &codec,
                codec_seed_tag,
                &model,
                english_seed,
            )?);

            let control = sample_uniform_letters(length, &mut control_rng)?;
            let control_seed = trial_seed(cfg.gate.seed, length, trial, CONTROL_GATE_TAG);
            control_trials.push(run_trial(
                &control,
                cfg,
                &codec,
                codec_seed_tag,
                &model,
                control_seed,
            )?);
        }
        let row = summarise_row(length, &english_trials, &control_trials);
        fp_detections = fp_detections.saturating_add(row.control_detections);
        fp_trials = fp_trials.saturating_add(control_trials.len());
        rows.push(row);
    }

    let false_positive_rate = rate(fp_detections, fp_trials);
    let operating_point = closest_operating_point(&rows);
    let detectable_floor = rows
        .iter()
        .filter(|row| row.power >= cfg.power_threshold)
        .min_by_key(|row| row.length)
        .map(row_operating_point);

    Ok(PowerReport {
        codec_name,
        one_carrier_budget: ONE_CARRIER_BUDGET,
        rows,
        false_positive_detections: fp_detections,
        false_positive_trials: fp_trials,
        false_positive_rate,
        operating_point,
        detectable_floor,
        power_threshold: cfg.power_threshold,
    })
}

/// Runs the fast planted controls behind `codecpower --self-test`.
///
/// # Errors
/// Returns [`RlError`] if any planted trial or matched-null gate fails.
pub fn codecpower_self_test(seed: u64) -> Result<CodecpowerSelfTest, RlError> {
    let cfg = PowerCfg {
        source_letters: english_letters(PLANT_PLAINTEXT),
        lengths: vec![SELFTEST_SHORT_LENGTH, SELFTEST_LONG_LENGTH],
        trials: 2,
        sep: DEFAULT_COMMA_SEP,
        base: DEFAULT_PLANT_BASE,
        power_threshold: DEFAULT_POWER_THRESHOLD,
        gate: BatteryCfg {
            null_trials: 24,
            restarts: 12,
            iters: 3_000,
            top_k: 0,
            census_null_trials: 0,
            seed,
        },
    };
    let report = measure_power(&cfg)?;
    let short_power = row_power(&report, SELFTEST_SHORT_LENGTH);
    let long_power = row_power(&report, SELFTEST_LONG_LENGTH);
    Ok(CodecpowerSelfTest {
        short_power,
        long_power,
        false_positive_rate: report.false_positive_rate,
    })
}

fn source_letters(cfg: &PowerCfg) -> Vec<usize> {
    if cfg.source_letters.is_empty() {
        english_letters(PLANT_PLAINTEXT)
    } else {
        cfg.source_letters.clone()
    }
}

fn sample_english_window(
    source: &[usize],
    length: usize,
    rng: &mut SplitMix64,
) -> Result<Vec<usize>, RlError> {
    if length == 0 {
        return Ok(Vec::new());
    }
    if source.is_empty() {
        return Ok(Vec::new());
    }
    if source.len() >= length {
        let starts = source.len() - length + 1;
        let start = random_index_below(starts, rng)?;
        return Ok(source.iter().skip(start).take(length).copied().collect());
    }
    let start = random_index_below(source.len(), rng)?;
    Ok((0..length)
        .map(|offset| {
            source
                .get((start + offset) % source.len())
                .copied()
                .unwrap_or(0)
        })
        .collect())
}

fn sample_uniform_letters(length: usize, rng: &mut SplitMix64) -> Result<Vec<usize>, RlError> {
    let mut letters = Vec::with_capacity(length);
    for _ in 0..length {
        letters.push(random_index_below(26, rng)?);
    }
    Ok(letters)
}

fn run_trial(
    letters: &[usize],
    cfg: &PowerCfg,
    codec: &RlCodec,
    codec_seed_tag: u64,
    model: &QuadgramModel,
    seed: u64,
) -> Result<TrialStats, RlError> {
    let digits = encode_comma(letters, cfg.sep, cfg.base);
    let derivation = derive_magnitudes(&digits, cfg.base)?;
    let carrier_len = derivation.magnitudes.len();
    let Some(symbols) = codec.decode(&derivation.magnitudes) else {
        return Ok(TrialStats {
            carrier_len,
            survivor: false,
            z: 0.0,
            p: 1.0,
        });
    };
    let gate_cfg = BatteryCfg { seed, ..cfg.gate };
    let verdict = gate_symbol_stream(codec.name(), &symbols, codec_seed_tag, model, &gate_cfg)?;
    Ok(stats_from_verdict(carrier_len, &verdict))
}

fn stats_from_verdict(carrier_len: usize, verdict: &CodecVerdict) -> TrialStats {
    TrialStats {
        carrier_len,
        survivor: verdict.survivor,
        z: verdict.z,
        p: verdict.p,
    }
}

fn summarise_row(length: usize, english: &[TrialStats], control: &[TrialStats]) -> PowerRow {
    let detections = english.iter().filter(|trial| trial.survivor).count();
    let control_detections = control.iter().filter(|trial| trial.survivor).count();
    PowerRow {
        length,
        trials: english.len(),
        mean_carrier: mean_carrier(english),
        detections,
        power: rate(detections, english.len()),
        mean_z: mean_by(english, |trial| trial.z),
        mean_p: mean_by(english, |trial| trial.p),
        control_detections,
        control_rate: rate(control_detections, control.len()),
    }
}

fn mean_carrier(trials: &[TrialStats]) -> f64 {
    if trials.is_empty() {
        return 0.0;
    }
    trials
        .iter()
        .map(|trial| trial.carrier_len as f64)
        .sum::<f64>()
        / trials.len() as f64
}

fn mean_by(trials: &[TrialStats], value: impl Fn(&TrialStats) -> f64) -> f64 {
    if trials.is_empty() {
        return 0.0;
    }
    trials.iter().map(value).sum::<f64>() / trials.len() as f64
}

fn rate(count: usize, trials: usize) -> f64 {
    if trials == 0 {
        0.0
    } else {
        count as f64 / trials as f64
    }
}

fn row_power(report: &PowerReport, length: usize) -> f64 {
    report
        .rows
        .iter()
        .find(|row| row.length == length)
        .map_or(0.0, |row| row.power)
}

fn closest_operating_point(rows: &[PowerRow]) -> Option<OperatingPoint> {
    rows.iter()
        .min_by(|left, right| {
            let left_distance = (left.mean_carrier - ONE_CARRIER_BUDGET as f64).abs();
            let right_distance = (right.mean_carrier - ONE_CARRIER_BUDGET as f64).abs();
            left_distance.total_cmp(&right_distance)
        })
        .map(row_operating_point)
}

fn row_operating_point(row: &PowerRow) -> OperatingPoint {
    OperatingPoint {
        length: row.length,
        mean_carrier: row.mean_carrier,
        power: row.power,
    }
}

fn trial_seed(seed: u64, length: usize, trial: usize, tag: u64) -> u64 {
    let length_tag = u64::try_from(length)
        .unwrap_or(u64::MAX)
        .wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let trial_tag = u64::try_from(trial)
        .unwrap_or(u64::MAX)
        .wrapping_mul(0xbf58_476d_1ce4_e5b9);
    mix_seed(seed, tag ^ length_tag ^ trial_tag)
}

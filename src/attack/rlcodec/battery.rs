//! The battery: per-codec matched-null gating and the whole-run report.
//!
//! ## Why the codec null is a symbol-stream Markov resample
//!
//! Each codec is gated against an **order-1 Markov resample of its *decoded
//! symbol stream*** ([`markov_resample`]), not a magnitude-level resample. This is
//! the standard "is this monoalphabetic-substitution text English?" control,
//! tightened to the right reference: it holds the decoded alphabet size, length,
//! and *symbol-bigram* structure fixed while destroying only the higher-order
//! structure a genuine plaintext carries. The null is then run through the *same*
//! substitution search, and a codec survives only if its real best score beats it.
//!
//! Nulling at the symbol level (rather than resampling/shuffling the magnitudes)
//! is load-bearing. The carrier `M` has a census-significant exact repeat; a
//! variable-length codec faithfully transmits it as a repeated symbol substring,
//! which free substitution maps to a common English string (e.g. `INTHE…INTHE`).
//! Any null that resamples or shuffles the *magnitudes* destroys that repeat (and
//! drifts the decoded alphabet), so real `one` beats it with a spurious
//! `z ≈ 2–4` — re-detecting the census repeat, **not** finding English. The
//! symbol-stream Markov resample preserves the repeat's bigram contribution, so
//! real `one` no longer beats it (`z ≲ 0`, the honest negative), while a long,
//! low-freedom genuine-English plant still wins on its quadgram structure (the
//! self-test positive control). The census keeps the magnitude-level Markov null,
//! where preserving the transition law is the right reference for repeat-length
//! significance.

use crate::analysis::translate_isomorph::markov_resample;
use crate::attack::quadgram::QuadgramModel;
use crate::core::glyph::Glyph;
use crate::nulls::null::{SplitMix64, add_one_p_value, mix_seed};

use super::census::{CensusReport, magnitude_census};
use super::codecs::{RlCodec, all_codecs, alphabet_size};
use super::derive::{RunLengthDerivation, derive_magnitudes};
use super::search::{SubResult, substitution_search};
use super::{
    BatteryCfg, DEFAULT_CENSUS_NULL_TRIALS, DEFAULT_ITERS, DEFAULT_NULL_TRIALS, DEFAULT_RESTARTS,
    DEFAULT_SEED, DEFAULT_TOP_K, RlError, SURVIVOR_ALPHA,
};

/// Smallest standard deviation treated as non-degenerate when forming the z-score.
const SIGMA_FLOOR: f64 = 1e-9;
/// Seed tag separating the census null stream from the codec streams.
const CENSUS_TAG: u64 = 0x0ce0_5005_0000_0001;
/// Seed tag for a codec's real (non-null) search.
const REAL_TAG: u64 = 0x5ea1_0000_0000_0000;
/// Seed tag for a codec's matched-null loop.
const NULL_TAG: u64 = 0x0011_0000_0000_0000;

/// The default CLI report budget (larger than the test/self-test budgets).
#[must_use]
pub fn default_battery_cfg() -> BatteryCfg {
    BatteryCfg {
        null_trials: DEFAULT_NULL_TRIALS,
        restarts: DEFAULT_RESTARTS,
        iters: DEFAULT_ITERS,
        top_k: DEFAULT_TOP_K,
        census_null_trials: DEFAULT_CENSUS_NULL_TRIALS,
        seed: DEFAULT_SEED,
    }
}

/// A summary of the magnitude derivation for the report header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivationSummary {
    /// Number of input digits.
    pub n_digits: usize,
    /// The base the walk lives on.
    pub base: usize,
    /// Number of `±1` move bits.
    pub n_bits: usize,
    /// Number of up (`+1`) moves.
    pub n_up: usize,
    /// Number of down (`-1`) moves.
    pub n_down: usize,
    /// Number of run-length magnitudes (`|M|`).
    pub n_magnitudes: usize,
    /// Magnitude distribution as `(value, count)` pairs, sorted by value.
    pub distribution: Vec<(usize, usize)>,
}

/// One codec's verdict: its best real score, the matched-null calibration, and
/// the survivor gate.
#[derive(Clone, Debug, PartialEq)]
pub struct CodecVerdict {
    /// Codec display name.
    pub codec_name: String,
    /// Number of decoded symbols (letters scored).
    pub n_letters: usize,
    /// Decoded alphabet size (distinct symbols).
    pub alphabet: usize,
    /// Best real mean quadgram score (`NEG_INFINITY` if not evaluated).
    pub real_mean: f64,
    /// Mean of the matched-null best scores.
    pub null_mean: f64,
    /// Maximum matched-null best score.
    pub null_max: f64,
    /// z-score of the real score against the matched-null distribution.
    pub z: f64,
    /// Add-one p-value: fraction of nulls scoring at least the real score.
    pub p: f64,
    /// Whether the codec beats its matched null (`z > 0` and `p < 0.05`).
    pub survivor: bool,
    /// The rendered best-scoring plaintext (always kept — read it, not just the
    /// gate).
    pub text: String,
    /// `false` when the codec was degenerate / skipped (no gate was applied).
    pub evaluated: bool,
}

impl CodecVerdict {
    /// Builds a non-evaluated verdict carrying a short reason in `text`.
    fn degenerate(name: String, n_letters: usize, alphabet: usize, reason: String) -> Self {
        Self {
            codec_name: name,
            n_letters,
            alphabet,
            real_mean: f64::NEG_INFINITY,
            null_mean: f64::NEG_INFINITY,
            null_max: f64::NEG_INFINITY,
            z: 0.0,
            p: 1.0,
            survivor: false,
            text: reason,
            evaluated: false,
        }
    }
}

/// The whole battery run: derivation header, census, per-codec verdicts, and the
/// honest overall verdict.
#[derive(Clone, Debug, PartialEq)]
pub struct BatteryReport {
    /// Magnitude-derivation summary.
    pub derivation: DerivationSummary,
    /// Magnitude census (repeat structure + matched null).
    pub census: CensusReport,
    /// Per-codec verdicts, in the fixed [`all_codecs`] order.
    pub verdicts: Vec<CodecVerdict>,
    /// Whether any codec survived its matched null (expected `false` on real
    /// `one`: the honest negative).
    pub overall_survivor: bool,
}

/// Mean, population standard deviation, and maximum of a non-empty slice.
fn mean_std_max(values: &[f64]) -> (f64, f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0, 0.0);
    }
    let count = values.len() as f64;
    let mean = values.iter().sum::<f64>() / count;
    let variance = values
        .iter()
        .map(|value| (value - mean) * (value - mean))
        .sum::<f64>()
        / count;
    let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    (mean, variance.sqrt(), max)
}

/// Evaluates one codec: decode → substitution search, calibrated against the same
/// search run on order-1 Markov resamples of the *decoded symbol stream* (see the
/// module note for why the symbol-level null, not a magnitude-level one, gates the
/// codecs).
///
/// The verdict is a survivor only when the real score beats the matched null
/// (`z > 0` and `p < 0.05`). Deterministic-map codecs are nulled identically for
/// a uniform verdict.
///
/// # Errors
/// Returns [`RlError`] if a Markov resample or substitution search fails.
pub fn evaluate_codec(
    magnitudes: &[usize],
    codec: &RlCodec,
    model: &QuadgramModel,
    cfg: &BatteryCfg,
) -> Result<CodecVerdict, RlError> {
    let name = codec.name();
    let Some(real_symbols) = codec.decode(magnitudes) else {
        return Ok(CodecVerdict::degenerate(
            name,
            0,
            0,
            "(degenerate: no symbol stream)".to_owned(),
        ));
    };
    let n_alphabet = alphabet_size(&real_symbols);
    let n_letters = real_symbols.len();

    let real_seed = mix_seed(cfg.seed, codec.seed_tag() ^ REAL_TAG);
    let real = substitution_search(
        &real_symbols,
        n_alphabet,
        model,
        cfg.restarts,
        cfg.iters,
        real_seed,
    )?;
    if real.skipped {
        return Ok(CodecVerdict::degenerate(
            name,
            n_letters,
            n_alphabet,
            format!("(skipped: {n_letters} symbols over {n_alphabet}-symbol alphabet)"),
        ));
    }

    let null_seed = mix_seed(cfg.seed, codec.seed_tag() ^ NULL_TAG);
    let mut rng = SplitMix64::new(null_seed);
    let real_stream: Vec<u32> = real_symbols.iter().map(|&symbol| symbol as u32).collect();
    let mut null_scores: Vec<f64> = Vec::new();
    for trial in 0..cfg.null_trials {
        let resampled = markov_resample(&real_stream, n_alphabet, &mut rng)?;
        let null_symbols: Vec<usize> = resampled.iter().map(|&value| value as usize).collect();
        let null_alphabet = alphabet_size(&null_symbols);
        let trial_seed = mix_seed(null_seed, trial as u64);
        let null = substitution_search(
            &null_symbols,
            null_alphabet,
            model,
            cfg.restarts,
            cfg.iters,
            trial_seed,
        )?;
        if !null.skipped {
            null_scores.push(null.best_mean);
        }
    }

    Ok(finalise_verdict(
        name,
        n_letters,
        n_alphabet,
        &real,
        &null_scores,
    ))
}

/// Forms the gated verdict from the real result and the collected null scores.
fn finalise_verdict(
    name: String,
    n_letters: usize,
    n_alphabet: usize,
    real: &SubResult,
    null_scores: &[f64],
) -> CodecVerdict {
    if null_scores.is_empty() {
        return CodecVerdict::degenerate(
            name,
            n_letters,
            n_alphabet,
            "(degenerate: no valid matched-null trials)".to_owned(),
        );
    }
    let (null_mean, null_std, null_max) = mean_std_max(null_scores);
    let reached = null_scores
        .iter()
        .filter(|&&score| score >= real.best_mean)
        .count();
    let p = add_one_p_value(reached, null_scores.len());
    // Gate the survivor on whether the real score beats the null *mean* and clears
    // the add-one p-value — NOT on the displayed z. A (near-)deterministic null
    // collapses `null_std` to ~0; tying the verdict to `z > 0` there would force a
    // false negative even when the real score strictly beats the null and
    // `p < SURVIVOR_ALPHA`. z is reported as `+inf` in that zero-variance-but-beaten
    // case (honestly: unboundedly many sigma above a constant null) and finite
    // otherwise.
    let beats_null = real.best_mean > null_mean;
    let z = if null_std > SIGMA_FLOOR {
        (real.best_mean - null_mean) / null_std
    } else if beats_null {
        f64::INFINITY
    } else {
        0.0
    };
    let survivor = beats_null && p < SURVIVOR_ALPHA;
    CodecVerdict {
        codec_name: name,
        n_letters,
        alphabet: n_alphabet,
        real_mean: real.best_mean,
        null_mean,
        null_max,
        z,
        p,
        survivor,
        text: real.text.clone(),
        evaluated: true,
    }
}

/// Runs the whole battery: derive `M`, census it, evaluate every codec in the
/// fixed order, and report the honest overall verdict.
///
/// # Errors
/// Returns [`RlError`] if the input is not a clean `±1` walk, if the English
/// quadgram model fails to build, or if a matched null / search fails.
pub fn run_battery(
    digits: &[Glyph],
    base: usize,
    cfg: &BatteryCfg,
) -> Result<BatteryReport, RlError> {
    let derivation = derive_magnitudes(digits, base)?;
    if derivation.magnitudes.is_empty() {
        return Err(RlError::EmptyMagnitudes);
    }
    let model = QuadgramModel::english()?;
    let census = magnitude_census(
        &derivation.magnitudes,
        cfg.top_k,
        cfg.census_null_trials,
        mix_seed(cfg.seed, CENSUS_TAG),
    )?;

    let mut verdicts = Vec::new();
    for codec in all_codecs() {
        verdicts.push(evaluate_codec(&derivation.magnitudes, &codec, &model, cfg)?);
    }
    let overall_survivor = verdicts.iter().any(|verdict| verdict.survivor);

    Ok(BatteryReport {
        derivation: summarise(digits.len(), base, &derivation),
        census,
        verdicts,
        overall_survivor,
    })
}

/// Builds the derivation header summary.
fn summarise(n_digits: usize, base: usize, derivation: &RunLengthDerivation) -> DerivationSummary {
    let mut counts: std::collections::BTreeMap<usize, usize> = std::collections::BTreeMap::new();
    for &magnitude in &derivation.magnitudes {
        *counts.entry(magnitude).or_insert(0) += 1;
    }
    DerivationSummary {
        n_digits,
        base,
        n_bits: derivation.n_bits,
        n_up: derivation.n_up,
        n_down: derivation.n_down,
        n_magnitudes: derivation.magnitudes.len(),
        distribution: counts.into_iter().collect(),
    }
}

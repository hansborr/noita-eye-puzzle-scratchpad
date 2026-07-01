//! In-process self-test for the bigram-order codec gate.

use crate::attack::rlcodec::one_practice_digits;

use super::{
    BIGRAM_PLANT_STREAM, BigramCfg, BigramError, BigramLanguage, READABLE_MIN, StreamKind,
    analyze_bigramcodec, planted_magpair_walk,
};

const POSITIVE_NULL_TRIALS: usize = 24;
const POSITIVE_RESTARTS: usize = 12;
const POSITIVE_ITERS: usize = 1_800;
const NEGATIVE_NULL_TRIALS: usize = 20;
const NEGATIVE_RESTARTS: usize = 4;
const NEGATIVE_ITERS: usize = 500;

/// Outcome of the `bigramcodec --self-test` controls.
#[derive(Clone, Debug, PartialEq)]
pub struct BigramSelfTestReport {
    /// Readability crib-word coverage for the planted positive control.
    pub positive_readability_coverage: usize,
    /// Whether the planted positive control beat the order-0 null.
    pub positive_beats_order0: bool,
    /// The planted English positive's order-1 z-score.
    ///
    /// This is expected not to clear because the objective is a bigram score and
    /// the order-1 null preserves the transition matrix that objective sees.
    pub positive_order1_z: f64,
    /// The planted English positive's add-one p-value versus order-1.
    pub positive_order1_p: f64,
    /// Whether the planted English positive beat the order-1 null.
    pub positive_beats_order1: bool,
    /// Maximum readability crib-word coverage observed across real `one` rows.
    pub negative_max_readability_coverage: usize,
}

impl BigramSelfTestReport {
    /// `true` iff the positive is readable, beats order-0, demonstrates that the
    /// order-1 gate does not clear on genuine English, and real `one` is not
    /// readable under the same heuristic.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.positive_readability_coverage >= READABLE_MIN
            && self.positive_beats_order0
            && self.positive_order1_z.is_finite()
            && self.positive_order1_p.is_finite()
            && !self.positive_beats_order1
            && self.negative_max_readability_coverage < READABLE_MIN
    }
}

/// Runs the planted positive control and the real-`one` negative control.
///
/// # Errors
/// Returns [`BigramError`] if either control fails to run.
pub fn bigramcodec_self_test(seed: u64) -> Result<BigramSelfTestReport, BigramError> {
    let positive_cfg = BigramCfg {
        null_trials: POSITIVE_NULL_TRIALS,
        restarts: POSITIVE_RESTARTS,
        iters: POSITIVE_ITERS,
        seed,
    };
    let plant_digits = planted_magpair_walk();
    let positive = analyze_bigramcodec(&plant_digits, 5, &[BIGRAM_PLANT_STREAM], &positive_cfg)?;
    let positive_row = positive
        .streams
        .iter()
        .find(|stream| stream.stream.kind == BIGRAM_PLANT_STREAM)
        .and_then(|stream| {
            stream
                .languages
                .iter()
                .find(|row| row.language == BigramLanguage::English)
        });
    let positive_readability_coverage = positive_row.map_or(0, |row| row.readability_coverage);
    let positive_beats_order0 = positive_row
        .and_then(|row| row.order0.as_ref())
        .is_some_and(|null| null.beats);
    let positive_order1_z = positive_row
        .and_then(|row| row.order1.as_ref())
        .map_or(f64::NAN, |null| null.z);
    let positive_order1_p = positive_row
        .and_then(|row| row.order1.as_ref())
        .map_or(f64::NAN, |null| null.p);
    let positive_beats_order1 = positive_row
        .and_then(|row| row.order1.as_ref())
        .is_some_and(|null| null.beats);

    let negative_cfg = BigramCfg {
        null_trials: NEGATIVE_NULL_TRIALS,
        restarts: NEGATIVE_RESTARTS,
        iters: NEGATIVE_ITERS,
        seed: seed ^ 0x6269_6772_5e1f_7e57,
    };
    let one_digits = one_practice_digits()?;
    let negative = analyze_bigramcodec(
        &one_digits,
        5,
        &[
            StreamKind::DigitPairs,
            StreamKind::Edges,
            StreamKind::MagPairs,
        ],
        &negative_cfg,
    )?;
    let negative_max_readability_coverage = negative.streams.iter().fold(0, |max, stream| {
        stream
            .languages
            .iter()
            .map(|row| row.readability_coverage)
            .max()
            .map_or(max, |coverage| max.max(coverage))
    });

    Ok(BigramSelfTestReport {
        positive_readability_coverage,
        positive_beats_order0,
        positive_order1_z,
        positive_order1_p,
        positive_beats_order1,
        negative_max_readability_coverage,
    })
}

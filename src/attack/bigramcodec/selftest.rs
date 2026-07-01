//! In-process self-test for the bigram-order codec gate.

use crate::attack::rlcodec::one_practice_digits;

use super::{
    BIGRAM_PLANT_STREAM, BigramCfg, BigramError, BigramLanguage, HonestVerdict, StreamKind,
    analyze_bigramcodec, planted_magpair_walk,
};

const POSITIVE_NULL_TRIALS: usize = 24;
const POSITIVE_RESTARTS: usize = 12;
const POSITIVE_ITERS: usize = 1_800;
const NEGATIVE_NULL_TRIALS: usize = 20;
const NEGATIVE_RESTARTS: usize = 4;
const NEGATIVE_ITERS: usize = 500;

/// Outcome of the `bigramcodec --self-test` controls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BigramSelfTestReport {
    /// Whether the planted positive control recovered the expected crib text.
    pub positive_readable: bool,
    /// Whether the planted positive control beat the order-0 null.
    pub positive_beats_order0: bool,
    /// Whether real practice puzzle `one` produced any order-1 candidate.
    pub negative_has_candidate: bool,
}

impl BigramSelfTestReport {
    /// `true` iff the positive fires and the real-`one` negative stays below the
    /// order-1 candidate gate.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.positive_readable && self.positive_beats_order0 && !self.negative_has_candidate
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
    let positive_text = positive_row.map_or("", |row| row.real.text.as_str());
    let positive_readable = positive_text.contains("THERAIN") || positive_text.contains("THEWIND");
    let positive_beats_order0 = positive_row
        .and_then(|row| row.order0.as_ref())
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
    let negative_has_candidate = negative.streams.iter().any(|stream| {
        stream
            .languages
            .iter()
            .any(|row| row.verdict == HonestVerdict::Candidate)
    });

    Ok(BigramSelfTestReport {
        positive_readable,
        positive_beats_order0,
        negative_has_candidate,
    })
}

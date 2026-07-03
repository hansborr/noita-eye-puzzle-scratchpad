//! Structured-coloring self-test leg for `pairclass --self-test`.

use super::campaign::{PowerCfg, StreamPrep};
use super::lexicon::{build_lexicon, parse_wordlist};
use super::structured::{
    StructuredFamilyProfile, StructuredNegativeReport, StructuredNullCfg, StructuredNullGate,
    StructuredPowerReport, StructuredRunCfg, structured_null_gate,
};
use super::{
    PairclassError, SolveCfg, measure_structured_power, measure_structured_random_negative,
};

const STRUCTURED_SENTENCE: &str = "cat dog cat dog";
const STRUCTURED_WORDLIST: &str = "cat 100\ndog 90\nact 3\ntag 2\ncot 1\n";
const STRUCTURED_LEN: usize = 12;

/// The structured-coloring Avenue-A self-test leg.
#[derive(Clone, Debug)]
pub struct StructuredLeg {
    /// Structured planted-positive report.
    pub positive: StructuredPowerReport,
    /// Random-coloring negative report.
    pub negative: StructuredNegativeReport,
    /// Matched Markov null report.
    pub null: StructuredNullGate,
}

impl StructuredLeg {
    /// Passed: the positive fires and both negatives stay quiet.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.positive.cleared_bar && self.negative.quiet && self.null.null_ge_floor == 0
    }
}

pub(super) fn run_structured_leg(seed: u64) -> Result<StructuredLeg, PairclassError> {
    let word_entries = parse_wordlist(STRUCTURED_WORDLIST, usize::MAX);
    let lexicon = build_lexicon(&word_entries)?;
    let run_cfg = StructuredRunCfg {
        profile: StructuredFamilyProfile::Toy,
        max_decodes: 24,
        rank_beam: 32,
        marginal_l1: 2.0,
        score_margin: 0.0,
    };
    let solve_cfg = SolveCfg {
        beam: 128,
        max_gaps: 0,
        max_gap_len: 0,
        top: 3,
        ..SolveCfg::default()
    };
    let power = PowerCfg {
        n_plants: 1,
        plant_len: STRUCTURED_LEN,
        n_classes: 4,
        longest_tie: None,
        bar: 0.8,
        seed,
    };
    let positive = measure_structured_power(
        STRUCTURED_SENTENCE,
        &power,
        &word_entries,
        &lexicon,
        &solve_cfg,
        &run_cfg,
    )?;
    let negative = measure_structured_random_negative(
        STRUCTURED_SENTENCE,
        &power,
        &word_entries,
        &lexicon,
        &solve_cfg,
        &run_cfg,
        positive.score_floor,
    )?;
    let tokens: Vec<u8> = "catdogcatdog"
        .bytes()
        .filter(u8::is_ascii_lowercase)
        .map(|byte| (byte - b'a') % 4)
        .collect();
    let prep = StreamPrep {
        tokens,
        n_classes: 4,
        tie_table: Vec::new(),
        n_tied: 0,
        longest_tie: None,
    };
    let null = structured_null_gate(
        &prep,
        &word_entries,
        &lexicon,
        &solve_cfg,
        &run_cfg,
        &StructuredNullCfg {
            null_trials: 2,
            real_best: None,
            score_floor: positive.score_floor,
            seed,
        },
    )?;
    Ok(StructuredLeg {
        positive,
        negative,
        null,
    })
}

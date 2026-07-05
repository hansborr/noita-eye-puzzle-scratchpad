//! In-process controls for the crib-free shadow finish.

use crate::attack::quadgram::QuadgramModel;

use super::artifact::{canonical_from_plaintext, encode_with_key};
use super::engine::{TruthProbe, run_ladder_with_probe};
use super::scoring::{WordSegModel, combined_score, score_anchor_words, score_quadgrams};
use super::tables::builtin_tables;
use super::{
    DigitOrder, ShadowFinishArtifact, ShadowFinishConfig, ShadowFinishError, ShadowFinishTable,
    ShadowFinishVerdict,
};

const CONTROL_NULL_TRIALS: usize = 3;
const CONTROL_TOP_K: usize = 256;
const CONTROL_ALPHA: f64 = 0.50;
const CONTROL_LEN: usize = 349;

/// Outcome of `shadowfinish --self-test`.
#[derive(Clone, Debug, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "self-test report DTO: each bool is an independent control leg surfaced by the CLI"
)]
pub struct ShadowFinishSelfTest {
    /// The planted plaintext survived Tier A and exact round-trip.
    pub positive_roundtrip: bool,
    /// Planted truth Tier-A rank across the full enumeration surface.
    pub positive_truth_rank: Option<usize>,
    /// The planted truth was inside the configured per-class top-K.
    pub positive_truth_top_k: bool,
    /// Planted best score minus the matched-null maximum.
    pub positive_margin_vs_junk_max: f64,
    /// The mutated wrong plaintext does not round-trip to the plant ciphertext.
    pub wrong_plaintext_no_roundtrip: bool,
    /// The wrong plaintext's score sits inside the junk distribution.
    pub wrong_plaintext_inside_junk: bool,
    /// Overall self-test verdict.
    pub passed: bool,
}

/// Runs the planted positive, matched junk negative, and breadth controls.
///
/// # Errors
/// Returns [`ShadowFinishError`] if a control fixture cannot be built or the
/// production finish ladder fails.
pub fn shadow_finish_self_test(seed: u64) -> Result<ShadowFinishSelfTest, ShadowFinishError> {
    let tables = builtin_tables()?;
    run_control(seed, &tables, CONTROL_TOP_K, CONTROL_NULL_TRIALS)
}

#[cfg(test)]
pub(super) fn shadow_finish_self_test_fast_for_test(
    seed: u64,
) -> Result<ShadowFinishSelfTest, ShadowFinishError> {
    let tables = builtin_tables()?
        .into_iter()
        .filter(|table| table.name == "sixbit-lower-space")
        .collect::<Vec<_>>();
    run_control(seed, &tables, 64, 1)
}

fn run_control(
    seed: u64,
    tables: &[ShadowFinishTable],
    top_k: usize,
    null_trials: usize,
) -> Result<ShadowFinishSelfTest, ShadowFinishError> {
    let fixture = Fixture::new(seed)?;
    let artifact = ShadowFinishArtifact::parse(&fixture.artifact_json)?;
    let prepared = artifact.prepare_classes(&fixture.ciphertext)?;
    let word_model = WordSegModel::from_wordlist(&fixture.wordlist, usize::MAX)?;
    let quadgram = QuadgramModel::english()?;
    let mut config = ShadowFinishConfig {
        top_k_per_class: top_k,
        null_trials,
        alpha: CONTROL_ALPHA,
        seed,
        ..ShadowFinishConfig::default()
    };
    config.include_phase1 = false;
    let truth = TruthProbe {
        plaintext: &fixture.plaintext,
    };
    let outcome = run_ladder_with_probe(
        &artifact,
        &prepared,
        &fixture.ciphertext,
        tables,
        &word_model,
        &quadgram,
        &config,
        Some(&truth),
    )?;
    let positive_roundtrip = outcome
        .report
        .top_candidates
        .iter()
        .any(|candidate| candidate.plaintext == fixture.plaintext && candidate.roundtrip)
        && outcome.report.verdict == ShadowFinishVerdict::RoundTripDecode;
    let positive_truth_top_k = outcome.truth_tier_a_rank.is_some_and(|rank| rank <= top_k);
    let positive_margin_vs_junk_max = outcome.report.calibration.margin_vs_null_max;
    let wrong_plaintext_no_roundtrip = fixture.wrong_plaintext_no_roundtrip(tables)?;
    let wrong_score = score_plaintext(
        &fixture.wrong_plaintext,
        &word_model,
        &quadgram,
        &artifact.hard_anchors,
    );
    let wrong_plaintext_inside_junk = outcome
        .report
        .calibration
        .samples
        .iter()
        .any(|&sample| sample >= wrong_score);
    let passed = positive_roundtrip
        && positive_truth_top_k
        && positive_margin_vs_junk_max > 0.0
        && wrong_plaintext_no_roundtrip
        && wrong_plaintext_inside_junk;
    Ok(ShadowFinishSelfTest {
        positive_roundtrip,
        positive_truth_rank: outcome.truth_tier_a_rank,
        positive_truth_top_k,
        positive_margin_vs_junk_max,
        wrong_plaintext_no_roundtrip,
        wrong_plaintext_inside_junk,
        passed,
    })
}

#[derive(Clone, Debug)]
struct Fixture {
    artifact_json: String,
    ciphertext: Vec<u16>,
    plaintext: Vec<u8>,
    wrong_plaintext: Vec<u8>,
    wordlist: String,
    permutation: [u8; 8],
}

impl Fixture {
    fn new(seed: u64) -> Result<Self, ShadowFinishError> {
        let tables = builtin_tables()?;
        let table = tables
            .iter()
            .find(|table| table.name == "sixbit-lower-space")
            .ok_or_else(|| {
                ShadowFinishError::Table("missing sixbit-lower-space control table".to_owned())
            })?;
        let plaintext = plant_plaintext();
        let permutation = if seed.is_multiple_of(2) {
            [3, 1, 4, 0, 7, 2, 6, 5]
        } else {
            [5, 2, 7, 1, 6, 0, 4, 3]
        };
        let q_pattern =
            canonical_from_plaintext(&plaintext, table, DigitOrder::HighLow, permutation)?;
        let key = control_key();
        let legal_readouts = (0..8).collect::<Vec<_>>();
        let ciphertext = encode_with_key(&q_pattern, 8, &legal_readouts, &key)?;
        let artifact_json = artifact_json(&q_pattern, &key, ciphertext.len());
        let wrong_plaintext = wrong_plaintext();
        Ok(Self {
            artifact_json,
            ciphertext,
            plaintext,
            wrong_plaintext,
            wordlist: control_wordlist(),
            permutation,
        })
    }

    fn wrong_plaintext_no_roundtrip(
        &self,
        tables: &[ShadowFinishTable],
    ) -> Result<bool, ShadowFinishError> {
        let table = tables
            .iter()
            .find(|table| table.name == "sixbit-lower-space")
            .ok_or_else(|| {
                ShadowFinishError::Table("missing sixbit-lower-space control table".to_owned())
            })?;
        let q_pattern = canonical_from_plaintext(
            &self.wrong_plaintext,
            table,
            DigitOrder::HighLow,
            self.permutation,
        )?;
        let rendered = encode_with_key(&q_pattern, 8, &(0..8).collect::<Vec<_>>(), &control_key())?;
        Ok(rendered != self.ciphertext)
    }
}

fn score_plaintext(
    plaintext: &[u8],
    word_model: &WordSegModel,
    quadgram: &QuadgramModel,
    anchors: &[crate::analysis::shadow_search::Anchor],
) -> f64 {
    let quad = score_quadgrams(quadgram, plaintext);
    let word = word_model.score_text(plaintext);
    let anchor = score_anchor_words(word_model, plaintext, anchors);
    combined_score(quad, word, anchor)
}

fn plant_plaintext() -> Vec<u8> {
    let phrase = b"the hidden state search can finish without a crib when repeated spans carry clear english words ";
    let mut out = Vec::with_capacity(CONTROL_LEN);
    while out.len() < CONTROL_LEN {
        out.extend_from_slice(phrase);
    }
    out.truncate(CONTROL_LEN);
    out
}

fn wrong_plaintext() -> Vec<u8> {
    let phrase = b"zqxv jqxz vqzx xzqv jqxz ";
    let mut out = Vec::with_capacity(CONTROL_LEN);
    while out.len() < CONTROL_LEN {
        out.extend_from_slice(phrase);
    }
    out.truncate(CONTROL_LEN);
    out
}

fn control_wordlist() -> String {
    [
        ("the", 1000),
        ("hidden", 900),
        ("state", 850),
        ("search", 800),
        ("can", 750),
        ("finish", 700),
        ("without", 650),
        ("a", 640),
        ("crib", 630),
        ("when", 620),
        ("repeated", 610),
        ("spans", 600),
        ("carry", 590),
        ("clear", 580),
        ("english", 570),
        ("words", 560),
    ]
    .iter()
    .map(|(word, count)| format!("{word} {count}"))
    .collect::<Vec<_>>()
    .join("\n")
}

fn control_key() -> crate::analysis::shadow_search::RepresentativeKey {
    crate::analysis::shadow_search::RepresentativeKey {
        initial_state_index: 0,
        initial_state: (0..8).collect(),
        choices: (0..8)
            .map(|readout| crate::analysis::shadow_search::KeyChoice {
                readout,
                fiber_choice: 0,
                element_index: readout,
                element: (0..8).map(|value| (value + readout) % 8).collect(),
            })
            .collect(),
    }
}

fn artifact_json(
    q_pattern: &[u16],
    key: &crate::analysis::shadow_search::RepresentativeKey,
    input_len: usize,
) -> String {
    format!(
        "{{\"tool\":\"shadowsearch\",\"input_len\":{},\"alphabet_size\":8,\
         \"basis\":{{\"legal_readouts\":[0,1,2,3,4,5,6,7]}},\
         \"hard_anchors\":[{}],\"outcome\":{{\"top_canonical_classes\":[{}]}}}}",
        input_len,
        anchor_json(24, 120, 64),
        class_json(q_pattern, key)
    )
}

fn class_json(
    q_pattern: &[u16],
    key: &crate::analysis::shadow_search::RepresentativeKey,
) -> String {
    format!(
        "{{\"soft_score\":1,\"sequence_count\":1,\"key_multiplicity\":1,\
         \"canonical_pattern\":{},\"representative_key\":{}}}",
        u16_json(q_pattern),
        key_json(key)
    )
}

fn key_json(key: &crate::analysis::shadow_search::RepresentativeKey) -> String {
    let choices = key
        .choices
        .iter()
        .map(|choice| {
            format!(
                "{{\"readout\":{},\"fiber_choice\":{},\"element_index\":{},\"element\":{}}}",
                choice.readout,
                choice.fiber_choice,
                choice.element_index,
                usize_json(&choice.element)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"initial_state_index\":{},\"initial_state\":{},\"choices\":[{}]}}",
        key.initial_state_index,
        usize_json(&key.initial_state),
        choices
    )
}

fn anchor_json(first: usize, second: usize, length: usize) -> String {
    format!(
        "{{\"first\":{first},\"second\":{second},\"length\":{length},\
         \"raw_first\":{first},\"raw_second\":{second},\"raw_length\":{length},\"trim\":0}}"
    )
}

fn usize_json(values: &[usize]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn u16_json(values: &[u16]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}

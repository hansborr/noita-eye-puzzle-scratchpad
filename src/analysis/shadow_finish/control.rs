//! In-process controls for the crib-free shadow finish.

use crate::attack::quadgram::QuadgramModel;

use super::artifact::{canonical_from_plaintext, encode_with_key};
use super::engine::{TruthProbe, run_ladder_with_probe};
use super::pairs::decode_pattern;
use super::scoring::{
    WordSegModel, combined_score, score_anchor_words, score_byte_coverage, score_quadgrams,
};
use super::tables::builtin_tables;
use super::{
    DigitOrder, PairPhase, ShadowFinishArtifact, ShadowFinishConfig, ShadowFinishError,
    ShadowFinishTable, ShadowFinishVerdict,
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
    /// The phase-0 replay invariant held for the planted plaintext.
    pub positive_roundtrip: bool,
    /// The planted plaintext cleared the matched null as a language hypothesis.
    pub positive_candidate_verdict: bool,
    /// The planted plaintext won Tier B under the language statistic.
    pub positive_truth_best: bool,
    /// Planted truth Tier-A rank across the full enumeration surface.
    pub positive_truth_rank: Option<usize>,
    /// The planted truth was inside the configured per-class top-K.
    pub positive_truth_top_k: bool,
    /// Planted best score minus the matched-null maximum.
    pub positive_margin_vs_junk_max: f64,
    /// A repeated anchor trimmed to dirty word boundaries still scores as English.
    pub dirty_boundary_anchor: bool,
    /// The mutated wrong plaintext does not round-trip to the plant ciphertext.
    pub wrong_plaintext_no_roundtrip: bool,
    /// The wrong plaintext's score sits inside the junk distribution.
    pub wrong_plaintext_inside_junk: bool,
    /// Two different table/order/permutation interpretations both replay.
    pub vacuity_both_roundtrip: bool,
    /// The alternate replaying interpretation is textually different.
    pub vacuity_distinct_plaintexts: bool,
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
        .any(|candidate| candidate.plaintext == fixture.plaintext && candidate.roundtrip);
    let positive_truth_best = outcome
        .report
        .top_candidates
        .first()
        .is_some_and(|candidate| candidate.plaintext == fixture.plaintext);
    let positive_candidate_verdict = outcome.report.verdict == ShadowFinishVerdict::Candidate;
    let positive_truth_top_k = outcome.truth_tier_a_rank.is_some_and(|rank| rank <= top_k);
    let positive_margin_vs_junk_max = outcome.report.calibration.margin_vs_null_max;
    let dirty_boundary_anchor =
        dirty_boundary_anchor_passes(&fixture, &word_model, &artifact.hard_anchors);
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
    let vacuity = fixture.vacuity_control(tables)?;
    let passed = positive_roundtrip
        && positive_candidate_verdict
        && positive_truth_best
        && positive_truth_top_k
        && positive_margin_vs_junk_max > 0.0
        && dirty_boundary_anchor
        && wrong_plaintext_no_roundtrip
        && wrong_plaintext_inside_junk
        && vacuity.both_roundtrip
        && vacuity.distinct_plaintexts;
    Ok(ShadowFinishSelfTest {
        positive_roundtrip,
        positive_candidate_verdict,
        positive_truth_best,
        positive_truth_rank: outcome.truth_tier_a_rank,
        positive_truth_top_k,
        positive_margin_vs_junk_max,
        dirty_boundary_anchor,
        wrong_plaintext_no_roundtrip,
        wrong_plaintext_inside_junk,
        vacuity_both_roundtrip: vacuity.both_roundtrip,
        vacuity_distinct_plaintexts: vacuity.distinct_plaintexts,
        passed,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VacuityControl {
    both_roundtrip: bool,
    distinct_plaintexts: bool,
}

#[derive(Clone, Debug)]
struct Fixture {
    artifact_json: String,
    ciphertext: Vec<u16>,
    q_pattern: Vec<u16>,
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
            q_pattern,
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

    fn vacuity_control(
        &self,
        tables: &[ShadowFinishTable],
    ) -> Result<VacuityControl, ShadowFinishError> {
        let truth_table = find_table(tables, "sixbit-lower-space")?;
        let (truth_text, _strict) = decode_pattern(
            &self.q_pattern,
            PairPhase::Phase0,
            DigitOrder::HighLow,
            self.permutation,
            truth_table,
        )
        .ok_or_else(|| {
            ShadowFinishError::RoundTrip("control truth interpretation failed to decode".to_owned())
        })?;
        let alt_table = tables
            .iter()
            .find(|table| table.name == "sixbit-base64")
            .or_else(|| tables.first())
            .ok_or_else(|| ShadowFinishError::Table("empty control table set".to_owned()))?;
        let alt_permutation = [0, 1, 2, 3, 4, 5, 6, 7];
        let (alt_text, _strict) = decode_pattern(
            &self.q_pattern,
            PairPhase::Phase0,
            DigitOrder::LowHigh,
            alt_permutation,
            alt_table,
        )
        .ok_or_else(|| {
            ShadowFinishError::RoundTrip(
                "control alternate interpretation failed to decode".to_owned(),
            )
        })?;
        let truth_roundtrip = self.roundtrips(
            &truth_text,
            truth_table,
            DigitOrder::HighLow,
            self.permutation,
        )?;
        let alt_roundtrip =
            self.roundtrips(&alt_text, alt_table, DigitOrder::LowHigh, alt_permutation)?;
        Ok(VacuityControl {
            both_roundtrip: truth_roundtrip && alt_roundtrip,
            distinct_plaintexts: truth_text != alt_text,
        })
    }

    fn roundtrips(
        &self,
        plaintext: &[u8],
        table: &ShadowFinishTable,
        order: DigitOrder,
        permutation: [u8; 8],
    ) -> Result<bool, ShadowFinishError> {
        let q_pattern = canonical_from_plaintext(plaintext, table, order, permutation)?;
        let rendered = encode_with_key(&q_pattern, 8, &(0..8).collect::<Vec<_>>(), &control_key())?;
        Ok(rendered == self.ciphertext)
    }
}

fn find_table<'a>(
    tables: &'a [ShadowFinishTable],
    name: &str,
) -> Result<&'a ShadowFinishTable, ShadowFinishError> {
    tables
        .iter()
        .find(|table| table.name == name)
        .ok_or_else(|| ShadowFinishError::Table(format!("missing {name} control table")))
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
    let coverage = score_byte_coverage(plaintext);
    combined_score(quad, word, anchor, coverage)
}

fn dirty_boundary_anchor_passes(
    fixture: &Fixture,
    word_model: &WordSegModel,
    anchors: &[crate::analysis::shadow_search::Anchor],
) -> bool {
    let truth = score_anchor_words(word_model, &fixture.plaintext, anchors);
    let wrong = score_anchor_words(word_model, &fixture.wrong_plaintext, anchors);
    let raw_chars = anchors.first().map_or(0, |anchor| anchor.length / 2);
    truth.spans_scored > 0
        && truth.bytes < raw_chars
        && truth.mean_logp > wrong.mean_logp
        && truth.coverage_score > 6.0
}

fn plant_plaintext() -> Vec<u8> {
    let phrase = [
        b"the ".as_slice(),
        control_anchor_phrase(),
        b"when repeated spans carry clear english words and ".as_slice(),
        control_anchor_phrase(),
        b"the search remains clear when english words carry the hidden state ".as_slice(),
    ]
    .concat();
    let mut out = Vec::with_capacity(CONTROL_LEN);
    while out.len() < CONTROL_LEN {
        out.extend_from_slice(&phrase);
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
        ("and", 550),
        ("remains", 540),
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
        control_anchor_json(),
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

fn control_anchor_phrase() -> &'static [u8] {
    b"hidden state search can finish without a crib "
}

fn control_anchor_json() -> String {
    let prefix_len = b"the ".len();
    let phrase_len = control_anchor_phrase().len();
    let bridge_len = b"when repeated spans carry clear english words and ".len();
    let trim_chars = 2usize;
    let raw_first = prefix_len * 2;
    let raw_second = (prefix_len + phrase_len + bridge_len) * 2;
    let raw_length = phrase_len * 2;
    let trim = trim_chars * 2;
    anchor_json(
        raw_first + trim,
        raw_second + trim,
        raw_length - 2 * trim,
        raw_first,
        raw_second,
        raw_length,
        trim,
    )
}

fn anchor_json(
    first: usize,
    second: usize,
    length: usize,
    raw_first: usize,
    raw_second: usize,
    raw_length: usize,
    trim: usize,
) -> String {
    format!(
        "{{\"first\":{first},\"second\":{second},\"length\":{length},\
         \"raw_first\":{raw_first},\"raw_second\":{raw_second},\
         \"raw_length\":{raw_length},\"trim\":{trim}}}"
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

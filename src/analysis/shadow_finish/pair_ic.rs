//! Phase-0 pair-value index-of-coincidence ranking for shadow-finish classes.

use crate::nulls::null::{SplitMix64, fisher_yates};

use super::artifact::ShadowFinishArtifact;
use super::pairs::{decode_pattern, pair_values};
use super::{DigitOrder, PairPhase, ShadowFinishError, ShadowFinishTable};

/// English monogram index of coincidence used as the default target.
pub const ENGLISH_MONOGRAM_IC: f64 = 0.0667;
/// Number of two-octal-digit values in the finish codec.
pub const PAIR_VALUE_COUNT: usize = 64;
/// Default deterministic seed for pair-IC controls.
pub const DEFAULT_PAIR_IC_SEED: u64 = 0x7061_6972_5f69_6300;

const ENGLISH_LIKE_WINDOW: f64 = 0.0075;
const SHARP_SECOND_DISTANCE_GAP: f64 = 0.0100;
const FLAT_CLASS_IC_CEILING: f64 = 0.0450;
const SELF_TEST_EPSILON: f64 = 1.0e-12;
const SELF_TEST_LEN: usize = 349;
const SELF_TEST_NULL_MIN_DISTANCE: f64 = 0.0200;

/// Shape summary for the 24-class pair-IC ranking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairIcShape {
    /// One class is near English IC and the rest look flat/junk by the heuristic.
    SharplyPeaked,
    /// The ranking is not a one-class English-like peak.
    Flat,
}

impl PairIcShape {
    /// Stable report label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SharplyPeaked => "sharply-peaked",
            Self::Flat => "flat/diffuse",
        }
    }
}

/// One class in the pair-IC ranking.
#[derive(Clone, Debug, PartialEq)]
pub struct PairIcClassRank {
    /// Rank by closeness to the target IC; one-based.
    pub rank: usize,
    /// Canonical class index in artifact order; zero-based to match `shadowfinish`.
    pub class_index: usize,
    /// Number of phase-0 pairs scored.
    pub pairs: usize,
    /// Pair-value index of coincidence over values `0..64`.
    pub pair_ic: f64,
    /// Absolute distance from the target IC.
    pub distance: f64,
    /// Stage-(ii) soft-anchor score carried by the artifact.
    pub soft_score: usize,
    /// Deduped survivor sequence count in this canonical class.
    pub sequence_count: usize,
    /// Sum of key multiplicities in this canonical class.
    pub key_multiplicity: u64,
}

/// Complete pair-IC class-ranking report.
#[derive(Clone, Debug, PartialEq)]
pub struct PairIcReport {
    /// Target IC used for ranking.
    pub target_ic: f64,
    /// Pairing phase used for every class.
    pub phase: PairPhase,
    /// Number of canonical classes parsed from the artifact.
    pub classes: usize,
    /// q-symbols dropped by phase-0 chunking.
    pub dropped_q_symbols: usize,
    /// Heuristic shape of the class-axis ranking.
    pub shape: PairIcShape,
    /// Window used to count English-like rows around the target IC.
    pub english_like_window: f64,
    /// Number of rows inside `target_ic +/- english_like_window`.
    pub english_like_classes: usize,
    /// Best-vs-second absolute-distance gap.
    pub best_second_distance_gap: f64,
    /// Rows sorted by closeness to `target_ic`.
    pub rankings: Vec<PairIcClassRank>,
}

/// Outcome of the pair-IC invariance and matched-null self-test.
#[derive(Clone, Debug, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "self-test DTO: each boolean is displayed independently by the CLI"
)]
pub struct PairIcSelfTest {
    /// Pair-IC of the planted plaintext's 6-bit value stream.
    pub plaintext_ic: f64,
    /// Pair-IC after random table, label permutation, and digit-order transpose.
    pub transformed_ic: f64,
    /// Absolute difference between the two IC measurements.
    pub invariance_delta: f64,
    /// The transformed stream decoded back to the planted plaintext.
    pub decoded_roundtrip: bool,
    /// The invariance check matched within the fixed epsilon.
    pub invariance_passed: bool,
    /// Pair-IC of the matched flat/junk control stream.
    pub flat_null_ic: f64,
    /// Absolute distance of the flat/junk control from English IC.
    pub flat_null_distance: f64,
    /// The flat/junk control is far enough from English IC.
    pub flat_null_away: bool,
    /// Overall self-test verdict.
    pub passed: bool,
}

/// Runs the file-driven pair-IC class ranking over a `shadowsearch --output`
/// artifact.
///
/// # Errors
/// Returns [`ShadowFinishError`] for malformed artifacts, invalid class labels,
/// too-short classes, or an invalid target IC.
pub fn run_pair_ic_ranking(
    artifact_text: &str,
    target_ic: f64,
) -> Result<PairIcReport, ShadowFinishError> {
    if !target_ic.is_finite() || target_ic <= 0.0 || target_ic >= 1.0 {
        return Err(ShadowFinishError::Config(
            "--target-ic must be finite and inside (0,1)".to_owned(),
        ));
    }
    let artifact = ShadowFinishArtifact::parse(artifact_text)?;
    let mut rankings = artifact
        .classes
        .iter()
        .enumerate()
        .map(|(class_index, class)| {
            let values = pair_values_checked(
                &class.canonical_pattern,
                PairPhase::Phase0,
                DigitOrder::HighLow,
                identity_permutation(),
            )?;
            let pair_ic = pair_value_ic(&values)?;
            Ok(PairIcClassRank {
                rank: 0,
                class_index,
                pairs: values.len(),
                pair_ic,
                distance: (pair_ic - target_ic).abs(),
                soft_score: class.soft_score,
                sequence_count: class.sequence_count,
                key_multiplicity: class.key_multiplicity,
            })
        })
        .collect::<Result<Vec<_>, ShadowFinishError>>()?;
    rankings.sort_by(|left, right| {
        left.distance
            .total_cmp(&right.distance)
            .then_with(|| right.pair_ic.total_cmp(&left.pair_ic))
            .then_with(|| left.class_index.cmp(&right.class_index))
    });
    for (index, row) in rankings.iter_mut().enumerate() {
        row.rank = index + 1;
    }
    let english_like_classes = rankings
        .iter()
        .filter(|row| row.distance <= ENGLISH_LIKE_WINDOW)
        .count();
    let best_second_distance_gap = match rankings.as_slice() {
        [best, second, ..] => second.distance - best.distance,
        _ => 0.0,
    };
    let shape = classify_shape(&rankings, english_like_classes, best_second_distance_gap);
    Ok(PairIcReport {
        target_ic,
        phase: PairPhase::Phase0,
        classes: rankings.len(),
        dropped_q_symbols: artifact.input_len % 2,
        shape,
        english_like_window: ENGLISH_LIKE_WINDOW,
        english_like_classes,
        best_second_distance_gap,
        rankings,
    })
}

/// Runs the pair-IC invariance and matched-flat-null self-test.
///
/// # Errors
/// Returns [`ShadowFinishError`] if the synthetic codec table or deterministic
/// shuffle cannot be built.
pub fn pair_ic_self_test(seed: u64) -> Result<PairIcSelfTest, ShadowFinishError> {
    let mut rng = SplitMix64::new(seed);
    let plaintext = planted_plaintext();
    let table = random_injective_table(&mut rng)?;
    let encoded_values = encode_plaintext_values(&plaintext, &table)?;
    let plaintext_ic = pair_value_ic(&encoded_values)?;
    let mut label_to_digit = identity_permutation();
    fisher_yates(&mut label_to_digit, &mut rng).map_err(|error| {
        ShadowFinishError::Config(format!(
            "label-permutation shuffle rejected bound {}",
            error.bound
        ))
    })?;
    let order = if rng.next_u64().is_multiple_of(2) {
        DigitOrder::HighLow
    } else {
        DigitOrder::LowHigh
    };
    let transformed_pattern = pattern_from_values(&encoded_values, label_to_digit, order)?;
    let transformed_values = pair_values_checked(
        &transformed_pattern,
        PairPhase::Phase0,
        DigitOrder::HighLow,
        identity_permutation(),
    )?;
    let transformed_ic = pair_value_ic(&transformed_values)?;
    let decoded = decode_pattern(
        &transformed_pattern,
        PairPhase::Phase0,
        order,
        label_to_digit,
        &table,
    )
    .ok_or_else(|| ShadowFinishError::Config("transformed control failed to decode".to_owned()))?
    .0;
    let invariance_delta = (plaintext_ic - transformed_ic).abs();
    let invariance_passed = invariance_delta <= SELF_TEST_EPSILON;
    let flat_null_values = flat_null_values(encoded_values.len());
    let flat_null_ic = pair_value_ic(&flat_null_values)?;
    let flat_null_distance = (flat_null_ic - ENGLISH_MONOGRAM_IC).abs();
    let flat_null_away = flat_null_distance >= SELF_TEST_NULL_MIN_DISTANCE;
    let decoded_roundtrip = decoded == plaintext;
    Ok(PairIcSelfTest {
        plaintext_ic,
        transformed_ic,
        invariance_delta,
        decoded_roundtrip,
        invariance_passed,
        flat_null_ic,
        flat_null_distance,
        flat_null_away,
        passed: invariance_passed && decoded_roundtrip && flat_null_away,
    })
}

/// Computes the index of coincidence over pair values `0..64`.
///
/// # Errors
/// Returns [`ShadowFinishError`] when fewer than two values are supplied or a
/// value is outside `0..64`.
pub fn pair_value_ic(values: &[u8]) -> Result<f64, ShadowFinishError> {
    if values.len() < 2 {
        return Err(ShadowFinishError::Config(
            "pair-IC needs at least two pair values".to_owned(),
        ));
    }
    let mut counts = [0usize; PAIR_VALUE_COUNT];
    for &value in values {
        let index = usize::from(value);
        let Some(count) = counts.get_mut(index) else {
            return Err(ShadowFinishError::Config(format!(
                "pair value {value} outside 0..64"
            )));
        };
        *count += 1;
    }
    let numerator = counts
        .iter()
        .map(|&count| count.saturating_mul(count.saturating_sub(1)))
        .sum::<usize>();
    let denominator = values.len().saturating_mul(values.len() - 1);
    Ok(numerator as f64 / denominator as f64)
}

fn pair_values_checked(
    pattern: &[u16],
    phase: PairPhase,
    order: DigitOrder,
    permutation: [u8; 8],
) -> Result<Vec<u8>, ShadowFinishError> {
    let out = pair_values(pattern, phase, order, permutation).ok_or_else(label_error)?;
    if out.len() < 2 {
        return Err(ShadowFinishError::Config(
            "pair-IC needs at least two phase-0 pairs".to_owned(),
        ));
    }
    Ok(out)
}

fn classify_shape(
    rankings: &[PairIcClassRank],
    english_like_classes: usize,
    best_second_distance_gap: f64,
) -> PairIcShape {
    let flat_class_count = rankings
        .iter()
        .filter(|row| row.pair_ic <= FLAT_CLASS_IC_CEILING)
        .count();
    if english_like_classes == 1
        && best_second_distance_gap >= SHARP_SECOND_DISTANCE_GAP
        && flat_class_count + 1 >= rankings.len()
    {
        PairIcShape::SharplyPeaked
    } else {
        PairIcShape::Flat
    }
}

fn label_error() -> ShadowFinishError {
    ShadowFinishError::Artifact(
        "canonical pattern contains a label outside the 8-digit finish surface".to_owned(),
    )
}

fn identity_permutation() -> [u8; 8] {
    [0, 1, 2, 3, 4, 5, 6, 7]
}

fn random_injective_table(rng: &mut SplitMix64) -> Result<ShadowFinishTable, ShadowFinishError> {
    let mut bytes = *b" abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.";
    fisher_yates(&mut bytes, rng).map_err(|error| {
        ShadowFinishError::Config(format!("table shuffle rejected bound {}", error.bound))
    })?;
    ShadowFinishTable::new("pair-ic-control", bytes)
}

fn encode_plaintext_values(
    plaintext: &[u8],
    table: &ShadowFinishTable,
) -> Result<Vec<u8>, ShadowFinishError> {
    plaintext
        .iter()
        .map(|&byte| {
            table.encode(byte).ok_or_else(|| {
                ShadowFinishError::Table(format!(
                    "control plaintext byte 0x{byte:02x} missing from injective table"
                ))
            })
        })
        .collect()
}

fn pattern_from_values(
    values: &[u8],
    label_to_digit: [u8; 8],
    order: DigitOrder,
) -> Result<Vec<u16>, ShadowFinishError> {
    let mut digit_to_label = [0u16; 8];
    for (label, &digit) in label_to_digit.iter().enumerate() {
        let slot = digit_to_label.get_mut(usize::from(digit)).ok_or_else(|| {
            ShadowFinishError::Config(format!("digit {digit} outside octal range"))
        })?;
        *slot = u16::try_from(label)
            .map_err(|_error| ShadowFinishError::Config("label exceeds u16".to_owned()))?;
    }
    let mut out = Vec::with_capacity(values.len().saturating_mul(2));
    for &value in values {
        if usize::from(value) >= PAIR_VALUE_COUNT {
            return Err(ShadowFinishError::Config(format!(
                "pair value {value} outside 0..64"
            )));
        }
        let high = value / 8;
        let low = value % 8;
        let (left_digit, right_digit) = match order {
            DigitOrder::HighLow => (high, low),
            DigitOrder::LowHigh => (low, high),
        };
        out.push(label_for_digit(&digit_to_label, left_digit)?);
        out.push(label_for_digit(&digit_to_label, right_digit)?);
    }
    Ok(out)
}

fn label_for_digit(digit_to_label: &[u16; 8], digit: u8) -> Result<u16, ShadowFinishError> {
    digit_to_label
        .get(usize::from(digit))
        .copied()
        .ok_or_else(|| ShadowFinishError::Config(format!("digit {digit} outside octal range")))
}

fn flat_null_values(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| (index % PAIR_VALUE_COUNT) as u8)
        .collect()
}

fn planted_plaintext() -> Vec<u8> {
    let phrase = b"the hidden class ranker measures letter frequency only and remains a necessary condition ";
    let mut out = Vec::with_capacity(SELF_TEST_LEN);
    while out.len() < SELF_TEST_LEN {
        out.extend_from_slice(phrase);
    }
    out.truncate(SELF_TEST_LEN);
    out
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_PAIR_IC_SEED, ENGLISH_MONOGRAM_IC, PairIcShape, pair_ic_self_test, pair_value_ic,
        run_pair_ic_ranking,
    };

    #[test]
    fn self_test_passes() {
        let report = pair_ic_self_test(DEFAULT_PAIR_IC_SEED).expect("self-test runs");
        assert!(report.invariance_passed, "{report:?}");
        assert!(report.decoded_roundtrip, "{report:?}");
        assert!(report.flat_null_away, "{report:?}");
        assert!(report.passed, "{report:?}");
    }

    #[test]
    fn ic_matches_hand_count() {
        let values = [1, 1, 1, 2, 2, 3];
        let ic = pair_value_ic(&values).expect("values valid");
        assert!((ic - (8.0 / 30.0)).abs() < 1.0e-12);
    }

    #[test]
    fn artifact_ranking_uses_public_entrypoint() {
        let artifact = artifact_fixture();
        let report = run_pair_ic_ranking(&artifact, ENGLISH_MONOGRAM_IC).expect("ranks");
        assert_eq!(report.classes, 2);
        let best = report.rankings.first().expect("one ranked class");
        assert_eq!(best.class_index, 1);
        assert_eq!(best.pairs, 26);
        assert_eq!(report.shape, PairIcShape::Flat);
    }

    fn artifact_fixture() -> String {
        format!(
            "{{\"tool\":\"shadowsearch\",\"input_len\":52,\"alphabet_size\":8,\
             \"basis\":{{\"legal_readouts\":[0,1,2,3,4,5,6,7]}},\
             \"hard_anchors\":[],\"outcome\":{{\"top_canonical_classes\":[{},{}]}}}}",
            class_json(&flat_pattern(), 0),
            class_json(&englishish_pattern(), 1)
        )
    }

    fn class_json(pattern: &[u16], soft_score: usize) -> String {
        format!(
            "{{\"soft_score\":{soft_score},\"sequence_count\":1,\"key_multiplicity\":1,\
             \"canonical_pattern\":{},\"representative_key\":{}}}",
            u16_json(pattern),
            key_json()
        )
    }

    fn flat_pattern() -> Vec<u16> {
        (0..52)
            .map(|index| u16::try_from(index % 8).expect("small"))
            .collect()
    }

    fn englishish_pattern() -> Vec<u16> {
        let values: [u8; 26] = [
            1, 1, 1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 6, 6, 7, 8, 9, 10, 11, 12, 13, 14,
        ];
        values
            .into_iter()
            .flat_map(|value| [u16::from(value / 8), u16::from(value % 8)])
            .collect()
    }

    fn key_json() -> String {
        let choices = (0..8)
            .map(|readout| {
                format!(
                    "{{\"readout\":{readout},\"fiber_choice\":0,\"element_index\":{readout},\
                     \"element\":[0,1,2,3,4,5,6,7]}}"
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"initial_state_index\":0,\"initial_state\":[0,1,2,3,4,5,6,7],\
             \"choices\":[{choices}]}}"
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
}

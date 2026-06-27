use super::nulls::run_positive_controls;
use super::report::cipher_attack_interpretation_lines;
use super::search::append_cipher_rows;
use super::{
    AttackRow, BestCandidate, CandidateScore, CipherAttackConfig, CipherAttackError,
    CipherAttackReport, CipherFamily, LanguageKind, POSITIVE_CONTROL_MIN_MARGIN, PlantRecovery,
    PositiveControlReport, ScoreNull, SearchSummary, scoring_plans, validate_config,
};
use crate::core::glyph::Glyph;

#[cfg(test)]
fn run_cipher_attack_for_test(
    config: CipherAttackConfig,
    messages: &[Vec<Glyph>],
) -> Result<Vec<AttackRow>, CipherAttackError> {
    validate_config(config)?;
    let plans = scoring_plans()?;
    let mut rows = Vec::new();
    for cipher in CipherFamily::all() {
        append_cipher_rows(cipher, config, messages, &plans, &mut rows)?;
    }
    Ok(rows)
}

#[test]
fn shuffle_null_is_deterministic_for_fixed_seed() {
    let config = CipherAttackConfig {
        seed: 0x1234_5678,
        samples: 4,
        null_trials: 2,
        vigenere_max_period: 2,
    };
    let messages = vec![
        glyphs(&[0, 1, 2, 3, 4, 5, 6, 7]),
        glyphs(&[8, 9, 10, 11, 12, 13]),
    ];
    let first = run_cipher_attack_for_test(config, &messages).unwrap();
    let second = run_cipher_attack_for_test(config, &messages).unwrap();
    assert_eq!(first, second);
}

#[test]
fn positive_control_recovers_caesar_and_vigenere_plants() {
    let report = run_positive_controls(0xfeed_face).unwrap();
    assert_eq!(report.caesar.cipher, CipherFamily::Caesar);
    assert_eq!(report.caesar.expected_key, report.caesar.recovered_key);
    assert!(report.caesar.margin_over_null_max >= POSITIVE_CONTROL_MIN_MARGIN);
    assert_eq!(report.vigenere.cipher, CipherFamily::Vigenere);
    assert_eq!(report.vigenere.expected_key, report.vigenere.recovered_key);
    assert!(report.vigenere.margin_over_null_max >= POSITIVE_CONTROL_MIN_MARGIN);
}

#[test]
fn cipher_attack_interpretation_does_not_treat_small_pointwise_p_as_hit() {
    let report = CipherAttackReport {
        config: CipherAttackConfig::default(),
        order_name: "standard36-u012-d012".to_owned(),
        message_lengths: vec![("fixture", 100)],
        total_symbols: 100,
        boundary_rule: "fixture boundary",
        null_model: "fixture null",
        rows: vec![
            attack_row(-2.9975, -3.0100, -3.0000, 0.0),
            attack_row(-2.9800, -3.0100, -3.0000, 0.0),
            attack_row(-3.0050, -3.0100, -3.0000, 0.25),
            attack_row(-3.0200, -3.0100, -3.0000, 1.0),
        ],
        positive_control: PositiveControlReport {
            caesar: plant_recovery(CipherFamily::Caesar, 0.4900),
            vigenere: plant_recovery(CipherFamily::Vigenere, 0.6100),
        },
    };

    let interpretation = cipher_attack_interpretation_lines(&report).join("\n");

    assert!(
        interpretation.contains("not 3 near-solutions"),
        "{interpretation}"
    );
    assert!(
        interpretation.contains("small values are expected by selection"),
        "{interpretation}"
    );
    assert!(
        interpretation.contains("no family-wise-significant result exists"),
        "{interpretation}"
    );
    assert!(
        interpretation.contains("No credible English/Finnish decryption is established"),
        "{interpretation}"
    );
    assert!(
        interpretation.contains("0.0025..0.0200 nats"),
        "{interpretation}"
    );
    assert!(
        interpretation.contains("positive-control plant margins of 0.4900..0.6100 nats"),
        "{interpretation}"
    );
    assert!(
        interpretation.contains("nowhere near the scale of a genuine cipher hit"),
        "{interpretation}"
    );
}

fn attack_row(real: f64, q95: f64, max: f64, empirical_p: f64) -> AttackRow {
    AttackRow {
        cipher: CipherFamily::Caesar,
        language: LanguageKind::English,
        mapping_label: "fixture".to_owned(),
        mapping_note: "fixture mapping".to_owned(),
        search: SearchSummary {
            key_space: "fixture keyspace".to_owned(),
            candidates_evaluated: 100,
            exhaustive: true,
            sampling_seed: None,
            note: "fixture search".to_owned(),
        },
        real: BestCandidate {
            score: candidate_score(real),
            key: "fixture-key".to_owned(),
        },
        null: ScoreNull {
            trials: 4,
            mean: -3.0200,
            q95,
            max,
            empirical_p_count: 0,
            empirical_p,
        },
    }
}

fn plant_recovery(cipher: CipherFamily, margin_over_null_max: f64) -> PlantRecovery {
    PlantRecovery {
        cipher,
        plaintext_symbols: 100,
        expected_key: "expected".to_owned(),
        recovered_key: "expected".to_owned(),
        real_score: candidate_score(-2.5000),
        null: ScoreNull {
            trials: 4,
            mean: -3.1000,
            q95: -3.0000,
            max: -2.5000 - margin_over_null_max,
            empirical_p_count: 0,
            empirical_p: 0.0,
        },
        margin_over_null_max,
    }
}

fn candidate_score(bigram_mean_log_likelihood: f64) -> CandidateScore {
    CandidateScore {
        symbols: 100,
        unigram_mean_log_likelihood: bigram_mean_log_likelihood,
        bigram_mean_log_likelihood,
    }
}

fn glyphs(values: &[u16]) -> Vec<Glyph> {
    values.iter().copied().map(Glyph).collect()
}

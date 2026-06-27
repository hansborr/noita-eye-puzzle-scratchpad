use super::{
    ALPHABET_SIZE, ControlsError, ISOMORPH_KEY_PERIOD, IsomorphControlConfig,
    MAX_ABSENT_PERIOD_MATCHES, MIN_PERIOD_MATCH_SEPARATION, MIN_PRESENT_PERIOD_MATCHES,
    MonoalphabeticControlConfig, SubstitutionKey, balanced_uniform_sequence, detect_isomorphs,
    normalize_plaintext, run_isomorph_control, run_monoalphabetic_control, sorted_frequency_counts,
};
use crate::analysis::analysis;
use crate::analysis::isomorph::PatternSignature;
use crate::core::glyph::Glyph;

#[test]
fn monoalphabetic_control_preserves_exact_statistics() {
    let report = run_monoalphabetic_control(MonoalphabeticControlConfig {
        seed: 0x1234_5678_9abc_def0,
    })
    .unwrap();

    assert_eq!(report.long_fixture.length, 420);
    assert_eq!(
        report.long_fixture.plaintext_ioc.to_bits(),
        report.long_fixture.ciphertext_ioc.to_bits()
    );
    assert!(
        (report.long_fixture.plaintext_entropy - report.long_fixture.ciphertext_entropy).abs()
            < 1e-12
    );
    assert!(report.long_fixture.frequency_multiset_preserved);
    assert!(report.long_fixture.bigram_multiset_preserved);
    assert!(report.long_fixture.known_key_recovered);
    assert_eq!(
        report.long_fixture.normalized_plaintext,
        report.long_fixture.recovered_plaintext
    );
}

#[test]
fn monoalphabetic_control_separates_english_like_from_uniform() {
    let report = run_monoalphabetic_control(MonoalphabeticControlConfig { seed: 0xf00d }).unwrap();

    assert!(report.long_fixture.plaintext_ioc > report.uniform_floor);
    assert!(report.flattened_ioc < report.uniform_floor);
    assert!(report.long_fixture.plaintext_ioc - report.flattened_ioc > 0.03);
}

#[test]
fn documented_common_glyph_plaintexts_are_known_key_vectors() {
    let report = run_monoalphabetic_control(MonoalphabeticControlConfig { seed: 0xbeef }).unwrap();
    let normalized = report
        .documented_vectors
        .iter()
        .map(|fixture| fixture.normalized_plaintext.as_str())
        .collect::<Vec<_>>();

    assert_eq!(normalized, vec!["SEEKTHEEND", "BRINGTHETREASUREHERE"]);
    for fixture in &report.documented_vectors {
        assert_eq!(
            fixture.plaintext_ioc.to_bits(),
            fixture.ciphertext_ioc.to_bits()
        );
        assert!(fixture.frequency_multiset_preserved);
        assert!(fixture.bigram_multiset_preserved);
        assert!(fixture.known_key_recovered);
        assert_eq!(fixture.normalized_plaintext, fixture.recovered_plaintext);
    }
}

#[test]
fn generated_key_is_a_bijection() {
    let key = SubstitutionKey::from_seed(7, ALPHABET_SIZE).unwrap();
    let plaintext = normalize_plaintext("test", "ABCDEFGHIJKLMNOPQRSTUVWXYZ").unwrap();
    let ciphertext = key.encrypt("test", &plaintext).unwrap();
    let recovered = key.decrypt("test", &ciphertext).unwrap();

    assert_eq!(recovered, plaintext);
    assert_eq!(
        sorted_frequency_counts(&plaintext),
        sorted_frequency_counts(&ciphertext)
    );
}

#[test]
fn balanced_uniform_comparison_sits_below_with_replacement_floor() {
    let sample = balanced_uniform_sequence(ALPHABET_SIZE, 420).unwrap();
    let ioc = analysis::index_of_coincidence(&sample);
    let uniform_floor = 1.0 / ALPHABET_SIZE as f64;

    assert!(ioc < uniform_floor);
}

#[test]
fn unsupported_plaintext_symbols_are_rejected() {
    let error = normalize_plaintext("bad fixture", "SEEK 123").unwrap_err();

    assert_eq!(
        error,
        ControlsError::UnsupportedPlaintextSymbol {
            label: "bad fixture",
            symbol: '1'
        }
    );
}

#[test]
fn isomorph_control_separates_present_and_absent_structure() {
    for seed in [0x6973_6f6d_6f72_7068, 0x1234_5678_9abc_def0, 0xf00d, 0] {
        let report = run_isomorph_control(IsomorphControlConfig { seed }).unwrap();

        assert_eq!(report.vigenere.length, 1496);
        assert!(report.vigenere.expected_period_matches >= MIN_PRESENT_PERIOD_MATCHES);
        assert_eq!(
            report.vigenere.best_period.map(|signal| signal.period),
            Some(ISOMORPH_KEY_PERIOD)
        );

        for absent in [&report.autokey, &report.running_key] {
            let absent_max_matches = absent.best_period.map_or(0, |signal| signal.matches);
            assert!(absent_max_matches <= MAX_ABSENT_PERIOD_MATCHES);
            assert!(
                report.vigenere.expected_period_matches
                    >= absent_max_matches + MIN_PERIOD_MATCH_SEPARATION
            );
        }
    }
}

#[test]
fn isomorph_control_is_deterministic_for_seed() {
    let first = run_isomorph_control(IsomorphControlConfig { seed: 0xf00d }).unwrap();
    let second = run_isomorph_control(IsomorphControlConfig { seed: 0xf00d }).unwrap();

    assert_eq!(first, second);
}

#[test]
fn isomorph_control_default_seed_numbers_are_anchored() {
    let report = run_isomorph_control(IsomorphControlConfig::default()).unwrap();

    assert_eq!(report.vigenere.informative_windows, 1480);
    assert_eq!(report.vigenere.repeated_signature_kinds, 49);
    assert_eq!(report.vigenere.exact_repeated_windows, 38);
    assert_eq!(report.vigenere.expected_period_matches, 923);
    assert_eq!(
        report.vigenere.best_period.map(|signal| signal.period),
        Some(7)
    );
    assert_eq!(
        report.vigenere.best_period.map(|signal| signal.matches),
        Some(923)
    );
    assert_eq!(
        report
            .vigenere
            .best_period
            .map(|signal| signal.signature_kinds),
        Some(44)
    );

    assert_eq!(report.autokey.informative_windows, 1479);
    assert_eq!(report.autokey.repeated_signature_kinds, 16);
    assert_eq!(report.autokey.exact_repeated_windows, 0);
    assert_eq!(report.autokey.expected_period_matches, 7);
    assert_eq!(
        report.autokey.best_period.map(|signal| signal.period),
        Some(2)
    );
    assert_eq!(
        report.autokey.best_period.map(|signal| signal.matches),
        Some(11)
    );
    assert_eq!(
        report
            .autokey
            .best_period
            .map(|signal| signal.signature_kinds),
        Some(7)
    );

    assert_eq!(report.running_key.informative_windows, 1479);
    assert_eq!(report.running_key.repeated_signature_kinds, 15);
    assert_eq!(report.running_key.exact_repeated_windows, 0);
    assert_eq!(report.running_key.expected_period_matches, 2);
    assert_eq!(
        report.running_key.best_period.map(|signal| signal.period),
        Some(2)
    );
    assert_eq!(
        report.running_key.best_period.map(|signal| signal.matches),
        Some(10)
    );
    assert_eq!(
        report
            .running_key
            .best_period
            .map(|signal| signal.signature_kinds),
        Some(10)
    );
}

#[test]
fn signature_detector_finds_repeated_relative_pattern_period() {
    let period = [0, 1, 2, 0, 3, 4, 0]
        .iter()
        .copied()
        .map(Glyph)
        .collect::<Vec<_>>();
    let mut seq = Vec::new();
    for index in 0..140 {
        seq.push(period.get(index % period.len()).copied().unwrap());
    }

    let detection = detect_isomorphs("test", &seq, 9).unwrap();

    assert_eq!(detection.best_period().map(|signal| signal.period), Some(7));
    assert!(detection.period_matches(7) > detection.period_matches(6));
}

#[test]
fn pattern_signature_uses_first_occurrence_shape() {
    let abcab = PatternSignature::from_window(&[Glyph(0), Glyph(1), Glyph(2), Glyph(0), Glyph(1)]);
    let xyzxy =
        PatternSignature::from_window(&[Glyph(23), Glyph(24), Glyph(25), Glyph(23), Glyph(24)]);

    assert_eq!(abcab, xyzxy);
    assert_eq!(abcab.render(), "0,1,2,0,1");
}

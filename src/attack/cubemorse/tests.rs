use crate::core::glyph::Glyph;

use super::{
    CubeMorseConfig, CubeMorseError, CubeMorseVerdict, PLANT_TEXT, analyze_cube_morse,
    cubemorse_self_test, encode_cube_morse,
};

const SIX_SOLUTION: &str = "CUBE IS A GREAT TOY MODEL OF NON-COMMUTATIVITY.";

fn parse_words(line: &str) -> Vec<Vec<Glyph>> {
    line.split_whitespace()
        .map(|word| {
            word.bytes()
                .map(|byte| Glyph(u16::from(byte - b'1')))
                .collect()
        })
        .collect()
}

#[test]
fn planted_control_recovers_and_replays_under_matched_null() {
    let report = cubemorse_self_test(0x6375_6265_7465_7374).unwrap();
    assert!(report.passed(), "failed cube/Morse self-test: {report:?}");
}

#[test]
fn all_three_six_face_relabelings_recover_the_same_candidate() {
    let fixture = include_str!("../../../research/data/practice-puzzles/six");
    for line in fixture.lines().filter(|line| !line.trim().is_empty()) {
        let words = parse_words(line);
        let report = analyze_cube_morse(
            &words,
            CubeMorseConfig {
                null_trials: 8,
                seed: 0x7369_785f_6c69_6e65,
                top: 3,
            },
        )
        .unwrap();
        assert_eq!(report.verdict, CubeMorseVerdict::ExactCandidate);
        let candidate = report.candidates.first().unwrap();
        assert_eq!(candidate.plaintext, SIX_SOLUTION);
        assert!(candidate.exact());
        assert_eq!(candidate.total, 139);
        let replay = encode_cube_morse(&candidate.plaintext, candidate.cell).unwrap();
        assert_eq!(replay, words);
    }
}

#[test]
fn rejects_symbols_outside_six_faces() {
    let error = analyze_cube_morse(
        &[vec![Glyph(0), Glyph(6)]],
        CubeMorseConfig {
            null_trials: 0,
            ..CubeMorseConfig::default()
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        CubeMorseError::SymbolOutOfRange { value: 6 }
    ));
}

#[test]
fn opposite_face_jump_is_an_honest_negative() {
    let report = analyze_cube_morse(
        &[vec![Glyph(0), Glyph(5), Glyph(1)]],
        CubeMorseConfig {
            null_trials: 0,
            top: 3,
            ..CubeMorseConfig::default()
        },
    )
    .unwrap();
    assert_eq!(report.verdict, CubeMorseVerdict::NoCandidate);
    assert!(report.candidates.is_empty());
}

#[test]
fn known_cell_encodes_one_command_per_non_space_character() {
    let fixture = include_str!("../../../research/data/practice-puzzles/six");
    let words = parse_words(fixture.lines().next().unwrap());
    let report = analyze_cube_morse(
        &words,
        CubeMorseConfig {
            null_trials: 0,
            top: 1,
            ..CubeMorseConfig::default()
        },
    )
    .unwrap();
    let candidate = report.candidates.first().unwrap();
    assert_ne!(candidate.plaintext, PLANT_TEXT);
    assert_eq!(
        encode_cube_morse(&candidate.plaintext, candidate.cell)
            .unwrap()
            .iter()
            .map(Vec::len)
            .sum::<usize>(),
        139
    );
}

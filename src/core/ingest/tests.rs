use super::*;
use crate::data::corpus;

fn glyphs(values: &[u16]) -> Vec<Glyph> {
    values.iter().copied().map(Glyph).collect()
}

#[test]
fn rendered_drops_delimiter_and_whitespace() {
    let parsed =
        parse_sequence("012 345\n01", SequenceLayer::RenderedOrientation).expect("rendered parse");
    assert_eq!(parsed.glyphs, glyphs(&[0, 1, 2, 3, 4, 0, 1]));
    assert!(parsed.transparent.is_empty());
}

#[test]
fn rendered_rejects_non_digit_with_index() {
    let error =
        parse_sequence("01x", SequenceLayer::RenderedOrientation).expect_err("non-digit must fail");
    match error {
        IngestError::InvalidToken {
            layer,
            token,
            index,
        } => {
            assert_eq!(layer, LayerKind::RenderedOrientation);
            assert_eq!(token, "x");
            assert_eq!(index, 2);
        }
        other => panic!("expected InvalidToken, got {other:?}"),
    }
}

#[test]
fn rendered_rejects_digit_above_five_with_index() {
    let error =
        parse_sequence("016", SequenceLayer::RenderedOrientation).expect_err("digit > 5 must fail");
    match error {
        IngestError::InvalidToken { token, index, .. } => {
            assert_eq!(token, "6");
            assert_eq!(index, 2);
        }
        other => panic!("expected InvalidToken, got {other:?}"),
    }
}

#[test]
fn rendered_empty_and_all_whitespace_are_empty() {
    assert!(matches!(
        parse_sequence("", SequenceLayer::RenderedOrientation),
        Err(IngestError::Empty)
    ));
    assert!(matches!(
        parse_sequence("  \n\t ", SequenceLayer::RenderedOrientation),
        Err(IngestError::Empty)
    ));
    // An all-delimiter input is likewise empty (all `5`s dropped).
    assert!(matches!(
        parse_sequence("555", SequenceLayer::RenderedOrientation),
        Err(IngestError::Empty)
    ));
}

#[test]
fn honeycomb_parses_accepted_values() {
    let parsed =
        parse_sequence("0 12 82", SequenceLayer::HoneycombReading).expect("honeycomb parse");
    assert_eq!(parsed.glyphs, glyphs(&[0, 12, 82]));
    assert!(parsed.transparent.is_empty());
}

#[test]
fn honeycomb_tolerates_extra_separators() {
    let parsed =
        parse_sequence("0,,12 , 82,", SequenceLayer::HoneycombReading).expect("honeycomb parse");
    assert_eq!(parsed.glyphs, glyphs(&[0, 12, 82]));
}

#[test]
fn honeycomb_rejects_above_alphabet_and_non_numeric() {
    // 83 is the first raw-but-unaccepted trigram value.
    let error = parse_sequence("83", SequenceLayer::HoneycombReading)
        .expect_err("83 is outside the eye alphabet");
    match error {
        IngestError::InvalidToken {
            layer,
            token,
            index,
        } => {
            assert_eq!(layer, LayerKind::HoneycombReading);
            assert_eq!(token, "83");
            assert_eq!(index, 0);
        }
        other => panic!("expected InvalidToken, got {other:?}"),
    }
    assert!(matches!(
        parse_sequence("125", SequenceLayer::HoneycombReading),
        Err(IngestError::InvalidToken { .. })
    ));
    assert!(matches!(
        parse_sequence("x", SequenceLayer::HoneycombReading),
        Err(IngestError::InvalidToken { .. })
    ));
}

#[test]
fn honeycomb_reports_token_index_among_tokens() {
    let error = parse_sequence("0 1 83", SequenceLayer::HoneycombReading)
        .expect_err("third token is out of range");
    match error {
        IngestError::InvalidToken { token, index, .. } => {
            assert_eq!(token, "83");
            assert_eq!(index, 2);
        }
        other => panic!("expected InvalidToken, got {other:?}"),
    }
}

#[test]
fn cipher_alphabet_passes_transparent_symbols_through() {
    let alphabet = Alphabet::from_chars("ABCDEFGHIJKLMNOPQRSTUVWXYZ").expect("alphabet");
    let transparent = TransparentSet::default();
    let layer = SequenceLayer::CipherAlphabet {
        alphabet: &alphabet,
        transparent: &transparent,
    };
    let parsed = parse_sequence("AB CD.", layer).expect("cipher parse");
    assert_eq!(parsed.glyphs, glyphs(&[0, 1, 2, 3]));
    assert_eq!(
        parsed.transparent,
        vec![
            TransparentMark {
                ch: ' ',
                position: 2
            },
            TransparentMark {
                ch: '.',
                position: 5
            },
        ]
    );
}

#[test]
fn cipher_alphabet_rejects_out_of_alphabet_char() {
    let alphabet = Alphabet::from_chars("ABCDEFGHIJKLMNOPQRSTUVWXYZ").expect("alphabet");
    let transparent = TransparentSet::default();
    let layer = SequenceLayer::CipherAlphabet {
        alphabet: &alphabet,
        transparent: &transparent,
    };
    // A digit is neither a cipher letter nor a transparent symbol.
    let error = parse_sequence("AB3", layer).expect_err("digit is invalid here");
    match error {
        IngestError::InvalidToken {
            layer,
            token,
            index,
        } => {
            assert_eq!(layer, LayerKind::CipherAlphabet);
            assert_eq!(token, "3");
            assert_eq!(index, 2);
        }
        other => panic!("expected InvalidToken, got {other:?}"),
    }
}

#[test]
fn cipher_alphabet_all_transparent_is_empty() {
    let alphabet = Alphabet::from_chars("ABCDEFGHIJKLMNOPQRSTUVWXYZ").expect("alphabet");
    let transparent = TransparentSet::default();
    let layer = SequenceLayer::CipherAlphabet {
        alphabet: &alphabet,
        transparent: &transparent,
    };
    assert!(matches!(
        parse_sequence("  ", layer),
        Err(IngestError::Empty)
    ));
}

#[test]
fn transparent_set_override_excludes_hash() {
    // Puzzle `seven` treats `#` as a possible cipher symbol, not plumbing.
    let default = TransparentSet::default();
    assert!(default.contains('#'));
    let without_hash = TransparentSet::from_chars(" .,?!\n");
    assert!(!without_hash.contains('#'));
    assert!(without_hash.contains(' '));
}

#[test]
fn rendered_matches_corpus_parser_for_all_nine_messages() {
    for message in &corpus::MESSAGES {
        let ingested = parse_sequence(message.digits, SequenceLayer::RenderedOrientation)
            .expect("corpus digits parse under the rendered layer");
        let expected = message
            .sequence()
            .expect("corpus message yields a sequence");
        assert_eq!(
            ingested.glyphs, expected.glyphs,
            "ingest must reproduce the corpus parse for message {}",
            message.key
        );
        assert!(ingested.transparent.is_empty());
    }
}

#[test]
fn load_sequence_maps_missing_path_to_io_error() {
    let missing = Path::new("research/data/practice-puzzles/does-not-exist");
    let error = load_sequence(Input::Path(missing), SequenceLayer::RenderedOrientation)
        .expect_err("missing path must fail");
    assert!(matches!(error, IngestError::Io(_)));
}

use super::{
    DEFAULT_LANGUAGE_ALPHABET, DEFAULT_SMOOTHING, LanguageAlphabet, LanguageError, LanguageModel,
    default_alphabet, english_model, finnish_model,
};

const HELD_OUT_ENGLISH: &str = "\
The little passage was almost lost in the dark, but Alice kept her hand upon
the wall and walked carefully forward. She was not thinking about riddles now,
only about the sound of ordinary words and the hope of finding daylight again.";

const HELD_OUT_FINNISH: &str = "\
Vaka vanha Väinämöinen lauloi illan hämärässä, sanat kulkivat hiljalleen ja
äänet nousivat veden ylitse. Kansan vanhat virret säilyivät muistissa ja
kulkeutuivat polvelta toiselle.";

#[test]
fn default_alphabet_contains_ascii_and_finnish_letters() {
    let alphabet = default_alphabet().unwrap();
    assert_eq!(alphabet.len(), 29);
    assert_eq!(alphabet.symbol(0), Some('A'));
    assert_eq!(alphabet.index('z'), Some(25));
    assert_eq!(alphabet.index('ä'), Some(27));
    assert_eq!(alphabet.index('?'), None);
    assert_eq!(
        alphabet.symbols().iter().collect::<String>(),
        DEFAULT_LANGUAGE_ALPHABET
    );
}

#[test]
fn alphabet_rejects_duplicate_after_normalization() {
    assert_eq!(
        LanguageAlphabet::from_chars("Aa"),
        Err(LanguageError::DuplicateAlphabetSymbol { symbol: 'A' })
    );
}

#[test]
fn normalization_rejects_unsupported_alphabetic_symbols() {
    let alphabet = default_alphabet().unwrap();
    assert_eq!(
        alphabet.normalize_text("café"),
        Err(LanguageError::UnsupportedSymbol { symbol: 'é' })
    );
}

#[test]
fn model_rejects_empty_training_after_comments() {
    let alphabet = default_alphabet().unwrap();
    assert!(matches!(
        LanguageModel::from_sample("# provenance only\n\n", alphabet, DEFAULT_SMOOTHING),
        Err(LanguageError::EmptyTrainingText)
    ));
}

#[test]
fn scoring_rejects_empty_and_out_of_range_candidates() {
    let model = LanguageModel::from_sample("ABBA", default_alphabet().unwrap(), 1.0).unwrap();
    assert_eq!(
        model.score_text("... 123"),
        Err(LanguageError::EmptyCandidate)
    );
    assert_eq!(
        model.score_indices(&[0, 99]),
        Err(LanguageError::IndexOutsideAlphabet {
            index: 99,
            alphabet_len: 29,
        })
    );
}

#[test]
fn additive_smoothing_keeps_unseen_bigrams_finite() {
    let model = LanguageModel::from_sample("AAAAAA", default_alphabet().unwrap(), 1.0).unwrap();
    let score = model.score_text("ZZ").unwrap();
    assert!(score.bigram_mean_log_likelihood.is_finite());
    assert_eq!(score.symbols, 2);
}

#[test]
fn held_out_language_calibration_separates_english_and_finnish() {
    let english = english_model().unwrap();
    let finnish = finnish_model().unwrap();

    let english_under_english = english
        .score_text(HELD_OUT_ENGLISH)
        .unwrap()
        .bigram_mean_log_likelihood;
    let english_under_finnish = finnish
        .score_text(HELD_OUT_ENGLISH)
        .unwrap()
        .bigram_mean_log_likelihood;
    let finnish_under_finnish = finnish
        .score_text(HELD_OUT_FINNISH)
        .unwrap()
        .bigram_mean_log_likelihood;
    let finnish_under_english = english
        .score_text(HELD_OUT_FINNISH)
        .unwrap()
        .bigram_mean_log_likelihood;

    println!(
        "English held-out: English model {english_under_english:.6}, Finnish model {english_under_finnish:.6}; Finnish held-out: Finnish model {finnish_under_finnish:.6}, English model {finnish_under_english:.6}"
    );

    assert!(
        english_under_english > english_under_finnish,
        "English held-out scored {english_under_english} under English and {english_under_finnish} under Finnish"
    );
    assert!(
        finnish_under_finnish > finnish_under_english,
        "Finnish held-out scored {finnish_under_finnish} under Finnish and {finnish_under_english} under English"
    );
}

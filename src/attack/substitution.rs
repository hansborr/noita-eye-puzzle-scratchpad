//! Monoalphabetic substitution resolver for already-segmented candidate text.
//!
//! This is a narrow candidate-finishing instrument: it assumes word separators
//! are already visible and asks whether the non-space symbols can host an
//! English monoalphabetic substitution above a matched symbol-shuffle null. A
//! surviving candidate is still a language hypothesis, never a verified decode.

use std::fmt;

use crate::attack::quadgram::{QuadgramError, QuadgramModel};
use crate::attack::rlcodec::{RlError, SubResult, substitution_search};
use crate::nulls::null::{RandomBoundError, SplitMix64, add_one_p_value, fisher_yates, mix_seed};

/// Default deterministic seed for substitution finishing.
pub const DEFAULT_SEED: u64 = 0x7375_6273_7469_7401;
/// Default random restarts for one substitution search.
pub const DEFAULT_RESTARTS: usize = 24;
/// Default annealing proposals per restart.
pub const DEFAULT_ITERS: usize = 12_000;
/// Default matched-null trials.
pub const DEFAULT_NULL_TRIALS: usize = 20;
/// Candidate threshold on the add-one empirical p-value.
pub const DEFAULT_ALPHA: f64 = 0.05;
/// Maximum supported substitution alphabet.
pub const MAX_ALPHABET: usize = 26;

const PLANT_PLAINTEXT: &str = "would an octal number system have come before the decimal number system it has been suggested that the reconstructed proto indo european word for nine might be related to the proto indo european word for new based on this some have speculated that proto indo europeans used an octal number system though the evidence supporting this is slim";
const PLANT_ALPHABET: &str = "QWERTYUIOPASDFGHJKLZXCVBNM";

/// Configuration for one substitution finish run.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SubstitutionConfig {
    /// Random restarts for each substitution search.
    pub restarts: usize,
    /// Annealing proposals per restart.
    pub iters: usize,
    /// Matched-null trials.
    pub null_trials: usize,
    /// Deterministic seed for the search and nulls.
    pub seed: u64,
    /// Candidate threshold on add-one empirical p-value.
    pub alpha: f64,
}

impl Default for SubstitutionConfig {
    fn default() -> Self {
        Self {
            restarts: DEFAULT_RESTARTS,
            iters: DEFAULT_ITERS,
            null_trials: DEFAULT_NULL_TRIALS,
            seed: DEFAULT_SEED,
            alpha: DEFAULT_ALPHA,
        }
    }
}

/// Verdict vocabulary for the substitution finish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubstitutionVerdict {
    /// The observed text beat the matched null at the configured alpha.
    Candidate,
    /// The observed text did not beat the matched null.
    NoCandidate,
    /// The null battery cannot reach the configured alpha.
    LowPowerNoExclusion,
}

impl SubstitutionVerdict {
    /// Stable report label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Candidate => "Candidate",
            Self::NoCandidate => "NoCandidate",
            Self::LowPowerNoExclusion => "LowPowerNoExclusion",
        }
    }
}

/// Parsed substitution input with word separators preserved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubstitutionInput {
    /// Alphabet characters in symbol-id order.
    pub alphabet: Vec<char>,
    /// Text tokens: `Some(symbol_id)` for cipher symbols, `None` for separators.
    pub tokens: Vec<Option<usize>>,
}

impl SubstitutionInput {
    /// Number of non-separator symbols.
    #[must_use]
    pub fn symbol_count(&self) -> usize {
        self.tokens.iter().filter(|token| token.is_some()).count()
    }

    /// Number of separator positions.
    #[must_use]
    pub fn separator_count(&self) -> usize {
        self.tokens.iter().filter(|token| token.is_none()).count()
    }

    fn dense_symbols(&self) -> Vec<usize> {
        self.tokens.iter().filter_map(|&token| token).collect()
    }
}

/// One source-symbol to plaintext-letter mapping row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappingRow {
    /// Source symbol from the supplied alphabet.
    pub symbol: char,
    /// Recovered plaintext letter.
    pub letter: char,
}

/// Result of one substitution finish run.
#[derive(Clone, Debug, PartialEq)]
pub struct SubstitutionReport {
    /// Verdict under the matched null.
    pub verdict: SubstitutionVerdict,
    /// Number of non-space symbols searched.
    pub symbols: usize,
    /// Substitution alphabet size.
    pub alphabet_size: usize,
    /// Number of visible separator positions.
    pub separators: usize,
    /// Best observed mean quadgram score.
    pub observed_score: f64,
    /// Best null score, if nulls were run.
    pub null_max: f64,
    /// Number of null scores greater than or equal to observed.
    pub null_ge: usize,
    /// Add-one empirical p-value.
    pub p_emp: f64,
    /// Observed minus best-null score.
    pub margin_vs_null_max: f64,
    /// Best candidate text with separators preserved.
    pub plaintext: String,
    /// Source-symbol to plaintext-letter map.
    pub mapping: Vec<MappingRow>,
}

/// Self-test outcome for the substitution finish instrument.
#[derive(Clone, Debug, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "self-test DTO: each boolean is displayed independently by the CLI"
)]
pub struct SubstitutionSelfTest {
    /// Planted positive produced a candidate verdict.
    pub positive_candidate: bool,
    /// Planted positive recovered the expected plaintext exactly.
    pub positive_exact: bool,
    /// Matched null did not match the observed planted score.
    pub positive_beats_null: bool,
    /// Flat/junk control did not produce a candidate verdict.
    pub flat_no_candidate: bool,
    /// Overall self-test verdict.
    pub passed: bool,
}

/// Errors returned by the substitution finisher.
#[derive(Clone, Debug, PartialEq)]
pub enum SubstitutionError {
    /// The alphabet string was empty.
    EmptyAlphabet,
    /// The alphabet has more than 26 symbols.
    AlphabetTooLarge {
        /// Number of symbols supplied.
        size: usize,
    },
    /// The alphabet repeated a character.
    RepeatedAlphabetSymbol {
        /// Repeated character.
        symbol: char,
    },
    /// The text contained a non-whitespace character outside the alphabet.
    SymbolOutsideAlphabet {
        /// Rejected character.
        symbol: char,
    },
    /// No symbols were present after parsing.
    EmptyText,
    /// The bundled quadgram model could not be built.
    Quadgram(QuadgramError),
    /// The shared substitution search failed.
    Search(RlError),
    /// A deterministic random draw rejected its bound.
    Random(RandomBoundError),
}

impl From<QuadgramError> for SubstitutionError {
    fn from(error: QuadgramError) -> Self {
        Self::Quadgram(error)
    }
}

impl From<RandomBoundError> for SubstitutionError {
    fn from(error: RandomBoundError) -> Self {
        Self::Random(error)
    }
}

impl From<RlError> for SubstitutionError {
    fn from(error: RlError) -> Self {
        Self::Search(error)
    }
}

impl fmt::Display for SubstitutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyAlphabet => write!(f, "substitution alphabet cannot be empty"),
            Self::AlphabetTooLarge { size } => write!(
                f,
                "substitution alphabet has {size} symbols; maximum is {MAX_ALPHABET}"
            ),
            Self::RepeatedAlphabetSymbol { symbol } => {
                write!(f, "substitution alphabet repeats {symbol:?}")
            }
            Self::SymbolOutsideAlphabet { symbol } => {
                write!(f, "input contains symbol {symbol:?} outside --alphabet")
            }
            Self::EmptyText => write!(f, "input contains no substitution symbols"),
            Self::Quadgram(error) => write!(f, "quadgram model: {error}"),
            Self::Search(error) => write!(f, "substitution search: {error}"),
            Self::Random(error) => write!(f, "random draw rejected bound {}", error.bound),
        }
    }
}

impl std::error::Error for SubstitutionError {}

/// Parses raw text using an explicit substitution alphabet.
///
/// Whitespace is preserved as visible word separators in the rendered candidate;
/// every non-whitespace character must appear in `alphabet`.
///
/// # Errors
/// Returns [`SubstitutionError`] if the alphabet is malformed or the text uses a
/// symbol outside it.
pub fn parse_substitution_input(
    text: &str,
    alphabet: &str,
) -> Result<SubstitutionInput, SubstitutionError> {
    let alphabet_chars = alphabet.chars().collect::<Vec<_>>();
    if alphabet_chars.is_empty() {
        return Err(SubstitutionError::EmptyAlphabet);
    }
    if alphabet_chars.len() > MAX_ALPHABET {
        return Err(SubstitutionError::AlphabetTooLarge {
            size: alphabet_chars.len(),
        });
    }
    for (index, &symbol) in alphabet_chars.iter().enumerate() {
        if alphabet_chars
            .iter()
            .take(index)
            .any(|&previous| previous == symbol)
        {
            return Err(SubstitutionError::RepeatedAlphabetSymbol { symbol });
        }
    }
    let mut tokens = Vec::new();
    let mut pending_separator = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            pending_separator = true;
            continue;
        }
        let Some(symbol) = alphabet_chars.iter().position(|&symbol| symbol == ch) else {
            return Err(SubstitutionError::SymbolOutsideAlphabet { symbol: ch });
        };
        if pending_separator && !tokens.is_empty() {
            tokens.push(None);
        }
        pending_separator = false;
        tokens.push(Some(symbol));
    }
    if !tokens.iter().any(Option::is_some) {
        return Err(SubstitutionError::EmptyText);
    }
    Ok(SubstitutionInput {
        alphabet: alphabet_chars,
        tokens,
    })
}

/// Runs a monoalphabetic substitution search and matched null.
///
/// # Errors
/// Returns [`SubstitutionError`] if the quadgram model or a deterministic null
/// shuffle fails.
pub fn run_substitution_finish(
    input: &SubstitutionInput,
    config: &SubstitutionConfig,
) -> Result<SubstitutionReport, SubstitutionError> {
    let model = QuadgramModel::english()?;
    let symbols = input.dense_symbols();
    if symbols.is_empty() {
        return Err(SubstitutionError::EmptyText);
    }
    let observed = substitution_search(
        &symbols,
        input.alphabet.len(),
        &model,
        config.restarts,
        config.iters,
        config.seed,
    )?;
    let mut null_scores = Vec::with_capacity(config.null_trials);
    for trial in 0..config.null_trials {
        let mut decoy = symbols.clone();
        let mut rng = SplitMix64::new(mix_seed(config.seed, trial as u64 + 0x5155_4200));
        fisher_yates(&mut decoy, &mut rng)?;
        let scored = substitution_search(
            &decoy,
            input.alphabet.len(),
            &model,
            config.restarts,
            config.iters,
            mix_seed(config.seed, trial as u64 + 0x5355_4200),
        )?;
        null_scores.push(scored.best_mean);
    }
    Ok(report_from_scores(input, config, &observed, &null_scores))
}

/// Runs the planted positive and flat-control self-test.
///
/// # Errors
/// Returns [`SubstitutionError`] if parsing or search fails.
pub fn substitution_self_test(
    mut config: SubstitutionConfig,
) -> Result<SubstitutionSelfTest, SubstitutionError> {
    config.restarts = config.restarts.max(8);
    config.iters = config.iters.max(2_000);
    config.null_trials = config.null_trials.max(4);
    let planted = encipher_plant()?;
    let positive = run_substitution_finish(&planted, &config)?;
    let flat = flat_control(&planted)?;
    let flat_report = run_substitution_finish(
        &flat,
        &SubstitutionConfig {
            null_trials: config.null_trials.min(4),
            ..config
        },
    )?;
    let expected = PLANT_PLAINTEXT.to_ascii_uppercase();
    let positive_candidate = positive.verdict == SubstitutionVerdict::Candidate;
    let positive_exact = positive.plaintext == expected;
    let positive_beats_null = positive.null_ge == 0 && positive.margin_vs_null_max > 0.0;
    let flat_no_candidate = flat_report.verdict != SubstitutionVerdict::Candidate;
    Ok(SubstitutionSelfTest {
        positive_candidate,
        positive_exact,
        positive_beats_null,
        flat_no_candidate,
        passed: positive_candidate && positive_exact && positive_beats_null && flat_no_candidate,
    })
}

fn report_from_scores(
    input: &SubstitutionInput,
    config: &SubstitutionConfig,
    observed: &SubResult,
    null_scores: &[f64],
) -> SubstitutionReport {
    let null_ge = null_scores
        .iter()
        .filter(|&&score| score >= observed.best_mean)
        .count();
    let p_emp = add_one_p_value(null_ge, null_scores.len());
    let null_max = null_scores
        .iter()
        .copied()
        .fold(f64::NEG_INFINITY, f64::max);
    let min_p = 1.0 / (null_scores.len().saturating_add(1) as f64);
    let verdict = if min_p > config.alpha {
        SubstitutionVerdict::LowPowerNoExclusion
    } else if p_emp <= config.alpha {
        SubstitutionVerdict::Candidate
    } else {
        SubstitutionVerdict::NoCandidate
    };
    SubstitutionReport {
        verdict,
        symbols: input.symbol_count(),
        alphabet_size: input.alphabet.len(),
        separators: input.separator_count(),
        observed_score: observed.best_mean,
        null_max,
        null_ge,
        p_emp,
        margin_vs_null_max: observed.best_mean - null_max,
        plaintext: render_candidate(input, &observed.mapping),
        mapping: input
            .alphabet
            .iter()
            .enumerate()
            .map(|(symbol_id, &symbol)| MappingRow {
                symbol,
                letter: observed
                    .mapping
                    .get(symbol_id)
                    .and_then(|&letter| u8::try_from(letter).ok())
                    .map_or('?', |letter| char::from(b'A'.saturating_add(letter))),
            })
            .collect(),
    }
}

fn render_candidate(input: &SubstitutionInput, mapping: &[usize]) -> String {
    let mut out = String::new();
    for token in &input.tokens {
        match token {
            Some(symbol) => {
                let letter = mapping.get(*symbol).copied().unwrap_or(0);
                out.push(char::from(
                    b'A'.saturating_add(u8::try_from(letter).unwrap_or(0)),
                ));
            }
            None => out.push(' '),
        }
    }
    out
}

fn encipher_plant() -> Result<SubstitutionInput, SubstitutionError> {
    let plaintext_alphabet = "ETAOINSHRDLCUMWFGYPBVKJXQZ";
    let cipher_alphabet = PLANT_ALPHABET.chars().collect::<Vec<_>>();
    let mut text = String::new();
    for ch in PLANT_PLAINTEXT.chars() {
        if ch == ' ' {
            text.push(ch);
            continue;
        }
        let upper = ch.to_ascii_uppercase();
        let index = plaintext_alphabet
            .chars()
            .position(|letter| letter == upper)
            .unwrap_or(0);
        text.push(*cipher_alphabet.get(index).unwrap_or(&'Q'));
    }
    parse_substitution_input(&text, PLANT_ALPHABET)
}

fn flat_control(planted: &SubstitutionInput) -> Result<SubstitutionInput, SubstitutionError> {
    let mut symbols = planted.dense_symbols();
    let mut rng = SplitMix64::new(0x666c_6174_5f73_7562);
    fisher_yates(&mut symbols, &mut rng)?;
    let mut iter = symbols.into_iter();
    let tokens = planted
        .tokens
        .iter()
        .map(|token| token.map(|_symbol| iter.next().unwrap_or(0)))
        .collect();
    Ok(SubstitutionInput {
        alphabet: planted.alphabet.clone(),
        tokens,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_ALPHA, SubstitutionConfig, SubstitutionError, SubstitutionVerdict,
        parse_substitution_input, run_substitution_finish, substitution_self_test,
    };

    #[test]
    fn parser_preserves_word_separators() {
        let input = parse_substitution_input("aB  c\nA", "aBcA").expect("parse");
        assert_eq!(input.symbol_count(), 4);
        assert_eq!(input.separator_count(), 2);
        assert!(matches!(
            parse_substitution_input("ab", "aa"),
            Err(SubstitutionError::RepeatedAlphabetSymbol { symbol: 'a' })
        ));
    }

    #[test]
    fn planted_self_test_passes() {
        let report = substitution_self_test(SubstitutionConfig {
            restarts: 8,
            iters: 2_000,
            null_trials: 4,
            seed: 0x1234,
            alpha: 0.25,
        })
        .expect("self-test runs");
        assert!(report.passed, "{report:?}");
    }

    #[test]
    fn null_power_floor_is_reported() {
        let input = parse_substitution_input("QTPZX QT GSZQD TPFKTN", "QWERTYUIOPASDFGHJKLZXCVBNM")
            .expect("parse");
        let report = run_substitution_finish(
            &input,
            &SubstitutionConfig {
                restarts: 1,
                iters: 10,
                null_trials: 0,
                seed: 7,
                alpha: DEFAULT_ALPHA,
            },
        )
        .expect("run");
        assert_eq!(report.verdict, SubstitutionVerdict::LowPowerNoExclusion);
    }
}

//! Unified solve pipeline for searched-and-scored cipher hypotheses.
//!
//! This module is deliberately claim-disciplined: it searches and scores
//! hypotheses, but a high score is not a decode. Every emitted [`Candidate`]
//! carries the independent cipher round-trip, held-out mapping, and matched-null
//! gates needed by downstream renderers and candidate records.

use std::fmt;
use std::io;
use std::path::PathBuf;

use crate::ciphers::{AnyCipher, CipherError};
use crate::glyph::Glyph;
use crate::ingest::IngestError;
use crate::language::{LanguageError, LanguageModel};

/// A direct symbol-to-language-index mapping.
///
/// The table domain is the transduced cipher alphabet: entry `i` gives the
/// target [`crate::language::LanguageAlphabet`] index for cipher symbol `i`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapping {
    table: Vec<usize>,
}

impl Mapping {
    /// Builds the identity mapping `i -> i` for `cipher_alphabet_size` symbols.
    #[must_use]
    pub fn identity(cipher_alphabet_size: usize) -> Self {
        Self {
            table: (0..cipher_alphabet_size).collect(),
        }
    }

    /// Applies this mapping to a cipher-symbol stream.
    ///
    /// # Errors
    /// Returns [`SolveError::MappingSymbolOutsideTable`] if a glyph is outside
    /// the mapping domain.
    pub fn apply(&self, symbols: &[Glyph]) -> Result<Vec<usize>, SolveError> {
        let mut mapped = Vec::with_capacity(symbols.len());
        for glyph in symbols {
            let symbol = usize::from(glyph.0);
            let Some(&index) = self.table.get(symbol) else {
                return Err(SolveError::MappingSymbolOutsideTable {
                    symbol,
                    table_len: self.table.len(),
                });
            };
            mapped.push(index);
        }
        Ok(mapped)
    }

    /// Returns the raw mapping table.
    #[must_use]
    pub fn table(&self) -> &[usize] {
        &self.table
    }
}

/// Minimal codec stage for Phase 1.
///
/// The full codec family belongs to brief 04a. Phase 1 threads this enum
/// through candidates so later widening codecs have a stable field to extend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnyCodec {
    /// Pass decrypted cipher symbols through unchanged.
    Identity,
}

impl AnyCodec {
    /// Transduces decrypted cipher symbols into the mapping domain.
    #[must_use]
    pub fn transduce(self, symbols: &[Glyph]) -> Vec<Glyph> {
        match self {
            Self::Identity => symbols.to_vec(),
        }
    }
}

/// Language model used to score a candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Language {
    /// Score with the Finnish model.
    Finnish,
    /// Score with the English model.
    English,
}

/// Which language models a solve request should evaluate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LanguageChoice {
    /// Score only Finnish.
    Finnish,
    /// Score only English.
    English,
    /// Score both models, evaluating Finnish first.
    Both,
}

impl LanguageChoice {
    /// Returns the concrete scoring languages in evaluation order.
    #[must_use]
    pub fn languages(self) -> &'static [Language] {
        match self {
            Self::Finnish => &[Language::Finnish],
            Self::English => &[Language::English],
            Self::Both => &[Language::Finnish, Language::English],
        }
    }
}

/// A Phase-2 mapping-search configuration placeholder.
///
/// Phase 1 does not implement search. The variant is present so Phase 2 can add
/// hill-climb or annealing without reshaping [`HypothesisSpace`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MappingSearch {
    /// Number of random restarts.
    pub restarts: usize,
    /// Number of mapping proposals per restart.
    pub iterations: usize,
    /// Optional annealing schedule. `None` means pure hill-climb.
    pub anneal: Option<AnnealSchedule>,
    /// Deterministic seed for all mapping-search randomness.
    pub seed: u64,
}

/// Simulated-annealing schedule placeholder for Phase 2.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct AnnealSchedule {
    /// Initial acceptance temperature.
    pub start_temperature: f64,
    /// Final acceptance temperature.
    pub end_temperature: f64,
}

/// Mapping strategy for a solve request.
#[derive(Clone, Debug, PartialEq)]
pub enum MappingStrategy {
    /// Enumerate this declared fixed mapping set.
    Fixed(Vec<Mapping>),
    /// Phase-2 seam for hill-climb or annealed mapping search.
    Search(MappingSearch),
}

/// A cipher family/key search specification.
///
/// Phase 1 keeps this as a concrete list of keyed ciphers. Convenience
/// constructors for larger sampled keyspaces can layer on top without changing
/// the solve loop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CipherFamilySpec {
    /// Human-readable family label.
    pub label: String,
    /// Keyed cipher candidates to evaluate for this family.
    pub ciphers: Vec<AnyCipher>,
}

/// Cipher, mapping, and language space searched by [`solve`].
#[derive(Clone, Debug, PartialEq)]
pub struct HypothesisSpace {
    /// Cipher families and keyed candidates to evaluate.
    pub families: Vec<CipherFamilySpec>,
    /// Fixed mappings in Phase 1; search configuration in Phase 2.
    pub mappings: MappingStrategy,
    /// Language models to score, with Finnish evaluated first for [`Both`].
    ///
    /// [`Both`]: LanguageChoice::Both
    pub language: LanguageChoice,
    /// Size of the cipher alphabet expected by the request.
    pub cipher_alphabet_size: usize,
}

/// Input to the solve engine.
pub struct SolveRequest<'a> {
    /// Ciphertext glyph stream.
    pub ciphertext: &'a [Glyph],
    /// Hypothesis space to enumerate.
    pub space: HypothesisSpace,
    /// English language model.
    pub english: &'a LanguageModel,
    /// Finnish language model.
    pub finnish: &'a LanguageModel,
}

/// One scored hypothesis emitted by [`solve`].
#[derive(Clone, Debug, PartialEq)]
pub struct Candidate {
    /// Cipher family plus key that produced the decrypted symbols.
    pub cipher: AnyCipher,
    /// Cipher-layer decrypted symbols, before codec or mapping.
    pub decrypted_symbols: Vec<Glyph>,
    /// Whether `cipher.encrypt(decrypted_symbols) == ciphertext`.
    pub crypto_round_trip_ok: bool,
    /// Codec used between cipher symbols and mapping domain.
    pub codec: AnyCodec,
    /// Symbol-to-language-index mapping used for rendering and scoring.
    pub mapping: Mapping,
    /// Language model used for the reported score.
    pub language: Language,
    /// Rendered language text for the mapped indices.
    pub rendered_text: String,
    /// In-sample bigram mean log-likelihood.
    pub score: f64,
    /// Held-out mapping score on a disjoint fold.
    pub heldout_mapping_score: f64,
    /// Mean score from the matched Fisher-Yates null.
    pub null_mean: f64,
    /// Whether this candidate beats its matched null mean.
    pub beats_null: bool,
}

/// Error returned by the solve pipeline.
#[derive(Debug)]
pub enum SolveError {
    /// Language-model scoring failed.
    Language(LanguageError),
    /// Cipher construction or translation failed.
    Cipher(CipherError),
    /// External ciphertext ingest failed.
    Ingest(IngestError),
    /// A deterministic random draw could not be made for the given bound.
    RandomBoundTooLarge {
        /// Offending random bound.
        bound: usize,
    },
    /// A cipher/key failed the mandatory cipher-layer round-trip check.
    RoundTripFailed {
        /// Human-readable cipher label.
        cipher: &'static str,
    },
    /// No cipher families or mappings were supplied.
    EmptyHypothesisSpace,
    /// The fixed mapping set was empty.
    EmptyMappingSet,
    /// A mapped symbol was outside the mapping table.
    MappingSymbolOutsideTable {
        /// Offending cipher symbol.
        symbol: usize,
        /// Length of the mapping table.
        table_len: usize,
    },
    /// A ciphertext symbol was outside the declared cipher alphabet.
    CiphertextSymbolOutsideAlphabet {
        /// Offending cipher symbol.
        symbol: usize,
        /// Declared cipher alphabet size.
        alphabet_size: usize,
    },
    /// A language index could not be rendered with the selected model alphabet.
    LanguageIndexOutsideAlphabet {
        /// Offending language index.
        index: usize,
    },
    /// Mapping search is a Phase-2 feature and is not implemented in Phase 1.
    MappingSearchUnavailable,
    /// Writing a candidate record failed.
    CandidateRecordWrite {
        /// Destination path.
        path: PathBuf,
        /// Underlying I/O error.
        source: io::Error,
    },
}

impl fmt::Display for SolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Language(error) => write!(f, "language scoring failed: {error}"),
            Self::Cipher(error) => write!(f, "cipher operation failed: {error}"),
            Self::Ingest(error) => write!(f, "ciphertext ingest failed: {error}"),
            Self::RandomBoundTooLarge { bound } => {
                write!(f, "random bound {bound} is zero or too large")
            }
            Self::RoundTripFailed { cipher } => {
                write!(f, "cipher-layer round trip failed for {cipher}")
            }
            Self::EmptyHypothesisSpace => f.write_str("solve hypothesis space is empty"),
            Self::EmptyMappingSet => f.write_str("solve fixed mapping set is empty"),
            Self::MappingSymbolOutsideTable { symbol, table_len } => write!(
                f,
                "cipher symbol {symbol} is outside mapping table length {table_len}"
            ),
            Self::CiphertextSymbolOutsideAlphabet {
                symbol,
                alphabet_size,
            } => write!(
                f,
                "ciphertext symbol {symbol} is outside cipher alphabet length {alphabet_size}"
            ),
            Self::LanguageIndexOutsideAlphabet { index } => {
                write!(f, "language index {index} is outside the model alphabet")
            }
            Self::MappingSearchUnavailable => f.write_str("mapping search is reserved for Phase 2"),
            Self::CandidateRecordWrite { path, source } => {
                write!(
                    f,
                    "failed to write candidate record {}: {source}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for SolveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Language(error) => Some(error),
            Self::Cipher(error) => Some(error),
            Self::Ingest(error) => Some(error),
            Self::CandidateRecordWrite { source, .. } => Some(source),
            Self::RandomBoundTooLarge { .. }
            | Self::RoundTripFailed { .. }
            | Self::EmptyHypothesisSpace
            | Self::EmptyMappingSet
            | Self::MappingSymbolOutsideTable { .. }
            | Self::CiphertextSymbolOutsideAlphabet { .. }
            | Self::LanguageIndexOutsideAlphabet { .. }
            | Self::MappingSearchUnavailable => None,
        }
    }
}

impl From<LanguageError> for SolveError {
    fn from(error: LanguageError) -> Self {
        Self::Language(error)
    }
}

impl From<CipherError> for SolveError {
    fn from(error: CipherError) -> Self {
        Self::Cipher(error)
    }
}

impl From<IngestError> for SolveError {
    fn from(error: IngestError) -> Self {
        Self::Ingest(error)
    }
}

impl From<crate::null::RandomBoundError> for SolveError {
    fn from(error: crate::null::RandomBoundError) -> Self {
        Self::RandomBoundTooLarge { bound: error.bound }
    }
}

/// Enumerates, scores, gates, and ranks solve candidates.
///
/// Phase 1 only accepts [`MappingStrategy::Fixed`]. Phase 2 will implement the
/// [`MappingStrategy::Search`] variant without changing this public entry point.
///
/// # Errors
/// Returns [`SolveError`] if the hypothesis space is malformed or scoring cannot
/// complete.
pub fn solve(req: &SolveRequest<'_>) -> Result<Vec<Candidate>, SolveError> {
    validate_request(req)?;
    let MappingStrategy::Fixed(mappings) = &req.space.mappings else {
        return Err(SolveError::MappingSearchUnavailable);
    };

    let mut candidates = Vec::new();
    for family in &req.space.families {
        for cipher in &family.ciphers {
            candidates.extend(evaluate_cipher(req, cipher, mappings)?);
        }
    }
    candidates.sort_by(|left, right| right.score.total_cmp(&left.score));
    Ok(candidates)
}

fn validate_request(req: &SolveRequest<'_>) -> Result<(), SolveError> {
    if req
        .space
        .families
        .iter()
        .all(|family| family.ciphers.is_empty())
    {
        return Err(SolveError::EmptyHypothesisSpace);
    }
    if req.space.cipher_alphabet_size == 0 {
        return Err(SolveError::EmptyHypothesisSpace);
    }
    if matches!(&req.space.mappings, MappingStrategy::Fixed(mappings) if mappings.is_empty()) {
        return Err(SolveError::EmptyMappingSet);
    }
    validate_ciphertext_symbols(req.ciphertext, req.space.cipher_alphabet_size)
}

fn validate_ciphertext_symbols(
    ciphertext: &[Glyph],
    alphabet_size: usize,
) -> Result<(), SolveError> {
    for glyph in ciphertext {
        let symbol = usize::from(glyph.0);
        if symbol >= alphabet_size {
            return Err(SolveError::CiphertextSymbolOutsideAlphabet {
                symbol,
                alphabet_size,
            });
        }
    }
    Ok(())
}

fn evaluate_cipher(
    req: &SolveRequest<'_>,
    cipher: &AnyCipher,
    mappings: &[Mapping],
) -> Result<Vec<Candidate>, SolveError> {
    let decrypted_symbols = cipher.decrypt(req.ciphertext)?;
    let round_trip = cipher.encrypt(&decrypted_symbols)?;
    if round_trip != req.ciphertext {
        return Ok(Vec::new());
    }

    let codec = AnyCodec::Identity;
    let transduced = codec.transduce(&decrypted_symbols);
    let mut candidates = Vec::new();
    for mapping in mappings {
        let mapped = mapping.apply(&transduced)?;
        for language in req.space.language.languages() {
            candidates.push(evaluate_mapping(
                req,
                cipher,
                &decrypted_symbols,
                codec,
                mapping,
                &mapped,
                *language,
            )?);
        }
    }
    Ok(candidates)
}

fn evaluate_mapping(
    req: &SolveRequest<'_>,
    cipher: &AnyCipher,
    decrypted_symbols: &[Glyph],
    codec: AnyCodec,
    mapping: &Mapping,
    mapped: &[usize],
    language: Language,
) -> Result<Candidate, SolveError> {
    let model = model_for(req, language);
    let score = model.score_indices(mapped)?.bigram_mean_log_likelihood;
    Ok(Candidate {
        cipher: cipher.clone(),
        decrypted_symbols: decrypted_symbols.to_vec(),
        crypto_round_trip_ok: true,
        codec,
        mapping: mapping.clone(),
        language,
        rendered_text: render_indices(mapped, model)?,
        score,
        heldout_mapping_score: heldout_score(mapped, model)?,
        null_mean: 0.0,
        beats_null: false,
    })
}

fn model_for<'a>(req: &'a SolveRequest<'_>, language: Language) -> &'a LanguageModel {
    match language {
        Language::Finnish => req.finnish,
        Language::English => req.english,
    }
}

fn render_indices(indices: &[usize], model: &LanguageModel) -> Result<String, SolveError> {
    let mut rendered = String::with_capacity(indices.len());
    for index in indices {
        let Some(ch) = model.alphabet().symbol(*index) else {
            return Err(SolveError::LanguageIndexOutsideAlphabet { index: *index });
        };
        rendered.push(ch);
    }
    Ok(rendered)
}

fn heldout_score(indices: &[usize], model: &LanguageModel) -> Result<f64, SolveError> {
    let heldout = indices
        .iter()
        .copied()
        .enumerate()
        .filter_map(|(position, index)| (position % 2 == 1).then_some(index))
        .collect::<Vec<_>>();
    if heldout.is_empty() {
        return Ok(model.score_indices(indices)?.bigram_mean_log_likelihood);
    }
    Ok(model.score_indices(&heldout)?.bigram_mean_log_likelihood)
}

#[cfg(test)]
mod tests {
    use super::{
        AnyCodec, CipherFamilySpec, HypothesisSpace, Language, LanguageChoice, Mapping,
        MappingStrategy, SolveError, SolveRequest, solve,
    };
    use crate::ciphers::{AnyCipher, CaesarKey, caesar_encrypt};
    use crate::glyph::Glyph;
    use crate::language::{LanguageModel, english_model, finnish_model};

    #[test]
    fn identity_mapping_maps_symbols_to_themselves() {
        let mapping = Mapping::identity(5);
        let input = glyphs(&[0, 2, 4]);

        assert_eq!(mapping.table(), &[0, 1, 2, 3, 4]);
        assert_eq!(mapping.apply(&input).unwrap(), vec![0, 2, 4]);
    }

    #[test]
    fn mapping_rejects_symbols_outside_table() {
        let mapping = Mapping::identity(2);
        let error = mapping.apply(&glyphs(&[0, 2])).unwrap_err();

        assert!(matches!(
            error,
            SolveError::MappingSymbolOutsideTable {
                symbol: 2,
                table_len: 2,
            }
        ));
    }

    #[test]
    fn identity_codec_passes_symbols_through() {
        let input = glyphs(&[3, 1, 4]);

        assert_eq!(AnyCodec::Identity.transduce(&input), input);
    }

    #[test]
    fn fixed_mapping_caesar_plant_recovers_top_candidate() {
        let english = english_model().unwrap();
        let finnish = finnish_model().unwrap();
        let plaintext = normalized_plaintext(
            "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG",
            &english,
        );
        let key = CaesarKey::new(english.alphabet().len(), 7).unwrap();
        let ciphertext = caesar_encrypt(&plaintext, &key).unwrap();
        let request = SolveRequest {
            ciphertext: &ciphertext,
            space: HypothesisSpace {
                families: vec![CipherFamilySpec {
                    label: "Caesar".to_owned(),
                    ciphers: caesar_ciphers(english.alphabet().len()),
                }],
                mappings: MappingStrategy::Fixed(vec![Mapping::identity(english.alphabet().len())]),
                language: LanguageChoice::English,
                cipher_alphabet_size: english.alphabet().len(),
            },
            english: &english,
            finnish: &finnish,
        };

        let candidates = solve(&request).unwrap();
        let top = candidates.first().unwrap();

        assert_eq!(top.cipher, AnyCipher::Caesar(key));
        assert_eq!(top.language, Language::English);
        assert_eq!(top.decrypted_symbols, plaintext);
        assert!(top.crypto_round_trip_ok);
        assert_eq!(
            top.rendered_text,
            "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGTHEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
        );
        assert!(top.heldout_mapping_score.is_finite());
    }

    fn glyphs(values: &[u16]) -> Vec<Glyph> {
        values.iter().copied().map(Glyph).collect()
    }

    fn normalized_plaintext(text: &str, model: &LanguageModel) -> Vec<Glyph> {
        model
            .alphabet()
            .normalize_text(text)
            .unwrap()
            .into_iter()
            .map(|index| Glyph(index as u16))
            .collect()
    }

    fn caesar_ciphers(alphabet_size: usize) -> Vec<AnyCipher> {
        (0..alphabet_size)
            .map(|shift| AnyCipher::Caesar(CaesarKey::new(alphabet_size, shift).unwrap()))
            .collect()
    }
}

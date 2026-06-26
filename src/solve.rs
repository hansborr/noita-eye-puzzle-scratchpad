//! Unified solve pipeline for searched-and-scored cipher hypotheses.
//!
//! This module is deliberately claim-disciplined: it searches and scores
//! hypotheses, but a high score is not a decode. Every emitted [`Candidate`]
//! carries the independent cipher round-trip, held-out mapping, and matched-null
//! gates needed by downstream renderers and candidate records.

use std::fmt;
use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};

use crate::ciphers::{AnyCipher, CipherError};
use crate::glyph::Glyph;
use crate::ingest::IngestError;
use crate::language::{LanguageError, LanguageModel};
use crate::null::{SplitMix64, fisher_yates, mix_seed};

/// Default deterministic seed for solve matched-null controls.
pub const DEFAULT_SEED: u64 = 0x736f_6c76_6504;

/// Default number of matched-null shuffles for solve candidates.
pub const DEFAULT_NULL_TRIALS: usize = 16;

/// Minimum margin by which a *searched* candidate's in-sample bigram score must
/// beat the matched-null search mean before [`Candidate::beats_null`] is set.
///
/// The mapping search also fits shuffled noise, so the matched null is inflated
/// relative to the fixed-mapping case; a bare `>` would manufacture winners. The
/// fixed-mapping path keeps the unmargined `score > null_mean` comparison.
pub const SEARCH_BEATS_NULL_MARGIN: f64 = 0.15;

/// A direct symbol-to-language-index mapping.
///
/// The table domain is the transduced cipher alphabet: entry `i` gives the
/// target [`crate::language::LanguageAlphabet`] index for cipher symbol `i`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapping {
    table: Vec<usize>,
}

impl Mapping {
    /// Builds a mapping from an explicit table.
    #[must_use]
    pub fn from_table(table: Vec<usize>) -> Self {
        Self { table }
    }

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

/// Configuration for the Phase-2 symbol→letter mapping search.
///
/// The search hill-climbs (or anneals) a [`Mapping`] that maximizes the
/// in-sample bigram log-likelihood of the rendered text. All randomness flows
/// through a [`SplitMix64`] seeded by [`seed`](Self::seed), so a fixed seed makes
/// the whole search bit-for-bit reproducible.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MappingSearch {
    /// Number of random restarts (each escapes a different local optimum). A
    /// value of `0` is treated as a single restart.
    pub restarts: usize,
    /// Number of mapping proposals evaluated per restart.
    pub iterations: usize,
    /// Optional annealing schedule. `None` means pure hill-climb (accept only
    /// non-worsening proposals).
    pub anneal: Option<AnnealSchedule>,
    /// Deterministic seed for all mapping-search randomness.
    pub seed: u64,
}

/// Simulated-annealing schedule for [`MappingSearch`].
///
/// The acceptance temperature falls linearly from
/// [`start_temperature`](Self::start_temperature) to
/// [`end_temperature`](Self::end_temperature) across a restart's iterations.
/// A worsening proposal of size `delta < 0` is accepted with probability
/// `exp(delta / temperature)` (Metropolis); at temperature `0` the search is a
/// pure hill-climb.
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
    /// Deterministic seed for matched-null controls.
    pub seed: u64,
    /// Number of matched-null Fisher-Yates shuffles.
    pub null_trials: usize,
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
    /// A matched-null control requested zero trials.
    ZeroNullTrials,
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
            Self::ZeroNullTrials => f.write_str("solve matched null requires at least one trial"),
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
            | Self::ZeroNullTrials
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
/// Both [`MappingStrategy`] variants share the enumerate → decrypt →
/// cipher-round-trip → map → score → gate → rank skeleton. [`Fixed`] scores a
/// declared mapping set; [`Search`] hill-climbs / anneals a symbol→letter mapping
/// that maximizes the in-sample bigram log-likelihood (Phase 2). Every emitted
/// [`Candidate`] carries the three independent gates (`crypto_round_trip_ok`,
/// `heldout_mapping_score`, `beats_null`) so a renderer or candidate record can
/// report each without collapsing them: a high score is never a decode.
///
/// [`Fixed`]: MappingStrategy::Fixed
/// [`Search`]: MappingStrategy::Search
///
/// # Errors
/// Returns [`SolveError`] if the hypothesis space is malformed or scoring cannot
/// complete.
pub fn solve(req: &SolveRequest<'_>) -> Result<Vec<Candidate>, SolveError> {
    validate_request(req)?;
    let mut candidates = match &req.space.mappings {
        MappingStrategy::Fixed(mappings) => {
            let mut collected = Vec::new();
            for family in &req.space.families {
                collected.extend(evaluate_family(req, family, mappings)?);
            }
            collected
        }
        MappingStrategy::Search(search) => solve_search(req, search)?,
    };
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
    if req.space.null_trials == 0 {
        return Err(SolveError::ZeroNullTrials);
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

fn evaluate_family(
    req: &SolveRequest<'_>,
    family: &CipherFamilySpec,
    mappings: &[Mapping],
) -> Result<Vec<Candidate>, SolveError> {
    let mut candidates = Vec::new();
    for mapping in mappings {
        for language in req.space.language.languages() {
            let null_mean = matched_null_mean(req, family, mapping, *language)?;
            for cipher in &family.ciphers {
                if let Some(candidate) =
                    evaluate_cipher(req, cipher, mapping, *language, null_mean)?
                {
                    candidates.push(candidate);
                }
            }
        }
    }
    Ok(candidates)
}

fn evaluate_cipher(
    req: &SolveRequest<'_>,
    cipher: &AnyCipher,
    mapping: &Mapping,
    language: Language,
    null_mean: f64,
) -> Result<Option<Candidate>, SolveError> {
    let Some(decrypted_symbols) = decrypt_round_trip(cipher, req.ciphertext)? else {
        return Ok(None);
    };
    let codec = AnyCodec::Identity;
    let transduced = codec.transduce(&decrypted_symbols);
    let scored = score_transduced(&transduced, mapping, model_for(req, language))?;
    Ok(Some(Candidate {
        cipher: cipher.clone(),
        decrypted_symbols,
        crypto_round_trip_ok: true,
        codec,
        mapping: mapping.clone(),
        language,
        rendered_text: scored.rendered_text,
        score: scored.score,
        heldout_mapping_score: scored.heldout_mapping_score,
        null_mean,
        beats_null: scored.score > null_mean,
    }))
}

fn decrypt_round_trip(
    cipher: &AnyCipher,
    ciphertext: &[Glyph],
) -> Result<Option<Vec<Glyph>>, SolveError> {
    let decrypted_symbols = cipher.decrypt(ciphertext)?;
    let round_trip = cipher.encrypt(&decrypted_symbols)?;
    if round_trip == ciphertext {
        Ok(Some(decrypted_symbols))
    } else {
        Ok(None)
    }
}

#[derive(Clone, Debug, PartialEq)]
struct ScoredText {
    rendered_text: String,
    score: f64,
    heldout_mapping_score: f64,
}

fn score_transduced(
    transduced: &[Glyph],
    mapping: &Mapping,
    model: &LanguageModel,
) -> Result<ScoredText, SolveError> {
    let mapped = mapping.apply(transduced)?;
    Ok(ScoredText {
        rendered_text: render_indices(&mapped, model)?,
        score: model.score_indices(&mapped)?.bigram_mean_log_likelihood,
        heldout_mapping_score: heldout_score(&mapped, model)?,
    })
}

fn matched_null_mean(
    req: &SolveRequest<'_>,
    family: &CipherFamilySpec,
    mapping: &Mapping,
    language: Language,
) -> Result<f64, SolveError> {
    let model = model_for(req, language);
    let seed = mix_seed(req.space.seed, family_seed_tag(family) ^ 0x6e75_6c6c);
    let mut rng = SplitMix64::new(seed);
    let mut total = 0.0;
    for _trial in 0..req.space.null_trials {
        let mut shuffled = req.ciphertext.to_vec();
        fisher_yates(&mut shuffled, &mut rng)?;
        total += best_family_score(&shuffled, family, mapping, model)?;
    }
    Ok(total / req.space.null_trials as f64)
}

fn best_family_score(
    ciphertext: &[Glyph],
    family: &CipherFamilySpec,
    mapping: &Mapping,
    model: &LanguageModel,
) -> Result<f64, SolveError> {
    let mut best = None;
    for cipher in &family.ciphers {
        let Some(decrypted_symbols) = decrypt_round_trip(cipher, ciphertext)? else {
            continue;
        };
        let transduced = AnyCodec::Identity.transduce(&decrypted_symbols);
        let score = score_transduced(&transduced, mapping, model)?.score;
        if best.is_none_or(|previous| score > previous) {
            best = Some(score);
        }
    }
    best.ok_or(SolveError::EmptyHypothesisSpace)
}

fn family_seed_tag(family: &CipherFamilySpec) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in family.label.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
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

// ---------------------------------------------------------------------------
// Phase 2 — mapping search (hill-climb / simulated annealing).
// ---------------------------------------------------------------------------

/// Outcome of one mapping search: the best mapping found and its in-sample score.
struct MappingSearchOutcome {
    mapping: Mapping,
    score: f64,
}

/// One reversible proposal applied to a mapping table during the search.
enum Proposal {
    /// Repointed `symbol`'s target, restoring `old` on rejection.
    Repoint { symbol: usize, old: usize },
    /// Swapped the targets of symbols `a` and `b`.
    Swap { a: usize, b: usize },
}

fn solve_search(
    req: &SolveRequest<'_>,
    search: &MappingSearch,
) -> Result<Vec<Candidate>, SolveError> {
    let mut candidates = Vec::new();
    for family in &req.space.families {
        for language in req.space.language.languages() {
            let null_mean = matched_null_search_mean(req, family, *language, search)?;
            for (cipher_index, cipher) in family.ciphers.iter().enumerate() {
                if let Some(candidate) = evaluate_cipher_search(
                    req,
                    family,
                    cipher,
                    cipher_index,
                    *language,
                    null_mean,
                    search,
                )? {
                    candidates.push(candidate);
                }
            }
        }
    }
    Ok(candidates)
}

fn evaluate_cipher_search(
    req: &SolveRequest<'_>,
    family: &CipherFamilySpec,
    cipher: &AnyCipher,
    cipher_index: usize,
    language: Language,
    null_mean: f64,
    search: &MappingSearch,
) -> Result<Option<Candidate>, SolveError> {
    let Some(decrypted_symbols) = decrypt_round_trip(cipher, req.ciphertext)? else {
        return Ok(None);
    };
    let model = model_for(req, language);
    let codec = AnyCodec::Identity;
    let transduced = codec.transduce(&decrypted_symbols);
    let symbols = to_symbol_indices(&transduced, req.space.cipher_alphabet_size)?;
    let seed = search_seed(search.seed, family, cipher_index, language);

    let full = search_mapping(
        &symbols,
        req.space.cipher_alphabet_size,
        model,
        search,
        seed,
    )?;
    let mapped = full.mapping.apply(&transduced)?;
    let rendered_text = render_indices(&mapped, model)?;
    let heldout_mapping_score = heldout_search_score(
        &symbols,
        req.space.cipher_alphabet_size,
        model,
        search,
        mix_seed(seed, 0x0068_656c_646f_7574),
    )?;

    Ok(Some(Candidate {
        cipher: cipher.clone(),
        decrypted_symbols,
        crypto_round_trip_ok: true,
        codec,
        mapping: full.mapping,
        language,
        rendered_text,
        score: full.score,
        heldout_mapping_score,
        null_mean,
        beats_null: full.score >= null_mean + SEARCH_BEATS_NULL_MARGIN,
    }))
}

/// Held-out mapping gate for the searched case: search a mapping on a CONTIGUOUS
/// train fold (the first half), then score it on the disjoint second-half fold.
///
/// The split is contiguous, not alternating, so each fold keeps its bigram
/// adjacency — an alternating split would shred the very structure the bigram
/// model reads, pinning even a correct mapping at chance. An at-chance or negative
/// held-out score means the searched mapping overfit the train fold rather than
/// decoding anything — the mapping-layer analogue of the cipher round-trip, which
/// cannot validate a many-to-one (non-invertible) map.
fn heldout_search_score(
    symbols: &[usize],
    cipher_alphabet_size: usize,
    model: &LanguageModel,
    search: &MappingSearch,
    seed: u64,
) -> Result<f64, SolveError> {
    let midpoint = symbols.len() / 2;
    let (train, heldout) = symbols.split_at(midpoint);
    if train.len() < 2 || heldout.len() < 2 {
        // Too short to split; fall back to scoring the full searched mapping.
        let full = search_mapping(symbols, cipher_alphabet_size, model, search, seed)?;
        return Ok(full.score);
    }
    let trained = search_mapping(train, cipher_alphabet_size, model, search, seed)?;
    let mapped_heldout = apply_table(trained.mapping.table(), heldout)?;
    Ok(model
        .score_indices(&mapped_heldout)?
        .bigram_mean_log_likelihood)
}

/// Reruns the IDENTICAL search on `null_trials` Fisher-Yates-shuffled copies of
/// the ciphertext and returns the mean best-per-family in-sample score.
///
/// Same seed-tag discipline as the fixed-mapping null (`mix_seed(seed, tag ^
/// 0x6e75_6c6c)`), so the searched null is calibrated identically. A search on
/// shuffled symbols still fits noise, which is exactly why
/// [`SEARCH_BEATS_NULL_MARGIN`] guards [`Candidate::beats_null`].
fn matched_null_search_mean(
    req: &SolveRequest<'_>,
    family: &CipherFamilySpec,
    language: Language,
    search: &MappingSearch,
) -> Result<f64, SolveError> {
    let model = model_for(req, language);
    let shuffle_seed = mix_seed(req.space.seed, family_seed_tag(family) ^ 0x6e75_6c6c);
    let mut rng = SplitMix64::new(shuffle_seed);
    let mut total = 0.0;
    for trial in 0..req.space.null_trials {
        let mut shuffled = req.ciphertext.to_vec();
        fisher_yates(&mut shuffled, &mut rng)?;
        let trial_seed = search_seed(search.seed, family, trial, language);
        total += best_family_search_score(
            &shuffled,
            family,
            req.space.cipher_alphabet_size,
            model,
            search,
            trial_seed,
        )?;
    }
    Ok(total / req.space.null_trials as f64)
}

fn best_family_search_score(
    ciphertext: &[Glyph],
    family: &CipherFamilySpec,
    cipher_alphabet_size: usize,
    model: &LanguageModel,
    search: &MappingSearch,
    seed: u64,
) -> Result<f64, SolveError> {
    let mut best = None;
    for (cipher_index, cipher) in family.ciphers.iter().enumerate() {
        let Some(decrypted_symbols) = decrypt_round_trip(cipher, ciphertext)? else {
            continue;
        };
        let transduced = AnyCodec::Identity.transduce(&decrypted_symbols);
        let symbols = to_symbol_indices(&transduced, cipher_alphabet_size)?;
        let cipher_seed = mix_seed(seed, cipher_index as u64);
        let outcome = search_mapping(&symbols, cipher_alphabet_size, model, search, cipher_seed)?;
        if best.is_none_or(|previous| outcome.score > previous) {
            best = Some(outcome.score);
        }
    }
    best.ok_or(SolveError::EmptyHypothesisSpace)
}

/// Hill-climbs (or anneals) a symbol→letter mapping maximizing the in-sample
/// bigram mean log-likelihood of `symbols` under `model`, with multi-restart.
fn search_mapping(
    symbols: &[usize],
    cipher_alphabet_size: usize,
    model: &LanguageModel,
    cfg: &MappingSearch,
    seed: u64,
) -> Result<MappingSearchOutcome, SolveError> {
    let language_size = model.alphabet().len();
    // When the cipher alphabet fits the language alphabet a substitution is
    // injective, so the search is constrained to bijections (swap / relabel-to-
    // unused). An unconstrained many-to-one search would collapse the alphabet
    // onto a few high-probability letters and beat the model on pure noise; the
    // injective constraint keeps the in-sample objective honest. A larger cipher
    // alphabet (the 83→29 eyes) forces many-to-one, where the degeneracy is
    // symmetric with the matched null and the honest negative still holds.
    let injective = cipher_alphabet_size <= language_size;
    let ranked_letters = language_frequency_rank(model)?;
    let symbol_order = symbol_frequency_order(symbols, cipher_alphabet_size);
    let restarts = cfg.restarts.max(1);
    let mut rng = SplitMix64::new(seed);
    let mut best: Option<MappingSearchOutcome> = None;
    let mut buffer = Vec::with_capacity(symbols.len());

    for restart in 0..restarts {
        let mut table = initial_table(
            restart,
            &symbol_order,
            &ranked_letters,
            cipher_alphabet_size,
            language_size,
            &mut rng,
        )?;
        let mut current = score_table(&table, symbols, model, &mut buffer)?;
        for iteration in 0..cfg.iterations {
            let temperature = temperature_at(cfg.anneal, iteration, cfg.iterations);
            let proposal = propose(
                &mut table,
                cipher_alphabet_size,
                language_size,
                injective,
                &mut rng,
            )?;
            let proposed = score_table(&table, symbols, model, &mut buffer)?;
            let delta = proposed - current;
            if accept(delta, temperature, &mut rng) {
                current = proposed;
            } else {
                undo_proposal(&mut table, &proposal);
            }
        }
        if best
            .as_ref()
            .is_none_or(|previous| current > previous.score)
        {
            best = Some(MappingSearchOutcome {
                mapping: Mapping::from_table(table),
                score: current,
            });
        }
    }
    best.ok_or(SolveError::EmptyHypothesisSpace)
}

/// Scores a mapping `table` over the `symbols` stream (reusing `buffer` to avoid
/// per-iteration allocation in the search hot loop).
fn score_table(
    table: &[usize],
    symbols: &[usize],
    model: &LanguageModel,
    buffer: &mut Vec<usize>,
) -> Result<f64, SolveError> {
    let mapped = apply_table_into(table, symbols, buffer)?;
    Ok(model.score_indices(mapped)?.bigram_mean_log_likelihood)
}

fn apply_table_into<'b>(
    table: &[usize],
    symbols: &[usize],
    buffer: &'b mut Vec<usize>,
) -> Result<&'b [usize], SolveError> {
    buffer.clear();
    for &symbol in symbols {
        let &letter = table
            .get(symbol)
            .ok_or(SolveError::MappingSymbolOutsideTable {
                symbol,
                table_len: table.len(),
            })?;
        buffer.push(letter);
    }
    Ok(buffer)
}

fn apply_table(table: &[usize], symbols: &[usize]) -> Result<Vec<usize>, SolveError> {
    let mut buffer = Vec::with_capacity(symbols.len());
    let _slice = apply_table_into(table, symbols, &mut buffer)?;
    Ok(buffer)
}

/// Builds the initial mapping table for a restart. Restart `0` uses a
/// frequency-rank alignment (most-frequent cipher symbol → most-frequent target
/// letter); later restarts perturb that alignment with random swaps to escape its
/// basin while keeping a sensible target multiset.
fn initial_table(
    restart: usize,
    symbol_order: &[usize],
    ranked_letters: &[usize],
    cipher_alphabet_size: usize,
    language_size: usize,
    rng: &mut SplitMix64,
) -> Result<Vec<usize>, SolveError> {
    let mut table = vec![0usize; cipher_alphabet_size];
    for (rank, &symbol) in symbol_order.iter().enumerate() {
        let letter = ranked_letters
            .get(rank % language_size.max(1))
            .copied()
            .unwrap_or(0);
        if let Some(slot) = table.get_mut(symbol) {
            *slot = letter;
        }
    }
    if restart > 0 && cipher_alphabet_size >= 2 {
        for _swap in 0..cipher_alphabet_size {
            let a = crate::null::random_index_below(cipher_alphabet_size, rng)?;
            let b = crate::null::random_index_below(cipher_alphabet_size, rng)?;
            table.swap(a, b);
        }
    }
    Ok(table)
}

/// Proposes a reversible move.
///
/// In the **injective** (substitution) regime moves preserve a bijection: a swap
/// of two symbols' targets, or — when the language alphabet is wider than the
/// cipher alphabet — a relabel of one symbol to a currently-unused letter. In the
/// **many-to-one** regime (the eyes) ~20% of moves repoint a symbol to any letter
/// and ~80% swap, reaching mappings no bijection can express.
fn propose(
    table: &mut [usize],
    cipher_alphabet_size: usize,
    language_size: usize,
    injective: bool,
    rng: &mut SplitMix64,
) -> Result<Proposal, SolveError> {
    if cipher_alphabet_size < 2 {
        let target = crate::null::random_index_below(language_size.max(1), rng)?;
        let old = table.first().copied().unwrap_or(0);
        if let Some(slot) = table.first_mut() {
            *slot = target;
        }
        return Ok(Proposal::Repoint { symbol: 0, old });
    }
    if injective {
        let unused =
            (language_size > cipher_alphabet_size).then(|| unused_letters(table, language_size));
        let relabel =
            unused.as_ref().is_some_and(|set| !set.is_empty()) && rng.next_u64().is_multiple_of(2);
        if let (true, Some(set)) = (relabel, unused.as_ref()) {
            let pick = crate::null::random_index_below(set.len(), rng)?;
            let target = set.get(pick).copied().unwrap_or(0);
            let symbol = crate::null::random_index_below(cipher_alphabet_size, rng)?;
            let old = table.get(symbol).copied().unwrap_or(0);
            if let Some(slot) = table.get_mut(symbol) {
                *slot = target;
            }
            return Ok(Proposal::Repoint { symbol, old });
        }
        return swap_targets(table, cipher_alphabet_size, rng);
    }
    if rng.next_u64().is_multiple_of(5) {
        let symbol = crate::null::random_index_below(cipher_alphabet_size, rng)?;
        let target = crate::null::random_index_below(language_size.max(1), rng)?;
        let old = table.get(symbol).copied().unwrap_or(0);
        if let Some(slot) = table.get_mut(symbol) {
            *slot = target;
        }
        return Ok(Proposal::Repoint { symbol, old });
    }
    swap_targets(table, cipher_alphabet_size, rng)
}

fn swap_targets(
    table: &mut [usize],
    cipher_alphabet_size: usize,
    rng: &mut SplitMix64,
) -> Result<Proposal, SolveError> {
    let a = crate::null::random_index_below(cipher_alphabet_size, rng)?;
    let mut b = crate::null::random_index_below(cipher_alphabet_size, rng)?;
    if a == b {
        b = (b + 1) % cipher_alphabet_size;
    }
    table.swap(a, b);
    Ok(Proposal::Swap { a, b })
}

/// Returns the language letters not currently used as any symbol's target.
fn unused_letters(table: &[usize], language_size: usize) -> Vec<usize> {
    let mut used = vec![false; language_size];
    for &letter in table {
        if let Some(slot) = used.get_mut(letter) {
            *slot = true;
        }
    }
    (0..language_size)
        .filter(|letter| !used.get(*letter).copied().unwrap_or(true))
        .collect()
}

fn undo_proposal(table: &mut [usize], proposal: &Proposal) {
    match *proposal {
        Proposal::Repoint { symbol, old } => {
            if let Some(slot) = table.get_mut(symbol) {
                *slot = old;
            }
        }
        Proposal::Swap { a, b } => table.swap(a, b),
    }
}

/// Metropolis acceptance: always accept a non-worsening move; accept a worsening
/// move of size `delta < 0` with probability `exp(delta / temperature)`. At
/// temperature `0` (pure hill-climb) a worsening move is always rejected.
fn accept(delta: f64, temperature: f64, rng: &mut SplitMix64) -> bool {
    if delta >= 0.0 {
        return true;
    }
    if temperature <= 0.0 {
        return false;
    }
    let uniform = (rng.next_u64() >> 11) as f64 / ((1u64 << 53) as f64);
    (delta / temperature).exp() > uniform
}

fn temperature_at(anneal: Option<AnnealSchedule>, iteration: usize, iterations: usize) -> f64 {
    let Some(schedule) = anneal else {
        return 0.0;
    };
    if iterations <= 1 {
        return schedule.start_temperature.max(0.0);
    }
    let progress = iteration as f64 / (iterations - 1) as f64;
    let temperature = schedule.start_temperature
        + (schedule.end_temperature - schedule.start_temperature) * progress;
    temperature.max(0.0)
}

/// Ranks language indices by descending unigram log-likelihood (most-frequent
/// first), using only the public scorer (no private field access).
fn language_frequency_rank(model: &LanguageModel) -> Result<Vec<usize>, SolveError> {
    let size = model.alphabet().len();
    let mut scored = Vec::with_capacity(size);
    for index in 0..size {
        let log_likelihood = model.score_indices(&[index])?.unigram_mean_log_likelihood;
        scored.push((index, log_likelihood));
    }
    scored.sort_by(|left, right| {
        right
            .1
            .total_cmp(&left.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    Ok(scored.into_iter().map(|(index, _)| index).collect())
}

/// Orders cipher symbols by descending occurrence count in `symbols`.
fn symbol_frequency_order(symbols: &[usize], cipher_alphabet_size: usize) -> Vec<usize> {
    let mut counts = vec![0usize; cipher_alphabet_size];
    for &symbol in symbols {
        if let Some(count) = counts.get_mut(symbol) {
            *count += 1;
        }
    }
    let mut order = (0..cipher_alphabet_size).collect::<Vec<_>>();
    order.sort_by(|&left, &right| {
        counts
            .get(right)
            .copied()
            .unwrap_or(0)
            .cmp(&counts.get(left).copied().unwrap_or(0))
            .then_with(|| left.cmp(&right))
    });
    order
}

fn to_symbol_indices(
    symbols: &[Glyph],
    cipher_alphabet_size: usize,
) -> Result<Vec<usize>, SolveError> {
    let mut indices = Vec::with_capacity(symbols.len());
    for glyph in symbols {
        let symbol = usize::from(glyph.0);
        if symbol >= cipher_alphabet_size {
            return Err(SolveError::CiphertextSymbolOutsideAlphabet {
                symbol,
                alphabet_size: cipher_alphabet_size,
            });
        }
        indices.push(symbol);
    }
    Ok(indices)
}

fn search_seed(
    base: u64,
    family: &CipherFamilySpec,
    cipher_index: usize,
    language: Language,
) -> u64 {
    let family_tag = family_seed_tag(family) ^ language_tag(language);
    mix_seed(base, mix_seed(family_tag, cipher_index as u64))
}

fn language_tag(language: Language) -> u64 {
    match language {
        Language::Finnish => 0xf1_f1_f1_f1_f1_f1_f1_f1,
        Language::English => 0xe9_e9_e9_e9_e9_e9_e9_e9,
    }
}

/// Whether a [`Candidate`] clears all three independent gates and may therefore
/// be reported as a surviving HYPOTHESIS (never a decode).
///
/// This is a *derived* reporting verdict for records and tests — the three gates
/// stay separate on the [`Candidate`] and are never collapsed into a stored
/// boolean. A surviving candidate must (1) pass the cipher-layer round-trip,
/// (2) beat its matched-null search mean (the overfit guard), and (3) generalize
/// to the held-out fold above that same null mean (the mapping-confidence gate).
#[must_use]
pub fn candidate_survives(candidate: &Candidate) -> bool {
    candidate.crypto_round_trip_ok
        && candidate.beats_null
        && candidate.heldout_mapping_score > candidate.null_mean
}

// ---------------------------------------------------------------------------
// Step 9 — candidate auto-logging (mirrors gak_attack::eyes' private writer).
// ---------------------------------------------------------------------------

/// The verbatim claim ceiling reproduced in every solve candidate record. It is
/// the same ceiling the eye records carry: no record may make a stronger claim.
pub const SOLVE_CLAIM_CEILING: &str = "deterministic, engine-generated, strikingly structured data of unknown meaning; unsolved; no primary developer source confirms recoverable plaintext.";

/// The top candidate's record fields, scored under BOTH language models.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SolveRecordCandidate<'a> {
    /// Stable, display-only cipher family name.
    pub cipher_name: &'a str,
    /// Cipher-layer round-trip gate (necessary, not sufficient).
    pub crypto_round_trip_ok: bool,
    /// In-sample bigram mean log-likelihood under the candidate's language.
    pub score: f64,
    /// Held-out fold mapping score (the mapping-confidence gate).
    pub heldout_mapping_score: f64,
    /// Matched-null search mean.
    pub null_mean: f64,
    /// Matched-null overfit-guard verdict.
    pub beats_null: bool,
    /// The rendered text scored under the English model.
    pub english_bigram: f64,
    /// The rendered text scored under the Finnish model.
    pub finnish_bigram: f64,
    /// Rendered candidate text (logged verbatim for human review).
    pub rendered_text: &'a str,
    /// Whether the candidate clears all three gates ([`candidate_survives`]).
    pub survived: bool,
}

/// Inputs for one solve candidate record (keeps the writer signature small).
#[derive(Clone, Copy, Debug)]
pub struct SolveRecordInputs<'a> {
    /// Stable run/puzzle label (used in the seed-derived filename).
    pub label: &'a str,
    /// Deterministic run seed (the only filename entropy — no wall clock).
    pub seed: u64,
    /// Declared cipher alphabet size.
    pub cipher_alphabet_size: usize,
    /// Number of cipher symbols in the ciphertext.
    pub total_symbols: usize,
    /// Number of round-trip-consistent candidates the run produced.
    pub candidates_evaluated: usize,
    /// Number of candidates that cleared all three gates.
    pub survivors: usize,
    /// The top candidate, if any survived the cipher-layer round-trip.
    pub top: Option<SolveRecordCandidate<'a>>,
}

/// Builds the stable, clock-free record filename from the run label and seed.
fn solve_record_filename(label: &str, seed: u64) -> String {
    let slug: String = label
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    format!("solve-{slug}-seed-{seed:016x}.md")
}

/// Writes the mandatory solve candidate record (filename is a STABLE label/seed,
/// no clock; re-running the same config overwrites the prior record).
///
/// Returns the path written. The record carries the verbatim claim ceiling, the
/// HYPOTHESIS-not-decode label, all three gate verdicts, both language scores,
/// and any candidate cleartext verbatim for human review.
///
/// # Errors
/// Returns [`SolveError::CandidateRecordWrite`] if the directory cannot be
/// created or the file cannot be written.
pub fn write_solve_candidate_record(
    dir: &Path,
    inputs: &SolveRecordInputs<'_>,
) -> Result<PathBuf, SolveError> {
    let path = dir.join(solve_record_filename(inputs.label, inputs.seed));
    let body = render_solve_candidate_record(inputs).map_err(|_error| {
        SolveError::CandidateRecordWrite {
            path: path.clone(),
            source: io::Error::other("record formatting failed"),
        }
    })?;
    std::fs::create_dir_all(dir).map_err(|source| SolveError::CandidateRecordWrite {
        path: path.clone(),
        source,
    })?;
    std::fs::write(&path, body).map_err(|source| SolveError::CandidateRecordWrite {
        path: path.clone(),
        source,
    })?;
    Ok(path)
}

/// Renders the candidate-record markdown body (pure; unit-testable without the
/// filesystem).
///
/// # Errors
/// Returns [`std::fmt::Error`] only if a write to the in-memory string buffer
/// fails (in practice never).
pub fn render_solve_candidate_record(inputs: &SolveRecordInputs<'_>) -> Result<String, fmt::Error> {
    let mut out = String::new();
    let verdict = match inputs.top {
        Some(top) if top.survived => {
            "CANDIDATE SURVIVED ALL THREE GATES — logged as a HYPOTHESIS, NOT a decode"
        }
        _ => "NO surviving candidate — decode remains blocked",
    };
    writeln!(out, "# Solve candidate record: {}", inputs.label)?;
    writeln!(out)?;
    writeln!(
        out,
        "Stable label (NO wall-clock): label={} seed=0x{:016x} cipher-alphabet={} symbols={}",
        inputs.label, inputs.seed, inputs.cipher_alphabet_size, inputs.total_symbols
    )?;
    writeln!(out)?;
    writeln!(out, "## Verdict")?;
    writeln!(out)?;
    writeln!(out, "**{verdict}.**")?;
    writeln!(out)?;
    writeln!(
        out,
        "This record is a HYPOTHESIS, NOT a decode. solve SEARCHES and SCORES; a high"
    )?;
    writeln!(
        out,
        "score is not a decode. Round-trip-consistent candidates: {}; survivors of all three gates: {}.",
        inputs.candidates_evaluated, inputs.survivors
    )?;
    writeln!(out)?;
    writeln!(out, "## Claim ceiling (absolute)")?;
    writeln!(out)?;
    writeln!(out, "{SOLVE_CLAIM_CEILING}")?;
    writeln!(
        out,
        "Nothing in this record is stronger. A clean honest negative is a SUCCESS."
    )?;
    writeln!(out)?;
    render_solve_gates(&mut out, inputs)?;
    Ok(out)
}

fn render_solve_gates(out: &mut String, inputs: &SolveRecordInputs<'_>) -> fmt::Result {
    writeln!(out, "## Three independent gates (never collapsed)")?;
    writeln!(out)?;
    let Some(top) = inputs.top else {
        writeln!(
            out,
            "No candidate survived the cipher-layer round-trip; nothing to score."
        )?;
        return Ok(());
    };
    writeln!(out, "Top candidate cipher: {}", top.cipher_name)?;
    writeln!(
        out,
        "- Gate 1 cipher round-trip (necessary, NOT sufficient): {}",
        top.crypto_round_trip_ok
    )?;
    writeln!(
        out,
        "- Gate 2 held-out mapping score: {:.6} (matched-null mean {:.6}); generalizes: {}",
        top.heldout_mapping_score,
        top.null_mean,
        top.heldout_mapping_score > top.null_mean
    )?;
    writeln!(
        out,
        "- Gate 3 matched-null in-sample: score {:.6} vs null {:.6}; beats_null: {}",
        top.score, top.null_mean, top.beats_null
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "## Language scores (Finnish weighted at least as highly)"
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "- Finnish bigram mean log-likelihood: {:.6}",
        top.finnish_bigram
    )?;
    writeln!(
        out,
        "- English bigram mean log-likelihood: {:.6}",
        top.english_bigram
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "## Candidate cleartext (verbatim; a HYPOTHESIS, not a decode)"
    )?;
    writeln!(out)?;
    writeln!(out, "{}", top.rendered_text)?;
    Ok(())
}

/// Builds a [`SolveRecordInputs`] from a solve run and writes its record.
///
/// Scores the top candidate's rendered text under BOTH language models (Finnish
/// first), derives the survivor counts via [`candidate_survives`], and delegates
/// to [`write_solve_candidate_record`]. This is the auto-logging entry the CLI
/// and validation tests call.
///
/// # Errors
/// Returns [`SolveError`] if a language score fails or the record cannot be
/// written.
pub fn log_solve_run(
    dir: &Path,
    label: &str,
    seed: u64,
    cipher_alphabet_size: usize,
    candidates: &[Candidate],
    english: &LanguageModel,
    finnish: &LanguageModel,
) -> Result<PathBuf, SolveError> {
    let survivors = candidates.iter().filter(|c| candidate_survives(c)).count();
    let total_symbols = candidates.first().map_or(0, |c| c.decrypted_symbols.len());
    let top = match candidates.first() {
        Some(candidate) => Some(SolveRecordCandidate {
            cipher_name: candidate.cipher.name(),
            crypto_round_trip_ok: candidate.crypto_round_trip_ok,
            score: candidate.score,
            heldout_mapping_score: candidate.heldout_mapping_score,
            null_mean: candidate.null_mean,
            beats_null: candidate.beats_null,
            english_bigram: english
                .score_text(&candidate.rendered_text)?
                .bigram_mean_log_likelihood,
            finnish_bigram: finnish
                .score_text(&candidate.rendered_text)?
                .bigram_mean_log_likelihood,
            rendered_text: &candidate.rendered_text,
            survived: candidate_survives(candidate),
        }),
        None => None,
    };
    let inputs = SolveRecordInputs {
        label,
        seed,
        cipher_alphabet_size,
        total_symbols,
        candidates_evaluated: candidates.len(),
        survivors,
        top,
    };
    write_solve_candidate_record(dir, &inputs)
}

#[cfg(test)]
mod tests {
    use super::{
        AnnealSchedule, AnyCodec, CipherFamilySpec, DEFAULT_NULL_TRIALS, DEFAULT_SEED,
        HypothesisSpace, Language, LanguageChoice, Mapping, MappingSearch, MappingStrategy,
        SolveError, SolveRequest, candidate_survives, solve,
    };
    use crate::ciphers::{
        AnyCipher, CaesarKey, TranspositionKey, caesar_encrypt, transposition_encrypt,
    };
    use crate::glyph::Glyph;
    use crate::language::{LanguageModel, english_model, finnish_model};
    use crate::null::{SplitMix64, shuffled_permutation};

    /// A small-alphabet English passage over only the nine letters
    /// `{A,E,H,I,N,O,R,S,T}`, where a planted substitution is well-determined by
    /// the bigram objective and the hill-climb recovers it exactly.
    const SMALL_ALPHABET_TEXT: &str = "\
THE STONE IN THE NORTH IS AN IRON HEART AND THE HEROES REST NEAR THE SHORE \
THESE THREE SISTERS SHINE IN THE EAST AS THE RAIN STARTS A HORSE RAN INTO THE \
TENT AND THE NEST ROSE THE SAINT SENT NINE NOTES TO THE NORTH SHORE THE EARTH \
IS THIN AND THE STONES ARE HOT THIS IS THE STORE THAT THE HEROES SHARE THE \
NORTHERN STARS SHINE ON THE ROSE AND THE HEART OF IRON RESTS IN THE STONE \
THESE NINE SAINTS ENTER THE TENT AS THE RAIN OF THE EAST STARTS TO SHINE";

    /// A long English passage covering every letter many times, used to plant a
    /// searched-substitution positive control.
    const POSITIVE_CONTROL_TEXT: &str = "\
THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG WHILE FIVE WIZARDS VEX A JADED \
SPHINX OF QUARTZ NEAR THE FOGGY HARBOR EACH MORNING THE CRYPTANALYST WEIGHS \
EVERY HYPOTHESIS AGAINST A MATCHED NULL BEFORE CALLING ANY CANDIDATE A DECODE \
BECAUSE A HIGH SCORE WITHOUT HELD OUT VALIDATION IS ALMOST CERTAINLY A \
COINCIDENCE THE PATIENT JACKAL QUIETLY EXAMINED SIX BRIGHT ZEBRAS GRAZING BY \
THE WINDING RIVER AS THE WIZARD JUDGED THE VEXING PUZZLE WITH QUIET FOCUS AND \
NEVER MISTOOK A LUCKY BIGRAM FOR A GENUINE PLAINTEXT THE QUICK BROWN FOX JUMPS \
OVER THE LAZY DOG WHILE FIVE WIZARDS VEX A JADED SPHINX OF QUARTZ AND THE \
JOVIAL EXPERT KEPT WEIGHING EVIDENCE BEFORE EVERY HONEST NEGATIVE VERDICT";

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

    // Step 10(b) — letter-puzzle validation over the checked-in practice corpus.
    //
    // HONEST OUTCOME (claim discipline): the pipeline runs end-to-end, all three
    // gates fire, and the top candidate is LOGGED as a labelled HYPOTHESIS. But
    // with the bigram language model these short (~120-280 letter) single streams
    // do NOT beat the matched null and do NOT clear the held-out gate (measured:
    // even a 16x60000 anneal leaves the margin near zero and the held-out score at
    // chance). So the gates correctly REFUSE to promote them as decodes. That is
    // the candidates-README trap working as designed — a high in-sample score with
    // no held-out validation is never reported as signal — not a pipeline failure.
    // No plaintext is ever asserted (no cleartext is committed).
    #[test]
    fn letter_puzzles_run_end_to_end_and_log_as_hypotheses() {
        let english = english_model().unwrap();
        let finnish = finnish_model().unwrap();
        let dir = std::env::temp_dir().join(format!("noita-solve-letters-{}", std::process::id()));
        let _removed = std::fs::remove_dir_all(&dir);

        for (name, text) in [
            (
                "three",
                include_str!("../research/data/practice-puzzles/three"),
            ),
            (
                "four",
                include_str!("../research/data/practice-puzzles/four"),
            ),
            (
                "five",
                include_str!("../research/data/practice-puzzles/five"),
            ),
            (
                "seven",
                include_str!("../research/data/practice-puzzles/seven"),
            ),
        ] {
            let glyphs = parse_letter_puzzle(text);
            assert!(!glyphs.is_empty(), "{name} parsed to no cipher symbols");
            let request = letter_request(&glyphs, &english, &finnish, anneal_search(4, 6000, 0.02));
            let candidates = solve(&request).unwrap();
            let top = candidates.first().unwrap();

            // The pipeline ran and every gate fired (finite, computed).
            assert!(top.crypto_round_trip_ok);
            assert!(top.score.is_finite());
            assert!(top.heldout_mapping_score.is_finite());
            assert!(top.null_mean.is_finite());

            // The candidate is logged as a labelled HYPOTHESIS for human review.
            let path = super::log_solve_run(
                &dir,
                name,
                super::DEFAULT_SEED,
                26,
                &candidates,
                &english,
                &finnish,
            )
            .unwrap();
            let record = std::fs::read_to_string(&path).unwrap();
            assert!(record.contains(super::SOLVE_CLAIM_CEILING));
            assert!(record.contains("HYPOTHESIS, NOT a decode"));

            // Claim discipline: on a short single stream with a bigram model the
            // matched-null + held-out gates correctly do NOT promote a decode.
            assert!(
                !candidate_survives(top),
                "{name} unexpectedly surfaced a surviving candidate (score {}, null {}, heldout {})",
                top.score,
                top.null_mean,
                top.heldout_mapping_score
            );
        }
        let _cleanup = std::fs::remove_dir_all(&dir);
    }

    // Step 10(c) — THE EYES HONEST NEGATIVE (the single most important test).
    // Load the embedded 83-symbol reading-layer eye corpus via corpus/orders (NOT
    // /tmp), run the mapping search, and confirm it surfaces NO surviving
    // candidate: the decode REMAINS BLOCKED on the unknown symbol->meaning
    // mapping. A clean honest negative is the SUCCESS condition. Note the 83->29
    // mapping is many-to-one => non-invertible, so a cipher round-trip can hold
    // yet NO surviving candidate may exist; the held-out + matched-null gates carry
    // the load.
    #[test]
    fn eyes_search_surfaces_no_surviving_candidate() {
        let english = english_model().unwrap();
        let finnish = finnish_model().unwrap();
        let eyes = eye_reading_layer();
        assert!(eyes.len() > 100, "eye reading-layer stream looks truncated");

        let request = eye_request(&eyes, &english, &finnish, anneal_search(3, 4000, 0.02));
        let candidates = solve(&request).unwrap();

        // Identity round-trips trivially on the eyes, so candidates DO appear...
        assert!(!candidates.is_empty());
        // ...but NONE survives all three gates: the decode remains blocked.
        assert!(
            candidates
                .iter()
                .all(|candidate| !candidate_survives(candidate)),
            "the eyes unexpectedly surfaced a surviving candidate — the standing conclusion is BLOCKED"
        );
        if let Some(top) = candidates.first() {
            assert!(
                !top.beats_null,
                "the eyes beat their matched null (score {}, null {}) — investigate before claiming signal",
                top.score, top.null_mean
            );
        }

        // The honest negative is logged with the verbatim claim ceiling.
        let dir = std::env::temp_dir().join(format!("noita-solve-eyes-{}", std::process::id()));
        let _removed = std::fs::remove_dir_all(&dir);
        let path = super::log_solve_run(
            &dir,
            "eyes-reading-layer",
            super::DEFAULT_SEED,
            crate::ciphers::EYE_READING_ALPHABET_SIZE,
            &candidates,
            &english,
            &finnish,
        )
        .unwrap();
        let record = std::fs::read_to_string(&path).unwrap();
        assert!(record.contains(super::SOLVE_CLAIM_CEILING));
        assert!(record.contains("NO surviving candidate"));
        let _cleanup = std::fs::remove_dir_all(&dir);
    }

    fn parse_letter_puzzle(text: &str) -> Vec<Glyph> {
        let alphabet = crate::glyph::Alphabet::from_chars("ABCDEFGHIJKLMNOPQRSTUVWXYZ").unwrap();
        let transparent = crate::ingest::TransparentSet::default();
        crate::ingest::parse_sequence(
            text,
            crate::ingest::SequenceLayer::CipherAlphabet {
                alphabet: &alphabet,
                transparent: &transparent,
            },
        )
        .unwrap()
        .glyphs
    }

    fn eye_reading_layer() -> Vec<Glyph> {
        let grids = crate::orders::corpus_grids().unwrap();
        let order = crate::orders::accepted_honeycomb_order();
        crate::orders::read_corpus_values(&grids, order)
            .unwrap()
            .iter()
            .map(|value| Glyph(u16::from(value.get())))
            .collect()
    }

    fn letter_request<'a>(
        ciphertext: &'a [Glyph],
        english: &'a LanguageModel,
        finnish: &'a LanguageModel,
        search: MappingSearch,
    ) -> SolveRequest<'a> {
        SolveRequest {
            ciphertext,
            space: HypothesisSpace {
                families: vec![CipherFamilySpec {
                    label: "identity".to_owned(),
                    ciphers: vec![AnyCipher::Identity],
                }],
                mappings: MappingStrategy::Search(search),
                language: LanguageChoice::Both,
                cipher_alphabet_size: 26,
                seed: DEFAULT_SEED,
                null_trials: 2,
            },
            english,
            finnish,
        }
    }

    fn eye_request<'a>(
        ciphertext: &'a [Glyph],
        english: &'a LanguageModel,
        finnish: &'a LanguageModel,
        search: MappingSearch,
    ) -> SolveRequest<'a> {
        SolveRequest {
            ciphertext,
            space: HypothesisSpace {
                families: vec![CipherFamilySpec {
                    label: "identity".to_owned(),
                    ciphers: vec![AnyCipher::Identity],
                }],
                mappings: MappingStrategy::Search(search),
                language: LanguageChoice::Both,
                cipher_alphabet_size: crate::ciphers::EYE_READING_ALPHABET_SIZE,
                seed: DEFAULT_SEED,
                null_trials: 2,
            },
            english,
            finnish,
        }
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
                    ciphers: identity_plus_caesar_ciphers(english.alphabet().len()),
                }],
                mappings: MappingStrategy::Fixed(vec![Mapping::identity(english.alphabet().len())]),
                language: LanguageChoice::English,
                cipher_alphabet_size: english.alphabet().len(),
                seed: DEFAULT_SEED,
                null_trials: DEFAULT_NULL_TRIALS,
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
        assert!(top.beats_null);
        assert!(top.score - top.null_mean >= 0.10);
    }

    #[test]
    fn fixed_mapping_transposition_plant_recovers_top_candidate() {
        let english = english_model().unwrap();
        let finnish = finnish_model().unwrap();
        let plaintext = normalized_plaintext(
            "EVERY EMITTED CANDIDATE IS A HYPOTHESIS AND NOT A DECODE EVERY EMITTED CANDIDATE IS A HYPOTHESIS",
            &english,
        );
        let key = TranspositionKey::new(7, vec![3, 0, 6, 1, 5, 2, 4]).unwrap();
        let ciphertext = transposition_encrypt(&plaintext, &key).unwrap();
        let request = SolveRequest {
            ciphertext: &ciphertext,
            space: HypothesisSpace {
                families: vec![CipherFamilySpec {
                    label: "transposition".to_owned(),
                    ciphers: vec![
                        AnyCipher::Identity,
                        AnyCipher::Transposition(
                            TranspositionKey::new(7, vec![0, 1, 2, 3, 4, 5, 6]).unwrap(),
                        ),
                        AnyCipher::Transposition(key.clone()),
                    ],
                }],
                mappings: MappingStrategy::Fixed(vec![Mapping::identity(english.alphabet().len())]),
                language: LanguageChoice::English,
                cipher_alphabet_size: english.alphabet().len(),
                seed: DEFAULT_SEED,
                null_trials: DEFAULT_NULL_TRIALS,
            },
            english: &english,
            finnish: &finnish,
        };

        let candidates = solve(&request).unwrap();
        let top = candidates.first().unwrap();

        assert_eq!(top.cipher, AnyCipher::Transposition(key));
        assert_eq!(top.decrypted_symbols, plaintext);
        assert!(top.crypto_round_trip_ok);
        assert!(top.score > top.heldout_mapping_score - 1.0);
        assert!(top.beats_null);
    }

    // Step 6 — the hill-climb (+ held-out gate) surfaces a planted small-alphabet
    // substitution as a surviving candidate: it beats the matched null by a
    // comfortable margin and its held-out fold generalizes above that null. (Exact
    // recovery is left to the stronger annealed search; a bare hill-climb can stall
    // in a near-symmetric local optimum of the bigram objective.)
    #[test]
    fn hillclimb_surfaces_planted_small_alphabet_substitution() {
        let english = english_model().unwrap();
        let finnish = finnish_model().unwrap();
        let (ciphertext, size, _expected) = plant_small_alphabet(SMALL_ALPHABET_TEXT, &english);

        let request = searched_request(&ciphertext, size, &english, &finnish, hillclimb(8, 4000));
        let candidates = solve(&request).unwrap();
        let top = candidates.first().unwrap();

        assert!(top.crypto_round_trip_ok);
        assert!(top.beats_null, "score {} null {}", top.score, top.null_mean);
        assert!(
            top.score - top.null_mean >= 0.25,
            "hill-climb margin {} below the comfortable bar (score {}, null {})",
            top.score - top.null_mean,
            top.score,
            top.null_mean
        );
        assert!(
            top.heldout_mapping_score > top.null_mean,
            "heldout {} null {}",
            top.heldout_mapping_score,
            top.null_mean
        );
        assert!(candidate_survives(top));
    }

    // Step 7 + step 10(a) — the annealed full search recovers a planted 26-letter
    // substitution as the top, round-trip-consistent, held-out-validated,
    // beats-null candidate. NOTE: the bigram objective's optimum is NOT exactly
    // the true plaintext (a different permutation can score higher than genuine
    // English at this length), so this asserts substantial signal recovery — never
    // an exact decode. That gap is precisely the claim-discipline point.
    #[test]
    fn annealed_search_recovers_planted_substitution() {
        let english = english_model().unwrap();
        let finnish = finnish_model().unwrap();
        let plaintext = normalized_plaintext(POSITIVE_CONTROL_TEXT, &english);
        let size = english.alphabet().len();
        let true_table = planted_permutation(size, 0x504c_414e_5431);
        let ciphertext = plant_substitution(&plaintext, &true_table);
        let expected = expected_text(&plaintext, &english);
        let true_score = english
            .score_indices(
                &plaintext
                    .iter()
                    .map(|g| usize::from(g.0))
                    .collect::<Vec<_>>(),
            )
            .unwrap()
            .bigram_mean_log_likelihood;

        let request = searched_request(
            &ciphertext,
            size,
            &english,
            &finnish,
            anneal_search(6, 20000, 0.02),
        );
        let candidates = solve(&request).unwrap();
        let top = candidates.first().unwrap();

        assert!(top.crypto_round_trip_ok);
        assert!(top.beats_null, "score {} null {}", top.score, top.null_mean);
        assert!(top.heldout_mapping_score > top.null_mean);
        assert!(candidate_survives(top));
        // The search reaches at least the planted optimum's quality.
        assert!(
            top.score >= true_score,
            "search score {} did not reach planted true score {}",
            top.score,
            true_score
        );
        // Substantial recovery of the planted signal (deterministic for this seed).
        let matches = top
            .rendered_text
            .chars()
            .zip(expected.chars())
            .filter(|(found, truth)| found == truth)
            .count();
        let total = expected.chars().count();
        assert!(
            matches * 4 >= total * 3,
            "recovered only {matches}/{total} positions of the planted plaintext"
        );
    }

    #[test]
    fn searched_solve_is_deterministic_for_fixed_seed() {
        let english = english_model().unwrap();
        let finnish = finnish_model().unwrap();
        let plaintext = normalized_plaintext(POSITIVE_CONTROL_TEXT, &english);
        let size = english.alphabet().len();
        let mapping = planted_permutation(size, 0x504c_414e_5433);
        let ciphertext = plant_substitution(&plaintext, &mapping);

        let request = searched_request(&ciphertext, size, &english, &finnish, hillclimb(3, 1500));
        let first = solve(&request).unwrap();
        let second = solve(&request).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn searched_matched_null_stays_flat_on_shuffled_ciphertext() {
        let english = english_model().unwrap();
        let finnish = finnish_model().unwrap();
        let plaintext = normalized_plaintext(POSITIVE_CONTROL_TEXT, &english);
        let size = english.alphabet().len();
        let mapping = planted_permutation(size, 0x504c_414e_5434);
        let planted = plant_substitution(&plaintext, &mapping);

        // Destroy the bigram structure by shuffling the ciphertext once; the
        // search on noise must not manufacture a beats-null winner.
        let mut shuffled = planted;
        let mut rng = SplitMix64::new(0x0053_4855_4646_4c45);
        crate::null::fisher_yates(&mut shuffled, &mut rng).unwrap();

        let request = searched_request(&shuffled, size, &english, &finnish, hillclimb(6, 4000));
        let candidates = solve(&request).unwrap();
        let top = candidates.first().unwrap();

        assert!(
            !top.beats_null,
            "search on shuffled noise beat its matched null (score {}, null {})",
            top.score, top.null_mean
        );
        assert!(!candidate_survives(top));
    }

    // Step 9 — the record renderer is a pure string builder (no filesystem) and
    // carries the claim ceiling, the HYPOTHESIS label, all three gate verdicts,
    // and BOTH language scores.
    #[test]
    fn solve_record_renders_ceiling_label_gates_and_both_languages() {
        let top = super::SolveRecordCandidate {
            cipher_name: "Identity",
            crypto_round_trip_ok: true,
            score: -2.85,
            heldout_mapping_score: -2.96,
            null_mean: -3.22,
            beats_null: true,
            english_bigram: -2.85,
            finnish_bigram: -3.40,
            rendered_text: "THEWINDINGRIVER",
            survived: true,
        };
        let inputs = super::SolveRecordInputs {
            label: "positive-control",
            seed: super::DEFAULT_SEED,
            cipher_alphabet_size: 29,
            total_symbols: 15,
            candidates_evaluated: 3,
            survivors: 1,
            top: Some(top),
        };
        let body = super::render_solve_candidate_record(&inputs).unwrap();

        assert!(body.contains(super::SOLVE_CLAIM_CEILING));
        assert!(body.contains("HYPOTHESIS, NOT a decode"));
        assert!(body.contains("CANDIDATE SURVIVED ALL THREE GATES"));
        assert!(body.contains("Gate 1 cipher round-trip"));
        assert!(body.contains("Gate 2 held-out mapping score"));
        assert!(body.contains("beats_null: true"));
        assert!(body.contains("Finnish bigram mean log-likelihood: -3.40"));
        assert!(body.contains("English bigram mean log-likelihood: -2.85"));
        assert!(body.contains("THEWINDINGRIVER"));
    }

    #[test]
    fn solve_record_reports_honest_negative_when_no_candidate() {
        let inputs = super::SolveRecordInputs {
            label: "eyes",
            seed: super::DEFAULT_SEED,
            cipher_alphabet_size: 83,
            total_symbols: 400,
            candidates_evaluated: 0,
            survivors: 0,
            top: None,
        };
        let body = super::render_solve_candidate_record(&inputs).unwrap();

        assert!(body.contains("NO surviving candidate — decode remains blocked"));
        assert!(body.contains(super::SOLVE_CLAIM_CEILING));
        assert!(body.contains("nothing to score"));
    }

    #[test]
    fn log_solve_run_writes_seed_derived_record() {
        let english = english_model().unwrap();
        let finnish = finnish_model().unwrap();
        let (ciphertext, size, _expected) = plant_small_alphabet(SMALL_ALPHABET_TEXT, &english);
        let request = searched_request(&ciphertext, size, &english, &finnish, hillclimb(4, 2000));
        let candidates = solve(&request).unwrap();

        let dir = std::env::temp_dir().join(format!("noita-solve-rec-{}", std::process::id()));
        let _removed = std::fs::remove_dir_all(&dir);
        let path = super::log_solve_run(
            &dir,
            "small-alphabet",
            super::DEFAULT_SEED,
            size,
            &candidates,
            &english,
            &finnish,
        )
        .unwrap();

        assert!(
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("solve-small-alphabet-seed-")
        );
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains(super::SOLVE_CLAIM_CEILING));
        assert!(written.contains("Finnish bigram mean log-likelihood"));
        let _cleanup = std::fs::remove_dir_all(&dir);
    }

    fn searched_request<'a>(
        ciphertext: &'a [Glyph],
        cipher_alphabet_size: usize,
        english: &'a LanguageModel,
        finnish: &'a LanguageModel,
        search: MappingSearch,
    ) -> SolveRequest<'a> {
        SolveRequest {
            ciphertext,
            space: HypothesisSpace {
                families: vec![CipherFamilySpec {
                    label: "identity".to_owned(),
                    ciphers: vec![AnyCipher::Identity],
                }],
                mappings: MappingStrategy::Search(search),
                language: LanguageChoice::English,
                cipher_alphabet_size,
                seed: DEFAULT_SEED,
                null_trials: 3,
            },
            english,
            finnish,
        }
    }

    fn hillclimb(restarts: usize, iterations: usize) -> MappingSearch {
        MappingSearch {
            restarts,
            iterations,
            anneal: None,
            seed: DEFAULT_SEED,
        }
    }

    fn anneal_search(restarts: usize, iterations: usize, start_temperature: f64) -> MappingSearch {
        MappingSearch {
            restarts,
            iterations,
            anneal: Some(AnnealSchedule {
                start_temperature,
                end_temperature: 0.0,
            }),
            seed: DEFAULT_SEED,
        }
    }

    fn planted_permutation(size: usize, seed: u64) -> Vec<usize> {
        let mut rng = SplitMix64::new(seed);
        shuffled_permutation(size, &mut rng).unwrap()
    }

    /// Plants a substitution: builds a ciphertext whose `mapping` re-applies to the
    /// plaintext, i.e. `ciphertext[i] = mapping^{-1}(plaintext[i])`.
    fn plant_substitution(plaintext: &[Glyph], mapping: &[usize]) -> Vec<Glyph> {
        let mut inverse = vec![0usize; mapping.len()];
        for (symbol, &letter) in mapping.iter().enumerate() {
            if let Some(slot) = inverse.get_mut(letter) {
                *slot = symbol;
            }
        }
        plaintext
            .iter()
            .map(|glyph| Glyph(inverse.get(usize::from(glyph.0)).copied().unwrap_or(0) as u16))
            .collect()
    }

    /// Plants a small-alphabet substitution: assigns each distinct plaintext
    /// letter (in first-appearance order) its own cipher symbol, so the cipher
    /// alphabet is exactly the number of distinct letters used. Returns the
    /// ciphertext, that cipher-alphabet size, and the expected rendered text.
    fn plant_small_alphabet(text: &str, model: &LanguageModel) -> (Vec<Glyph>, usize, String) {
        let plaintext = normalized_plaintext(text, model);
        let mut order: Vec<usize> = Vec::new();
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        for glyph in &plaintext {
            let letter = usize::from(glyph.0);
            let symbol = if let Some(index) = order.iter().position(|&seen| seen == letter) {
                index
            } else {
                order.push(letter);
                order.len() - 1
            };
            ciphertext.push(Glyph(symbol as u16));
        }
        let expected = expected_text(&plaintext, model);
        (ciphertext, order.len(), expected)
    }

    fn expected_text(plaintext: &[Glyph], model: &LanguageModel) -> String {
        plaintext
            .iter()
            .map(|glyph| model.alphabet().symbol(usize::from(glyph.0)).unwrap())
            .collect()
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

    fn identity_plus_caesar_ciphers(alphabet_size: usize) -> Vec<AnyCipher> {
        std::iter::once(AnyCipher::Identity)
            .chain(
                (0..alphabet_size)
                    .map(|shift| AnyCipher::Caesar(CaesarKey::new(alphabet_size, shift).unwrap())),
            )
            .collect()
    }
}

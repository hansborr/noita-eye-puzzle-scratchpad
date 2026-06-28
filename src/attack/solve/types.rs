use super::*;

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
/// target [`crate::attack::language::LanguageAlphabet`] index for cipher symbol `i`.
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
    /// Codec stage between decrypted cipher symbols and the mapping domain. Phase
    /// 1 implements [`CodecStrategy::Fixed`] only; the default is a single
    /// [`AnyCodec::Identity`] (cipher alphabet already >= language alphabet).
    pub codec: CodecStrategy,
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
    /// Transparent (pass-through) marks recorded at ingest, reinserted
    /// into each candidate's [`rendered_text`](Candidate::rendered_text) at
    /// position-faithful, codec-aware spots. The cipher/codec/mapping and the
    /// bigram scorer never see these (they are not in `ciphertext`); they are
    /// readability plumbing only. Empty for the eyes and any no-transparent input,
    /// for which reinsertion is a strict no-op (rendered text byte-identical).
    pub transparent: &'a [TransparentMark],
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
    /// Whether the codec round-trips: re-expanding the transduced stream (ungroup
    /// digits / re-integrate a delta from its seed) reproduces `decrypted_symbols`.
    /// Trivially `true` for [`AnyCodec::Identity`]; an honest fourth gate alongside
    /// `crypto_round_trip_ok`.
    pub codec_round_trip_ok: bool,
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
    /// Mean full-stream score from the matched Fisher-Yates null (the overfit bar).
    pub null_mean: f64,
    /// Mean held-out fold score from the matched Fisher-Yates null — the
    /// apples-to-apples baseline the candidate's `heldout_mapping_score` must beat to
    /// count as generalizing. Computed with the same fold scheme as the candidate's
    /// held-out score (alternating for fixed mappings, contiguous for searched
    /// mappings). Comparing `heldout_mapping_score` to the full-stream `null_mean`
    /// instead (the old bug) falsely failed a true decode.
    pub null_heldout_mean: f64,
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
    /// Codec transduction failed.
    Codec(CodecError),
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
    /// The fixed codec set was empty.
    EmptyCodecSet,
    /// Retained for API stability. The codec search is implemented
    /// ([`CodecStrategy::Search`]); this variant is no longer returned.
    CodecSearchUnavailable,
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
            Self::Codec(error) => write!(f, "codec transduction failed: {error}"),
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
            Self::EmptyCodecSet => f.write_str("solve fixed codec set is empty"),
            Self::CodecSearchUnavailable => f.write_str("codec search is reserved for Phase 2"),
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
            Self::Codec(error) => Some(error),
            Self::Ingest(error) => Some(error),
            Self::CandidateRecordWrite { source, .. } => Some(source),
            Self::RandomBoundTooLarge { .. }
            | Self::RoundTripFailed { .. }
            | Self::EmptyHypothesisSpace
            | Self::ZeroNullTrials
            | Self::EmptyMappingSet
            | Self::EmptyCodecSet
            | Self::CodecSearchUnavailable
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

impl From<CodecError> for SolveError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error)
    }
}

impl From<IngestError> for SolveError {
    fn from(error: IngestError) -> Self {
        Self::Ingest(error)
    }
}

impl From<crate::nulls::null::RandomBoundError> for SolveError {
    fn from(error: crate::nulls::null::RandomBoundError) -> Self {
        Self::RandomBoundTooLarge { bound: error.bound }
    }
}

/// Candidates plus the structured codec-search skip trace.
///
/// [`CodecStrategy::Fixed`] leaves [`skipped`](Self::skipped) empty (its codecs are
/// user-declared, not pruned). [`CodecStrategy::Search`] fills it: every enumerated
/// codec that was pruned before its mapping search ran appears here with its
/// [`CodecSkipReason`], so no skip is silent (the renderer / CLI can show the full
/// enumeration trace).
#[derive(Clone, Debug, PartialEq)]
pub struct SolveOutcome {
    /// Ranked solve candidates (highest in-sample score first).
    pub candidates: Vec<Candidate>,
    /// Codecs the search enumerated but pruned, each with its skip reason.
    pub skipped: Vec<SkippedCodec>,
}

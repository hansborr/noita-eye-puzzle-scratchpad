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
use crate::codec::{
    AnyCodec, Codec, CodecError, CodecSearch, CodecSkipReason, CodecStrategy,
    DEFAULT_LANGUAGE_ALPHABET_SIZE, MAX_SEARCH_OUTPUT_ALPHABET, SkippedCodec, codec_round_trip_ok,
    enumerate_codecs, output_alphabet_hosts_language, resolved_output_alphabet_size,
};
use crate::glyph::Glyph;
use crate::ingest::{IngestError, TransparentMark};
use crate::language::{LanguageError, LanguageModel};
use crate::null::{SplitMix64, fisher_yates, mix_seed};

mod types;

pub use types::*;

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
    Ok(solve_with_codec_trace(req)?.candidates)
}

/// Like [`solve`], but also returns the codec-search skip trace ([`SolveOutcome`]).
///
/// This is the trace-bearing entry point for the codec search: `solve` is the
/// thin wrapper that discards [`SolveOutcome::skipped`]. The default
/// Identity/[`Fixed`](CodecStrategy::Fixed) path is byte-for-byte identical to the
/// pre-Phase-2 `solve` — same enumeration order, same seeds, same ranking — with
/// an empty skip trace.
///
/// # Errors
/// Returns [`SolveError`] if the hypothesis space is malformed or scoring cannot
/// complete.
pub fn solve_with_codec_trace(req: &SolveRequest<'_>) -> Result<SolveOutcome, SolveError> {
    validate_request(req)?;
    let mut outcome = match &req.space.codec {
        CodecStrategy::Fixed(codecs) => SolveOutcome {
            candidates: solve_fixed_codecs(req, codecs)?,
            skipped: Vec::new(),
        },
        CodecStrategy::Search(search) => run_codec_search(req, search)?,
    };
    outcome
        .candidates
        .sort_by(|left, right| right.score.total_cmp(&left.score));
    Ok(outcome)
}

/// The [`CodecStrategy::Fixed`] path: round-trip + score every declared codec
/// (no pruning, no search). Returns the unranked candidates; the caller sorts.
fn solve_fixed_codecs(
    req: &SolveRequest<'_>,
    codecs: &[AnyCodec],
) -> Result<Vec<Candidate>, SolveError> {
    let mut candidates = Vec::new();
    // Alphabet-size sanity (`codec::output_alphabet_hosts_language`) is intentionally
    // NOT enforced on this Fixed path: these codecs are user-declared and scored
    // as-is (round-tripped + scored only, no search). Enforcement as a pruning
    // filter is a Phase-2 codec-search concern (brief 04a step 5, under
    // `CodecStrategy::Search`), where each enumerated codec is pruned by that
    // predicate and every skip is logged.
    for codec in codecs {
        match &req.space.mappings {
            MappingStrategy::Fixed(mappings) => {
                for family in &req.space.families {
                    candidates.extend(evaluate_family(req, family, mappings, codec)?);
                }
            }
            MappingStrategy::Search(search) => {
                candidates.extend(solve_search(req, search, codec)?);
            }
        }
    }
    Ok(candidates)
}

/// The [`CodecStrategy::Search`] path (brief 04a step 5; Phase-2a selection-complete
/// null): enumerate codec parameters, prune each by alphabet-size sanity + the
/// [`MAX_SEARCH_OUTPUT_ALPHABET`] ceiling + transduce feasibility (logging every
/// skip), then run the mapping strategy on each surviving codec's transduced stream.
///
/// The matched null is computed at the **enumeration level**, not per codec: the
/// real run reports the MAX in-sample score over all surviving codecs (the caller
/// sorts and the top candidate wins), so the null must pay for that codec selection
/// too — see [`enumeration_null_mean`]. Every emitted candidate carries that one
/// null and is gated against it with the [`SEARCH_BEATS_NULL_MARGIN`] guard.
///
/// Determinism: the enumeration order is fixed and the codec-enumeration index is
/// mixed into the per-codec mapping-search seed, so the same `CodecSearch.seed`
/// reproduces the same candidates (and the null mirrors that exact derivation).
/// Returns the unranked candidates; the caller sorts.
fn run_codec_search(
    req: &SolveRequest<'_>,
    search: &CodecSearch,
) -> Result<SolveOutcome, SolveError> {
    let cipher_alphabet_size = req.space.cipher_alphabet_size;
    let (survivors, skipped) = surviving_codecs(req, search, cipher_alphabet_size);
    let mut candidates = Vec::new();
    for family in &req.space.families {
        for language in req.space.language.languages() {
            // Enumeration-level matched null (brief 04a Phase-2a fix): the
            // SELECTION-COMPLETE bar. The real run reports the MAX in-sample score
            // over ALL surviving codecs, so a per-codec null — which maxes over
            // ciphers within ONE codec only — is OPTIMISTIC once >1 codec survives
            // (it never pays for codec selection). This null reruns the IDENTICAL
            // surviving-codec enumeration on each shuffle and maxes over every
            // (surviving codec × mapping × cipher), so every Search candidate is gated
            // against the max-over-codecs-on-noise bar. With exactly one survivor it
            // equals the old per-codec null byte-for-byte (a pure re-aggregation).
            let null_mean = enumeration_null_mean(req, family, *language, search, &survivors)?;
            for (index, codec) in &survivors {
                match &req.space.mappings {
                    MappingStrategy::Fixed(mappings) => {
                        for mapping in mappings {
                            for cipher in &family.ciphers {
                                if let Some(candidate) = evaluate_cipher(
                                    req, cipher, mapping, *language, null_mean, codec,
                                )? {
                                    candidates
                                        .push(stamp_enumeration_beats_null(candidate, null_mean));
                                }
                            }
                        }
                    }
                    MappingStrategy::Search(mapping_search) => {
                        // Mix the codec-enumeration index into the mapping-search seed
                        // so distinct codecs explore distinct (still deterministic)
                        // random streams; the null mirrors this exact derivation.
                        let derived = codec_search_mapping(mapping_search, search.seed, *index);
                        for (cipher_index, cipher) in family.ciphers.iter().enumerate() {
                            if let Some(candidate) = evaluate_cipher_search(
                                req,
                                family,
                                cipher,
                                cipher_index,
                                *language,
                                null_mean,
                                &derived,
                                codec,
                            )? {
                                candidates.push(stamp_enumeration_beats_null(candidate, null_mean));
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(SolveOutcome {
        candidates,
        skipped,
    })
}

/// Enumerates the codec search space and applies the three prunes (alphabet-size
/// sanity, output-alphabet ceiling, transduce feasibility), returning the surviving
/// codecs (each paired with its enumeration index, which seeds the per-codec
/// mapping search) and the structured skip trace.
///
/// The real run and the enumeration-level null share this exact survivor set so the
/// null reruns the IDENTICAL enumeration. The prunes are content-independent: sanity
/// and ceiling depend only on the codec parameters, and (since every cipher family
/// is length-preserving and Fisher-Yates preserves both length and alphabet) a
/// shuffled ciphertext transduces iff the original does — so the survivor set is the
/// same on every shuffle.
fn surviving_codecs(
    req: &SolveRequest<'_>,
    search: &CodecSearch,
    cipher_alphabet_size: usize,
) -> (Vec<(usize, AnyCodec)>, Vec<SkippedCodec>) {
    let mut survivors = Vec::new();
    let mut skipped = Vec::new();
    // The binding fixed-mapping domain (smallest declared mapping table). `None`
    // for a mapping SEARCH, whose tables are sized to each codec's resolved output
    // and therefore impose no domain prune. This is content-independent (it depends
    // only on the declared mappings), so the survivor set is identical on every
    // null shuffle — preserving the shared-enumeration invariant the null relies on.
    let fixed_mapping_domain = match &req.space.mappings {
        MappingStrategy::Fixed(mappings) => mappings.iter().map(|m| m.table().len()).min(),
        MappingStrategy::Search(_) => None,
    };
    for (index, codec) in enumerate_codecs(search, cipher_alphabet_size)
        .into_iter()
        .enumerate()
    {
        // Prune (a) — alphabet-size sanity. CRITICAL (D2 landmine): resolve the true
        // mapping domain via `output_alphabet_hosts_language` /
        // `resolved_output_alphabet_size`; NEVER the bare `Codec::output_alphabet_size`
        // trait method, which returns the 0 passthrough sentinel for `Identity` and
        // would wrongly prune it (see codec.rs).
        if !output_alphabet_hosts_language(
            &codec,
            cipher_alphabet_size,
            DEFAULT_LANGUAGE_ALPHABET_SIZE,
        ) {
            skipped.push(SkippedCodec {
                reason: CodecSkipReason::SanityTooSmall {
                    resolved: resolved_output_alphabet_size(&codec, cipher_alphabet_size),
                    language: DEFAULT_LANGUAGE_ALPHABET_SIZE,
                },
                codec,
            });
            continue;
        }
        // Prune (b) — output-alphabet ceiling (documented cap; too wide to map
        // honestly), again resolved (never the bare trait sentinel).
        let resolved = resolved_output_alphabet_size(&codec, cipher_alphabet_size);
        if resolved > MAX_SEARCH_OUTPUT_ALPHABET {
            skipped.push(SkippedCodec {
                reason: CodecSkipReason::CeilingTooWide {
                    resolved,
                    ceiling: MAX_SEARCH_OUTPUT_ALPHABET,
                },
                codec,
            });
            continue;
        }
        // Prune (c) — transduce feasibility. All seven cipher families are
        // length-preserving, so the ciphertext length is exactly the decrypted
        // length, and its symbols share the cipher alphabet (0..base) with any
        // decrypted stream; a codec that cannot transduce the ciphertext (e.g. a
        // grouping whose group_len does not divide the stream) is logged-and-skipped
        // rather than silently truncating or aborting the whole search.
        if codec.transduce(req.ciphertext).is_err() {
            skipped.push(SkippedCodec {
                reason: CodecSkipReason::Untransducible,
                codec,
            });
            continue;
        }
        // Prune (d) — fixed-mapping domain (defense-in-depth). A `CodecStrategy::Search`
        // can be paired with an explicit `MappingStrategy::Fixed` whose table is sized
        // to the BARE cipher alphabet; a widening codec then emits symbols past that
        // table. Skip-with-log (mirroring the prunes above) instead of letting
        // `Mapping::apply` hard-error with `MappingSymbolOutsideTable`. Only a fixed
        // mapping imposes this domain — a mapping search sizes its tables to `resolved`,
        // so `fixed_mapping_domain` is `None` there and this prune is inert.
        if let Some(mapping_domain) = fixed_mapping_domain.filter(|&domain| resolved > domain) {
            skipped.push(SkippedCodec {
                reason: CodecSkipReason::MappingDomainMismatch {
                    resolved,
                    mapping_domain,
                },
                codec,
            });
            continue;
        }
        survivors.push((index, codec));
    }
    (survivors, skipped)
}

/// Derives the per-codec [`MappingSearch`] for the codec at enumeration `index`:
/// mixes the codec-enumeration index into the mapping-search seed so distinct codecs
/// explore distinct (still deterministic) random streams. Shared by the real run and
/// [`enumeration_null_mean`] so the null's per-codec search seeds mirror the real run
/// exactly.
fn codec_search_mapping(
    mapping_search: &MappingSearch,
    codec_search_seed: u64,
    index: usize,
) -> MappingSearch {
    MappingSearch {
        seed: mix_seed(
            mapping_search.seed,
            mix_seed(codec_search_seed, index as u64),
        ),
        ..*mapping_search
    }
}

/// Re-stamps a [`CodecStrategy::Search`] candidate's `beats_null` against the
/// enumeration-level null with the [`SEARCH_BEATS_NULL_MARGIN`] guard.
///
/// Every candidate emitted from the codec search is gated against the
/// max-over-codecs-on-noise bar (the codec enumeration is itself a selection), so
/// the margin applies uniformly — including the fixed-mapping sub-path, whose
/// stand-alone [`CodecStrategy::Fixed`] null uses the bare `score > null_mean`
/// comparison. The candidate already carries the enumeration null in `null_mean`; this
/// only recomputes the verdict.
fn stamp_enumeration_beats_null(mut candidate: Candidate, null_mean: f64) -> Candidate {
    candidate.beats_null = candidate.score >= null_mean + SEARCH_BEATS_NULL_MARGIN;
    candidate
}

/// Enumeration-level matched null for [`CodecStrategy::Search`] (brief 04a Phase-2a
/// fix): the SELECTION-COMPLETE bar that pays for codec selection.
///
/// The real run reports the MAX in-sample score over all surviving codecs (the caller
/// sorts and the top candidate wins), so a per-codec null — which maxes over ciphers
/// within ONE codec only — is OPTIMISTIC once more than one codec survives. This
/// reruns the IDENTICAL surviving-codec enumeration on each of `null_trials`
/// Fisher-Yates shuffles and takes the MAX score over every (surviving codec ×
/// mapping × cipher) per shuffle, then averages those maxima.
///
/// Determinism mirrors the per-codec null EXACTLY — the same per-family shuffle seed
/// (`family_seed_tag ^ 0x6e75_6c6c`, the null tag, distinct from the real run's
/// seeds) and the same codec-index-derived mapping-search seeds — so this is a pure
/// RE-AGGREGATION of the same per-`(trial, codec)` scores: max-over-codecs-per-shuffle
/// instead of mean-within-each-codec. With exactly one surviving codec (and one fixed
/// mapping) it therefore equals the old per-codec null byte-for-byte.
fn enumeration_null_mean(
    req: &SolveRequest<'_>,
    family: &CipherFamilySpec,
    language: Language,
    search: &CodecSearch,
    survivors: &[(usize, AnyCodec)],
) -> Result<f64, SolveError> {
    if survivors.is_empty() {
        return Ok(0.0);
    }
    let model = model_for(req, language);
    let shuffle_seed = mix_seed(req.space.seed, family_seed_tag(family) ^ 0x6e75_6c6c);
    let mut rng = SplitMix64::new(shuffle_seed);
    let mut total = 0.0;
    for trial in 0..req.space.null_trials {
        let mut shuffled = req.ciphertext.to_vec();
        fisher_yates(&mut shuffled, &mut rng)?;
        // MAX over all surviving codecs for this shuffle — the codec selection the
        // real run performs (top-of-N-codecs wins).
        let mut trial_best: Option<f64> = None;
        for (index, codec) in survivors {
            let score = match &req.space.mappings {
                MappingStrategy::Fixed(mappings) => {
                    best_codec_fixed_null_score(&shuffled, family, mappings, model, codec)?
                }
                MappingStrategy::Search(mapping_search) => {
                    let derived = codec_search_mapping(mapping_search, search.seed, *index);
                    let trial_seed = search_seed(derived.seed, family, trial, language);
                    best_family_search_score(
                        &shuffled,
                        family,
                        req.space.cipher_alphabet_size,
                        model,
                        &derived,
                        trial_seed,
                        codec,
                    )?
                }
            };
            trial_best = Some(trial_best.map_or(score, |best| best.max(score)));
        }
        if let Some(best) = trial_best {
            total += best;
        }
    }
    Ok(total / req.space.null_trials as f64)
}

/// Best fixed-mapping in-sample score for one codec on a (shuffled) stream, maxed
/// over the declared mapping set × the cipher family. The enumeration null maxes this
/// over codecs in turn, mirroring the real run's selection across (codec × mapping ×
/// cipher).
fn best_codec_fixed_null_score(
    ciphertext: &[Glyph],
    family: &CipherFamilySpec,
    mappings: &[Mapping],
    model: &LanguageModel,
    codec: &AnyCodec,
) -> Result<f64, SolveError> {
    let mut best: Option<f64> = None;
    for mapping in mappings {
        let score = best_family_score(ciphertext, family, mapping, model, codec)?;
        best = Some(best.map_or(score, |previous: f64| previous.max(score)));
    }
    best.ok_or(SolveError::EmptyMappingSet)
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
    if matches!(&req.space.codec, CodecStrategy::Fixed(codecs) if codecs.is_empty()) {
        return Err(SolveError::EmptyCodecSet);
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
    codec: &AnyCodec,
) -> Result<Vec<Candidate>, SolveError> {
    let mut candidates = Vec::new();
    for mapping in mappings {
        for language in req.space.language.languages() {
            let null_mean = matched_null_mean(req, family, mapping, *language, codec)?;
            for cipher in &family.ciphers {
                if let Some(candidate) =
                    evaluate_cipher(req, cipher, mapping, *language, null_mean, codec)?
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
    codec: &AnyCodec,
) -> Result<Option<Candidate>, SolveError> {
    let Some(decrypted_symbols) = decrypt_round_trip(cipher, req.ciphertext)? else {
        return Ok(None);
    };
    let transduced = codec.transduce(&decrypted_symbols)?;
    let scored = score_transduced(&transduced, mapping, model_for(req, language))?;
    let rendered_text = reinsert_transparent(&scored.rendered_text, req.transparent, codec);
    Ok(Some(Candidate {
        cipher: cipher.clone(),
        crypto_round_trip_ok: true,
        codec_round_trip_ok: codec_round_trip_ok(codec, &decrypted_symbols),
        decrypted_symbols,
        codec: codec.clone(),
        mapping: mapping.clone(),
        language,
        rendered_text,
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
    codec: &AnyCodec,
) -> Result<f64, SolveError> {
    let model = model_for(req, language);
    let seed = mix_seed(req.space.seed, family_seed_tag(family) ^ 0x6e75_6c6c);
    let mut rng = SplitMix64::new(seed);
    let mut total = 0.0;
    for _trial in 0..req.space.null_trials {
        let mut shuffled = req.ciphertext.to_vec();
        fisher_yates(&mut shuffled, &mut rng)?;
        total += best_family_score(&shuffled, family, mapping, model, codec)?;
    }
    Ok(total / req.space.null_trials as f64)
}

fn best_family_score(
    ciphertext: &[Glyph],
    family: &CipherFamilySpec,
    mapping: &Mapping,
    model: &LanguageModel,
    codec: &AnyCodec,
) -> Result<f64, SolveError> {
    let mut best = None;
    for cipher in &family.ciphers {
        let Some(decrypted_symbols) = decrypt_round_trip(cipher, ciphertext)? else {
            continue;
        };
        let transduced = codec.transduce(&decrypted_symbols)?;
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

/// Reinserts transparent (pass-through) marks into a rendered candidate string at
/// position-faithful, **codec-aware** spots.
///
/// A [`TransparentMark::position`] is in the ORIGINAL char coordinate (cipher
/// symbols + transparent chars interleaved). The cipher-glyph stream excludes the
/// transparent chars, and a length-changing codec (e.g. [`AnyCodec::FixedGrouping`])
/// compresses it further, so each mark is mapped in three hops:
///
/// 1. original position → cipher-stream index = the number of cipher glyphs
///    strictly before it. Marks arrive in ascending position order, so for the
///    `i`-th mark exactly `i` transparent chars precede it; the cipher index is
///    therefore `position - i`.
/// 2. cipher-stream index → rendered-char index through the codec length transform
///    ([`rendered_index_for_cipher_index`]): `Identity` is 1:1; a grouping codec
///    DIVIDES by `group_len`; a delta codec drops its seed (length −1) before its
///    inner codec.
/// 3. a mark that falls MID-GROUP is **snapped to the nearest group boundary** —
///    the exact intra-group offset is lost to grouping, so spaces are reinserted at
///    group-boundary granularity (documented honestly, never silently).
///
/// BEHAVIOR-PRESERVING: with no marks (the eyes; any no-transparent input) this is a
/// strict no-op and returns `rendered` unchanged byte-for-byte.
fn reinsert_transparent(rendered: &str, marks: &[TransparentMark], codec: &AnyCodec) -> String {
    if marks.is_empty() {
        return rendered.to_owned();
    }
    let rendered_chars: Vec<char> = rendered.chars().collect();
    let rendered_len = rendered_chars.len();
    // Each mark's snapped rendered-char index (monotonic non-decreasing in
    // position), clamped into `0..=rendered_len` so a trailing mark lands at the end.
    let targets: Vec<usize> = marks
        .iter()
        .enumerate()
        .map(|(index, mark)| {
            let cipher_index = mark.position.saturating_sub(index);
            rendered_index_for_cipher_index(codec, cipher_index).min(rendered_len)
        })
        .collect();
    let mut out = String::with_capacity(rendered.len() + marks.len());
    let mut mark_idx = 0usize;
    for r in 0..=rendered_len {
        while targets.get(mark_idx).is_some_and(|&target| target == r) {
            if let Some(mark) = marks.get(mark_idx) {
                out.push(mark.ch);
            }
            mark_idx = mark_idx.saturating_add(1);
        }
        if let Some(&ch) = rendered_chars.get(r) {
            out.push(ch);
        }
    }
    out
}

/// Maps a cipher-stream index to the rendered-char index it precedes, through a
/// codec's length transform (the snap-to-nearest-group-boundary rule for grouping).
///
/// - [`AnyCodec::Identity`] is 1:1 (no length change).
/// - [`AnyCodec::FixedGrouping`] divides by `group_len`, rounding to the NEAREST
///   group boundary (`round(cipher_index / group_len)`): a mark inside a group has
///   no exact rendered position, so it snaps to the closer boundary.
/// - [`AnyCodec::Delta`] drops the seed symbol (length −1: a leading mark snaps to
///   index 0), then recurses into the inner codec.
fn rendered_index_for_cipher_index(codec: &AnyCodec, cipher_index: usize) -> usize {
    match codec {
        AnyCodec::Identity => cipher_index,
        AnyCodec::FixedGrouping(grouping) => {
            let group_len = grouping.group_len.max(1);
            // round(cipher_index / group_len) = floor((cipher_index + group_len/2) / group_len).
            cipher_index
                .saturating_add(group_len / 2)
                .checked_div(group_len)
                .unwrap_or(cipher_index)
        }
        AnyCodec::Delta(delta) => {
            rendered_index_for_cipher_index(&delta.then, cipher_index.saturating_sub(1))
        }
    }
}

// NOTE: this FIXED-mapping held-out helper scores ALTERNATING (odd) positions,
// whereas the SEARCH path (`heldout_search_score`) uses CONTIGUOUS folds. The
// difference is deliberate and behavior-preserving: the fixed path applies ONE
// already-given mapping (no re-fit), so the held-out score is purely
// informational and its alternating value is pinned byte-for-byte by the
// `solve_caesar_s123_nt4` golden fixture — switching it to contiguous would
// silently change that committed number. The search path instead RE-FITS a
// mapping on the train fold, so it needs contiguous folds to keep bigram
// adjacency intact (an alternating split would shred the very structure the
// re-fit must generalize).
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
    codec: &AnyCodec,
) -> Result<Vec<Candidate>, SolveError> {
    let mut candidates = Vec::new();
    for family in &req.space.families {
        for language in req.space.language.languages() {
            let null_mean = matched_null_search_mean(req, family, *language, search, codec)?;
            for (cipher_index, cipher) in family.ciphers.iter().enumerate() {
                if let Some(candidate) = evaluate_cipher_search(
                    req,
                    family,
                    cipher,
                    cipher_index,
                    *language,
                    null_mean,
                    search,
                    codec,
                )? {
                    candidates.push(candidate);
                }
            }
        }
    }
    Ok(candidates)
}

// The codec stage threads an extra dimension through the established search
// pipeline; the params are the existing pipeline shape plus `codec`, so bundling
// them into a context struct would obscure rather than clarify.
#[allow(
    clippy::too_many_arguments,
    reason = "Phase-1 codec wiring adds one codec parameter to the existing search path"
)]
fn evaluate_cipher_search(
    req: &SolveRequest<'_>,
    family: &CipherFamilySpec,
    cipher: &AnyCipher,
    cipher_index: usize,
    language: Language,
    null_mean: f64,
    search: &MappingSearch,
    codec: &AnyCodec,
) -> Result<Option<Candidate>, SolveError> {
    let Some(decrypted_symbols) = decrypt_round_trip(cipher, req.ciphertext)? else {
        return Ok(None);
    };
    let model = model_for(req, language);
    let transduced = codec.transduce(&decrypted_symbols)?;
    // The mapping search domain is the codec's output alphabet (Identity resolves
    // back to the cipher alphabet size, keeping the eyes path byte-for-byte).
    let mapping_domain = resolved_output_alphabet_size(codec, req.space.cipher_alphabet_size);
    let symbols = to_symbol_indices(&transduced, mapping_domain)?;
    let seed = search_seed(search.seed, family, cipher_index, language);

    let full = search_mapping(&symbols, mapping_domain, model, search, seed)?;
    let mapped = full.mapping.apply(&transduced)?;
    let rendered_text =
        reinsert_transparent(&render_indices(&mapped, model)?, req.transparent, codec);
    let heldout_mapping_score = heldout_search_score(
        &symbols,
        mapping_domain,
        model,
        search,
        mix_seed(seed, 0x0068_656c_646f_7574),
    )?;

    Ok(Some(Candidate {
        cipher: cipher.clone(),
        crypto_round_trip_ok: true,
        codec_round_trip_ok: codec_round_trip_ok(codec, &decrypted_symbols),
        decrypted_symbols,
        codec: codec.clone(),
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
    codec: &AnyCodec,
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
            codec,
        )?;
    }
    Ok(total / req.space.null_trials as f64)
}

#[allow(
    clippy::too_many_arguments,
    reason = "Phase-1 codec wiring adds one codec parameter to the existing search path"
)]
fn best_family_search_score(
    ciphertext: &[Glyph],
    family: &CipherFamilySpec,
    cipher_alphabet_size: usize,
    model: &LanguageModel,
    search: &MappingSearch,
    seed: u64,
    codec: &AnyCodec,
) -> Result<f64, SolveError> {
    let mut best = None;
    let mapping_domain = resolved_output_alphabet_size(codec, cipher_alphabet_size);
    for (cipher_index, cipher) in family.ciphers.iter().enumerate() {
        let Some(decrypted_symbols) = decrypt_round_trip(cipher, ciphertext)? else {
            continue;
        };
        let transduced = codec.transduce(&decrypted_symbols)?;
        let symbols = to_symbol_indices(&transduced, mapping_domain)?;
        let cipher_seed = mix_seed(seed, cipher_index as u64);
        let outcome = search_mapping(&symbols, mapping_domain, model, search, cipher_seed)?;
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
#[allow(
    clippy::struct_excessive_bools,
    reason = "record DTO: codec/cipher round-trip, beats-null, and survived are four independent gate verdicts surfaced verbatim, not a packed state machine"
)]
pub struct SolveRecordCandidate<'a> {
    /// Stable, display-only cipher family name.
    pub cipher_name: &'a str,
    /// Stable, display-only codec family name ([`Codec::name`]): the transduction
    /// stage between the decrypted cipher symbols and the symbol->letter mapping.
    pub codec_name: &'a str,
    /// Codec round-trip gate (the fourth structural check, alongside the cipher
    /// round-trip): re-expanding the transduced stream reproduces the decrypted
    /// symbols. Like the cipher round-trip it proves only codec/cipher consistency,
    /// never a decode.
    pub codec_round_trip_ok: bool,
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
    /// The exact, copy-pasteable command that reproduces this record; clock-free;
    /// the D2 reproducibility guarantee.
    pub provenance: &'a str,
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
    writeln!(out, "## Provenance (reproducible)")?;
    writeln!(out)?;
    writeln!(out, "{}", inputs.provenance)?;
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
        "Top candidate codec: {} (the transduction stage; codec round-trip below)",
        top.codec_name
    )?;
    writeln!(
        out,
        "- Gate 1 cipher round-trip (necessary, NOT sufficient): {}",
        top.crypto_round_trip_ok
    )?;
    writeln!(
        out,
        "- Gate 1b codec round-trip (codec/cipher consistency, NOT a decode): {}",
        top.codec_round_trip_ok
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
/// `total_symbols` is the ciphertext length (cipher-symbol count), passed by the
/// caller so the record header reports it even on the zero-candidate honest
/// negative — it must not be derived from `candidates.first()`, which is empty
/// then. Every cipher family is length-preserving, so on the has-candidate path
/// this equals the top candidate's `decrypted_symbols.len()`.
///
/// `provenance` is the exact, clock-free command that reproduces this record (the
/// D2 reproducibility guarantee); it is threaded verbatim into the record's
/// Provenance section.
///
/// # Errors
/// Returns [`SolveError`] if a language score fails or the record cannot be
/// written.
// The args are the auto-log's cohesive inputs (record dir + run identity/shape +
// provenance command + candidates + both language models); defect-3's
// `total_symbols` count and defect-D2's `provenance` string push this to 9.
// Bundling them into a context struct would obscure rather than clarify.
#[allow(
    clippy::too_many_arguments,
    reason = "auto-log inputs: dir + run identity/shape (incl. defect-3 total_symbols + defect-D2 provenance) + candidates + both models"
)]
pub fn log_solve_run(
    dir: &Path,
    label: &str,
    seed: u64,
    cipher_alphabet_size: usize,
    total_symbols: usize,
    provenance: &str,
    candidates: &[Candidate],
    english: &LanguageModel,
    finnish: &LanguageModel,
) -> Result<PathBuf, SolveError> {
    let survivors = candidates.iter().filter(|c| candidate_survives(c)).count();
    let top = match candidates.first() {
        Some(candidate) => Some(SolveRecordCandidate {
            cipher_name: candidate.cipher.name(),
            codec_name: candidate.codec.name(),
            codec_round_trip_ok: candidate.codec_round_trip_ok,
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
        provenance,
        candidates_evaluated: candidates.len(),
        survivors,
        top,
    };
    write_solve_candidate_record(dir, &inputs)
}

#[cfg(test)]
mod tests {
    use super::{
        AnnealSchedule, AnyCodec, CipherFamilySpec, Codec, CodecStrategy, DEFAULT_NULL_TRIALS,
        DEFAULT_SEED, HypothesisSpace, Language, LanguageChoice, Mapping, MappingSearch,
        MappingStrategy, SolveError, SolveRequest, candidate_survives, enumeration_null_mean,
        solve, solve_with_codec_trace, surviving_codecs,
    };
    use crate::ciphers::{
        AnyCipher, CaesarKey, TranspositionKey, caesar_encrypt, transposition_encrypt,
    };
    use crate::codec::{
        CodecSearch, CodecSkipReason, DeltaCodec, DigitOrder, GroupingCodec,
        MAX_SEARCH_OUTPUT_ALPHABET,
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
                include_str!("../../../research/data/practice-puzzles/three"),
            ),
            (
                "four",
                include_str!("../../../research/data/practice-puzzles/four"),
            ),
            (
                "five",
                include_str!("../../../research/data/practice-puzzles/five"),
            ),
            (
                "seven",
                include_str!("../../../research/data/practice-puzzles/seven"),
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
                glyphs.len(),
                "test: letter-puzzle log_solve_run",
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
            // Pin the REASON the honest negative holds, not just the verdict: the
            // re-fit mapping does NOT generalize to the held-out fold, so its
            // held-out score sits BELOW the matched-null mean. (Direction only —
            // no brittle exact float — so it locks the reason against silent
            // drift while staying robust to search-config tweaks.)
            assert!(
                top.heldout_mapping_score < top.null_mean,
                "eyes held-out score {} unexpectedly reached/beat the null mean {}",
                top.heldout_mapping_score,
                top.null_mean
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
            eyes.len(),
            "test: eyes honest-negative log_solve_run",
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

    // ===================================================================
    // Step 9 (Phase-2b capstone) — corpus codec/grouping samples one/two/six.
    //
    // Each runs the CHECKED-IN corpus file (NEVER /tmp) end-to-end through
    // CodecStrategy::Search + MappingStrategy::Search and auto-logs the best
    // candidate as a labelled HYPOTHESIS. HONEST FRAMING (binding): the streams
    // are SHORT and the transduced alphabets are MANY-TO-ONE vs the 29-letter
    // language, so a candidate may LEGITIMATELY FAIL to beat the matched null —
    // exactly like the eyes honest-negative. These tests therefore assert ONLY
    // that the pipeline runs, the four gate verdicts are computed/recorded, and a
    // record is logged as a HYPOTHESIS; they NEVER assert a hard-coded plaintext
    // and NEVER require beats-null. Provenance: EXTERNAL samples (see
    // research/data/practice-puzzles/README.md); no cleartext is committed.
    // ===================================================================

    fn parse_corpus_puzzle(text: &str, alphabet: &str) -> crate::ingest::ParsedSequence {
        let alphabet = crate::glyph::Alphabet::from_chars(alphabet).expect("corpus alphabet");
        let transparent = crate::ingest::TransparentSet::default();
        crate::ingest::parse_sequence(
            text,
            crate::ingest::SequenceLayer::CipherAlphabet {
                alphabet: &alphabet,
                transparent: &transparent,
            },
        )
        .expect("corpus parse")
    }

    fn corpus_codec_request<'a>(
        parsed: &'a crate::ingest::ParsedSequence,
        cipher_alphabet_size: usize,
        english: &'a LanguageModel,
        finnish: &'a LanguageModel,
    ) -> SolveRequest<'a> {
        SolveRequest {
            ciphertext: &parsed.glyphs,
            transparent: &parsed.transparent,
            space: HypothesisSpace {
                // Identity-only family keeps the test fast; the committed records
                // use the CLI's identity+caesar default. The codec SEARCH is the
                // unit under test, not the cipher family.
                families: vec![CipherFamilySpec {
                    label: "identity".to_owned(),
                    ciphers: vec![AnyCipher::Identity],
                }],
                codec: CodecStrategy::Search(CodecSearch {
                    max_group_len: 3,
                    try_delta: true,
                    orders: vec![DigitOrder::Msb, DigitOrder::Lsb],
                    seed: DEFAULT_SEED,
                }),
                mappings: MappingStrategy::Search(hillclimb(2, 400)),
                language: LanguageChoice::Both,
                cipher_alphabet_size,
                seed: DEFAULT_SEED,
                null_trials: 2,
            },
            english,
            finnish,
        }
    }

    // `one`: 266 digits {0..4}, the ±1-C5 walk. EXPECTED HONEST NEGATIVE — but the
    // binding constraint is TRANSDUCE FEASIBILITY, not the sanity floor/ceiling.
    // group_len 1/2 fail the 29-symbol sanity floor (5, 25 < 29); group_len 3
    // (5³ = 125) DOES clear BOTH that floor and the 256 output-alphabet ceiling, yet
    // 266 = 2·7·19 is not divisible by 3, so the grouping cannot partition the stream
    // (transduce-feasibility prune (c) → Untransducible). The delta variants
    // difference first: the 265 = 5·53 move stream is divisible by neither 2 nor 3,
    // so no in-budget (group_len ≤ 3) codec partitions it either. EVERY enumerated
    // codec is therefore logged-and-skipped. The ±1-C5 structure is a documented
    // Delta SEARCH HINT (an observed ciphertext property), never a decode or
    // triviality claim. NO hard-coded decode asserted.
    #[test]
    fn corpus_one_runs_end_to_end_and_logs_hypothesis() {
        let english = english_model().unwrap();
        let finnish = finnish_model().unwrap();
        let parsed = parse_corpus_puzzle(
            include_str!("../../../research/data/practice-puzzles/one"),
            "01234",
        );
        assert_eq!(parsed.glyphs.len(), 266);
        assert!(
            !parsed.transparent.iter().any(|mark| mark.ch == ' '),
            "puzzle one has no word-boundary spaces (a pure ±1-C5 walk)"
        );

        let request = corpus_codec_request(&parsed, 5, &english, &finnish);
        let outcome = solve_with_codec_trace(&request).unwrap();

        assert!(
            outcome.candidates.is_empty(),
            "one has no in-budget codec that both hosts the language and partitions \
             the 266-digit (or differenced 265) stream"
        );
        // The skips are LOGGED, never silently dropped (no-silent-truncation).
        assert!(
            !outcome.skipped.is_empty(),
            "every pruned codec must be surfaced in the skip trace"
        );

        let dir = std::env::temp_dir().join(format!("noita-corpus-one-{}", std::process::id()));
        let _removed = std::fs::remove_dir_all(&dir);
        let path = super::log_solve_run(
            &dir,
            "one",
            super::DEFAULT_SEED,
            5,
            parsed.glyphs.len(),
            "test: corpus one log_solve_run",
            &outcome.candidates,
            &english,
            &finnish,
        )
        .unwrap();
        let record = std::fs::read_to_string(&path).unwrap();
        assert!(record.contains(super::SOLVE_CLAIM_CEILING));
        assert!(record.contains("NO surviving candidate"));
        // Defect 3 regression: the header reports the REAL ciphertext length (266),
        // not 0, even though there are no candidates to derive it from.
        assert_eq!(outcome.candidates.len(), 0);
        assert!(
            record.contains("symbols=266"),
            "zero-candidate record must still report the 266-symbol ciphertext length"
        );
        let _cleanup = std::fs::remove_dir_all(&dir);
    }

    // `two`: 698 letters {A..L}. group_len 2 (12²=144 ≥ 29) survives on the even
    // stream; group_len 1 (12 < 29) and group_len 3 (12³=1728 > ceiling) are
    // logged-and-skipped. The pipeline runs end-to-end and the best candidate is
    // logged as a HYPOTHESIS. NO hard-coded decode asserted (two's English is known
    // to the maintainer but WITHHELD; see the pending exact-match test below).
    #[test]
    fn corpus_two_runs_end_to_end_and_logs_hypothesis() {
        let english = english_model().unwrap();
        let finnish = finnish_model().unwrap();
        let parsed = parse_corpus_puzzle(
            include_str!("../../../research/data/practice-puzzles/two"),
            "ABCDEFGHIJKL",
        );
        assert_eq!(parsed.glyphs.len(), 698);
        assert!(
            !parsed.transparent.iter().any(|mark| mark.ch == ' '),
            "puzzle two has no word-boundary spaces"
        );

        let request = corpus_codec_request(&parsed, 12, &english, &finnish);
        let outcome = solve_with_codec_trace(&request).unwrap();
        assert!(
            !outcome.candidates.is_empty(),
            "two should surface candidates"
        );
        assert!(!outcome.skipped.is_empty(), "pruned codecs must be logged");

        let top = outcome.candidates.first().unwrap();
        // All four gate verdicts are computed (the pipeline ran end-to-end).
        assert!(top.crypto_round_trip_ok);
        assert!(
            top.codec_round_trip_ok,
            "pair grouping round-trips on the even stream"
        );
        assert!(top.score.is_finite());
        assert!(top.heldout_mapping_score.is_finite());
        assert!(top.null_mean.is_finite());

        let dir = std::env::temp_dir().join(format!("noita-corpus-two-{}", std::process::id()));
        let _removed = std::fs::remove_dir_all(&dir);
        let path = super::log_solve_run(
            &dir,
            "two",
            super::DEFAULT_SEED,
            12,
            parsed.glyphs.len(),
            "test: corpus two log_solve_run",
            &outcome.candidates,
            &english,
            &finnish,
        )
        .unwrap();
        let record = std::fs::read_to_string(&path).unwrap();
        assert!(record.contains(super::SOLVE_CLAIM_CEILING));
        assert!(record.contains("HYPOTHESIS"));
        assert!(record.contains("codec round-trip"));
        let _cleanup = std::fs::remove_dir_all(&dir);
    }

    // `two` exact-match regression: PENDING the maintainer's WITHHELD cleartext.
    // Puzzle two's English is known to the maintainer but deliberately NOT committed
    // (so the engine cannot be tuned to it). This test exercises the recovery PATH
    // but the exact-match assertion stays PENDING that withheld constant — it must
    // NOT pretend to know the plaintext. Promote to a real known-answer regression
    // only once a human confirms the recovered candidate against ground truth, then:
    //   const EXPECTED: &str = "<maintainer-confirmed puzzle-two cleartext>";
    //   assert_eq!(top.rendered_text, EXPECTED);
    #[test]
    #[ignore = "pending the maintainer's WITHHELD puzzle-two cleartext (not committed; promote to a known-answer regression once a human confirms it)"]
    fn corpus_two_exact_match_pending_withheld_cleartext() {
        let english = english_model().unwrap();
        let finnish = finnish_model().unwrap();
        let parsed = parse_corpus_puzzle(
            include_str!("../../../research/data/practice-puzzles/two"),
            "ABCDEFGHIJKL",
        );
        let request = corpus_codec_request(&parsed, 12, &english, &finnish);
        let top_text = solve_with_codec_trace(&request)
            .unwrap()
            .candidates
            .into_iter()
            .next()
            .map(|candidate| candidate.rendered_text);
        // A candidate the human can compare against the WITHHELD ground truth. The
        // exact-match assertion is intentionally absent until that constant lands.
        assert!(top_text.is_some());
    }

    // `six`: 417 digits {1..6} WITH preserved spaces — the transparent-passthrough
    // case. 417 is ODD, so FixedGrouping{2,6} cannot partition it and is logged
    // Untransducible; the transducible base-6 groupings (group_len 3 → 216, or
    // Delta-of-pair over the 416 differenced moves → 36) survive and host the
    // language. The best candidate is logged as a HYPOTHESIS and its rendered_text
    // SHOWS the reinserted spaces; the bigram scorer SKIPS them. NO hard-coded
    // decode asserted.
    #[test]
    fn corpus_six_grouping_reinserts_spaces_and_logs_hypothesis() {
        let english = english_model().unwrap();
        let finnish = finnish_model().unwrap();
        let parsed = parse_corpus_puzzle(
            include_str!("../../../research/data/practice-puzzles/six"),
            "123456",
        );
        assert_eq!(parsed.glyphs.len(), 417);
        assert!(
            !parsed.transparent.is_empty(),
            "puzzle six preserves word-boundary spaces and blank-line newlines"
        );

        let request = corpus_codec_request(&parsed, 6, &english, &finnish);
        let outcome = solve_with_codec_trace(&request).unwrap();
        assert!(
            !outcome.candidates.is_empty(),
            "six should surface a transducible base-6 grouping candidate"
        );
        assert!(
            !outcome.skipped.is_empty(),
            "pruned codecs (incl. group_len 2, untransducible on the odd 417) must be logged"
        );

        let top = outcome.candidates.first().unwrap();
        assert!(top.crypto_round_trip_ok);
        assert!(top.codec_round_trip_ok);

        // The preserved spaces are reinserted into rendered_text at their
        // (group-boundary-snapped) positions.
        assert!(
            top.rendered_text.contains(' '),
            "six's preserved spaces must survive into rendered_text"
        );

        // ...and the bigram scorer SKIPS them: the candidate's score (computed on the
        // space-free mapped indices) equals re-scoring the SPACED rendered_text under
        // the same model, because normalize_text strips the transparent chars.
        let model: &LanguageModel = match top.language {
            Language::Finnish => &finnish,
            Language::English => &english,
        };
        let rescored = model
            .score_text(&top.rendered_text)
            .unwrap()
            .bigram_mean_log_likelihood;
        assert!(
            (rescored - top.score).abs() < 1e-6,
            "scorer must skip transparent chars (rescored {rescored} vs score {})",
            top.score
        );

        let dir = std::env::temp_dir().join(format!("noita-corpus-six-{}", std::process::id()));
        let _removed = std::fs::remove_dir_all(&dir);
        let path = super::log_solve_run(
            &dir,
            "six",
            super::DEFAULT_SEED,
            6,
            parsed.glyphs.len(),
            "test: corpus six log_solve_run",
            &outcome.candidates,
            &english,
            &finnish,
        )
        .unwrap();
        let record = std::fs::read_to_string(&path).unwrap();
        assert!(record.contains(super::SOLVE_CLAIM_CEILING));
        assert!(record.contains("HYPOTHESIS"));
        // The reinserted spaces appear in the logged cleartext too.
        assert!(record.contains(' '));
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
            transparent: &[],
            space: HypothesisSpace {
                families: vec![CipherFamilySpec {
                    label: "identity".to_owned(),
                    ciphers: vec![AnyCipher::Identity],
                }],
                codec: CodecStrategy::Fixed(vec![AnyCodec::Identity]),
                mappings: MappingStrategy::Search(search),
                language: LanguageChoice::Both,
                cipher_alphabet_size: 26,
                seed: DEFAULT_SEED,
                null_trials: 5,
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
            transparent: &[],
            space: HypothesisSpace {
                families: vec![CipherFamilySpec {
                    label: "identity".to_owned(),
                    ciphers: vec![AnyCipher::Identity],
                }],
                codec: CodecStrategy::Fixed(vec![AnyCodec::Identity]),
                mappings: MappingStrategy::Search(search),
                language: LanguageChoice::Both,
                cipher_alphabet_size: crate::ciphers::EYE_READING_ALPHABET_SIZE,
                seed: DEFAULT_SEED,
                null_trials: 5,
            },
            english,
            finnish,
        }
    }

    #[test]
    fn identity_codec_passes_symbols_through() {
        let input = glyphs(&[3, 1, 4]);

        assert_eq!(AnyCodec::Identity.transduce(&input).unwrap(), input);
    }

    // Part 1 — transparent-space reinsertion (brief 04a step 9). A
    // `TransparentMark.position` is in the ORIGINAL char coordinate; the cipher
    // stream excludes those chars and a grouping codec compresses it, so each mark
    // is mapped original-position -> cipher index -> rendered index (snapped to the
    // nearest group boundary for grouping). With no marks it is a strict no-op.
    #[test]
    fn reinsert_transparent_places_spaces_under_identity_and_grouping() {
        // Original "AB CD EF": cipher glyphs at 0,1,3,4,6,7; spaces at 2 and 5.
        let marks = [
            crate::ingest::TransparentMark {
                ch: ' ',
                position: 2,
            },
            crate::ingest::TransparentMark {
                ch: ' ',
                position: 5,
            },
        ];

        // Identity (1:1): spaces land before rendered chars 2 and 4 — exactly the
        // original word boundaries.
        assert_eq!(
            super::reinsert_transparent("ABCDEF", &marks, &AnyCodec::Identity),
            "AB CD EF"
        );

        // A base-anything pair grouping compresses 6 cipher glyphs -> 3 rendered
        // chars; each original word (2 digits) becomes one letter, so the spaces
        // fall on the group boundaries -> "X Y Z".
        let pair = AnyCodec::FixedGrouping(GroupingCodec {
            group_len: 2,
            base: 6,
            order: DigitOrder::Msb,
            stride: 2,
        });
        assert_eq!(super::reinsert_transparent("XYZ", &marks, &pair), "X Y Z");

        // Mid-group snap: a space at original position 3 ("ABC DEF") sits INSIDE the
        // second pair (cipher index 3, group boundaries at 0,2,4,6); it snaps to the
        // nearest boundary (rendered index 2) -> "XY Z". The exact intra-group offset
        // is intentionally lost to grouping (documented honestly).
        let mid = [crate::ingest::TransparentMark {
            ch: ' ',
            position: 3,
        }];
        assert_eq!(super::reinsert_transparent("XYZ", &mid, &pair), "XY Z");

        // BEHAVIOR-PRESERVING: no marks => byte-identical passthrough (the eyes).
        assert_eq!(
            super::reinsert_transparent("ABCDEF", &[], &AnyCodec::Identity),
            "ABCDEF"
        );
    }

    // Step 4 — synthetic plant-through-codec positive control (fixed codec).
    // Plant: English (language indices 0..28) -> expand each letter into TWO base-6
    // digits (MSB) -> a base-6 digit stream -> Caesar(base 6, shift 2) -> ciphertext.
    // solve with the matching FixedGrouping{2,6,Msb,2} + the known grouped-value ->
    // letter mapping recovers the planted English as the TOP, codec+cipher
    // round-trip-consistent candidate. (A direct 6-symbol substitution could never
    // host 29 letters; the codec widens 6 -> 6^2 = 36 >= 29 first.)
    #[test]
    fn fixed_grouping_plant_recovers_planted_english() {
        let english = english_model().unwrap();
        let finnish = finnish_model().unwrap();
        let base = 6usize;
        let group_len = 2usize;
        let language_size = english.alphabet().len(); // 29 <= 36 = 6^2

        let plaintext_indices = english
            .alphabet()
            .normalize_text(
                "THE NORTHERN STARS SHINE ON THE ROSE AND THE HEART OF IRON RESTS IN THE STONE \
                 THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG NEAR THE FOGGY HARBOR EVERY MORNING",
            )
            .unwrap();

        // Inverse codec: expand each language index into group_len base-6 digits (MSB).
        let mut digits: Vec<Glyph> = Vec::with_capacity(plaintext_indices.len() * group_len);
        for &index in &plaintext_indices {
            digits.push(Glyph((index / base) as u16));
            digits.push(Glyph((index % base) as u16));
        }

        // Known cipher: Caesar over base 6, shift 2.
        let key = CaesarKey::new(base, 2).unwrap();
        let ciphertext = caesar_encrypt(&digits, &key).unwrap();

        // Known mapping: grouped value v (0..36) -> language index v for v < size.
        // The planted English only produces v == index < size, so it renders exactly.
        let mapping = Mapping::from_table(
            (0..base.pow(group_len as u32))
                .map(|value| if value < language_size { value } else { 0 })
                .collect(),
        );
        let codec = AnyCodec::FixedGrouping(GroupingCodec {
            group_len,
            base,
            order: DigitOrder::Msb,
            stride: group_len,
        });

        let request = SolveRequest {
            ciphertext: &ciphertext,
            transparent: &[],
            space: HypothesisSpace {
                families: vec![CipherFamilySpec {
                    label: "Caesar".to_owned(),
                    ciphers: identity_plus_caesar_ciphers(base),
                }],
                codec: CodecStrategy::Fixed(vec![codec]),
                mappings: MappingStrategy::Fixed(vec![mapping]),
                language: LanguageChoice::English,
                cipher_alphabet_size: base,
                seed: DEFAULT_SEED,
                null_trials: DEFAULT_NULL_TRIALS,
            },
            english: &english,
            finnish: &finnish,
        };

        let candidates = solve(&request).unwrap();
        let top = candidates.first().unwrap();

        // Recovered as the TOP, codec+cipher round-trip-consistent candidate.
        assert_eq!(top.cipher, AnyCipher::Caesar(key));
        assert!(top.crypto_round_trip_ok);
        assert!(top.codec_round_trip_ok);
        assert!(top.beats_null, "score {} null {}", top.score, top.null_mean);

        // The rendered text is exactly the planted English (letters, no spaces).
        let expected: String = plaintext_indices
            .iter()
            .map(|&index| english.alphabet().symbol(index).unwrap())
            .collect();
        assert_eq!(top.rendered_text, expected);
    }

    // Step 5 — the codec SEARCH enumerates grouping codecs, prunes the ones that
    // cannot host the language (or explode past the ceiling), and on the survivors
    // runs the established per-codec evaluation. Here it must DISCOVER the planted
    // base-6 pair grouping (and its MSB order) and rank the correct codec + cipher
    // + known mapping to the top, reproducing the EXACT planted English. (The
    // 6-symbol cipher alphabet cannot host 29 letters directly; the search widens
    // 6 -> 6^2 = 36 >= 29 by enumerating group_len.)
    #[test]
    fn codec_search_recovers_planted_fixed_grouping() {
        let english = english_model().unwrap();
        let finnish = finnish_model().unwrap();
        let base = 6usize;
        let group_len = 2usize;
        let (ciphertext, key, plaintext_indices) = plant_base6_pair_english(&english);
        let mapping = grouped_value_identity_mapping(&english);

        let request = SolveRequest {
            ciphertext: &ciphertext,
            transparent: &[],
            space: HypothesisSpace {
                families: vec![CipherFamilySpec {
                    label: "Caesar".to_owned(),
                    ciphers: identity_plus_caesar_ciphers(base),
                }],
                // group_len 1 (Identity, 6 < 29) is sanity-skipped; group_len 2
                // survives for both orders, and only the MSB order recovers English.
                codec: CodecStrategy::Search(CodecSearch {
                    max_group_len: 2,
                    try_delta: false,
                    orders: vec![DigitOrder::Msb, DigitOrder::Lsb],
                    seed: DEFAULT_SEED,
                }),
                mappings: MappingStrategy::Fixed(vec![mapping]),
                language: LanguageChoice::English,
                cipher_alphabet_size: base,
                seed: DEFAULT_SEED,
                null_trials: DEFAULT_NULL_TRIALS,
            },
            english: &english,
            finnish: &finnish,
        };

        let outcome = solve_with_codec_trace(&request).unwrap();
        let top = outcome.candidates.first().unwrap();

        // The winning codec is exactly the planted base-6 MSB pair grouping.
        assert_eq!(
            top.codec,
            AnyCodec::FixedGrouping(GroupingCodec {
                group_len,
                base,
                order: DigitOrder::Msb,
                stride: group_len,
            })
        );
        assert_eq!(top.cipher, AnyCipher::Caesar(key));
        assert!(top.crypto_round_trip_ok);
        assert!(top.codec_round_trip_ok);
        assert!(top.beats_null, "score {} null {}", top.score, top.null_mean);

        let expected: String = plaintext_indices
            .iter()
            .map(|&index| english.alphabet().symbol(index).unwrap())
            .collect();
        assert_eq!(top.rendered_text, expected);

        // group_len 1 (Identity over the 6-symbol alphabet) was logged-and-skipped
        // for failing alphabet-size sanity — never silently dropped.
        assert!(outcome.skipped.iter().any(|skip| {
            skip.codec == AnyCodec::Identity
                && matches!(skip.reason, CodecSkipReason::SanityTooSmall { .. })
        }));
    }

    // Step 5 — bounded + logged: an out-of-budget codec is surfaced in the skip
    // trace with its reason, not silently dropped. base 5, max_group_len 4 yields
    // both prune reasons: group_len 1/2 (5, 25 < 29) -> SanityTooSmall; group_len 4
    // (5^4 = 625 > 256 ceiling) -> CeilingTooWide; only group_len 3 (125) survives.
    #[test]
    fn codec_search_logs_and_skips_out_of_budget_codecs() {
        let english = english_model().unwrap();
        let finnish = finnish_model().unwrap();
        // A length divisible by 3 so the surviving group_len-3 codec transduces.
        let ciphertext = glyphs(&[0, 1, 2, 3, 4, 0, 1, 2, 3, 4, 0, 1]);
        let request = SolveRequest {
            ciphertext: &ciphertext,
            transparent: &[],
            space: HypothesisSpace {
                families: vec![CipherFamilySpec {
                    label: "identity".to_owned(),
                    ciphers: vec![AnyCipher::Identity],
                }],
                codec: CodecStrategy::Search(CodecSearch {
                    max_group_len: 4,
                    try_delta: false,
                    orders: vec![DigitOrder::Msb],
                    seed: DEFAULT_SEED,
                }),
                mappings: MappingStrategy::Fixed(vec![Mapping::from_table(
                    (0..MAX_SEARCH_OUTPUT_ALPHABET).map(|_| 0usize).collect(),
                )]),
                language: LanguageChoice::English,
                cipher_alphabet_size: 5,
                seed: DEFAULT_SEED,
                null_trials: 2,
            },
            english: &english,
            finnish: &finnish,
        };

        let outcome = solve_with_codec_trace(&request).unwrap();

        // Both prune reasons appear in the structured trace (logged, not dropped).
        assert!(
            outcome
                .skipped
                .iter()
                .any(|skip| matches!(skip.reason, CodecSkipReason::SanityTooSmall { .. })),
            "expected a SanityTooSmall skip in {:?}",
            outcome.skipped
        );
        assert!(
            outcome.skipped.iter().any(|skip| matches!(
                skip.reason,
                CodecSkipReason::CeilingTooWide {
                    resolved: 625,
                    ceiling: MAX_SEARCH_OUTPUT_ALPHABET,
                }
            )),
            "expected a CeilingTooWide(625) skip in {:?}",
            outcome.skipped
        );
        // The surviving group_len-3 codec still produced candidates.
        assert!(!outcome.candidates.is_empty());
    }

    // Defect-1(b) defense-in-depth — a `CodecStrategy::Search` paired with an
    // EXPLICIT `MappingStrategy::Fixed` whose table is sized to the BARE cipher
    // alphabet must SKIP-WITH-LOG (not hard-error) every widening codec the mapping
    // cannot host. Without this prune the group_len-2 grouping (6² = 36) would feed
    // 36-valued symbols to a 6-entry mapping table and `Mapping::apply` would return
    // `MappingSymbolOutsideTable`, aborting the whole search. (The CLI never reaches
    // here — it auto-enables the mapping search under `--codec-search`.)
    #[test]
    fn codec_search_skips_codec_too_wide_for_fixed_mapping() {
        let english = english_model().unwrap();
        let finnish = finnish_model().unwrap();
        let base = 6usize;
        // Length divisible by 2 so the group_len-2 codec is otherwise transducible:
        // its skip must be the MAPPING-domain prune, not Untransducible.
        let ciphertext = glyphs(&[0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 5]);
        let request = SolveRequest {
            ciphertext: &ciphertext,
            transparent: &[],
            space: HypothesisSpace {
                families: vec![CipherFamilySpec {
                    label: "identity".to_owned(),
                    ciphers: vec![AnyCipher::Identity],
                }],
                codec: CodecStrategy::Search(CodecSearch {
                    max_group_len: 2,
                    try_delta: false,
                    orders: vec![DigitOrder::Msb],
                    seed: DEFAULT_SEED,
                }),
                // Domain == the bare 6-symbol cipher alphabet — too small to host the
                // group_len-2 widening (36 symbols).
                mappings: MappingStrategy::Fixed(vec![Mapping::identity(base)]),
                language: LanguageChoice::English,
                cipher_alphabet_size: base,
                seed: DEFAULT_SEED,
                null_trials: 2,
            },
            english: &english,
            finnish: &finnish,
        };

        // The whole point: it returns Ok (skips-with-log), it does NOT hard-error
        // with MappingSymbolOutsideTable.
        let outcome = solve_with_codec_trace(&request).unwrap();

        // group_len 2 (6² = 36 > the 6-entry mapping domain) is logged as a
        // MappingDomainMismatch, never silently dropped nor hard-errored.
        assert!(
            outcome.skipped.iter().any(|skip| matches!(
                skip.reason,
                CodecSkipReason::MappingDomainMismatch {
                    resolved: 36,
                    mapping_domain: 6,
                }
            )),
            "expected a MappingDomainMismatch(36, 6) skip in {:?}",
            outcome.skipped
        );
        // group_len 1 (Identity, 6 < 29) is the sanity-floor skip; with both codecs
        // pruned there is no survivor and thus no candidate — but NO error.
        assert!(
            outcome
                .skipped
                .iter()
                .any(|skip| matches!(skip.reason, CodecSkipReason::SanityTooSmall { .. })),
            "expected a SanityTooSmall skip in {:?}",
            outcome.skipped
        );
        assert!(outcome.candidates.is_empty());
    }

    #[test]
    fn codec_search_is_deterministic_for_fixed_seed() {
        let english = english_model().unwrap();
        let finnish = finnish_model().unwrap();
        let base = 6usize;
        let (ciphertext, _key, _indices) = plant_base6_pair_english(&english);
        let mapping = grouped_value_identity_mapping(&english);
        let request = SolveRequest {
            ciphertext: &ciphertext,
            transparent: &[],
            space: HypothesisSpace {
                families: vec![CipherFamilySpec {
                    label: "Caesar".to_owned(),
                    ciphers: identity_plus_caesar_ciphers(base),
                }],
                codec: CodecStrategy::Search(CodecSearch {
                    max_group_len: 2,
                    try_delta: true,
                    orders: vec![DigitOrder::Msb, DigitOrder::Lsb],
                    seed: DEFAULT_SEED,
                }),
                mappings: MappingStrategy::Fixed(vec![mapping]),
                language: LanguageChoice::Both,
                cipher_alphabet_size: base,
                seed: DEFAULT_SEED,
                null_trials: 3,
            },
            english: &english,
            finnish: &finnish,
        };

        let first = solve_with_codec_trace(&request).unwrap();
        let second = solve_with_codec_trace(&request).unwrap();
        assert_eq!(first, second);
    }

    // Step 6 (brief 04a Phase-2a) — the ENUMERATION-LEVEL matched null stays FLAT
    // under codec search WITH codec SELECTION in play. The base-6 plant's ciphertext
    // is shuffled into noise, then a codec search that yields TWO surviving codecs
    // (FixedGrouping{2,6} in BOTH Msb and Lsb order, each 6^2 = 36 >= 29) + a mapping
    // search runs on it. The real run takes the MAX score over both codecs, so the
    // null is computed at the enumeration level (max-over-codecs-per-shuffle) and the
    // winner is gated against THAT bar — not its own single-codec null — so trying two
    // codecs and reporting the best does NOT manufacture a beats-null winner on noise.
    //
    // This is the test that was VACUOUS before the Phase-2a fix: with a single
    // surviving codec it never exercised codec selection, so the OLD per-codec null
    // (which maxes over ciphers within one codec only) was never asked to pay for it.
    #[test]
    fn codec_search_matched_null_stays_flat_on_shuffled_noise() {
        let english = english_model().unwrap();
        let finnish = finnish_model().unwrap();
        let base = 6usize;
        let (planted, _key, _indices) = plant_base6_pair_english(&english);

        // Destroy the bigram structure by shuffling the ciphertext once.
        let mut shuffled = planted;
        let mut rng = SplitMix64::new(0x0053_4855_4636_3636);
        crate::null::fisher_yates(&mut shuffled, &mut rng).unwrap();

        let request = SolveRequest {
            ciphertext: &shuffled,
            transparent: &[],
            space: HypothesisSpace {
                families: vec![CipherFamilySpec {
                    label: "identity".to_owned(),
                    ciphers: vec![AnyCipher::Identity],
                }],
                // group_len 1 (Identity, 6 < 29) is sanity-skipped; group_len 2 in
                // BOTH orders survives (36 >= 29) and transduces the even-length
                // stream -> TWO surviving codecs, so codec SELECTION is exercised.
                codec: CodecStrategy::Search(CodecSearch {
                    max_group_len: 2,
                    try_delta: false,
                    orders: vec![DigitOrder::Msb, DigitOrder::Lsb],
                    seed: DEFAULT_SEED,
                }),
                mappings: MappingStrategy::Search(hillclimb(6, 4000)),
                language: LanguageChoice::English,
                cipher_alphabet_size: base,
                seed: DEFAULT_SEED,
                null_trials: 3,
            },
            english: &english,
            finnish: &finnish,
        };

        let outcome = solve_with_codec_trace(&request).unwrap();

        // (i) At least TWO distinct surviving codecs actually ran (codec selection is
        // real), with Identity logged-and-skipped for failing alphabet-size sanity.
        let mut distinct: Vec<AnyCodec> = Vec::new();
        for candidate in &outcome.candidates {
            if !distinct.contains(&candidate.codec) {
                distinct.push(candidate.codec.clone());
            }
        }
        assert!(
            distinct.len() >= 2,
            "expected >=2 surviving codecs to exercise selection, saw {distinct:?}"
        );
        assert!(outcome.skipped.iter().any(|skip| {
            skip.codec == AnyCodec::Identity
                && matches!(skip.reason, CodecSkipReason::SanityTooSmall { .. })
        }));

        // (ii) On shuffled noise the top candidate does NOT beat the enumeration-level
        // null: codec selection on noise manufactures no winner.
        let top = outcome.candidates.first().unwrap();
        assert!(
            !top.beats_null,
            "codec search on shuffled noise beat its enumeration-level null (score {}, null {})",
            top.score, top.null_mean
        );
        assert!(!candidate_survives(top));
    }

    // Step 6 (brief 04a Phase-2a) — the enumeration-level null is SELECTION-COMPLETE
    // over codecs: maxing the on-noise score over ALL surviving codecs per shuffle is
    // >= every single codec's on-noise null (same shuffles, same seeds, no max). The
    // winning candidate carries exactly THAT enumeration-level null — the assertion
    // that would FAIL under the OLD per-codec null, where the winner carried only its
    // own (smaller) single-codec null and never paid for codec selection.
    #[test]
    fn enumeration_null_is_selection_complete_over_codecs() {
        let english = english_model().unwrap();
        let finnish = finnish_model().unwrap();
        let base = 6usize;
        let (planted, _key, _indices) = plant_base6_pair_english(&english);
        let mut shuffled = planted;
        let mut rng = SplitMix64::new(0x0053_4855_4636_3637);
        crate::null::fisher_yates(&mut shuffled, &mut rng).unwrap();

        let search = CodecSearch {
            max_group_len: 2,
            try_delta: false,
            orders: vec![DigitOrder::Msb, DigitOrder::Lsb],
            seed: DEFAULT_SEED,
        };
        let request = SolveRequest {
            ciphertext: &shuffled,
            transparent: &[],
            space: HypothesisSpace {
                families: vec![CipherFamilySpec {
                    label: "identity".to_owned(),
                    ciphers: vec![AnyCipher::Identity],
                }],
                codec: CodecStrategy::Search(search.clone()),
                mappings: MappingStrategy::Search(hillclimb(4, 2000)),
                language: LanguageChoice::English,
                cipher_alphabet_size: base,
                seed: DEFAULT_SEED,
                null_trials: 3,
            },
            english: &english,
            finnish: &finnish,
        };

        // The exact survivor set the real run uses (>=2 codecs => selection is live).
        let (survivors, _skipped) = surviving_codecs(&request, &search, base);
        assert!(
            survivors.len() >= 2,
            "need >=2 survivors to exercise codec selection, saw {}",
            survivors.len()
        );
        let family = request.space.families.first().unwrap();

        // The enumeration-level null maxes over ALL survivors per shuffle...
        let full = enumeration_null_mean(&request, family, Language::English, &search, &survivors)
            .unwrap();
        // ...so it dominates every single-codec on-noise null computed with the SAME
        // shuffles and codec-index-derived seeds (the per-trial max >= any one codec).
        let mut max_single = f64::NEG_INFINITY;
        for survivor in &survivors {
            let single = vec![survivor.clone()];
            let one = enumeration_null_mean(&request, family, Language::English, &search, &single)
                .unwrap();
            assert!(
                full >= one,
                "enumeration null {full} below single-codec null {one} (selection not paid for)"
            );
            max_single = max_single.max(one);
        }
        assert!(
            full >= max_single,
            "enumeration null {full} below the best single-codec null {max_single}"
        );

        // The winning candidate carries exactly this enumeration-level null (the
        // discriminating assertion: under the OLD per-codec null it carried only its
        // own codec's smaller null), and it reproduces BIT-for-bit for the fixed seed.
        // Compared via `to_bits` for exact deterministic equality (clippy::float_cmp).
        let candidates = solve(&request).unwrap();
        let top = candidates.first().unwrap();
        assert_eq!(top.null_mean.to_bits(), full.to_bits());
        let again = solve(&request).unwrap();
        assert_eq!(again.first().unwrap().null_mean.to_bits(), full.to_bits());
    }

    // Step 6 — held-out fold ABOVE the shuffled baseline on the synthetic plant:
    // the codec-searched candidate's held-out mapping score sits above its matched
    // null, i.e. the mapping generalizes to unseen positions rather than overfitting
    // the in-sample fold. (Uses the known grouped-value->letter mapping so the
    // held-out signal is the codec/null plumbing under test, not the mapping search.)
    #[test]
    fn codec_search_heldout_above_null_on_plant() {
        let english = english_model().unwrap();
        let finnish = finnish_model().unwrap();
        let base = 6usize;
        let (ciphertext, key, _indices) = plant_base6_pair_english(&english);
        let mapping = grouped_value_identity_mapping(&english);

        let request = SolveRequest {
            ciphertext: &ciphertext,
            transparent: &[],
            space: HypothesisSpace {
                families: vec![CipherFamilySpec {
                    label: "Caesar".to_owned(),
                    ciphers: vec![AnyCipher::Identity, AnyCipher::Caesar(key)],
                }],
                codec: CodecStrategy::Search(CodecSearch {
                    max_group_len: 2,
                    try_delta: false,
                    orders: vec![DigitOrder::Msb],
                    seed: DEFAULT_SEED,
                }),
                mappings: MappingStrategy::Fixed(vec![mapping]),
                language: LanguageChoice::English,
                cipher_alphabet_size: base,
                seed: DEFAULT_SEED,
                null_trials: 8,
            },
            english: &english,
            finnish: &finnish,
        };

        let candidates = solve(&request).unwrap();
        let top = candidates.first().unwrap();
        assert_eq!(top.cipher, AnyCipher::Caesar(key));
        assert!(
            top.heldout_mapping_score > top.null_mean,
            "held-out {} did not clear the matched null {}",
            top.heldout_mapping_score,
            top.null_mean
        );
        assert!(top.beats_null);
        assert!(candidate_survives(top));
    }

    // Step 7 — the DELTA search path recovers the +/-1-`C5`-shaped plant. The
    // planted English rides a walk on C5 (base 5) under a Caesar shift; only the
    // `Delta{base 5}` codec over the base-5 trigram grouping both hosts the language
    // (5^3 = 125 >= 29) AND fits the stream. The direct (non-delta) trigram grouping
    // is logged-and-skipped: the walk length (3N+1) is not a multiple of 3, so the
    // grouping cannot transduce it -- the +/-1 walk structure is exactly the search
    // hint that makes the delta codec the natural first attempt. (An OBSERVED
    // ciphertext property and a search hint, never a claim of "no message".)
    #[test]
    fn delta_search_recovers_delta_c5_plant() {
        let english = english_model().unwrap();
        let finnish = finnish_model().unwrap();
        let base = 5usize;
        let (ciphertext, _key, plaintext_indices) = plant_delta_c5_english(&english);
        let mapping = grouped_value_identity_mapping(&english);

        let request = SolveRequest {
            ciphertext: &ciphertext,
            transparent: &[],
            space: HypothesisSpace {
                families: vec![CipherFamilySpec {
                    label: "Caesar".to_owned(),
                    ciphers: identity_plus_caesar_ciphers(base),
                }],
                codec: CodecStrategy::Search(CodecSearch {
                    max_group_len: 3,
                    try_delta: true,
                    orders: vec![DigitOrder::Msb],
                    seed: DEFAULT_SEED,
                }),
                mappings: MappingStrategy::Fixed(vec![mapping]),
                language: LanguageChoice::English,
                cipher_alphabet_size: base,
                seed: DEFAULT_SEED,
                null_trials: DEFAULT_NULL_TRIALS,
            },
            english: &english,
            finnish: &finnish,
        };

        let outcome = solve_with_codec_trace(&request).unwrap();
        let top = outcome.candidates.first().unwrap();

        // The winning codec is the delta over the base-5 trigram grouping.
        assert_eq!(
            top.codec,
            AnyCodec::Delta(DeltaCodec {
                base,
                then: Box::new(AnyCodec::FixedGrouping(GroupingCodec {
                    group_len: 3,
                    base,
                    order: DigitOrder::Msb,
                    stride: 3,
                })),
            })
        );
        assert!(top.crypto_round_trip_ok);
        assert!(top.codec_round_trip_ok);
        assert!(top.beats_null, "score {} null {}", top.score, top.null_mean);

        let expected: String = plaintext_indices
            .iter()
            .map(|&index| english.alphabet().symbol(index).unwrap())
            .collect();
        assert_eq!(top.rendered_text, expected);

        // The DIRECT (non-delta) base-5 trigram grouping is logged-and-skipped as
        // Untransducible (the 3N+1 walk length is not a multiple of 3); only the
        // delta path -- which differences the +/-1 walk first -- fits. Differencing
        // is shift-invariant, which is also why the Caesar key is not separately
        // identifiable through the delta codec, so the cipher key is not asserted.
        assert!(outcome.skipped.iter().any(|skip| {
            skip.codec
                == AnyCodec::FixedGrouping(GroupingCodec {
                    group_len: 3,
                    base,
                    order: DigitOrder::Msb,
                    stride: 3,
                })
                && skip.reason == CodecSkipReason::Untransducible
        }));

        // Reproducible for the fixed seed.
        let again = solve_with_codec_trace(&request).unwrap();
        assert_eq!(outcome, again);
    }

    // Step 8 — the synthetic plant-through-codec positive control (the real proof).
    // A known English plaintext is pushed through the INVERSE of a
    // FixedGrouping{3,5,Msb,3} codec (each letter -> three base-5 digits) then a
    // known Caesar cipher; solve + codec SEARCH must recover the (cipher key + codec
    // + mapping) and reproduce the EXACT planted English, with all four gates green.
    // Exact match (not merely a high score) is required because the plaintext is
    // known: a 5-symbol cipher alphabet cannot host 29 letters directly, so the
    // search must DISCOVER the base-5 trigram widening (5^3 = 125 >= 29), the MSB
    // order, AND the Caesar key. A broken search (wrong codec/order/key, mis-pruned
    // survivor, or mis-ranked candidate) renders different text and fails here.
    #[test]
    fn codec_search_positive_control_recovers_exact_english() {
        let english = english_model().unwrap();
        let finnish = finnish_model().unwrap();
        let base = 5usize;
        let (ciphertext, key, plaintext_indices) = plant_base5_trigram_english(&english);
        let mapping = grouped_value_identity_mapping(&english);

        let request = SolveRequest {
            ciphertext: &ciphertext,
            transparent: &[],
            space: HypothesisSpace {
                families: vec![CipherFamilySpec {
                    label: "Caesar".to_owned(),
                    ciphers: identity_plus_caesar_ciphers(base),
                }],
                // A full search: group_len 1..=3, both orders, delta on/off. Only the
                // direct base-5 MSB trigram grouping recovers the plant; the rest are
                // sanity-skipped (5, 25 < 29), length-skipped (delta trigram), or
                // score below it (Lsb order, wrong Caesar key).
                codec: CodecStrategy::Search(CodecSearch {
                    max_group_len: 3,
                    try_delta: true,
                    orders: vec![DigitOrder::Msb, DigitOrder::Lsb],
                    seed: DEFAULT_SEED,
                }),
                mappings: MappingStrategy::Fixed(vec![mapping]),
                language: LanguageChoice::English,
                cipher_alphabet_size: base,
                seed: DEFAULT_SEED,
                null_trials: DEFAULT_NULL_TRIALS,
            },
            english: &english,
            finnish: &finnish,
        };

        let outcome = solve_with_codec_trace(&request).unwrap();
        let top = outcome.candidates.first().unwrap();

        // Recovered (cipher key + codec + mapping): the exact planted configuration.
        assert_eq!(top.cipher, AnyCipher::Caesar(key));
        assert_eq!(
            top.codec,
            AnyCodec::FixedGrouping(GroupingCodec {
                group_len: 3,
                base,
                order: DigitOrder::Msb,
                stride: 3,
            })
        );
        assert_eq!(top.mapping, grouped_value_identity_mapping(&english));

        // All four gates green: crypto round-trip, codec round-trip, beats matched
        // null, and held-out generalizes above the null (candidate_survives bundles
        // the latter three without collapsing them).
        assert!(top.crypto_round_trip_ok);
        assert!(top.codec_round_trip_ok);
        assert!(top.beats_null, "score {} null {}", top.score, top.null_mean);
        assert!(
            top.heldout_mapping_score > top.null_mean,
            "held-out {} did not clear the matched null {}",
            top.heldout_mapping_score,
            top.null_mean
        );
        assert!(candidate_survives(top));

        // EXACT planted English (the proof), not merely a high score.
        let expected: String = plaintext_indices
            .iter()
            .map(|&index| english.alphabet().symbol(index).unwrap())
            .collect();
        assert_eq!(top.rendered_text, expected);
        // Guard against a trivially-satisfied assertion: the plaintext is a long,
        // varied passage, not a degenerate constant string.
        assert!(expected.len() > 200);
        assert!(
            expected
                .chars()
                .any(|c| c != expected.chars().next().unwrap())
        );

        // The too-small codecs were logged-and-skipped, never silently dropped.
        assert!(
            outcome
                .skipped
                .iter()
                .any(|skip| matches!(skip.reason, CodecSkipReason::SanityTooSmall { .. }))
        );

        // Reproducible for the fixed seed.
        let again = solve_with_codec_trace(&request).unwrap();
        assert_eq!(outcome, again);
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
            transparent: &[],
            space: HypothesisSpace {
                families: vec![CipherFamilySpec {
                    label: "Caesar".to_owned(),
                    ciphers: identity_plus_caesar_ciphers(english.alphabet().len()),
                }],
                codec: CodecStrategy::Fixed(vec![AnyCodec::Identity]),
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
            transparent: &[],
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
                codec: CodecStrategy::Fixed(vec![AnyCodec::Identity]),
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
            codec_name: "fixed-grouping",
            codec_round_trip_ok: true,
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
            provenance: "make run ARGS='solve --label positive-control'",
            candidates_evaluated: 3,
            survivors: 1,
            top: Some(top),
        };
        let body = super::render_solve_candidate_record(&inputs).unwrap();

        assert!(body.contains(super::SOLVE_CLAIM_CEILING));
        assert!(body.contains("HYPOTHESIS, NOT a decode"));
        assert!(body.contains("## Provenance (reproducible)"));
        assert!(body.contains("make run ARGS='solve --label positive-control'"));
        assert!(body.contains("CANDIDATE SURVIVED ALL THREE GATES"));
        assert!(body.contains("Top candidate codec: fixed-grouping"));
        assert!(body.contains("Gate 1 cipher round-trip"));
        assert!(
            body.contains(
                "Gate 1b codec round-trip (codec/cipher consistency, NOT a decode): true"
            )
        );
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
            provenance: "make run ARGS='solve --label eyes --candidates-dir research/gak-threads/candidates'",
            candidates_evaluated: 0,
            survivors: 0,
            top: None,
        };
        let body = super::render_solve_candidate_record(&inputs).unwrap();

        assert!(body.contains("NO surviving candidate — decode remains blocked"));
        assert!(body.contains(super::SOLVE_CLAIM_CEILING));
        assert!(body.contains("nothing to score"));
        assert!(body.contains("## Provenance (reproducible)"));
        assert!(body.contains(
            "make run ARGS='solve --label eyes --candidates-dir research/gak-threads/candidates'"
        ));
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
            ciphertext.len(),
            "test: log_solve_run_writes_seed_derived_record",
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
            transparent: &[],
            space: HypothesisSpace {
                families: vec![CipherFamilySpec {
                    label: "identity".to_owned(),
                    ciphers: vec![AnyCipher::Identity],
                }],
                codec: CodecStrategy::Fixed(vec![AnyCodec::Identity]),
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

    /// Plants English -> inverse base-6 pair grouping (MSB; each letter index
    /// becomes two base-6 digits) -> Caesar(base 6, shift 2). Returns the
    /// ciphertext, the Caesar key, and the planted language indices.
    fn plant_base6_pair_english(model: &LanguageModel) -> (Vec<Glyph>, CaesarKey, Vec<usize>) {
        let base = 6usize;
        let plaintext_indices = model
            .alphabet()
            .normalize_text(
                "THE NORTHERN STARS SHINE ON THE ROSE AND THE HEART OF IRON RESTS IN THE STONE \
                 THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG NEAR THE FOGGY HARBOR EVERY MORNING",
            )
            .unwrap();
        let mut digits: Vec<Glyph> = Vec::with_capacity(plaintext_indices.len() * 2);
        for &index in &plaintext_indices {
            digits.push(Glyph((index / base) as u16));
            digits.push(Glyph((index % base) as u16));
        }
        let key = CaesarKey::new(base, 2).unwrap();
        let ciphertext = caesar_encrypt(&digits, &key).unwrap();
        (ciphertext, key, plaintext_indices)
    }

    /// Plants English through the INVERSE of a `Delta{base 5}` + base-5 trigram
    /// grouping codec: each letter index becomes a base-5 MSB triple (a move
    /// triple), the moves integrate from a seed into a walk on the pentagon `C5`
    /// (base 5), then Caesar encrypts the walk. Recovering it REQUIRES the delta
    /// codec: differencing the walk peels the Caesar shift and the seed back to the
    /// moves, and grouping the moves by three rebuilds each letter index. This is
    /// the synthetic analogue of the +/-1-`C5` structure observed in practice
    /// puzzle `one` (every transition +/-1 mod 5). Returns the ciphertext, the
    /// Caesar key, and the planted language indices.
    fn plant_delta_c5_english(model: &LanguageModel) -> (Vec<Glyph>, CaesarKey, Vec<usize>) {
        let base = 5usize;
        let plaintext_indices = model
            .alphabet()
            .normalize_text(
                "THE NORTHERN STARS SHINE ON THE ROSE AND THE HEART OF IRON RESTS IN THE STONE \
                 THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG NEAR THE FOGGY HARBOR EVERY MORNING \
                 THESE NINE SAINTS ENTER THE TENT AS THE RAIN OF THE EAST STARTS TO SHINE AGAIN",
            )
            .unwrap();
        // Inverse grouping: each language index (< 5^3 = 125) -> 3 base-5 MSB digits
        // = the moves.
        let mut moves: Vec<usize> = Vec::with_capacity(plaintext_indices.len() * 3);
        for &index in &plaintext_indices {
            moves.push(index / 25);
            moves.push((index / 5) % 5);
            moves.push(index % 5);
        }
        // Inverse differencing: integrate the moves from seed 0 into a base-5 walk.
        let mut walk: Vec<Glyph> = Vec::with_capacity(moves.len() + 1);
        let mut accumulator = 0usize;
        walk.push(Glyph(accumulator as u16));
        for step in &moves {
            accumulator = (accumulator + step) % base;
            walk.push(Glyph(accumulator as u16));
        }
        let key = CaesarKey::new(base, 3).unwrap();
        let ciphertext = caesar_encrypt(&walk, &key).unwrap();
        (ciphertext, key, plaintext_indices)
    }

    /// Plants English through the INVERSE of a `FixedGrouping{3,5,Msb,3}` codec
    /// (the honeycomb generalization): each letter index becomes three base-5 MSB
    /// digits, then Caesar(base 5, shift 3) encrypts the digit stream. Unlike the
    /// delta plant, the per-digit Caesar wrap makes the key uniquely identifiable
    /// (only the correct shift regroups to the planted indices). Returns the
    /// ciphertext, the Caesar key, and the planted language indices.
    fn plant_base5_trigram_english(model: &LanguageModel) -> (Vec<Glyph>, CaesarKey, Vec<usize>) {
        let base = 5usize;
        let plaintext_indices = model
            .alphabet()
            .normalize_text(POSITIVE_CONTROL_TEXT)
            .unwrap();
        let mut digits: Vec<Glyph> = Vec::with_capacity(plaintext_indices.len() * 3);
        for &index in &plaintext_indices {
            digits.push(Glyph((index / 25) as u16));
            digits.push(Glyph(((index / 5) % 5) as u16));
            digits.push(Glyph((index % 5) as u16));
        }
        let key = CaesarKey::new(base, 3).unwrap();
        let ciphertext = caesar_encrypt(&digits, &key).unwrap();
        (ciphertext, key, plaintext_indices)
    }

    /// The known grouped-value -> letter map for the base-6 pair plant: the
    /// inverse grouping makes each grouped value equal the planted language index,
    /// so `value -> value` (clamped to 0 for values without a planted letter)
    /// renders the planted English exactly. Sized to the search ceiling so it
    /// applies cleanly to every surviving codec the search may try.
    fn grouped_value_identity_mapping(model: &LanguageModel) -> Mapping {
        let language_size = model.alphabet().len();
        Mapping::from_table(
            (0..MAX_SEARCH_OUTPUT_ALPHABET)
                .map(|value| if value < language_size { value } else { 0 })
                .collect(),
        )
    }

    /// Plants a LONGER English passage (`POSITIVE_CONTROL_TEXT` repeated `reps`
    /// times) through the INVERSE of a `FixedGrouping{3,5,Msb,3}` codec (each letter
    /// index becomes three base-5 MSB digits) then `Caesar(base 5, shift 3)` -- the
    /// same construction as [`plant_base5_trigram_english`], just with more plaintext.
    /// The joint codec+mapping SEARCH needs that extra length: a free many-to-one
    /// mapping search over the 125-value transduced alphabet otherwise sits just
    /// under the beats-null gate (the single-passage margin lands ~0.148 < the 0.15
    /// `SEARCH_BEATS_NULL_MARGIN`), whereas the longer passage clears it comfortably.
    /// Returns the ciphertext, the Caesar key, and the planted language indices.
    fn plant_base5_trigram_repeated_english(
        model: &LanguageModel,
        reps: usize,
    ) -> (Vec<Glyph>, CaesarKey, Vec<usize>) {
        let base = 5usize;
        let text = vec![POSITIVE_CONTROL_TEXT; reps].join(" ");
        let plaintext_indices = model.alphabet().normalize_text(&text).unwrap();
        let mut digits: Vec<Glyph> = Vec::with_capacity(plaintext_indices.len() * 3);
        for &index in &plaintext_indices {
            digits.push(Glyph((index / 25) as u16));
            digits.push(Glyph(((index / 5) % 5) as u16));
            digits.push(Glyph((index % 5) as u16));
        }
        let key = CaesarKey::new(base, 3).unwrap();
        let ciphertext = caesar_encrypt(&digits, &key).unwrap();
        (ciphertext, key, plaintext_indices)
    }

    // Step 8 review follow-up -- the JOINT codec-search x mapping-search positive
    // control (closes the one coverage gap). Every other POSITIVE codec-search test
    // FIXES the mapping (`MappingStrategy::Fixed` with the known grouped-value->letter
    // table) and searches only the codec + cipher key; the joint composition where
    // BOTH the codec AND the mapping are searched was exercised only NEGATIVELY (the
    // matched-null-stays-flat-on-noise test). Phase 2b runs exactly this joint path on
    // the real corpus -- where the mapping is UNKNOWN and must be searched -- so this
    // synthetic positive control proves the joint path recovers a KNOWN plant and
    // rides all four gates.
    //
    // A longer English passage is planted through the INVERSE of FixedGrouping{3,5,
    // Msb,3} then Caesar(base 5, shift 3). `solve` runs `CodecStrategy::Search` (only
    // the base-5 MSB trigram both hosts the 29-letter alphabet -- 5^3 = 125 >= 29 --
    // and transduces the 3N-length stream; group_len 1 and 2 are sanity-skipped at 5
    // and 25 < 29, and the delta trigram is length-skipped) AND
    // `MappingStrategy::Search` (a free MANY-TO-ONE hill-climb over the 125-value
    // transduced alphabet -- the same eyes-like 83->29 regime Phase 2b faces).
    //
    // PRIMARY assertions: codec recovery + four-gate survival + a comfortable
    // beats-null margin -- NOT byte-exact planted English. A searched substitution
    // over a 125-value alphabet recovers an equivalent RELABELING (and, being
    // many-to-one, may collapse symbols), which is exactly why the sibling
    // exact-recovery test FIXES the mapping. The Caesar key is likewise not asserted:
    // a per-digit shift before the MSB grouping is a bijection on the 125 grouped
    // values that the free mapping search absorbs, so the key is not identifiable.
    #[test]
    fn codec_search_with_mapping_search_recovers_plant_and_survives() {
        let english = english_model().unwrap();
        let finnish = finnish_model().unwrap();
        let base = 5usize;
        let (ciphertext, key, plaintext_indices) =
            plant_base5_trigram_repeated_english(&english, 3);

        let request = SolveRequest {
            ciphertext: &ciphertext,
            transparent: &[],
            space: HypothesisSpace {
                families: vec![CipherFamilySpec {
                    label: "Caesar".to_owned(),
                    // The cipher layer is genuinely in the space (identity + the
                    // planted Caesar); its key is not asserted (the mapping absorbs it).
                    ciphers: vec![AnyCipher::Identity, AnyCipher::Caesar(key)],
                }],
                // Codec SEARCH: group_len 1..=3, delta on/off, MSB order. Only the
                // direct base-5 MSB trigram survives both prunes.
                codec: CodecStrategy::Search(CodecSearch {
                    max_group_len: 3,
                    try_delta: true,
                    orders: vec![DigitOrder::Msb],
                    seed: DEFAULT_SEED,
                }),
                // Mapping SEARCH (NOT Fixed): the joint half this test exists to cover.
                mappings: MappingStrategy::Search(hillclimb(3, 1500)),
                language: LanguageChoice::English,
                cipher_alphabet_size: base,
                seed: DEFAULT_SEED,
                null_trials: 3,
            },
            english: &english,
            finnish: &finnish,
        };

        let outcome = solve_with_codec_trace(&request).unwrap();
        let top = outcome.candidates.first().unwrap();

        // (1) Recovered codec == the planted grouping. With the mapping searched
        // (not fixed) this is the only codec the search can surface: group_len 1/2 are
        // sanity-skipped and the delta trigram is length-skipped, so no relabel-
        // equivalent rival (e.g. an Lsb grouping) competes for the top slot.
        assert_eq!(
            top.codec,
            AnyCodec::FixedGrouping(GroupingCodec {
                group_len: 3,
                base,
                order: DigitOrder::Msb,
                stride: 3,
            })
        );

        // (2) All four gates fire AND stay SEPARATE (distinct Candidate fields, never
        // collapsed): cipher round-trip, codec round-trip, beats the matched null, and
        // the held-out fold generalizes above that same null.
        assert!(top.crypto_round_trip_ok);
        assert!(top.codec_round_trip_ok);
        assert!(top.beats_null, "score {} null {}", top.score, top.null_mean);
        assert!(
            top.heldout_mapping_score > top.null_mean,
            "held-out {} did not clear the matched null {}",
            top.heldout_mapping_score,
            top.null_mean
        );
        assert!(candidate_survives(top));

        // (3) Comfortable margins -- far above the ~0 a garbage or empty search would
        // yield, so the test genuinely DISCRIMINATES a working joint search from a
        // broken one. (Observed for this fixed seed: score margin ~0.247, held-out
        // margin ~0.272; the bars below leave clear headroom yet would fail on noise.)
        assert!(
            top.score - top.null_mean >= 0.15,
            "joint-search score margin {} below the comfortable bar (score {}, null {})",
            top.score - top.null_mean,
            top.score,
            top.null_mean
        );
        assert!(
            top.heldout_mapping_score - top.null_mean >= 0.10,
            "held-out margin {} below the comfortable bar (held-out {}, null {})",
            top.heldout_mapping_score - top.null_mean,
            top.heldout_mapping_score,
            top.null_mean
        );

        // (4) The codec search genuinely ENUMERATED and PRUNED (too-small codecs
        // logged-and-skipped, never silently dropped), so the surviving codec is a
        // real search result, not a fixed single option dressed up as a search.
        assert!(
            outcome
                .skipped
                .iter()
                .any(|skip| matches!(skip.reason, CodecSkipReason::SanityTooSmall { .. }))
        );

        // (5) NOT byte-exact planted English (a searched many-to-one relabeling
        // differs from the plant), but the rendering is full-length and
        // non-degenerate -- guarding against an empty or constant candidate slipping
        // through the gates.
        assert_eq!(top.rendered_text.chars().count(), plaintext_indices.len());
        let first = top.rendered_text.chars().next().unwrap();
        assert!(
            top.rendered_text.chars().any(|c| c != first),
            "rendered text is a degenerate constant string"
        );
    }
}

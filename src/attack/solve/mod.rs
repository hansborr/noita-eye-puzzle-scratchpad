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

mod codec_search;
mod eval;
mod record;
mod search;
mod types;

use codec_search::{
    codec_search_mapping, enumeration_null_mean, stamp_enumeration_beats_null, surviving_codecs,
};
use eval::{evaluate_cipher, evaluate_family};
use search::{evaluate_cipher_search, solve_search};

pub use record::*;
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
            let (null_mean, null_heldout_mean) =
                enumeration_null_mean(req, family, *language, search, &survivors)?;
            for (index, codec) in &survivors {
                match &req.space.mappings {
                    MappingStrategy::Fixed(mappings) => {
                        for mapping in mappings {
                            for cipher in &family.ciphers {
                                if let Some(candidate) = evaluate_cipher(
                                    req,
                                    cipher,
                                    mapping,
                                    *language,
                                    null_mean,
                                    null_heldout_mean,
                                    codec,
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
                                null_heldout_mean,
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

/// Whether a [`Candidate`] clears all three independent gates and may therefore
/// be reported as a surviving HYPOTHESIS (never a decode).
///
/// This is a *derived* reporting verdict for records and tests — the three gates
/// stay separate on the [`Candidate`] and are never collapsed into a stored
/// boolean. A surviving candidate must (1) pass the cipher-layer round-trip,
/// (2) beat its matched-null full-stream mean (the overfit guard), and (3)
/// generalize — its held-out fold must beat the matched null's HELD-OUT fold
/// (`null_heldout_mean`), apples-to-apples. Comparing the held-out fold to the
/// full-stream `null_mean` instead (the old bug) falsely failed a true decode,
/// since a fold of natural-language text scores below the contiguous full stream
/// while the full-stream null pays no such penalty.
#[must_use]
pub fn candidate_survives(candidate: &Candidate) -> bool {
    candidate.crypto_round_trip_ok
        && candidate.beats_null
        && candidate.heldout_mapping_score > candidate.null_heldout_mean
}

#[cfg(test)]
mod tests;

#[allow(
    unused_imports,
    reason = "CodecStrategy is referenced only by this module's intra-doc links"
)]
use super::CodecStrategy;
use super::eval::{best_codec_fixed_null_score, family_seed_tag, model_for};
use super::search::{best_family_search_score, search_seed};
use super::{
    AnyCodec, Candidate, CipherFamilySpec, Codec, CodecSearch, CodecSkipReason,
    DEFAULT_LANGUAGE_ALPHABET_SIZE, Language, MAX_SEARCH_OUTPUT_ALPHABET, MappingSearch,
    MappingStrategy, SEARCH_BEATS_NULL_MARGIN, SkippedCodec, SolveError, SolveRequest, SplitMix64,
    enumerate_codecs, fisher_yates, mix_seed, output_alphabet_hosts_language,
    resolved_output_alphabet_size,
};

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
pub(super) fn surviving_codecs(
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
pub(super) fn codec_search_mapping(
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
pub(super) fn stamp_enumeration_beats_null(mut candidate: Candidate, null_mean: f64) -> Candidate {
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
pub(super) fn enumeration_null_mean(
    req: &SolveRequest<'_>,
    family: &CipherFamilySpec,
    language: Language,
    search: &CodecSearch,
    survivors: &[(usize, AnyCodec)],
) -> Result<(f64, f64), SolveError> {
    if survivors.is_empty() {
        return Ok((0.0, 0.0));
    }
    let model = model_for(req, language);
    let shuffle_seed = mix_seed(req.space.seed, family_seed_tag(family) ^ 0x6e75_6c6c);
    let mut rng = SplitMix64::new(shuffle_seed);
    let mut trials: Vec<(f64, f64)> = Vec::with_capacity(req.space.null_trials);
    for trial in 0..req.space.null_trials {
        let mut shuffled = req.ciphertext.to_vec();
        fisher_yates(&mut shuffled, &mut rng)?;
        // MAX over all surviving codecs for this shuffle — the codec selection the
        // real run performs (top-of-N-codecs wins). The held-out fold score travels
        // with the selected (max-in-sample) codec so the null exposes a held-out
        // baseline, not just the full-stream one.
        let mut trial_best: Option<(f64, f64)> = None;
        for (index, codec) in survivors {
            let (score, heldout) = match &req.space.mappings {
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
            if trial_best.is_none_or(|(previous, _)| score > previous) {
                trial_best = Some((score, heldout));
            }
        }
        if let Some(best) = trial_best {
            trials.push(best);
        }
    }
    let stats = crate::heldout::matched_null_stats(&trials);
    Ok((stats.full_mean, stats.heldout_mean))
}

use super::{
    AnyCipher, AnyCodec, Candidate, CipherFamilySpec, Codec, Glyph, Language, LanguageModel,
    Mapping, SolveError, SolveRequest, SplitMix64, TransparentMark, codec_round_trip_ok,
    fisher_yates, mix_seed,
};

/// Best fixed-mapping in-sample score for one codec on a (shuffled) stream, maxed
/// over the declared mapping set × the cipher family. The enumeration null maxes this
/// over codecs in turn, mirroring the real run's selection across (codec × mapping ×
/// cipher).
pub(super) fn best_codec_fixed_null_score(
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

pub(super) fn evaluate_family(
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

pub(super) fn evaluate_cipher(
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

pub(super) fn decrypt_round_trip(
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

pub(super) fn family_seed_tag(family: &CipherFamilySpec) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in family.label.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

pub(super) fn model_for<'a>(req: &'a SolveRequest<'_>, language: Language) -> &'a LanguageModel {
    match language {
        Language::Finnish => req.finnish,
        Language::English => req.english,
    }
}

pub(super) fn render_indices(
    indices: &[usize],
    model: &LanguageModel,
) -> Result<String, SolveError> {
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
pub(super) fn reinsert_transparent(
    rendered: &str,
    marks: &[TransparentMark],
    codec: &AnyCodec,
) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{DigitOrder, GroupingCodec};

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
}

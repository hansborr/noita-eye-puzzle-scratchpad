use super::{
    AnnealSchedule, AnyCodec, CipherFamilySpec, Codec, CodecStrategy, DEFAULT_NULL_TRIALS,
    DEFAULT_SEED, HypothesisSpace, Language, LanguageChoice, Mapping, MappingSearch,
    MappingStrategy, SolveError, SolveRequest, candidate_survives, enumeration_null_mean, solve,
    solve_with_codec_trace, surviving_codecs,
};
use crate::attack::codec::{
    CodecSearch, CodecSkipReason, DeltaCodec, DigitOrder, GroupingCodec, MAX_SEARCH_OUTPUT_ALPHABET,
};
use crate::attack::language::{LanguageModel, english_model, finnish_model};
use crate::ciphers::{
    AnyCipher, CaesarKey, TranspositionKey, caesar_encrypt, transposition_encrypt,
};
use crate::core::glyph::Glyph;
use crate::nulls::null::{SplitMix64, shuffled_permutation};

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

// Letter-puzzle validation over the checked-in practice corpus.
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
            super::SolveRunIdentity {
                label: name,
                seed: super::DEFAULT_SEED,
                cipher_alphabet_size: 26,
                total_symbols: glyphs.len(),
            },
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

// THE EYES HONEST NEGATIVE (the single most important test).
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
        // Pin the REASON the honest negative holds, not just the verdict. The
        // LOAD-BEARING gate is the in-sample overfit bar (Gate 3): the re-fit
        // mapping's in-sample score does NOT clear the matched null's in-sample
        // mean, so the candidate cannot survive regardless of the other gates.
        // (Direction only — no brittle exact float — robust to search-config
        // tweaks.)
        assert!(
            !top.beats_null,
            "the eyes beat their matched null (score {}, null {}) — investigate before claiming signal",
            top.score, top.null_mean
        );
        // T1 NOTE (corrected, apples-to-apples held-out gate): under the OLD
        // bug — comparing the held-out fold to the FULL-stream null mean — the
        // eyes' top candidate also "failed" Gate 2, which over-attributed the
        // honest negative. With the fold-vs-fold comparison the eyes' held-out
        // fold actually sits marginally ABOVE the null's held-out fold (Gate 2 is
        // a near-tie, within search noise), so Gate 2 is NOT load-bearing here.
        // The honest negative stands entirely on Gate 3 above — the decode remains
        // BLOCKED for the honest reason (no in-sample signal above noise), not an
        // artifactual held-out miscalibration. The near-tie margin is too small to
        // assert a direction robustly, so it is documented, not pinned.
    }

    // The honest negative is logged with the verbatim claim ceiling.
    let dir = std::env::temp_dir().join(format!("noita-solve-eyes-{}", std::process::id()));
    let _removed = std::fs::remove_dir_all(&dir);
    let path = super::log_solve_run(
        &dir,
        super::SolveRunIdentity {
            label: "eyes-reading-layer",
            seed: super::DEFAULT_SEED,
            cipher_alphabet_size: crate::ciphers::EYE_READING_ALPHABET_SIZE,
            total_symbols: eyes.len(),
        },
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
// Corpus codec/grouping samples one/two/six.
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

fn parse_corpus_puzzle(text: &str, alphabet: &str) -> crate::core::ingest::ParsedSequence {
    let alphabet = crate::core::glyph::Alphabet::from_chars(alphabet).expect("corpus alphabet");
    let transparent = crate::core::ingest::TransparentSet::default();
    crate::core::ingest::parse_sequence(
        text,
        crate::core::ingest::SequenceLayer::CipherAlphabet {
            alphabet: &alphabet,
            transparent: &transparent,
        },
    )
    .expect("corpus parse")
}

fn corpus_codec_request<'a>(
    parsed: &'a crate::core::ingest::ParsedSequence,
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
        super::SolveRunIdentity {
            label: "one",
            seed: super::DEFAULT_SEED,
            cipher_alphabet_size: 5,
            total_symbols: parsed.glyphs.len(),
        },
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
        super::SolveRunIdentity {
            label: "two",
            seed: super::DEFAULT_SEED,
            cipher_alphabet_size: 12,
            total_symbols: parsed.glyphs.len(),
        },
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
        super::SolveRunIdentity {
            label: "six",
            seed: super::DEFAULT_SEED,
            cipher_alphabet_size: 6,
            total_symbols: parsed.glyphs.len(),
        },
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
    let alphabet = crate::core::glyph::Alphabet::from_chars("ABCDEFGHIJKLMNOPQRSTUVWXYZ").unwrap();
    let transparent = crate::core::ingest::TransparentSet::default();
    crate::core::ingest::parse_sequence(
        text,
        crate::core::ingest::SequenceLayer::CipherAlphabet {
            alphabet: &alphabet,
            transparent: &transparent,
        },
    )
    .unwrap()
    .glyphs
}

fn eye_reading_layer() -> Vec<Glyph> {
    let grids = crate::analysis::orders::corpus_grids().unwrap();
    let order = crate::analysis::orders::accepted_honeycomb_order();
    crate::analysis::orders::read_corpus_values(&grids, order)
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

// Synthetic plant-through-codec positive control (fixed codec).
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

// The codec SEARCH enumerates grouping codecs, prunes the ones that
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

// Bounded + logged: an out-of-budget codec is surfaced in the skip
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

// The ENUMERATION-LEVEL matched null stays FLAT
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
    crate::nulls::null::fisher_yates(&mut shuffled, &mut rng).unwrap();

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

// The enumeration-level null is SELECTION-COMPLETE
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
    crate::nulls::null::fisher_yates(&mut shuffled, &mut rng).unwrap();

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
    // (`.0` is the full-stream mean — the selection-complete overfit bar under
    // test here; `.1` is the held-out mean, exercised separately.)
    let full = enumeration_null_mean(&request, family, Language::English, &search, &survivors)
        .unwrap()
        .0;
    // ...so it dominates every single-codec on-noise null computed with the SAME
    // shuffles and codec-index-derived seeds (the per-trial max >= any one codec).
    let mut max_single = f64::NEG_INFINITY;
    for survivor in &survivors {
        let single = vec![survivor.clone()];
        let one = enumeration_null_mean(&request, family, Language::English, &search, &single)
            .unwrap()
            .0;
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

// Held-out fold ABOVE the shuffled baseline on the synthetic plant:
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
        top.heldout_mapping_score > top.null_heldout_mean,
        "held-out {} did not clear the matched null's held-out fold {}",
        top.heldout_mapping_score,
        top.null_heldout_mean
    );
    assert!(top.beats_null);
    assert!(candidate_survives(top));
}

// The DELTA search path recovers the +/-1-`C5`-shaped plant. The
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

// The synthetic plant-through-codec positive control (the real proof).
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

// The hill-climb (+ held-out gate) surfaces a planted small-alphabet
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

// The annealed full search recovers a planted 26-letter
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
    crate::nulls::null::fisher_yates(&mut shuffled, &mut rng).unwrap();

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

// The record renderer is a pure string builder (no filesystem) and
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
        null_heldout_mean: -3.30,
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
        body.contains("Gate 1b codec round-trip (codec/cipher consistency, NOT a decode): true")
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
        super::SolveRunIdentity {
            label: "small-alphabet",
            seed: super::DEFAULT_SEED,
            cipher_alphabet_size: size,
            total_symbols: ciphertext.len(),
        },
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

// The JOINT codec-search x mapping-search positive
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
    let (ciphertext, key, plaintext_indices) = plant_base5_trigram_repeated_english(&english, 3);

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

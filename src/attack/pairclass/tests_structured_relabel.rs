//! Definitive structured relabel-coverage regression.

use std::collections::BTreeMap;

use super::campaign::{StreamPrep, solve_cfg};
use super::lexicon::build_lexicon;
use super::plant::{PlantSpec, copy_ties, plant_from_text_with_coloring};
use super::solve::{SolveInput, solve};
use super::structured::{
    StructuredCandidateMeta, StructuredFamilyProfile, StructuredRunCfg, StructuredStream,
    generate_structured_candidates,
};
use super::{
    CopySpan, DEFAULT_SEED, Lexicon, TWO_MODULUS, embedded_two, prepare_stream, tie_targets,
};
use crate::nulls::null::{SplitMix64, mix_seed, random_index_below};

const STRUCTURED_CONTROL_TAG: u64 = 0x7374_7275_6374_0001;

struct DefinitiveRelabelFixture {
    entries: Vec<(String, u64)>,
    lexicon: Lexicon,
    cfg: StructuredRunCfg,
    truth: StructuredCandidateMeta,
    truth_coloring: [u8; 26],
    prep: StreamPrep,
    copy: Option<CopySpan>,
    ties: Vec<Option<usize>>,
    letters: Vec<u8>,
}

#[derive(Debug)]
struct RelabelDiagnostic {
    plant_index: usize,
    base_transform: String,
    base_l1: f64,
    base_chi2: f64,
    truth_transform: String,
    truth_l1: f64,
    truth_chi2: f64,
    l1_gap: f64,
    chi2_gap: f64,
    sibling_rank: usize,
    truth_marginal_pass: bool,
    guaranteed_candidates: usize,
    extra_candidates: usize,
    candidate_count: usize,
}

fn corpus_word_entries() -> Vec<(String, u64)> {
    let text = std::fs::read_to_string("research/data/lang/english-corpus-large.txt")
        .expect("corpus is present");
    let mut counts = BTreeMap::<String, u64>::new();
    for word in text.split(|ch: char| !ch.is_ascii_alphabetic()) {
        if word.is_empty() {
            continue;
        }
        let entry = counts.entry(word.to_ascii_lowercase()).or_insert(0);
        *entry += 1;
    }
    let mut entries: Vec<(String, u64)> = counts.into_iter().collect();
    entries.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    entries
}

fn structured_core_cfg() -> StructuredRunCfg {
    StructuredRunCfg {
        profile: StructuredFamilyProfile::Core,
        max_decodes: 4096,
        rank_beam: 400,
        marginal_l1: 0.16,
        score_margin: 0.0,
    }
}

fn control_candidate(entries: &[(String, u64)], cfg: &StructuredRunCfg) -> StructuredCandidateMeta {
    let tokens = [0u8, 1, 2, 3];
    let stream = StructuredStream {
        label: "control",
        tokens: &tokens,
        n_classes: 4,
        tie_to: None,
    };
    let mut control_cfg = *cfg;
    control_cfg.max_decodes = control_cfg.max_decodes.max(1);
    control_cfg.marginal_l1 = 2.0;
    let generated =
        generate_structured_candidates(&[stream], entries, &control_cfg).expect("control family");
    let mut rng = SplitMix64::new(mix_seed(DEFAULT_SEED, STRUCTURED_CONTROL_TAG));
    let index =
        random_index_below(generated.candidates.len(), &mut rng).expect("valid control bound");
    generated
        .candidates
        .get(index)
        .or_else(|| generated.candidates.first())
        .expect("control candidate")
        .clone()
}

fn text_letters(text: &str) -> Vec<u8> {
    text.chars()
        .filter_map(|ch| {
            let lower = ch.to_ascii_lowercase();
            lower.is_ascii_lowercase().then(|| lower as u8 - b'a')
        })
        .collect()
}

fn plant_source(letters: &[u8], plant_len: usize, index: usize, n_plants: usize) -> String {
    let start = if letters.len() <= plant_len || n_plants == 0 {
        0
    } else {
        (letters.len() - plant_len) / n_plants.max(1) * index
    };
    letters
        .get(start..)
        .unwrap_or(&[])
        .iter()
        .map(|&letter| char::from(b'a' + letter.min(25)))
        .collect()
}

fn tie_to_copy(longest_tie: Option<(usize, usize, usize)>, plant_len: usize) -> Option<CopySpan> {
    let (_src, _dst, span_len) = longest_tie?;
    let span_len = span_len.min(plant_len / 3).max(1);
    (plant_len >= 3 * span_len).then_some(CopySpan {
        src: 0,
        dst: plant_len / 3,
        len: span_len,
    })
}

fn tie_table(copy: Option<CopySpan>, len: usize) -> Vec<Option<usize>> {
    copy.map_or_else(Vec::new, |span| {
        tie_targets(&copy_ties(span, len).expect("copy span fits"), len)
    })
}

fn marginal_fit_for_coloring(
    entries: &[(String, u64)],
    tokens: &[u8],
    coloring: &[Option<u8>; 26],
) -> (f64, f64) {
    let mut counts = [0u64; 26];
    let mut total = 0u64;
    for (word, count) in entries {
        let weight = (*count).max(1);
        for byte in word.bytes().filter(u8::is_ascii_lowercase) {
            let index = usize::from(byte - b'a');
            if let Some(slot) = counts.get_mut(index) {
                *slot = slot.saturating_add(weight);
            }
            total = total.saturating_add(weight);
        }
    }
    let mut expected = [0.0; 4];
    for (letter, slot) in coloring.iter().enumerate() {
        let Some(class) = slot else {
            continue;
        };
        let count = counts.get(letter).copied().unwrap_or(0);
        if let Some(expected_slot) = expected.get_mut(usize::from(*class)) {
            *expected_slot += count as f64 / total.max(1) as f64;
        }
    }
    let mut observed = [0usize; 4];
    for &token in tokens {
        if let Some(slot) = observed.get_mut(usize::from(token)) {
            *slot += 1;
        }
    }
    let n = tokens.len().max(1) as f64;
    let mut l1 = 0.0;
    let mut chi2 = 0.0;
    for class in 0..4 {
        let observed_count = observed.get(class).copied().unwrap_or(0) as f64;
        let expected_rate = expected.get(class).copied().unwrap_or(0.0);
        l1 += (observed_count / n - expected_rate).abs();
        let exp_count = (expected_rate * n).max(1.0e-9);
        let delta = observed_count - exp_count;
        chi2 += delta * delta / exp_count;
    }
    (l1, chi2)
}

fn definitive_relabel_fixture() -> DefinitiveRelabelFixture {
    let entries = corpus_word_entries();
    let lexicon = build_lexicon(&entries).expect("lexicon builds");
    assert_eq!(entries.len(), 11_419);
    let cfg = structured_core_cfg();
    let truth = control_candidate(&entries, &cfg);
    let truth_coloring = truth.coloring.map(|slot| slot.expect("fully pinned"));
    let values = embedded_two().expect("embedded two parses");
    let prep = prepare_stream(&values, TWO_MODULUS, 0, false, 34)
        .expect("stream prepares")
        .expect("embedded two is a walk");
    let copy = tie_to_copy(prep.longest_tie, prep.tokens.len());
    let ties = tie_table(copy, prep.tokens.len());
    let plant_text = std::fs::read_to_string("research/data/lang/english-corpus-large.txt")
        .expect("plant corpus is present");
    let letters = text_letters(&plant_text);
    DefinitiveRelabelFixture {
        entries,
        lexicon,
        cfg,
        truth,
        truth_coloring,
        prep,
        copy,
        ties,
        letters,
    }
}

fn definitive_relabel_diagnostic(
    fixture: &DefinitiveRelabelFixture,
    plant_index: usize,
) -> RelabelDiagnostic {
    let source = plant_source(&fixture.letters, fixture.prep.tokens.len(), plant_index, 6);
    let plant = plant_from_text_with_coloring(
        &source,
        &PlantSpec {
            len: fixture.prep.tokens.len(),
            n_classes: fixture.prep.n_classes,
            copy: fixture.copy,
        },
        fixture.truth_coloring,
    )
    .expect("plant builds");
    let stream = StructuredStream {
        label: "plant",
        tokens: &plant.tokens,
        n_classes: fixture.prep.n_classes,
        tie_to: Some(fixture.ties.as_slice()),
    };
    let generated = generate_structured_candidates(&[stream], &fixture.entries, &fixture.cfg)
        .expect("generation runs");
    let truth_marginal =
        marginal_fit_for_coloring(&fixture.entries, &plant.tokens, &fixture.truth.coloring);
    let base_best = generated
        .candidates
        .iter()
        .filter(|candidate| same_base(candidate, &fixture.truth))
        .min_by(|left, right| left.marginal_l1.total_cmp(&right.marginal_l1))
        .expect("base sibling exists");
    let mut siblings = generated
        .candidates
        .iter()
        .filter(|candidate| same_base(candidate, &fixture.truth))
        .collect::<Vec<_>>();
    siblings.sort_by(|left, right| left.marginal_l1.total_cmp(&right.marginal_l1));
    let retained_truth = generated
        .candidates
        .iter()
        .find(|candidate| candidate.coloring == fixture.truth.coloring)
        .unwrap_or_else(|| {
            panic!(
                "truth relabel missing for plant {plant_index}; base-best {} {:.6}, truth {} {:.6}, gap {:.6}, candidates {}",
                base_best.transform,
                base_best.marginal_l1,
                fixture.truth.transform,
                truth_marginal.0,
                truth_marginal.0 - base_best.marginal_l1,
                generated.candidates.len()
            )
        });
    let sibling_rank = siblings
        .iter()
        .position(|candidate| candidate.coloring == fixture.truth.coloring)
        .map(|rank| rank + 1)
        .expect("truth sibling was retained");
    let rank_cfg = solve_cfg(fixture.cfg.rank_beam, 2, 8, 3.6, 5, 2048);
    let solved = solve(
        &SolveInput {
            tokens: &plant.tokens,
            n_classes: fixture.prep.n_classes,
            tie_to: Some(fixture.ties.as_slice()),
            lexicon: &fixture.lexicon,
            truth: None,
            seed_coloring: Some(&fixture.truth.coloring),
            accept_partial_final: false,
        },
        &rank_cfg,
    )
    .expect("truth solve runs");
    assert!(
        !solved.solutions.is_empty(),
        "truth coloring should decode at rank beam for plant {plant_index}"
    );
    RelabelDiagnostic {
        plant_index,
        base_transform: base_best.transform.clone(),
        base_l1: base_best.marginal_l1,
        base_chi2: base_best.marginal_chi2,
        truth_transform: retained_truth.transform.clone(),
        truth_l1: retained_truth.marginal_l1,
        truth_chi2: retained_truth.marginal_chi2,
        l1_gap: retained_truth.marginal_l1 - base_best.marginal_l1,
        chi2_gap: retained_truth.marginal_chi2 - base_best.marginal_chi2,
        sibling_rank,
        truth_marginal_pass: retained_truth.marginal_pass,
        guaranteed_candidates: generated.guaranteed_candidates,
        extra_candidates: generated.extra_candidates,
        candidate_count: generated.candidates.len(),
    }
}

fn same_base(candidate: &StructuredCandidateMeta, truth: &StructuredCandidateMeta) -> bool {
    candidate.family == truth.family
        && candidate.projection == truth.projection
        && candidate.order == truth.order
}

fn assert_definitive_relabel_calibration(
    diagnostics: &[RelabelDiagnostic],
    marginal_l1: f64,
    token_len: usize,
) {
    let near_best_chi2_delta = 9.0;
    let edge_l1 = marginal_l1 + 13.0 / token_len as f64;
    for index in [0usize, 1, 3] {
        let diag = diagnostics
            .iter()
            .find(|diag| diag.plant_index == index)
            .expect("diagnostic exists");
        assert_ne!(
            diag.base_transform, diag.truth_transform,
            "diagnostic: {diag:?}"
        );
        assert!(diag.base_l1.is_finite(), "diagnostic: {diag:?}");
        assert!(diag.base_chi2.is_finite(), "diagnostic: {diag:?}");
        assert!(diag.truth_l1.is_finite(), "diagnostic: {diag:?}");
        assert!(diag.truth_chi2.is_finite(), "diagnostic: {diag:?}");
        assert!(diag.l1_gap >= 0.0, "diagnostic: {diag:?}");
        assert!(
            diag.chi2_gap <= near_best_chi2_delta,
            "diagnostic: {diag:?}"
        );
        if diag.truth_marginal_pass {
            assert!(diag.sibling_rank <= 11, "diagnostic: {diag:?}");
        } else {
            assert!(diag.truth_l1 <= edge_l1, "diagnostic: {diag:?}");
        }
    }
    assert!(
        diagnostics
            .iter()
            .any(|diag| !diag.truth_marginal_pass && diag.plant_index == 0),
        "regression must exercise the over-threshold retained relabel: {diagnostics:?}"
    );
    assert!(
        diagnostics.iter().all(|diag| diag.extra_candidates <= 4096),
        "extra budget must stay capped: {diagnostics:?}"
    );
    assert!(
        diagnostics
            .iter()
            .map(|diag| diag.candidate_count)
            .max()
            .unwrap_or(0)
            <= 20_000,
        "hybrid relabel retention should remain tractable: {diagnostics:?}"
    );
    assert!(
        diagnostics
            .iter()
            .map(|diag| diag.guaranteed_candidates)
            .max()
            .unwrap_or(0)
            <= 17_000,
        "guaranteed set should stay bounded: {diagnostics:?}"
    );
}

#[test]
fn structured_core_near_tie_relabels_keep_definitive_positive_truths() {
    let fixture = definitive_relabel_fixture();
    let diagnostics = (0..6)
        .map(|plant_index| definitive_relabel_diagnostic(&fixture, plant_index))
        .collect::<Vec<_>>();
    assert_definitive_relabel_calibration(
        &diagnostics,
        fixture.cfg.marginal_l1,
        fixture.prep.tokens.len(),
    );
}

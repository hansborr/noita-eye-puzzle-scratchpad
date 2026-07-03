//! Tests for structured-coloring Avenue-A mode.

use super::campaign::{PowerCfg, StreamPrep, solve_cfg};
use super::lexicon::{build_lexicon, parse_wordlist};
use super::structured::{
    StructuredFamilyProfile, StructuredNullCfg, StructuredRunCfg, StructuredStream,
    generate_structured_candidates, measure_structured_power, measure_structured_random_negative,
    structured_null_gate,
};

const WORDLIST: &str = "cat 100\ndog 90\nact 3\ntag 2\ncot 1\n";
const TEXT: &str = "cat dog cat dog";

fn toy_entries() -> Vec<(String, u64)> {
    parse_wordlist(WORDLIST, usize::MAX)
}

fn toy_cfg() -> StructuredRunCfg {
    StructuredRunCfg {
        profile: StructuredFamilyProfile::Toy,
        max_decodes: 24,
        marginal_l1: 2.0,
        score_margin: 0.0,
    }
}

fn power_cfg() -> PowerCfg {
    PowerCfg {
        n_plants: 1,
        plant_len: 12,
        n_classes: 4,
        longest_tie: None,
        bar: 0.8,
        seed: 7,
    }
}

#[test]
fn structured_family_enumerates_known_rank_projection() {
    let entries = toy_entries();
    let tokens = [0u8, 1, 2, 3];
    let stream = StructuredStream {
        label: "toy",
        tokens: &tokens,
        n_classes: 4,
        tie_to: None,
    };
    let generated =
        generate_structured_candidates(&[stream], &entries, &toy_cfg()).expect("generation runs");
    assert_eq!(generated.base_colorings, 1);
    assert!(!generated.candidates.is_empty());
    assert!(generated.candidates.iter().all(|candidate| {
        candidate.coloring.len() == 26
            && candidate
                .coloring
                .iter()
                .all(|slot| slot.is_some_and(|class| class < 4))
    }));
}

#[test]
fn structured_generation_keeps_base_best_when_extra_budget_is_zero() {
    let entries = toy_entries();
    let tokens = [0u8, 1, 2, 3];
    let stream = StructuredStream {
        label: "toy",
        tokens: &tokens,
        n_classes: 4,
        tie_to: None,
    };
    let mut cfg = toy_cfg();
    cfg.max_decodes = 0;
    cfg.marginal_l1 = 2.0;
    let generated =
        generate_structured_candidates(&[stream], &entries, &cfg).expect("generation runs");
    assert_eq!(generated.base_colorings, 1);
    assert_eq!(generated.guaranteed_candidates, 1);
    assert_eq!(generated.extra_candidates, 0);
    assert_eq!(generated.candidates.len(), 1);
    assert!(generated.dropped_by_cap > 0, "report: {generated:?}");
    assert_eq!(generated.dropped_by_filter, 0, "report: {generated:?}");
}

#[test]
fn structured_generation_reports_filter_drops() {
    let entries = toy_entries();
    let tokens = [0u8, 1, 2, 3];
    let stream = StructuredStream {
        label: "toy",
        tokens: &tokens,
        n_classes: 4,
        tie_to: None,
    };
    let mut cfg = toy_cfg();
    cfg.max_decodes = 24;
    cfg.marginal_l1 = 0.0;
    let generated =
        generate_structured_candidates(&[stream], &entries, &cfg).expect("generation runs");
    assert_eq!(generated.guaranteed_candidates, 1);
    assert!(generated.dropped_by_filter > 0, "report: {generated:?}");
    assert!(
        generated.l1_at_filter_cut.is_some(),
        "report: {generated:?}"
    );
}

#[test]
fn structured_positive_control_fires() {
    let entries = toy_entries();
    let lexicon = build_lexicon(&entries).expect("lexicon builds");
    let solve = solve_cfg(128, 0, 0, 3.6, 3, 2048);
    let positive =
        measure_structured_power(TEXT, &power_cfg(), &entries, &lexicon, &solve, &toy_cfg())
            .expect("positive runs");
    assert!(positive.cleared_bar, "positive report: {positive:?}");
    assert!(positive.score_floor.is_some());
    assert!(
        positive
            .plants
            .iter()
            .all(|plant| plant.truth_candidate_rank.is_some())
    );
}

#[test]
fn structured_empty_positive_does_not_clear() {
    let entries = toy_entries();
    let lexicon = build_lexicon(&entries).expect("lexicon builds");
    let solve = solve_cfg(128, 0, 0, 3.6, 3, 2048);
    let mut power = power_cfg();
    power.n_plants = 0;
    power.bar = 0.0;
    let positive = measure_structured_power(TEXT, &power, &entries, &lexicon, &solve, &toy_cfg())
        .expect("positive runs");
    assert!(positive.plants.is_empty());
    assert!(positive.score_floor.is_none());
    assert!(!positive.cleared_bar, "positive report: {positive:?}");
}

#[test]
fn structured_random_coloring_negative_stays_quiet() {
    let entries = toy_entries();
    let lexicon = build_lexicon(&entries).expect("lexicon builds");
    let solve = solve_cfg(128, 0, 0, 3.6, 3, 2048);
    let positive =
        measure_structured_power(TEXT, &power_cfg(), &entries, &lexicon, &solve, &toy_cfg())
            .expect("positive runs");
    let negative = measure_structured_random_negative(
        TEXT,
        &power_cfg(),
        &entries,
        &lexicon,
        &solve,
        &toy_cfg(),
        positive.score_floor,
    )
    .expect("negative runs");
    assert!(negative.quiet, "negative report: {negative:?}");
}

#[test]
fn structured_null_gate_stays_quiet() {
    let entries = toy_entries();
    let lexicon = build_lexicon(&entries).expect("lexicon builds");
    let solve = solve_cfg(128, 0, 0, 3.6, 3, 2048);
    let positive =
        measure_structured_power(TEXT, &power_cfg(), &entries, &lexicon, &solve, &toy_cfg())
            .expect("positive runs");
    let tokens: Vec<u8> = "catdogcatdog"
        .bytes()
        .filter(u8::is_ascii_lowercase)
        .map(|byte| (byte - b'a') % 4)
        .collect();
    let prep = StreamPrep {
        tokens,
        n_classes: 4,
        tie_table: Vec::new(),
        n_tied: 0,
        longest_tie: None,
    };
    let null = structured_null_gate(
        &prep,
        &entries,
        &lexicon,
        &solve,
        &toy_cfg(),
        &StructuredNullCfg {
            null_trials: 2,
            real_best: None,
            score_floor: positive.score_floor,
            seed: 7,
        },
    )
    .expect("null runs");
    assert_eq!(null.null_bests.len(), 2);
    assert_eq!(null.null_ge_floor, 0, "null report: {null:?}");
}

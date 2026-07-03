//! Tests for structured-coloring Avenue-A mode.

use std::collections::BTreeSet;

use super::campaign::{PowerCfg, StreamPrep, solve_cfg};
use super::lexicon::{build_lexicon, parse_wordlist};
use super::plant::{PlantSpec, plant_from_text, plant_from_text_with_coloring};
use super::structured::{
    StructuredControlCfg, StructuredFamilyProfile, StructuredGenerationReport, StructuredNullCfg,
    StructuredNullGate, StructuredRunCfg, StructuredRunReport, StructuredStream,
    StructuredVerdictCfg, StructuredVerdictProfile, confirm_structured_top_candidates,
    draw_out_of_family_random_plant, generate_structured_candidates, measure_structured_power,
    measure_structured_random_negative, run_structured_oracle_decode, structured_null_gate,
    structured_verdict,
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
        rank_beam: 32,
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
fn structured_generation_keeps_guaranteed_relabels_when_extra_budget_is_zero() {
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
    assert!(
        generated.guaranteed_candidates >= 1,
        "report: {generated:?}"
    );
    assert_eq!(generated.extra_candidates, 0);
    assert_eq!(generated.candidates.len(), generated.guaranteed_candidates);
    assert!(generated.dropped_by_cap > 0, "report: {generated:?}");
    assert_eq!(generated.dropped_by_filter, 0, "report: {generated:?}");
}

#[test]
fn structured_generation_reports_filter_drops() {
    let entries = toy_entries();
    let tokens = [0u8, 1, 2, 3].repeat(32);
    let stream = StructuredStream {
        label: "toy",
        tokens: tokens.as_slice(),
        n_classes: 4,
        tie_to: None,
    };
    let mut cfg = toy_cfg();
    cfg.max_decodes = 24;
    cfg.marginal_l1 = 0.0;
    let generated =
        generate_structured_candidates(&[stream], &entries, &cfg).expect("generation runs");
    assert!(
        generated.guaranteed_candidates >= 1,
        "report: {generated:?}"
    );
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
    let positive = measure_structured_power(
        TEXT,
        &power_cfg(),
        &entries,
        &lexicon,
        &solve,
        &toy_cfg(),
        2,
    )
    .expect("positive runs");
    assert!(positive.cleared_bar, "positive report: {positive:?}");
    assert!(positive.all_truth_decoded());
    assert!(
        positive
            .plants
            .iter()
            .all(|plant| plant.truth_candidate_rank.is_some())
    );
    assert!(
        positive
            .plants
            .iter()
            .all(|plant| plant.null.as_ref().is_some_and(|null| null.null_ge == 0)),
        "positive should clear its own matched null: {positive:?}"
    );
}

#[test]
fn structured_positive_requires_every_truth_candidate_to_decode() {
    let entries = toy_entries();
    let lexicon = build_lexicon(&entries).expect("lexicon builds");
    let solve = solve_cfg(128, 0, 0, 3.6, 3, 2048);
    let mut power = power_cfg();
    power.n_plants = 2;
    power.bar = 0.4;
    let positive = measure_structured_power(
        "catdogcatdogxx",
        &power,
        &entries,
        &lexicon,
        &solve,
        &toy_cfg(),
        0,
    )
    .expect("positive runs");

    assert!(
        positive
            .plants
            .iter()
            .any(|plant| plant.truth_candidate_rank.is_some() && plant.truth_score.is_none()),
        "fixture should include a generated truth coloring dropped at rank beam: {positive:?}"
    );
    assert!(
        positive.mean_recovery >= power.bar,
        "old mean-recovery-only gate would have cleared: {positive:?}"
    );
    assert!(!positive.all_truth_decoded());
    assert!(!positive.cleared_bar, "positive report: {positive:?}");
}

#[test]
fn structured_real_confirm_renders_topk_without_changing_rank_score() {
    let entries = toy_entries();
    let lexicon = build_lexicon(&entries).expect("lexicon builds");
    let solve = solve_cfg(128, 0, 0, 3.6, 2, 2048);
    let mut cfg = toy_cfg();
    cfg.rank_beam = 16;
    let plant = plant_from_text_with_coloring(
        TEXT,
        &PlantSpec {
            len: 12,
            n_classes: 4,
            copy: None,
        },
        std::array::from_fn(|letter| (letter % 4) as u8),
    )
    .expect("toy plant builds");
    let stream = StructuredStream {
        label: "toy-real",
        tokens: &plant.tokens,
        n_classes: 4,
        tie_to: None,
    };

    let mut report = run_structured_oracle_decode(&[stream], &entries, &lexicon, &solve, &cfg)
        .expect("rank pass runs");
    let rank_best = report.best_score().expect("rank pass surfaces a best");
    assert!(
        report
            .solutions
            .iter()
            .all(|candidate| candidate.confirm.is_none()),
        "rank pass should not perform confirmation: {report:?}"
    );

    confirm_structured_top_candidates(&mut report, &[stream], &lexicon, &solve)
        .expect("confirm pass runs");

    assert_eq!(report.best_score(), Some(rank_best));
    assert!(report.solutions.len() <= 2);
    assert!(
        report.solutions.iter().all(|candidate| {
            candidate.confirm.as_ref().is_some_and(|confirm| {
                confirm.beam == solve.beam
                    && confirm.solution.as_ref().is_some_and(|solution| {
                        !solution.rendered.is_empty() && solution.score.is_finite()
                    })
            })
        }),
        "confirm pass should render every top candidate: {report:?}"
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
    let positive =
        measure_structured_power(TEXT, &power, &entries, &lexicon, &solve, &toy_cfg(), 0)
            .expect("positive runs");
    assert!(positive.plants.is_empty());
    assert!(!positive.all_truth_decoded());
    assert!(!positive.cleared_bar, "positive report: {positive:?}");
}

#[test]
fn structured_random_coloring_negative_stays_quiet() {
    let entries = toy_entries();
    let lexicon = build_lexicon(&entries).expect("lexicon builds");
    let solve = solve_cfg(128, 0, 0, 3.6, 3, 2048);
    let negative = measure_structured_random_negative(
        TEXT,
        &power_cfg(),
        &entries,
        &lexicon,
        &solve,
        &toy_cfg(),
        &StructuredControlCfg {
            null_trials: 2,
            candidate_alpha: 1.0 / 3.0,
        },
    )
    .expect("negative runs");
    assert!(negative.quiet, "negative report: {negative:?}");
    assert_eq!(negative.false_positive_count(1.0 / 3.0), 0);
}

#[test]
fn structured_random_negative_redraws_family_collision() {
    let spec = PlantSpec {
        len: 12,
        n_classes: 4,
        copy: None,
    };
    let first = plant_from_text(TEXT, &spec, 99).expect("first draw builds");
    let mut forbidden = BTreeSet::new();
    let inserted = forbidden.insert(first.coloring);
    assert!(inserted);
    let (second, redraw_count) =
        draw_out_of_family_random_plant(TEXT, &spec, 99, 0, &forbidden).expect("redraw succeeds");
    assert_eq!(redraw_count, 1);
    assert_ne!(second.coloring, first.coloring);
    assert!(!forbidden.contains(&second.coloring));
}

#[test]
fn structured_null_gate_stays_quiet() {
    let entries = toy_entries();
    let lexicon = build_lexicon(&entries).expect("lexicon builds");
    let solve = solve_cfg(128, 0, 0, 3.6, 3, 2048);
    let positive = measure_structured_power(
        TEXT,
        &power_cfg(),
        &entries,
        &lexicon,
        &solve,
        &toy_cfg(),
        2,
    )
    .expect("positive runs");
    let observed_best = positive.plants.first().and_then(|plant| plant.best_score);
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
            observed_best,
            seed: 7,
        },
    )
    .expect("null runs");
    assert_eq!(null.null_bests.len(), 2);
    assert_eq!(null.null_ge, 0, "null report: {null:?}");
}

#[test]
fn structured_core_curated_profile_has_pre_broadening_base_count() {
    let entries = toy_entries();
    let tokens = [0u8, 1, 2, 3].repeat(8);
    let stream = StructuredStream {
        label: "curated",
        tokens: tokens.as_slice(),
        n_classes: 4,
        tie_to: None,
    };
    let mut cfg = toy_cfg();
    cfg.profile = StructuredFamilyProfile::CoreCurated;
    cfg.max_decodes = 0;
    cfg.marginal_l1 = 2.0;
    let generated =
        generate_structured_candidates(&[stream], &entries, &cfg).expect("generation runs");

    assert_eq!(generated.base_colorings, 374);
}

#[test]
fn structured_verdict_ignores_unrelated_negative_raw_score_shift() {
    let entries = toy_entries();
    let lexicon = build_lexicon(&entries).expect("lexicon builds");
    let solve = solve_cfg(128, 0, 0, 3.6, 3, 2048);
    let positive = measure_structured_power(
        TEXT,
        &power_cfg(),
        &entries,
        &lexicon,
        &solve,
        &toy_cfg(),
        2,
    )
    .expect("positive runs");
    let negative = measure_structured_random_negative(
        TEXT,
        &power_cfg(),
        &entries,
        &lexicon,
        &solve,
        &toy_cfg(),
        &StructuredControlCfg {
            null_trials: 2,
            candidate_alpha: 1.0 / 3.0,
        },
    )
    .expect("negative runs");
    let report = empty_structured_report();
    let real_null = StructuredNullGate {
        observed_best: None,
        null_bests: vec![Some(0.0), Some(1.0)],
        null_ge: 0,
    };
    let verdict_cfg = StructuredVerdictCfg {
        profile: StructuredVerdictProfile::Broad,
        plant_bar: 0.8,
        positive_alpha: 0.05,
        curated_truth_top_rank: 3,
        real_alpha: f64::NAN,
    };
    let before = structured_verdict(&report, &positive, &negative, &real_null, &verdict_cfg);
    let mut shifted_negative = negative.clone();
    if let Some(plant) = shifted_negative.plants.first_mut() {
        plant.best_score = Some(1_000_000.0);
    }
    let after = structured_verdict(
        &report,
        &positive,
        &shifted_negative,
        &real_null,
        &verdict_cfg,
    );

    assert_eq!(before, after);
}

fn empty_structured_report() -> StructuredRunReport {
    StructuredRunReport {
        generation: StructuredGenerationReport {
            base_colorings: 1,
            expanded_relabels: 1,
            candidates: Vec::new(),
            guaranteed_candidates: 0,
            extra_candidates: 0,
            dropped_by_filter: 0,
            l1_at_filter_cut: None,
            dropped_by_cap: 0,
            l1_at_cut: None,
        },
        attempts: Vec::new(),
        solutions: Vec::new(),
        total_expanded: 0,
    }
}

//! Structured-coloring verdict tests.

use super::campaign::{PowerCfg, solve_cfg};
use super::lexicon::{build_lexicon, parse_wordlist};
use super::structured::{
    StructuredControlCfg, StructuredFamilyProfile, StructuredGenerationReport,
    StructuredNegativeReport, StructuredNullGate, StructuredPlantOutcome, StructuredPowerReport,
    StructuredRunCfg, StructuredRunReport, StructuredVerdict, StructuredVerdictCfg,
    StructuredVerdictProfile, measure_structured_power, measure_structured_random_negative,
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
fn curated_low_power_controls_return_low_power_no_exclusion() {
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
    let verdict_cfg = StructuredVerdictCfg {
        profile: StructuredVerdictProfile::Curated,
        plant_bar: 0.8,
        plant_floor: 0.15,
        positive_alpha: 0.05,
        curated_truth_top_rank: 3,
        real_alpha: 0.02,
    };
    assert!(
        positive.all_truth_decoded(),
        "positive report: {positive:?}"
    );
    assert!(
        positive.all_recovery_at_bar(verdict_cfg.plant_bar),
        "positive report: {positive:?}"
    );
    assert_ne!(
        positive.curated_pass_count(
            verdict_cfg.plant_bar,
            verdict_cfg.positive_alpha,
            verdict_cfg.curated_truth_top_rank
        ),
        positive.plants.len(),
        "fixture must be statistically underpowered at curated alpha: {positive:?}"
    );
    let report = empty_structured_report();
    let real_null = empty_real_null();

    assert_eq!(
        structured_verdict(&report, &positive, &negative, &real_null, &verdict_cfg),
        StructuredVerdict::LowPowerNoExclusion
    );
}

#[test]
fn structured_recovery_gate_allows_between_floor_and_bar() {
    for profile in [
        StructuredVerdictProfile::Curated,
        StructuredVerdictProfile::Broad,
    ] {
        let verdict_cfg = StructuredVerdictCfg {
            profile,
            plant_bar: 0.4,
            plant_floor: 0.15,
            positive_alpha: 0.05,
            curated_truth_top_rank: 3,
            real_alpha: 0.02,
        };
        let positive = manual_power_report(&[(0.80, true), (0.30, false)]);
        assert!(positive.all_truth_decoded());
        assert!(positive.recovery_gate_cleared(verdict_cfg.plant_bar, verdict_cfg.plant_floor));
        assert!(!positive.all_recovery_at_bar(verdict_cfg.plant_bar));

        assert_eq!(
            structured_verdict(
                &empty_structured_report(),
                &positive,
                &quiet_negative_report(),
                &empty_real_null(),
                &verdict_cfg,
            ),
            StructuredVerdict::LowPowerNoExclusion
        );
    }
}

#[test]
fn structured_recovery_gate_fails_below_floor() {
    for profile in [
        StructuredVerdictProfile::Curated,
        StructuredVerdictProfile::Broad,
    ] {
        let verdict_cfg = StructuredVerdictCfg {
            profile,
            plant_bar: 0.4,
            plant_floor: 0.15,
            positive_alpha: 0.05,
            curated_truth_top_rank: 3,
            real_alpha: 0.02,
        };
        let positive = manual_power_report(&[(0.80, true), (0.10, false)]);
        assert!(positive.all_truth_decoded());
        assert!(positive.mean_recovery >= verdict_cfg.plant_bar);
        assert!(positive.any_recovery_below(verdict_cfg.plant_floor));

        assert_eq!(
            structured_verdict(
                &empty_structured_report(),
                &positive,
                &quiet_negative_report(),
                &empty_real_null(),
                &verdict_cfg,
            ),
            StructuredVerdict::ControlsFailed
        );
    }
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
    let real_null = empty_real_null();
    let verdict_cfg = StructuredVerdictCfg {
        profile: StructuredVerdictProfile::Broad,
        plant_bar: 0.8,
        plant_floor: 0.15,
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

fn manual_power_report(plants: &[(f64, bool)]) -> StructuredPowerReport {
    let outcomes = plants
        .iter()
        .enumerate()
        .map(
            |(index, &(recovery, truth_is_family_best))| StructuredPlantOutcome {
                recovery,
                truth_candidate_rank: Some(index + 1),
                truth_score_rank: Some(index + 1),
                truth_score: Some(10.0 - index as f32),
                best_score: Some(10.0),
                truth_is_family_best,
                null: Some(StructuredNullGate {
                    observed_best: Some(10.0 - index as f32),
                    null_bests: vec![Some(0.0), Some(1.0)],
                    null_candidate_counts: vec![1, 1],
                    null_ge: 0,
                }),
            },
        )
        .collect::<Vec<_>>();
    let mean_recovery =
        outcomes.iter().map(|plant| plant.recovery).sum::<f64>() / outcomes.len() as f64;
    StructuredPowerReport {
        plants: outcomes,
        mean_recovery,
        cleared_bar: true,
    }
}

fn quiet_negative_report() -> StructuredNegativeReport {
    StructuredNegativeReport {
        plants: Vec::new(),
        false_positive_like: 0,
        quiet: true,
    }
}

fn empty_real_null() -> StructuredNullGate {
    StructuredNullGate {
        observed_best: None,
        null_bests: vec![Some(0.0), Some(1.0)],
        null_candidate_counts: vec![0, 0],
        null_ge: 0,
    }
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

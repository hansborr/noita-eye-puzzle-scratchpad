use std::collections::BTreeSet;

use super::{
    AglGakConfig, AglGakMode, AglGakVerdict, AglMultiplierSubgroup, DEFAULT_SEED,
    fixed_point_enumeration, run_agl_gak,
};

#[test]
fn run_agl_gak_is_deterministic() {
    let config = AglGakConfig {
        seed: DEFAULT_SEED,
        null_trials: 257,
        mode: AglGakMode::FeasibilityOnly,
        subgroup: AglMultiplierSubgroup::Full,
    };
    assert_eq!(run_agl_gak(config).unwrap(), run_agl_gak(config).unwrap());
}

#[test]
fn eye_pins_match_verified_streams() {
    let config = AglGakConfig {
        null_trials: 257,
        ..AglGakConfig::default()
    };
    let report = run_agl_gak(config).unwrap();
    let first_values = report
        .message_first_symbols
        .iter()
        .map(|(_key, value)| *value)
        .collect::<Vec<_>>();
    assert_eq!(first_values, vec![50, 80, 36, 76, 63, 34, 27, 77, 33]);
    let distinct_starts = first_values.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(distinct_starts.len(), 9);
    assert!(report.shared_run_lengths.contains(&24));
    assert!(report.shared_run_lengths.contains(&20));
    let prefix = report.global_prefix.unwrap();
    assert_eq!(prefix.start, 1);
    assert_eq!(prefix.len, 2);
    assert_eq!(prefix.values, vec![66, 5]);
    assert_eq!(prefix.distinct_symbols, 2);
}

#[test]
fn fixed_point_enumeration_counts_reproduce() {
    let full = fixed_point_enumeration(AglMultiplierSubgroup::Full);
    assert_eq!(full.discrepancies, 6_724);
    assert_eq!(full.fixing_at_least_two_points, 0);
    assert_eq!(full.max_fixed_points, 1);

    let qr = fixed_point_enumeration(AglMultiplierSubgroup::QuadraticResidues);
    assert_eq!(qr.discrepancies, 3_362);
    assert_eq!(qr.fixing_at_least_two_points, 0);
    assert_eq!(qr.max_fixed_points, 1);
}

#[test]
fn positive_controls_fire_and_eyes_are_excluded() {
    let config = AglGakConfig {
        null_trials: 257,
        ..AglGakConfig::default()
    };
    let report = run_agl_gak(config).unwrap();
    assert!(report.positive_control_feasible_ok);
    assert!(report.positive_control_infeasible_ok);
    for subgroup in &report.subgroup_reports {
        assert_eq!(subgroup.verdict, AglGakVerdict::Excluded);
        assert_eq!(subgroup.agreement_check.violations, 0);
        assert_eq!(subgroup.forward_simulation.varying_shared_runs, 0);
        assert_eq!(subgroup.positive_controls.recovered_fixed_point, Some(42));
    }
}

#[test]
fn prefix_transcription_robustness_counts_are_pinned() {
    let config = AglGakConfig {
        null_trials: 257,
        ..AglGakConfig::default()
    };
    let report = run_agl_gak(config).unwrap();
    let robustness = report.transcription_robustness;

    assert_eq!(robustness.footprints.len(), 9);
    for footprint in &robustness.footprints {
        assert_eq!(
            footprint.digit_indices,
            vec![0, 1, 2, 3, 4, 39, 40, 41, 42],
            "{} footprint changed",
            footprint.message_key
        );
    }

    assert_eq!(robustness.singles.changed_digits, 1);
    assert_eq!(robustness.singles.total_variants, 324);
    assert_eq!(robustness.singles.excluded_variants, 324);
    assert_eq!(robustness.singles.global_prefix_obstruction_variants, 78);
    assert_eq!(robustness.singles.outside_alphabet_variants, 51);
    assert_eq!(robustness.singles.exact_verified_prefix_variants, 78);
    assert_eq!(robustness.singles.breaks.len(), 0);

    assert_eq!(robustness.doubles.changed_digits, 2);
    assert_eq!(robustness.doubles.total_variants, 5_184);
    assert_eq!(robustness.doubles.excluded_variants, 5_184);
    assert_eq!(robustness.doubles.global_prefix_obstruction_variants, 257);
    assert_eq!(robustness.doubles.outside_alphabet_variants, 1_516);
    assert_eq!(robustness.doubles.exact_verified_prefix_variants, 257);
    assert_eq!(robustness.doubles.breaks.len(), 0);
}

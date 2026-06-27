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

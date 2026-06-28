use super::{
    CALIBRATED_GEOMETRY, LeakCeilingConfig, TWO_COSETS, TWO_DOMINANT_OCCURRENCES, TWO_STREAM_LEN,
    binomial_f64, coupon_full_pin, coverage_undecidable_fraction, harmonic, log2_factorial,
    near_identity_neighborhood, odd_double_factorial, run_leak_ceiling,
};
use crate::report::Report;

fn close(actual: f64, expected: f64, eps: f64) {
    assert!(
        (actual - expected).abs() <= eps,
        "expected {expected}, got {actual} (eps {eps})"
    );
}

#[test]
fn analytic_primitives_are_exact() {
    close(log2_factorial(0), 0.0, 1e-12);
    close(log2_factorial(1), 0.0, 1e-12);
    close(log2_factorial(2), 1.0, 1e-12);
    close(harmonic(1), 1.0, 1e-12);
    close(harmonic(2), 1.5, 1e-12);
    close(binomial_f64(5, 2), 10.0, 1e-9);
    close(binomial_f64(83, 2), 3403.0, 1e-6);
    close(odd_double_factorial(0), 1.0, 1e-12);
    close(odd_double_factorial(1), 1.0, 1e-12);
    close(odd_double_factorial(2), 3.0, 1e-12);
    close(odd_double_factorial(3), 15.0, 1e-12);
    close(odd_double_factorial(4), 105.0, 1e-12);
    close(near_identity_neighborhood(83, 0), 1.0, 1e-12);
    close(coupon_full_pin(12), 29.818_879_797_456_006, 1e-9);
    close(coupon_full_pin(83), 366.763_770_447_117_7, 1e-9);
}

#[test]
fn coverage_model_edge_cases() {
    // Empty stream is fully undecidable.
    close(coverage_undecidable_fraction(83, 0, 10, 2.0), 1.0, 1e-12);
    // Saturating occurrences drive the decodable fraction to the cap.
    close(coverage_undecidable_fraction(4, 100, 1000, 2.0), 0.0, 1e-12);
}

#[test]
fn measured_supply_is_pinned() {
    let report = run_leak_ceiling(LeakCeilingConfig::default()).unwrap();
    let supply = &report.supply;
    assert_eq!(supply.total_trigrams, 1036);
    assert_eq!(supply.distinct_symbols, 83);
    assert_eq!(supply.alphabet_size, 83);
    assert_eq!(supply.out_degree.source_symbols, 83);
    assert_eq!(supply.out_degree.min, 3);
    assert_eq!(supply.out_degree.max, 19);
    close(supply.out_degree.mean, 10.240_963_855_421_686, 1e-9);
    // Headline chaining supply (broad gap-isomorph graph, deterministic).
    assert_eq!(supply.chaining.window_len, 11);
    assert_eq!(supply.chaining.links, 23232);
    assert_eq!(supply.chaining.distinct_contexts, 2112);
    assert_eq!(supply.chaining.distinct_edges, 20982);
    assert_eq!(supply.chaining.symbols_touched, 83);
    assert_eq!(supply.chaining.component_count, 1);
    assert_eq!(supply.chaining.largest_component, 83);
    // Isomorph occurrence-pair supply: scarce at short windows.
    let window4 = supply
        .isomorph
        .iter()
        .find(|iso| iso.window_len == 4)
        .unwrap();
    assert_eq!(window4.repeated_signature_kinds, 3);
    assert_eq!(window4.max_repeat_count, 9);
    assert_eq!(window4.aligned_occurrence_pairs, 56);
    assert_eq!(supply.dominant_occurrences, 9);
    assert_eq!(supply.richest_occurrences, 26);
    // Empirical entropy is near (but below) the flat 83-symbol ceiling.
    close(supply.entropy_bits_per_symbol, 5.793_2, 1e-3);
    assert!(supply.entropy_bits_per_symbol < supply.max_entropy_bits_per_symbol);
}

#[test]
fn demand_and_ceiling_are_consistent() {
    let report = run_leak_ceiling(LeakCeilingConfig::default()).unwrap();
    let demand = &report.demand;
    assert_eq!(demand.cert_degree_sharp, 82);
    assert_eq!(demand.cert_degree_low, 2);
    close(demand.coupon_full_pin_n83, 366.763_770_447_117_7, 1e-6);

    let ceiling = &report.ceiling;
    // Cannot pin even one S83 element: shortfall >> 1 either way.
    assert!(ceiling.per_element_shortfall_ratio > 10.0);
    assert!(ceiling.per_element_shortfall_ratio_richest > 5.0);
    // Underdetermination: unconstrained hopeless, near-identity far closer but still > 1.
    assert!(ceiling.underdetermination_unconstrained > 50.0);
    assert!(ceiling.underdetermination_near_identity > 1.0);
    assert!(ceiling.underdetermination_near_identity < ceiling.underdetermination_unconstrained);
    // The eyes are essentially fully undecidable at this budget.
    assert!(ceiling.eyes_undecidable_fraction > 0.95);
    assert!(ceiling.eyes_undecidable_richest > 0.95);
    close(
        ceiling.eyes_unique_fraction,
        1.0 - ceiling.eyes_undecidable_fraction,
        1e-12,
    );
}

#[test]
fn two_calibration_lands_in_band() {
    // Sanity check (not a falsifiable positive control): the single-point,
    // one-free-parameter (G) fit pins the arithmetic; only G=2 lands in band.
    let report = run_leak_ceiling(LeakCeilingConfig::default()).unwrap();
    let calibration = &report.calibration;
    let predicted = coverage_undecidable_fraction(
        TWO_COSETS,
        TWO_STREAM_LEN,
        TWO_DOMINANT_OCCURRENCES,
        CALIBRATED_GEOMETRY,
    );
    // G1b measured 76-83% undecidable (15-24% uniquely covered).
    assert!(
        (0.76..=0.83).contains(&predicted),
        "two undecidable {predicted} outside measured band 0.76..=0.83"
    );
    assert!(calibration.passes);
    assert!((0.15..=0.24).contains(&calibration.predicted_unique));
    // The eyes prediction is robust to the single geometry constant.
    for fraction in calibration.eyes_undecidable_g_band {
        assert!(
            fraction > 0.95,
            "eyes undecidable {fraction} not robustly high across G"
        );
    }
}

#[test]
fn scaling_sweep_crossings_are_located() {
    let report = run_leak_ceiling(LeakCeilingConfig::default()).unwrap();
    let scaling = &report.scaling;
    assert_eq!(scaling.fixed_m, 1036);
    assert_eq!(scaling.crossing_50, Some(4));
    assert_eq!(scaling.crossing_90, Some(20));
    // The curve is monotone non-decreasing across the swept N.
    let mut previous = 0.0_f64;
    for point in &scaling.points {
        assert!(
            point.undecidable_fraction >= previous - 1e-9,
            "non-monotone at N={}",
            point.cosets
        );
        previous = point.undecidable_fraction;
    }
    // The eyes endpoint sits near the top of the curve.
    let eyes = scaling.points.last().unwrap();
    assert_eq!(eyes.cosets, 83);
    assert!(eyes.undecidable_fraction > 0.99);
}

#[test]
fn report_is_deterministic_and_renders() {
    let first = run_leak_ceiling(LeakCeilingConfig::default()).unwrap();
    let second = run_leak_ceiling(LeakCeilingConfig::default()).unwrap();
    assert_eq!(first, second);
    let rendered = first.render();
    assert!(rendered.contains("G3 isomorph-leak information ceiling"));
    assert!(rendered.contains("Part D — single-point geometry calibration"));
    assert!(rendered.contains("IN-BAND"));
}

#[test]
fn zero_isomorph_window_is_rejected() {
    let config = LeakCeilingConfig {
        isomorph_window_len: 0,
        ..LeakCeilingConfig::default()
    };
    assert!(run_leak_ceiling(config).is_err());
}

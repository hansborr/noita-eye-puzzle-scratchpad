//! Rendering for the G3 leak-ceiling report.
//!
//! Extracted verbatim from the leaf module; the byte-exact stdout render — every
//! honesty label and caveat — is preserved unchanged.

use crate::analysis::orders;
use crate::report::{self, Report};

use super::{
    AnalyticDemand, CALIBRATED_GEOMETRY, CalibrationControl, CeilingEstimate, ChainingSupply,
    EmpiricalSupply, LeakCeilingReport, LeakCeilingStreamReport, ScalingSweep, StreamCeilingBounds,
    StreamDemand, TWO_COSETS, TWO_DOMINANT_OCCURRENCES, coupon_full_pin,
};

impl Report for LeakCeilingReport {
    fn render(&self) -> String {
        let mut out = String::new();
        append_header(&mut out, self);
        report::appendln!(&mut out);
        append_supply(&mut out, &self.supply, self.config.isomorph_window_len);
        report::appendln!(&mut out);
        append_demand(&mut out, &self.demand);
        report::appendln!(&mut out);
        append_ceiling(&mut out, &self.ceiling);
        report::appendln!(&mut out);
        append_calibration(&mut out, &self.calibration);
        report::appendln!(&mut out);
        append_scaling(&mut out, &self.scaling);
        report::appendln!(&mut out);
        append_interpretation(&mut out, self);
        out
    }
}

fn append_header(out: &mut String, report: &LeakCeilingReport) {
    report::appendln!(out, "G3 isomorph-leak information ceiling");
    report::appendln!(
        out,
        "order: {} (chaining window/core {}/{}, isomorph reference window {})",
        orders::accepted_honeycomb_order().name(),
        report.config.chaining_window_len,
        report.config.chaining_core_len,
        report.config.isomorph_window_len
    );
    report::appendln!(
        out,
        "labels: supply=measured; demand/ceiling=analytic & model-conditional; MI figure=upper bound; coupon demand for maximal H=S82 (N=83 cosets) and scales down with larger H"
    );
}

fn append_supply(out: &mut String, supply: &EmpiricalSupply, isomorph_window_len: usize) {
    report::appendln!(out, "Part A — empirical supply (measured, read-only)");
    report::appendln!(
        out,
        "  M (trigrams): {}   distinct symbols: {}/{}",
        supply.total_trigrams,
        supply.distinct_symbols,
        supply.alphabet_size
    );
    report::appendln!(
        out,
        "  message lengths: {}",
        report::format_message_lengths(&supply.message_lengths)
    );
    report::appendln!(
        out,
        "  raw successor out-degree: source symbols {} mean {:.3} min {} max {} branching {:.3} bits",
        supply.out_degree.source_symbols,
        supply.out_degree.mean,
        supply.out_degree.min,
        supply.out_degree.max,
        supply.out_degree.branching_bits
    );
    report::appendln!(
        out,
        "    (the eyes' analogue of G1b's flat out-degree 8 on all 12 `two` symbols; here it is uneven, 3..19)"
    );
    report::appendln!(
        out,
        "  out-degree histogram (degree:symbols): {}",
        report::format_histogram(&supply.out_degree.histogram)
    );
    append_chaining_line(out, "chaining supply (headline)", supply.chaining);
    for sensitivity in &supply.chaining_sensitivity {
        append_chaining_line(out, "chaining supply (sensitivity)", *sensitivity);
    }
    report::appendln!(
        out,
        "    caveat: this is the broad gap-isomorph graph (collision-prone); full 83/83 coverage is not same-plaintext genuine supply (see chaining_graph.rs)."
    );
    report::appendln!(
        out,
        "  repeated-isomorph occurrence-pair supply (pooled across messages):"
    );
    for iso in &supply.isomorph {
        report::appendln!(
            out,
            "    window {:>2}: kinds {:>2} max-repeat {:>2} aligned-occ-pairs SumC(occ,2) {:>4} (redundant) informative-windows {}",
            iso.window_len,
            iso.repeated_signature_kinds,
            iso.max_repeat_count,
            iso.aligned_occurrence_pairs,
            iso.informative_windows
        );
    }
    report::appendln!(
        out,
        "  dominant signature occurrences: {} (window {}, length-matched to G1b two's 76); richest across windows: {}",
        supply.dominant_occurrences,
        isomorph_window_len,
        supply.richest_occurrences
    );
    report::appendln!(
        out,
        "  empirical per-symbol entropy H_emp: {:.4} bits (message-weighted; uniform ceiling log2(83) = {:.4})",
        supply.entropy_bits_per_symbol,
        supply.max_entropy_bits_per_symbol
    );
}

fn append_chaining_line(out: &mut String, label: &str, supply: ChainingSupply) {
    report::appendln!(
        out,
        "  {label} w{}/c{}: links {} contexts {} distinct-edges {} | touched {} comps {} largest {} | core touched {} core-comps {} core-largest {}",
        supply.window_len,
        supply.core_len,
        supply.links,
        supply.distinct_contexts,
        supply.distinct_edges,
        supply.symbols_touched,
        supply.component_count,
        supply.largest_component,
        supply.core_supported_symbols,
        supply.core_supported_components,
        supply.core_largest_component
    );
}

fn append_demand(out: &mut String, demand: &AnalyticDemand) {
    report::appendln!(out, "Part B — demand (analytic, model-conditional)");
    report::appendln!(
        out,
        "  edge-overlap certification degree t(N={}): sharp S_N regime t = N-1 = {}; low-transitivity (dihedral) t = {}",
        demand.cosets,
        demand.cert_degree_sharp,
        demand.cert_degree_low
    );
    report::appendln!(
        out,
        "  coupon-collector full-pin demand: exact >=N-1 N*(H_N-1) = {:.1} (N=83; the Part C headline demand); full-collection asymptotic N*lnN slightly larger: N=83 -> {:.1}, N=12 -> {:.1}",
        demand.coupon_harmonic_exact,
        demand.coupon_full_pin_n83,
        demand.coupon_full_pin_n12
    );
    report::appendln!(
        out,
        "  (one keystream element is fully pinned only after observing its permutation on >= N-1 of N cosets)"
    );
}

fn append_ceiling(out: &mut String, ceiling: &CeilingEstimate) {
    report::appendln!(out, "Part C — the ceiling (supply vs demand)");
    report::appendln!(
        out,
        "  per-element recurrence shortfall: demand exact >=N-1 N*(H_N-1) = {:.1} (full-collection N*lnN slightly larger); supply occ (length-matched) = {} -> shortfall {:.1}x; richest occ = {} -> shortfall {:.1}x",
        ceiling.per_element_demand,
        ceiling.per_element_supply,
        ceiling.per_element_shortfall_ratio,
        ceiling.per_element_supply_richest,
        ceiling.per_element_shortfall_ratio_richest
    );
    report::appendln!(
        out,
        "    => cannot fully pin even one element's S83 coset-permutation (shortfall >> 1; cf. two's ratio {:.2} < 1)",
        coupon_full_pin(TWO_COSETS) / TWO_DOMINANT_OCCURRENCES as f64
    );
    report::appendln!(
        out,
        "  MI upper bound on leaked bits (bounds the per-position keystream, not a GAK seed): M*H_emp = {:.0} bits",
        ceiling.mi_upper_bound_bits
    );
    report::appendln!(
        out,
        "  needed per-position keystream entropy (i) unconstrained S_N: M*log2(N!) = {:.0} bits -> underdetermination {:.1}x",
        ceiling.key_bits_unconstrained,
        ceiling.underdetermination_unconstrained
    );
    report::appendln!(
        out,
        "  needed per-position keystream entropy (ii) near-identity (<=4 swaps/letter): log2(neighborhood) = {:.1} bits/letter, M* = {:.0} bits -> underdetermination {:.1}x (per-symbol 41.9/5.79, independent of the M=1036 budget)",
        ceiling.near_identity_neighborhood_log2,
        ceiling.key_bits_near_identity,
        ceiling.underdetermination_near_identity
    );
    report::appendln!(
        out,
        "    => the near-identity prior is what makes recovery even conceivable ({:.0}x -> {:.0}x), but it is still > 1: too little to pin the per-position keystream (a model-free chaining recovery's object), not a GAK deck seed (~log2(83!)~414 bits, which 6002 bits over-determines). This treats all M positions as independent S_N draws (maximal H=S82); under a smaller hidden subgroup the leak could suffice.",
        ceiling.underdetermination_unconstrained,
        ceiling.underdetermination_near_identity
    );
    report::appendln!(
        out,
        "  coverage model -> eyes undecidable fraction: {} (w4-matched); {} (richest signature)",
        report::format_percent(ceiling.eyes_undecidable_fraction),
        report::format_percent(ceiling.eyes_undecidable_richest)
    );
}

fn append_calibration(out: &mut String, calibration: &CalibrationControl) {
    report::appendln!(
        out,
        "Part D — single-point geometry calibration (one fitted constant; sanity check, not a licensing gate)"
    );
    report::appendln!(
        out,
        "  feed G1b two: N={} M={} dominant-occ={} out-degree={}",
        calibration.cosets,
        calibration.stream_len,
        calibration.dominant_occurrences,
        calibration.out_degree
    );
    report::appendln!(
        out,
        "  model predicts undecidable {} (unique {}); G1b measured band {}..{} undecidable -> single-point fit {} (one free constant G fit to one band; only G=2 lands: G=1->~89%, G=3->~67% -> a fit, not an independent prediction)",
        report::format_percent(calibration.predicted_undecidable),
        report::format_percent(calibration.predicted_unique),
        report::format_percent(calibration.measured_undecidable_low),
        report::format_percent(calibration.measured_undecidable_high),
        if calibration.passes {
            "IN-BAND"
        } else {
            "OUT-OF-BAND"
        }
    );
    report::appendln!(
        out,
        "    weakness (a) length-matched miss: fed two's L=4 occ=76 the model says 78.3% undecidable but G1b measured L=4 is 83% (band's high edge); decodable 151.8 vs measured uniquely-covered 105 (~45% optimistic) -- only lands in band because [0.76,0.83] also spans the L=6 row.\n    weakness (b) regime mismatch: for two occ=76>N=12 the coverage factor (1-(1-1/N)^occ)=0.9987 is saturated (~1) and was never exercised; for the eyes occ<<N so that factor (0.10/0.27) is load-bearing -- eyes survive even at coverage=1 (~95% undecidable)."
    );
    let [g1, g2, g3] = calibration.eyes_undecidable_g_band;
    report::appendln!(
        out,
        "  eyes undecidable robustness over geometry G in {{1,2,3}}: {} / {} / {} (this robustness, not the calibration, carries the conclusion)",
        report::format_percent(g1),
        report::format_percent(g2),
        report::format_percent(g3)
    );
    report::appendln!(
        out,
        "  scope: calibrated at the length-4 reference window; coverage-saturated regime; not claimed to track G1b's phrase-length dependence; eyes conclusion robust to G."
    );
}

fn append_scaling(out: &mut String, scaling: &ScalingSweep) {
    report::appendln!(
        out,
        "Part D — scaling sweep undecidable_fraction(N) at fixed M = {}",
        scaling.fixed_m
    );
    report::appendln!(
        out,
        "  occ(N) = M/N (near-uniform dominant-repeat rate); geometry G = {:.0} (G1b-calibrated)",
        CALIBRATED_GEOMETRY
    );
    report::appendln!(
        out,
        "  crosses 50% at N = {}; crosses 90% at N = {}",
        scaling
            .crossing_50
            .map_or_else(|| "n/a".to_owned(), |n| n.to_string()),
        scaling
            .crossing_90
            .map_or_else(|| "n/a".to_owned(), |n| n.to_string())
    );
    for point in &scaling.points {
        if matches!(point.cosets, 4 | 12 | 20 | 32 | 50 | 83) {
            report::appendln!(
                out,
                "    N {:>2}: occ {:>5.1} undecidable {}",
                point.cosets,
                point.occurrences,
                report::format_percent(point.undecidable_fraction)
            );
        }
    }
    report::appendln!(
        out,
        "  anchors: two ~ N=12 (measured ~78-83% undecidable); eyes = N=83."
    );
}

fn append_interpretation(out: &mut String, report: &LeakCeilingReport) {
    report::appendln!(out, "Interpretation");
    report::appendln!(
        out,
        "  Wiki question \"is chaining recovery even possible for the eyes?\": the answer is a quantified no at this trigram budget. The richest aligned isomorph signature ({} occurrences) falls {:.0}x short of the {:.0} aligned observations needed to pin even one S83 coset-permutation, and the coverage model (calibrated to reproduce G1b's two collapse) predicts ~{} of the {} transitions undecidable.",
        report.ceiling.per_element_supply_richest,
        report.ceiling.per_element_shortfall_ratio_richest,
        report.ceiling.per_element_demand,
        report::format_percent(report.ceiling.eyes_undecidable_richest),
        report.supply.total_trigrams
    );
    report::appendln!(
        out,
        "  This bounds recoverability only; it makes no claim that the eyes are or are not GAK. Assumptions: coupon demand for maximal H=S82 (scales down with larger H); MI figure is an upper bound; coverage model is analytic with one G1b-calibrated geometry constant."
    );
}

// ---------------------------------------------------------------------------
// Stream path render (file-driven; measured supply + textbook demand + bounds).
//
// Deliberately omits the fitted coverage / undecidable-fraction prediction, its
// single-point fit, and the scaling sweep -- those are gated to the eye path. This
// render is provenance-neutral (no eye / wiki / GAK / G3 citations) and makes no
// recoverability prediction.
// ---------------------------------------------------------------------------

impl Report for LeakCeilingStreamReport {
    fn render(&self) -> String {
        let mut out = String::new();
        append_stream_header(&mut out, self);
        report::appendln!(&mut out);
        append_stream_supply(&mut out, &self.supply, self.config.isomorph_window_len);
        report::appendln!(&mut out);
        append_stream_demand(&mut out, &self.demand);
        report::appendln!(&mut out);
        append_stream_bounds(&mut out, &self.bounds);
        report::appendln!(&mut out);
        append_stream_interpretation(&mut out);
        out
    }
}

fn append_stream_header(out: &mut String, report: &LeakCeilingStreamReport) {
    report::appendln!(
        out,
        "leak supply / demand / bounds (file-driven; measured + textbook, no fitted recoverability model)"
    );
    report::appendln!(
        out,
        "order: {} (chaining window/core {}/{}, isomorph reference window {})",
        report.order.name(),
        report.config.chaining_window_len,
        report.config.chaining_core_len,
        report.config.isomorph_window_len
    );
    report::appendln!(
        out,
        "labels: supply=measured; demand=analytic coupon-collector over N; bounds=information-theoretic/counting inequalities. No recoverability prediction is made here: the fitted coverage model is omitted because its single free constant was reverse-fit to one measurement with no matched null and no buildable positive control. What follows are direct measurements, a textbook evidence demand, and bounds -- not a prediction of how much is recoverable."
    );
}

fn append_stream_supply(out: &mut String, supply: &EmpiricalSupply, isomorph_window_len: usize) {
    report::appendln!(out, "Part A -- empirical supply (measured, read-only)");
    report::appendln!(
        out,
        "  M (trigrams): {}   distinct symbols: {}/{}",
        supply.total_trigrams,
        supply.distinct_symbols,
        supply.alphabet_size
    );
    report::appendln!(
        out,
        "  message lengths: {}",
        report::format_message_lengths(&supply.message_lengths)
    );
    report::appendln!(
        out,
        "  raw successor out-degree: source symbols {} mean {:.3} min {} max {} branching {:.3} bits",
        supply.out_degree.source_symbols,
        supply.out_degree.mean,
        supply.out_degree.min,
        supply.out_degree.max,
        supply.out_degree.branching_bits
    );
    report::appendln!(
        out,
        "  out-degree histogram (degree:symbols): {}",
        report::format_histogram(&supply.out_degree.histogram)
    );
    append_chaining_line(out, "chaining supply (headline)", supply.chaining);
    for sensitivity in &supply.chaining_sensitivity {
        append_chaining_line(out, "chaining supply (sensitivity)", *sensitivity);
    }
    report::appendln!(
        out,
        "    note: this is the broad gap-isomorph chaining graph (collision-prone); a full N/N touch is not same-plaintext genuine supply."
    );
    report::appendln!(
        out,
        "  repeated-isomorph occurrence-pair supply (pooled across messages):"
    );
    for iso in &supply.isomorph {
        report::appendln!(
            out,
            "    window {:>2}: kinds {:>2} max-repeat {:>2} aligned-occ-pairs SumC(occ,2) {:>4} (redundant) informative-windows {}",
            iso.window_len,
            iso.repeated_signature_kinds,
            iso.max_repeat_count,
            iso.aligned_occurrence_pairs,
            iso.informative_windows
        );
    }
    report::appendln!(
        out,
        "  dominant signature occurrences: {} (window {}); richest across windows: {}",
        supply.dominant_occurrences,
        isomorph_window_len,
        supply.richest_occurrences
    );
    report::appendln!(
        out,
        "  empirical per-symbol entropy H_emp: {:.4} bits (message-weighted; uniform ceiling log2(N) = {:.4})",
        supply.entropy_bits_per_symbol,
        supply.max_entropy_bits_per_symbol
    );
}

fn append_stream_demand(out: &mut String, demand: &StreamDemand) {
    report::appendln!(
        out,
        "Part B -- demand (analytic coupon-collector over N = {})",
        demand.cosets
    );
    report::appendln!(
        out,
        "  edge-overlap certification degree t(N={}): sharp S_N regime t = N-1 = {}; low-transitivity (dihedral) t = {}",
        demand.cosets,
        demand.cert_degree_sharp,
        demand.cert_degree_low
    );
    report::appendln!(
        out,
        "  coupon-collector full-pin demand: exact >=N-1 N*(H_N-1) = {:.1}; full-collection asymptotic N*lnN = {:.1}",
        demand.coupon_harmonic_exact,
        demand.coupon_full_pin
    );
    report::appendln!(
        out,
        "  (one keystream element is fully pinned only after observing its permutation on >= N-1 of N cosets)"
    );
}

fn append_stream_bounds(out: &mut String, bounds: &StreamCeilingBounds) {
    report::appendln!(
        out,
        "Part C -- bounds (counting / information-theoretic inequalities; no fitted prediction)"
    );
    report::appendln!(
        out,
        "  per-element evidence demand vs measured supply (a counting bound, not a recovery probability): demand exact >=N-1 N*(H_N-1) = {:.1}; supply occ (length-matched) = {} -> ratio {:.1}x; richest occ = {} -> ratio {:.1}x",
        bounds.per_element_demand,
        bounds.per_element_supply,
        bounds.per_element_shortfall_ratio,
        bounds.per_element_supply_richest,
        bounds.per_element_shortfall_ratio_richest
    );
    report::appendln!(
        out,
        "  MI upper bound on leaked bits (bounds the per-position keystream): M*H_emp = {:.0} bits",
        bounds.mi_upper_bound_bits
    );
    report::appendln!(
        out,
        "  needed per-position keystream entropy (i) unconstrained S_N: M*log2(N!) = {:.0} bits -> underdetermination {:.1}x",
        bounds.key_bits_unconstrained,
        bounds.underdetermination_unconstrained
    );
    report::appendln!(
        out,
        "  needed per-position keystream entropy (ii) near-identity (<=4 swaps/element): log2(neighborhood) = {:.1} bits/element, M* = {:.0} bits -> underdetermination {:.1}x",
        bounds.near_identity_neighborhood_log2,
        bounds.key_bits_near_identity,
        bounds.underdetermination_near_identity
    );
}

fn append_stream_interpretation(out: &mut String) {
    report::appendln!(out, "Interpretation");
    report::appendln!(
        out,
        "  These are measurements (Part A supply), a textbook coupon-collector evidence demand (Part B), and information-theoretic / counting bounds (Part C) on the supplied stream(s). They are NOT a prediction of how much is recoverable: the fitted coverage model that would estimate a recoverable fraction is deliberately omitted here because its single free constant has no non-circular control. The demand/supply ratio and the underdetermination factors are bounds -- they state what the evidence at this budget cannot do; this run emits no candidate, no recovery, and no decode."
    );
}

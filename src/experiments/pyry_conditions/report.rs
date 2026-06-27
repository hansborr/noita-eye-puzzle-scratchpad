use super::{
    CandidateFamily, ConditionEvaluation, FLAT_IOC_NORMALIZED_CEILING, FamilyFixtureReport,
    MIN_SHARED_RUN_LEN, PyryCondition, PyryConditionsReport,
};
use crate::report::{self, Report};

impl Report for PyryConditionsReport {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(&mut out, "Pyry's Conditions falsification harness");
        report::appendln!(&mut out, "order: {}", self.order.name());
        report::appendln!(
            &mut out,
            "fixed alphabet: accepted honeycomb reading-layer values 0..=82"
        );
        report::appendln!(&mut out, "seed: {}", self.config.seed);
        report::appendln!(
            &mut out,
            "fixture draws per family: {}",
            self.config.fixture_draws
        );
        report::appendln!(
            &mut out,
            "message lengths: {}",
            report::format_message_lengths(&self.message_lengths)
        );
        report::appendln!(&mut out, "pooled eye length: {}", self.total_length);
        report::appendln!(
            &mut out,
            "boundary rule: predicates run per message where adjacency or windows matter; no window crosses a message join"
        );
        report::appendln!(
            &mut out,
            "fixture source: deterministic non-uniform 83-symbol plaintext with planted same-offset repeated sections, sampled with SplitMix64"
        );
        report::appendln!(
            &mut out,
            "scope: structural falsification only; no language scoring, no symbol-to-meaning mapping, no reading-order re-selection"
        );
        report::appendln!(&mut out);
        append_pyry_condition_legend(&mut out);
        report::appendln!(&mut out);
        append_pyry_matrix(&mut out, self);
        report::appendln!(&mut out);
        append_pyry_eye_scalars(&mut out, &self.eyes);
        report::appendln!(&mut out);
        append_pyry_fixture_keys(&mut out, self);
        report::appendln!(&mut out);
        append_pyry_interpretation(&mut out, self);
        out
    }
}

fn append_pyry_condition_legend(out: &mut String) {
    report::appendln!(out, "condition encoding");
    for condition in PyryCondition::all() {
        report::appendln!(out, "  {}: {}", condition.short_label(), condition.label());
    }
    report::appendln!(
        out,
        "  C1 threshold: pooled IoC x83 <= {:.3}",
        FLAT_IOC_NORMALIZED_CEILING
    );
    report::appendln!(
        out,
        "  C3/C5 shared-section threshold: same-offset run length >= {}",
        MIN_SHARED_RUN_LEN
    );
}

fn append_pyry_matrix(out: &mut String, report: &PyryConditionsReport) {
    report::appendln!(out, "falsification matrix");
    report::appendln!(
        out,
        "{:<24} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} {:>8} {:>10}",
        "row",
        "C1",
        "C2",
        "C3",
        "C4",
        "C5",
        "C6",
        "C7",
        "C8",
        "C9",
        "all9",
        "verdict"
    );
    append_pyry_eye_matrix_row(out, &report.eyes);
    for family in &report.families {
        append_pyry_family_matrix_row(out, family);
    }
}

fn append_pyry_eye_matrix_row(out: &mut String, evaluation: &ConditionEvaluation) {
    let verdict = if evaluation.vector.all_pass() {
        "sanity"
    } else {
        "partial"
    };
    let all_pass_count = format!("{}/9", evaluation.vector.passed_count());
    append_pyry_matrix_row(
        out,
        "eyes",
        PyryCondition::all()
            .into_iter()
            .map(|condition| yes_no(evaluation.vector.get(condition)).to_owned()),
        &all_pass_count,
        verdict,
    );
}

fn append_pyry_family_matrix_row(out: &mut String, family: &FamilyFixtureReport) {
    let draws = family.draws.len();
    let verdict = if family.all_conditions_pass_count > 0 {
        "consistent"
    } else {
        "falsified"
    };
    let all_pass_count = format!("{}/{}", family.all_conditions_pass_count, draws);
    append_pyry_matrix_row(
        out,
        family.family.label(),
        PyryCondition::all().into_iter().map(|condition| {
            let count = condition_pass_count(family, condition);
            format!("{count}/{draws}")
        }),
        &all_pass_count,
        verdict,
    );
}

fn append_pyry_matrix_row(
    out: &mut String,
    label: &str,
    cells: impl IntoIterator<Item = String>,
    all_pass_count: &str,
    verdict: &str,
) {
    let mut rendered_cells = cells.into_iter();
    let c1 = rendered_cells.next().unwrap_or_default();
    let c2 = rendered_cells.next().unwrap_or_default();
    let c3 = rendered_cells.next().unwrap_or_default();
    let c4 = rendered_cells.next().unwrap_or_default();
    let c5 = rendered_cells.next().unwrap_or_default();
    let c6 = rendered_cells.next().unwrap_or_default();
    let c7 = rendered_cells.next().unwrap_or_default();
    let c8 = rendered_cells.next().unwrap_or_default();
    let c9 = rendered_cells.next().unwrap_or_default();
    report::appendln!(
        out,
        "{:<24} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} {:>8} {:>10}",
        label,
        c1,
        c2,
        c3,
        c4,
        c5,
        c6,
        c7,
        c8,
        c9,
        all_pass_count,
        verdict
    );
}

fn condition_pass_count(family: &FamilyFixtureReport, condition: PyryCondition) -> usize {
    family
        .condition_pass_counts
        .get(condition.number().saturating_sub(1))
        .copied()
        .unwrap_or_default()
}

fn append_pyry_eye_scalars(out: &mut String, evaluation: &ConditionEvaluation) {
    let metrics = &evaluation.metrics;
    report::appendln!(out, "eye scalar diagnostics");
    report::appendln!(
        out,
        "  IoC {:.6} (x83 {:.3}); support {}/83, outside {}, range {}",
        metrics.pooled_ioc,
        metrics.normalized_ioc,
        metrics.distinct_in_alphabet,
        metrics.outside_alphabet,
        format_optional_u8_range(metrics.min_value, metrics.max_value)
    );
    report::appendln!(
        out,
        "  shared runs {}, longest {}, varying-prefix {}, differing-first/shared-second {}",
        metrics.shared_run_count,
        metrics.longest_shared_run,
        metrics.varying_prefix_shared_runs,
        metrics.differing_first_shared_second_cases
    );
    report::appendln!(
        out,
        "  isomorph groups {}, longest {:?}; near pairs {}; adjacent equals {}",
        metrics.repeated_isomorph_groups,
        metrics.longest_repeated_isomorph,
        metrics.near_isomorph_pairs,
        metrics.adjacent_equal_count
    );
    report::appendln!(
        out,
        "  non-shared isomorph groups {}, exact-duplicate groups {}",
        metrics.non_shared_isomorph_groups,
        metrics.non_shared_exact_duplicate_groups
    );
}

fn append_pyry_fixture_keys(out: &mut String, report: &PyryConditionsReport) {
    report::appendln!(out, "fixture key/source summaries from draw 0");
    for family in &report.families {
        let summary = family
            .draws
            .first()
            .map_or("n/a", |draw| draw.key_summary.as_str());
        report::appendln!(out, "  {}: {}", family.family.label(), summary);
    }
}

fn append_pyry_interpretation(out: &mut String, report: &PyryConditionsReport) {
    let consistent = report
        .families
        .iter()
        .filter(|family| family.all_conditions_pass_count > 0)
        .map(|family| family.family.label())
        .collect::<Vec<_>>();
    if consistent.is_empty() {
        report::appendln!(
            out,
            "Interpretation: no generated family jointly satisfied all nine conditions in this seeded fixture battery. That is a sample-conditional falsification signal, not a proof that the family is impossible."
        );
    } else {
        report::appendln!(
            out,
            "Interpretation: sampled fixture rows with at least one all-nine pass: {}. That is candidate-consistency only; it does not identify the cipher.",
            consistent.join(", ")
        );
    }

    if let Some(self_modifying) = report
        .families
        .iter()
        .find(|family| family.family == CandidateFamily::AutokeyAlbertiStyle)
    {
        report::appendln!(
            out,
            "Self-modifying direction: autokey/Alberti-style fixtures passed all nine in {}/{} draws. This specifically tests whether a plaintext-dependent state can produce the differing-first/shared-second pattern while keeping later same-offset material aligned.",
            self_modifying.all_conditions_pass_count,
            self_modifying.draws.len()
        );
        report::appendln!(
            out,
            "Fixture caveat: this autokey C8 (no-doubled-trigram) pass is partly structural to the fixture. Plaintext-autokey produces equal adjacent ciphertext only when the plaintext repeats at distance two, and the sampled plaintext is constructed to avoid distance-two repeats, so the 'consistent' verdict reflects compatibility under that source construction rather than a pure-cipher guarantee."
        );
    }

    report::appendln!(
        out,
        "Caveat: the nine conditions were abstracted from the eyes, so the eye row is a sanity baseline, not evidence. Fixture failures depend on sampled plaintexts and keys; fixture passes are not solutions."
    );
    report::appendln!(
        out,
        "Layer caveat: all rows use engine-fixed integer trigram values under the accepted honeycomb order. The rendered orientation layer and the 83-value reading layer are not conflated."
    );
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn format_optional_u8_range(min: Option<u8>, max: Option<u8>) -> String {
    match (min, max) {
        (Some(min), Some(max)) => format!("{min}..{max}"),
        _ => "n/a".to_owned(),
    }
}

use super::{
    AglGakMode, AglGakPositiveControls, AglGakReport, AglGakVerdict, AglMultiplierSubgroup,
};
use crate::report::{self, Report};

impl Report for AglGakReport {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(&mut out, "Thread 2 AGL(1,83)-GAK stress test");
        report::appendln!(&mut out, "order: {}", self.order.name());
        report::appendln!(&mut out, "seed: {}", self.config.seed);
        report::appendln!(
            &mut out,
            "forward-simulation trials per subgroup: {}",
            self.config.null_trials
        );
        report::appendln!(
            &mut out,
            "subgroups: C83:C82 and C83:C41 (preferred display order starts with {})",
            format_agl_subgroup(self.config.subgroup)
        );
        report::appendln!(
            &mut out,
            "mode: {}",
            match self.config.mode {
                AglGakMode::FeasibilityOnly => "feasibility-only",
                AglGakMode::FeasibilityAndFit => "feasibility+fit requested",
            }
        );
        report::appendln!(
            &mut out,
            "wiki pages under test: Affine-General-Linear-Group-(AGL).md; The-Transitivity-Restriction-(6-Groups-for-83).md; Message-Starts.md; Shared-Sections.md; Isomorphic-Cipher-Hierarchy.md"
        );
        report::appendln!(&mut out);
        append_agl_gak_observed(&mut out, self);
        report::appendln!(&mut out);
        append_agl_gak_subgroups(&mut out, self);
        report::appendln!(&mut out);
        append_agl_gak_interpretation(&mut out, self);
        out
    }
}

fn append_agl_gak_observed(out: &mut String, report: &AglGakReport) {
    report::appendln!(out, "observed mapping-independent structure");
    report::appendln!(
        out,
        "  first symbols: {}",
        report
            .message_first_symbols
            .iter()
            .map(|(key, value)| format!("{key}:{value}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    match &report.global_prefix {
        Some(prefix) => report::appendln!(
            out,
            "  all-message shared prefix: start {} len {} values {} distinct {}/{}",
            prefix.start,
            prefix.len,
            report::format_usize_values(&prefix.values),
            prefix.distinct_symbols,
            prefix.len
        ),
        None => report::appendln!(out, "  all-message shared prefix: none"),
    }
    report::appendln!(
        out,
        "  selected shared-run lengths: {}",
        report::format_usize_values(&report.shared_run_lengths)
    );
    report::appendln!(out, "  selected varying-run anchors:");
    for run in report
        .shared_runs
        .iter()
        .filter(|run| run.differing_predecessor && run.varying)
    {
        report::appendln!(
            out,
            "    {}/{} start {} len {} distinct {}/{} role {}",
            run.left_key,
            run.right_key,
            run.start,
            run.len,
            run.distinct_symbols,
            run.len,
            run.role.label()
        );
    }
}

fn append_agl_gak_subgroups(out: &mut String, report: &AglGakReport) {
    report::appendln!(out, "subgroup verdicts");
    // The "fixed>=2/universe" denominator is the exhaustive differing-discrepancy
    // universe size (6724 for C83:C82, 3362 for C83:C41); naming it makes clear the
    // exclusion is exhaustive over that universe rather than sampled.
    report::appendln!(
        out,
        "  {:<8} {:<9} {:>12} {:>16} {:>17} {:>14} {:<12}",
        "group",
        "verdict",
        "agreement",
        "forward",
        "fixed>=2/universe",
        "max fixed",
        "controls"
    );
    for subgroup in &report.subgroup_reports {
        report::appendln!(
            out,
            "  {:<8} {:<9} {:>5}/{:<6} {:>7}/{:<8} {:>7}/{:<9} {:>14} {:<12}",
            format_agl_subgroup(subgroup.subgroup),
            format_agl_verdict(subgroup.verdict),
            subgroup.agreement_check.violations,
            subgroup.agreement_check.checks,
            subgroup.forward_simulation.varying_shared_runs,
            subgroup.forward_simulation.trials,
            subgroup.fixed_points.fixing_at_least_two_points,
            subgroup.fixed_points.discrepancies,
            subgroup.fixed_points.max_fixed_points,
            format_agl_controls(subgroup.positive_controls)
        );
        if let Some(obstruction) = &subgroup.obstruction {
            report::appendln!(
                out,
                "    obstruction: {}/{} start {} len {} distinct {}/{} after predecessors {} vs {}",
                obstruction.left_key,
                obstruction.right_key,
                obstruction.start,
                obstruction.len,
                obstruction.distinct_symbols,
                obstruction.len,
                obstruction.left_predecessor,
                obstruction.right_predecessor
            );
        }
        report::appendln!(
            out,
            "    forward add-one p for a varying shared run: {}",
            report::format_probability(subgroup.forward_simulation.add_one_p_value)
        );
        if subgroup.fit_attempted {
            report::appendln!(
                out,
                "    fit: requested, but no fit is retained after the exhaustive structural exclusion"
            );
        }
    }
}

fn append_agl_gak_interpretation(out: &mut String, report: &AglGakReport) {
    let all_excluded = report
        .subgroup_reports
        .iter()
        .all(|subgroup| subgroup.verdict == AglGakVerdict::Excluded);
    if all_excluded {
        report::appendln!(
            out,
            "Interpretation: AGL(1,83)-GAK is rigorously excluded for both C83:C82 and C83:C41 under the verified right-multiplication / left-coset model. The wiki's tentative message-start exclusion was over-conceded / weaker than needed: the rigorous kill is the varying-shared-run mechanism. After a differing start, an affine discrepancy can fix at most one point, so any AGL shared run must be constant; the eyes' shared runs vary."
        );
    } else {
        report::appendln!(
            out,
            "Interpretation: this run did not exclude every requested AGL subgroup. Treat any structural fit as a hypothesis to kill with held-out isomorphs, not as a decode."
        );
    }
    report::appendln!(
        out,
        "Claim ceiling: this excludes one candidate group family and narrows the transitive GAK candidate set toward {{A83, S83}}, with D166 conditional elsewhere. It says nothing about recoverable plaintext; the eyes remain deterministic, engine-generated, strikingly structured data of unknown meaning; unsolved; no primary developer source confirms recoverable plaintext. Scope: this excludes the point-stabilizer AGL-GAK family (output = moved reference point, single shared running key); it does not speak to non-GAK affine constructions or a non-point-stabilizer hidden subgroup."
    );
    report::appendln!(
        out,
        "Multiplicity note: both AGL multiplier variants are tested, and the repeated tails reported here are structural/exhaustive checks rather than language-scoring claims."
    );
}

fn format_agl_subgroup(subgroup: AglMultiplierSubgroup) -> &'static str {
    match subgroup {
        AglMultiplierSubgroup::Full => "C83:C82",
        AglMultiplierSubgroup::QuadraticResidues => "C83:C41",
    }
}

fn format_agl_verdict(verdict: AglGakVerdict) -> &'static str {
    match verdict {
        AglGakVerdict::Excluded => "excluded",
        AglGakVerdict::NotExcluded => "open",
    }
}

fn format_agl_controls(controls: AglGakPositiveControls) -> &'static str {
    match (
        controls.constant_shared_run_ok,
        controls.pure_translation_rejected_ok,
    ) {
        (true, true) => "ok",
        (false, true) => "const-fail",
        (true, false) => "pure-fail",
        (false, false) => "failed",
    }
}

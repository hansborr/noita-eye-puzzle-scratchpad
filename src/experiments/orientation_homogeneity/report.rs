//! Cross-message orientation-frequency homogeneity report rendering.
//!
//! Holds the [`Report`] implementation for [`OrientationHomogeneityReport`] and
//! its `append_*`/`format_*` helpers, split out of the experiment body so the
//! compute lives separately.

use crate::report::{self, Report};

use super::{
    HomogeneityNullComparison, ORIENTATION_BUCKETS, OrientationHomogeneityReport,
    OrientationProfile, ScalarNullBand,
};

impl Report for OrientationHomogeneityReport {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(&mut out, "cross-message orientation-frequency homogeneity");
        report::appendln!(
            &mut out,
            "layer: engine-fixed single orientations 0..=4; delimiter 5 stripped"
        );
        report::appendln!(
            &mut out,
            "order independence: no honeycomb traversal, no trigram reading layer, no symbol-to-meaning guess"
        );
        report::appendln!(&mut out, "seed: {}", self.config.seed);
        report::appendln!(&mut out, "seed streams: {}", self.config.seed_count);
        report::appendln!(&mut out, "trials per seed: {}", self.config.trials_per_seed);
        report::appendln!(
            &mut out,
            "total repartitions: {}",
            self.config
                .trials_per_seed
                .saturating_mul(self.config.seed_count)
        );
        report::appendln!(
            &mut out,
            "message lengths: {}",
            format_orientation_profile_lengths(&self.profiles)
        );
        report::appendln!(
            &mut out,
            "total orientations: {} (verified eye-count sum {})",
            self.total_orientations,
            self.total_eye_count
        );
        report::appendln!(
            &mut out,
            "null: shuffle the pooled orientation multiset and repartition into the true message lengths"
        );
        report::appendln!(&mut out);
        append_orientation_profiles(&mut out, self);
        report::appendln!(&mut out);
        append_orientation_uniform_context(&mut out, self);
        report::appendln!(&mut out);
        append_orientation_homogeneity_statistics(&mut out, self);
        report::appendln!(&mut out);
        append_orientation_repartition_null(&mut out, self);
        report::appendln!(&mut out);
        append_orientation_positive_control(&mut out, self);
        report::appendln!(&mut out);
        append_orientation_homogeneity_interpretation(&mut out, self);
        out
    }
}

fn append_orientation_profiles(out: &mut String, report: &OrientationHomogeneityReport) {
    report::appendln!(out, "per-message orientation profiles");
    report::appendln!(
        out,
        "{:<6} {:>5} {:>5} {:>5} {:>5} {:>5} {:>5} {:>8} {:>8} {:>8} {:>8} {:>8}",
        "msg",
        "len",
        "c0",
        "c1",
        "c2",
        "c3",
        "c4",
        "f0",
        "f1",
        "f2",
        "f3",
        "f4"
    );
    for profile in &report.profiles {
        let [c0, c1, c2, c3, c4] = profile.counts;
        let [f0, f1, f2, f3, f4] = profile.frequencies;
        report::appendln!(
            out,
            "{:<6} {:>5} {:>5} {:>5} {:>5} {:>5} {:>5} {:>8.4} {:>8.4} {:>8.4} {:>8.4} {:>8.4}",
            profile.message_key,
            profile.length,
            c0,
            c1,
            c2,
            c3,
            c4,
            f0,
            f1,
            f2,
            f3,
            f4
        );
    }
}

fn append_orientation_uniform_context(out: &mut String, report: &OrientationHomogeneityReport) {
    let uniform = report.pooled_uniform;
    report::appendln!(out, "pooled orientation-frequency context");
    report::appendln!(
        out,
        "pooled counts: {}",
        format_orientation_counts(&uniform.counts)
    );
    report::appendln!(
        out,
        "pooled chi-square vs uniform: {} df {} p>=chi2 {}",
        report::format_chi_square(uniform.chi_square_vs_uniform),
        uniform.degrees_of_freedom,
        report::format_chi_square_p_value(uniform.asymptotic_upper_tail_p)
    );
}

fn append_orientation_homogeneity_statistics(
    out: &mut String,
    report: &OrientationHomogeneityReport,
) {
    let homogeneity = report.homogeneity;
    report::appendln!(out, "observed cross-message homogeneity statistics");
    report::appendln!(
        out,
        "Pearson X^2: {} df {} asymptotic p>=X^2 {}",
        report::format_chi_square(homogeneity.pearson_chi_square),
        homogeneity.degrees_of_freedom,
        report::format_chi_square_p_value(homogeneity.pearson_asymptotic_upper_tail_p)
    );
    report::appendln!(
        out,
        "G-test: {} df {} asymptotic p>=G {}",
        report::format_chi_square(homogeneity.g_test),
        homogeneity.degrees_of_freedom,
        report::format_chi_square_p_value(homogeneity.g_test_asymptotic_upper_tail_p)
    );
}

fn append_orientation_repartition_null(out: &mut String, report: &OrientationHomogeneityReport) {
    report::appendln!(out, "length-matched repartition null");
    report::appendln!(
        out,
        "{:<12} {:>10} {:>10} {:>19} {:>20} {:>10} {:>10} {:>10}",
        "stat",
        "observed",
        "mean",
        "null 95%",
        "null min/med/max",
        "p<=obs",
        "p>=obs",
        "p2"
    );
    append_homogeneity_null_row(out, "Pearson X^2", report.pearson_null);
    append_homogeneity_null_row(out, "G-test", report.g_test_null);
}

fn append_homogeneity_null_row(
    out: &mut String,
    label: &str,
    comparison: HomogeneityNullComparison,
) {
    report::appendln!(
        out,
        "{:<12} {:>10} {:>10.3} {:>19} {:>20} {:>10} {:>10} {:>10}",
        label,
        report::format_chi_square(comparison.observed),
        comparison.null.mean,
        format_null_band_f64(comparison.null.q025, comparison.null.q975),
        format_null_min_median_max(comparison.null),
        report::format_probability(comparison.lower_tail_add_one_p),
        report::format_probability(comparison.upper_tail_add_one_p),
        report::format_probability(comparison.two_sided_add_one_p)
    );
}

fn append_orientation_positive_control(out: &mut String, report: &OrientationHomogeneityReport) {
    report::appendln!(out, "heterogeneous positive control");
    report::appendln!(
        out,
        "fixture: same nine lengths, but each synthetic message has a deliberately different dominant orientation"
    );
    report::appendln!(
        out,
        "{:<12} {:>10} {:>19} {:>10} {:>10}",
        "stat",
        "observed",
        "null 95%",
        "p>=obs",
        "verdict"
    );
    append_positive_homogeneity_row(out, "Pearson X^2", report.positive_control.pearson);
    append_positive_homogeneity_row(out, "G-test", report.positive_control.g_test);
}

fn append_positive_homogeneity_row(
    out: &mut String,
    label: &str,
    comparison: HomogeneityNullComparison,
) {
    let verdict = if comparison.observed > comparison.null.q975 {
        "upper-tail"
    } else {
        "inside"
    };
    report::appendln!(
        out,
        "{:<12} {:>10} {:>19} {:>10} {:>10}",
        label,
        report::format_chi_square(comparison.observed),
        format_null_band_f64(comparison.null.q025, comparison.null.q975),
        report::format_probability(comparison.upper_tail_add_one_p),
        verdict
    );
}

fn append_orientation_homogeneity_interpretation(
    out: &mut String,
    report: &OrientationHomogeneityReport,
) {
    let pearson = report.pearson_null;
    let g_test = report.g_test_null;
    if pearson.observed < pearson.null.median && pearson.lower_tail_add_one_p <= 0.05 {
        report::appendln!(
            out,
            "Interpretation: the Pearson statistic is in the lower tail of the length-matched repartition null, so the nine messages are more homogeneous in orientation frequencies than random repartitions of the same pooled symbols. The G-test lower-tail p is {}.",
            report::format_probability(g_test.lower_tail_add_one_p)
        );
        report::appendln!(
            out,
            "That is an order-independent shared-source distribution signature. It constrains source homogeneity only; it does not imply meaning, and a single deterministic generator emitting structured-but-meaningless data remains an equally valid explanation."
        );
    } else if pearson.observed > pearson.null.median && pearson.upper_tail_add_one_p <= 0.05 {
        report::appendln!(
            out,
            "Interpretation: the Pearson statistic is in the upper tail of the length-matched repartition null, so the messages are more heterogeneous in orientation frequencies than a shared pooled distribution would predict. The G-test upper-tail p is {}.",
            report::format_probability(g_test.upper_tail_add_one_p)
        );
        report::appendln!(
            out,
            "This would argue against unusually tight cross-message homogeneity, but it still says nothing about plaintext or symbol meaning."
        );
    } else {
        report::appendln!(
            out,
            "Interpretation: the observed homogeneity statistic lands in the bulk of the length-matched repartition null. Similar-looking per-message profiles are therefore unremarkable at this sampling depth."
        );
    }
    report::appendln!(
        out,
        "Decode potential: none directly. This is structural evidence at the orientation-frequency layer, not a language or cipher attack."
    );
}

fn format_orientation_profile_lengths(profiles: &[OrientationProfile]) -> String {
    profiles
        .iter()
        .map(|profile| format!("{}:{}", profile.message_key, profile.length))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_orientation_counts(counts: &[usize; ORIENTATION_BUCKETS]) -> String {
    counts
        .iter()
        .enumerate()
        .map(|(digit, count)| format!("{digit}:{count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_null_band_f64(q025: f64, q975: f64) -> String {
    format!("{q025:.3}..{q975:.3}")
}

fn format_null_min_median_max(band: ScalarNullBand) -> String {
    format!("{:.3}/{:.3}/{:.3}", band.min, band.median, band.max)
}

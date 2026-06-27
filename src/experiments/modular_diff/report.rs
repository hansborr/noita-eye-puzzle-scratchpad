//! Experiment 13 modular-difference report rendering for [`ModularDiffReport`].
//!
//! Holds the `Report` implementation and its `append_*`/`format_*` helpers,
//! split out of the modular-difference body so the compute lives separately.

use crate::report::{self, Report};

use super::{
    ControlFamily, ControlFamilyBand, ControlSeparation, FamilyPlacement, LagAutocorrelation,
    ModularDiffReport, ModulusReport, PeriodIoc, ScalarBand, ValuePeak,
};

impl Report for ModularDiffReport {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(
            &mut out,
            "Experiment 13 modular-difference family fingerprint"
        );
        report::appendln!(&mut out, "order: {}", self.order.name());
        report::appendln!(
            &mut out,
            "headline modulus: 83-symbol accepted honeycomb alphabet"
        );
        report::appendln!(
            &mut out,
            "secondary modulus: 125-symbol base-5 trigram space"
        );
        report::appendln!(&mut out, "seed: {}", self.config.seed);
        report::appendln!(
            &mut out,
            "trials per control/shuffle row: {}",
            self.config.trials
        );
        report::appendln!(&mut out, "max period: {}", self.config.max_period);
        report::appendln!(&mut out, "max lag: {}", self.config.max_lag);
        report::appendln!(
            &mut out,
            "message lengths: {}",
            report::format_message_lengths(&self.message_lengths)
        );
        report::appendln!(&mut out, "pooled raw length: {}", self.total_length);
        report::appendln!(
            &mut out,
            "boundary rule: every modular difference resets at message starts; no pair crosses a message join"
        );
        report::appendln!(
            &mut out,
            "mapping rule: a global additive offset cancels in the difference stream; no symbol-to-language mapping is scored"
        );
        report::appendln!(
            &mut out,
            "controls: generated wheel, period-7 Vigenere, S83 deck-keystream, flat random, plus within-message multiset-preserving shuffles"
        );
        report::appendln!(&mut out);
        append_modular_diff_modulus(
            &mut out,
            "primary mod-83 differenced streams",
            &self.primary,
        );
        report::appendln!(&mut out);
        append_modular_diff_modulus(
            &mut out,
            "secondary mod-125 differenced streams",
            &self.secondary,
        );
        report::appendln!(&mut out);
        append_modular_diff_calibration(&mut out, self);
        report::appendln!(&mut out);
        append_modular_diff_interpretation(&mut out, self);
        out
    }
}

fn append_modular_diff_modulus(out: &mut String, title: &str, modulus: &ModulusReport) {
    report::appendln!(out, "{title}");
    report::appendln!(
        out,
        "  raw message-weighted IoC: {:.6} (normalized {:.3})",
        modulus.raw_ioc,
        modulus.raw_ioc * modulus.modulus as f64
    );
    report::appendln!(
        out,
        "  {:>1} {:>5} {:>8} {:>7} {:>10} {:>9} {:>4} {:>8} {:>7} {:>9} {:>9} {:>13}",
        "k",
        "len",
        "IoC",
        "norm",
        "delta",
        "chi2",
        "supp",
        "top",
        "topx",
        "bestP",
        "bestLag",
        "shuf struct"
    );
    for row in &modulus.differences {
        let stats = &row.stats;
        report::appendln!(
            out,
            "  {:>1} {:>5} {:>8.6} {:>7.3} {:>+10.6} {:>9.2} {:>4} {:>8} {:>7.3} {:>9} {:>9} {:>13}",
            row.difference_order,
            stats.length,
            stats.ioc,
            stats.normalized_ioc,
            stats.delta_ioc,
            stats.chi_square_uniform,
            stats.distinct_support_size,
            format_moddiff_peak(stats.top_difference),
            stats.top_difference.over_uniform,
            format_moddiff_period(stats.best_period_ioc),
            format_moddiff_lag(stats.best_autocorrelation),
            format_moddiff_band(row.shuffle_baseline.structure_score)
        );
    }
}

fn append_modular_diff_calibration(out: &mut String, report: &ModularDiffReport) {
    report::appendln!(out, "primary fixture calibration");
    append_modular_diff_fixture_keys(out, report);
    report::appendln!(
        out,
        "  {:>1} {:>11} {:>13} {:>13} {:>13} {:>13} {:>8} {:>13}",
        "k",
        "wheel top",
        "Vig p-excess",
        "deck struct",
        "flat struct",
        "shuffle struct",
        "sep",
        "eye band"
    );
    for control in &report.controls {
        report::appendln!(
            out,
            "  {:>1} {:>11} {:>13} {:>13} {:>13} {:>13} {:>8} {:>13}",
            control.difference_order,
            format_family_metric(
                &control.family_bands,
                ControlFamily::IncrementingWheel,
                |band| band.fingerprint.top_rate
            ),
            format_family_metric(
                &control.family_bands,
                ControlFamily::PeriodicVigenere,
                |band| { band.fingerprint.period_excess }
            ),
            format_family_metric(
                &control.family_bands,
                ControlFamily::DeckS83Keystream,
                |band| { band.fingerprint.structure_score }
            ),
            format_family_metric(&control.family_bands, ControlFamily::FlatRandom, |band| {
                band.fingerprint.structure_score
            }),
            format_primary_shuffle_structure(report, control.difference_order),
            format_moddiff_separation(control.separation),
            control.eye_placement.label()
        );
    }
    report::appendln!(
        out,
        "  deck and flat are treated as a shared structureless band; their overlap is a calibration check, not a failure."
    );
}

fn append_modular_diff_fixture_keys(out: &mut String, report: &ModularDiffReport) {
    let Some(first) = report.controls.first() else {
        return;
    };
    report::appendln!(out, "  fixture keys:");
    for band in &first.family_bands {
        report::appendln!(out, "    {}: {}", band.family.label(), band.key_summary);
    }
}

fn append_modular_diff_interpretation(out: &mut String, report: &ModularDiffReport) {
    if let Some(row) = report
        .primary
        .differences
        .iter()
        .find(|row| row.difference_order == 1)
    {
        let stats = &row.stats;
        report::appendln!(
            out,
            "Headline k=1 mod-83: top difference {} occurs {}/{} ({:.4}); delta-IoC {:+.6}; placement {}.",
            stats.top_difference.value,
            stats.top_difference.count,
            stats.length,
            stats.top_difference.rate,
            stats.delta_ioc,
            report.headline_placement.label()
        );
    }

    match report.headline_placement {
        FamilyPlacement::StructurelessLike => report::appendln!(
            out,
            "Interpretation: the first-difference eye stream lands in the calibrated structureless deck/flat/shuffle band, not the incrementing-wheel band. It has no dominant constant difference, which disfavors the simple incrementing-wheel fingerprint specifically while remaining consistent with deck, autokey, flat substitution, or other non-wheel structures."
        ),
        FamilyPlacement::WheelLike => report::appendln!(
            out,
            "Interpretation: the first-difference eye stream has a dominant constant-difference signature. That would be a near-decode lead only after rechecking the Experiment-0 corpus and transcription integrity."
        ),
        FamilyPlacement::VigenereLike => report::appendln!(
            out,
            "Interpretation: the first-difference eye stream matches the generated periodic-key difference fingerprint. This is structural evidence only; it does not identify plaintext or a symbol mapping."
        ),
        FamilyPlacement::BetweenBands => report::appendln!(
            out,
            "Interpretation: the first-difference eye stream falls between separated fixture bands. Treat this as unresolved structural placement, not a decode."
        ),
        FamilyPlacement::Uncalibrated => report::appendln!(
            out,
            "Interpretation: the generated positive controls did not separate enough for a calibrated placement, so no family verdict is reported."
        ),
    }
    report::appendln!(
        out,
        "This experiment is mapping-independent and structural. It scores no language model and makes no plaintext claim."
    );
}

fn format_moddiff_peak(peak: ValuePeak) -> String {
    format!("{}:{}", peak.value, peak.count)
}

fn format_moddiff_period(row: Option<PeriodIoc>) -> String {
    row.map_or_else(
        || "none".to_owned(),
        |period| format!("p{}={:.3}", period.period, period.normalized_ioc),
    )
}

fn format_moddiff_lag(row: Option<LagAutocorrelation>) -> String {
    row.map_or_else(
        || "none".to_owned(),
        |lag| format!("l{}={:.3}", lag.lag, lag.normalized_rate),
    )
}

fn format_moddiff_band(band: ScalarBand) -> String {
    format!("{:.3}..{:.3}", band.q025, band.q975)
}

fn format_family_metric(
    bands: &[ControlFamilyBand],
    family: ControlFamily,
    metric: impl Fn(&ControlFamilyBand) -> ScalarBand,
) -> String {
    bands.iter().find(|band| band.family == family).map_or_else(
        || "n/a".to_owned(),
        |band| format_moddiff_band(metric(band)),
    )
}

fn format_primary_shuffle_structure(report: &ModularDiffReport, difference_order: usize) -> String {
    report
        .primary
        .differences
        .iter()
        .find(|row| row.difference_order == difference_order)
        .map_or_else(
            || "n/a".to_owned(),
            |row| format_moddiff_band(row.shuffle_baseline.structure_score),
        )
}

fn format_moddiff_separation(separation: ControlSeparation) -> &'static str {
    if separation.is_calibrated() {
        "ok"
    } else {
        "overlap"
    }
}

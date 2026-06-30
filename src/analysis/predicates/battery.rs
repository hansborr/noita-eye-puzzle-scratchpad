//! The battery driver, the multiple-comparisons meta-analysis, and the report.
//!
//! [`run_battery`] evaluates every [`Predicate`] against its matched null and
//! collects the per-predicate [`PredicateOutcome`]s; [`MetaAnalysis`] turns the
//! per-predicate p-values into the family-wise picture that is the real
//! deliverable. The [`Report`] impl renders both with the binding honesty notes.

use std::convert::Infallible;

use crate::core::trigram::TrigramValue;
use crate::nulls::null::{WithinMessageShuffle, add_one_p_value, mix_seed, run_null_test};
use crate::report::{self, Report};

use super::{
    DEFAULT_ALPHABET_SIZE, FAMILY_ALPHA, GapProfile, NullShape, Predicate, PredicateError,
    ValueResample, corpus_message_values,
};

/// The recomputed significance of one predicate against its matched null.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PredicateOutcome {
    /// Which predicate this is.
    pub predicate: Predicate,
    /// The observed statistic (upper tail is the surprising direction).
    pub observed: usize,
    /// The number of aggregation units (messages, or 1 for the gap predicate).
    pub unit_total: usize,
    /// Whether the community claim holds on the real input.
    pub satisfied: bool,
    /// The matched null shape used.
    pub null_shape: NullShape,
    /// Number of Monte-Carlo trials run.
    pub trials: usize,
    /// Surrogate draws at least as extreme as `observed`.
    pub null_hits: usize,
    /// Add-one empirical upper-tail p-value `(null_hits + 1) / (trials + 1)`.
    pub p_value: f64,
}

/// Bonferroni family-wise adjusted p-value `min(1, k * p)`.
#[must_use]
pub fn bonferroni_adjusted(p: f64, k: usize) -> f64 {
    (p * k as f64).min(1.0)
}

/// Šidák family-wise adjusted p-value `1 - (1 - p)^k`, computed stably.
#[must_use]
pub fn sidak_adjusted(p: f64, k: usize) -> f64 {
    -f64::exp_m1(k as f64 * f64::ln_1p(-p))
}

/// The multiple-comparisons meta-analysis over the whole battery.
///
/// `expected_survivors` is `Σ pₖ`: under a global null where no predicate carries
/// signal, this is the expected number of predicates that would land at or beyond
/// their observed threshold purely by chance. A family-wise correction
/// (Bonferroni / Šidák) then asks which predicates survive once the count of
/// tested predicates is accounted for.
#[derive(Clone, Debug, PartialEq)]
pub struct MetaAnalysis {
    /// Number of predicates tested (a LOWER BOUND on the true search size).
    pub k: usize,
    /// `Σ pₖ`: expected number of chance survivors at the observed thresholds.
    pub expected_survivors: f64,
    /// Number of predicates whose community claim holds on the real input.
    pub observed_hits: usize,
    /// Family-wise error rate the survivor lists are taken at.
    pub family_alpha: f64,
    /// Predicate ids surviving the Bonferroni correction at `family_alpha`.
    pub survivors_bonferroni: Vec<&'static str>,
    /// Predicate ids surviving the Šidák correction at `family_alpha`.
    pub survivors_sidak: Vec<&'static str>,
}

impl MetaAnalysis {
    /// Builds the meta-analysis from the per-predicate outcomes.
    #[must_use]
    pub fn of(outcomes: &[PredicateOutcome]) -> Self {
        let k = outcomes.len();
        let expected_survivors = outcomes.iter().map(|outcome| outcome.p_value).sum();
        let observed_hits = outcomes.iter().filter(|outcome| outcome.satisfied).count();
        let survivors_bonferroni = outcomes
            .iter()
            .filter(|outcome| bonferroni_adjusted(outcome.p_value, k) < FAMILY_ALPHA)
            .map(|outcome| outcome.predicate.id())
            .collect();
        let survivors_sidak = outcomes
            .iter()
            .filter(|outcome| sidak_adjusted(outcome.p_value, k) < FAMILY_ALPHA)
            .map(|outcome| outcome.predicate.id())
            .collect();
        Self {
            k,
            expected_survivors,
            observed_hits,
            family_alpha: FAMILY_ALPHA,
            survivors_bonferroni,
            survivors_sidak,
        }
    }
}

/// A full battery run: the inputs, the gap profile, the per-predicate outcomes,
/// and the meta-analysis.
#[derive(Clone, Debug, PartialEq)]
pub struct BatteryReport {
    /// Human label for where the value streams came from.
    pub source: String,
    /// Declared alphabet size (its char count, or 83 for the corpus).
    pub alphabet_size: usize,
    /// Number of messages.
    pub message_count: usize,
    /// Total trigrams across all messages.
    pub total_trigrams: usize,
    /// Whether the run is conditional on the accepted honeycomb reading order.
    pub order_conditional: bool,
    /// PRNG seed used for every null.
    pub seed: u64,
    /// The realized/missing recurrence-gap profile (predicate a's substrate).
    pub gap_profile: GapProfile,
    /// Per-predicate recomputed significance.
    pub outcomes: Vec<PredicateOutcome>,
    /// The multiple-comparisons meta-analysis.
    pub meta: MetaAnalysis,
}

/// Evaluates the whole predicate battery over per-message value streams.
///
/// Each predicate is scored against its matched null (the gap predicate against a
/// within-message shuffle, the magnitude/sum predicates against a pooled
/// value-resample), with an independent PRNG sub-stream per predicate.
///
/// # Errors
/// Returns [`PredicateError::EmptyInput`] if there are no messages, or
/// [`PredicateError::Random`] if a value-resample draw fails.
pub fn run_battery(
    messages: &[Vec<TrigramValue>],
    alphabet_size: usize,
    seed: u64,
    shuffle_trials: usize,
    resample_trials: usize,
) -> Result<BatteryReport, PredicateError> {
    if messages.is_empty() {
        return Err(PredicateError::EmptyInput);
    }
    let shuffle = WithinMessageShuffle { messages };
    let resample = ValueResample::new(messages);
    let mut outcomes = Vec::with_capacity(Predicate::ALL.len());
    for (index, predicate) in Predicate::ALL.into_iter().enumerate() {
        let predicate_seed = mix_seed(seed, index as u64);
        outcomes.push(evaluate(
            predicate,
            messages,
            &shuffle,
            &resample,
            predicate_seed,
            shuffle_trials,
            resample_trials,
        )?);
    }
    let meta = MetaAnalysis::of(&outcomes);
    Ok(BatteryReport {
        source: "file-driven stream (no honeycomb reading claimed)".to_owned(),
        alphabet_size,
        message_count: messages.len(),
        total_trigrams: messages.iter().map(Vec::len).sum(),
        order_conditional: false,
        seed,
        gap_profile: GapProfile::of(messages),
        outcomes,
        meta,
    })
}

/// Runs the battery on the verified eye corpus under the accepted honeycomb order.
///
/// # Errors
/// Returns [`PredicateError::Grid`] if the corpus cannot be read, or
/// [`PredicateError::Random`] if a value-resample draw fails.
pub fn run_corpus_battery(
    seed: u64,
    shuffle_trials: usize,
    resample_trials: usize,
) -> Result<BatteryReport, PredicateError> {
    let messages = corpus_message_values()?;
    let mut report = run_battery(
        &messages,
        DEFAULT_ALPHABET_SIZE,
        seed,
        shuffle_trials,
        resample_trials,
    )?;
    "eye corpus, accepted honeycomb order standard36-u012-d012 (alphabet 83)"
        .clone_into(&mut report.source);
    report.order_conditional = true;
    Ok(report)
}

/// Scores one predicate against its matched null.
fn evaluate(
    predicate: Predicate,
    messages: &[Vec<TrigramValue>],
    shuffle: &WithinMessageShuffle<'_, TrigramValue>,
    resample: &ValueResample,
    seed: u64,
    shuffle_trials: usize,
    resample_trials: usize,
) -> Result<PredicateOutcome, PredicateError> {
    let observed = predicate.statistic(messages);
    let statistic =
        |draw: &Vec<Vec<TrigramValue>>| Ok::<usize, Infallible>(predicate.statistic(draw));
    let null_shape = predicate.null_shape();
    let (trials, null_hits) = match null_shape {
        NullShape::WithinMessageShuffle => {
            let result = run_null_test(statistic, observed, shuffle, shuffle_trials, seed)?;
            (shuffle_trials, result.upper_tail_count)
        }
        NullShape::ValueResample => {
            let result = run_null_test(statistic, observed, resample, resample_trials, seed)?;
            (resample_trials, result.upper_tail_count)
        }
    };
    Ok(PredicateOutcome {
        predicate,
        observed,
        unit_total: predicate.unit_total(messages),
        satisfied: predicate.satisfied(messages),
        null_shape,
        trials,
        null_hits,
        p_value: add_one_p_value(null_hits, trials),
    })
}

impl Report for BatteryReport {
    fn render(&self) -> String {
        let mut out = String::new();
        self.render_header(&mut out);
        self.render_gap(&mut out);
        self.render_predicates(&mut out);
        self.render_meta(&mut out);
        out
    }
}

impl BatteryReport {
    fn render_header(&self, out: &mut String) {
        report::appendln!(
            out,
            "Toboter predicate battery -- recomputed nulls + multiple-comparisons meta-analysis"
        );
        report::appendln!(out, "source: {}", self.source);
        report::appendln!(
            out,
            "messages: {} ; trigrams: {} ; alphabet: {} ; seed: 0x{:016x}",
            self.message_count,
            self.total_trigrams,
            self.alphabet_size,
            self.seed
        );
        if self.order_conditional {
            report::appendln!(
                out,
                "CAVEAT: every predicate is conditional on the accepted honeycomb reading order."
            );
        }
    }

    fn render_gap(&self, out: &mut String) {
        let profile = &self.gap_profile;
        report::appendln!(out);
        report::appendln!(
            out,
            "gap profile (predicate a): search bound d<={} ; realized distances: {} ; max realized: {}",
            profile.search_bound,
            profile.realized.len(),
            profile.max_realized
        );
        report::appendln!(
            out,
            "  only-1-missing run length M={}: distance 1 absent, distances 2..={} all realized (this is the tested statistic).",
            profile.only_one_missing_run,
            profile.only_one_missing_run.max(1)
        );
        report::appendln!(
            out,
            "  strict literal claim (only missing over full 1..={} is exactly 1): {} -- full missing set {:?}",
            profile.max_realized,
            yes_no(profile.only_missing_one()),
            profile.missing.iter().copied().collect::<Vec<_>>()
        );
        report::appendln!(
            out,
            "  honest read: the large-distance tail thins out (expected; not part of the claim) -- the discriminant is the no-doubles + dense low-gap run, which rules out the (char + N*pos) mod 83 family (it would recur only at multiples of 83)."
        );
        report::appendln!(
            out,
            "  circularity: the gap structure also selected the reading order, so (a)'s significance is order- and plaintext-model-conditional."
        );
    }

    fn render_predicates(&self, out: &mut String) {
        report::appendln!(out);
        report::appendln!(out, "per-predicate recomputed significance:");
        for outcome in &self.outcomes {
            let predicate = outcome.predicate;
            report::appendln!(out, "  {} | {}", predicate.id(), predicate.title());
            report::appendln!(
                out,
                "    null: {:<24} observed {}/{}  holds: {}",
                outcome.null_shape.label(),
                outcome.observed,
                outcome.unit_total,
                yes_no(outcome.satisfied)
            );
            report::appendln!(
                out,
                "    recomputed p = {:.5} ({} / {} trials)  vs community: {}",
                outcome.p_value,
                outcome.null_hits,
                outcome.trials,
                predicate.community_claim()
            );
            report::appendln!(
                out,
                "    family-wise adjusted: Bonferroni {:.5} | Sidak {:.5} -> survives FWER({:.2}): {} (Bonferroni-robust to K up to ~{})",
                bonferroni_adjusted(outcome.p_value, self.meta.k),
                sidak_adjusted(outcome.p_value, self.meta.k),
                self.meta.family_alpha,
                yes_no(bonferroni_adjusted(outcome.p_value, self.meta.k) < self.meta.family_alpha),
                max_surviving_k(outcome.p_value, self.meta.family_alpha)
            );
        }
    }

    fn render_meta(&self, out: &mut String) {
        let meta = &self.meta;
        report::appendln!(out);
        report::appendln!(out, "multiple-comparisons meta-analysis (THE deliverable):");
        report::appendln!(
            out,
            "  K predicates tested: {} -- a LOWER BOUND: these survive a far larger UNDISCLOSED search (the dead-end catalog), so the true K (hence the correction) is larger.",
            meta.k
        );
        report::appendln!(
            out,
            "  expected survivors at observed thresholds (sum of p): {:.4}",
            meta.expected_survivors
        );
        report::appendln!(
            out,
            "  observed hits (community claim holds): {} of {}",
            meta.observed_hits,
            meta.k
        );
        report::appendln!(
            out,
            "  survive Bonferroni @ {:.2}: {}",
            meta.family_alpha,
            survivor_list(&meta.survivors_bonferroni)
        );
        report::appendln!(
            out,
            "  survive Sidak @ {:.2}:      {}",
            meta.family_alpha,
            survivor_list(&meta.survivors_sidak)
        );
        report::appendln!(
            out,
            "  K-sensitivity: each predicate's 'robust to K up to ~N' above is alpha/p; at the realistic (larger) true K the harsher correction removes the weaker ones first. Only (a) pairs a low p with an INDEPENDENT mechanistic rationale (it rules out an entire cipher family), so it is the one defensible discriminant; (c)/(d)/(e) survive at K={} but that is fragile and they remain individually-cherry-picked facts.",
            meta.k
        );
        report::appendln!(out);
        report::appendln!(
            out,
            "honesty: predicates (b)-(e) are individually WEAK as standalone findings (they are survivors of an undisclosed larger search) and are NOT reported as findings on their own; the meta-analysis is the deliverable. A surviving predicate is a structural discriminator, never a decode."
        );
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "YES" } else { "no" }
}

/// Largest family size `K` at which a predicate of empirical p-value `p` still
/// survives a Bonferroni correction at `alpha` (i.e. `floor(alpha / p)`). This
/// makes the "true K is a lower bound" caveat concrete: a predicate that only
/// survives to a small `K` is fragile to the undisclosed larger search.
#[allow(
    clippy::cast_sign_loss,
    reason = "alpha and p are both strictly positive, so alpha/p is non-negative"
)]
fn max_surviving_k(p: f64, alpha: f64) -> usize {
    if p <= 0.0 {
        return usize::MAX;
    }
    (alpha / p).floor() as usize
}

fn survivor_list(ids: &[&'static str]) -> String {
    if ids.is_empty() {
        "(none)".to_owned()
    } else {
        ids.join(", ")
    }
}

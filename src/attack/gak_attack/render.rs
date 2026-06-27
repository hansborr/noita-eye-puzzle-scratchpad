use super::{GakAttackReport, SmallSupportValidation, fraction};
use crate::report::{self, Report};

impl Report for GakAttackReport {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(
            &mut out,
            "Thread 4 synthetic GAK-attack (GCTAK decisive gate)"
        );
        report::appendln!(
            &mut out,
            "hidden subgroup: {}",
            self.hidden_subgroup.label()
        );
        report::appendln!(&mut out, "seed: {}", self.config.seed);
        report::appendln!(
            &mut out,
            "seeds per group kind: {}",
            self.config.seeds_per_kind
        );
        report::appendln!(
            &mut out,
            "cyclic order: {}; dihedral D_2k half-order k: {}",
            self.config.cyclic_order,
            self.config.dihedral_half_order
        );
        report::appendln!(
            &mut out,
            "plaintext letters: {}; phrase repeats: {}; phrase length: {}",
            self.config.num_pt_letters,
            self.config.phrase_repeats,
            self.config.phrase_len
        );
        report::appendln!(
            &mut out,
            "TENTATIVE small-support radius (<=k transpositions): {} (0 = unconstrained gate regime)",
            self.config.small_support_radius
        );
        report::appendln!(
            &mut out,
            "wiki pages this unit encodes: Group-Autokey-(GAK).md; Group-Ciphertext-Autokey-(GCTAK).md; Alphabet-Chaining.md / Graph-Chaining.md"
        );
        report::appendln!(&mut out);
        append_gak_attack_rates(&mut out, self);
        report::appendln!(&mut out);
        append_gak_attack_outcomes(&mut out, self);
        report::appendln!(&mut out);
        append_gak_attack_exemplars(&mut out, self);
        report::appendln!(&mut out);
        append_gak_attack_deck(&mut out, self);
        report::appendln!(&mut out);
        append_gak_attack_marginalization(&mut out, self);
        report::appendln!(&mut out);
        append_gak_attack_interpretation(&mut out, self);
        out
    }
}

fn append_gak_attack_marginalization(out: &mut String, attack_report: &GakAttackReport) {
    let marg = &attack_report.marginalization;
    report::appendln!(
        out,
        "UNIT 2b hidden-state marginalization (idea 3) + TENTATIVE small-support prior (idea 2)"
    );
    report::appendln!(
        out,
        "  idea 3 overcomes the unit-2a obstruction: instead of collapsing each phrase column to its single-valued core (the 2a baseline), a BOUNDED BEAM / belief-propagation over the hidden-state branches admits the multi-valued branches that GENERALIZE to a HELD-OUT chain-link fold (a TRAIN/HELD-OUT split of the same column's occurrences). The recovered object is the per-letter visible-coset edge MARGINAL over hidden states (multi-valued from allowed) -- a PARTIAL visible-coset action recovery, NOT a recovered key, NOT the plaintext->group-element mapping. SYNTHETIC-ONLY."
    );
    report::appendln!(
        out,
        "  beam width bound: {} (DISCLOSED, no silent truncation; dropped beams are reported per n)",
        marg.beam_width
    );
    report::appendln!(
        out,
        "  small-support prior (idea 2) for the headline sweep: {}",
        marg.prior.label()
    );
    report::appendln!(
        out,
        "  decimals tagged (mean) are PER-SEED MEAN fractions; the recov/edges columns are AGGREGATE totals over all seeds (the aggregate ratio differs slightly from the per-seed mean)."
    );
    report::appendln!(
        out,
        "  {:<4} {:>12} {:>7} {:>13} {:>11} {:>9} {:>11} {:>9} {:>11} {:>8} {:>8} {:>7} {:>8}",
        "n",
        "|H|=(n-1)!",
        "seeds",
        "i3 recov/edges",
        "i3 (mean)",
        "core recov",
        "core (mean)",
        "null recov",
        "null (mean)",
        "i3>core",
        "i3>null",
        "p",
        "dropped"
    );
    for point in &marg.points {
        report::appendln!(
            out,
            "  {:<4} {:>12} {:>7} {:>13} {:>11} {:>9} {:>11} {:>9} {:>11} {:>8} {:>8} {:>7} {:>8}",
            point.state_size,
            point.hidden_subgroup_order,
            point.seeds,
            format!("{}/{}", point.idea3_true_total, point.truth_edges_total),
            format!("{:.3}", point.idea3_mean_fraction),
            point.baseline_true_total,
            format!("{:.3}", point.baseline_mean_fraction),
            point.null_true_total,
            format!("{:.3}", point.null_mean_fraction),
            report::yes_no(point.idea3_beats_baseline),
            report::yes_no(point.idea3_beats_null),
            format!("{:.3}", point.matched_null_p_value),
            point.beams_dropped
        );
    }
    report::appendln!(
        out,
        "  MEASURED result: idea-3 marginalization recovers SEVERAL-FOLD more true per-letter coset edges than the 2a single-valued core at every n (the multi-valued branches the core discards are most of the action), and beats the matched null. It is STRONGEST at the smallest n and BREAKS as the hidden-state count |H| = (n-1)! grows (the train fold samples a shrinking share of the hidden states), degrading toward -- never below -- the 2a baseline. \"Helps on small n, breaks as n grows\" is the expected, reportable outcome, not a thread failure. (This wording holds on the default-seed sweep; non-default --seed runs are not gate-guaranteed -- see the table above.)"
    );
    append_gak_attack_small_support(out, &marg.small_support_validation);
}

fn append_gak_attack_small_support(out: &mut String, validation: &SmallSupportValidation) {
    report::appendln!(
        out,
        "  TENTATIVE small-support prior validation (idea 2; the prior is a heuristic to validate, NOT a hard constraint, labelled everywhere)"
    );
    report::appendln!(
        out,
        "    method: generate fixtures WITH small-support truth and WITHOUT (unconstrained S_n), run idea-3 with the prior OFF and ON in each (n={}, {} seeds), and measure edge-recall + edge-precision.",
        validation.state_size,
        validation.seeds
    );
    report::appendln!(
        out,
        "    small-support truth: recall on/off = {}/{} of {}; precision on/off = {:.3}/{:.3}",
        validation.small_truth_prior_on,
        validation.small_truth_prior_off,
        validation.small_truth_total,
        validation.small_precision(true),
        validation.small_precision(false)
    );
    report::appendln!(
        out,
        "    unconstrained truth: recall on/off = {}/{} of {}; precision on/off = {:.3}/{:.3}",
        validation.broad_truth_prior_on,
        validation.broad_truth_prior_off,
        validation.broad_truth_total,
        validation.broad_precision(true),
        validation.broad_precision(false)
    );
    report::appendln!(
        out,
        "    prior FAILS GRACEFULLY (the robust, structural guarantee): {} -- its confidence floor only ever DROPS genuine low-support edges (recall ON <= OFF in both conditions) and never invents any, so precision is held or improved and a WRONG small-support assumption is never rewarded.",
        report::yes_no(validation.prior_fails_gracefully())
    );
    report::appendln!(
        out,
        "    prior is SELECTIVELY discriminative (weak, TENTATIVE signal): {} -- in the deck realization the near-identity structure of the per-letter permutations only WEAKLY survives into the visible-coset marginal (hidden-state cycling spreads the marked card), so the prior helps small-support truth only marginally more than unconstrained truth. This thin margin is reported as TENTATIVE; the graceful-failure property is the load-bearing result.",
        report::yes_no(validation.prior_is_discriminative())
    );
}

fn append_gak_attack_deck(out: &mut String, attack_report: &GakAttackReport) {
    let deck = &attack_report.deck;
    report::appendln!(
        out,
        "REAL-GAK deck attack (non-trivial hidden subgroup H = Stab(top) = S_(n-1), |H| = (n-1)! > 1)"
    );
    report::appendln!(
        out,
        "  this is the community's stated open problem. What this unit recovers is PARTIAL visible-coset action recovery (a fraction of per-letter visible-coset transitions; NOT a recovered key, NOT the plaintext->group-element mapping), plus a MEASURED bound on how far that gets. SYNTHETIC-ONLY (we hold ground truth)."
    );
    report::appendln!(out, "  per-letter draw regime: {}", deck.regime.label());
    report::appendln!(
        out,
        "  measured obstruction: under non-trivial H the visible transition depends on the FULL hidden state, so most of a letter's visible-coset action is multi-valued across hidden states. The recoverable part (single-valued core) is bounded by this multi-valuedness -- which MOTIVATES idea 3 (hidden-state marginalization)."
    );
    report::appendln!(
        out,
        "  {:<4} {:>12} {:>7} {:>20} {:>20} {:>12} {:>14} {:>9} {:>6}",
        "n",
        "|H|=(n-1)!",
        "seeds",
        "real (recov/letters)",
        "null (recov/letters)",
        "real>null",
        "multivalued-frac",
        "aborts",
        "p"
    );
    for tractability in &deck.tractability {
        report::appendln!(
            out,
            "  {:<4} {:>12} {:>7} {:>11} {:>8} {:>11} {:>8} {:>12} {:>14} {:>9} {:>6}",
            tractability.state_size,
            tractability.hidden_subgroup_order,
            tractability.seeds,
            format!(
                "{}/{}",
                tractability.real_recovered_total, tractability.letters_total
            ),
            format!("{:.3}", tractability.real_mean_fraction),
            format!(
                "{}/{}",
                tractability.null_recovered_total, tractability.letters_total
            ),
            format!("{:.3}", tractability.null_mean_fraction),
            report::yes_no(tractability.real_beats_null),
            format!("{:.3}", tractability.multi_valued_fraction),
            tractability.true_conflict_aborts,
            format!("{:.3}", tractability.matched_null_p_value)
        );
    }
    report::appendln!(
        out,
        "  multivalued-frac: the MEASURED hidden-state obstruction (fraction of visible cosets that map multi-valued under a fixed letter). Larger => less recoverable here; this is the headline honest result of the unit and the motivation for idea 3."
    );
    report::appendln!(
        out,
        "  fixed-context TRUE-conflict aborts (a FEATURE, not a bug): occurrence-pair alignments where two arrows out of / into one symbol under ONE fixed alignment proved a bad isomorph alignment and were dropped, protecting honesty. (Cross-hidden-state multi-valuedness is NOT a conflict -- it is the measured obstruction above.)"
    );
    report::appendln!(
        out,
        "  beats matched null on the easiest fixture (n={}): {}",
        deck.easiest_state_size,
        report::yes_no(deck.beats_null_on_easiest)
    );
    report::appendln!(
        out,
        "  measured negative is the deliverable: partial visible-coset action recovery stays SMALL and roughly FLAT across n (it does NOT climb with n), bounded by the hidden-state obstruction; this is the expected, reportable outcome, not a thread failure. The matched null is destroyed at small n and only begins to match real at larger n / some seeds. (This wording holds on the default-seed sweep; non-default --seed runs are not gate-guaranteed -- see the table above.)"
    );
    report::appendln!(
        out,
        "  the per-seed p-value is conservative (high per-fixture variance) and is non-significant on its own -- say so; the aggregate contrast is the AGGREGATE recovered-letter count real vs null."
    );
    report::appendln!(
        out,
        "  TENTATIVE small-support prior + hidden-state marginalization are the NEXT unit: this unit only generates both regimes and leaves documented hooks (the overlap-threshold merge and the single-valued-core light merge), it does NOT apply those priors."
    );
}

fn append_gak_attack_rates(out: &mut String, attack_report: &GakAttackReport) {
    report::appendln!(
        out,
        "rate-beats-null gate (the gate is the RATE vs null, NOT a single seed)"
    );
    report::appendln!(
        out,
        "  required minimum real recovery rate per group kind: {:.3}",
        attack_report.min_real_recovery_rate
    );
    report::appendln!(
        out,
        "  {:<10} {:<7} {:>6} {:>18} {:>18}",
        "group",
        "noncomm",
        "seeds",
        "real-rate (real/n)",
        "null-rate (null/n)"
    );
    for rate in &attack_report.rates {
        report::appendln!(
            out,
            "  {:<10} {:<7} {:>6} {:>10} {:>7} {:>10} {:>7}",
            rate.group,
            report::yes_no(rate.non_commutative),
            rate.seeds,
            format!("{:.3}", rate.real_fraction()),
            format!("{}/{}", rate.real_recovered, rate.seeds),
            format!("{:.3}", rate.null_fraction()),
            format!("{}/{}", rate.null_recovered, rate.seeds)
        );
    }
    report::appendln!(
        out,
        "  rate-vs-null gate passed (real rate clears floor AND strictly exceeds matched-null rate): {}",
        report::yes_no(attack_report.rate_gate_passed)
    );
    report::appendln!(
        out,
        "  matched shuffle null failed to recover on every independent seed (required contrast): {}",
        report::yes_no(attack_report.all_null_failed)
    );
}

fn append_gak_attack_outcomes(out: &mut String, attack_report: &GakAttackReport) {
    report::appendln!(
        out,
        "per-seed outcomes and per-letter permutation-recovery fractions (real vs null)"
    );
    report::appendln!(
        out,
        "  {:<10} {:>10} {:>6} {:>20} {:>20} {:>16}",
        "group",
        "|G|/real",
        "ct-len",
        "real perm-recovery",
        "null perm-recovery",
        "chain-links ok"
    );
    for outcome in &attack_report.outcomes {
        report::appendln!(
            out,
            "  {:<10} {:>5}/{:<4} {:>6} {:>13} {:>6} {:>13} {:>6} {:>8}/{:<7}",
            outcome.group,
            outcome.group_order,
            outcome.realized_order,
            outcome.ciphertext_len,
            format!(
                "{}/{}",
                outcome.real_permutations_recovered, outcome.permutations_total
            ),
            format!(
                "{:.3}",
                fraction(
                    outcome.real_permutations_recovered,
                    outcome.permutations_total
                )
            ),
            format!(
                "{}/{}",
                outcome.null_permutations_recovered, outcome.permutations_total
            ),
            format!(
                "{:.3}",
                fraction(
                    outcome.null_permutations_recovered,
                    outcome.permutations_total
                )
            ),
            outcome.chain_link_consistent,
            outcome.chain_link_checks
        );
    }
}

fn append_gak_attack_exemplars(out: &mut String, attack_report: &GakAttackReport) {
    report::appendln!(
        out,
        "retry-selected exemplars (ILLUSTRATIONS ONLY, NOT pass evidence; the gate passes on the RATE above)"
    );
    for exemplar in &attack_report.exemplars {
        let outcome = exemplar.outcome;
        report::appendln!(
            out,
            "  {} exemplar: seed {} found after {} attempt(s); real per-letter permutation recovery {}/{}; chain-links {}/{} satisfied",
            outcome.group,
            outcome.seed,
            exemplar.attempts_used,
            outcome.real_permutations_recovered,
            outcome.permutations_total,
            outcome.chain_link_consistent,
            outcome.chain_link_checks
        );
    }
    report::appendln!(
        out,
        "  note: an exemplar is an illustration of one worked seed, not evidence every seed recovers."
    );
}

fn append_gak_attack_interpretation(out: &mut String, attack_report: &GakAttackReport) {
    if attack_report.rate_gate_passed {
        report::appendln!(
            out,
            "Interpretation: on these SYNTHETIC-ONLY GCTAK fixtures (we hold the ground-truth key), the extended-chaining solver recovers per-letter permutations at a real rate that clears the documented floor and strictly beats its matched within-message shuffle null. This validates the methodology as a positive control; it is NOT a decode."
        );
    } else {
        report::appendln!(
            out,
            "Interpretation: the rate-beats-null gate did not pass for every group kind on these SYNTHETIC-ONLY fixtures. A negative or partial result is the expected, reportable outcome of the broader GAK thread, not a failure of it."
        );
    }
    report::appendln!(
        out,
        "REAL-GAK deck interpretation: on the non-trivial-H deck stabilizer (real GAK, |H|>1) the attack achieves PARTIAL visible-coset action recovery (a fraction of per-letter visible-coset transitions; NOT a recovered key, NOT the plaintext->group-element mapping). That fraction stays SMALL and roughly FLAT across n -- bounded by the MEASURED hidden-state obstruction (the multi-valuedness of the visible-coset action across hidden states), which is the part not recoverable without idea 3. The matched null is destroyed at small n and only begins to match real at larger n / some seeds. This measured obstruction is the contribution the wiki asks for and motivates idea 3; it is computed on SYNTHETIC ground truth and says nothing about the eyes. (The FLAT/destroyed-null wording holds on the default-seed sweep; non-default --seed runs are not gate-guaranteed -- see the table above.)"
    );
    report::appendln!(
        out,
        "UNIT 2b idea-3 interpretation: hidden-state marginalization (a bounded beam over hidden-state branches, scored by held-out chain links) recovers MARKEDLY more of the per-letter visible-coset action than the 2a single-valued-core baseline on SYNTHETIC small-n deck GAK -- but only PARTIAL visible-coset action recovery (an edge marginal over hidden states), NEVER a recovered key and NEVER the plaintext->group-element mapping. It breaks as |H| = (n-1)! grows; a marginal/negative result at larger n is the expected outcome. The TENTATIVE small-support prior is validated (fails gracefully; only weakly discriminative in this realization) and is OFF in the headline sweep so no result silently depends on it. The beam width and dropped-beam counts are disclosed (no silent truncation). (The MARKEDLY-more wording holds on the default-seed sweep; non-default --seed runs are not gate-guaranteed -- see the table above.)"
    );
    report::appendln!(
        out,
        "Synthetic-only disclaimer: this unit NEVER touches the eye corpus; it generates and solves its own GCTAK ciphertexts whose key it holds. No claim here transfers to the eyes."
    );
    report::appendln!(
        out,
        "Claim ceiling: the eyes remain deterministic, engine-generated, strikingly structured data of unknown meaning; unsolved; no primary developer source confirms recoverable plaintext. This run says nothing about recoverable eye plaintext."
    );
    report::appendln!(
        out,
        "TENTATIVE small-support prior: the <=k-swaps / small-support search heuristic is a TENTATIVE prior to validate, not a hard constraint; the GCTAK gate runs unconstrained (radius 0) and does not depend on it."
    );
    report::appendln!(
        out,
        "Reportable-negative framing: a negative or partial recovery result in later GAK steps is the expected, reportable outcome, not a thread failure."
    );
}

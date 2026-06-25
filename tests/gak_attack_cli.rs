//! CLI regression tests for the Thread 4 synthetic GAK-attack (GCTAK gate).
//!
//! This suite is the **honesty lock** for the `gak-attack` subcommand: it pins
//! the report's claim ceiling, synthetic-only disclaimer, TENTATIVE
//! small-support label, rate-vs-null gate wording, and the
//! exemplar-is-not-pass-evidence label so an edit that quietly overclaims is
//! caught by the gate. The asserted strings are gate-verdict-independent: they
//! print identically whether or not the rate-beats-null gate passes (the
//! verdict is the solver's authoritative output and is not asserted here).

mod common;

use common::{assert_contains, run_noita_eye};

#[test]
fn gak_attack_subcommand_reports_synthetic_gate_and_honesty_caveats() {
    // A small per-kind seed count is enough to exercise the whole honesty
    // surface; the gate's pass/fail verdict (the solver's business) is not
    // asserted, only the constant honesty strings around it.
    let stdout = run_noita_eye(&["gak-attack", "--seeds-per-kind", "2", "--seed", "123"]);

    // Headline + that this is the GCTAK decisive gate.
    assert_contains(
        &stdout,
        "Thread 4 synthetic GAK-attack (GCTAK decisive gate)",
    );
    assert_contains(&stdout, "hidden subgroup: trivial-H (GCTAK)");

    // Wiki citations the unit encodes.
    assert_contains(
        &stdout,
        "wiki pages this unit encodes: Group-Autokey-(GAK).md; Group-Ciphertext-Autokey-(GCTAK).md; Alphabet-Chaining.md / Graph-Chaining.md",
    );

    // The gate is the RATE vs the matched null, NOT a single seed.
    assert_contains(
        &stdout,
        "rate-beats-null gate (the gate is the RATE vs null, NOT a single seed)",
    );
    assert_contains(
        &stdout,
        "rate-vs-null gate passed (real rate clears floor AND strictly exceeds matched-null rate):",
    );
    assert_contains(
        &stdout,
        "matched shuffle null failed to recover on every independent seed (required contrast):",
    );

    // Per-letter permutation-recovery fractions (real vs null) are surfaced.
    assert_contains(
        &stdout,
        "per-seed outcomes and per-letter permutation-recovery fractions (real vs null)",
    );

    // Exemplars are illustrations, NOT pass evidence.
    assert_contains(
        &stdout,
        "retry-selected exemplars (ILLUSTRATIONS ONLY, NOT pass evidence; the gate passes on the RATE above)",
    );
    assert_contains(
        &stdout,
        "note: an exemplar is an illustration of one worked seed, not evidence every seed recovers.",
    );

    // Synthetic-only disclaimer: the eyes are NOT touched here.
    assert_contains(
        &stdout,
        "Synthetic-only disclaimer: this unit NEVER touches the eye corpus;",
    );

    // Claim ceiling holds verbatim-in-spirit.
    assert_contains(
        &stdout,
        "deterministic, engine-generated, strikingly structured data of unknown meaning; unsolved; no primary developer source confirms recoverable plaintext.",
    );

    // The small-support prior is labelled TENTATIVE and not a hard constraint.
    assert_contains(
        &stdout,
        "TENTATIVE small-support prior: the <=k-swaps / small-support search heuristic is a TENTATIVE prior to validate, not a hard constraint;",
    );

    // A negative/partial result is the expected, reportable outcome.
    assert_contains(
        &stdout,
        "the expected, reportable outcome, not a thread failure.",
    );

    // --- Unit 2a: the REAL-GAK (non-trivial-H) deck attack honesty surface. ---

    // The deck attack is real GAK (|H| > 1) and is the community's open problem.
    assert_contains(
        &stdout,
        "REAL-GAK deck attack (non-trivial hidden subgroup H = Stab(top) = S_(n-1), |H| = (n-1)! > 1)",
    );
    // P0a: what is recovered is PARTIAL visible-coset action recovery, NOT a key
    // and NOT the plaintext->group-element mapping (the claim ceiling).
    assert_contains(
        &stdout,
        "What this unit recovers is PARTIAL visible-coset action recovery (a fraction of per-letter visible-coset transitions; NOT a recovered key, NOT the plaintext->group-element mapping)",
    );

    // P1a: the headline deliverable is the MEASURED hidden-state obstruction (the
    // multi-valuedness that bounds recovery and motivates idea 3).
    assert_contains(
        &stdout,
        "most of a letter's visible-coset action is multi-valued across hidden states. The recoverable part (single-valued core) is bounded by this multi-valuedness",
    );
    assert_contains(
        &stdout,
        "multivalued-frac: the MEASURED hidden-state obstruction (fraction of visible cosets that map multi-valued under a fixed letter).",
    );

    // P1a: fixed-context TRUE-conflict aborts are surfaced as a FEATURE; the
    // cross-hidden-state multi-valuedness is explicitly NOT called a conflict.
    assert_contains(
        &stdout,
        "fixed-context TRUE-conflict aborts (a FEATURE, not a bug):",
    );
    assert_contains(
        &stdout,
        "Cross-hidden-state multi-valuedness is NOT a conflict",
    );

    // P1c: the recovered fraction is small and roughly FLAT (does not climb with
    // n); the null only begins to match real at larger n / some seeds.
    assert_contains(
        &stdout,
        "partial visible-coset action recovery stays SMALL and roughly FLAT across n (it does NOT climb with n)",
    );
    // P2b: the per-seed p-value is conservative / non-significant on its own.
    assert_contains(
        &stdout,
        "the per-seed p-value is conservative (high per-fixture variance) and is non-significant on its own",
    );

    // The small-support prior + hidden-state marginalization are the NEXT unit,
    // present only as documented hooks here (not applied).
    assert_contains(
        &stdout,
        "TENTATIVE small-support prior + hidden-state marginalization are the NEXT unit: this unit only generates both regimes and leaves documented hooks",
    );

    // P0a: the deck recovery is PARTIAL visible-coset action recovery on SYNTHETIC
    // ground truth, NOT a recovered key and NOT the plaintext->group-element
    // mapping, and says nothing about the eyes.
    assert_contains(
        &stdout,
        "PARTIAL visible-coset action recovery (a fraction of per-letter visible-coset transitions; NOT a recovered key, NOT the plaintext->group-element mapping)",
    );
    assert_contains(
        &stdout,
        "computed on SYNTHETIC ground truth and says nothing about the eyes.",
    );
}

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
}

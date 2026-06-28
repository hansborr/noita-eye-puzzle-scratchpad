//! CLI regression tests for the Thread 4 synthetic GAK-attack (GCTAK gate).
//!
//! This suite is the **honesty lock** for the `gak-attack` subcommand: it pins
//! the report's synthetic-only disclaimer, tentative
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

    // The gate is the rate vs the matched null, not a single seed.
    assert_contains(
        &stdout,
        "rate-beats-null gate (the gate is the rate vs null, not a single seed)",
    );
    assert_contains(
        &stdout,
        "rate-vs-null gate passed (real rate clears floor and strictly exceeds matched-null rate):",
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

    // Exemplars are illustrations, not pass evidence.
    assert_contains(
        &stdout,
        "retry-selected exemplars (illustrations only, not pass evidence; the gate passes on the rate above)",
    );
    assert_contains(
        &stdout,
        "note: an exemplar is an illustration of one worked seed, not evidence every seed recovers.",
    );

    // Synthetic-only disclaimer: the eyes are not touched here.
    assert_contains(
        &stdout,
        "Synthetic-only disclaimer: this unit never touches the eye corpus;",
    );

    // The small-support prior is labelled tentative and not a hard constraint.
    assert_contains(
        &stdout,
        "Tentative small-support prior: the <=k-swaps / small-support search heuristic is a tentative prior to validate, not a hard constraint;",
    );

    // A negative/partial result is the expected, reportable outcome.
    assert_contains(
        &stdout,
        "the expected, reportable outcome, not a thread failure.",
    );

    // --- Unit 2a: the real-GAK (non-trivial-H) deck attack honesty surface. ---

    // The deck attack is real GAK (|H| > 1) and is the community's open problem.
    assert_contains(
        &stdout,
        "Real-GAK deck attack (non-trivial hidden subgroup H = Stab(top) = S_(n-1), |H| = (n-1)! > 1)",
    );
    // P0a: what is recovered is partial visible-coset action recovery, not a key
    // and not the plaintext->group-element mapping (the recovery-honesty bound).
    assert_contains(
        &stdout,
        "What this unit recovers is partial visible-coset action recovery (a fraction of per-letter visible-coset transitions; not a recovered key, not the plaintext->group-element mapping)",
    );

    // P1a: the headline deliverable is the measured hidden-state obstruction (the
    // multi-valuedness that bounds recovery and motivates idea 3).
    assert_contains(
        &stdout,
        "most of a letter's visible-coset action is multi-valued across hidden states. The recoverable part (single-valued core) is bounded by this multi-valuedness",
    );
    assert_contains(
        &stdout,
        "multivalued-frac: the measured hidden-state obstruction (fraction of visible cosets that map multi-valued under a fixed letter).",
    );

    // P1a: fixed-context true-conflict aborts are surfaced as a feature; the
    // cross-hidden-state multi-valuedness is explicitly not called a conflict.
    assert_contains(
        &stdout,
        "fixed-context true-conflict aborts (a feature, not a bug):",
    );
    assert_contains(
        &stdout,
        "Cross-hidden-state multi-valuedness is not a conflict",
    );

    // P1c: the recovered fraction is small and roughly flat (does not climb with
    // n); the null only begins to match real at larger n / some seeds.
    assert_contains(
        &stdout,
        "partial visible-coset action recovery stays small and roughly flat across n (it does not climb with n)",
    );
    // P2b: the per-seed p-value is conservative / non-significant on its own.
    assert_contains(
        &stdout,
        "the per-seed p-value is conservative (high per-fixture variance) and is non-significant on its own",
    );

    // The small-support prior + hidden-state marginalization are the next unit,
    // present only as documented hooks here (not applied).
    assert_contains(
        &stdout,
        "Tentative small-support prior + hidden-state marginalization are the next unit: this unit only generates both regimes and leaves documented hooks",
    );

    // P0a: the deck recovery is partial visible-coset action recovery on synthetic
    // ground truth, not a recovered key and not the plaintext->group-element
    // mapping, and says nothing about the eyes.
    assert_contains(
        &stdout,
        "partial visible-coset action recovery (a fraction of per-letter visible-coset transitions; not a recovered key, not the plaintext->group-element mapping)",
    );
    assert_contains(
        &stdout,
        "computed on synthetic ground truth and says nothing about the eyes.",
    );
}

#[test]
fn gak_attack_subcommand_reports_unit_2b_marginalization_honesty_surface() {
    // The unit-2b (idea 3 + idea 2) honesty surface: the bundled report carries the
    // hidden-state marginalization result with what recovery may claim, the beam-width
    // disclosure, the partial-not-a-key labelling, the measured "helps on small n /
    // breaks as n grows" outcome, and the tentative small-support prior validation.
    // All asserted strings are gate-verdict-independent constants.
    let stdout = run_noita_eye(&["gak-attack", "--seeds-per-kind", "2", "--seed", "123"]);

    // Unit-2b headline: idea 3 (marginalization) + idea 2 (small-support prior).
    assert_contains(
        &stdout,
        "Unit 2b hidden-state marginalization (idea 3) + tentative small-support prior (idea 2)",
    );

    // The recovered object is the per-letter coset marginal, a partial visible-coset
    // action recovery, not a key and not the plaintext->group-element mapping.
    assert_contains(
        &stdout,
        "The recovered object is the per-letter visible-coset edge marginal over hidden states (multi-valued from allowed) -- a partial visible-coset action recovery, not a recovered key, not the plaintext->group-element mapping. Synthetic-only.",
    );

    // The beam width bound is disclosed (no silent truncation); dropped beams reported.
    assert_contains(
        &stdout,
        "beam width bound: 8 (disclosed, no silent truncation; dropped beams are reported per n)",
    );

    // The headline sweep runs the prior off so no result silently depends on it.
    assert_contains(
        &stdout,
        "small-support prior (idea 2) for the headline sweep: off (support-rank + width-cap candidates, held-out-strict select)",
    );

    // The measured result: idea-3 beats the 2a single-valued core, and breaks as |H|
    // grows -- "helps on small n, breaks as n grows" is the expected outcome.
    assert_contains(
        &stdout,
        "idea-3 marginalization recovers several-fold more true per-letter coset edges than the 2a single-valued core at every n",
    );
    assert_contains(
        &stdout,
        "\"Helps on small n, breaks as n grows\" is the expected, reportable outcome, not a thread failure.",
    );

    // The tentative small-support prior is labelled a heuristic, validated, and the
    // graceful-failure property is the load-bearing result.
    assert_contains(
        &stdout,
        "Tentative small-support prior validation (idea 2; the prior is a heuristic to validate, not a hard constraint, labelled everywhere)",
    );
    assert_contains(
        &stdout,
        "prior fails gracefully (the robust, structural guarantee):",
    );
    assert_contains(
        &stdout,
        "prior is selectively discriminative (weak, tentative signal):",
    );

    // The unit-2b interpretation holds the recovery-honesty bound: partial recovery, never a
    // key, breaks as |H| grows, prior off in the headline, beam width disclosed.
    assert_contains(
        &stdout,
        "but only partial visible-coset action recovery (an edge marginal over hidden states), never a recovered key and never the plaintext->group-element mapping.",
    );
    assert_contains(
        &stdout,
        "a marginal/negative result at larger n is the expected outcome.",
    );
}

#[test]
fn gak_attack_eyes_subcommand_locks_the_eyes_honesty_surface() {
    // The eyes Step-3 honesty lock: the only unit that touches the real eyes, and
    // the highest honesty-risk surface in the project. We pin the
    // expected-no-candidate framing, the hypothesis-not-decode label, the held-out +
    // Thread-3 gate wording, and the candidate-logging protocol. We deliberately do
    // not assert a decode or a specific gate verdict (per the spec: pin the honesty
    // strings, not a decode verdict). The candidate record is written to a temp dir
    // so the committed candidates/ tree is untouched by the test.
    let dir = std::env::temp_dir().join("gak-eyes-cli-honesty");
    // Start from a fresh dir so a leftover record from a prior run cannot mask a
    // dropped-write regression (the assertion below is on the exact filename).
    // Best-effort: a missing dir on the first run is fine, so the result is bound
    // and dropped rather than asserted.
    let _removed = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp candidates dir");
    let dir_str = dir.to_string_lossy().into_owned();
    let stdout = run_noita_eye(&[
        "gak-attack-eyes",
        "--trials",
        "16",
        "--candidates-dir",
        &dir_str,
    ]);

    // Headline: the only unit that touches the real eyes.
    assert_contains(
        &stdout,
        "Thread 4 eyes Step 3 (the only unit that touches the real eye corpus)",
    );

    // The expected outcome is no surviving candidate; the decode remains blocked.
    assert_contains(
        &stdout,
        "Expected outcome: no surviving candidate. The standing conclusion is the eye decode remains blocked on the unknown symbol->meaning mapping; a clean honest negative is a success, not a failure.",
    );

    // What is recovered is structure, not cleartext; any candidate is a hypothesis.
    assert_contains(
        &stdout,
        "What is recovered: structure (visible-coset / chain-link constraints), not cleartext.",
    );
    assert_contains(&stdout, "Any candidate is a hypothesis, never a decode.");

    // The exact entry path (per-message, boundaries kept, never re-ordered).
    assert_contains(
        &stdout,
        "entry path (exact): orders::corpus_grids() -> accepted_honeycomb_order() -> read_corpus_message_values (per-message, boundaries kept, never concatenated, never re-ordered)",
    );

    // Gate 1: held-out isomorphs vs a matched within-message shuffle null, with the
    // positive control that must fire on known signal.
    assert_contains(
        &stdout,
        "Gate 1 -- held-out isomorphs vs matched within-message shuffle null",
    );
    assert_contains(
        &stdout,
        "held-out positive control on a synthetic isomorph-rich eye-shaped fixture:",
    );
    // The population-relative, fair material-effect bar (p-value necessary, not
    // sufficient) — calibrated to the eyes' own max achievable score so the negative
    // rests on a detector the eyes could in principle have passed (F1).
    assert_contains(
        &stdout,
        "material-effect bar (p-value is necessary, not sufficient), population-relative and fair to the eyes:",
    );
    assert_contains(
        &stdout,
        "below the eyes' max, so genuine signal could clear it",
    );
    assert_contains(
        &stdout,
        "Gate 1 verdict (held-out beats matched null and clears the calibrated material-effect bar):",
    );

    // Gate 2: Thread-3 perfect-isomorphism consistency, reused (never re-derived).
    assert_contains(
        &stdout,
        "Gate 2 -- Thread-3 perfect-isomorphism consistency (Thread-3 API reused, never re-derived)",
    );
    assert_contains(&stdout, "Gate 2 verdict (model consistent with Thread 3):");

    // Gate 3: speculative, last, Finnish-weighted, never primary.
    assert_contains(
        &stdout,
        "Gate 3 -- speculative cleartext plausibility (last, Finnish-weighted, never primary)",
    );

    // The candidate-logging protocol (standing user directive).
    assert_contains(
        &stdout,
        "Candidate-logging protocol: every eyes run writes a dated, clock-free record under research/gak-threads/candidates/",
    );
    assert_contains(
        &stdout,
        "any candidate cleartext (English or Finnish) is logged verbatim for human review.",
    );

    // The record file was actually written, under its exact deterministic name
    // (mirrors eyes_record_filename): asserting the precise name — not merely an
    // `eyes-*` prefix — catches both a dropped write and a wrong/stale filename.
    // --trials matches the value passed above; seed and beam stay at defaults.
    let expected_name = format!(
        "eyes-seed-{:016x}-trials-{}-beam-{}.md",
        noita_eye_puzzle::attack::gak_attack::EYES_DEFAULT_SEED,
        16,
        noita_eye_puzzle::attack::gak_attack::EYES_DEFAULT_BEAM_WIDTH,
    );
    assert!(
        dir.join(&expected_name).is_file(),
        "the eyes run must write the candidate record {expected_name} under {dir_str}"
    );
}

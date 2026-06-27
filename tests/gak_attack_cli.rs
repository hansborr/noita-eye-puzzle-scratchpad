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

#[test]
fn gak_attack_subcommand_reports_unit_2b_marginalization_honesty_surface() {
    // The unit-2b (idea 3 + idea 2) honesty surface: the bundled report carries the
    // hidden-state marginalization result with its claim ceiling, the beam-width
    // disclosure, the partial-not-a-key labelling, the measured "helps on small n /
    // breaks as n grows" outcome, and the TENTATIVE small-support prior validation.
    // All asserted strings are gate-verdict-independent constants.
    let stdout = run_noita_eye(&["gak-attack", "--seeds-per-kind", "2", "--seed", "123"]);

    // Unit-2b headline: idea 3 (marginalization) + idea 2 (small-support prior).
    assert_contains(
        &stdout,
        "UNIT 2b hidden-state marginalization (idea 3) + TENTATIVE small-support prior (idea 2)",
    );

    // The recovered object is the per-letter coset MARGINAL, a PARTIAL visible-coset
    // action recovery, NOT a key and NOT the plaintext->group-element mapping.
    assert_contains(
        &stdout,
        "The recovered object is the per-letter visible-coset edge MARGINAL over hidden states (multi-valued from allowed) -- a PARTIAL visible-coset action recovery, NOT a recovered key, NOT the plaintext->group-element mapping. SYNTHETIC-ONLY.",
    );

    // The beam width bound is DISCLOSED (no silent truncation); dropped beams reported.
    assert_contains(
        &stdout,
        "beam width bound: 8 (DISCLOSED, no silent truncation; dropped beams are reported per n)",
    );

    // The headline sweep runs the prior OFF so no result silently depends on it.
    assert_contains(
        &stdout,
        "small-support prior (idea 2) for the headline sweep: OFF (support-rank + width-cap candidates, held-out-strict select)",
    );

    // The MEASURED result: idea-3 beats the 2a single-valued core, and breaks as |H|
    // grows -- "helps on small n, breaks as n grows" is the expected outcome.
    assert_contains(
        &stdout,
        "idea-3 marginalization recovers SEVERAL-FOLD more true per-letter coset edges than the 2a single-valued core at every n",
    );
    assert_contains(
        &stdout,
        "\"Helps on small n, breaks as n grows\" is the expected, reportable outcome, not a thread failure.",
    );

    // The TENTATIVE small-support prior is labelled a heuristic, validated, and the
    // graceful-failure property is the load-bearing result.
    assert_contains(
        &stdout,
        "TENTATIVE small-support prior validation (idea 2; the prior is a heuristic to validate, NOT a hard constraint, labelled everywhere)",
    );
    assert_contains(
        &stdout,
        "prior FAILS GRACEFULLY (the robust, structural guarantee):",
    );
    assert_contains(
        &stdout,
        "prior is SELECTIVELY discriminative (weak, TENTATIVE signal):",
    );

    // The unit-2b interpretation holds the claim ceiling: PARTIAL recovery, never a
    // key, breaks as |H| grows, prior OFF in the headline, beam width disclosed.
    assert_contains(
        &stdout,
        "but only PARTIAL visible-coset action recovery (an edge marginal over hidden states), NEVER a recovered key and NEVER the plaintext->group-element mapping.",
    );
    assert_contains(
        &stdout,
        "a marginal/negative result at larger n is the expected outcome.",
    );
}

#[test]
fn gak_attack_eyes_subcommand_locks_the_eyes_honesty_surface() {
    // The EYES Step-3 honesty lock: the ONLY unit that touches the real eyes, and
    // the highest honesty-risk surface in the project. We pin the claim ceiling, the
    // expected-no-candidate framing, the HYPOTHESIS-not-decode label, the held-out +
    // Thread-3 gate wording, and the candidate-logging protocol. We deliberately do
    // NOT assert a decode or a specific gate verdict (per the spec: pin the honesty
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

    // Headline: the ONLY unit that touches the real eyes.
    assert_contains(
        &stdout,
        "Thread 4 EYES Step 3 (the ONLY unit that touches the real eye corpus)",
    );

    // The claim ceiling, verbatim-in-spirit.
    assert_contains(
        &stdout,
        "the eyes are deterministic, engine-generated, strikingly structured data of unknown meaning; unsolved; no primary developer source confirms recoverable plaintext.",
    );

    // The expected outcome is NO surviving candidate; the decode remains BLOCKED.
    assert_contains(
        &stdout,
        "Expected outcome: NO surviving candidate. The standing conclusion is the eye decode remains BLOCKED on the unknown symbol->meaning mapping; a clean honest negative is a SUCCESS, not a failure.",
    );

    // What is recovered is STRUCTURE, not cleartext; any candidate is a HYPOTHESIS.
    assert_contains(
        &stdout,
        "What is recovered: STRUCTURE (visible-coset / chain-link constraints), NOT cleartext.",
    );
    assert_contains(&stdout, "Any candidate is a HYPOTHESIS, never a decode.");

    // The exact entry path (per-message, boundaries kept, never re-ordered).
    assert_contains(
        &stdout,
        "entry path (exact): orders::corpus_grids() -> accepted_honeycomb_order() -> read_corpus_message_values (per-message, boundaries kept, never concatenated, never re-ordered)",
    );

    // GATE 1: held-out isomorphs vs a matched within-message shuffle null, with the
    // POSITIVE CONTROL that must fire on known signal.
    assert_contains(
        &stdout,
        "GATE 1 -- held-out isomorphs vs matched within-message shuffle null",
    );
    assert_contains(
        &stdout,
        "held-out POSITIVE CONTROL on a synthetic isomorph-rich eye-shaped fixture:",
    );
    // The POPULATION-RELATIVE, FAIR material-effect bar (p-value necessary, NOT
    // sufficient) — calibrated to the eyes' OWN max achievable score so the negative
    // rests on a detector the eyes could in principle have passed (F1).
    assert_contains(
        &stdout,
        "material-effect bar (p-value is NECESSARY, NOT sufficient), POPULATION-RELATIVE and FAIR to the eyes:",
    );
    assert_contains(
        &stdout,
        "BELOW the eyes' max, so genuine signal COULD clear it",
    );
    assert_contains(
        &stdout,
        "GATE 1 VERDICT (held-out beats matched null AND clears the calibrated material-effect bar):",
    );

    // GATE 2: Thread-3 perfect-isomorphism consistency, REUSED (never re-derived).
    assert_contains(
        &stdout,
        "GATE 2 -- Thread-3 perfect-isomorphism consistency (Thread-3 API REUSED, never re-derived)",
    );
    assert_contains(&stdout, "GATE 2 VERDICT (model consistent with Thread 3):");

    // GATE 3: SPECULATIVE, LAST, Finnish-weighted, NEVER primary.
    assert_contains(
        &stdout,
        "GATE 3 -- SPECULATIVE cleartext plausibility (LAST, Finnish-weighted, NEVER primary)",
    );

    // The candidate-logging protocol (standing user directive).
    assert_contains(
        &stdout,
        "Candidate-logging protocol: every eyes run writes a dated, clock-free record under research/gak-threads/candidates/",
    );
    assert_contains(
        &stdout,
        "any candidate cleartext (English OR Finnish) is logged VERBATIM for human review.",
    );

    // The record file was actually written, under its EXACT deterministic name
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

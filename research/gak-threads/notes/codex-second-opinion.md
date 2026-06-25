# Codex cross-model second opinion — GAK-threads wave-1

**Date:** 2026-06-24. **Reviewer:** `codex-cli 0.142.0` (`codex exec`, a different
model family), run as four focused passes (serial, one workspace-lock each) against
the wave-1 deliverables. Codex was instructed to be adversarial (find holes, not
agree by default), to re-run the scratchpad Python where it could, and to hold the
project's claim ceiling. It modified no files and ran no `cargo`/`make`.

This note records the verdicts **verbatim** (per-item `[AGREE]/[CONCERN]/[HOLE]`)
and the resulting reconciliation. Logs: `scratchpad/codex/{agl,dihedral,math}.log`.

---

## Angle 1 — AGL(1,83) exclusion  →  CORROBORATED (codex re-ran the enumerations)

> **[AGREE] (a)** The key lemma holds: for differing starts `D.0 != 0`, every affine
> `D=(a,b)` over `F_83` fixes at most one point; I rechecked `0/6724` for `C83:C82`
> and `0/3362` for `C83:C41`, and reran the `2,000,000`-trial forward search with `0`
> varying-run hits per variant.
>
> **[AGREE] (b)** The real streams are varying: all nine starts are distinct, cols
> `1..2` are shared as `[66,5]`, group A has `20/24` distinct symbols, group B `18/20`.
>
> **[AGREE] (c)** The "resync is generic" result does not undercut the exclusion; it
> only shows constant stutter resync is common (98.78%), while the empirical argument
> adds the missing constraint that varying shared runs require two fixed points,
> impossible for nontrivial affine discrepancies.
>
> **[AGREE] (d)** `C83:C41` is excluded by the same lemma … `PROGRESS.md:132-134`
> saying "not yet excluded" is **stale/contradictory** with `PROGRESS.md:78-90`.
>
> **Bottom line:** AGL is rigorously excluded for the specified AGL-GAK model with
> moved-reference-point output and a single shared plaintext/key segment behind the
> shared sections. The kill is **not** the wiki's "fine-tuning is rare" argument; it
> is the stronger varying-run fixed-point argument. Residual gap is scope: this does
> not decode the eyes, and does not exclude non-GAK affine constructions or reject the
> shared-plaintext interpretation of the shared sections.

**Reconciliation:** the apparent verification-vs-empirical disagreement dissolves —
the wiki's *stated* reason is weak (verification pass right), a *stronger* reason does
the job (empirical pass right). Codex independently reproduced both exclusion counts
and wrote its own `agl_c41.py` to confirm the index-2 subgroup. **Action:** fix the
stale `C₈₃:C₄₁` line (done below).

## Angle 2 — Dihedral (D₁₆₆) exclusion  →  CORROBORATED, downgraded to MEDIUM confidence

> **(a) [AGREE]** The group theory is sound: in my concrete `D166` coset-action check
> I got 0 divide-order violations, reflection cycles `1 + 41*2`, rotation cycles `83`,
> and 0 noncommuting pairs among the 82 order-83 elements.
>
> **(b) [AGREE]** The fragility claim is correct: full columns `0..10` give the
> conflict, but core columns `0..8` do not; specifically `3->Q` is col `4/8`, `Q->)`
> is **only col `9` extension**, `3->-` is col `4/8`, and `-->_` is col `6`.
>
> **(c) [CONCERN]** Net verdict is **option (ii): the D166 exclusion holds
> conditionally, but is fragile to a single mis-transcription** or bad same-plaintext
> extension; A5 is load-bearing because the "both order-83 therefore commute" step only
> works if all three windows share one global CT-to-coset labeling and hidden subgroup.
>
> **Bottom line:** the algebraic exclusion is safe to build on only as a **conditional
> result, not a robust settled fact … medium confidence**. The biggest risk is not
> group theory; it is the same-plaintext/transcription status of that over-extended
> column 9.

**Reconciliation:** matches the wave-1 framing (`SUPPORTED but single-witness-fragile`,
HOLE 1 + HOLE 2). Codex re-derived the exact column provenance independently. **Report
`transitivity.rs` at MEDIUM confidence / "conditionally excluded," carrying HOLE 1 +
HOLE 2 verbatim** — do not present D₁₆₆ exclusion as settled fact (the wiki's framing).

## Angle 3 — "Exactly 6 transitive groups on 83 points"  →  CORROBORATED (high)

> **[AGREE]** Solvable case … `82 = 2*41`, divisor set `{1,2,41,82}`, giving `C83`,
> `D166`, `C83:C41`, `AGL(1,83)` exactly once (one subgroup per divisor since
> `Aut(C83)=C82` is cyclic).
> **[AGREE]** Non-solvable case … I independently brute-checked the projective equation
> `(q^d-1)/(q-1)=83` over prime powers and found no solution; `d=2` would require
> `q=82`, not a prime power → only `A83`, `S83`.
> **[AGREE]** `83` is not a Mathieu/sporadic prime degree; small-prime sanity checks
> `5,7,11,23` match the known counts `5,7,8,7`.
> **[CONCERN]** Scope/tooling: no GAP cross-check available; the non-solvable count is
> classification-*applied*, not reproved. (Also: the wiki AGL page's general order
> formula is suspect, but the thread uses the correct `|AGL(1,83)| = 83*82`.)
>
> **Bottom line:** agree with "exactly 6," conditional on the standard CFSG-based
> prime-degree 2-transitive classification. Group-theoretic narrowing only — does not
> prove the eyes are GAK or transitive. **Confidence: high.**

## Angle 4 — Perfect-isomorphism scan  →  LOGIC CORROBORATED; artifact needs hygiene fixes

> **[AGREE] (a)** Contrapositive logic: GAK is proven perfectly isomorphic; a genuine
> internal broken-repeat violation with same plaintext on both sides would falsify
> CTAK..XGAK.
> **[CONCERN] (b)** Reproduces **only under the stricter threshold**: with
> `classify_v4.POST_MIN = 8` the headline reproduces (strong bar 0, null 0/3000; loose
> bar 1 at `east4@65` vs `west4@67`, add-one `p = 0.049`). But `classify_v4.py` itself
> says `POST_MIN = 5`, while `emit_safe.py` monkeypatches it to `8`; running
> `final_run.py` as-is gives different results. `p ≈ 0.049` is weak and should not be
> overread.
> **[AGREE] (c)** Classifier correctly keys on **gap pattern**, not raw cross-stream
> symbol equality (`maximal_right_agreement` breaks on previous-occurrence distance
> mismatch) — handles the deck/GAK subtlety that a single differing CT symbol is not a
> violation.
> **[CONCERN] (d)** Wiki regression checks only partly automated: `wiki_regression.py`
> still imports `classify_v2` and labels 3A as an internal violation (stale code); 3B's
> full `*` rows don't reproduce as plain canonical gap strings; 3C's bound row is
> hard-coded from the wiki annotation, not an independent recomputation.
>
> **Bottom line:** supports "no robust strong-bar falsification found" and keeps
> GAK/XGAK viable, but does not prove perfect isomorphism, and certainly not that the
> eyes are GAK. The main real issue is **reproducibility hygiene around `POST_MIN` and
> stale regression code, not the core gap-pattern logic.** Confidence: moderate-high on
> the logical framing, moderate on the empirical artifact as packaged.

**Reconciliation:** the *conclusion* (zero robust internal violations; GAK family stays
viable) stands and the core classifier logic is sound, but the prototype has two
hygiene defects that **must be fixed when hardening into `perfect_isomorphism.rs`**:
(1) the `POST_MIN` post-context threshold must be a single principled, documented
parameter — not a default of 5 silently monkeypatched to 8; (2) the wiki regression
checks must run against the *current* classifier (drop the stale `classify_v2` import)
and recompute 3B/3C rather than asserting hard-coded annotations. The loose-bar
`p ≈ 0.049` candidate is within the null — report as benign, do not overread.

---

## Net effect on wave-1 conclusions

| Claim | Wave-1 | After codex |
| --- | --- | --- |
| AGL(1,83) excluded (both variants) | empirical, strong | **CORROBORATED** — re-run independently; C₈₃:C₄₁ included |
| D₁₆₆ excluded | supported, single-witness-fragile | **CORROBORATED, MEDIUM confidence / conditional** (rides on col 9) |
| Exactly 6 transitive groups | audited | **CORROBORATED, high** (CFSG-conditional; no GAP) |
| Perfect-iso: 0 robust internal violations | supported | **logic CORROBORATED; artifact needs `POST_MIN`/regression hygiene** before hardening |
| `data.wak` dead end | closed | (not re-reviewed — low-risk paper result) |

**Candidate set under the GAK hypothesis (post-codex):** `{A₈₃, S₈₃}` — C₈₃ (commutative),
both AGL variants (varying-run lemma), and D₁₆₆ (conditional/medium) excluded. All
exclusions remain conditional on the shared-plaintext interpretation of the shared
sections and a single global cipher configuration across the nine messages; none of this
decodes the eyes or changes the claim ceiling.

## Action items carried into wave-2 implementation

1. **`PROGRESS.md`** — remove the stale "`C₈₃:C₄₁` not yet excluded" claim (done in this pass).
2. **`transitivity.rs`** — report D₁₆₆ at MEDIUM confidence / conditional, HOLE 1 + HOLE 2 verbatim.
3. **`perfect_isomorphism.rs`** — make `POST_MIN` a single documented parameter; rebuild the
   wiki regression checks against the current classifier (no `classify_v2`); recompute 3B/3C.
4. **`agl_gak.rs`** — exclusion covers both variants; record the wiki *over-conceded* and the
   varying-run mechanism is the rigorous kill.
5. Run **`codex review`** (subagents per module/dimension, in-prompt) on the wave-2 Rust diff
   before any commit.

# GAK Threads — Wave-1 PROGRESS

**Date:** 2026-06-24. **Wave:** 1 (verification notes + empirical Python prototypes
+ frozen Rust implementation specs). Source material: wiki clone at
`/home/node/persist/eye-messages.wiki/` (content current to **2026-01-16**) and the
nine Experiment-0-verified streams in `src/corpus.rs` (1036 reading-layer trigrams,
83 contiguous symbols, accepted honeycomb order `standard36-u012-d012`).

**Claim ceiling (held throughout, non-negotiable).** The strongest defensible
statement about the eyes remains: *deterministic, engine-generated, strikingly
structured data of unknown meaning; unsolved; no primary developer source confirms
recoverable plaintext.* Everything below is mapping-independent structural work
(ciphertext-symbol **equality** + group structure only); no symbol→meaning mapping
is invented or consumed. All empirical numbers are from **throwaway Python
prototypes** in the session scratchpad — NOT yet wired into the build gate; nothing
under `src/` was modified this wave. Model-conditional and assumed items are labelled
inline.

---

## (1) Per-thread status table

| Thread | Wave-1 outcome | Load-bearing-claim status | Key number / finding | Implementation spec | Next action |
| --- | --- | --- | --- | --- | --- |
| **1A** Transitivity restriction (6 groups for 83) | Theorem **re-derived two ways**, method cross-checked on 4 small primes | **AUDITED — holds** (conditional on the published 2-transitive-prime-degree classification; CFSG-dependent) | exactly **6** groups: `{C₈₃, D₁₆₆, C₈₃:C₄₁, AGL(1,83), A₈₃, S₈₃}`; solvable count = τ(82)=4, +`{A₈₃,S₈₃}`, +0 projective/Mathieu/sporadic | (proof note only — no Rust module; encoded as a test constant in `transitivity.rs`) | Optional: GAP `NrTransitiveGroups(83)` machine cross-check if GAP becomes available (the one residual gap) |
| **1B** Dihedral GAK exclusion | Logic **sound**; cited triple reproduces **byte-for-byte**; contradiction reconstructed | **SUPPORTED but single-witness-fragile** — conditional on A1 (same plaintext) + A5 (one global config) | `D₁₆₆` excluded; order-83 forcing robust on 9-core, commutativity conflict lives **only** at over-extended col9; **0** typo-robust genuine witnesses besides the cited triple | [`specs/thread-1b-5-spec.md`](specs/thread-1b-5-spec.md) → `src/transitivity.rs` | Implement `transitivity.rs`; report must carry HOLE 1 + HOLE 2 verbatim |
| **5** Chaining graph (conflicts + coverage) | Prototype complete; broad + genuine tiers; null + positive control fire | **Quantified** (transitivity = *evidence for*, not proof) | broad: **79/83** touched, **1** component (untouched `{1,27,28,76}`); genuine: **28/83**, **5** comps `[14,4,4,4,2]`; ~900× null on conflicts | [`specs/thread-1b-5-spec.md`](specs/thread-1b-5-spec.md) → `src/chaining_graph.rs` | Implement `chaining_graph.rs` (shared chain-link primitive; build before Thread 4) |
| **2** AGL stress-test (the "soft link") | Prototype complete; **stronger** result than expected — *rigorous* exclusion | **FLAGGED-WITH-A-HOLE in the wiki, then KILLED by us** — wiki exclusion overstated; varying-shared-run argument is the rigorous kill | `AGL(1,83)` (both `C83:C82` & `C83:C41`) **excluded exhaustively**: shared run after a differing start must be **constant**; eyes' runs **vary** (20/24, 18/20). 0 violations / 40000; 0/2M forward sims | [`specs/thread-2-spec.md`](specs/thread-2-spec.md) → `src/agl_gak.rs` (+ `AglGakKey` in `ciphers.rs`) | Implement `agl_gak.rs`; report must record the wiki *over-conceded* and the *varying-run* mechanism |
| **3** Perfect-isomorphism / allomorph scan | Prototype complete; classifier regression-hardened against 2 over-extension traps | **SUPPORTS (does not prove) perfect iso → keeps GAK family viable** | **0** robust internal violations at strong bar (null also 0); 1 loose-bar candidate (Stutter east4@65/west4@67) within null (p≈0.049); positive control `A.B.CB.AC` fires p<5e-4 | [`specs/thread-3-spec.md`](specs/thread-3-spec.md) → `src/perfect_isomorphism.rs` | Implement `perfect_isomorphism.rs`; emit the safe-isomorph extent list (16 spans) for Threads 1B/5/4 |
| **4** GAK attack prototype (the prize) | **Spec only** — gated research spike | Targets the wiki's **stated open problem** (no known GAK attack) | none yet (no run); depends on Thread 5's `chaining_graph`; small-support ≤4-swap prior is **TENTATIVE** | [`specs/thread-4-spec.md`](specs/thread-4-spec.md) → `ciphers::GakKey` + `src/gak_attack.rs` | **GO** for the gated spike (see §4); Step-0 generator first, GCTAK solve = decisive gate |
| **6** Binary / game-data re-exam | `data.wak` unpacked (14745 files) & scanned | **CLOSED — confirmed dead end** | **0** hits for eye-message digit strings, base-7/base-5 transform, or 83-entry table in shipped data; consistent with hardcoded `u32` constants in `noita.exe` | (n/a — no module) | Do not reopen; game data re-enters only as post-hoc verification for a Thread-4 candidate |

---

## (2) Headline empirical results

All from scratchpad Python prototypes (Monte-Carlo numbers are seeded estimates,
not exact tail probabilities). Each negative carries a matched within-message
multiset-shuffle null; each positive control fired on known signal.

### Dihedral conflict catalogue (Thread 1B/5)
- **Genuine (Tier A, provably-same-plaintext isomorphs):** order-83-forcing contexts
  = **6**; TRUE (non-permutation) conflicts = **0**; shared-pivot order-83 +
  commutativity-conflict witness triangles = **1** — and it **is the wiki's own cited
  triple**. **0 / 131** shared-pivot candidate conflicts are typo-robust (independent
  witnesses: **0**; fragile: all).
- **Broad (Tier B, any ≥2 gap-isomorphic occurrences — UPPER BOUND, conflates genuine
  with coincidental gap-isomorphs):** contexts = 492; order-83-forcing = 392; raw
  order-83+conflict triples = **17 124**; distinct context-pairs with a conflict =
  **5 242**; distinct occurrence-SETs (independence proxy) = **4 988**; greedy
  mutually-disjoint witnesses = **32**.
- **vs null (30 within-message shuffles):** real exceeds null on *every* metric;
  p = 1/31 ≈ 0.032 is the resolution floor (no shuffle reached real on any metric);
  ~900× the null conflict count.

### Transitivity coverage (Thread 5) vs null
- **Broad:** symbols-touched = **79/83** (95%); largest-component = **79**;
  #components = **1** (untouched `{1,27,28,76}`).
- **Genuine:** symbols-touched = **28/83**; largest-component = **14**;
  #components = **5** (sizes `[14,4,4,4,2]`).
- **Null mean:** touched 52.3, largest-component 28.7, #components 9.1 — real has a
  single giant component where the null fragments into ~9.
- *Honest read:* "nearly all symbols in one component" is well-supported on the broad
  graph, **much weaker** on the genuine-only graph. Coverage is **evidence for, not
  proof of**, a transitive action.

### Perfect-iso internal-violation count (Thread 3) vs null
- **Strong bar (≥3-repeat seed):** real internal violations = **0**; matched null
  (3000 iters) = **0** (P≥1 = 0).
- **Loose bar (≥2-repeat):** real = **1** (east4@65 vs west4@67, in the wiki's Stutter
  Section); matched null P(≥1) = **0.049** (mean 0.053, max 3) — **within chance
  collision**, classified benign. **Net: zero robust internal violations survive.**
- Positive control: `A.B.CB.AC` (6 occ) and `ABC.DC.AD.B` (4 occ) both fire at
  empirical p **< 5e-4** (null never produced ≥2 occurrences in 2000 shuffles).
  *(We recompute under our own matched null rather than quoting the wiki's
  ~3×10⁻²⁰ figure.)*

### AGL feasibility verdict (Thread 2)
- **AGL(1,83)-GAK rigorously EXCLUDED — exhaustively, not statistically** — for both
  `C83:C82` and `C83:C41`. Mechanism: after a differing immediately-preceding symbol
  the inter-message discrepancy `D` is a fixed non-identity affine map fixing **≤1**
  point ⇒ any shared run must be a **constant** stutter; the eyes' shared runs
  **vary** (group A east1/west1/east2: 20/24 distinct over 24 cols; group B
  east4/west4/east5: 18/20). Confirmations: 0 differing-`D` fix ≥2 points (all 6724 /
  3362); 0 / 2,000,000 forward sims produced a varying shared run ≥2; positive control
  (a constant length-6 shared run) fires. The tightest clincher needs no long run —
  cols 1–2 = `(66,5)`, a length-2 *varying* run shared by all nine after nine
  *distinct* first symbols, is already AGL-impossible. **Candidate set after Thread 2:
  `{A₈₃, S₈₃}`.** The varying-run fixed-point lemma excludes **both** affine variants
  (`C₈₃:C₈₂` and `C₈₃:C₄₁`) identically — codex independently re-ran the enumerations
  (`0/6724` and `0/3362` discrepancies fix ≥2 points). All affine exclusions are
  conditional on the shared-plaintext interpretation of the shared sections + a single
  global cipher configuration (the same assumption the whole transitivity analysis
  rests on); rejecting that assumption reopens the affine options *and* weakens the
  6-group restriction itself, not `C₈₃:C₄₁` alone.

### `data.wak` scan verdict (Thread 6)
- **Lead CLOSED — confirmed dead end.** Archive unpacked (42 MB, format reverse-
  engineered, 14 745 files extracted, integrity-checked). **0** hits for eye-message
  digit strings (incl. the shared prefix and a message-0-unique run), **0** base-7/
  base-5 transform, **0** 83-entry table, **0** eye-message integer content. All
  `eye`-named assets are unrelated world-gen/gameplay. Consistent with the prior
  Ghidra finding (messages are hardcoded `u32` constants in `FUN_0061ed60`); the
  storage layer has **no** symbol→meaning table.

### 6-group proof confidence (Thread 1A)
- **High**, with precise scope. Solvable count = **4** = τ(82) is elementary/certain.
  Non-solvable count = **2** (`A₈₃`,`S₈₃`) rests on the published classification of
  2-transitive groups of prime degree (Burnside + Feit; Dixon–Mortimer §7.7) — the
  single CFSG-dependent external fact, not reproved but arithmetic side-conditions
  self-checked (83 prime; not a Mathieu degree; not a projective degree
  `(qᵈ−1)/(q−1)` — searched exhaustively). Method validated on `p∈{5,7,11,23}` →
  `5,7,8,7`. **Not done:** direct GAP `NrTransitiveGroups(83)` cross-check (GAP not
  installed; `gap` aliases to `git apply`). One sharpening: the hidden-subgroup sizes
  are `{1,2,41,82, 82!/2, 82!}` — the wiki's "`…`" hides that the `A₈₃/S₈₃` survivors
  are the *maximal/hardest* cases, not small continuations.

---

## (3) Wiki-claim audit ledger

| Wiki page (under `/home/node/persist/eye-messages.wiki/`) | Verdict | Note |
| --- | --- | --- |
| `The-Transitivity-Restriction-(6-Groups-for-83).md` ("exactly 6 groups") | **AUDITED** | Re-derived two ways; conditional on published 2-transitive classification. |
| `Proof-that-the-eyes-cannot-be-a-dihedral-GAK-cipher.md` | **FLAGGED-WITH-A-HOLE** | Logic sound, but the contradiction is single-witness-fragile. **HOLE 1 (wiki-acknowledged):** *"a single strategic typo at col6 (or col9) does dissolve this triple's contradiction"* — the within-triple second conflict reuses col6/col9 and does not remove it. **HOLE 2 (NOT wiki-flagged):** *"the commutativity-conflict half lives entirely in the over-extension … on the high-confidence repeated 9-core the order-83 forcing fires but no conflict appears."* Exclusion holds conditional on A1+A5 for that triple. |
| `Proof-that-GAK-is-transitive.md` (right-coset action) | **AUDITED** | This is the correct support for "cycle lengths divide element order," **not** the semidirect-product left-action proof (a trap the verification note flags). |
| `Proof-that-GAK-has-perfect-isomorphism.md` | **AUDITED** | Containment proof verified directly; makes one clean internal violation a whole-family falsifier. |
| `Isomorphic-Cipher-Hierarchy.md` (`CTAK<GCTAK<GAK<XGAK ≤ PerfIso`) | **AUDITED** | The `≤` (open upper edge) is load-bearing and preserved; writing `<` there would overclaim. |
| `Affine-General-Linear-Group-(AGL).md` / `Message-Starts.md` / `Shared-Sections.md` (AGL exclusion) | **FLAGGED-WITH-A-HOLE, then strengthened** | Wiki framed resync as rare/pathological "fine-tuning"; per-pair it is the **generic** case (98.78%) with near-free first symbols — *the wiki overstates*. But the verification note then **over-conceded**: once shared runs must be **varying** (as the eyes' are), message-starts **rigorously exclude** AGL. Hole quote: *"Calling it a 'special exception' / pathological 'fine-tuning' undersells it: per pair it is the generic outcome (98.78%)."* |
| `Group-Autokey-(GAK).md` (L/R convention) | **AUDITED (with correction)** | Output = moved reference point forces the **right-mult / left-coset** variant; mixing left-mult update with `g.x₀` output is the exact mis-model the thread warns about. |
| `Allomorphs.md` 3A/3B/3C regression checks | **AUDITED** | All gap patterns reproduce byte-for-byte; 3C corruption theory carried explicitly as a **hypothesis that bounds, not locates**. |
| `Smallest-GAK-Examples-…Small-Hidden-Subgroups.md` | **TENTATIVE (empty on wiki)** | Currently `TBD`/empty; do **not** cite numbers from it. |
| Deck-cipher small-support / ≤4-swaps-per-letter prior (`Deck-Cipher.md`) | **TENTATIVE** | Allomorph-derived search heuristic; a prior to validate, **not** a hard constraint. Must stay labelled in any Thread-4 output. |
| `Chaining-Conflict-Rates.md` ("conflicts are the norm") | **TENTATIVE / partially-supported** | Matched by the broad chaining graph's abundance, but most broad conflicts ride coincidental gap-isomorphs; typo-robust same-plaintext conflicts = 0–1, not "a dozen independent." |
| `Chaining-Conflicts.md` ("reflections give 2 fixed points") | **FLAGGED (minor, off-path)** | For odd `n=83` the model gives **1** fixed point; descriptive inaccuracy on a different page, irrelevant to the proof. |

**Still-open / not-yet-tested-this-wave:** whether perfect isomorphism actually holds
(unprovable without plaintext — measured as evidence only); whether a GAK attack
exists at all (Thread 4). *(Correction, post-codex: `C₈₃:C₄₁` **is** excluded by the
same varying-run fixed-point lemma as `AGL(1,83)` — see §2 Thread-2 verdict and
`notes/codex-second-opinion.md`; the earlier "not yet excluded" was stale.)*

---

## (4) Recommended implementation order for the gated Rust modules

All four implementation specs are frozen and ready to land under `-D warnings` with
`make verify` green (four-file wiring per `notes/api-infra.md`; matched null +
positive control per module; cite the exact wiki page in rustdoc + report).

1. **`src/chaining_graph.rs`** — [`specs/thread-1b-5-spec.md`](specs/thread-1b-5-spec.md).
   Build first: it owns the shared **chain-link primitive** + conflict catalogue +
   coverage that Threads 1B and 4 both consume. (Hard dependency for Thread 4.)
2. **`src/transitivity.rs`** — [`specs/thread-1b-5-spec.md`](specs/thread-1b-5-spec.md).
   Consumes the chain-link primitive; encodes the 6-group set and emits the
   `DihedralExcluded` verdict, with HOLE 1 + HOLE 2 carried verbatim in the report.
3. **`src/perfect_isomorphism.rs`** — [`specs/thread-3-spec.md`](specs/thread-3-spec.md).
   Parallelizable. Emits the **safe-isomorph extent list** (16 spans) that Threads
   1B/5/4 need to avoid chaining across allomorphic boundaries.
4. **`src/agl_gak.rs`** (+ `AglGakKey` in `ciphers.rs`) —
   [`specs/thread-2-spec.md`](specs/thread-2-spec.md). Parallelizable. Encodes the
   rigorous varying-shared-run exclusion; report records that the wiki *over-conceded*.
5. **`ciphers::GakKey` + `src/gak_attack.rs`** —
   [`specs/thread-4-spec.md`](specs/thread-4-spec.md). **Last**, and only after 1–3
   land (it consumes `chaining_graph` and Thread 3's safe isomorphs).

### Thread 4 spike — GO / NO-GO

**Verdict: GO for the gated, time-boxed spike** — with the spec's milestones treated
as hard gates, not aspirations. The wave-1 results clear the precondition the brief
sets ("staffed only after Threads 1/3/5 confirm the family"): Thread 3 keeps the GAK
family viable (0 robust internal violations), Thread 1A fixes the 6-group target,
Thread 2 prunes AGL so the spike aims at the right survivors (`A₈₃/S₈₃`), and Thread
5 supplies the chaining graph it depends on. Gates, in order:
- **Step 0 (week-1):** general `S_n` GAK generator round-trips exactly + reproduces
  perfect isomorphs. If shaky → **STOP**.
- **Step 1 (decisive gate):** GCTAK solved end-to-end as a positive control.
  **No GCTAK solve → no GAK attempt.**
- **Step 2/3:** partial small-`n` `S_n` recovery is already the publishable win;
  pointing at the eyes (Step 3) is a stretch whose most plausible honest outcome is
  *no surviving candidate*. **The trap to avoid:** any eye "solution" without
  synthetic ground truth and a held-out check is almost certainly coincidence and
  must not be reported as a decode. *(Caveat: the small-support ≤4-swap prior is
  TENTATIVE — a toggleable search heuristic to validate, never a silent dependency.)*

---

## (5) Cross-model second opinion

**Codex cross-model second opinion: DONE.** Four focused `codex exec` passes (a
different model family, adversarial, re-running the scratchpad Python where possible).
Full verbatim verdicts: [`notes/codex-second-opinion.md`](notes/codex-second-opinion.md).

- **AGL exclusion — CORROBORATED.** Codex re-ran the enumerations (`0/6724`, `0/3362`,
  `0/2M` sims) and confirmed both variants excluded; flagged the now-fixed stale
  `C₈₃:C₄₁` line. `[AGREE]×4`.
- **Dihedral exclusion — CORROBORATED, MEDIUM confidence.** Codex built its own D₁₆₆
  model (0 divide-order violations) and re-derived the exact column provenance (`Q->)`
  is col-9 over-extension only). Net `[CONCERN]`: conditional, fragile to one
  mis-transcription — **report at medium confidence, not settled fact.**
- **6-group count — CORROBORATED, high.** Brute-checked the projective equation; only
  residual gap is the absent GAP cross-check (CFSG-conditional). `[AGREE]×3 + [CONCERN]`
  on tooling.
- **Perfect-iso — logic CORROBORATED; artifact needs hygiene.** Classifier correctly
  keys on gap pattern `[AGREE]`; but `[CONCERN]` on `POST_MIN` reproducibility (default
  5 monkeypatched to 8) and stale `classify_v2` import in the regression script. Core
  conclusion (0 robust internal violations) stands; **fix `POST_MIN` + regressions when
  hardening `perfect_isomorphism.rs`.**

No codex verdict overturned a wave-1 conclusion; two were sharpened (dihedral →
medium-confidence/conditional; perfect-iso artifact → hygiene fixes required) and one
stale contradiction (`C₈₃:C₄₁`) was corrected. The claim ceiling is unchanged.

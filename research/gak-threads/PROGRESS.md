# GAK Threads — Wave-1 PROGRESS

**Date:** 2026-06-24. **Wave:** 1 (verification notes + empirical Python prototypes
+ frozen Rust implementation specs). Source material: Lymm's eye-messages wiki
(github.com/Lymm37/eye-messages/wiki, content current to 2026-01-16) and the
nine Experiment-0-verified streams in `src/corpus.rs` (1036 reading-layer trigrams,
83 contiguous symbols, accepted honeycomb order `standard36-u012-d012`).

Claim ceiling (held throughout, non-negotiable). The strongest defensible
statement about the eyes remains: *deterministic, engine-generated, strikingly
structured data of unknown meaning; unsolved; no primary developer source confirms
recoverable plaintext.* Everything below is mapping-independent structural work
(ciphertext-symbol equality + group structure only); no plaintext meaning or
letter-to-action key is invented or consumed. All empirical numbers are from
throwaway Python prototypes in the session scratchpad — not yet wired into the
build gate; nothing under `src/` was modified this wave. Model-conditional and
assumed items are labelled inline.

---

## (1) Per-thread status table

| Thread | Wave-1 outcome | Load-bearing-claim status | Key number / finding | Implementation spec | Next action |
| --- | --- | --- | --- | --- | --- |
| **1A** Transitivity restriction (6 groups for 83) | Theorem re-derived two ways, method cross-checked on 4 small primes; OEIS primitive-count route closes the count cross-check | **Audited — holds** (conditional on the published 2-transitive-prime-degree classification; CFSG-dependent) | exactly 6 groups: `{C₈₃, D₁₆₆, C₈₃:C₄₁, AGL(1,83), A₈₃, S₈₃}`; solvable count = τ(82)=4, +`{A₈₃,S₈₃}`, +0 projective/Mathieu/sporadic; OEIS A000019 `a(83)=6` [verified 2026-07-06] | (proof note only — no Rust module; encoded as a test constant in `transitivity.rs`) | Direct GAP `NrTransitiveGroups(83)` is unavailable (`fail`) [Lymm]; `NrPrimitiveGroups(83)` would only be an extra machine check |
| **1B** Dihedral GAK exclusion | Logic sound; cited triple reproduces byte-for-byte; contradiction reconstructed | **Corroborative but single-witness-fragile** — D₁₆₆ is excluded within-model by Full AGL subsumption [verified]; this witness remains conditional on A1 (same plaintext) + A5 (one global config) | Thread-1B witness: order-83 forcing robust on 9-core, commutativity conflict lives only at over-extended col9; 0 typo-robust genuine witnesses besides the cited triple | [`specs/thread-1b-5-spec.md`](specs/thread-1b-5-spec.md) → `src/transitivity.rs` | **Landed** (248fb32): retained as independent corroboration; exactly 1 pinned witness, `core_only=0`; hole 1/2 + A1–A5 + claim ceiling printed verbatim |
| **5** Chaining graph (conflicts + coverage) | Prototype complete; broad + genuine tiers; null + positive control fire | **Quantified** (transitivity = *evidence for*, not proof) | broad: 79/83 touched, 1 component (untouched `{1,27,28,76}`); genuine: 28/83, 5 comps `[14,4,4,4,2]`; ~900× null on conflicts | [`specs/thread-1b-5-spec.md`](specs/thread-1b-5-spec.md) → `src/chaining_graph.rs` | **Landed** (248fb32): Rust v1 is window-11 + shared-pivot only (not comparable to the L=10..15 survey at left) — broad 2614 conflicts, 83/83 in 1 comp; core-supported 83/83 (a provenance filter, not the genuine tier); positive control real 46 > null-max 2 |
| **2** AGL stress-test (the "soft link") | Prototype complete; stronger result than expected — *rigorous* exclusion | **Flagged-with-a-hole in the wiki, then killed by us** — wiki exclusion overstated; varying-shared-run argument is the rigorous kill | `AGL(1,83)` (both `C83:C82` & `C83:C41`) excluded exhaustively: shared run after a differing start must be constant; eyes' runs vary (20/24, 18/20). 0 violations / 40000; 0/2M forward sims | [`specs/thread-2-spec.md`](specs/thread-2-spec.md) → `src/agl_gak.rs` (+ `AglGakKey` in `ciphers.rs`) | **Landed** (a3413e7): both variants rigorously excluded, exhaustively not statistically — fixed≥2 = 0/6724 (`C82`) and 0/3362 (`C41`), agreement violations 0/40000, forward sims 0/2M; verdict gates on the all-nine `(66,5)` prefix; report records the wiki *over-conceded* |
| **3** Perfect-isomorphism / allomorph scan | Prototype complete; classifier regression-hardened against 2 over-extension traps | **Supports (does not prove) perfect iso → keeps GAK family viable** | **0** robust internal violations at strong bar (null also 0); 1 loose-bar candidate (Stutter east4@65/west4@67) within null (p≈0.049); positive control `A.B.CB.AC` fires p<5e-4 | [`specs/thread-3-spec.md`](specs/thread-3-spec.md) → `src/perfect_isomorphism.rs` | **Landed** (47f0c51): 0 robust strong-bar internal violations over the full ≥3-repeat tier (matched null mean 0, max 0; add-one p 1.0) → supports perfect iso; 16 safe-isomorph extents exported; both positive controls + 3A/3B/3C fire; review P0s (matched-null population, POST_MIN guard) fixed |
| **4** GAK attack prototype (the prize) | **Complete** — all six units landed; synthetic positive controls + measured tractability bound + honest eyes negative | Targets the wiki's stated open problem (no known GAK attack); standing eyes claim unchanged | Step 0 `GakKey`; GCTAK gate passes (synthetic, rate-beats-null, incl. dihedral); real-GAK deck = partial recovery bounded by ~0.8 measured hidden-state obstruction; idea-3 marginalization recovers several-fold more (≈5.9x@n=5), breaks as `(n-1)!` grows; eyes Step 3 = no surviving candidate (held-out score 0, p=1.0) | [`specs/thread-4-spec.md`](specs/thread-4-spec.md) → `ciphers::GakKey` + `src/gak_attack.rs` | **Done** (e7b88f8, d3b30fd, aaa9e9a, 1d928a2, 8aa7c53, 44d4ec4 — see §6). Decode remains blocked on missing key material, method disclosure, or known plaintext |
| **6** Binary / game-data re-exam | `data.wak` unpacked (14745 files) & scanned | **Closed — confirmed dead end** | **0** hits for eye-message digit strings, base-7/base-5 transform, or 83-entry table in shipped data; consistent with hardcoded `u32` constants in `noita.exe` | (n/a — no module) | Do not reopen; game data re-enters only as post-hoc verification for a Thread-4 candidate |

---

## (2) Headline empirical results

All from scratchpad Python prototypes (Monte-Carlo numbers are seeded estimates,
not exact tail probabilities). Each negative carries a matched within-message
multiset-shuffle null; each positive control fired on known signal.

### Dihedral conflict catalogue (Thread 1B/5)
- **Genuine (Tier A, provably-same-plaintext isomorphs):** order-83-forcing contexts
  = 6; true (non-permutation) conflicts = 0; shared-pivot order-83 +
  commutativity-conflict witness triangles = 1 — and it is the wiki's own cited
  triple. 0 / 131 shared-pivot candidate conflicts are typo-robust (independent
  witnesses: 0; fragile: all).
- **Broad (Tier B, any ≥2 gap-isomorphic occurrences — upper bound, conflates genuine
  with coincidental gap-isomorphs):** contexts = 492; order-83-forcing = 392; raw
  order-83+conflict triples = 17 124; distinct context-pairs with a conflict =
  5 242; distinct occurrence-SETs (independence proxy) = 4 988; greedy
  mutually-disjoint witnesses = 32.
- **vs null (30 within-message shuffles):** real exceeds null on *every* metric;
  p = 1/31 ≈ 0.032 is the resolution floor (no shuffle reached real on any metric);
  ~900× the null conflict count.

### Transitivity coverage (Thread 5) vs null
- **Broad:** symbols-touched = 79/83 (95%); largest-component = 79;
  #components = 1 (untouched `{1,27,28,76}`).
- **Genuine:** symbols-touched = 28/83; largest-component = 14;
  #components = 5 (sizes `[14,4,4,4,2]`).
- **Null mean:** touched 52.3, largest-component 28.7, #components 9.1 — real has a
  single giant component where the null fragments into ~9.
- *Honest read:* "nearly all symbols in one component" is well-supported on the broad
  graph, much weaker on the genuine-only graph. Coverage is evidence for, not
  proof of, a transitive action.

### Perfect-iso internal-violation count (Thread 3) vs null
- **Strong bar (≥3-repeat seed):** real internal violations = 0; matched null
  (3000 iters) = 0 (P≥1 = 0).
- **Loose bar (≥2-repeat):** real = 1 (east4@65 vs west4@67, in the wiki's Stutter
  Section); matched null P(≥1) = 0.049 (mean 0.053, max 3) — within chance
  collision, classified benign. Net: zero robust internal violations survive.
- Positive control: `A.B.CB.AC` (6 occ) and `ABC.DC.AD.B` (4 occ) both fire at
  empirical p ≈ 1/2001 (add-one floor); null never reached ≥2 in 2000 shuffles.
  *(We recompute under our own matched null rather than quoting the wiki's
  ~3×10⁻²⁰ figure.)*

### AGL feasibility verdict (Thread 2)
- **AGL(1,83)-GAK rigorously excluded — exhaustively, not statistically** — for both
  `C83:C82` and `C83:C41`. Mechanism: after a differing immediately-preceding symbol
  the inter-message discrepancy `D` is a fixed non-identity affine map fixing ≤1
  point ⇒ any shared run must be a constant stutter; the eyes' shared runs
  vary (group A east1/west1/east2: 20/24 distinct over 24 cols; group B
  east4/west4/east5: 18/20). Confirmations: 0 differing-`D` fix ≥2 points (all 6724 /
  3362); 0 / 2,000,000 forward sims produced a varying shared run ≥2; positive control
  (a constant length-6 shared run) fires. The tightest clincher needs no long run —
  cols 1–2 = `(66,5)`, a length-2 *varying* run shared by all nine after nine
  *distinct* first symbols, is already AGL-impossible. Candidate set after Thread 2:
  `{A₈₃, S₈₃}`. The varying-run fixed-point lemma excludes both affine variants
  (`C₈₃:C₈₂` and `C₈₃:C₄₁`) identically — an independent cross-model re-run reproduced the enumerations
  (`0/6724` and `0/3362` discrepancies fix ≥2 points). All affine exclusions are
  conditional on the shared-plaintext interpretation of the shared sections + a single
  global cipher configuration (the same assumption the whole transitivity analysis
  rests on); rejecting that assumption reopens the affine options *and* weakens the
  6-group restriction itself, not `C₈₃:C₄₁` alone.

### `data.wak` scan verdict (Thread 6)
- **Lead closed — confirmed dead end.** Archive unpacked (42 MB, format reverse-
  engineered, 14 745 files extracted, integrity-checked). 0 hits for eye-message
  digit strings (incl. the shared prefix and a message-0-unique run), 0 base-7/
  base-5 transform, 0 83-entry table, 0 eye-message integer content. All
  `eye`-named assets are unrelated world-gen/gameplay. Consistent with the prior
  Ghidra finding (messages are hardcoded `u32` constants in `FUN_0061ed60`); the
  storage layer discloses no key, method, or plaintext layer.

### 6-group proof confidence (Thread 1A)
- **High**, with precise scope. Solvable count = 4 = τ(82) is elementary/certain.
  Non-solvable count = 2 (`A₈₃`,`S₈₃`) rests on the published classification of
  2-transitive groups of prime degree (Burnside + Feit; Dixon–Mortimer §7.7) — the
  single CFSG-dependent external fact, not reproved but arithmetic side-conditions
  self-checked (83 prime; not a Mathieu degree; not a projective degree
  `(qᵈ−1)/(q−1)` — searched exhaustively). Method validated on `p∈{5,7,11,23}` →
  `5,7,8,7`. Count cross-check: direct GAP `NrTransitiveGroups(83)` is unavailable
  (`fail`, per maintainer-run GAP) [Lymm], but at prime degree transitive implies
  primitive and the OEIS A000019 b-file fetched 2026-07-06 gives `a(83)=6`
  [verified]. One sharpening: the hidden-subgroup sizes
  are `{1,2,41,82, 82!/2, 82!}` — the wiki's "`…`" hides that the `A₈₃/S₈₃` survivors
  are the *maximal/hardest* cases, not small continuations.

---

## (3) Wiki-claim audit ledger

| Wiki page (under github.com/Lymm37/eye-messages/wiki) | Verdict | Note |
| --- | --- | --- |
| `The-Transitivity-Restriction-(6-Groups-for-83).md` ("exactly 6 groups") | **Audited** | Re-derived two ways; conditional on published 2-transitive classification. |
| `Proof-that-the-eyes-cannot-be-a-dihedral-GAK-cipher.md` | **Flagged-with-a-hole** | Logic sound, but the contradiction is single-witness-fragile. **Hole 1 (wiki-acknowledged):** *"a single strategic typo at col6 (or col9) does dissolve this triple's contradiction"* — the within-triple second conflict reuses col6/col9 and does not remove it. **Hole 2 (not wiki-flagged):** *"the commutativity-conflict half lives entirely in the over-extension … on the high-confidence repeated 9-core the order-83 forcing fires but no conflict appears."* Exclusion holds conditional on A1+A5 for that triple. |
| `Proof-that-GAK-is-transitive.md` (right-coset action) | **Audited** | This is the correct support for "cycle lengths divide element order," not the semidirect-product left-action proof (a trap the verification note flags). |
| `Proof-that-GAK-has-perfect-isomorphism.md` | **Audited** | Containment proof verified directly; makes one clean internal violation a whole-family falsifier. |
| `Isomorphic-Cipher-Hierarchy.md` (`CTAK<GCTAK<GAK<XGAK ≤ PerfIso`) | **Audited** | The `≤` (open upper edge) is load-bearing and preserved; writing `<` there would overclaim. |
| `Affine-General-Linear-Group-(AGL).md` / `Message-Starts.md` / `Shared-Sections.md` (AGL exclusion) | **Flagged-with-a-hole, then strengthened** | Wiki framed resync as rare/pathological "fine-tuning"; per-pair it is the generic case (98.78%) with near-free first symbols — *the wiki overstates*. But the verification note then over-conceded: once shared runs must be varying (as the eyes' are), message-starts rigorously exclude AGL. Hole quote: *"Calling it a 'special exception' / pathological 'fine-tuning' undersells it: per pair it is the generic outcome (98.78%)."* |
| `Group-Autokey-(GAK).md` (L/R convention) | **Audited (with correction)** | Output = moved reference point forces the right-mult / left-coset variant; mixing left-mult update with `g.x₀` output is the exact mis-model the thread warns about. |
| `Allomorphs.md` 3A/3B/3C regression checks | **Audited** | All gap patterns reproduce byte-for-byte; 3C corruption theory carried explicitly as a hypothesis that bounds, not locates. |
| `Smallest-GAK-Examples-…Small-Hidden-Subgroups.md` | **Tentative (empty on wiki)** | Currently `TBD`/empty; do not cite numbers from it. |
| Deck-cipher small-support / ≤4-swaps-per-letter prior (`Deck-Cipher.md`) | **Tentative** | Allomorph-derived search heuristic; a prior to validate, not a hard constraint. Must stay labelled in any Thread-4 output. |
| `Chaining-Conflict-Rates.md` ("conflicts are the norm") | **Tentative / partially-supported** | Matched by the broad chaining graph's abundance, but most broad conflicts ride coincidental gap-isomorphs; typo-robust same-plaintext conflicts = 0–1, not "a dozen independent." |
| `Chaining-Conflicts.md` ("reflections give 2 fixed points") | **Flagged (minor, off-path)** | For odd `n=83` the model gives 1 fixed point; descriptive inaccuracy on a different page, irrelevant to the proof. |

**Still-open / not-yet-tested-this-wave:** whether perfect isomorphism actually holds
(unprovable without plaintext — measured as evidence only). *(Correction:
`C₈₃:C₄₁` is excluded by the same varying-run fixed-point lemma as `AGL(1,83)` —
see §2 Thread-2 verdict; the earlier "not yet
excluded" was stale.)* **Resolved in wave 2:** "whether a GAK attack exists at all"
(Thread 4) is now answered as far as this workbench can — a synthetic GCTAK gate
*passes*, a real-GAK deck attack recovers *partial* visible-coset action up to a
measured hidden-state bound, and the eyes Step 3 yields no surviving candidate
(§6). The decode remains blocked on missing key material, method disclosure, or
known plaintext.

---

## (4) Recommended implementation order for the gated Rust modules

All four implementation specs are frozen and ready to land under `-D warnings` with
`make verify` green (four-file wiring; matched null +
positive control per module; cite the exact wiki page in rustdoc + report).

1. **`src/chaining_graph.rs`** — [`specs/thread-1b-5-spec.md`](specs/thread-1b-5-spec.md).
   Build first: it owns the shared chain-link primitive + conflict catalogue +
   coverage that Threads 1B and 4 both consume. (Hard dependency for Thread 4.)
2. **`src/transitivity.rs`** — [`specs/thread-1b-5-spec.md`](specs/thread-1b-5-spec.md).
   Consumes the chain-link primitive; encodes the 6-group set and emits the
   `DihedralExcluded` verdict, with hole 1 + hole 2 carried verbatim in the report.
3. **`src/perfect_isomorphism.rs`** — [`specs/thread-3-spec.md`](specs/thread-3-spec.md).
   Parallelizable. Emits the safe-isomorph extent list (16 spans) that Threads
   1B/5/4 need to avoid chaining across allomorphic boundaries.
4. **`src/agl_gak.rs`** (+ `AglGakKey` in `ciphers.rs`) —
   [`specs/thread-2-spec.md`](specs/thread-2-spec.md). Parallelizable. Encodes the
   rigorous varying-shared-run exclusion; report records that the wiki *over-conceded*.
5. **`ciphers::GakKey` + `src/gak_attack.rs`** —
   [`specs/thread-4-spec.md`](specs/thread-4-spec.md). Last, and only after 1–3
   land (it consumes `chaining_graph` and Thread 3's safe isomorphs).

### Thread 4 spike — GO / NO-GO

Verdict: GO for the gated, time-boxed spike — with the spec's milestones treated
as hard gates, not aspirations. The wave-1 results clear the precondition the brief
sets ("staffed only after Threads 1/3/5 confirm the family"): Thread 3 keeps the GAK
family viable (0 robust internal violations), Thread 1A fixes the 6-group target,
Thread 2 prunes AGL so the spike aims at the right survivors (`A₈₃/S₈₃`), and Thread
5 supplies the chaining graph it depends on. Gates, in order:
- **Step 0 (week-1):** general `S_n` GAK generator round-trips exactly + reproduces
  perfect isomorphs. If shaky → stop.
- **Step 1 (decisive gate):** GCTAK solved end-to-end as a positive control.
  No GCTAK solve → no GAK attempt.
- **Step 2/3:** partial small-`n` `S_n` recovery is already the publishable win;
  pointing at the eyes (Step 3) is a stretch whose most plausible honest outcome is
  *no surviving candidate*. **The trap to avoid:** any eye "solution" without
  synthetic ground truth and a held-out check is almost certainly coincidence and
  must not be reported as a decode. *(Caveat: the small-support ≤4-swap prior is
  tentative — a toggleable search heuristic to validate, never a silent dependency.)*

---

## (5) Cross-model verification

Cross-model verification: Done. Four focused adversarial passes by a
different model family, re-running the scratchpad Python where possible.

- **AGL exclusion — corroborated.** The cross-model re-run reproduced the enumerations (`0/6724`, `0/3362`,
  `0/2M` sims) and confirmed both variants excluded; flagged the now-fixed stale
  `C₈₃:C₄₁` line. `[AGREE]×4`.
- **Dihedral exclusion — corroborated at the time; superseded by the AGL-subsumption
  upgrade.** An independent D₁₆₆ model (0 divide-order violations) re-derived the
  exact column provenance (`Q->)` is col-9 over-extension only). At the time, net
  `[CONCERN]`: conditional, fragile to one mis-transcription — reported at medium
  confidence, not settled fact. **Update (2026-07-06):** within the point-stabilizer
  GAK model, D₁₆₆-GAK is now excluded as a special case of the exhaustive AGL sweep,
  inheriting the same conditions (one global configuration, the `(66,5)`-prefix gate,
  T02 hardening). This single-witness argument survives only as corroboration; it
  alone remains medium-confidence/fragile.
- **6-group count — corroborated, high.** Brute-checked the projective equation;
  OEIS A000019 `a(83)=6` closes the count cross-check [verified 2026-07-06].
  The CFSG-conditional wording remains; the direct GAP transitive-groups route is
  unavailable (`fail`) [Lymm].
- **Perfect-iso — logic corroborated; artifact needs hygiene.** Classifier correctly
  keys on gap pattern `[AGREE]`; but `[CONCERN]` on `POST_MIN` reproducibility (default
  5 monkeypatched to 8) and stale `classify_v2` import in the regression script. Core
  conclusion (0 robust internal violations) stands; fix `POST_MIN` + regressions when
  hardening `perfect_isomorphism.rs`.

No cross-model verdict overturned a wave-1 conclusion; two were sharpened (dihedral →
medium-confidence/conditional at the time, later upgraded 2026-07-06 to
excluded-by-subsumption within-model, with the single-witness argument retained only
as corroboration at medium confidence; perfect-iso artifact → hygiene fixes required)
and one stale contradiction (`C₈₃:C₄₁`) was corrected. The claim ceiling is unchanged.

---

## (6) Wave-2 landings — the Rust modules + the Thread-4 GAK-attack arc

Wave 2 moved the frozen specs into the build gate. Every module below is landed
under `-D warnings` with `make verify` green, is mapping-independent (ciphertext
symbol equality + group structure only), and carries a matched within-message shuffle
null plus a positive control that fires on known signal. The prose companion is
[`notes/wave-2-summary.md`](notes/wave-2-summary.md).

### Foundational structural modules (Threads 1B, 2, 3, 5)

| Commit | Module(s) | Outcome (one line) |
| --- | --- | --- |
| `248fb32` | `src/chaining_graph.rs` (Thread 5) + `src/transitivity.rs` (Thread 1B) | Shared chain-link primitive + conflict catalogue + connected-component coverage (broad + core-supported tiers) with a non-commutative GAK-stream positive control (real 46 > null max 2); `D₁₆₆` single-witness corroboration retained but no longer load-bearing after the AGL subsumption audit, hole 1/2 + A1–A5 + claim ceiling printed verbatim, exactly one pinned witness (`core_only=0`). |
| `47f0c51` | `src/perfect_isomorphism.rs` (Thread 3) | Perfect isomorphism supported (does not prove): 0 robust strong-bar internal violations over the full ≥3-repeat tier (matched null mean 0, max 0; add-one p 1.0); 16 safe-isomorph extents exported for Threads 1B/5/4; positive controls + 3A/3B/3C fire. Two review P0s (matched-null population, POST_MIN far-run guard) fixed. |
| `a3413e7` | `src/agl_gak.rs` + `AglGakKey` in `ciphers.rs` (Thread 2) | `AGL(1,83)`-GAK exhaustively excluded for both `C83:C82` and `C83:C41`: differing-discrepancy elements fixing ≥2 points = 0/6724 and 0/3362; agreement violations 0/40000; forward varying-shared-run sims 0/2,000,000; verdict gates on the all-nine `(66,5)` prefix. Report records the wiki *over-conceded*. |
| `a31bc3a` | chore/review-fixups merge | Centralized `median` / `scaled_quantile_index` null helpers; enforced zero-trial guards in library nulls; resolved doc drift. House-keeping only — no scientific claim changed. |

**Candidate transitive group set after these landings:** of the 6 transitive groups on
83 points `{C₈₃, D₁₆₆, C₈₃:C₄₁, AGL(1,83)=C₈₃:C₈₂, A₈₃, S₈₃}` — `C₈₃` is out (commutative,
no non-commuting chaining); both AGL variants exhaustively excluded (Thread 2);
`D₁₆₆` excluded within-model by subsumption in the Full AGL sweep [Lymm,
verified], with the Thread-1B single-witness argument retained only as
corroboration; perfect isomorphism supported (Thread 3, keeps the family viable).
⇒ live candidates `{A₈₃, S₈₃}`. (All affine/dihedral exclusions are conditional on
the shared-plaintext + single-global-config assumption the whole transitivity
analysis rests on; the AGL/`D₁₆₆` subsumption also inherits the point-stabilizer
readout and all-nine `(66,5)` prefix/T02-hardening conditions.)

### Thread 4 — GAK attack (complete; all six units landed)

The wiki's stated open problem ("we need a GAK attack") — a gated, time-boxed
spike. Every unit except the final eyes Step 3 is synthetic only (ground truth
held back; the eyes are not touched). The eyes are touched only at unit 2c.

| Commit | Unit | Outcome (one line) |
| --- | --- | --- |
| `e7b88f8` | Step 0 — `GakKey` | A general parametric-`n` GAK cipher primitive (permutation-group realization, cumulative left-multiplication state, hidden-subgroup coset readout), exact round-trip, GAK→GCTAK reduction cross-check, perfect-isomorph reproduction. No claim about the eyes. |
| `d3b30fd` | Unit 1a — GCTAK decisive gate | The decisive go/no-go solver. Gate passes as a synthetic positive control — rate-beats-null across seeds (≥0.8 real, null recovers 0), including a non-commutative dihedral state group, with no ground-truth leak. Reproduces the wiki's "GCTAK is fully solvable." |
| `aaa9e9a` | Unit 1b — CLI wiring + honesty lock | `gak-attack` subcommand + report (four-file pattern); `tests/gak_attack_cli.rs` locks the claim-ceiling / synthetic-only / tentative / rate-vs-null / exemplars-not-pass-evidence strings so a quiet overclaim trips the gate. |
| `1d928a2` | Unit 2a — real-GAK deck attack | Generalized chaining on a non-trivial hidden subgroup (deck stabilizer `H=S_{n-1}`, `|H|=(n-1)!>1`). Only partial visible-coset action recovery, bounded by a measured ~0.8 hidden-state multi-valuedness obstruction — not a recovered key, not plaintext. The measured bound motivates idea 3. |
| `8aa7c53` | Unit 2b — hidden-state marginalization + small-support prior | Truth-free held-out beam (idea 3) recovers several-fold more of the per-letter marginal than the 2a single-valued core (≈5.9x/3.9x/4.9x/2.8x for n=5..8) and beats its matched null everywhere, breaking cleanly as `|H|=(n-1)!` grows (mean recovered frac 0.407→0.156) — a measured tractability bound. The small-support prior (idea 2) is tentative, fails gracefully, only weakly discriminative, and is off in the headline. |
| `44d4ec4` | Unit 2c — eyes Step 3 (honest negative) | The matured attack on the real corpus behind held-out + Thread-3 gates: No surviving candidate. Gate 1 (held-out isomorphs vs matched null): real hits=0, misses=0, score=0, p=1.0000; material-effect bar is population-relative and fair (eyes bar 1722 < their max-achievable 6888), so the eyes *could* have passed with real signal — held-out positive control fired on synthetic signal. Gate 2 (Thread-3 consistency): 0 robust violations, consistent. Gate 3 (speculative cleartext): correctly not run. No candidate cleartext (English or Finnish) arose. Logged to `candidates/eyes-seed-657965735f737470-trials-2000-beam-8.md`. |

Transfer caveat [Lymm]. The ≤~4-swaps-per-letter lead presumes proximity to a
shared base permutation whose identity is unknown for the eyes. The practice
`gak-swap-recover` solver conditions on a public base permutation and therefore
does not transfer as-is; any eyes-facing attack must recover or marginalize over
the base permutation rather than silently assuming it.

Standing conclusion (unchanged by wave 2). The eyes remain unsolved; the decode
remains blocked on missing key material, method disclosure, or known plaintext.
The synthetic GCTAK gate and the synthetic deck / idea-3 recoveries are synthetic
positive results (ground truth
held) and the measured `~0.8` / `(n-1)!` bounds are a tractability contribution to the
community's open problem — none of them is an eye result and none is a decode. The eyes
Step-3 negative is clean and fair (the eyes could have passed; they scored 0). Claim
ceiling holds verbatim: *deterministic, engine-generated, strikingly structured data of
unknown meaning; unsolved; no primary developer source confirms recoverable plaintext.*

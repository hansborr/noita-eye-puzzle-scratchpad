# Thread 3 — Perfect-isomorphism / allomorph scan (empirical)

**Status:** prototype complete. Mapping-independent (symbol equality only). Throwaway
Python lives in the session scratchpad; this note records the results and method.

Honesty anchor (held throughout). Perfect isomorphism is not provable without
the plaintext (Perfect-Isomorphism.md; Isomorphs-(Gap-Patterns).md). This work
measures *evidence for or against* it and constrains *family selection* only. It is
not a decode and produces no symbol→meaning mapping. The strongest defensible
statement about the eyes remains: deterministic, engine-generated, strikingly
structured data of unknown meaning; unsolved; no primary developer source confirms
recoverable plaintext.

---

## Input and validation

- **Streams:** `scratchpad/streams.json` — nine per-message symbol streams, order
  `standard36-u012-d012`, values `0..82` (83 distinct symbols, contiguous), display
  `char = value + 32`. Stream lengths: east1 99, west1 103, east2 118, west2 102,
  east3 137, west3 124, east4 119, west4 120, east5 114.
- **Cross-check against the wiki's own anchors (all reproduce byte-for-byte):**
  - Allomorphs.md 1–2 shared-section CT lines found in east1@1 / west1@1.
  - Allomorphs.md 7/8/9 CT lines found in east4@35 / west4@35 / east5@35.
  - `streams.json:wiki_validation` main-isomorph instances reproduce gap signature
    `[0,0,0,0,0,3,0,7,4,0,9]` (gap pattern `ABC.DC.AD.B`) at west1@40, west1@70,
    east2@45, east2@80.

The streams operate at the per-symbol level. The wiki's `A.B.CB.AC` (9 chars) is
the *trigram-collapsed* view of the same isomorph; at symbol level it is the 11-symbol
window `ABC.DC.AD.B` (e.g. `OLPJ3P-O3QL`). Both views are reproduced below.

---

## (1) Catalog + significance

Gap patterns enumerated over per-message windows (lengths 8/9/11), grouped by
canonical isomorph signature (repeats relabelled `A,B,C,…`; `.` = unique). A
within-message multiset-shuffle null (each message's symbols permuted, length and
multiset preserved; 2000 iterations) attaches significance.

**Positive control fires (and is overwhelmingly significant under our own null):**

| pattern (window) | repeats | occurrences | messages | matched-null max-occ (2000 it.) | empirical p (add-one) |
|---|---|---|---|---|---|
| `A.B.CB.AC` (w9) | 3 | **6** | east1, west1, east2 | 1 | **≈ 1/2001 (add-one floor)** |
| `ABC.DC.AD.B` (w11) | 4 | **4** | west1, east2 | 1 | **≈ 1/2001 (add-one floor)** |

The null never reached ≥2 occurrences of any matching-profile pattern in the 2000
shuffles (max = 1), so zero shuffles met-or-exceeded the observed count and the add-one
estimator pins at its resolution floor `(0+1)/(2000+1) = 1/2001 ≈ 4.9975e-4`. (Quoting a
strict "< 5e-4" would read as sub-floor resolution this null cannot deliver; the honest
statement is "at the add-one floor".) This recomputes the wiki's intuition under our matched null rather
than quoting the wiki's ~3×10⁻²⁰ figure as a finding. A correct detector must fire
on `A.B.CB.AC`; it does. Weaker (2-repeat) patterns are labelled coincidental-prone by
the same null (e.g. `A.B..B.A`, see regression below).

## (2)–(3) Maximal extension + break localization + classification

Each strong seed's occurrences are extended pairwise outward (left toward message
start, right toward message end). The first column where the in-window repeat structure
diverges is the break. Each break is classified:

- **boundary allomorph (benign):** shared plaintext ended; different plaintext follows.
  Default per the conservatism rule.
- **internal-violation candidate:** a 1–2 column desync island flanked on both
  sides by continuing isomorphic agreement, with a back-reference spanning the island
  identically in both occurrences (the negation of the perfect-iso definition).

The classifier was regression-hardened against false positives. Two over-extension
traps were found and fixed during development:
1. one occurrence's own isomorph extending further than the other's → boundary, not a
   violation (a "cross-break link" present on only one side is not two-sided);
2. late re-convergence on different/later shared plaintext faking a violation
   across a multi-symbol differing-plaintext island — this is exactly wiki check 3A.

The final discriminator requires a short island (≤2 cols) and a substantial
re-synced isomorphic far run (`POST_MIN = 8`) carrying a shared cross-island
back-reference. It is validated by a synthetic positive control (a deliberate
single-insertion internal violation → correctly `internal_violation`) and by the wiki
regression checks (3A → correctly `boundary`).

## (4) Headline metric — internal violations vs matched null

Same discriminator run identically on real data and on 3000 within-message shuffles.
Distinct events deduplicated by break column (overlapping seeds pinning one desync
count once).

| seed bar | real internal-violation events | matched null (events) | verdict |
|---|---|---|---|
| **strong (≥3 repeats)** | **0** | 0 in 3000 iters (P≥1 = 0) | **no violations; null also zero** |
| loose (≥2 repeats) | **1** | P(≥1) = **0.049**, mean 0.053, max 3 | within chance-collision null |

The single loose-bar candidate is east4@65 vs west4@67 — squarely in the
Stutter Section (messages 7–8). It (i) rests on a *weak* 2-repeat seed, (ii) sits
in the region the wiki already attributes to benign GAK-expected desync (first-letter
desync / swap-typo; The-Stutter-Section.md, Allomorphs.md), and (iii) is not in
excess of the matched null (add-one p ≈ 0.049 — a single such candidate from
coincidental gap-pattern collision is fully expected). Per the conservatism rule it is
classified benign/boundary. A second candidate surfaced under a looser earlier
threshold (an *intra*-west1 self-pair, breaks at 66/96) but evaporated under the
regression-validated `POST_MIN = 8` rule: it was a short coincidental re-convergence
near west1's end (the 3A failure mode), with the "shared" back-reference resting on
*different* symbols that each merely repeat internally.

Net: zero robust internal violations survive scrutiny.

## (5) Wiki regression checks — all reproduce

- **3A (messages 1–2 shared section, east1/west1):** gap patterns reproduce
  byte-for-byte — msg1 `A..BC.D....AB.......DC...`, msg2 `A..BC.D....AB.......DC..D`
  (25-symbol windows at offset 1). Sole differing position = index 24 (the trailing
  `p`/`=`). Classifier → boundary allomorph. ✓
- **3B (messages 7/8/9, east4/west4/east5):** the strong tail isomorph
  `.AB......B.A` is identical across all three (anchors @35). Message 7 carries the
  `O…O` repeat (anchor-relative positions 10,16,26) that 8/9 lack → allomorphic
  *before* the strong tail; not promoted to an internal violation. ✓ (The full
  `*`-annotated rows use wiki-specific `*` relabeling and so don't match a plain gap
  string verbatim; the load-bearing claims — shared tail + msg7 allomorphy — do.)
- **3C (single-deletion corruption-theory bound):** exclusion row
  `+++++xxxxx?????x++++++++++++` reproduced verbatim, carried explicitly as a
  hypothesis conditional on the single-deletion assumption that *bounds* where a
  difference must lie — never a pinpoint. ✓
- **Cross-cut:** `A.B..B.A` reproduces with 7 occurrences (6 inside the main
  isomorph at the cited offsets, the 7th at east3@101 — exactly the wiki's count and
  placement), confirming the wiki's "false-positive-prone 2-repeat" example.

## (6) Safe-isomorph extent list

Written to `scratchpad/safe_isomorphs.json` (16 spans). Each entry is a maximal
isomorphic span anchored on a strong (≥3-repeat) seed, extended left+right to the first
divergence, using the conservative (tightest) right boundary over all partners so
Threads 1B/5 never chain across differing plaintext. All 16 lie in the messages 1–3
main-isomorph cluster (east1/west1/east2); `boundary_break_index` marks the exclusive
end (first divergent column).

---

## Verdict

The evidence supports (does not prove) perfect isomorphism, and therefore keeps
the GAK family viable. Under a regression-validated, null-arbitrated discriminator,
every break across the strong isomorphs is a boundary allomorph; zero internal
perfect-isomorphism violations survive scrutiny at the strong bar (and the matched
null is also zero there). The only internal-violation candidate is a single weak-seed
desync in the wiki-documented Stutter Section that does not exceed the matched
chance-collision null. Because a single clean internal violation would falsify the
whole CTAK..XGAK family by contrapositive (Proof-that-GAK-has-perfect-isomorphism.md),
its absence here is positive support for staying inside the perfectly-isomorphic
region. This is *family-selection* evidence only: it neither proves perfect
isomorphism (impossible without plaintext) nor implies "the eyes are GAK" — it keeps
GAK in the running and hands Threads 1B/5 a vetted safe-isomorph map.

Caveats. (a) Perfect isomorphism is unprovable without plaintext. (b) The
boundary-vs-internal call carries judgment; the discriminator is conservative by
construction and was hardened against two real over-extension traps, but a different
threshold could surface or dismiss the borderline Stutter candidate — which is why the
matched null, not the absolute count, is the arbiter, and by that test the
candidate is unremarkable. (c) Numbers are Monte-Carlo (seeded Python `random`;
2000–3000 iterations); they are stable in the regimes reported but are estimates, not
exact tail probabilities.

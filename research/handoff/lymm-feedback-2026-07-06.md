# Lymm review feedback — corrections to land (2026-07-06)

Lymm (author of the community GAK framework and the practice puzzles) reviewed
`research/findings/eyes-structural-summary.md` and the repo generally; the repo
owner relayed the feedback on 2026-07-06. This doc is (a) the durable record of
that review and (b) the edit spec for the cleanup. Each item states the
correction, the provenance of any new fact, and the exact files to touch.

Provenance legend: **[Lymm]** = maintainer statement relayed 2026-07-06, not
independently re-derived here; **[verified]** = independently checked in this
repo on 2026-07-06 (method noted inline).

---

## 1. The digit→direction mapping is binary-verifiable, not "unverifiable"

**[Lymm]** The eye images are hardcoded in the function that draws the eyes and
can be extracted directly from the shipped binary; the directions visible in
game match the base-5 digit values extracted from the raw hex. A different
digit↔direction labeling would only induce a fixed substitution on the
ciphertext — cryptanalytically immaterial (which the repo already says).

The current docs treat the mapping as image-only/unverifiable, and agents keep
getting stuck on it.

Edits:
- `research/03-confirmed-vs-speculation.md:104-108` — rewrite the entry: the
  direction-per-digit mapping is **verifiable from the shipped binary** (eye
  sprites hardcoded in the drawing function; maintainer-confirmed 2026-07-06,
  not yet independently re-extracted here — optional Ghidra follow-up in the
  `…-ghidra` worktree). Keep the immateriality note. Remove the
  "image-only / unverifiable" verdict.
- `research/03-confirmed-vs-speculation.md:179` — remove "the exact
  direction-per-digit mapping" from the **Not established** list (or move it to
  a "verifiable-on-demand, immaterial" note).
- `AGENTS.md` design note ("Do not encode unverifiable pixel-direction
  names…") — keep the rule (digit labels stay conventional), but fix the
  rationale: the inventory/mapping is binary-verifiable; the rule exists
  because the labeling is a convention the statistics never depend on, not
  because it is unknowable.

## 2. Reading-order "circularity" framing overstates the risk

**[Lymm]** Contiguity was not a pre-registered validation criterion: it emerged
while testing reading orders and stood out as significant. The order is
*retained* because of downstream, independently significant structure
(isomorphs, forbidden-successor). Equivalent-up-to-substitution reading orders
(83 symbols on a non-contiguous range) are immaterial — every statistic the
workbench computes is substitution-invariant or conditioned on the fixed digit
sequence.

Edits (reword, don't delete the look-elsewhere caveat):
- `research/03-confirmed-vs-speculation.md:161` — retitle away from "the
  central risk" / circular-reasoning framing. Accurate statement: the
  contiguity p-value carries a post-hoc selection effect (quantify as
  look-elsewhere, as now), but the community did not *choose* the order by a
  contiguity criterion; retention rests on downstream isomorph structure.
  State explicitly that substitution-equivalent alternative orders change no
  computed statistic.
- `research/02-theories-and-encoding.md:26` — same reframe.
- `research/01-overview.md:92` — keep "cryptanalysis is order-conditional"
  (true), drop any implication of community circular reasoning.

## 3. Dihedral vs AGL verdict scopes — make them consistent

**[Lymm]** (a) D₁₆₆ is a subgroup of AGL(1,83) (all solvable transitive groups
of prime degree p lie in AGL(1,p), Galois), so an exclusion of the AGL-GAK
family within a model also excludes dihedral-GAK within that model. (b) The
summary's relative confidences read backwards: the dihedral proof covered
arbitrary substitution on top; the AGL proof did not, yet AGL is labeled
"exhaustively excluded" while D₁₆₆ stays "conditional".

**PENDING VERIFICATION** — a proof-scope audit of `agl-exclusion.md`,
`thread-2-empirical.md`, `thread-1b-5-empirical.md` is running; fill in the
resolved scope matrix here before implementing. Planned edit shape:
- Add a short **scope matrix** to `research/findings/eyes-structural-summary.md`
  (§ candidate family + § AGL): for each exclusion — model covered
  (point-stabilizer GAK), key-space enumerated, substitution-on-top covered
  or not, and the subgroup-lattice fact D₁₆₆ ≤ AGL(1,83).
- If the exhaustive AGL enumeration subsumes dihedral configurations
  within-model, upgrade the D₁₆₆ verdict to match within that model (its own
  single-witness argument then only carries the substitution-hardened part).
- `research/frontier.md:21` — "AGL is tentatively ruled out" is stale against
  `frontier.md:75-78` (our exhaustive exclusion); fix in place.
- Mirror the clarified labels in `research/gak-threads/PROGRESS.md:237-241`.

## 4. Six-transitive-groups count: close the "GAP cross-check pending" gap

**[Lymm]** GAP's `NrTransitiveGroups(83)` returns `fail` — the transitive-groups
library does not reach degree 83 (and OEIS A002106 stops short). The
*primitive*-groups route does reach it: transitive ⇒ primitive at prime degree
(blocks divide the degree), and the primitive count at degree 83 is 6.

**[verified]** OEIS A000019 b-file fetched 2026-07-06: a(83) = 6 (a(82)=10,
a(81)=155). This machine-independent count matches the audited theorem
application {C₈₃, D₁₆₆, C₈₃:C₄₁, AGL(1,83), A₈₃, S₈₃}.

Edits — replace "GAP `NrTransitiveGroups(83)` cross-check not done / optional
residual gap" with the closed cross-check (transitive=primitive at prime
degree + OEIS A000019 a(83)=6 [verified 2026-07-06]; `NrTransitiveGroups(83)`
itself returns `fail` per maintainer-run GAP, so that route is unavailable, and
`NrPrimitiveGroups(83)` is the machine check if ever wanted) in:
- `research/gak-threads/notes/thread-1a-transitivity-proof.md:32` and `:272-274`
- `research/gak-threads/PROGRESS.md:25`
- `research/handoff/README.md:117`
- `research/findings/eyes-structural-summary.md:38-42`

## 5. Isomorph leak-ceiling wording — say what an isomorph observation is

**[Lymm]** "The richest aligned isomorph signature supplies 26 occurrences"
reads as if isomorph chains directly constrain the plaintext permutations;
they do not. (Lymm agrees with the information-theoretic *conclusion* — not
enough ciphertext to pin near-arbitrary S₈₃ assignments.)

Edits:
- `research/findings/eyes-structural-summary.md:134-153` — reword the ceiling
  section: state explicitly what is being counted (repeated-signature
  occurrences usable, under the most generous reading, as constraints on the
  hidden state/key evolution — coset-graph edges — NOT direct observations of
  plaintext→permutation assignments), and that the ceiling is therefore an
  upper bound on the most optimistic leak model, making the "12.8×–36.9×
  short" conclusion conservative. Align wording with
  `research/gak-threads/notes/` G3 leak-ceiling source doc (implementer: read
  it first and reuse its precise definitions).

## 6. Retire the "symbol-to-meaning mapping" framing repo-wide

**[Lymm]** There is no fixed symbol-to-meaning mapping — the cipher is
polyalphabetic. If "mapping" means the plaintext-letter→group-action
assignment, that *is* the key: it is the thing to be recovered and would never
be externally provided (no practice cipher would provide it either — it would
defeat the puzzle).

Reframe: the standing blocker is **key material (the letter→action assignment),
a method/cipher-family disclosure, or known plaintext (a crib)** — not a
"symbol→meaning table". Keep the generic term "external anchor" only where it
means *any verifiable external constraint*; kill "symbol-to-meaning
mapping/anchor" phrasing.

Edits (each instance judged in context by the implementer):
- `research/findings/eyes-structural-summary.md:201, 210-214`
- `research/handoff/T11-external-anchor-hunt.md` — rescope the hunt to
  method/key/known-plaintext disclosures.
- `research/README.md:76`
- `research/05-code-investigations.md:16, 423, 428`
- `research/NEXT-STEPS.md:42, 89`
- `research/threads-eyes.md:90`
- `research/gak-threads/candidates/README.md:20`
- `research/handoff/next-cycle-2026-07-06.md:19, 153, 173`
- `src/attack/gak_attack/eyes/mod.rs:17`, `src/attack/gak_attack/eyes/report.rs:92`
  (doc comments; keep rustdoc clean)
- `research/attack-methodology.md:117, 123` — likely fine as generic "external
  anchor"; adjust only if they say "mapping".

## 7. "~83 internal states" → superseded, not merely disputed

**[Lymm]** The ~83-states figure is old and hopeful (custom-Alberti era).
Current surviving theories (GAK on a near-S₈₃ state group) imply an
S₈₃-scale state space (83! ≈ 10¹²⁴).

Edits — where docs argue "[disputed]/likely circular ≈ alphabet size", add the
supersession: under the surviving family the state space is S₈₃-scale; "~83
states" is historical. Files: `research/01-overview.md:107`,
`research/02-theories-and-encoding.md:59-61`,
`research/03-confirmed-vs-speculation.md:82, 84, 126, 165, 180`,
`research/05-code-investigations.md:287-288` (leave `06-sources.md:153` as-is —
it is a source quotation; annotate only if unclear).

## 8. Base permutation is unknown for the eyes — flag every transfer claim

**[Lymm]** The GAK work has been taking the base permutation as known; for the
real eyes it is not. (In the repo this is true of the *practice-puzzle*
deck-swap solver, where the base permutation is public by construction — but
eyes-facing transfer language must carry the caveat.)

Edits:
- `research/frontier.md:36-39` ("Live tractable lead") — add: the ≤~4
  swaps/letter lead presumes proximity to a *shared base permutation whose
  identity is unknown for the eyes*; the practice-puzzle swap recovery
  (`gak-swap-recover`) conditions on a public base permutation and does not
  transfer as-is — base-permutation recovery is part of any eyes-facing
  attack.
- `research/data/practice-puzzles/deck-swap/SWAP-RECOVERY-METHOD.md` — add the
  same one-line transfer caveat if absent.
- `research/gak-threads/PROGRESS.md` — same, wherever swap-recovery→eyes
  transfer is implied.

## 9. Recurring agent misconceptions — make the corrections prominent

The repo already disputes several claims agents keep regenerating (Pyry-as-dev
is consistently flagged; ~83 states is consistently flagged) — but the
corrections are buried. Add a short **"Recurring misconceptions (do not
regenerate)"** list to `research/attack-methodology.md`:
- "Pyry is a Nolla dev" — unverified; known team Purho/Harjola/Teikari.
- "~83 internal states" — superseded; surviving family implies S₈₃-scale.
- "We need a symbol-to-meaning mapping" — no such fixed mapping exists
  (polyalphabetic); the letter→action assignment IS the key.
- "The digit→direction mapping is unverifiable" — binary-verifiable (item 1).
- "Alternative substitution-equivalent reading orders are a live concern" —
  immaterial to every computed statistic.
- New methodology lesson: scope-match a verdict's stated confidence to what
  its proof actually covers (model, key space, substitution layer) — the
  AGL/dihedral label inversion (item 3) is the case study.

## 10. New handoff: general small-N GAK solver (Lymm's stated priority)

**[Lymm]** "The thing I am the most interested in at this point isn't trying
to attack the eyes, but giving a general method of solving smaller GAK ciphers
that is faster than bruteforce."

Create `research/handoff/gak-general-solver.md`: goal — beat brute force on
small-N GAK instances with **unknown base permutation**, known-plaintext and
ciphertext-only variants; ladder from the existing
`gak-swap-recover --strategy local-search` machinery (which currently
conditions on a public base permutation); self-validation per golden rules
(planted positive control + matched null at every rung). This becomes the
active direction; the eyes "publish-and-close" stance is unchanged.

---

## Implementation notes

- Line numbers above are as of commit `64dbef6`; re-locate by content.
- Every new factual claim carries its provenance tag into the edited docs —
  do not upgrade **[Lymm]** items to independently-verified.
- `research/README.md` dossier table: update the structural-summary row's
  one-paragraph summary where items 3/4/6 change its wording.

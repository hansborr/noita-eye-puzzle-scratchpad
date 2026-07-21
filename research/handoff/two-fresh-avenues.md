# `two` — fresh attack avenues (2026-07-02)

> **SUPERSEDED IN PART (2026-07-04):** an independent agent's crib-assisted
> solve shows the live information is on the **full 12-symbol surface**
> (isomorph column-maps → group closure), not this doc's deck-free 4-class
> coloring surface, and the underlying `C3 × H` direct-product reading is
> superseded (order-96 state group, order-48 observable shadow). Avenues A and
> G stand as scoped honest negatives; the *framing* below does not. Route
> forward: `two-cross-agent-recon.md`.

**Thesis: the campaign measured the wrong problem's difficulty.** Rounds 1–7
proved a chain of negatives about *searching* the 26→4 coloring, but every
difficulty number was measured on **random-coloring plants**. The real coloring
is a *codec artifact* — a deterministic function of the plaintext letter — and
may be simple. If it is, none of the search walls apply: we just **enumerate**
the convention and decode. This is the same move that cracked `one`.

This doc is a dated forward-looking backlog. It supersedes none of the scoped
negatives preserved in `two-pairclass-attack.md`; it reframes what those
negatives *mean* and lists the then-untried levers. Everything here is
**hypothesis** until a controls-first instrument fires. Produced from: a wiki
re-read (`../eye-messages.wiki`), two grounding probes (this session, scratch),
and a two-model design consult (codex `gpt-5.5` xhigh + Gemini-3.1-pro on a
shared brief). All four inputs independently rank **Avenue A first**.

## The reframing (why this is not just "more search")

Two diagnostics from the campaign are load-bearing and *unchanged*:

1. **`two` is NOT decode-limited.** Given the true coloring, oracle decode with
   a word LM recovers ~0.534 (readable text), tie-consistent
   (`two-pairclass-attack.md`, preserved Round 3).
2. **The objective SEPARATES true colorings from found ones** — oracle scores
   sit well above found-coloring scores (§Round 3). A searcher that *reached*
   truth would recognize it.

Every failure since is a **search** failure, not a decode or objective failure:
annealing has no gradient near truth (accuracy 0.730 → recovery 0.221 vs 0.534
at 1.0, §Round 4 ~L1123); left-to-right beam prunes truth at the *unconstrained
string head* at any width (§Round 5b ~L1148); the complete anchor DP explodes
inside the free occ1 span before the tie can bind (§Round 7 ~L1390). **All of
this is the cost of searching a `4^26` space seeded with a random coloring.**

The real coloring is not a random point in `4^26`. It is whatever the C3 rotor's
codec deterministically emits for each letter:

- The 4-class token is **two paired rotor-direction bits** — the *transparent*
  C3 channel (direct-product weakness), **not** the hidden S4 deck. The C3
  factor updates independently of the deck, so each plaintext letter's
  eps-pair is a fixed, deck-free function of the letter: a **fixed per-letter
  coloring**, and for a simple codec a **simple** one.
- **`one`'s lesson, verbatim:** the solve came from replacing the hidden-state
  assumption with a *deterministic convention* (7-bit ASCII + a fixed walk
  rule, zero key search, exact round-trip). The eyes-leads note in
  the current `CODEC-RESULTS.md` synthesis says to try deterministic conventions *before*
  assuming true hidden state.
- **The wiki agrees the real key is structured, not random.** Community
  analysis of the *actual eyes* finds "the permutations are not completely
  random, and there is actually a somewhat simple structure to them ... only a
  few swaps away from ... some shared base permutation"
  (`Deck-Cipher.md`; echoed in `Explanation-of-Progress.md`, `Allomorphs.md`
  bounds it at ~4 swaps/letter). And for **small by-hand puzzles** the wiki
  documents a *canonical deterministic construction*: `p = c⁻¹` — "each
  plaintext letter acts by the same group element that is represented by a
  given ciphertext letter ... the best choice for creating small puzzles that
  are reasonable to solve by hand" (`Group-Ciphertext-Autokey-(GCTAK).md`).
  `two` is exactly a community-made-by-hand practice puzzle, so a deterministic
  mapping is the *expected* case.

### Grounding probes (this session, SCRATCH — model-conditional, not findings)

- **Observed phase-0 class marginals are strongly skewed** `[107,51,143,47]` =
  sorted fractions `[0.411, 0.307, 0.147, 0.135]` — far from the balanced shape
  a random coloring trends toward. A real, under-used constraint. (Reproduces
  the handoff derivation exactly.)
- **Several structured bit-projection colorings fit those marginals** at
  L1 ≈ 0.065–0.09 (best: bits (1,4) of the A=0..25 rank), vs L1 0.437 for a
  balanced partition. *Necessary-condition pass, not proof.*
- **But moment-matching is a WEAK discriminator at N=348.** Scoring structured
  colorings by (marginal + 4×4 class-bigram) L1 against corpus English, the
  best structured candidate lands only at the **5th percentile** of random
  colorings — a good *random* coloring scores better. Both consults reached the
  same conclusion independently (Gemini: ~5.4 obs/trigram-bin; codex: same
  class-n-gram info that already measured power ≈ 0 in Round 1). **Consequence:
  do not rely on moments to *pick* the coloring — rely on decode.** The
  structured family is small enough (~50–200 base colorings) to just decode all
  of them. (Probe scripts: session scratchpad; the capability lands as an
  instrument when built, per the golden rule.)

---

## Avenue A — structured-coloring enumeration + oracle decode  ⭐ BUILD FIRST

> **STATUS (2026-07-03): RUN — scoped honest negative.** Built as
> `pairclass --coloring-family` (two-tier rank/confirm decode, per-stream
> matched-null gates, curated + broad family tiers); both definitive runs
> returned `LowPowerNoExclusion` with the real stream null-typical (curated
> p_emp 0.840, broad p_emp 1.000) while planted truths retain top-3/top-6
> rank 6/6. *These deterministic families produced no candidate* — not a
> family-space exclusion. Full record: `two-post-avenue-a-handoff.md`. Next levers per
> the ranking below: G, then F (seeded from marginal-consistent colorings).

**Idea.** Enumerate deterministic candidate colorings; oracle-decode each with
the Round-3 word LM; gate on English. Bypasses the *entire* search wall (no
`4^26`, no annealing, no left-to-right beam) **iff** truth is structured. Cheap:
~hundreds of decodes, seconds each, no memory risk. Honest either way — a clean
negative excludes *these families*, not "deterministic coloring."

**Candidate families** (union of both consults, priority order):

1. **6-bit / rank code conventions:** rank `A=0` and `A=1`, Caesar offsets
   `(rank+k) mod 26`, reversed alphabet, 5-bit rank + one pad/parity bit in each
   position, split into two octal triplets and take the two exposed high bits.
2. **Binary / Gray projections:** all 2-bit *affine* projections of rank5,
   `Gray(rank)`, bit-reversed rank — take any 2 of the (possibly XOR-combined)
   bits as the class.
3. **ASCII-derived:** upper/lowercase 7-bit ASCII two-bit projections,
   dropped-bit and chunk-boundary variants.
4. **Historical 5-bit codes:** Bacon, Baudot/ITA2 letter codes, Polybius 5×5 /
   6×5 coordinate parity or high-bit projections.
5. **Simple partitions:** rank mod 4, rank blocks, frequency-rank blocks,
   vowel/consonant + subclass.
6. **Keyword-permuted alphabets:** permute rank by a keyword *before* the above
   projections — `PERMUTATION`, `REPRESENTATION`, `DESTINATION` (the `one`
   theme), `NOITA`, `EYE`, `GROUP`, `GAK`, `ROTOR`.

**Expansion per family:** both token phases, reversed stream, bit swap, bit
complement, and all 24 class relabelings (unless the convention fixes labels).

**Discipline (binding).** Controls-first: **structured planted positives must
fire** and **random-coloring / null negatives must not**, before real `two` is
scored. A survivor is a **candidate**, not a decode, until it either
re-encodes exactly (the `one` gold standard — see Avenue E as verifier) or is
checked against the withheld ground truth. If nothing survives, record
"*these deterministic families excluded*," never "deterministic coloring
excluded."

**Vehicle.** The `pairclass` instrument already has the seeded-coloring oracle
path (`SolveInput.seed_coloring`; `--self-test` "oracle 1.000" leg). Add a
`--coloring-family` enumerate-and-oracle-decode mode; tests exercise the same
library fns.

**Risk (both consults).** The coloring could be **stateful** — position- or
deck-dependent — making a static 26→4 map wrong; the pair-letter model is a
*hypothesis*, not a proof (see `two-pairclass-attack.md`). Mitigation: the
fixed-coloring evidence (letter-aligned even-gap anchors, within-pair
independence, period-2 stagger = letter-internal position) supports it, and the
two token phases already cover the period-2 stagger. Test fixed-per-letter
first *because* it is cheap and falsifiable, not because it is certain.

---

## Avenue G — repeated-span pattern-crib scan  ⭐ BUILD SECOND (codex)

> **STATUS (2026-07-04): RUN — scoped honest negative.** Built as
> `pairclass --pattern-crib-scan` (commit `0b05f78`): the phase-0 repeated
> token anchor at positions 116 and 176, length 33, is scanned directly against
> normalized a..z corpus windows by the 26→4 coloring-consistency predicate
> (ASCII letters, plus Finnish `ä/å → a`, `ö → o`). Planted positives fired and
> matched/null negatives stayed quiet on all three committed language files
> (`english-corpus-large.txt`, `english.txt`, `finnish.txt`; each 0/49 Markov
> null candidate-like + 0/1 random negative). Real scans returned **0 surviving
> spans** in all three normalized corpora. Claim ceiling: no normalized a..z
> window in those committed corpora matches this fixed anchor/static-coloring
> model; this does not exclude custom plaintext, an unscanned phrase source,
> another phase, or a stateful codec. This document preserves the full Avenue-G
> record.

**Idea.** Attack the doubly-occurring ~34-letter repeated phrase *directly*,
without dictionary DP or a score-ranked harvest (so it cannot hit the occ1
explosion). For any candidate English span of the right length, require the
**isomorph constraint** against the observed class pattern on the tied span:

- same plaintext letter ⇒ same observed class, and
- different observed classes ⇒ different plaintext letters.

Scan a corpus / phrase list; a surviving span induces a partial coloring that
**pins ~40% of the text's classes** (the phrase spans ~40% under the model).
Cheap, falsifiable, and *independent of the head* — so it complements A and D.
May fail if the plaintext is custom (not corpus phrasing); that is an honest,
informative negative.

**Vehicle.** Reuse `isoscan`'s translate-isomorph machinery over the 4-class
token stream on the anchor span; new CLI subcommand or `pairclass` mode.

---

## Avenue F — soft-coloring EM / forward-backward  (Gemini; principled global)

**Idea.** The round-4 wall was "objective cliffs, no gradient near truth" — a
property of a *hard* discrete coloring. **Relax** it: make the 26→4 coloring a
continuous stochastic matrix, run forward-backward (Baum-Welch / soft Viterbi)
with the LM to get letter posteriors, then update the coloring to maximize
expected likelihood (EM). Continuous ⇒ gradients exist where hard annealing had
none; it is a *global* fit over coloring variables ⇒ no left-to-right
head-pruning. Directly targets **both** documented walls (Round 4 cliff, Round
5b head-prune).

**Effort/risk.** Medium build; classic EM local-optima risk. Seed from Avenue
A's top candidates and from marginal-consistent colorings to give it a basin
near truth. Good third lever if A and G miss.

---

## Avenue D — head-crib / message-start lever  (cheap; CANDIDATES ONLY)

**Idea.** The beam died because the string *head* is unconstrained. Seed it. The
wiki's `Message-Starts.md` finding is a concrete refinement: real messages
begin with a differing index/label char, then **shared plaintext from a
near-identity state** — so the head decodes from the *clean coset readout*,
the easiest place to pin classes if modeled as GAK-from-identity rather than as
an abstract cryptogram. Guess a first word (theme words à la `one`; common
openers) → seed the head coloring → run the existing `pairclass` beam; the
34-letter phrase then cascades once colored (Avenue G's pins compound here).

**Honesty (binding).** Guessed-head cribs are **high overclaim risk**: outputs
are candidates only, and this is *not* a licence to ask the maintainer for the
withheld snippet (standing directive: do not ask). Value is high *if* a real
external crib ever arrives; otherwise medium and overfit-prone.

---

## Avenue B — moment-matching  (DEMOTED: ranker/filter for A only)

Global fit over coloring variables (no left-to-right pathology), but **measured
weak at N=348** (this session's probe + both consults). **Do not** use as
standalone recovery. Use to **rank Avenue A's family** and emit top-K colorings
for oracle decode. If built: score with a Dirichlet-multinomial or bootstrap
covariance χ² (not raw least squares), calibrated on 348-char corpus snippets
*with the anchor topology*; break the 4! relabeling symmetry by canonicalizing
class order by observed marginals, then validate on held-out relabeled moments.

---

## Avenue C — CP-SAT / SAT / ILP  (only the QAP/moment variant)

CDCL / non-chronological backtracking genuinely escapes the head-pruning wall —
**but** full dictionary-segmentation-over-348-tokens is expected to explode like
occ1 in a cleaner suit (occ1 is free dictionary text; complete enumeration
saturates before the tie matters, §Round 7). Pure SAT feasibility yields junk
solutions; optimizing CP reintroduces a score bias unless it proves optimality.
**Acceptable use:** shell out to an external solver (OR-Tools / a SAT binary)
for the **moment-matching / QAP / ILP** coloring-recovery variant only — hard
timeout + memory cap, **no new Rust dependency**. **Not** for full word-lattice
decoding. (Minimal-dependency rule: external binary, not a linked crate.)

---

## Avenue E — model the exact codec / full octal stream  (VERIFIER, later)

Premature as a *first* attack — the 4-class channel is already decodable
(oracle 0.534) and modeling the full stream re-imports the hidden deck. Its real
value is as the **verifier**: once A/D/G yields a coloring + plaintext,
reconstruct the codec and attempt an **exact re-encode round-trip** against the
698-symbol ciphertext — the `one`-style gold standard that turns a candidate
into a *verified decode*. The hidden q/deck channel becomes a consistency check,
not a wall.

---

## Recommended sequence

1. **A** — build the structured-coloring enumerator (`pairclass` mode), run
   controls-first, decode the whole family. Fast, decisive, low risk.
2. **G** — repeated-span pattern-crib scan (isoscan over the 4-class anchor).
   Independent of A; pins ~40% of classes on a hit.
3. If A+G miss: **F** (soft-EM) seeded from A's/marginal-consistent candidates;
   **D** as a cheap candidate generator for the head.
4. **B** as a filter throughout; **C** only for the QAP variant; **E** as the
   final exact-round-trip verifier.
5. **Honest fallback unchanged:** the withheld-snippet external anchor — a
   ~10-letter crib pins classes and the repeated phrase amplifies it across
   ~40% of the text. Do not ask for it; it is the close only after the
   computational levers above are spent.

## Cross-model consult record

- **codex `gpt-5.5` (xhigh):** A > G(new) > B(as filter) > D > C > E. Supplied
  the rich structured-coloring family, Avenue G, the codec-verifier idea, and
  the kill-record wording. Session `019f25a7-d365-7ac0-af4d-a8ae0bb4b614`.
- **Gemini-3.1-pro:** A > D > F(new) > E > B > C. Supplied Avenue F and the A
  "stateful coloring" risk. (Copilot consult.)
- **Wiki (`../eye-messages.wiki`):** structured-not-random key evidence; the
  `p = c⁻¹` hand-puzzle convention; message-start = index-then-shared-plaintext.
- **Both models + probes agree:** A is #1; B is a filter, not a recovery; C is
  QAP-only; E is a verifier.

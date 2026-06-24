# Thread 3 — Perfect-isomorphism / allomorph consistency scan

**Priority:** High — decides whether the GAK *family* is the right place to look.
**Effort:** Medium. **Mapping-independent:** Yes (symbol equality only).
**Game-data/Ghidra helps:** No (content is hardcoded; there is no runtime plaintext
to recover).

**One-line:** The entire GAK program assumes the eyes are **perfectly isomorphic**
(same plaintext ⇒ identical gap pattern, always). The wiki admits it cannot prove
this without the plaintext. We can measure the *evidence for or against* it — and a
clean negative would redirect the whole search away from GAK toward XGAK /
imperfectly-isomorphic ciphers, which the community has *no* candidates for.

## Why this matters

The cipher hierarchy is `CTAK < GCTAK < GAK < XGAK ≤ Perfectly Isomorphic`. GAK
sits inside the **perfectly isomorphic** region. If the eyes are only *imperfectly*
isomorphic, **GAK is the wrong family** and the deck-cipher hypothesis is moot.
The wiki is candid about this:

> We can't prove that the isomorphs in the eyes are perfectly consistent without
> knowing the plaintext, we just know there are a lot of them that have the exact
> same repeat pattern…

We cannot prove perfect isomorphism either — but we *can* quantify how consistent
the observed isomorphs are, and where and how they break. That is a real,
mapping-independent measurement that bears directly on family selection, and it is
exactly the kind of null-backed structural work this repo is built for.

Wiki sources to read first:
- `/home/node/persist/eye-messages.wiki/Perfect-Isomorphism.md`
- `/home/node/persist/eye-messages.wiki/Allomorphs.md` (worked examples to
  reproduce — messages 1–2 shared section, messages 7/8/9 with the `*` extra
  repeat, and the single-deletion "corruption theory" bound)
- `/home/node/persist/eye-messages.wiki/Isomorphs-(Gap-Patterns).md`,
  `Isomorphic-Cipher-Hierarchy.md`, `The-Caboose.md`,
  `The-Funny‐looking-Obstacle.md`, `The-Stutter-Section.md`

## The distinction to measure

When an isomorph stops being isomorphic, there are two qualitatively different
causes:

- **(allomorph at a boundary)** the shared plaintext *ended* — the break sits at a
  plausible word/phrase boundary, with differing plaintext after it. This is fully
  consistent with **perfect** isomorphism. Expected, benign.
- **(internal violation)** the same plaintext continues, but a gap pattern that
  *should* recur is broken by one or two symbols *inside* an otherwise-continuing
  isomorph. This would be a **perfect-isomorphism violation** — evidence the cipher
  is only imperfectly isomorphic, i.e. *not* GAK.

The headline question: **after accounting for boundary allomorphs, are there any
robust internal violations?**

## Method

1. **Catalog isomorphs with significance.** Use `isomorph.rs` (`detect_isomorphs`,
   `PatternSignature`) over the per-message reading streams to enumerate every gap
   pattern and its occurrences; use `isomorph_null.rs` (within-message multiset
   shuffle null) to attach a significance score to each, so weak/coincidental
   patterns are labelled as such. Adopt the wiki's scoring intuition (more internal
   repeats × more occurrences × positional alignment ⇒ higher confidence).

2. **Maximally extend each strong isomorph** and locate the exact break position
   per occurrence — the first index where the gap pattern diverges across the
   aligned occurrences. Use `perseus.rs` shared-run reconstruction and the
   message-start alignment for anchoring.

3. **Classify each break** as *boundary allomorph* vs *internal violation*:
   - Boundary: the divergence is at the trailing edge of a shared run / near a
     message-start desync, consistent with plaintext ending. Cross-check against
     the funny-looking obstacle (messages 1–2), the caboose (messages 1–2 / 2–3
     "infix"), and the stutter section (messages 7–9), all of which the wiki
     attributes to plaintext differences, not cipher imperfection.
   - Internal: the divergence is a single/double symbol surrounded on *both* sides
     by continuing isomorphic agreement. These are the candidates that would
     falsify perfect isomorphism. Scrutinize each: is it really internal, or an
     artifact of over-extending past the true boundary, or a known typo region?

4. **Headline metric.** Report the count of robust internal violations, with a null
   expectation: under perfect isomorphism + plausible word-boundary structure, how
   many internal violations would you expect from chance gap-pattern collisions
   alone? (The wiki's own numbers — e.g. a 2-repeat pattern has ~1% chance per
   opportunity over ~1000 opportunities — give the baseline; build the matched
   null rather than eyeballing.)

5. **Reproduce the wiki's concrete allomorph claims** as regression-style checks:
   the messages-1–2 `A..BC.D....AB.......DC..D` pattern, the messages-7/8/9 `*`
   extra-repeat analysis, and the single-character-deletion bound. Confirming these
   exact gap patterns validates the wiki's data handling and our `isomorph.rs`
   simultaneously.

## Success / failure criteria

- **Supports perfect isomorphism (and thus GAK):** essentially all breaks are
  boundary allomorphs; zero internal violations survive scrutiny (or the count is
  within the chance-collision null). → GAK family stays viable; report the
  strongest defensible statement of support, *without* claiming proof (we still
  don't know the plaintext).
- **Against perfect isomorphism (high value, redirects the field):** one or more
  internal violations are robust to boundary/typo explanations and exceed the null.
  → GAK is *disfavoured*; the search should move to XGAK or imperfectly-isomorphic
  ciphers — for which, per the wiki, there are currently **no good candidates**, so
  this becomes the new frontier and an explicit ask back to the community.

## Pitfalls & honesty notes

- The boundary-vs-internal call is where the judgment lives. Be conservative:
  default a break to "boundary" unless the surrounding two-sided agreement is
  unambiguous, because over-extending an isomorph manufactures fake internal
  violations. Document each internal-violation candidate individually.
- "Corruption theory" (a single deletion/typo explains a difference) is a
  *hypothesis*, not a fact — the wiki uses it to *bound* where a difference must
  be, not to assert there is only one. Carry that nuance.
- This measurement constrains *family selection*; it is not a decode and yields no
  symbol→meaning mapping. Don't let a "perfect isomorphism supported" result be
  read as "the eyes are GAK" — it only keeps GAK in the running.
- Feeds Thread 1 and Thread 4: the maximal-extent / boundary map produced here is
  the safe-isomorph list those threads need so they don't build chains across
  differing plaintext.

## Reuse / build

- Reuse heavily: `isomorph.rs`, `isomorph_null.rs`, `perseus.rs`, `corpus.rs`,
  `analysis.rs` (for null baselines / chi-square if needed).
- New: maximal-extension + break-localization + boundary/internal classifier, and
  the matched internal-violation null.

# Thread 3 — Perfect-isomorphism conceptual verification

Scope of this note. Conceptual verification only. This note (a) checks that the
cipher-hierarchy framing the thread relies on is faithful to the wiki and its
supporting proofs, (b) confirms the boundary-allomorph vs internal-violation
distinction is the correct falsification discriminator and explains *why*, and
(c) restates the wiki's three concrete allomorph claims precisely enough to become
regression checks. The Python isomorph catalog / break classifier is a separate
agent's job; no statistics are computed here, and none are reported as findings.

Mapping-independent. Everything below uses only ciphertext-symbol *equality* and
group structure. No symbol→meaning mapping is invented or assumed.

Honesty anchor. Perfect isomorphism is not provable without the plaintext.
The wiki says so directly (Perfect-Isomorphism.md; Isomorphs-(Gap-Patterns).md). We
can only measure *evidence for or against* it. The strongest defensible statement
about the eyes remains: deterministic, engine-generated, strikingly structured data
of unknown meaning; unsolved; no primary developer source confirms recoverable
plaintext.

---

## (1) Hierarchy: CTAK < GCTAK < GAK < XGAK ≤ Perfectly Isomorphic — verified

### What the wiki actually states

`Isomorphic-Cipher-Hierarchy.md` does not print the single line the task uses
verbatim. It states the relationship as two facts that the task's compact form
merges:

- Main containment chain (line 5):
  `CTAK < GCTAK < GAK < Perfectly Isomorphic < Perfectly Phrase Isomorphic <
  Perfectly Word Isomorphic < Isomorphic`
- Parenthetical (line 7):
  "It's currently unknown whether XGAK covers all perfectly isomorphic ciphers, but
  it's definitely known that **GAK < XGAK ≤ Perfectly Isomorphic**."

`Extended-Group-Autokey-(XGAK).md` (line 7) confirms: "This is the last known cipher
class in the isomorphic cipher hierarchy that is within the perfectly isomorphic
region. It's currently unknown whether or not this covers all perfectly isomorphic
ciphers." XGAK ⊋ GAK example given: the classical progressive cipher (XGAK, not GAK).

**Verdict on the framing:** The thread's compact line
`CTAK < GCTAK < GAK < XGAK ≤ Perfectly Isomorphic` is a faithful merge of these two
wiki statements. One nuance must be preserved and is preserved here:

- The relation to the perfectly-isomorphic boundary is `≤`, not `<`. The `≤` is
  load-bearing: it encodes the open question of whether XGAK exhausts the
  perfectly-isomorphic region. Writing `<` there would overclaim. (Note the thread's
  own one-line summary writes `XGAK ≤ Perfectly Isomorphic` correctly; this note just
  flags that the strict `<` chain in the wiki stops at GAK < Perfectly Isomorphic,
  and XGAK is slotted in via the separately-proven GAK < XGAK ≤ PerfIso.)

### GAK lies inside the perfectly-isomorphic region — verified via proof

`Proof-that-GAK-has-perfect-isomorphism.md` proves the containment directly, not by
assertion. The mechanism (left-multiplication convention):

- State update `g_{i+1} = p(a_i) ∘ g_i`; output `c_i = c(p(a_i) ∘ g_i)`.
- `c` partitions `G` into right cosets of the hidden subgroup `H`, so `c(g1)=c(g2)`
  iff `H g1 = H g2`.
- Perfect isomorphism is defined as: for every context `g ∈ G` and every pair of
  initial states `a, b ∈ G`, `c(ga)=c(a)` iff `c(gb)=c(b)`.
- Proof: `c(ga)=c(a)` ⟹ `Hga=Ha` ⟹ (right-mult by `a⁻¹`) `Hg=H` ⟹ (right-mult by
  `b`) `Hgb=Hb` ⟹ `c(gb)=c(b)`. Symmetric the other direction. QED. Applies to GCTAK
  and CTAK as special cases of GAK (GCTAK = trivial `H`; CTAK = cyclic group).

So CTAK, GCTAK, GAK, and XGAK are all *proven* to be perfectly isomorphic
(Perfect-Isomorphism.md line 12 states exactly this set is "known and proven").

### Therefore a clean perfect-iso violation falsifies the GAK family — verified

This is the logical crux and it holds by contrapositive on the containment:

- Proven: `GAK ⊆ Perfectly-Isomorphic` (and likewise XGAK, GCTAK, CTAK ⊆ PerfIso).
- Contrapositive: if the eyes are not perfectly isomorphic, they are not
  GAK, XGAK, GCTAK, or CTAK — i.e. the entire GAK family is excluded.
- A *single robust internal perfect-iso violation* (definition in §2) is, by
  definition, a witness that the cipher is not perfectly isomorphic. One such witness
  is sufficient to falsify the whole family. This is what makes the scan high-value:
  the GAK program is a universal ("for all states / all contexts") claim, and
  universal claims die to a single clean counterexample.

The non-associativity proof (`Proof-that-non‐associativity-breaks-perfect-
isomorphism.md`) is the sharp boundary on the *other* side: it proves that the
*minimal* algebraic generalization past groups — replacing the group with a
non-associative loop/quasigroup whose plaintext-mapping image fails to associate —
breaks perfect isomorphism. Concretely: with `q1, q2, (q1q2)^λ ∈ Im(p)` and the
composition `F = L_{q1}∘L_{q2}∘L_{(q1q2)^λ}`, `F` fixes `q1q2`; perfect isomorphism
would force `F` to fix *all* of `Q` (fixed-point set is all-or-nothing), which
collapses to `L_{q1}∘L_{q2}=L_{q1q2}`, i.e. associativity — contradicting the
non-associativity assumption. So perfect isomorphism is genuinely *tight* around the
group-based constructions: associativity is essentially what buys it. This matters
for interpreting a violation: a clean internal violation pushes the eyes not just
out of GAK but plausibly out of the whole proven-perfect-iso region, toward XGAK's
*unknown* upper boundary or genuinely imperfectly-isomorphic ciphers — for which the
wiki states there are no good candidates (Isomorphic-Cipher-Hierarchy.md line 21;
thread §"Against perfect isomorphism").

**Caveat preserved:** XGAK's upper edge is `≤`, not `=`. A violation does not, by
itself, tell us we have exhausted the perfectly-isomorphic region — only that we have
left the *proven* part of it (CTAK..XGAK). The honest framing is "GAK family
disfavoured / falsified," not "the eyes are provably imperfectly isomorphic."

---

## (2) Boundary allomorph vs internal violation — correct discriminator — verified

The thread's two-way classification (thread §"The distinction to measure") is exactly
the right discriminator, and the *why* is grounded in the Allomorphs.md definition,
not assumed:

- **Boundary allomorph (benign):** the shared plaintext *ended*. The gap pattern
  diverges at the trailing edge of a shared run; differing plaintext follows.
  Allomorphs.md line 1: allomorphs "mark the boundaries where the shared plaintext
  definitely must end, assuming perfect isomorphism." A trailing break is therefore
  fully consistent with perfect isomorphism — it is the *expected* signature of
  two messages whose shared content ran out. It is not evidence against the GAK
  family; it is evidence *of* the very mechanism (same plaintext ⇒ same gap pattern,
  until the plaintext stops being the same).

  Subtlety to carry (Allomorphs.md line 10): in a deck/GAK cipher the *exact* divergence
  symbol can differ while the plaintext is *still shared* and the text *still
  isomorphic* — "it's possible in deck ciphers to have the same underlying plaintext
  and have the letter be different ... but it will always still be isomorphic if the
  shared plaintext really continues." So a single differing *symbol* is not by itself
  a violation; only a differing *gap pattern* (a broken repeat) is. The true plaintext
  boundary lies somewhere between the last visible shared repeat and the allomorph
  point — the break *bounds* the boundary, it doesn't pinpoint it.

- **Internal violation (would falsify perfect iso):** the same plaintext *continues*,
  yet a gap pattern that *should* recur is broken by one or two symbols inside an
  otherwise-continuing isomorph — with isomorphic agreement continuing on both
  sides of the break. Two-sided continuing agreement is what rules out the benign
  "plaintext ended" explanation: if the plaintext had ended, the agreement would not
  resume after the break. A break flanked on both sides by surviving isomorphism is a
  context `g` for which `c(ga)=c(a)` but `c(gb)≠c(b)` — the exact negation of the
  perfect-isomorphism definition in the GAK proof. That is a genuine witness.

**Why the distinction is the correct discriminator (one-line):** perfect isomorphism
is a statement about *contexts*, not *positions*. A trailing break changes the
*plaintext* (different context content after the boundary) and is silent about the
mechanism; a two-sided-flanked internal break holds the plaintext fixed across the
break and so isolates the *mechanism* — only the latter can contradict the
universal "for all states" property.

**Conservatism rule (carried from thread §Pitfalls, endorsed):** default every break
to "boundary" unless the two-sided continuing agreement is unambiguous. Over-extending
an isomorph past its true boundary manufactures fake internal violations. Each
internal-violation candidate must be examined individually and checked against three
benign explanations the wiki already supplies for desyncs:
  - **The Funny-looking Obstacle** (messages 1–2 / East 1, West 1): alternating
    synced/desynced trigrams from two short ~4-letter words/fragments being swapped,
    with a shared 4-letter segment between. The first misaligned segment *must* be
    different text due to a perfect-isomorphism conflict — i.e. the wiki attributes
    this to a *plaintext* difference, not cipher imperfection.
  - **The Caboose** (messages 2–3 / West 1, East 2): a 2-character infix/affix added
    to a repeated phrase in one message but not the other — again a plaintext
    difference (prefix/suffix/infix/extra word; ambiguous which).
  - **The Stutter Section** (messages 7–9 / East 4, West 4, East 5): short
    single-character desyncs that, in GAK specifically, can arise *naturally* from
    identical plaintext when the message *first letters* differ (they do in the eyes),
    or from swap-typos. So a stutter desync is *expected under GAK*, not a violation.

A candidate internal violation must survive all three of these before it counts.

---

## (3) The wiki's three concrete allomorph claims — restated as regression checks

Message numbering: the corpus (`src/corpus.rs`, `MESSAGES: [Message; 9]`) is 9
messages, region_index 1..5, alternating East/West, ordered
East1, West1, East2, West2, East3, West3, East4, West4, East5. The wiki's "messages
1,2,3" map to East1, West1, East2; "messages 7,8,9" map to East4, West4, East5. All
gap-pattern strings below are quoted verbatim from Allomorphs.md so the catalog
agent can assert character-for-character equality.

### Check 3A — Messages 1–2 shared-section allomorph (Allomorphs.md lines 4–10)

- **Messages:** East1 (message 1) and West1 (message 2), in their shared section.
- **Claim:** the two ciphertext rows are identical symbol-for-symbol through the
  shared section, and the gap pattern is the same up to the final position, where
  message 2 has a repeat that message 1 lacks.
- **Verbatim gap pattern, message 1 (top):**
  `A..BC.D....AB.......DC...`
- **Verbatim gap pattern, message 2 (bottom):**
  `A..BC.D....AB.......DC..D`
- **The break:** final symbol. Message 2's last symbol `=` repeats an earlier `=`
  inside the shared section (→ trailing `D` in the gap pattern); message 1's last
  symbol does not repeat (→ trailing `.`). The single differing gap-pattern position
  is the last one.
- **Classification under §2:** boundary allomorph (trailing edge; benign). The
  divergence is at the very end of the shared run, with no continuing two-sided
  isomorphic agreement after it. Consistent with perfect isomorphism. The plaintext
  difference must occur somewhere between the last shared repeat (`-`) and this final
  `=`/non-`=` position (boundary is *bounded*, not pinpointed — Allomorphs.md line 10).
- **Regression assertion:** the catalog's aligned gap-pattern strings for the
  East1/West1 shared section must equal these two strings exactly, and the classifier
  must label the sole differing position (the last) as a boundary allomorph, not an
  internal violation.

### Check 3B — Messages 7/8/9 `*` extra-repeat (Allomorphs.md lines 12–24)

- **Messages:** East4 (7), West4 (8), East5 (9).
- **Verbatim gap-pattern rows (Allomorphs.md lines 14–20):**
  - msg 7: `A...A.....B.....BC.D....C.BD`
  - msg 8: `.A..*A.........*..BC.D....C.BD`
  - msg 9: `A..*A.........*..BC.D....C.BD`
  (Rows are presented with the interleaved ciphertext lines `VokPV…`, `;G1jq…`,
  `V%QPV…` in the wiki; the catalog should reproduce the gap patterns, the `*`
  annotations included.)
- **Claim 1 (the `*` extra repeat):** messages 8 and 9 contain an extra repeat,
  marked `*`, that message 7 lacks. The shared distance from the `A...A` section to
  the stronger `BC.D....C.BD` isomorph differs between messages, so there must be
  a plaintext difference between them (at minimum a single-character deletion).
- **Claim 2 (msg 7 is allomorphic before the strong isomorph):** message 7 has a
  repeat of `O` with no corresponding repeat in the other messages, so message 7
  is allomorphic in the section *before* the strong `BC.D....C.BD` isomorph. Messages
  8 and 9 are isomorphic here and *plausibly* (tentative) the same plaintext in that
  segment.
- **Claim 3 (the `+`/`?` shared-vs-uncertain map, msgs 7 & 9, line 27):** verbatim
  `+++++???????????++++++++++++` over `VokPVW3^`.OSfk%+OMZdeo9FMiOd` — `+` marks
  positions known same-plaintext, `?` marks the range where a difference must lie.
- **Classification under §2:** boundary / known-plaintext-difference allomorph,
  cross-referenced to The Stutter Section (these are messages 7–9). The strong
  `BC.D....C.BD` tail is shared (isomorphic on the right); the divergence is confined
  to the *pre-isomorph* segment where plaintext differs. Not an internal violation:
  there is no broken repeat flanked by continuing agreement on *both* sides within a
  single shared run.
- **Regression assertion:** catalog must reproduce all three gap-pattern rows and the
  `+/?` annotation row character-for-character; classifier must (i) confirm the
  `BC.D....C.BD` tail isomorph across 7/8/9, (ii) flag msg 7's `O…O` repeat as the
  allomorphic feature, (iii) not promote anything here to an internal violation.

### Check 3C — Single-deletion "corruption theory" bound (Allomorphs.md lines 31–37)

- **Status: hypothesis, not fact.** Corruption theory *assumes* the only difference
  between msg 7 and msg 9 in the uncertain section is a single-character deletion (or
  similar localized corruption: typo, etc.). It is one consistent explanation, not
  an established fact, and it does not assert the difference is *unique* — it *bounds*
  *where* a difference must lie. This nuance is non-negotiable (thread §Pitfalls).
- **What it bounds (the actual claim):** given the single-deletion assumption, the
  deletion site can be narrowed by excluding positions that the observed gap patterns
  rule out:
  - Left exclusion: positions *before* the `O` are excluded — if plaintext were the
    same after that point, the non-isomorphic `O` repeat could not appear.
  - Right exclusion: positions *after* the `P` repeat in message 9 are excluded — if
    plaintext were the same before that point, message 7 would show a repeat there.
    (The wiki notes this excludes only *one* position on the right.)
- **Verbatim bound map (Allomorphs.md lines 34–36):**
  - exclusion row: `+++++xxxxx?????x++++++++++++`
  - msg 7 CT:      `VokPVW3^`.OSfk%+OMZdeo9FMiOd`
  - msg 9 CT:      `V%QPVWT^he*Y6ZPcU'B@>?3:(BN'>`
  `x` = positions excluded by the gap-pattern differences; the single-character
  deletion could fall anywhere in the remaining `?` range. The same analysis applies
  to other localized corruption (e.g. typos).
- **Regression assertion:** if the catalog agent implements the corruption-theory
  bound, it must (i) carry an explicit "hypothesis, conditional on single-deletion
  assumption" label, (ii) reproduce the `+++++xxxxx?????x++++++++++++` exclusion row
  exactly, (iii) frame the output as *bounds on where a difference must be*, never as
  "the difference is at position k." Reporting a pinpoint location, or dropping the
  conditional label, is a regression.

### Cross-cutting regression note: the `A.B.CB.AC` main isomorph

Not one of the three target claims, but the canonical positive control for the
catalog and worth pinning (Isomorphs-(Gap-Patterns).md lines 9–26): the main isomorph
`A.B.CB.AC` occurs 6 times across messages 1–3 (East1 twice, West1, East2 — two per
message), e.g. trigram-strings `OLPJ3P-O3`, `g+jX$j3g$`, `dN1D-15d-`, `&-`=Q`_&Q`,
`IhY47YaI7`. The wiki's quoted chance figure (~3×10⁻²⁰ for this many occurrences) is
*the wiki's own estimate*, not recomputed here; the catalog agent should recompute it
under its matched within-message null rather than quoting the wiki number as a
finding. This pattern is the positive control: a correct detector must fire on it.

---

## Summary verdict

- Hierarchy framing: verified against Isomorphic-Cipher-Hierarchy.md + XGAK page,
  with the `≤` (open upper boundary) nuance preserved. GAK is proven-inside
  perfectly-isomorphic (Proof-that-GAK-has-perfect-isomorphism.md), so a clean
  perfect-iso violation falsifies the whole CTAK..XGAK family by contrapositive. The
  non-associativity proof shows perfect iso is algebraically *tight* around the
  group constructions.
- Boundary vs internal discriminator: verified as the correct falsification axis,
  grounded in Allomorphs.md's definition. Boundary/trailing breaks are benign and
  *expected* under perfect iso; only an internal break with two-sided continuing
  isomorphic agreement is a genuine violation. Conservatism + the three benign
  desync explanations (Obstacle / Caboose / Stutter) are required gates.
- Three concrete claims: restated verbatim as checks 3A/3B/3C, with the
  corruption-theory bound explicitly labelled a hypothesis that *bounds* rather than
  *locates*.
- Open caveat held throughout: perfect isomorphism is not provable without the
  plaintext; this work measures evidence and constrains *family selection* only. It
  is not a decode and produces no symbol→meaning mapping.

# `two` — cross-agent reconciliation (2026-07-04)

An independent AI agent (outside this repo, own scratch code) analyzed practice
puzzle `two` and ultimately solved it **crib-assisted**. We obtained a
spoiler-firewalled extraction of its methods and structural facts (codex
`gpt-5.5` static read of the scratch folder; session
`019f2ec8-fa4b-7970-8160-90cb59fb126a`). **We deliberately do not hold the
plaintext, the crib content, or the key** — the standing goal is a crib-free
solve, and this doc records only structure and method.

Provenance tiers used below:

- **[V] verified in this repo** — re-derived from the committed `two` file or
  re-computed independently this session.
- **[R] reported** — read out of the other agent's code/notes by the codex
  extraction; plausible and internally consistent, but not re-verified here.
- The scratch folder itself is ephemeral (session `/tmp`); nothing below
  depends on it surviving.

## Headline: their solve did NOT go through our 348-token surface

Their successful pipeline works on the **full 12-symbol ciphertext** (isomorph
column-maps, then an 8-symbol step/GAK stream). It never touches the deck-free
eps-pair 4-class quotient that Rounds 1–9 (Avenues A and G included) attacked.
**[V]** their input is byte-identical to `research/data/practice-puzzles/two`
(698 symbols `A..L`). **[R]** the 348-token pairclass stream is a *lossy
quotient* of what carried their solve: the raw-symbol isomorph alignments
induce symbol bijections ("column maps") that reconstruct the state group, and
that information is destroyed by the 4-class projection.

This gives Rounds 8–9's honest negatives a candidate structural explanation:
not "the coloring families were wrong," but **the surface was** — the static
26→4 fixed-coloring model presumes the direct-product `C3 × H` reading that
their evidence supersedes (below).

## The state group: `C3 × S4` (order 72) is superseded

- **[V]** Their four column-map generators (on labels `A=0..L=11`)

  ```text
  t1 = (0 5 1)(2 10 3)(4 9 8)(6 11 7)
  t2 = (0 2 10)(1 3 5)(4 6 8)(7 9 11)
  t3 = (1 4)(2 11)(5 8)(7 10)
  t4 = (0 4 5)(1 8 9)(2 3 7)(6 10 11)
  ```

  close under composition to a group of **order 48**, element-order histogram
  `{1:1, 2:15, 3:32}`, structure `(C2^4) : C3`, transitive on the 12 symbols,
  preserving the mod-3 residue blocks `{ADGJ, BEHK, CFIL}`, point stabilizer
  order 4. (Re-computed this session from the generators alone.)
- **[R]** Their notes (attributed to a correction by Lymm, the puzzle author)
  state the **true group has order 96** with a hidden subgroup of order 8; the
  order-48 closure is an **index-2 shadow** (see the parity trap below).
- **Consequence for our dossier:** the `C3 × H` (`H ⊆ S4`) family — recorded in
  `CODEC-RESULTS.md` ("the transparent rotor channel", `C3 × S4` order 72 as
  maximal member) — is **wrong or at least superseded for `two`**: 72 neither
  divides nor contains 48 or 96. What survives **[V]** is the mod-3 *law*
  itself (`steps d = (next−cur) mod 12` with `d ≢ 0 (mod 3)`, legal step set
  `{1,2,4,5,7,8,10,11}`, every transition crossing residue blocks — re-verified
  on the committed file) — but the law proves a **block-transition constraint,
  not a direct-product C3 rotor**. The "transparent channel leaks 1/3 of the
  plaintext key-free" reading was conditional on the direct product and should
  be treated as model-conditional legacy until re-derived under the corrected
  group.

## Technique 1 — isomorph chaining → group closure in the true labeling

The genuinely new capability (we have no instrument for this):

- A **column map** is the symbol bijection induced by an isomorphic pair:
  aligned positions `ct[i+k] → ct[j+k]`, required consistent and bijective.
- In a repeated-plaintext GAK span the two state trajectories differ by a fixed
  state transform `τ`; on the visible labels that acts as a **right-action
  permutation already expressed in the observed alphabet** — so no relabeling /
  labeling search is ever needed.
- Chaining: if span A maps to B and B maps to C, the A→C map must be the
  composition — a consistency check *and* a way to multiply sparse evidence.
- Closing all observed maps under composition reconstructs (a subgroup of) the
  state group acting on the ciphertext labels. **[R]** four full maps suffice
  on `two`; shorter/partial maps validate against the generated elements.

Their scan discipline **[R]**: equality-pattern isomorph detection with a
**matched null that preserves the observed step distribution** (a random walk,
not a structure-destroying shuffle) — consistent with our own `isoscan`
order-1-Markov-null discipline.

Reconciliation with our anchors **[V-ish]**: our `isoscan --delta-mod 3`
repeats (68 @231/351, 51 @5/555, 41 @352/506, 37 @108/572, 34 @22/108;
`CODEC-RESULTS.md`) and their raw-symbol isomorph spans (65 @233/353,
49 @7/557, 41 @353/507, 33 @109/573, 33 @23/109 …) are the same anchor set
seen through two different lenses, with boundary fuzz of 1–2 positions —
exactly the overextension both sides measured independently. Our raw-stream
scan reported "no significant repeat" because it looked for **literal**
repeats; the raw stream carries long **pattern isomorphs** whose aligned
symbols differ by a consistent bijection — the thing our instrument does not
extract and theirs does.

## Technique 2 — anchor trimming (untrimmed hard anchors kill the true key)

**[R]** Measured on their pipeline:

- Raw isomorph extents used as **hard equality filters** over a
  `48 · 4^8 = 3,145,728`-key space → **0 survivors, including the truth**.
- A synthetic control showed the search machinery itself retained planted keys
  → the hard anchors were the fault.
- Fix: trim every hard anchor **2 positions per side** (`(a,b,L) →
  (a+2,b+2,L−4)`), drop trimmed spans shorter than 8 → 104,096 survivors.
- Short identical repeats were used only as **soft scores** (trimmed 1/side),
  never as hard filters.

This directly threatens any future `--anchor-seed` / pattern-crib hard
constraint in our own `pairclass`/`isoscan` work: a planted positive control
with *clean* boundaries will pass while real overextended anchors silently
exclude the truth. Codified as attack-methodology lesson #8.

## Technique 3 — a closed group is a lower bound (the parity trap)

**[R]** All their strong repeated-plaintext anchors have **even gaps** (the
codec emits two GAK letters per plaintext character and repeats start on
character boundaries), so every anchor-to-anchor transform is an even-length
product — the closure could only ever expose an **index-2 subgroup** (order 48
of 96). Escape: enumerate small block-preserving supergroups of the closure
and test them (their `control_and_supergroups.py` / lockstep evolution).
Codified as attack-methodology lesson #9.

## Their pipeline and the residual that needed the crib

**[R]** Order: structural battery + mod-3 law → early negatives (kill list
below) → order-24 GAK model elimination → 12-symbol isomorph anchors + column
maps → order-48 closure → untrimmed hard-anchor key search (0 survivors) →
synthetic control → trimmed hard anchors (104,096 survivor sequences) → soft
identical-repeat ranking (→ 96 keys / **24 canonical relabel classes**,
length-698 patterns over 8 classes) → validity filters + quadgram scoring over
`24 patterns × 8! digit relabelings ≈ 9.7 × 10^5` (+ small table/order
variants) → **not uniquely resolved crib-free** → crib (103 alphabetic
letters, entering at the digit/value-relabeling stage) → solved.

**The crib-free gap, precisely:** everything down to a ~10^6-point residual is
deterministic, controls-backed structure. The last mile — picking the right
point of ~10^6 — failed on quadgram + validity ranking alone and was closed
with a 103-letter crib. A crib-free finish must beat that discriminator: e.g.
wordlist/segmentation DP scoring, the repeated-span self-crib (the anchors
*are* ~30+ repeated plaintext letters — decode candidates must render the
repeat as the same real words twice), and the exact re-encode round-trip as
the only acceptance (`Avenue E` verifier discipline). Whether that closes it
is **unmeasured** — their scoring surface was quadgrams; ours would have to be
genuinely stronger.

## Their kill list (overlaps ours, no contradictions; extensions recorded)

**[R]** Failed approaches in their scratch, with why:

- Injective 16-token substitution annealing on width-2 blocks (both phases /
  directions; 150 restarts × 6000 iters): control cracked, real streams
  plateaued at junk.
- Homophonic 16-token annealer: its own control was unreliable → method
  untrusted (a lesson in itself).
- Fixed-width bit sweeps: a 263,376-cell sweep (35 binary step partitions × 59
  masks × framing variants) with a recovered positive control — real top cells
  far below the calibrated threshold; zero ASCII crib-pattern hits across 144
  patterns.
- Autokey/offset deltas (F4/XOR and Z4/subtraction, min length 14, null
  calibrated): no nonzero-offset isomorphs, no simple autokey layer.
- `tridir` derivative/integral/second-derivative streams: no language.
- Lattice/grid family (17×41, 41×17, parity splits, decimations, run-length,
  Morse-like separators, cumsums): structural quirks, no candidate.
- All 15 order-24 GAK models: exact CSP eliminated, near-miss depths at null
  level.
- Pure GCTAK reduction: the column-map group's centralizer has order 8 and is
  class-preserving — no candidate cover.

## Route implications (decision input, not a decision)

1. **The `two` ladder's live surface should move** from the 4-class pairclass
   quotient to the full 12-symbol stream: (i) an isomorph **column-map
   extraction + group-closure instrument** (natural extension of `isoscan`;
   controls: planted GAK positive with known τ, matched step-preserving null);
   (ii) trimmed-hard-anchor key search over the 8-class step space; (iii) the
   ~10^6 residual attacked crib-free per above. Avenues A/G's negatives stand
   as scoped records; their *framing* (static 26→4 coloring of a transparent
   C3 channel) is superseded.
2. **Community-request relevance:** nothing here touches the `gak-swap-recover`
   ns=3 cost wall (that engine is known-plaintext, known group). But column-map
   closure is a **ciphertext-only group-reconstruction** technique — exactly
   the "more general GAK attack" generality axis, and eyes-relevant (the eyes
   are ciphertext-only with unknown group). Candidate future companion
   instrument (Task-03-style), *after* it earns controls on `two`.
3. `CODEC-RESULTS.md` sections built on the `C3 × H` direct-product reading
   (transparent-channel leak rate, `groupscan`'s `H ⊆ S4` discriminator frame)
   need a superseded-model banner when next touched — the mod-3 law and the
   anchor positions survive; the group-theoretic interpretation does not.

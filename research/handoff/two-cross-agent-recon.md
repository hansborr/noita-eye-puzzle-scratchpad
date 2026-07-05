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

## Stage-2 mechanics (second firewalled extraction, 2026-07-04 — all [R])

Design-level mechanics of their key-search/ranking stages, extracted for the
stage-(ii) build (codex session `019f2ee2` range; same firewall — no
plaintext/crib/key was read out).

**Key parameterization (confirms the stabilizer-fiber hypothesis).** With
`G48` the order-48 closure and `QLIST = [1,2,4,5,7,8,10,11]`, a key is
`(u_-1, c_0..c_7)`: an initial state `u_-1 ∈ G48` (the factor 48 — the
initial state, *not* a relabel class) plus, per legal q value, a 2-bit choice
`c_j` of one of the 4 elements in the fiber `F_q = {g ∈ G48 : g[0] = q}`.
Evolution (their convention `compose(p,q)[x] = q[p[x]]`):

```text
u = u_-1
for ciphertext symbol S_i:
    r_i = inv(u)[S_i]          # must lie in QLIST (legality across the FULL stream)
    gamma_i = chosen element of F_{r_i}
    u = compose(gamma_i, u)
```

The length-698 **q sequence** is `index_of(r_i in QLIST)` — the
current-state readout of each symbol, *not* the raw adjacent delta.

**Search scope caveat.** The whole concrete pipeline runs inside the order-48
shadow; the order-96/supergroup work stayed exploratory (`lockstep`-style
two-span evolution; fiber size would be 8 at order 96). A 48-shadow survivor
is a **quotient candidate, not a true-group key** — a lift/supergroup check
is required before any true-group recovery claim.

**Anchor hard-filtering.** A key survives a trimmed anchor `(a,b,L)` iff its
induced q-index spans agree: `q[a..a+L) == q[b..b+L)`. Trim 2/side, drop
trimmed length < 8 (the raw len-7 identical repeat at 389/561 trims out).
Trimmed hard anchors, in application order: `(25,111,29), (9,559,45),
(234,508,38), (235,355,61), (355,509,37), (111,575,29), (330,488,13)`.
Two-pass evaluation: pass 1 evolves all 3,145,728 keys incrementally checking
only the first trimmed pair (streaming early-abort); pass 2 builds full
698-position q histories for pass-1 survivors and applies the remaining
anchors as full-span equality tests.

**Survivors.** The persisted 104,096 rows are **deduplicated length-698
q-index sequences** (multiple keys can induce the same q stream on this
ciphertext; their v2 artifact discarded the multiplicities — ours should
retain `nkeys` + one representative key per sequence for audit).

**Soft ranking.** 17 short identical-ciphertext repeats (lengths 5–7,
including the trimmed-out 389/561 len-7), each trimmed 1/side, each
contributing 0/1 if the q spans also agree — no length weighting. Measured:
max score 12/17, achieved by 96 sequences, collapsing to **24 canonical
classes** under first-occurrence relabeling of the 8 q symbols (quotients
global S8 digit naming; 24 is an observed count, not a group order). Soft
anchors: `(27,404,5), (86,688,5), (100,492,5), (148,576,5), (212,458,5),
(253,459,5), (270,298,5), (272,349,5), (337,693,5), (343,389,5), (391,423,5),
(398,419,5), (620,629,5), (627,645,5), (242,372,6), (342,388,6), (389,561,7)`.

**Validity/finish stage (context for stage (iii)).** Patterns read as 349
two-octal-digit pairs; enumerate label→digit permutations (8!) × digit order
HL/LH × charset tables (`ascii32/64/96`, a six-bit table); validity = every
used 6-bit value inside a strict/loose allowed set; then average-log-quadgram
scoring. **Crib-free resolution failed here** — validity + quadgrams did not
uniquely select the value/table/digit interpretation (no crib-free truth
rank was preserved in their artifacts).

**Their stage-specific pitfalls** (encode as controls): untrimmed hard
anchors killed all keys including truth; keep key multiplicities; enforce q
legality across the full stream explicitly; treat G48 output as shadow
candidate; their exploratory supergroup count omitted a generator once (do
not trust it unrechecked); their `rank_soft` comment/code mismatch (pair-IC
mentioned, never used); their finish enumeration was split inconsistently
across two scripts (consolidate ours).

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

   > **STATUS (2026-07-04): stage (i) DONE — the `isomap` instrument**
   > (`src/analysis/isomorph_map/`, CLI `isomap`, commits
   > `cfcbf32..283feb1`). File-driven + self-validating (`--self-test`: full
   > production-path GAK positive, order-1-Markov matched null, and a
   > dirty-boundary control routed through the production scan so deleting
   > the trim-2 discipline genuinely fails it — adversarially reviewed, one
   > P1 found and fixed). On real `two` it reproduces this doc's verified
   > known answer from raw ciphertext alone: longest raw pattern-isomorph
   > span 65 (null ceiling 15, p 0.005), 8 surviving span pairs matching the
   > cross-agent anchor list, 4 full column maps, closure = order 48,
   > histogram `{1:1,2:15,3:32}`, transitive, mod-3 blocks preserved,
   > stabilizer 4. The small-index supergroup probe is an explicitly marked
   > stage-1b seam. Next: stage (ii).
   >
   > **STATUS (2026-07-04): stage (ii) DONE — the `shadowsearch` instrument**
   > (`src/analysis/shadow_search/`, CLI `shadowsearch`, commits
   > `98d7399..a443f6e`). File-driven + self-validating (`--self-test`: planted
   > hidden-state positive through the production scan/search path, dirty
   > untrimmed-anchor failure routed through the production path, and order-1
   > Markov no-basis null). Adversarially reviewed; one P1 (pass-1 early-abort
   > lacked mutation coverage) fixed in `a443f6e`: the positive control now
   > asserts pass 1 genuinely filters, a first-anchor-only negative dies in
   > pass 1, and the real-`two` regression pins the pass-1 survivor count.
   > On real `two`, it verifies the previously reported
   > stage-(ii) counts from raw ciphertext alone: key space `3,145,728`;
   > pass-1 survivors `835,520`; the 7
   > trimmed hard-anchor set listed above; `104,096` deduped survivor q-index
   > sequences with key multiplicities retained; max soft score `12/17` reached by
   > `96` sequences; `24` canonical first-occurrence relabel classes. Output is
   > explicitly a quotient-candidate list under the order-48 closure shadow; the
   > order-96 caveat remains load-bearing for any true-key claim. Runtime ~15 s
   > (release); the `--output` JSON (canonical patterns + representative keys)
   > is the stage-(iii) hand-off artifact. Next: stage (iii), the crib-free
   > finish over the 24-class × 8! residual.
   >
   > **STATUS (2026-07-05): stage (iii) BUILT — the `shadowfinish` instrument**
   > (`src/analysis/shadow_finish/`, CLI `shadowfinish`). File-driven over a
   > regenerated `shadowsearch --output` artifact; self-validating before real
   > output (`--self-test`: planted English plaintext → table/digit map → q
   > stream → shadow-key encryption → full production finish ladder; wrong
   > plaintext negative; planted truth rank measured across the full 8! surface).
   > Control result: planted positive PASS (truth rank 1, margin vs junk max
   > +7.7443); wrong-plaintext negative PASS.
   >
   > Real `two` run (release, `target/two-shadowsearch.json` regenerated from
   > committed `two`; wordlist derived in-process from
   > `research/data/lang/english-corpus-large.txt`): covered the external
   > agent's reported phase-0 surface `24 classes × 40320 label→digit
   > permutations × 2 digit orders × 7 built-in tables = 13,547,520`
   > interpretations; phase-0 dropped 0 q-symbols. Tables covered:
   > `ascii32`, `ascii64`, `ascii96`, `sixbit-lower-space`,
   > `sixbit-upper-space`, `sixbit-base64`, `sixbit-base64url`. Tier A visited
   > 13,547,520 interpretations, retained 12,288 (= 24 × top-K 512), rejected
   > 897,120 by loose printable/value sanity, saw 66,808 strict-pass
   > interpretations, and dropped 12,638,112 by the explicit top-K bound. Tier B
   > top interpretation exactly re-encoded the full 698-symbol visible
   > ciphertext through its representative shadow key (class 14, `ascii32`,
   > phase0, HL), but the calibration run was intentionally reported as
   > **low power**: 2 matched decoy q-pattern nulls, observed best −1.9417,
   > null_ge 0/2, add-one `p_emp = 0.3333`, margin vs null max +3.5773. Because
   > 2 nulls cannot attain `alpha = 0.05`, verdict is
   > **`LowPowerNoExclusion`**, not `RoundTripDecode` and not `NoCandidate`.
   > Runtime for the 2-null real run, including self-test, was 2m30s release.
   > A 20-null alpha-resolution run was attempted first and stopped after
   > several minutes as currently impractical for this unoptimized implementation;
   > that is a runtime/power limitation to fix before making a stronger call.
   > The round-trip plaintext hypothesis was logged, not promoted:
   > `research/gak-threads/candidates/shadowfinish-two-shadowfinish-null2-seed-736861646f776603.md`.
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

# `two` — rotor-carrier / pair-class campaign (2026-07-01)

> **SUPERSEDED (2026-07-04):** the 348-token 4-class surface this doc attacks is
> a **lossy quotient** of `two`'s live 12-symbol stream — the deck channel it
> drops carries information, and the isomorph column-maps close to an order-48
> observable shadow of a reported order-96 state group (`two-cross-agent-recon.md`).
> The a′ LM-free anchor-harvest line is separately resolved as a
> bounded-tractability negative in `two-pairclass-aprime-reform.md`. The exact
> derivations and verified eps anchors below stand as a scoped dated record of
> the deck-free 4-class reading; the ranked next steps no longer describe the
> live route (that is `two-cross-agent-recon.md`).

Status: **scoped dated record (2026-07-04) of the deck-free 4-class surface —
no longer the live attack route.** `research/data/practice-puzzles/CODEC-RESULTS.md`
§`two` gives the current route; this file preserves the exact derivations, what
was excluded, and the ranked next steps as they stood.

## Derivations (exact)

From `research/data/practice-puzzles/two` (698 symbols `A..L`):

```python
v   = [ord(c) - ord('A') for c in ciphertext]      # 698 values 0..11
r   = [x % 3 for x in v]                           # rotor: ±1 walk on C3
q   = [x // 3 for x in v]                          # deck channel, 0..3
eps = [(r[i+1] - r[i]) % 3 for i in range(697)]    # in {1,2}; 2 == -1
b   = [1 if e == 1 else 0 for e in eps]            # 697 direction bits, 1 = up
# pair tokens, phase p in {0,1}: t_k = 2*b[p+2k] + b[p+2k+1]  (348 tokens)
```

Verified-exact maximal eps anchors (repeated spans; both sides fail to extend):
`231..298==351..418` (68), `5..55==555..605` (51), `352..392==506..546` (41),
`108..144==572..608` (37), `22..55==108..141` (34). All gaps even.

Key measured facts: eps periodicity is period-2 only (even steps 54.4% up, odd
28.2% up); pair-token marginals (phase 0) 107/51/143/47; within-pair bits
~independent; token drop2 (order-2 conditional-entropy drop) beats an order-1
Markov token resample at p = 0.025 (phase 0) / p = 0.005 (phase 1) — genuine
above-first-order structure in the public channel.

## The model under attack

One plaintext letter per two ciphertext symbols: letter → (eps pair public,
q pair deck-hidden). Token stream = plaintext image under an unknown 4-coloring
of the alphabet → a 348-letter 4-class cryptogram, deck-free. The two token
phases cover both stagger conventions (boundary eps with preceding vs following
letter).

## Excluded this campaign (do not re-try without new structure)

- `maskdecode` on the rotor walk (static/alternating masks, widths 5-8,
  raw-ASCII gate) — negative; plus scratch `A=0..25` letter-map sweep, widths
  4-8, both masks — negative.
- Morse / data-marker parity interleaves of the direction bits — pareidolia.
- Fixed 2- or 3-pair-token letter codebooks — k-gram census populates far more
  than 26 values.
- Deterministic periodic deck schedules p ≤ 24 at the anchors (phase-periodic
  permutation-relation consistency, 231 sample pairs) — at/below shuffled null
  everywhere. Assumes full-plaintext anchor repeats (true under the model).
- 4-class coloring recovery via projected class-4-gram objective (codex round
  1) — **measured power 0/6 on planted controls at length 348**; its negatives
  are uninformative. Do not re-run soft projected-n-gram objectives at this
  length; the margin arithmetic is against them (channel keeps ~1.85 bits/char,
  letter-LM needs ~2.1).

## Ranked next steps

1. ~~Joint word-aware decipherment (codex round 2)~~ **DONE — still
   underpowered.** Controls-first stop: plant coloring accuracy mean 0.365,
   plant letter recovery mean 0.072 (0/6 at the ≥0.5 bar) even with anchor ties
   enforced in-beam; real streams never scored, per the discipline. This is the
   preserved Round-2 verdict.
2. ~~Oracle-decode diagnostic (codex round 3)~~ **DONE — NOT decode-limited.**
   Oracle plant recovery 0.534 mean with the 50k word LM (≥0.5 bar passed,
   readable output); Stage B (unknown coloring) still failed controls but at a
   tiny budget (16 anneal moves). The wall is localized to the outer coloring
   search; the objective separates true from found colorings. This is the
   preserved Round-3 verdict.
3. ~~Scale the outer coloring search (codex round 4)~~ **DONE —
   search-still-failing-at-scale.** 4^8 structured seeding + 112 restarts ×
   1000 anneal moves, 16 workers, anchor-span bonus, ~2h16m: mean plant letter
   recovery 0.133 (bar ≥0.4, oracle ceiling 0.534), mean coloring accuracy
   0.432; real streams never scored, per the discipline. Sharpest diagnostic:
   best plant hit coloring accuracy 0.730 but only 0.221 recovery vs 0.534 at
   accuracy 1.0 — decode quality cliffs within ~7 wrong letters of truth, so
   annealing has no gradient where it matters; scale alone cannot fix this.
   This is the preserved Round-4 verdict.
4. ~~CSP with word-lattice propagation (codex rounds 5/5b)~~ **DONE for
   left-to-right ordering — truth BEAM-PRUNED at the string head.** Round 5
   (beam ≤420, ~1 min/plant) rejected as underpowered; round 5b at the real
   budget (beams 1k/5k/20k, 16 workers) was killed by host OOM after 3/6
   controls (~11 GB peak, ~65-75 min/control, container down twice) but the
   attribution is decisive: true path pruned at positions 10/9/4 of 348 with
   1-2 truth-states alive, never out-scored, prune position ~independent of
   beam width. Left-to-right beam ordering is excluded; the objective is not.
   This is the preserved Rounds-5/5b verdict.
5. ~~Anchor-seeded search-order fork (codex round 6)~~ **DONE, corrected —
   controls still fail, but the original verdict was confounded.** A
   cross-family audit found the first round-6 run hard-dropped truth whenever
   the harvest window ended inside a lexicon word; the old "not harvested +
   saturated => label-bias" conclusion is not a finding. The fixed
   `pairclass` harvest accepts interior final trie nodes only for Phase 1 and
   now reports truth's phrase-window fate. Self-test passes with an explicit
   mid-word harvest regression (`oracle 1.000, midword truth seed #1`). The
   corrected serious gate, using the derived 11,419-word English unigram list
   from `research/data/lang/english-corpus-large.txt` rather than the missing
   calibrated 50k LM, still failed controls at `--phrase-beam 1000000
   --phrase-top 5000 --beam 20000 --plant-bar 0.5 --max-mem-mib 12288`: mean
   plant letter recovery 0.071, mean coloring accuracy 0.238. Truth coloring
   was not harvested on any of 6 plants; every phrase harvest saturated; the
   clean window-fate attribution is mixed — plants 2/3/5 were window
   INFEASIBLE at positions 5-6 (coverage/gap/lexicon limit), while plants
   0/1/4 were window BEAM-PRUNED at positions 24/5/6 (score-pruning/LM
   label-bias). Controls-first refused to score the real stream; the null gate
   did not run. This is the corrected Round-6 verdict. Next crib-free lever:
   first eliminate the coverage failure with the calibrated 50k LM and/or
   better phrase-window edge/gap handling, then avoid score-ranked phrase
   harvest via class-signature/internal-repeat enumeration or branch-and-bound
   over colorings. The honest close remains the withheld-snippet external
   anchor.
6. ~~Land the `pairclass` instrument (golden rule)~~ **DONE — commit
   `0a9111a`.** `src/attack/pairclass/`: derivation (±1-walk → pair tokens) +
   tie anchors + the dictionary beam solver with incremental coloring
   induction, hard tie equalities, and BEAM-PRUNED/OUT-SCORED truth tracking,
   file-driven (`--input-file`/`--stdin` + `--alphabet`), self-validated
   (`--self-test`: planted positive recovery 1.0, matched Markov null,
   forced-prune check, walk gate, embedded-`two` regression). Memory bounded
   by construction (bounded top-K heap + up-front `--max-mem-mib` refusal): the
   ~11 GB Python worker is ~6 MiB here. It REPRODUCES round 5b exactly
   (small-beam controls fail the 0.4 bar, truth BEAM-PRUNED at the head,
   controls-first refuses the real stream). Still to land: the periodic-deck
   phase-consistency scan (generalize `groupscan` with `--max-period`).

Scratch artifacts (job-local, not in repo): token streams, codex briefs +
FINDINGS.md under the session tmp dir `two-pairclass/`; codex round-1 best
colorings and non-candidate decodes are quoted in FINDINGS.md. The capability
those scratch scripts prototyped now lives in-repo as the `pairclass`
instrument (item 6).

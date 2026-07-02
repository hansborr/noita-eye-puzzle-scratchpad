# `two` — rotor-carrier / pair-class campaign (2026-07-01)

Status: **live attack surface, no candidate yet.** Findings summary lives in
`research/data/practice-puzzles/CODEC-RESULTS.md` §"`two` — rotor-carrier
campaign"; this file is the working handoff: exact derivations, what has been
excluded, and the ranked next steps.

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

1. **Joint word-aware decipherment** (in flight as codex round 2): outer
   coloring search, inner T9-style word-lattice decode (letters-only with
   implicit segmentation; variant with space inside a class), anchors as hard
   tied-letter constraints inside the search, controls-first (≥6 planted
   colorings; abort if power < 0.5), order-1 Markov null gate on the real
   stream. Record the verdict in CODEC-RESULTS.md either way.
2. If round 2 is underpowered too: crib-pinned Markov null for drop2 (isolate
   the anchors' share of the above-first-order signal), then a
   constraint-propagation / dictionary CSP attack that uses the anchor ties +
   the 34-letter thrice-constrained phrase structure as the backbone instead of
   annealing.
3. Instruments to land (golden rule): the periodic-deck phase-consistency scan
   (generalize `groupscan` with a `--max-period`), and a `pairclass` derivation
   + entropy-gate CLI (tokens from any ±1-walk stream, drop-k vs Markov null,
   with planted positive + matched null self-test).
4. External anchor: if the maintainer can obtain any `two` plaintext snippet,
   the pair-letter model turns a ~10-letter crib into a large coloring +
   deck-relation seed (34-letter repeated phrase amplifies it 3×).

Scratch artifacts (job-local, not in repo): token streams, codex briefs +
FINDINGS.md under the session tmp dir `two-pairclass/`; codex round-1 best
colorings and non-candidate decodes are quoted in FINDINGS.md.

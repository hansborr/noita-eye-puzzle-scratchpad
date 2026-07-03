# Handoff — `two` pairclass (a′) LM-free anchor harvest: RESOLVED (bounded-tractability negative)

**Status: RESOLVED 2026-07-02.** The variant-B + exact-post-filter reformulation
(§3) was built on `feat/lm-free-window-harvest` (commits `abcf67c`..`51521ed`),
**independently audited** (all five §6 points PASS; the saturation was confirmed a
*genuine* bounded-tractability result of a true layer-merge DP, **not** a
v1-style non-merging-DFS budget artifact), and then **measured**.

**Outcome — the third fork, not §4's two:** the complete, un-beamed DP saturates
its 100M-transition budget **inside occ1** — saturation position **5–6** of
`span_len` 33, with **44–86M distinct merged states** already reached (measured
occ1 layer widths grow ~×10–36 per token: `1, 52, 1867, 41k, 0.6M, 6–9M, …`),
before occ2 or the tie can ever matter. This is a **computational wall, not a
cryptographic anchor-negative**: retention is *undecided*, not disproved. Because
occ1 is free dictionary text in *any* complete formulation (its letters must be
discovered before occ2 can be tied), **no tie-aware variant and no feasible
budget avoids this occ1 explosion.** Full measured record: `CODEC-RESULTS.md`
§Round 7.

**What this closes:** the LM-free anchor-window *harvest method* is exhausted —
its tractable form (score/coverage beam) **evicts truth** (v2), and its complete
form (un-beamed enumeration) is **intractable within occ1** (v3, measured). The
decisive retention question cannot be answered by this route. **Lever reverts** to
the maintainer's external mapping anchor / withheld snippet, or a *different
constraint surface* — not a beam and not a word-LM score key (see §Round 7 "Next
work": flanking-context widening, or LM-free marginal-fit selection over a
complete superset). **Do not re-run the "pending reformulation" spec below — it is
built and done;** it is preserved verbatim as the historical design contract.

---

**Historical status (pre-resolution):** the (a′) line is at a validated but
**un-built reformulation**. The current recorded result is confounded and must
not be treated as a finding. This note is self-contained; it supersedes the (a′)
portion of [`two-pairclass-attack.md`](two-pairclass-attack.md) and any
session-local scratch drafts.

## 1. Where we are

Goal of the `two` campaign: decode the 4-class pair-token cryptogram. The
bottleneck is recovering the 26-letter → 4-class **coloring** — round-3 oracle
showed that *given the true coloring*, LM decode recovers ~0.53, so coloring, not
decode, is the wall. Established negatives: left-to-right LM search prunes truth
at the string head (label-bias, round 5b, width-independent); score-guided
annealing excluded (round 4). Maintainer-blessed live fork: anchor / coloring-space
search rather than left-to-right over the string.

The **(a′)** line attacks this with an *LM-free* enumeration of colorings
consistent with the doubly-occurring tied span (a maximal repeated token span,
~34 tokens, two occurrences occ1/occ2), then seeds the survivors into Phase-2. The
point of "LM-free" is to avoid the score-eviction that causes label-bias.

**Branch `feat/lm-free-window-harvest` holds all (a′) work (off `exploration`,
NOT merged, worktree clean).** Commits: `ac9261e`,`d6fc619` (v1 DFS),
`90e7a9e`,`a69ac4e`,`690877d` (v2 merge-DP). **Its recorded §Round 7 in
`research/data/practice-puzzles/CODEC-RESULTS.md` is CONFOUNDED — do not cite it.**

## 2. Why the current result is not trustworthy (three confounders, each audit-caught)

1. **Round 6** (score-beam harvest): `finish()` dropped mid-word window finals →
   a spurious "label-bias" verdict. Fixed (`accept_partial_final`); re-run gave a
   mixed INFEASIBLE/BEAM-PRUNED result.
2. **Round 7 v1** (LM-free): a non-merging exponential DFS + gap iterative-deepening
   → `HarvestSaturatedMiss` was a *budget artifact*, not tractability. [P0]
3. **Round 7 v2** (merge-DP): STILL confounded by two compounding P0s —
   - (a) `DpKey.tie_letters` (`anchor/enumerate.rs`) carries occ1's decoded
     *letter sequence* to force occ2 == occ1. Because class→letter is one-to-many,
     exponentially many sequences induce ONE coloring → per-layer state explosion
     even though distinct colorings are only ~13–68. `can_drop_tie_letters` clears
     only at `second_offset+span_len`, which equals the window length, so the carry
     burdens every layer.
   - (b) the **coverage-frontier** (`enumerate/frontier.rs`, `StateLayer::offer`,
     10k/layer cap, evict by coverage) is a **beam that evicts truth** — truth
     opens with a leading word-suffix (coverage 0) and is dropped. Proof of
     incompleteness: distinct colorings collapsed 141–1017 → 13–68 while the 50k
     collector cap was NOT hit.

Verified **correct, keep unchanged**: tie enforcement is sound (just too large);
LM-free holds (trie membership only, never `word_logp` as a score); the SuffixTrie
edge model (leading word-suffix + trailing interior-node partial, leading gap only)
is correct and makes truth representable for the in-vocab corpus plants.

## 3. The validated next step — the reformulation (audit + gemini-3.1-pro both vetted)

occ1 and occ2 have **identical tokens**, so occ2 adds no coloring constraint beyond
parse-context. Remove the exponential `tie_letters` and the coverage beam; build a
**COMPLETE, un-beamed DP** keyed on `(trie-node, gap-state, coloring)`.

- **Recommended variant (B): keep occ2 as ordinary untied tokens, full window.**
  Enumerate `[0, window.len)` parsing occ2 as ordinary dictionary tokens but WITHOUT
  forcing occ2 == occ1 (no `tie_letters`). occ2's boundary tokens *prune* and this
  uses *less* peak memory than a short prefix (gemini [Medium]). Tighter superset,
  still cannot miss truth.
- **Alternative (A): drop occ2.** Enumerate `[src, src + max(second_offset, span_len))`
  — the `max(...)` is required to handle the overlap case `second_offset < span_len`
  (else occ1 itself is truncated; gemini [Critical]). Looser superset; risks a
  genuine coloring explosion on a short prefix.
- **Post-filter (required, both variants):** the superset can retain non-truth
  colorings the full tie would reject — a false-positive that matters for the
  matched-null leg (truth itself is safe: it is full-window-valid by construction,
  so truth-in-superset ⟺ truth genuinely retained). Post-filter each surviving
  coloring against the FULL window WITH the tie (cheap: small superset × one
  verification each). This makes the harvested set exact and the null meaningful.
- **Invariants:** LM-free; SuffixTrie edges; determined-then-verified `pin_class`;
  **no beam / no eviction anywhere** in the harvest. If the complete DP is somehow
  still too large, REPORT saturation honestly — never silently reinstate a beam.
- Delete the now-dead `tie_letters` and `frontier` code; keep the enumerator
  modular in `anchor/enumerate.rs` (do not re-bloat `anchor.rs` / the file-size gate).

## 4. The decisive fork (this round should END the (a′) line)

- **truth RETAINED** by the complete, post-filtered enumeration → eviction/label-bias
  was the whole wall; **(a′) works** → next round is Phase-2 seeded solve + matched
  null, then controls-first real-stream scoring. (For real-stream English fluency,
  fetch a large downloadable unigram frequency list — the in-repo corpus vocab is
  only 11,419 words; there is NO maintainer-held 50k list, that was a misconception.)
- **truth NOT retained** by the complete enumeration → a **genuine anchor-negative**:
  the 34-letter tie's colorings do not contain truth's → this closes the anchor-seed
  family, and the lever becomes the maintainer's withheld external snippet /
  external mapping anchor. Record as such (golden-rule safe).

## 5. Orchestration / mechanics

- codex session to resume: `019f24cc-9345-7d32-90d5-b9601023d3cf` (`exec resume`).
  Model pool: **CODEX-HEAVY** (codex implements + reviews; Claude orchestrates +
  second-opinion). codex was rate-limited earlier today (reset ~2:43 PM PDT), now
  available.
- Teammates used this session: a `reviewer` (methodology-audit charter; caught all
  three confounders above — reuse it to audit the reformulation, keep it independent
  of the design) and a `designer` (proposed (a′)). Re-taskable via SendMessage in a
  fresh team, or spawn equivalents.
- Discipline (AGENTS.md golden rules): file-driven CLI instrument + tests via the
  same library fns; planted positive control + matched null; controls-first (real
  stream scored ONLY if plants pass); a file-driven attack emits a *candidate*, never
  a "decode"; both practice puzzles are **English** (no Finnish scoring); record
  results in-repo, correct confounded records rather than appending.

## 6. Immediate next action

Dispatch codex (resume the session above, or fresh) on `feat/lm-free-window-harvest`
with the §3 reformulation — recommend **variant B + post-filter**. Then have the
`reviewer` audit: (1) `tie_letters` + `frontier` fully removed; (2) the DP is
complete/un-beamed (no eviction); (3) the post-filter enforces the full tie exactly;
(4) the overlap boundary is correct; (5) the retention verdict + an honest §Round 7
rewrite that states the v2 result was confounded by BOTH the exponential
augmentation AND the coverage-beam eviction. **Record no result until that audit
passes.**

# Noita Eye Messages — Research Findings

A skeptical research dossier on the Noita "Eye Messages" puzzle, produced by a
multi-agent research workflow (8 parallel research angles → per-angle deep-dive
and source-fetching → adversarial verification of load-bearing claims →
synthesis). The explicit goal was not to assume the community is correct, and
to surface everything that can be tested with code.

This folder sits inside the existing `noita-eye-puzzle` Rust workbench (`../src`).
See [07-workbench-bridge.md](07-workbench-bridge.md) for how the findings map onto
that code.

## How to read the confidence tags

Every non-trivial claim carries one of: [confirmed] (primary evidence —
game files/datamining, reproducible computation, dev statement), [likely]
(strong but not primary), [speculative] (plausible community inference), or
[disputed] (contradicted, unsourced, or order-/assumption-dependent).

## The single most important takeaway

Most celebrated "cipher properties" (flat frequency, no doubled symbols, a clean
0–82 value range, a distance-4 anomaly) are conditional on a reading order that
was itself chosen because it produced those clean results. On the raw stored
order they largely vanish (17 adjacent-equal trigrams; values span 0–122 with
gaps, not a clean 0–82). The community's headline improbability figure
`(83/125)^1036` is a *per-order* probability. Correcting it is subtler than it
looks: a Bonferroni correction over even ~86,000 *fixed* orders stays
astronomically small under an independent-uniform null, so the dominant risk is
not raw trial count but researcher degrees of freedom — the reading-order
family, digit mapping, grouping rule, and statistic were all chosen after seeing
the data. Quantifying both corrections is the highest-value code experiment
available.

## Verification scorecard

14 load-bearing "confirmed/likely" community claims were re-checked
adversarially. Result: 5 supported, 8 mixed, 1 unverifiable (full reasoning in
[03-confirmed-vs-speculation.md](03-confirmed-vs-speculation.md), raw verdicts in
[data/verdicts.json](data/verdicts.json)).

**Supported [confirmed]:**
- 9 messages total (5 East / 4 West), alternating placement, East-5 has no West counterpart.
- Each glyph is one of 5 orientations (digits 0–4); digit 5 is a non-rendered row delimiter.
- The eye generator is engine code, not Lua/sprites — it cannot be pulled from `data.wak`; glyphs are engine-rendered.
- Spawn conditions: no-mods-ever-this-run flag + "Entered East/West" trigger + `background_cave_02.png`.
- The puzzle is unsolved; flat trigram frequency rules out simple monoalphabetic substitution.

**Notably debunked / downgraded:**
- "**The developers confirmed it's solvable / decodable**" — [disputed]. No primary
  source upgrades the eyes to *solvable*: that framing traces to an unsourced 2022
  Hacker News intro line, echoed by AI-generated pages. A relayed-verbatim developer
  quote (Arvi, 2021-10-15 Twitch stream, via FuryForged) *does* attest that the eyes
  carry an **intentional** message and are "very difficult" — so intentionality is
  dev-attested, but the quote discloses no cipher, key, method, or solution, and
  recoverable plaintext is not dev-attested. The honest statement stays "structured
  data of unknown meaning, unsolved."
- The exact direction-per-digit mapping (1=up, 2=right, …) — [unverifiable] from
  any text source; shown only as an image. Treat as convention, not fact.
- The clean 0–82 range / distance-4 / no-doubles properties — [mixed];
  order-contingent (see takeaway above).

## Documents

| File | What's in it |
| --- | --- |
| [01-overview.md](01-overview.md) | What the puzzle is, the 9 message locations, glyph states, spawn conditions, seed-determinism, solved/unsolved status. |
| [02-theories-and-encoding.md](02-theories-and-encoding.md) | Every notable decoding theory (base-5 trigrams, base-7 engine layer, polyalphabetic/S_83, alphabet chaining, etc.) with a critical assessment of each. |
| [03-confirmed-vs-speculation.md](03-confirmed-vs-speculation.md) | The skeptic's document: confirmed vs likely vs speculative vs disputed, the adversarial verification verdicts, dead ends, and hidden assumptions. |
| [04-game-data-and-tooling.md](04-game-data-and-tooling.md) | How Noita stores data (data.wak, engine vs Lua, seed/PRNG), datamining via Ninji's Ghidra project, and the community tools/repos (Lymm's Binoculars, the analysis repos). |
| [05-code-investigations.md](05-code-investigations.md) | **The key deliverable.** 13 prioritized experiments to test/confirm/deny the findings in code, each with a hypothesis, method, expected-vs-null interpretation, tools, and difficulty. |
| [06-sources.md](06-sources.md) | 57 deduplicated sources grouped by type. |
| [07-workbench-bridge.md](07-workbench-bridge.md) | How to implement the experiments in the existing Rust crate: module-by-module build order and the first three commits. |
| [gak-threads/](gak-threads/README.md) | **Completed campaign / reference.** The six-thread (1A/1B/2/3/4/5/6) Group-Autokey (GAK) campaign — from the community wiki's GAK framework, which independently converges with our workbench — is DONE; every thread landed (see `gak-threads/PROGRESS.md` §6 and the `G1`/`G1b`/`G2`/`G3` result records). Read it as reference, not a next-work queue. |
| [findings/agl-exclusion.md](findings/agl-exclusion.md) | **Wiki-postable result.** Exhaustive exclusion of the AGL(1,83)-GAK families (`C83:C82`, `C83:C41`): the fixed-point lemma + complete enumeration (0/6724 and 0/3362 fix ≥2 points) strengthen the wiki's *tentative* exclusion to a rigorous one; the prefix-region transcription certificate now pins 324/324 one-digit and 5,184/5,184 bounded two-digit counterfactuals as still excluded. |
| [findings/eyes-structural-summary.md](findings/eyes-structural-summary.md) | **Publishable frontier summary.** One standalone synthesis of the eyes structural program: six-group transitivity pruning to `{A₈₃,S₈₃}` with `D₁₆₆` conditional; AGL exclusion plus T02 robustness; perfect-isomorphism / Stutter sensitivity; G3 leak ceiling; Thread-4 fair honest-negative; and the standing conclusion that recovery remains blocked on the symbol-to-meaning anchor. |
| [findings/two-pair-ic-class-ranking.md](findings/two-pair-ic-class-ranking.md) | Phase-0 pair-value IC ranking for practice puzzle `two`'s 24 shadow-finish classes. The invariant is useful for ordering later finish work, but the measured ranking is flat/diffuse rather than a single-class selector. |
| [findings/two-shadowfinish-substitution-candidate.md](findings/two-shadowfinish-substitution-candidate.md) | **Practice `two` solved/confirmed.** Fixed `shadowfinish` + `substfinish` recovered the octal/Proto-Indo-European plaintext hypothesis under matched nulls, then maintainer confirmation against withheld ground truth confirmed the solution. The pure computation remains letter-level; punctuation/hyphenation was source/syntax-aligned, not recovered by the Rust finisher. |
| [findings/two-original-generator-roundtrip-blocker.md](findings/two-original-generator-roundtrip-blocker.md) | **Practice `two` round-trip audit.** The repo lacks the original generator/key/codec/punctuation artifacts needed to re-encode the frozen candidate to the exact ciphertext; the current `shadowfinish` replay is only a vacuous fitted-surface invariant. |
| [attack-methodology.md](attack-methodology.md) | **Process lessons for building trustworthy cipher attacks** (matched nulls vs the search's DoF, gate-exercising positive controls, fold-vs-fold held-out scoring, the SA sum objective, reduced-base indexing, power calibration). Transfers to any new attack even when the cipher math does not. |
| [data/](data/) | Raw structured outputs: `facts.json` (126), `verdicts.json` (14), `code-testable.json` (47), `sources.json` (57) — for downstream tooling to ingest. |

## Where to start (code)

1. **Experiment 0** — cross-validate the four independent transcriptions before
   trusting any of them (now implemented: the crate's `corpus.rs` is the verified
   Experiment-0 corpus).
2. **Experiment 1** — reading-order multiple-comparisons audit with a null
   distribution. Most likely to confirm *or* deflate the consensus.
3. **Experiment 11** — run the tooling against Noita's *solved* ciphers as a
   positive control, so a null result on the eyes actually means something.

## Method & caveats

- Produced by ~35 LLM research agents over web sources (Noita Wiki, the primary
  Google Docs, GitHub analysis repos, Reddit, Hacker News, datamining write-ups).
  It is a map of the community's state of knowledge, fact-checked, not new
  cryptanalysis. Source URLs are inline throughout and in `06-sources.md`.
- The entire technical corpus rests on a handful of analysts and repos;
  independent reproduction is thin. The most valuable code contribution is adding
  the null distributions the community has not.

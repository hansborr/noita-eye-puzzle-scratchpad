# 05 — Code Investigations: Experiments to Test the Noita Eye-Messages Findings

This document is a prioritized, skeptical experiment plan for independently testing the community's claims about the Noita "Eye Messages" puzzle. The guiding principle: **do not assume the community is right.** Every experiment below is designed so that a *null* result is as informative as a positive one, and several are explicitly built to detect whether an apparent "encoding" is actually a coincidence or an artifact of the generation pipeline.

A recurring methodological trap runs through almost all community work and must be confronted head-on: nearly every "cipher property" (flat frequency, no doubled symbols, distance-4 anomaly, contiguous 0–82 range) is **conditional on a chosen reading order** that was itself selected *because* it produced a clean-looking result. Independent verification on this investigation found that on the **raw stored order**, those properties largely vanish (17 adjacent-equal trigrams exist; distance-4 is not elevated; the value set is 0–122 with gaps, not 0–82) [confirmed]. So the single most important class of experiments here is the one that quantifies how much of the "signal" survives correction for the multiple-comparisons / order-selection problem.

---

## Data sources you will use (ground truth substrate)

Before any experiment, obtain and cross-validate the raw glyph data. **Do not trust a single transcription.** There are at least four independent transcriptions; diff them first (Experiment 0).

- **eyes.json** (digit strings 0–4, delimiter = 5): `https://github.com/ngraham20/NoitaCryptographyResearch` (file `eye/eyes.json`) [confirmed]
- **data.csv** (alternate transcription): `https://github.com/Doctor-Ned/NoitaEyeGlyphResearch` [confirmed]
- **noitaGlyphs.txt / trigram bruteforce data**: `https://github.com/ToboterXP/EyeGlyphs` (`archive/eyeGlyphs-trigram order bruteforce.py`) [confirmed]
- **Xkeeper0 PHP transcoder** (the engine-decode reference, base-7 over 64-bit ints): `https://gist.githubusercontent.com/Xkeeper0/a6eda18571ef889be291822c400cc6c8/raw` [confirmed]
- **Primary doc** (encoding rules, spawn conditions): `https://docs.google.com/document/d/1s6gxrc1iLJ78iFfqC2d4qpB9_r_c5U5KwoHVYFFrjy0` [confirmed]
- **CodeWarrior0 analyses repo** (reference implementations): `https://github.com/codewarrior0/noita-eye-glyph-analyses` [confirmed]
- **Wiki (statistical claims, reading orders)**: `https://noita.wiki.gg/wiki/Eye_Messages` [confirmed]

---

## Experiment 0 — Cross-validate the four transcriptions (DO THIS FIRST)

**Difficulty: trivial. Priority: highest — everything downstream depends on it.**

**Hypothesis tested:** The independent transcriptions (ngraham20 `eyes.json`, Doctor-Ned `data.csv`, ToboterXP `noitaGlyphs.txt`, Xkeeper0 PHP output) agree byte-for-byte on all 9 messages.

**Method:**
1. Normalize each source to one canonical representation: per-message decimal trigram sequence (after the agreed reading order) AND the raw 0–4 digit string with delimiter removed.
2. Run Xkeeper0's PHP transcoder (`php eye.php`, needs bcmath) to regenerate ciphertext from the hard-coded `[u32,u32]` pair arrays — this is the closest thing to **engine ground truth** since it mirrors the decompiled base-7/64-bit decode [confirmed].
3. `diff` all four element-wise.

**Expected signal / interpretation:** A clean match across all four would strongly validate the dataset and let downstream experiments rest on solid ground. **Any divergence is critical** — it means at least one widely-cited analysis was run on corrupted ciphertext, which would silently invalidate isomorph/frequency claims. Flag and localize any mismatch before proceeding.

**Note on layering [confirmed]:** Xkeeper0's decode is **base-7 over 64-bit integers emitting −1..5 (5 = newline)** — the *engine* storage layer. The base-5 trigram (0–124) is the *human reading* of rendered glyphs. These are two different layers; do not conflate them. Confirm both reproduce the same final glyph stream.

---

## Experiment 1 — Reading-order multiple-comparisons audit (THE decisive test)

**Difficulty: medium. Priority: highest — the experiment that most directly tests whether the headline probability is honest.** (Caveat: the raw *order count* alone is unlikely to overturn it — the real exposure is researcher degrees of freedom; see the interpretation below.)

**Hypothesis tested:** The "exactly one of 36 reading orders yields an unbroken 0–82 range" result is genuinely improbable under chance, and is *not* an artifact of testing many orders and reporting the prettiest one.

**Method:**
1. Reconstruct the 9 glyph grids from raw data (rows split on delimiter; widths confirmed to be 39 with the bottom two rows differing by ≤1) [confirmed].
2. Implement all 36 "standard" reading orders AND Toboter's broader ~86,000-order space (`https://github.com/ToboterXP/EyeGlyphs`) [confirmed].
3. For each order: decode trigrams base-5 → base-10 across all 9 messages combined; record (a) number of distinct values, (b) whether the value set is a contiguous range, (c) the range span.
4. **Crucially**, build a null distribution: generate thousands of random glyph grids of identical dimensions, run the *same* 36-order (and ~86k-order) search on each, and record how often *at least one* order produces a contiguous 83-value (or any contiguous) range. This is the multiple-comparisons correction the community's `(83/125)^1036` figure omits. **Make the null's search space match the human one** — resample not just the grid but also the digit→value mapping and the trigram grouping rule, since those were chosen after seeing the data too (see interpretation).

**Expected signal / interpretation:**
- The naive per-order probability `(83/125)^1036` is real and reproduces (float64 `5.836e-185`; exact value `5.836200792956514e-185`) [confirmed], but it is the probability for *one fixed* order. The honest question is the **family-wise** probability across everything searched.
- **Trial count alone will not deflate it.** A Bonferroni/Šidák correction over even ~86k *fixed* orders leaves the outcome astronomically small *if* the null is independent-uniform trigrams — so do not expect the order count by itself to overturn the claim. The real exposure is **researcher degrees of freedom** (the "garden of forking paths"): the reading-order *family*, the digit→value mapping, the grouping into trigrams, and the "contiguous range" statistic were all selected *after* looking at the data. Separate and quantify the two corrections — fixed-order family-wise error vs. adaptive model selection — and treat the latter as the one that actually matters.
- **Positive (encoding likely real):** Even after correcting for ~86k trials, the contiguous-0–82 outcome remains astronomically unlikely, AND random grids essentially never produce it.
- **Null / deflationary:** If random grids of the same shape frequently yield *some* contiguous range under *some* of the 36/86k orders, then the "0–82" result is partly a selection artifact and the headline probability is misleading [disputed — community presents `(83/125)^1036` without this correction].
- Independent computation already shows the raw order gives 0–122 with gaps, so the contiguity is **definitely order-contingent** [confirmed]; this experiment quantifies whether that contingency is suspicious or benign.

**Tools:** `ToboterXP/EyeGlyphs` brute-force script as a starting point; reimplement the null-distribution wrapper yourself (the community version does not do this).

**Implementation status (2026-06-24):** the fixed standard36 null exists as
`src/null.rs` / `cargo run -- nulltest`, and the broader configured
researcher-degrees-of-freedom correction now exists as `src/dof_null.rs` /
`cargo run -- dofnull`. The DoF null does **not** compare raw statistic values
across incommensurable cells: each traversal/grouping/statistic cell is first
mapped to its own same-shape random-grid marginal tail from calibration set A.
The eyes and independent resampling set B then take the minimum calibrated
p-value over the same search space while both are scored against A. With seed
12345, 1000 calibration trials, and 1000 resampling trials, the eyes' min
marginal p is at the empirical floor (`1/1001`), but 199/1000 resampling grids
also reach an equally small calibrated min-p somewhere in the configured search.
The add-one adaptive p-value is **200/1001 = 0.199800** (95% Wilson
`0.176198..0.225697`; median Sidak-equivalent comparisons ≈173). The accepted
honeycomb trigram contiguous-0..=82 cell is also at `1/1001`. The fixed
standard36 null still supports the anomaly when the honeycomb family is treated
as data-independent; the broader configured DoF correction no longer supports it
as a small adaptive p-value over arbitrary traversal/grouping/statistic choice.

---

## Experiment 2 — Generation-pipeline artifact test (is the structure an encoding, or a side effect of hex→base-7?)

**Difficulty: medium. Priority: high — directly attacks the "meaningful plaintext" assumption.**

**Hypothesis tested:** The 0–82 contiguity and isomorph structure are partly an **artifact of the deterministic generation pipeline** (fixed 64-bit number → repeated division by 7 → −1 mapping), not evidence of an enciphered natural-language plaintext [speculative; this is a live concern, not established].

**Method:**
1. Implement the documented generator and confirm it reproduces the wiki's worked example: `int('acf686745634505c',16) = 12463296853015023708` → base-7 expansion → drop trailing 0 → subtract 1 → `[2,0,1,0,1,3,2,2,3,3,0,4,0,4,1,1,3,0,2,3,2,1]` [confirmed — reproduced in dossier].
2. Feed random inputs through the *same* pipeline — but **constrain them to the real structure**: match the per-message `[u32,u32]` block count, the output lengths, the delimiter layout, and the valid symbol alphabet. Unconstrained random 64-bit integers will not preserve block lengths, delimiter placement, or the "no internal −1" behaviour, so they are only a separate *negative* control, not the null. Also push known natural-language plaintexts (encoded various ways) through it.
3. Run the identical trigram/range and isomorph analyses on these synthetic outputs.

**Expected signal / interpretation:**
- **If random inputs through the base-7 pipeline also tend to produce near-contiguous ranges or pseudo-isomorphs**, then those features are pipeline artifacts → the "encoding" interpretation weakens substantially [would be a major correction].
- **If only the real data shows them**, the structure is special and the encoding hypothesis strengthens.
- Watch the radix tension carefully: division by 7 yields remainders 0–6, minus 1 → −1..5. The documented transcoder emits `(a % 7) − 1` **directly**, where −1 and 5 behave as control/newline values rather than glyph orientations — so "are the values clamped or mod-5'd?" is a **strawman unless the engine code actually clamps**; inspect the decompiled path before assuming it does. The "base-5 framing" may still be the wrong alphabet *layer* if the true alphabet is base-7-derived [disputed — wiki prose says "converted into 0-5", but the mechanism is base-7].

---

## Experiment 3 — Structural divisibility & trigram-count reproduction

**Difficulty: trivial. Priority: medium (sanity baseline, mostly already confirmed).**

**Hypothesis tested:** Every message's eye count is divisible by 3; total trigrams = 1036; the `(83/125)^1036` figure is internally consistent.

**Method:** Strip delimiter (5), assert `len % 3 == 0` per message; sum `len/3`; recompute `(83/125)**1036`.

**Expected signal:** Counts `{297,309,354,306,411,372,357,360,342}` all divisible by 3; sum = 1036; probability = `5.8362007929568295e-185` [confirmed — reproduced multiple times in dossier].

**Caveat / correction to flag:** Divisibility holds **only when counting eyes, excluding delimiters** — the raw string lengths (including delimiters) are mostly *not* divisible by 3 [confirmed]. Also note: a high-precision recomputation gives `...6514e-185` in the trailing digits; the wiki's published mantissa `...68295` is a float64 rounding artifact [confirmed — minor numerical defect in the wiki figure].

---

## Experiment 4 — Frequency / entropy / IoC: is it really non-monoalphabetic?

**Difficulty: low. Priority: high — this is the core "is there signal" test.**

**Hypothesis tested:** The trigram-value (0–82) frequency distribution is statistically flat, ruling out simple monoalphabetic substitution of a natural-language plaintext.

**Method:**
1. On the **accepted reading order**, build the unigram histogram over the 83-symbol alphabet.
2. Compute chi-square goodness-of-fit vs uniform; compute index of coincidence (IoC).
3. **Repeat on the raw stored order and on several alternative orders** to see how order-dependent flatness is.
4. Use `codewarrior0/simple_freq.py` and `SirCapybar/NoitaEyeGlyphResearch` IoC routines as reference implementations [confirmed these exist].

**Expected signal / interpretation:**
- Community reports median frequency ~12, mean ~12.48, IoC ~1.066 (near-random) [confirmed via CodeWarrior0 doc].
- **Flat distribution + IoC near `1/83`** → consistent with polyalphabetic, inconsistent with monoalphabetic substitution of skewed natural-language text. This is sound cryptographic reasoning [confirmed], but note it is community analysis, not dev-confirmed.
- **Interpret skeptically:** flatness is *also* exactly what you'd get from structured-but-meaningless data (e.g., the base-7 pipeline output). Flat frequency rules monoalphabetic *out*; it does **not** rule a real message *in*.

---

## Experiment 5 — Periodicity & autocorrelation (Vigenère family ruled out?)

**Difficulty: low. Priority: medium.**

**Hypothesis tested:** The ciphertext is aperiodic (no fixed key period), supporting the polyalphabetic/autokey conclusion and ruling out plain Vigenère/Caesar.

**Method:** Run Kasiski / autocorrelation / IoC-by-period (`codewarrior0/stat_period.py`) over candidate periods. Separately brute-force all 83 Caesar shifts and short Vigenère keys over the 0–82 stream and score outputs against English **and Finnish** n-gram models (Toboter ships both corpora; the plaintext language is unknown) [likely Finnish or English].

**Expected signal:** No dominant period; no Caesar/Vigenère key yields language-like statistics. A positive (readable plaintext) would be a sensational result and should be triple-checked against Experiment 0 data integrity before any announcement.

---

## Experiment 6 — Adjacency & distance-4 anomaly on raw vs reordered data

**Difficulty: low. Priority: high — exposes the circularity directly.**

**Hypothesis tested:** "No symbol twice in a row" and "distance-4 recurrence at ~2× expected rate" are properties of the **correctly reordered** ciphertext, not of the raw data.

**Method:**
1. On raw stored order: count adjacent-equal trigrams and build the recurrence-distance histogram.
2. On the accepted reading order: repeat.
3. Use `codewarrior0/repeats.py` as reference [confirmed exists].

**Expected signal / interpretation:**
- Independent computation already found, on the **raw order**: 17 adjacent-equal trigrams (NOT zero), and distances 1/3 (17/15) *higher* than distance 4 (10) — i.e., the celebrated anomalies **do not appear** [confirmed, disputed against community framing].
- Therefore: if a candidate reading order drives adjacent-equal to **0** and produces a genuine distance-4 spike at ~2× baseline, that order is corroborated as intended. **This makes "adjacent-equal == 0" a candidate discriminator among reading orders** — but it is **not** statistically independent of contiguity when searched over the same 36/86k orders, so it carries its own multiple-comparisons burden. Pre-register the role: use it to *confirm* Experiment 1's single winning order (one order, one test), or, if you *search* on it, fold it into the **same** family-wise null as contiguity and distance-4 and score the three jointly — do not report it as a free independent check.
- If *no* order simultaneously satisfies contiguity AND zero-adjacency AND the distance-4 spike, that tension itself is evidence the model is overfit.

---

## Experiment 7 — Isomorph detection & the "Alphabet Chaining" failure

**Difficulty: medium–high. Priority: medium-high.**

**Hypothesis tested:** Genuine isomorphs (repeated relative-pattern segments) exist across messages, consistent with a plaintext-driven polyalphabetic permutation cipher; and the classical "alphabet chaining" attack fails for a structural reason (non-commutativity), not because the isomorphs are spurious.

**Method:**
1. Run `codewarrior0/isomorphs.py` across the 9 sequences to locate repeated relative-pattern segments [confirmed exists].
2. Build a randomized-shuffle null: how often do isomorphs of the observed length appear in shuffled data of the same alphabet/length? (The community asserts isomorphs are significant but the dossier did not surface a Monte-Carlo null for them.)
3. Attempt alphabet chaining on the discovered isomorphs and confirm it does not yield consistent plaintext [confirmed it fails per wiki].
4. Test Perseus's permutation observation: symbols in non-shared sections allegedly never reappear in later size-≥2 shared sections (claimed p ≈ 0.192% by chance) — reconstruct aligned shared/non-shared regions and compare the empirical rate to a shuffle null [confirmed claim exists; null not yet done].

**Expected signal / interpretation:**
- **Isomorphs significant above null + chaining fails** is *consistent with* a non-commutative permutation cipher (Chaocipher/Hutton/S_83 family) but does **not** establish one [speculative]: chaining can also fail from a wrong reading order, misalignment, short/noisy isomorphs, a transcription error, an implementation bug, or a wrong-plaintext assumption. Before inferring a cipher class, run synthetic controls where alphabet chaining is *known* to succeed and *known* to fail, and confirm the eye corpus matches the known-fail control's signature — not merely that chaining "failed".
- **Isomorphs at chance level** → the "structure" is weaker than claimed and the cipher inferences are overbuilt.
- Note the echo-chamber risk: nearly all isomorph work traces to Lymm + codewarrior0; an independent null distribution is genuinely missing from the corpus and is high-value to add.

---

## Experiment 8 — Brute-force base-N reinterpretation cross-checked against known alphabets

**Difficulty: medium. Priority: medium.**

**Hypothesis tested:** The base-5 trigram model is the correct alphabet layer (vs base-7, vs single-glyph base-5, vs other groupings), tested by which interpretation best matches a plausible plaintext alphabet size.

**Method:**
1. Enumerate candidate interpretations: single glyphs (base-5), trigrams (base-5 → 0–124), the engine base-7 stream, pairs, tetragrams.
2. For each, compute alphabet size actually used, entropy, and fit to candidate plaintext alphabets (26-letter English, ~29-letter Finnish, ASCII).
3. The "83 distinct values" closely matching plausible 2× alphabet or rune-wheel sizes is suggestive but **the 83 Elder Futhark runes are an arbitrary researcher display mapping, NOT in-game runes** [confirmed] — do not over-read it.

**Expected signal / interpretation:** A base/grouping whose used-alphabet size and entropy cleanly match a real language alphabet is a candidate. **Skeptical note:** "83 states ≈ 83 distinct glyph values" risks being circular — the state-count estimate may simply equal the alphabet size [disputed]. Estimate internal states *independently* (via isomorph-length distributions / unicity distance) and check whether you recover ~83 without assuming it.

---

## Experiment 9 — Seed-invariance of content

**Difficulty: medium–high (requires the game or its PRNG). Priority: medium — tests a load-bearing but unproven assumption.**

**Hypothesis tested:** Eye-message *content* (the trigram value sequence) is identical across world seeds; only *locations* are seed-dependent.

**Method:**
1. Use Lymm's Binoculars (`https://gitlab.com/realgonzogames/lymms-binoculars`) or noita-telescope (`https://github.com/Lymm37/noita-telescope`) to get coordinates for ≥2 seeds [confirmed tools].
2. Capture glyphs in-game (unmodded — eyes do not spawn if mods were ever active this run, and only on `background_cave_02.png` after the "Entered East/West" trigger) [confirmed conditions], or reproduce via the engine.
3. Transcribe to trigrams and diff content across seeds.
4. Verify the X-mirroring relationship: for seed 1249563923, East1 (22064,−6079) / West1 (−49616,−6079) [confirmed in wiki table; not re-verified in-game].

**Expected signal / interpretation:** Identical content across seeds = content is hardcoded/seed-invariant (the community assumption) [likely, not proven — no byte-for-byte cross-seed proof exists in any primary source]. Any per-seed content variation would be a major finding overturning the premise that there is a single fixed message to solve.

**Primary-observer update (2026-06-22):** the repo owner reports, from direct in-game observation across **multiple world seeds**, that the eye-message content is **identical** — corroborating seed-invariance from primary observation, which no prior source had. This is a **qualitative** confirmation (eyeballed equivalence), not the byte-for-byte trigram diff across ≥2 named seeds that remains the gold standard. Status moves from "unproven assumption" toward "directly corroborated"; the stronger form is still open and would become in-scope for the std-only crate the moment a second-seed transcription is vendored under `research/data/` (the analysis half — a cross-seed diff test — needs no game access; only the second transcription does).

---

## Experiment 10 — Sprite-state extraction & clustering (verify the 0–4 orientation mapping)

**Difficulty: high. Priority: medium — addresses a genuinely unverified link.**

**Hypothesis tested:** The specific digit→direction mapping (0=center, 1=up, 2=right, 3=down, 4=left) is correct, and there are exactly 5 visually distinct orientations.

**Method:**
1. The glyphs are **engine-rendered with no sprite assets in `data.wak`** [confirmed] — so you cannot extract sprites from the archive. Instead, capture rendered eye images in-game (per Experiment 9 conditions) or from the decompiled render path in Ninji's Ghidra project.
2. Cluster the captured eye images (k-means / template matching) to confirm exactly 5 visual states.
3. Cross-map clusters to the digit values produced by the generator for the same positions.

**Expected signal / interpretation:**
- 5 clean clusters confirms the 5-orientation model.
- The exact **direction-per-digit** mapping is currently **only shown as an image** on the wiki/primary doc; no retrievable *text* source pins each pixel-direction to its digit, and one source (Cipherbrain) warns the numbering order is non-obvious [unverifiable from text — flagged in dossier verdicts]. This experiment is the *only* way to verify it from primary pixels rather than convention. Treat the popular mapping as **convention, not confirmed fact** until this is done [disputed/unverifiable].

**Primary-observer update (2026-06-22):** the repo owner, from direct in-game observation, confirms **exactly 5 visually distinct orientations** (corroborates the already-`[confirmed]` 0–4 inventory) and independently concurs the **digit→direction labeling is arbitrary** ("no reason to prefer the encoding the community uses"). Net effect: the *count* sub-claim is corroborated; the *mapping* sub-claim resolves not as "verified" but as "there is no canonical mapping to verify — it is a labeling convention." Critically, this is **cryptanalytically immaterial**: all downstream statistics run on the engine-fixed integer digit sequence (cross-validated byte-for-byte in Experiment 0), so a relabeling of the direction names permutes no value and changes no result. The only thing that would still matter is a *mis-assignment of which integer belongs to which glyph during transcription* — and that is exactly what Experiment 0 already rules out.

---

## Experiment 11 — Reproduce the methodology that SOLVED other Noita ciphers (calibration)

**Difficulty: low–medium. Priority: medium — provides a positive control.**

**Hypothesis tested:** The analytical pipeline used here actually works on Noita ciphers that *are* solved — i.e., your tooling isn't systematically blind.

**Method:** Apply the same frequency/IoC/substitution tooling to the **solved** Noita symbol systems as positive controls:
- Common Glyphs (map 1:1 to English: "SEEK THE END", "BRING THE TREASURE HERE") [confirmed solved].
- Orb-Room glyphs (Finnish creation-myth text) [confirmed solved].
- The Cessation Cipher Quest (decodes to "SEEKING TRUTH, THE WISE FIND INSTEAD ITS PROFOUND ABSENCE") — a fully-solved multi-step Nolla cipher [confirmed], at `https://noita.wiki.gg/wiki/The_Cessation_Cipher_Quest`.

**Expected signal / interpretation:** Match the control to the tool. The **Common Glyphs** (a 1:1 monoalphabetic map → "SEEK THE END") are the right positive control for the frequency/substitution pipeline and *should* be recovered cleanly; the Orb-room Finnish text is a language-scoring control. The **Cessation Cipher is a multi-step image/key puzzle** — the frequency/IoC/substitution tooling will **not** "recover" it without puzzle-specific machinery, so cite it only as proof that Nolla designs solvable ciphers, not as a tooling control. For the isomorph/chaining tooling, build *generated* polyalphabetic/autokey fixtures with known keys as the matched controls. If the matched controls pass, a *null* on the Eye Messages is meaningful (the tools work; the eyes are genuinely harder or not a simple cipher); if they fail, the methodology is suspect. **Important caveat:** the Cessation Cipher is a **separate** puzzle and must **not** be conflated with the eyes as evidence the eyes are solvable [confirmed — common conflation error].

---

## Experiment 12 — Candidate-cipher implementations (incrementing wheel / Chaocipher / S_83 deck)

**Difficulty: high. Priority: lower — this is the open research frontier, not a verification.**

**Hypothesis tested:** A specific live model (ngraham20's "incrementing wheel": 83-glyph outer ring + gapped-plaintext inner ring rotating one step per char; or an S_83 group-autokey / deck cipher) can reproduce the eyes' isomorph statistics and yield language-like plaintext.

**Method:**
1. Implement the wheel from `ngraham20/NoitaCryptographyResearch` (Rust/Python `src/`) and its inverse; run over the correctly-ordered ciphertext for various inner-ring alphabets/gap patterns; score outputs with English/Finnish n-gram models [confirmed model exists, unproven].
2. Implement single-83-wheel vs S_83 deck-shuffle (Lymm's GAK-over-S_83 model); encipher Finnish/English test text; compare IoC, no-double property, and isomorph stats against the real eyes. Toboter's `best.out` uses a Tolkien text as a known-plaintext GA test target [confirmed].

**Expected signal / interpretation:** A model that **simultaneously** reproduces the eyes' flat frequency, zero-adjacency, distance-4 spike, *and* isomorph structure — and yields readable plaintext — would be a solution. Note the community has tried Chaocipher/Hutton/alphabet-chaining and they **failed** [confirmed]; the live concern is possible plaintext/ciphertext corruption defeating perfect isomorphs [confirmed the community hypothesizes this]. Treat any "solution" without a fully disclosed, reproducible method as **not credible** — the wiki's own rule [confirmed].

---

## What would actually move the needle (summary of priorities)

1. **Experiment 0** (transcription cross-validation) — non-negotiable prerequisite.
2. **Experiment 1** (reading-order multiple-comparisons audit) — most likely to confirm OR deflate the headline "this can't be chance" claim, because the community figure omits the family-wise correction [disputed].
3. **Experiment 2** (generation-pipeline artifact test) — directly tests whether "structure" means "message."
4. **Experiments 4 & 6** (frequency/IoC + adjacency on raw vs reordered) — expose how much "signal" is order-induced [confirmed it is substantial].
5. **Experiment 11** (positive controls on solved ciphers) — calibrates whether a null result is meaningful.

**Two standing caveats grounding all of the above:**
- No primary Nolla/developer statement confirms the Eye Messages encode recoverable plaintext; "developers confirmed it's meaningful/solvable" traces to an **unsourced 2022 Hacker News intro line** and AI-generated/Grokipedia text, not a dev quote [confirmed — this is a debunked meta-claim]. The strongest honest statement is "structured data of unknown meaning, unsolved."
- The entire technical corpus rests on a handful of analysts (Lymm, CodeWarrior0, Toboter, Pyry, Perseus) and a few repos/Google Docs; independent reproduction beyond this group is thin [confirmed]. Adding independent **null distributions** (Experiments 1, 2, 7) is the single most valuable contribution this code investigation can make.
